//----------------------------------------------------------------------------
//
//  Transport stream processor shared library:
//  Corrupt TS packets.
//
//----------------------------------------------------------------------------

#include "tsPluginRepository.h"
#include "tsSignalizationDemux.h"
#include "tsPESPacket.h"
#include "tsAlgorithm.h"
#include "tsMemory.h"
#include "tsUString.h"
#include "tsCyclingPacketizer.h"
#include "tsOneShotPacketizer.h"
#include "tsUString.h"
#include <deque>
#include <list>
#include <vector>
#include <random>
#include <map>
#include <iostream>
#include <fstream>

TSDUCK_SOURCE;


//----------------------------------------------------------------------------
// Plugin definition
//----------------------------------------------------------------------------
#define PID_ANY 0x2fff

namespace ts {
	class CorruptPlugin;
}

namespace {
	struct TimeCommand {
		uint64_t time;
		ts::UString command;
	};

	class ScriptPlayer
	{
	public:
		ScriptPlayer(ts::CorruptPlugin *p);
		bool setScript(ts::UString script);
		void notifyTime(uint64_t timeInMs, uint64_t count);
		bool execCommand(ts::UString command, bool dryRun);

	private:
		bool parseOnOff(ts::UString onOff);
		bool parsePidClass(ts::UString pidStr, ts::PIDClass &pidClass, ts::PID &pid);
		bool parsePid(ts::UString pidStr, ts::PID &pid);
		bool parseError(ts::UString str, double &value);

 		ts::CorruptPlugin *_corrupter;
		ts::UString _script;
		std::deque<TimeCommand> _timeCommands;
	};

	// TInfo struct and functions
	template<typename T> struct TInfo {
		ts::PIDClass pidClass;
		ts::PID pid;
		T value;
	};

	template<typename T> static T getValueForPid(ts::PIDClass pidClass, ts::PID pid, std::list<TInfo<T>> &list, T defaultValue)
	{
		for (const auto &info : list) {
			if ((info.pidClass != ts::PIDClass::UNDEFINED && pidClass == info.pidClass) ||
					info.pid == PID_ANY ||
					info.pid == pid) {
				return info.value;
			}
		}
		return defaultValue;
	}

	template<typename T> static void setValueForPid(bool on, ts::PIDClass pidClass, ts::PID pid, std::list<TInfo<T>> &list, T value)
	{
		// find existing
		for (auto it = list.begin(); it != list.end(); it++) {
			if (it->pidClass == pidClass && it->pid == pid) {
				// found
				if (on) {
					it->value = value;
				} else {
					list.erase(it);
				}
				return;
			}
		}
		// not found
		if (on) {
			list.push_back({pidClass, pid, value});
		}
	}


	class Executor
	{
	public:
		Executor(ts::CorruptPlugin *corrupter)
		:_corrupter(corrupter)
		{
		}
		virtual ~Executor()
		{
		}
		virtual ts::ProcessorPlugin::Status process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data) = 0;

	protected:
		ts::CorruptPlugin *_corrupter;
	};

	class CCErrorExecutor: public Executor
	{
	public:
		CCErrorExecutor(ts::CorruptPlugin *corrupter)
		:Executor(corrupter)
		{
		}
        ts::ProcessorPlugin::Status process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data) override;
        void setCCError(bool on, ts::PIDClass pidClass, ts::PID pid, double rate);

	private:
		std::list<TInfo<double>> _infos;
	};

	class ScrambleExecutor: public Executor
	{
	public:
		ScrambleExecutor(ts::CorruptPlugin *corrupter)
		:Executor(corrupter)
		{
		}
		ts::ProcessorPlugin::Status process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data) override;
		void setScramble(bool on, ts::PIDClass pidClass, ts::PID pid);

	private:
		std::list<TInfo<bool>> _infos;
	};

    class PidMapExecutor : public Executor
    {
		TS_NOCOPY(PidMapExecutor); // because CyclingPacketizer has deleted move constructor
    public:
        PidMapExecutor(ts::CorruptPlugin* corrupter);

        ts::ProcessorPlugin::Status process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data) override;
        void setPidMap(bool on, ts::PID oldPid, ts::PID newPid);
        void handlePMT(const ts::PMT& table, ts::PID);
        void updatePMT(ts::PID pid = PID_ANY);

    private:
        struct Info {
        	ts::PMT pmt;
        	ts::SafePtr<ts::CyclingPacketizer> pzer_pmt;
        	uint8_t version; // current version
        };

        std::map<ts::PID, ts::PID> _map;
        std::map<ts::PID, Info> _pmts;
        bool _active;
    };

	class PtsOffsetExecutor: public Executor
	{
	public:
    	PtsOffsetExecutor(ts::CorruptPlugin *corrupter)
		:Executor(corrupter)
		{
		}
		ts::ProcessorPlugin::Status process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data) override;
		void setPtsOffset(bool on, ts::PIDClass pidClass, ts::PID pid, int offset);

	private:
		std::list<TInfo<int>> _infos;
	};

	class BitErrorExecutor: public Executor
		{
		public:
		BitErrorExecutor(ts::CorruptPlugin *corrupter)
			:Executor(corrupter)
			{
			}
			ts::ProcessorPlugin::Status process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data) override;
			void setBitError(bool on, ts::PIDClass pidClass, ts::PID pid, double rate);

		private:
			std::list<TInfo<double>> _infos;
		};

}

namespace ts {

    class CorruptPlugin: public ProcessorPlugin, private SignalizationHandlerInterface
    {
        TS_NOBUILD_NOCOPY(CorruptPlugin);
    public:
        // Implementation of plugin API
        CorruptPlugin(TSP*);
        virtual bool getOptions() override;
        virtual bool start() override;
        virtual bool stop() override;
        virtual Status processPacket(TSPacket&, TSPacketMetadata&) override;
        virtual void handlePMT(const PMT&, PID) override;
        void setCCError(bool on, PIDClass pidClass = PIDClass::UNDEFINED, PID pid = PID_NULL, double rate = 0);
        void setScramble(bool on, PIDClass pidClass = PIDClass::UNDEFINED, PID pid = PID_NULL);
        void setPidMap(bool on, PID oldPid = PID_NULL, PID newPid = PID_NULL);
        void setPtsOffset(bool on, PIDClass pidClass = PIDClass::UNDEFINED, PID pid = PID_NULL, int offset = 0);
        void setBitError(bool on, PIDClass pidClass = PIDClass::UNDEFINED, PID pid = PID_NULL, double rate = 0);
        SignalizationDemux &demux() { return _demux; }
        std::default_random_engine &randomEngine() {return _engine; }
        uint64_t currentPacket() { return _currentPacket; } // 1-based
        DuckContext &getDuck() { return duck; }

    private:
        int _seed;                             // seed 0 means random seed FIXME remove me
        std::default_random_engine _engine;
        UString _script;
        SignalizationDemux _demux;             // Full signalization demux
        ScriptPlayer _player;
        uint64_t _curTime;                      // Current packet time relative to the first packet
        ts::PID _pcr_pid;
        uint64_t _lastPcr;
        uint64_t _currentPacket;
        CCErrorExecutor _ccErrorExecutor;
        ScrambleExecutor _scrambleExecutor;
        PidMapExecutor _pidMapExecutor;
        PtsOffsetExecutor _ptsOffsetExecutor;
        BitErrorExecutor _bitErrorExecutor;
        // NOTE: pidMapExecutor must be executed LAST!
        std::vector<Executor *> _allExecutors = std::vector<Executor *> {&_ccErrorExecutor, &_ptsOffsetExecutor, &_bitErrorExecutor, &_scrambleExecutor, &_pidMapExecutor};

        // Implementation of SignalizationHandlerInterface
        void updateTime(TSPacket&);
        UString readScriptFile(UString filename);
    };
}

TS_REGISTER_PROCESSOR_PLUGIN(u"corrupt", ts::CorruptPlugin);


ScriptPlayer::ScriptPlayer(ts::CorruptPlugin *p)
: _corrupter(p)
, _script(u"")
{
}

bool ScriptPlayer::parseOnOff(ts::UString onOff)
{
	if (onOff == u"on") {
		return true;
	}
	return false;
}

bool ScriptPlayer::parsePid(ts::UString pidStr, ts::PID &pid)
{
	if (!pidStr.scan(u"%d", {&pid})) {
		_corrupter->error(u"cannot parse target pid from %s", {pidStr});
		return false;
	}
	return true;
}

bool ScriptPlayer::parsePidClass(ts::UString pidStr, ts::PIDClass &pidClass, ts::PID &pid)
{
	if (pidStr == u"video") {
		pidClass = ts::PIDClass::VIDEO;
		pid = ts::PID_NULL;
	} else if (pidStr == u"audio") {
		pidClass = ts::PIDClass::AUDIO;
		pid = ts::PID_NULL;
	} else if (pidStr == u"all") {
		pidClass = ts::PIDClass::UNDEFINED;
		pid = PID_ANY;
	} else {
		pidClass = ts::PIDClass::UNDEFINED;
		return parsePid(pidStr, pid);
	}
	return true;
}

bool ScriptPlayer::parseError(ts::UString str, double &value)
{
	try {
		value = std::stod(str.toUTF8());
		if (value < 0 || value > 100) {
			_corrupter->error(u"errorRate: error rate should be within [0, 100]: %s", {str});
			return false;
		}
		return true;
	} catch (...) {
		_corrupter->error(u"errorRate: incorrect format %s", {str});
		return false;
	}
}

bool ScriptPlayer::execCommand(ts::UString command, bool dryRun)
{
	bool on;
	ts::PIDClass pidClass;
	ts::PID pid;
	double errorRate;
	ts::UStringVector args;
	command.split(args, u' ', true, true);
	if (args.size()) {
		if (args[0].toLower() == u"cc") {
			if (args.size() != 4) {
				_corrupter->error(u"command cc: expected: cc on|off video|audio|all|<pid number> <errorRate>, actual: %s", {command});
				return false;
			}
			on = parseOnOff(args[1]);
			if (!parsePidClass(args[2], pidClass, pid)) {
				return false;
			}
			if (!parseError(args[3], errorRate)) {
				return false;
			}
			if (!dryRun) {
				_corrupter->setCCError(on, pidClass, pid, errorRate);
			}
		} else if (args[0].toLower() == u"scramble") {
			if (args.size() != 3) {
				_corrupter->error(u"command scramble: expected: scramble on|off video|audio|<pid number>, actual: %s", {command});
				return false;
			}
			on = parseOnOff(args[1]);
			if (!parsePidClass(args[2], pidClass, pid)) {
				return false;
			}
			if (!dryRun) {
				_corrupter->setScramble(on, pidClass, pid);
			}
		} else if (args[0].toLower() == u"pidmap") {
			if (args.size() != 4) {
				_corrupter->error(u"command pidMap: expected: pidMap on|off <old pid number> <new pid number>, actual: %s", {command});
				return false;
			}
			on = parseOnOff(args[1]);
			ts::PID from, to;
			if (!parsePid(args[2], from) || !parsePid(args[3], to)) {
				_corrupter->error(u"command pidMap: cannot parse pid %s %s", {args[2], args[3]});
				return false;
			}
			if (!dryRun) {
				_corrupter->setPidMap(on, from, to);
			}
		} else if (args[0].toLower() == u"offset") {
			if (args.size() != 4) {
				_corrupter->error(u"command offset: expected: offset on|off video|audio|all|<pid number> <90kHz tick>, actual: %s", {command});
				return false;
			}
			on = parseOnOff(args[1]);
			if (!parsePidClass(args[2], pidClass, pid)) {
				return false;
			}
			int offset;
			if (!args[3].scan(u"%d", {&offset})) {
				_corrupter->error(u"Cannot parse <90kHz tick>", {args[3]});
				return false;
			}
			if (!dryRun) {
				_corrupter->setPtsOffset(on, pidClass, pid, offset);
			}
		} else if (args[0].toLower() == u"biterror") {
			if (args.size() != 4) {
				_corrupter->error(u"command bitError: expected: bitError on|off video|audio|all|<pid number> <errorRate>, actual: %s", {command});
				return false;
			}
			on = parseOnOff(args[1]);
			if (!parsePidClass(args[2], pidClass, pid)) {
				return false;
			}
			if (!parseError(args[3], errorRate)) {
				return false;
			}
			if (!dryRun) {
				_corrupter->setBitError(on, pidClass, pid, errorRate);
			}
		} else {
			_corrupter->error(u"unknown command: %s", {command});
			return false;
		}
	}
	return true;
}

bool ScriptPlayer::setScript(ts::UString script)
{
	_script = script;
	// parse script into a ordered list of Action
	// do dry run to ensure each Action is correctly set
	// FIXME support map of count vs command if needed, i.e specify command since packet n
    ts::UStringVector actions;
    script.split(actions, u';', true, true);
    for (const auto &action : actions) {
    	ts::UStringVector time_command;
    	action.split(time_command, u':', true, true);
    	if (time_command.size() != 2) {
    		_corrupter->error(u"script's action is not in expected format (<time>: <command>): %s", {action});
    		return false;
    	}
    	ts::UStringVector unit_time;
    	time_command[0].split(unit_time, u' ', true, true);
    	if (unit_time.size() != 2) {
    		_corrupter->error(u"script action's time is not in expected format (ms|s <time_value>): %s", {time_command[0]});
    		return false;
    	}
    	uint64_t timeMs;
        if (!unit_time[1].scan(u"%d", { &timeMs })) {
            _corrupter->error(u"script action's time cannot be parsed as integer", { unit_time[1] });
            return false;
        }
    	if (unit_time[0] == u"ms") {
    		// pass
    	} else if (unit_time[0] == u"s") {
    		timeMs *= 1000;
    	} else {
    		_corrupter->error(u"script action's time is in unknown unit: %s", {unit_time[0]});
    		return false;
    	}
    	if (execCommand(time_command[1], true)) { // XXX set this to false to force run during dry run
    		_timeCommands.push_back({timeMs, time_command[1]});
    	} else {
    		_corrupter->error(u"script format error, failed to parse");
    		return false;
    	}
    }
    return true;
}

void ScriptPlayer::notifyTime(uint64_t timeInMs, uint64_t count)
{
	// scan the Action list and execute item that has time reached
	while (_timeCommands.size()) {
		if (_timeCommands[0].time <= timeInMs) {
			execCommand(_timeCommands[0].command, false);
			_timeCommands.pop_front();
		} else {
			break;
		}
	}
}

ts::ProcessorPlugin::Status CCErrorExecutor::process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data)
{
	const ts::PID pid = pkt.getPID();
	double rate = ::getValueForPid(_corrupter->demux().pidClass(pid), pid, _infos, 0.0);
	if (rate > 0) {
		uint32_t r = (_corrupter->currentPacket() * _corrupter->randomEngine()()) % _corrupter->randomEngine().max();
		if (r <= _corrupter->randomEngine().max() * rate / 100) {
			_corrupter->debug(u"Injected cc error at packet %d, random value %f", {_corrupter->currentPacket(), 100 * double(r) / _corrupter->randomEngine().max()});
			return ts::ProcessorPlugin::TSP_DROP;
		}
	}
	return ts::ProcessorPlugin::TSP_OK;
}

void CCErrorExecutor::setCCError(bool on, ts::PIDClass pidClass, ts::PID pid, double rate)
{
	::setValueForPid(on, pidClass, pid, _infos, rate);
}


ts::ProcessorPlugin::Status ScrambleExecutor::process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data)
{
	const ts::PID pid = pkt.getPID();
	bool shallProcess = ::getValueForPid(_corrupter->demux().pidClass(pid), pid, _infos, false);
	if (shallProcess) {
		// scramble it!
		if (!pkt.isScrambled() && pkt.hasPayload()) {
			pkt.setScrambling(ts::SC_EVEN_KEY);
//			_corrupter->debug(u"scrambled packet %d", {_corrupter->currentPacket()});
		}
	}
	return ts::ProcessorPlugin::TSP_OK;
}

// FIXME note that i did not add a scrambling descriptor
void ScrambleExecutor::setScramble(bool on, ts::PIDClass pidClass, ts::PID pid)
{
	::setValueForPid(on, pidClass, pid, _infos, true);
}

PidMapExecutor::PidMapExecutor(ts::CorruptPlugin *corrupter)
:Executor(corrupter)
,_active(false)
{
}

ts::ProcessorPlugin::Status PidMapExecutor::process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data)
{
	const ts::PID pid = pkt.getPID();
	if (_map.count(pid)) {
		ts::PID newPid = _map[pid];
		pkt.setPID(newPid);
	}
	if (_active) {
		const ts::PIDClass pidClass = _corrupter->demux().pidClass(pid);
		if (pidClass == ts::PIDClass::PSI && _pmts.count(pid)) {
			// replace PMT packet
			_pmts[pid].pzer_pmt->getNextPacket(pkt);
		}
	}
	return ts::ProcessorPlugin::TSP_OK;
}

void PidMapExecutor::setPidMap(bool on, ts::PID oldPid, ts::PID newPid)
{
	if (on) {
		_map[oldPid] = newPid;
	} else {
		_map.erase(oldPid);
	}
	updatePMT();
	_active = true; // once active, will not go back to inactive, PMT will be overridden by pzer_pmt
}

void PidMapExecutor::handlePMT(const ts::PMT& table, ts::PID pid)
{
	_corrupter->debug(u"handlePMT pid %d version %d", {pid, table.version});
	if (_pmts.count(pid)) {
		_pmts[pid].pmt = ts::PMT(table);
		// version will be incremented in updatePMT()
	} else {
		_pmts[pid].pmt = ts::PMT(table);
		_pmts[pid].version = table.version;
	}
	if (_map.size()) {
		updatePMT(pid);
	}
}

void PidMapExecutor::updatePMT(ts::PID pid)
{
	// supported MPTS
	// FIXME Limitation: once we specify any PidMap, we will take over the generation of all PMT
	// no matter the PMT is affected by the PidMap or not. This makes the version number of
	// unaffected PMT to be incremented unnecessarily
	for (auto &p : _pmts) {
		if (pid == PID_ANY || p.first == pid) {
			// the target PMT to update
			if (p.second.pzer_pmt.isNull()) {
				p.second.pzer_pmt = new ts::CyclingPacketizer(_corrupter->getDuck(), p.first, ts::CyclingPacketizer::StuffingPolicy::ALWAYS);
			} else {
				p.second.pzer_pmt->reset();
			}

			ts::PMT pmt(p.second.pmt);
			pmt.streams.clear();
			if (_map.count(pmt.pcr_pid)) {
				pmt.pcr_pid = _map[pmt.pcr_pid];
			}
			for (ts::PMT::StreamMap::const_iterator it = p.second.pmt.streams.begin(); it != p.second.pmt.streams.end(); ++it) {
				if (_map.count(it->first)) {
					pmt.streams[_map[it->first]] = it->second;
				} else {
					pmt.streams[it->first] = it->second;
				}
			}
			// increase the version of the PMT by one
			p.second.version++;
			pmt.version = p.second.version;
			_corrupter->debug(u"updatePMT %s, version %d", {pid == PID_ANY? u"due to pidMap change":ts::UString::Format(u"due to PMT %d", {pid}), pmt.version});
			p.second.pzer_pmt->removeSections(ts::TID_PMT, pmt.service_id);
			p.second.pzer_pmt->addTable(_corrupter->getDuck(), pmt);
		}
	}
}


ts::ProcessorPlugin::Status PtsOffsetExecutor::process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data)
{
	const ts::PID pid = pkt.getPID();
	int offset = ::getValueForPid(_corrupter->demux().pidClass(pid), pid, _infos, 0);
	if (offset != 0) {
		if (pkt.hasPTS()) {
//			_corrupter->info(u"changed PTS from %d to %d", {pkt.getPTS(), pkt.getPTS() + offset});
			pkt.setPTS(pkt.getPTS() + offset);
		}
		if (pkt.hasDTS()) {
			pkt.setDTS(pkt.getDTS() + offset);
		}
	}
	return ts::ProcessorPlugin::TSP_OK;
}

void PtsOffsetExecutor::setPtsOffset(bool on, ts::PIDClass pidClass, ts::PID pid, int offset)
{
	::setValueForPid(on, pidClass, pid, _infos, offset);
}


ts::ProcessorPlugin::Status BitErrorExecutor::process(ts::TSPacket& pkt, ts::TSPacketMetadata& pkt_data)
{
	const ts::PID pid = pkt.getPID();
	double rate = ::getValueForPid(_corrupter->demux().pidClass(pid), pid, _infos, 0.0);
	if (rate > 0) {
		uint32_t r = (_corrupter->currentPacket() * _corrupter->randomEngine()()) % _corrupter->randomEngine().max();
		if (r <= _corrupter->randomEngine().max() * rate / 100) {
			size_t range = 0;
			range += pkt.getHeaderSize();
			if (pkt.startPES()) {
				range += pkt.getHeaderSize();
			}
			if (range > 188) {
				_corrupter->debug(u"panic TS+PES header size is over 188: %d", {range});
			}
			int targetByte = r % range; // target bit to corrupt
			ts::TSPacket backup = pkt;
			uint8_t byte = ts::GetUInt8(pkt.b + targetByte);
			int targetBit = r % 8;
			byte ^= (1UL << targetBit);
			ts::PutUInt8(pkt.b + targetByte, byte);
			// note that packet number is 1-based
			_corrupter->debug(u"Injected biterror at packet %d byte %d bit %d in range %d, random value %f", {_corrupter->currentPacket(), targetByte, targetBit, range, 100 * double(r) / _corrupter->randomEngine().max()});
			if (backup.hasPCR()) {
				if (pkt.hasPCR()) {
					if (backup.getPCR() != pkt.getPCR()) {
						_corrupter->debug(u"Reverted biterror due to corruption at PCR");
						pkt = backup;
					}
				}
			}
		}
	}
	return ts::ProcessorPlugin::TSP_OK;
}

// FIXME limitation: we do not corrupt PCR in order to avoid error in regulate plugin
void BitErrorExecutor::setBitError(bool on, ts::PIDClass pidClass, ts::PID pid, double rate)
{
	::setValueForPid(on, pidClass, pid, _infos, rate);
}


//----------------------------------------------------------------------------
// Constructor
//----------------------------------------------------------------------------
/**
 * Support script mode
 * - tsp -P corrupt --seed 0 --script "ms|s <relative time>: <cmd> <arg1> <arg2> ...; ..."
 * Support
 * - CC error (deterministic packet drop)
 *   - cc on|off video|audio|all|<pid number> <errorRate>
 * - Video pid missing (drop all packets of that pid) => (cc error with 100% errorRate)
 * - Video pid scrambled
 *   - scramble on|off video|audio|<pid number>
 * - PCR pid changed (Change pid, and also change PMT)
 *   - pidMap on|off <old pid number> <new pid number>
 * - Video PTS and Audio PTS not aligned with PCR (TBD)
 *   - offset on|off video|audio|all|<pid number> <90kHz tick>
 * - Bit corruption (on TS header and on PES header)
 *   - bitError on|off video|audio|all|<pid number> <errorRate>
 */
ts::CorruptPlugin::CorruptPlugin(TSP* tsp_) :
    ProcessorPlugin(tsp_, u"Corrupt TS packets deterministically", u"[options]"),
	_seed(0),
    _demux(duck, this),
	_player(this),
	_curTime(0),
	_pcr_pid(PID_NULL),
	_lastPcr(INVALID_PCR),
	_currentPacket(0),
	_ccErrorExecutor(this),
	_scrambleExecutor(this),
    _pidMapExecutor(this),
    _ptsOffsetExecutor(this),
    _bitErrorExecutor(this)
{
    option(u"seed", 0, INTEGER, 0, 1, 0, std::numeric_limits<int32_t>::max());
    help(u"seed", u"seed-value", u"Set random seed for random generator.");

    option(u"script", 0, STRING, 0, 1);
    help(u"script", u"script", u"Set the script to play.");

    option(u"scriptFile", 0, STRING, 0, 1);
    help(u"scriptFile", u"scriptFile", u"Set the script file to play.");

}


//----------------------------------------------------------------------------
// Get command line options
//----------------------------------------------------------------------------

bool ts::CorruptPlugin::getOptions()
{
	getIntValue(_seed, u"seed", 0);
	if (_seed != 0) {
		_engine.seed(_seed);
	} else {
		std::random_device r;
		_engine.seed(r());
	}
	getValue(_script, u"script");
	UString scriptFile;
	getValue(scriptFile, u"scriptFile");
	if (_script.empty() && scriptFile.empty()) {
		tsp->error(u"Either script or scriptFile should be used, now both are empty\n");
	} else if (!_script.empty() && !scriptFile.empty()) {
		tsp->error(u"Either script or scriptFile should be used, not both, use script parameter now\n");
	} else if (!scriptFile.empty()){
		// _script is empty, load scriptFile into _script
		_script = readScriptFile(scriptFile);
	}
	tsp->info(u"seed (%d) script (%s)", {_seed, _script});
	if (!_player.setScript(_script)) {
		return false;
	}

    return true;
}


//----------------------------------------------------------------------------
// Start method.
//----------------------------------------------------------------------------

bool ts::CorruptPlugin::start()
{
    _demux.reset();
    _demux.addFilteredTableId(TID_PMT);
    return true;
}


//----------------------------------------------------------------------------
// Stop method.
//----------------------------------------------------------------------------

bool ts::CorruptPlugin::stop()
{
    return true;
}


//----------------------------------------------------------------------------
// Packet processing method
//----------------------------------------------------------------------------

ts::ProcessorPlugin::Status ts::CorruptPlugin::processPacket(TSPacket& pkt, TSPacketMetadata& pkt_data)
{
    updateTime(pkt);
    _player.notifyTime(_curTime / 27000, _currentPacket);
    _currentPacket++;

	_demux.feedPacket(pkt);

    // corruption logic
    for (Executor *executor : _allExecutors) {
    	ts::ProcessorPlugin::Status status = executor->process(pkt, pkt_data);
    	if (status != TSP_OK) {
    		return status;
    	}
    }
	return TSP_OK;
}

void ts::CorruptPlugin::handlePMT(const PMT& table, PID pid)
{
	_pidMapExecutor.handlePMT(table, pid);
}

/*
How to calculate relative packet time?
- The time for the first byte is 0. It keeps 0 until the second PCR is obtained.
- The difference between the first PCR and the second PCR is the duration to be added to the time.
  After the second PCR, the time is 0 + duration1.
  After the third PCR, the time is 0 + duration1 + duration2
- The time is not precise, max error is about 80ms. Error will increase at loop point, max error may be increased by 80ms
 */
void ts::CorruptPlugin::updateTime(TSPacket& pkt)
{
	// FIXME Limitation: we will use the PCR pid first encountered as the timeline
	// we assumed this PCR will exist until throughout the asset
    if (_pcr_pid == PID_NULL && pkt.hasPCR()) {
    	_pcr_pid = pkt.getPID();
        tsp->info(u"using PID 0x%X (%d) for PCR reference", {_pcr_pid, _pcr_pid});
    }
	if (pkt.hasPCR() && _pcr_pid == pkt.getPID()) {
        const uint64_t pcr = pkt.getPCR();
        if (_lastPcr != INVALID_PCR) {
            constexpr uint64_t max_pcr_diff = 2 * SYSTEM_CLOCK_FREQ; // 2 seconds in PCR units
            if (pcr < _lastPcr && pcr + PCR_SCALE < _lastPcr + max_pcr_diff) {
        		_curTime += pcr + PCR_SCALE - _lastPcr;
            } else if (pcr > _lastPcr && pcr < _lastPcr + max_pcr_diff) {
        		_curTime += pcr - _lastPcr;
            } else {
                tsp->warning(u"out of sequence PCR (%d -> %d), maybe source was cycling, restarting duration calculation", {_lastPcr, pcr});
                _lastPcr = INVALID_PCR;
            }
        }
		_lastPcr = pcr;
	}
}

ts::UString ts::CorruptPlugin::readScriptFile(UString filename)
{
	ts::UString ret;
	std::string line;
	std::ifstream myfile (filename.toUTF8().c_str());
	if (myfile.is_open()) {
		while (getline(myfile, line)) {
			ts::UString uline = ts::UString::FromUTF8(line);
			uline.trim(true, true, false);
			ret.append(uline);
			if (!uline.endWith(u";", CASE_INSENSITIVE, true)) {
				ret.append(u';');
			}
		}
		myfile.close();
	}
	return ret;
}


void ts::CorruptPlugin::setCCError(bool on, PIDClass pidClass, PID pid, double rate)
{
	tsp->info(u"setCCError: %d %d %d %f since packet %d", {on, pidClass, pid, rate, _currentPacket}); // packet count is 1-based
	// on/off should be specific to target pid, each pid has different on/off
	// re-on the same pid means updating value
	_ccErrorExecutor.setCCError(on, pidClass, pid, rate);
}

void ts::CorruptPlugin::setScramble(bool on, PIDClass pidClass, PID pid)
{
	tsp->info(u"setScramble: %d %d %d since packet %d", {on, pidClass, pid, _currentPacket});
	_scrambleExecutor.setScramble(on, pidClass, pid);
}

void ts::CorruptPlugin::setPidMap(bool on, PID oldPid, PID newPid)
{
	tsp->info(u"setPidMap: %d %d %d since packet %d", {on, oldPid, newPid, _currentPacket});
	_pidMapExecutor.setPidMap(on, oldPid, newPid);
}

void ts::CorruptPlugin::setPtsOffset(bool on, PIDClass pidClass, PID pid, int offset)
{
	tsp->info(u"setPtsOffset: %d %d %d %d since packet %d", {on, pidClass, pid, offset, _currentPacket});
	_ptsOffsetExecutor.setPtsOffset(on, pidClass, pid, offset);
}

void ts::CorruptPlugin::setBitError(bool on, PIDClass pidClass, PID pid, double rate)
{
	tsp->info(u"setBitError: %d %d %d %f since packet %d", {on, pidClass, pid, rate, _currentPacket});
	_bitErrorExecutor.setBitError(on, pidClass, pid, rate);
}
