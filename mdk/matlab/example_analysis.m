% MATLAB SysML DocGen MDK example.
% This file can be parsed by tools/mdk_sync.py without running MATLAB.

% sysml-docgen:begin
% {
%   "elements": [
%     {
%       "id": "REQ-MAT-001",
%       "name": "MATLAB 能量仿真需求",
%       "type": "Requirement",
%       "stereotype": "requirement",
%       "owner": "仿真组",
%       "attributes": {
%         "text": "MATLAB 仿真表明电池 SOC 在最坏工况下应保持不低于 30%。",
%         "verification": "Simulation"
%       },
%       "relations": [
%         {"type": "satisfy", "target": "BLK-BATTERY"}
%       ]
%     },
%     {
%       "id": "TST-MAT-001",
%       "name": "MATLAB SOC 仿真",
%       "type": "TestCase",
%       "stereotype": "testCase",
%       "owner": "仿真组",
%       "attributes": {
%         "method": "MATLAB Simulation",
%         "criterion": "SOC_min >= 30%"
%       },
%       "relations": [
%         {"type": "verify", "target": "REQ-MAT-001"}
%       ]
%     }
%   ]
% }
% sysml-docgen:end

soc_min = 0.32;
assert(soc_min >= 0.30);
