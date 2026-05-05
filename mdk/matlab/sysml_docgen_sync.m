function result = sysml_docgen_sync(elements, server, project, branch)
%SYSML_DOCGEN_SYNC Push MATLAB analysis elements to SysML DocGen MMS.
% elements must be a struct array with fields matching the repository shape.

if nargin < 2 || isempty(server)
    server = "http://127.0.0.1:8000";
end
if nargin < 3 || isempty(project)
    project = "satellite-power";
end
if nargin < 4 || isempty(branch)
    branch = "main";
end

payload = struct();
payload.project = project;
payload.branch = branch;
payload.username = "engineer";
payload.commit = true;
payload.message = "MATLAB analysis sync";
payload.model = struct();
payload.model.format = "json";
payload.model.elements = elements;
payload.model.source = struct("tool", "matlab", "adapter", "sysml_docgen_sync.m");

options = weboptions( ...
    "MediaType", "application/json", ...
    "HeaderFields", ["X-User" "engineer"; "X-Role" "author"] ...
);
result = webwrite(server + "/api/mdk/push", payload, options);
end
