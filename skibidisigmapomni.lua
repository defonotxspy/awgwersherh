--[[

    xAPI    -   A Powerful Pentesting and Debugging Tool
    Author  -   Eskue (@SQLanguage)
    Version -   4.0

]]

--// Init
type userdata = {}
type _function = _function

local xAPI = {
    environment = {
		crypt = {},
		debug = {},
		cache = {}
	},
	original_fenvs = {},
	environments = {},
	scopes = {},
	global_count = 0
}

function xAPI.cache(f: _function)
    return setmetatable({}, {
        __index = function(self, key)
            local value = f(key)

            self[key] = value
            return value
        end
    })
end

function xAPI.load(scope: () -> ())
	scope = scope or debug.info(2, "f")
	
	local environment = getfenv(scope)
	
	table.insert(xAPI.scopes, scope)
	table.insert(xAPI.environments, environment)
	
	for i, v in xAPI.environment do
		if type(v) == "table" then pcall(table.freeze, v) end
		
		environment[i] = v
	end
end

xAPI.service = xAPI.cache(function(service_name)
    return game:GetService(service_name)
end)

xAPI.library = xAPI.cache(function(module_name)
    return require(script.Libraries:FindFirstChild(module_name))
end)

xAPI.module = xAPI.cache(function(module_name)
	return require(script.Modules:FindFirstChild(module_name))
end)

local function _cclosure(f: _function)
	return coroutine.wrap(function(...)
		while true do
			coroutine.yield(f(...))
		end
	end)
end

local type_check = xAPI.library.TypeChecking.type_check
local add_global, library, module, environment, service, scopes, environments = xAPI.addGlobal, xAPI.library, xAPI.module, xAPI.environment, xAPI.service, xAPI.scopes, xAPI.environments

local player: Player = service.Players.LocalPlayer

--// Functions

local function random(length: number)
	local result = ""

	for _ = 1, length do
		result ..= string.char(math.random(0, 255))
	end

	return result
end

-- Instances

local function get_instances(): {Instance}
	local instances = {}
	
	for _, instance in game:GetDescendants() do
		table.insert(instances, instance)
	end
	
	game.DescendantAdded:Connect(function(instance)
		table.insert(instances, instance)
	end)
	
	return instances
end

local function get_nil_instances(): {Instance}
	local nil_instances = {}
	local instances = get_instances()
	
	for _, instance in instances do
		pcall(function()
			if not instance.Parent then
				table.insert(nil_instances, instance)
			end
		end)
	end
	
	return nil_instances
end

local function get_scripts(): {LuaSourceContainer}
	local scripts = {}
	local instances = get_instances()

	for _, instance in instances do
		pcall(function()
			if instance:IsA("BaseScript") then
				table.insert(scripts, instance)
			end
		end)
	end

	return scripts
end

local function get_modules(): {ModuleScript}
	local modules = {}
	local instances = get_instances()

	for _, instance in instances do
		pcall(function()
			if instance:IsA("ModuleScript") then
				table.insert(modules, instance)
			end
		end)
	end

	return modules
end

local function get_loaded_modules(): {ModuleScript}
	return get_modules()
end

local function get_script_hash(module: ModuleScript)
	local instances = get_instances()
	return library.HashLib.sha256((table.find(instances, module) or -1) .. module:GetFullName())
end

local function get_running_scripts(): {BaseScript}
	local scripts = get_scripts()
	local running_scripts = {}
	
	local run_check = Instance.new("Folder")
	
	local function is_destroyed(script)
		if script.Parent == nil then
			local parent_unlocked = pcall(function()
				script.Parent = run_check
				script.Parent = nil
			end)
			
			return parent_unlocked
		end
		
		return false
	end
	
	for _, script: BaseScript in scripts do
		if not is_destroyed(script) and script.Enabled and not script.Disabled then
			table.insert(running_scripts, script)
		end
	end
	
	return running_scripts
end

local function is_scriptable(object: Instance, property: string): boolean
	type_check(1, object, {"Instance"})
	type_check(2, property, {"string"})
	
	return select(1, pcall(function()
		return object[property]
	end))
end

local function get_hidden_ui(): PlayerGui?
	return (player and player.PlayerGui)
end

-- Metatable

local function get_raw_metatable(obj: any): {any}
	type_check(1, obj, {"any"})
	
	local raw_mt = library.Metatable.get_all_L_closures(obj)
	
	return setmetatable({
		__tostring = _cclosure(function(self)
			return tostring(self)
		end)
	}, {
		__index = raw_mt,
		__newindex = _cclosure(function(_, key, value)
			local success = pcall(function()
				getmetatable(obj)[key] = value
			end)
			
			if not success then error("attempt to write to a protected/read-only metatable", 2) end
		end)
	})
end

local function hook_metamethod(obj: any, method: string, hook: _function): _function
	type_check(1, obj, {"any"})
	type_check(2, method, {"string"})
	type_check(3, hook, {"function"}, true)
	
	local rmt = library.Metatable.get_all_L_closures(obj)
	local mt = getmetatable(obj)
	
	local old = rmt[method]
	local is_writable = pcall(function()
		mt[random(8)] = nil 
	end)
	
	if is_writable then
		mt[method] = hook
	else
		local is_hookable = pcall(setfenv, old, getfenv(old))
		
		if is_hookable then
			return _cclosure(module.Hookfunction(old, hook))
		else
			error("attempt to hook a non-hookable metatable", 2)
		end
	end
	
	return old
end

local function is_readonly(obj: {any}): boolean
	type_check(1, obj, {"table"})
	
	return not select(1, pcall(function()
		obj[random(8)] = nil
	end))
end

-- Closures

local function hook_function(old: _function, new: _function?): _function
	type_check(1, old, {"function"})
	type_check(2, new, {"function"}, true)
	
	xAPI.original_fenvs[old] = getfenv(old)
	
	return _cclosure(module.Hookfunction(old, new))
end

local function restore_function(f: _function)
	type_check(1, f, {"function"})
	
	setfenv(f, xAPI.original_fenvs[f] or getfenv(f))
end

local function emulate_call(f: _function, target: LuaSourceContainer, ...): ...any
	type_check(1, f, {"function"})
	type_check(2, target, {"Instance"})
	
	local original_environment = getfenv(f)
	local real_environment = getfenv()
	local sandbox = {}
	
	local fake_environment = setmetatable({
		script = target,
		_G = _G,
		shared = shared
	}, {
		__index = _cclosure(function(self, key)
			return sandbox[key] or real_environment[key]
		end),
		__newindex = _cclosure(function(self, key, value)
			sandbox[key] = value
		end),
		__metatable = "The metatable is locked"
	})
	
	local return_value = {setfenv(f, fake_environment)(...)}
	setfenv(f, real_environment)
	
	return unpack(return_value)
end

local function new_c_closure(f: _function): _function
	type_check(1, f, {"function"})
	
	return _cclosure(f)
end

local function new_l_closure(f: _function): _function
	type_check(1, f, {"function"})

	return function(...)
		return f(...)
	end
end

local function is_c_closure(f: _function): boolean
	type_check(1, f, {"function"})	

	return debug.info(f, "s") == "[C]"
end

local function is_l_closure(f: _function): boolean
	type_check(1, f, {"function"})	
	
	return debug.info(f, "s") ~= "[C]"
end

local function dump_string(source: string | _function): string
	type_check(1, source, {"string", "function"})	

	local compile = library.vLuau.luau_compile
	if type(source) == "string" then
		return ({compile(source)})[1] -- select() doesn't work for some reason
	else
		if pcall(setfenv, source, getfenv(source)) then
			return ({compile(environment.decompile(source))})[1]
		else
			return "-- non-hookable functions are not supported"
		end
	end
end

local function load_string(source: string, chunkname: string): _function
	type_check(1, source, {"string"})	
	type_check(2, chunkname, {"string"})

	return loadstring(dump_string(source), chunkname)
end

-- Modules

local function get_loaded_modules()
	return xAPI.environment.cache.loaded_modules
end

local function get_cached_modules()
	return xAPI.environment.cache.cached_modules
end

local function has_loaded(module_name: string): boolean
	type_check(1, module_name, {"string"})	
	
	local loaded_modules = get_loaded_modules()
	
	for i, module in loaded_modules do
		if module.Name == module_name then
			return true
		end
	end
	
	return false
end

local function has_cached(module_name: string): boolean
	type_check(1, module_name, {"string"})	
	
	local cached_modules = get_cached_modules()
	
	for i, module in cached_modules do
		if module.Name == module_name then
			return true
		end
	end
	
	return false
end

local function execute(module: ModuleScript, ...)
	type_check(1, module, {"Instance"})

	return require(module)(...)
end

local function get_l_closures(module: ModuleScript): {string: _function}
	type_check(1, module, {"Instance"})

	local l_closures = {}

	for i, f in next, getfenv(require(module)) do
		if is_l_closure(f) then
			l_closures[i] = f
		end
	end

	return l_closures
end

-- Initialize xAPI
xAPI.load()
