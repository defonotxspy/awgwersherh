--[[
    xAPI    -   A Simplified Pentesting and Debugging Tool
    Author  -   Adapted Version
    Version -   1.0
]]

--// Init
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

function xAPI.cache(f)
	return setmetatable({}, {
		__index = function(self, key)
			local value = f(key)
			self[key] = value
			return value
		end
	})
end

function xAPI.load(scope)
	scope = scope or debug.info(2, "f")
	local environment = getfenv(scope)
	table.insert(xAPI.scopes, scope)
	table.insert(xAPI.environments, environment)
	for i, v in pairs(xAPI.environment) do
		if type(v) == "table" then pcall(function() table.freeze(v) end) end
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

local function _cclosure(f)
	return coroutine.wrap(function(...)
		while true do
			coroutine.yield(f(...))
		end
	end)
end

function xAPI.addGlobal(names, value, libraries)
	xAPI.global_count = xAPI.global_count + 1
	for _, library in ipairs(libraries or {xAPI.environment}) do
		for _, name in ipairs(names) do
			library[name] = value
		end
	end
end

local type_check = xAPI.library("TypeChecking").type_check
local add_global, library, module, environment, service, scopes, environments = xAPI.addGlobal, xAPI.library, xAPI.module, xAPI.environment, xAPI.service, xAPI.scopes, xAPI.environments
local player = service("Players").LocalPlayer

--// Functions

local function random(length)
	local result = ""
	for _ = 1, length do
		result = result .. string.char(math.random(0, 255))
	end
	return result
end

-- Instances

do
	local instances = {}
	for _, instance in ipairs(game:GetDescendants()) do
		table.insert(instances, instance)
	end
	game.DescendantAdded:Connect(function(instance)
		table.insert(instances, instance)
	end)

	add_global({"getinstances", "get_instances"}, function()
		return table.clone(instances)
	end)

	add_global({"getnilinstances", "get_nil_instances"}, function()
		local nil_instances = {}
		for _, instance in ipairs(instances) do
			pcall(function()
				if not instance.Parent then
					table.insert(nil_instances, instance)
				end
			end)
		end
		return nil_instances
	end)

	add_global({"getscripts", "get_scripts"}, function()
		local scripts = {}
		for _, instance in ipairs(instances) do
			pcall(function()
				if instance:IsA("BaseScript") then
					table.insert(scripts, instance)
				end
			end)
		end
		return scripts
	end)

	add_global({"getmodules", "get_modules"}, function()
		local modules = {}
		for _, instance in ipairs(instances) do
			pcall(function()
				if instance:IsA("ModuleScript") then
					table.insert(modules, instance)
				end
			end)
		end
		return modules
	end)

	add_global({"getloadedmodules", "get_loaded_modules"}, function()
		return environment.getmodules()
	end)

	add_global({"getscripthash", "get_script_hash"}, function(module)
		return library("HashLib").sha256((table.find(instances, module) or -1) .. module:GetFullName())
	end)

	add_global({"getrunningscripts", "get_running_scripts"}, function()
		local scripts = environment.getscripts()
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

		for _, script in ipairs(scripts) do
			if not is_destroyed(script) and script.Enabled and not script.Disabled then
				table.insert(running_scripts, script)
			end
		end
		return running_scripts
	end)
end

add_global({"isscriptable", "is_scriptable"}, function(object, property)
	type_check(1, object, {"Instance"})
	type_check(2, property, {"string"})
	return select(1, pcall(function()
		return object[property]
	end))
end)

add_global({"gethui", "get_hidden_ui", "gethiddenui", "get_hui"}, function()
	return (player and player.PlayerGui)
end)

-- Metatable

add_global({"getrawmetatable", "get_raw_metatable"}, function(obj)
	type_check(1, obj, {"any"})
	local raw_mt = library("Metatable").get_all_L_closures(obj)
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
end)

add_global({"hookmetamethod"}, function(obj, method, hook)
	type_check(1, obj, {"any"})
	type_check(2, method, {"string"})
	type_check(3, hook, {"function"}, true)
	local rmt = library("Metatable").get_all_L_closures(obj)
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
			return _cclosure(module("Hookfunction")(old, hook))
		else
			error("attempt to hook a non-hookable metatable", 2)
		end
	end
	return old
end)

add_global({"isreadonly"}, function(obj)
	type_check(1, obj, {"table"})
	return not select(1, pcall(function()
		obj[random(8)] = nil
	end))
end)

-- Closures

add_global({"hookfunction", "replaceclosure", "hookfunc", "replacefunction", "replacefunc", "detourfunc", "detour_function"}, function(old, new)
	type_check(1, old, {"function"})
	type_check(2, new, {"function"}, true)
	xAPI.original_fenvs[old] = getfenv(old)
	return _cclosure(module("Hookfunction")(old, new))
end)

add_global({"restorefunction", "restore_function", "restore_func", "restoreclosure", "restore_closure"}, function(f)
	type_check(1, f, {"function"})
	setfenv(f, xAPI.original_fenvs[f] or getfenv(f))
end)

add_global({"emulate_call", "secure_call", "securecall"}, function(f, target, ...)
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
end)

add_global({"newcclosure", "new_c_closure"}, function(f)
	type_check(1, f, {"function"})
	return _cclosure(f)
end)

add_global({"newlclosure", "new_l_closure"}, function(f)
	type_check(1, f, {"function"})
	return function(...)
		return f(...)
	end
end)

add_global({"iscclosure", "is_c_closure"}, function(f)
	type_check(1, f, {"function"})    
	return debug.info(f, "s") == "[C]"
end)

add_global({"islclosure", "is_l_closure"}, function(f)
	type_check(1, f, {"function"})
	return debug.info(f, "s") ~= "[C]"
end)

add_global({"getclosureenvironment", "get_closure_environment"}, function(f)
	type_check(1, f, {"function"})
	return getfenv(f)
end)

add_global({"setclosureenvironment", "set_closure_environment"}, function(f, environment)
	type_check(1, f, {"function"})
	type_check(2, environment, {"table"})
	setfenv(f, environment)
	return f
end)

-- Variables

do
	local _G, shared = getfenv()._G, getfenv().shared
	add_global({"getreg", "get_register", "getregister"}, function()
		return debug.getregistry()
	end)

	add_global({"getgc", "get_garbage_collector", "getgarbagecollector"}, function()
		local gc, registry = {}, debug.getregistry()
		for _, value in ipairs(registry) do
			table.insert(gc, value)
		end
		return gc
	end)

	add_global({"getupvalue", "get_up_value"}, function(func, index)
		type_check(1, func, {"function"})
		type_check(2, index, {"number"})
		return debug.getupvalue(func, index)
	end)

	add_global({"setupvalue", "set_up_value"}, function(func, index, value)
		type_check(1, func, {"function"})
		type_check(2, index, {"number"})
		type_check(3, value, {"any"})
		debug.setupvalue(func, index, value)
	end)

	add_global({"getconstant", "get_constant"}, function(func, index)
		type_check(1, func, {"function"})
		type_check(2, index, {"number"})
		return debug.getconstant(func, index)
	end)

	add_global({"setconstant", "set_constant"}, function(func, index, value)
		type_check(1, func, {"function"})
		type_check(2, index, {"number"})
		type_check(3, value, {"any"})
		debug.setconstant(func, index, value)
	end)
end

xAPI.load()

return xAPI
