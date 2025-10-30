-- File: services/authentication_service/redis-scripts/register_user.lua
--
-- Atomically registers a new user in Redis.
-- This script is designed to be loaded and called as a Redis Function.
-- It uses the 'keys' and 'args' parameters provided by the Functions API.
--
-- keys[1]: The username being registered (e.g., "monty")
-- keys[2]: The email being registered (e.g., "monty@grewal.cc")
--
-- args[1]: The new user's unique ID (UUID)
-- args[2]: The securely hashed password
-- args[3]: The creation timestamp (ISO 8601 string)
-- args[4]: A comma-separated string of user roles (e.g., "user")

-- Step 1: Atomically check if the username index already exists.
if redis.call('EXISTS', 'user:username:' .. keys[1]) == 1 then
  return 'ERR_USERNAME_EXISTS'
end

-- Step 2: Atomically check if the email index already exists.
if redis.call('EXISTS', 'user:email:' .. keys[2]) == 1 then
  return 'ERR_EMAIL_EXISTS'
end

-- Step 3: All checks passed. Proceed with atomic creation.
local user_id = args[1]
local user_key = 'user:' .. user_id

-- Create the main user object as a Redis Hash.
redis.call('HSET', user_key,
  'user_id',       user_id,
  'username',      keys[1],
  'email',         keys[2],
  'password_hash', args[2],
  'created_at',    args[3],
  'roles',         args[4]
)

-- Create the secondary index for username-to-UUID lookup.
redis.call('SET', 'user:username:' .. keys[1], user_id)

-- Create the secondary index for email-to-UUID lookup.
redis.call('SET', 'user:email:' .. keys[2], user_id)

-- Step 4: Return a success code.
return 'OK'
