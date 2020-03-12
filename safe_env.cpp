#include "safe_env.hpp"

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <iostream>
#include <thread>
#include <future>
#include <cassert>

SafeEnv::SafeEnv(const std::string& sharename, bool safe, int timeout_secs)
 : m_safe_env(safe), m_share_name(sharename), m_timeout(timeout_secs)
{
	if (!safe) {
		assert(timeout_secs <= 0);
	}
}

static const int kSuccess = 42;

SafeEnv::Result
SafeEnv::operator()(const std::function<void()>& safe)
{
	// no safety required
	if (!m_safe_env) {
		safe();
		return Result::Success;
	}

	shm_unlink(m_share_name.c_str());
	// open the memory
	int shm_fd = shm_open(m_share_name.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRWXU | S_IRWXG);
	if (shm_fd < 0) {
		std::cerr << "Error in shm_open()" << std::endl;
		return Result::Error;
	}

	size_t msize = getpagesize();

	ftruncate(shm_fd, msize);

	// allocating the shared memory
	int* shared_memory = (int *) mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (shared_memory == MAP_FAILED) {
		std::cerr << "Error in mmap()" << std::endl;
		return Result::Error;
	}

	int pid = fork();

	if (!pid) {
		// child
		safe();

		shared_memory[0] = kSuccess;

		// terminate child successfully
		exit(0);
	} else if (pid > 0) {
		// master -> pid of child

		// wait until child exited
		int status;

		if (m_timeout > 0) {
			auto future = std::async(std::launch::async, &wait, &status);
			if (future.wait_for(std::chrono::seconds(m_timeout)) == std::future_status::timeout) {
				kill(pid, SIGKILL);
				shm_unlink(m_share_name.c_str());
				return Result::Timeout;
			}
		} else {
			int child_pid = wait(&status);
		}

		if (shared_memory[0] == kSuccess) {
			std::cerr << "Child exited with status successfully" << std::endl;
			shm_unlink(m_share_name.c_str());
			return Result::Success;
		}

		if (WIFEXITED(status)) {
			std::cerr << "Child exited with status " << WEXITSTATUS(status) << std::endl;
		}

		shm_unlink(m_share_name.c_str());
		return Result::Crash;
	} else {
		shm_unlink(m_share_name.c_str());
		std::cerr << "Cannot fork " << pid << std::endl;
		return Result::Error;
	}
}

std::string
SafeEnv::result2str(Result r)
{
	switch (r) {
#define A(n) case Result::n: return #n;
		A(Success);
		A(Crash);
		A(Timeout);
		A(Error);
	}

#undef A
	return "";
}
