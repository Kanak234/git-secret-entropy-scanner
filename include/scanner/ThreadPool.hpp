#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace scanner {

class ThreadPool {
public:
  explicit ThreadPool(size_t threads = std::thread::hardware_concurrency()) {
    if (threads == 0)
      threads = 4;
    for (size_t i = 0; i < threads; ++i) {
      workers_.emplace_back([this] {
        while (true) {
          std::function<void()> task;
          {
            std::unique_lock<std::mutex> lock(queueMutex_);
            cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
            if (stop_ && tasks_.empty())
              return;
            task = std::move(tasks_.front());
            tasks_.pop();
          }
          task();
          {
            std::lock_guard<std::mutex> lock(queueMutex_);
            --activeTasks_;
            if (activeTasks_ == 0 && tasks_.empty()) {
              doneCv_.notify_all();
            }
          }
        }
      });
    }
  }

  ~ThreadPool() {
    {
      std::lock_guard<std::mutex> lock(queueMutex_);
      stop_ = true;
    }
    cv_.notify_all();
    for (auto &worker : workers_) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

  void enqueue(std::function<void()> task) {
    {
      std::lock_guard<std::mutex> lock(queueMutex_);
      tasks_.push(std::move(task));
      ++activeTasks_;
    }
    cv_.notify_one();
  }

  void waitAll() {
    std::unique_lock<std::mutex> lock(queueMutex_);
    doneCv_.wait(lock, [this] { return activeTasks_ == 0 && tasks_.empty(); });
  }

private:
  std::vector<std::thread> workers_;
  std::queue<std::function<void()>> tasks_;
  std::mutex queueMutex_;
  std::condition_variable cv_;
  std::condition_variable doneCv_;
  size_t activeTasks_{0};
  bool stop_{false};
};

} // namespace scanner
