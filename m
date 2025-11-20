Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA7A7TEAMGQERTXRMGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D417BC74C5A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:08 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-6407e61783fsf1202358a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651588; cv=pass;
        d=google.com; s=arc-20240605;
        b=OPSlZIQ+caU9iDzFcogim3KK2jFocwFcfVvL0jGQbFdK2wUAV+j8XxnejZafSm2CwG
         rwKzZr5SJx7INrUKCQn4SQeBBrDDjmG5Mk/6lk2O+WXVd2ERKg9IvKzlPpEznSCQ1/oy
         abbQm3uW7ICnZnAEJc5hEGAYaJr7Xf/guc8x2RoSvKIo5gfs2Yt8XxbUI5PagPvteKl7
         g8xfzTqukgHXWM6SKnVOgWOujroFABc3D5jtbkGpefIJxGjzcXaPJqGo4GaycFQ2aSeT
         7VAcsQgudrq9lM8FWR8Rdfvvbh19fTvJqYoJOJ3N7u3lhp5j3URL9nlk7ieHWPGwpdyD
         UXRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Dvi16UWhceZ5ezb7YwYGuBjOIFtUWMEXwZYljAzcXJA=;
        fh=oTawrN/ejo4xUzTG4CjNXHRIEvMvVCSmgRhHwXOH6RQ=;
        b=dKnNaq5tUuhXVcbsXjhZ37GKPKPu9ch/GDL+8VgDpmiIfa04XkOHTgMc6eewdfT2am
         oBOzRabvZm1eC+FHrKa5NTDzwH8ZUqpElgGTx6y52O+5Tfznyy8K1yT4YelTQqla/E2l
         TEkN3XClIgUaGaeJXvv/ILcBXiys8yMQojQ593YWsCiH+SOs2dsQx6xk6UrbltauYB2B
         QTzq+oUrYjgv/HelDpZOkcEq9qdd1MhBE/5spla15ZNubDmTEd80qRfP3Tve0gNkUSU+
         EC8W1baylhLKhzBdHiHoCFJ4+xVD3/O9KohX0QvGzczN+LfC5wLSMdyOjjkZ2SpZ62vb
         BZYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SJJHWtSt;
       spf=pass (google.com: domain of 3adafaqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ADAfaQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651588; x=1764256388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Dvi16UWhceZ5ezb7YwYGuBjOIFtUWMEXwZYljAzcXJA=;
        b=B67pow/imeEafJNBovu4RoqCZ6t+unA0A8gqXhzfXPjJi9Ck7yP4gNwuPK/2EQNErP
         wSzxW/6yLRTgiSpjOE4A4+acNmn7UJ2IBOfKpO62Tv9d+Gs0sbKECil8QZRj/r4gPlAg
         kiUhBFAUBtuyiFGh7642WOEg3T1nmVrV1qbQeLVFEntSxUrkpZdl9gzSBSR2jIYXRaxt
         LVdjiiK6+UIVEei0lduNokbHqkEI7oxPu3izGOG8pcHu9ZrqpZT9tXwtSCwhwzOeymAB
         mQiwVmKQX2P20erIXV/lUabVwo9nzLS3qiK5x/KolitdepoCe43Fh+5W0ufh4zv2hKyt
         fq6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651588; x=1764256388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dvi16UWhceZ5ezb7YwYGuBjOIFtUWMEXwZYljAzcXJA=;
        b=rxz5KUEFJpP30b3RpID4CkWZr+iTGE2tXryslS7hpx6/UtHWIIZPyT8ov+1MLWFNbM
         +3JuVAStsEFaa7DfvXGWItdcfInaEQGl3T5Mq6g9H2+C9IwaH0TgDAMomWxuMhLFGK0n
         hVh2bDCZ5AJQmQ1sFhfMWFPG/G6UsL9R6MXyp0ngCrpFdcQ5VO/pOxyANwaRoG4YXHXj
         ooL6bCaSatblyM1PV6zS5ZQS03MsqquEc6v2+nEnPJ0u95DnRkttrEy1/eqK3TMXmhxd
         EknhTq6AcZQFxVfG3O0g+JZkj3EVv4PeHa0g+MZblefeqGG96LG6pC4DERzvmfujA93x
         rfnQ==
X-Forwarded-Encrypted: i=2; AJvYcCXmiKIt9/5WpApLHJC4DVpV4iXHvTDRHqkgSlYjXpsynJkf1D11v2iOW0bcConVFX1KjHiChA==@lfdr.de
X-Gm-Message-State: AOJu0YwX4A85z0nbvmPndCDJpB7tiyANe6LgUBVmACDmApH0C4v5r6ci
	T8Kr1F26NmRFfm0ZhDxjC7JdaUXZ70NiBEFdRwrF9LG2EO0crf/5vjFN
X-Google-Smtp-Source: AGHT+IEs5kbdVWWoxwAB7ewAVcXPHgNEg7UILc/ibCG9RfQgz7sZsOs754uP0SgUNZdI9q65fOlp8Q==
X-Received: by 2002:a05:6402:28ca:b0:643:8301:d14e with SMTP id 4fb4d7f45d1cf-64536470716mr2826434a12.28.1763651588223;
        Thu, 20 Nov 2025 07:13:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YIm+KvQpLuUzr6g40UyXRJlaIyABjz19xIBdXX4xdI9A=="
Received: by 2002:aa7:d6d7:0:b0:643:8196:951 with SMTP id 4fb4d7f45d1cf-64536368161ls950350a12.0.-pod-prod-07-eu;
 Thu, 20 Nov 2025 07:13:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVV7uE3UMOwbkum++vRODApEbLTCRjvAOm5EiSDX6W/01EywRQp3CaSgZ/1PfkAGFdnuV9WKPBAkiQ=@googlegroups.com
X-Received: by 2002:a05:6402:4588:b0:637:e271:8087 with SMTP id 4fb4d7f45d1cf-6453644e443mr2698305a12.18.1763651585385;
        Thu, 20 Nov 2025 07:13:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651585; cv=none;
        d=google.com; s=arc-20240605;
        b=QegmmqZpYrNSWdD+zV1KkLHXPFrical5IKodiAIm5FyOi/BKuuXtWIrnxpQOJN4gBK
         WJ+nwK6dmOWAI6LUZSLMf+AN07+iuo34Oz1hKycFe/idsa/QAppl9d0IYTnnxrkU3Emz
         HfJuIW68INPEE1w8zNNSdJPiBA/32Vk61OgwxRvTrxvALK+cI+RV7EyEzKAIUXTWds0C
         gIKwVUzkbG7obLVq8tPmETlEoZkW1ygklKVELZivNU0xj0BDJcLtbYVly2MDw+NYNXq7
         gv+HeeeGDm/gNraRpATzjaTQY0cHX1qh90J34SdxUViLOrzs6M4EASnKICvttaZWZpwW
         o6Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bGtcXg38DvnDW7LCtn8VPS4tEIyxPZjVcXoXmWDrgp8=;
        fh=n60qiFiu9OpOE0qRQ1iIK28s2bpLH+CsnFMhYGDNGNM=;
        b=C6VUfSrcKVEWj0Xu4j828/s01kr+TlTBFvoq3jZ8Qt4dJ7OS4Wb2+OQvoKDSzyy3Q0
         ddJw3jcJmqA9Itte+piAxMqzE93N8n00VyMkLFniVNu+V/QKk18QNE0vGHjSQ5vh1eNm
         gjcR4ooqKbR1z0eBtwehiLUaqjIwFy7hB7b3wg9Sf4/Xtt1LiohZOLoPbwGeE2H8Au02
         C7aKJyJkVFEM4rOzMMYQqj8xqgP4RNEEgjlb45rA8UssK5fV5OGcdgx9G/j9Wu7DDjGF
         G9siiW/xUUNHHuRwEZA2UfUuEoDzm+pyGq0nkelQ7rZADpv6/ZCJZDBvP8bLBwW6QRvF
         6/Bw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SJJHWtSt;
       spf=pass (google.com: domain of 3adafaqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ADAfaQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6453648cf50si73496a12.9.2025.11.20.07.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3adafaqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-429c5f1e9faso1058951f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZk0V/UsmjyJ2+ic9hq1mBLIt1zrKDrk6rGPBBTwM94PmE9QoiHzc4xUn3A6U60HjWakvRno0OKkE=@googlegroups.com
X-Received: from wraj7.prod.google.com ([2002:a5d:4527:0:b0:42b:2aa2:e459])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2406:b0:42b:4081:ccb8
 with SMTP id ffacd0b85a97d-42cb9a1d969mr3010427f8f.23.1763651584236; Thu, 20
 Nov 2025 07:13:04 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:44 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-20-elver@google.com>
Subject: [PATCH v4 19/35] locking/local_lock: Support Clang's context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SJJHWtSt;       spf=pass
 (google.com: domain of 3adafaqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ADAfaQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Add support for Clang's context analysis for local_lock_t and
local_trylock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
* Rework __this_cpu_local_lock helper
* Support local_trylock_t
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/local_lock.h                   | 45 ++++++------
 include/linux/local_lock_internal.h          | 71 +++++++++++++++----
 lib/test_context-analysis.c                  | 73 ++++++++++++++++++++
 4 files changed, 156 insertions(+), 35 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index dc7ae4f641f2..8737de63a707 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -81,7 +81,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/local_lock.h b/include/linux/local_lock.h
index 0d91d060e3e9..a83458bebe97 100644
--- a/include/linux/local_lock.h
+++ b/include/linux/local_lock.h
@@ -13,13 +13,13 @@
  * local_lock - Acquire a per CPU local lock
  * @lock:	The lock variable
  */
-#define local_lock(lock)		__local_lock(this_cpu_ptr(lock))
+#define local_lock(lock)		__local_lock(__this_cpu_local_lock(lock))
 
 /**
  * local_lock_irq - Acquire a per CPU local lock and disable interrupts
  * @lock:	The lock variable
  */
-#define local_lock_irq(lock)		__local_lock_irq(this_cpu_ptr(lock))
+#define local_lock_irq(lock)		__local_lock_irq(__this_cpu_local_lock(lock))
 
 /**
  * local_lock_irqsave - Acquire a per CPU local lock, save and disable
@@ -28,19 +28,19 @@
  * @flags:	Storage for interrupt flags
  */
 #define local_lock_irqsave(lock, flags)				\
-	__local_lock_irqsave(this_cpu_ptr(lock), flags)
+	__local_lock_irqsave(__this_cpu_local_lock(lock), flags)
 
 /**
  * local_unlock - Release a per CPU local lock
  * @lock:	The lock variable
  */
-#define local_unlock(lock)		__local_unlock(this_cpu_ptr(lock))
+#define local_unlock(lock)		__local_unlock(__this_cpu_local_lock(lock))
 
 /**
  * local_unlock_irq - Release a per CPU local lock and enable interrupts
  * @lock:	The lock variable
  */
-#define local_unlock_irq(lock)		__local_unlock_irq(this_cpu_ptr(lock))
+#define local_unlock_irq(lock)		__local_unlock_irq(__this_cpu_local_lock(lock))
 
 /**
  * local_unlock_irqrestore - Release a per CPU local lock and restore
@@ -49,7 +49,7 @@
  * @flags:      Interrupt flags to restore
  */
 #define local_unlock_irqrestore(lock, flags)			\
-	__local_unlock_irqrestore(this_cpu_ptr(lock), flags)
+	__local_unlock_irqrestore(__this_cpu_local_lock(lock), flags)
 
 /**
  * local_lock_init - Runtime initialize a lock instance
@@ -64,7 +64,7 @@
  * locking constrains it will _always_ fail to acquire the lock in NMI or
  * HARDIRQ context on PREEMPT_RT.
  */
-#define local_trylock(lock)		__local_trylock(this_cpu_ptr(lock))
+#define local_trylock(lock)		__local_trylock(__this_cpu_local_lock(lock))
 
 #define local_lock_is_locked(lock)	__local_lock_is_locked(lock)
 
@@ -79,27 +79,32 @@
  * HARDIRQ context on PREEMPT_RT.
  */
 #define local_trylock_irqsave(lock, flags)			\
-	__local_trylock_irqsave(this_cpu_ptr(lock), flags)
-
-DEFINE_GUARD(local_lock, local_lock_t __percpu*,
-	     local_lock(_T),
-	     local_unlock(_T))
-DEFINE_GUARD(local_lock_irq, local_lock_t __percpu*,
-	     local_lock_irq(_T),
-	     local_unlock_irq(_T))
+	__local_trylock_irqsave(__this_cpu_local_lock(lock), flags)
+
+DEFINE_LOCK_GUARD_1(local_lock, local_lock_t __percpu,
+		    local_lock(_T->lock),
+		    local_unlock(_T->lock))
+DEFINE_LOCK_GUARD_1(local_lock_irq, local_lock_t __percpu,
+		    local_lock_irq(_T->lock),
+		    local_unlock_irq(_T->lock))
 DEFINE_LOCK_GUARD_1(local_lock_irqsave, local_lock_t __percpu,
 		    local_lock_irqsave(_T->lock, _T->flags),
 		    local_unlock_irqrestore(_T->lock, _T->flags),
 		    unsigned long flags)
 
 #define local_lock_nested_bh(_lock)				\
-	__local_lock_nested_bh(this_cpu_ptr(_lock))
+	__local_lock_nested_bh(__this_cpu_local_lock(_lock))
 
 #define local_unlock_nested_bh(_lock)				\
-	__local_unlock_nested_bh(this_cpu_ptr(_lock))
+	__local_unlock_nested_bh(__this_cpu_local_lock(_lock))
 
-DEFINE_GUARD(local_lock_nested_bh, local_lock_t __percpu*,
-	     local_lock_nested_bh(_T),
-	     local_unlock_nested_bh(_T))
+DEFINE_LOCK_GUARD_1(local_lock_nested_bh, local_lock_t __percpu,
+		    local_lock_nested_bh(_T->lock),
+		    local_unlock_nested_bh(_T->lock))
+
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irq, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irqsave, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, __assumes_ctx_guard(_T), /* */)
 
 #endif
diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index 9f6cb32f04b0..17b8135bd2c3 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -10,21 +10,23 @@
 
 #ifndef CONFIG_PREEMPT_RT
 
-typedef struct {
+context_guard_struct(local_lock) {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
 	struct task_struct	*owner;
 #endif
-} local_lock_t;
+};
+typedef struct local_lock local_lock_t;
 
 /* local_trylock() and local_trylock_irqsave() only work with local_trylock_t */
-typedef struct {
+context_guard_struct(local_trylock) {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
 	struct task_struct	*owner;
 #endif
 	u8		acquired;
-} local_trylock_t;
+};
+typedef struct local_trylock local_trylock_t;
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 # define LOCAL_LOCK_DEBUG_INIT(lockname)		\
@@ -84,9 +86,14 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
+	__assume_ctx_guard(lock);				\
 } while (0)
 
-#define __local_trylock_init(lock) __local_lock_init((local_lock_t *)lock)
+#define __local_trylock_init(lock)				\
+do {								\
+	__local_lock_init((local_lock_t *)lock);		\
+	__assume_ctx_guard(lock);				\
+} while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
 do {								\
@@ -97,6 +104,7 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
+	__assume_ctx_guard(lock);				\
 } while (0)
 
 #define __local_lock_acquire(lock)					\
@@ -119,22 +127,25 @@ do {								\
 	do {							\
 		preempt_disable();				\
 		__local_lock_acquire(lock);			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irq(lock)					\
 	do {							\
 		local_irq_disable();				\
 		__local_lock_acquire(lock);			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irqsave(lock, flags)			\
 	do {							\
 		local_irq_save(flags);				\
 		__local_lock_acquire(lock);			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_trylock(lock)					\
-	({							\
+	__try_acquire_ctx_guard(lock, ({				\
 		local_trylock_t *tl;				\
 								\
 		preempt_disable();				\
@@ -148,10 +159,10 @@ do {								\
 				(local_lock_t *)tl);		\
 		}						\
 		!!tl;						\
-	})
+	}))
 
 #define __local_trylock_irqsave(lock, flags)			\
-	({							\
+	__try_acquire_ctx_guard(lock, ({				\
 		local_trylock_t *tl;				\
 								\
 		local_irq_save(flags);				\
@@ -165,7 +176,7 @@ do {								\
 				(local_lock_t *)tl);		\
 		}						\
 		!!tl;						\
-	})
+	}))
 
 /* preemption or migration must be disabled before calling __local_lock_is_locked */
 #define __local_lock_is_locked(lock) READ_ONCE(this_cpu_ptr(lock)->acquired)
@@ -188,18 +199,21 @@ do {								\
 
 #define __local_unlock(lock)					\
 	do {							\
+		__release(lock);				\
 		__local_lock_release(lock);			\
 		preempt_enable();				\
 	} while (0)
 
 #define __local_unlock_irq(lock)				\
 	do {							\
+		__release(lock);				\
 		__local_lock_release(lock);			\
 		local_irq_enable();				\
 	} while (0)
 
 #define __local_unlock_irqrestore(lock, flags)			\
 	do {							\
+		__release(lock);				\
 		__local_lock_release(lock);			\
 		local_irq_restore(flags);			\
 	} while (0)
@@ -208,13 +222,19 @@ do {								\
 	do {							\
 		lockdep_assert_in_softirq();			\
 		local_lock_acquire((lock));			\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_unlock_nested_bh(lock)				\
-	local_lock_release((lock))
+	do {							\
+		__release(lock);				\
+		local_lock_release((lock));			\
+	} while (0)
 
 #else /* !CONFIG_PREEMPT_RT */
 
+#include <linux/spinlock.h>
+
 /*
  * On PREEMPT_RT local_lock maps to a per CPU spinlock, which protects the
  * critical section while staying preemptible.
@@ -269,7 +289,7 @@ do {								\
 } while (0)
 
 #define __local_trylock(lock)					\
-	({							\
+	__try_acquire_ctx_guard(lock, context_unsafe(({		\
 		int __locked;					\
 								\
 		if (in_nmi() | in_hardirq()) {			\
@@ -281,17 +301,40 @@ do {								\
 				migrate_enable();		\
 		}						\
 		__locked;					\
-	})
+	})))
 
 #define __local_trylock_irqsave(lock, flags)			\
-	({							\
+	__try_acquire_ctx_guard(lock, ({			\
 		typecheck(unsigned long, flags);		\
 		flags = 0;					\
 		__local_trylock(lock);				\
-	})
+	}))
 
 /* migration must be disabled before calling __local_lock_is_locked */
 #define __local_lock_is_locked(__lock)					\
 	(rt_mutex_owner(&this_cpu_ptr(__lock)->lock) == current)
 
 #endif /* CONFIG_PREEMPT_RT */
+
+#if defined(WARN_CONTEXT_ANALYSIS)
+/*
+ * Because the compiler only knows about the base per-CPU variable, use this
+ * helper function to make the compiler think we lock/unlock the @base variable,
+ * and hide the fact we actually pass the per-CPU instance to lock/unlock
+ * functions.
+ */
+static __always_inline local_lock_t *__this_cpu_local_lock(local_lock_t __percpu *base)
+	__returns_ctx_guard(base) __attribute__((overloadable))
+{
+	return this_cpu_ptr(base);
+}
+#ifndef CONFIG_PREEMPT_RT
+static __always_inline local_trylock_t *__this_cpu_local_lock(local_trylock_t __percpu *base)
+	__returns_ctx_guard(base) __attribute__((overloadable))
+{
+	return this_cpu_ptr(base);
+}
+#endif /* CONFIG_PREEMPT_RT */
+#else  /* WARN_CONTEXT_ANALYSIS */
+#define __this_cpu_local_lock(base) this_cpu_ptr(base)
+#endif /* WARN_CONTEXT_ANALYSIS */
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 2203a57cd40d..74eca21f7aaa 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -6,7 +6,9 @@
 
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
+#include <linux/local_lock.h>
 #include <linux/mutex.h>
+#include <linux/percpu.h>
 #include <linux/rcupdate.h>
 #include <linux/rwsem.h>
 #include <linux/seqlock.h>
@@ -450,3 +452,74 @@ static void __used test_srcu_guard(struct test_srcu_data *d)
 	guard(srcu)(&d->srcu);
 	(void)srcu_dereference(d->data, &d->srcu);
 }
+
+struct test_local_lock_data {
+	local_lock_t lock;
+	int counter __guarded_by(&lock);
+};
+
+static DEFINE_PER_CPU(struct test_local_lock_data, test_local_lock_data) = {
+	.lock = INIT_LOCAL_LOCK(lock),
+};
+
+static void __used test_local_lock_init(struct test_local_lock_data *d)
+{
+	local_lock_init(&d->lock);
+	d->counter = 0;
+}
+
+static void __used test_local_lock(void)
+{
+	unsigned long flags;
+
+	local_lock(&test_local_lock_data.lock);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock(&test_local_lock_data.lock);
+
+	local_lock_irq(&test_local_lock_data.lock);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock_irq(&test_local_lock_data.lock);
+
+	local_lock_irqsave(&test_local_lock_data.lock, flags);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock_irqrestore(&test_local_lock_data.lock, flags);
+
+	local_lock_nested_bh(&test_local_lock_data.lock);
+	this_cpu_add(test_local_lock_data.counter, 1);
+	local_unlock_nested_bh(&test_local_lock_data.lock);
+}
+
+static void __used test_local_lock_guard(void)
+{
+	{ guard(local_lock)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+	{ guard(local_lock_irq)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+	{ guard(local_lock_irqsave)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+	{ guard(local_lock_nested_bh)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
+}
+
+struct test_local_trylock_data {
+	local_trylock_t lock;
+	int counter __guarded_by(&lock);
+};
+
+static DEFINE_PER_CPU(struct test_local_trylock_data, test_local_trylock_data) = {
+	.lock = INIT_LOCAL_TRYLOCK(lock),
+};
+
+static void __used test_local_trylock_init(struct test_local_trylock_data *d)
+{
+	local_trylock_init(&d->lock);
+	d->counter = 0;
+}
+
+static void __used test_local_trylock(void)
+{
+	local_lock(&test_local_trylock_data.lock);
+	this_cpu_add(test_local_trylock_data.counter, 1);
+	local_unlock(&test_local_trylock_data.lock);
+
+	if (local_trylock(&test_local_trylock_data.lock)) {
+		this_cpu_add(test_local_trylock_data.counter, 1);
+		local_unlock(&test_local_trylock_data.lock);
+	}
+}
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-20-elver%40google.com.
