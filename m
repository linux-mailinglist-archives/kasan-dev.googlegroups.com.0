Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ7GSXFAMGQEEWHLO5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C078CD098F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:49 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59584152ed3sf1430713e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159208; cv=pass;
        d=google.com; s=arc-20240605;
        b=J4W1BCMDmQwFkWubCbBz1BUFPlBufGFNAlffaz8bZUF60dJcez2bDnggvz9iXSY5+9
         8ogmCVqh3VexlrEOKkO+LnQ4MwZwpT8FxURraqJJ0abtR1Qr+m8tJqCnChDJPjiNyb/B
         xS3SDx+VSPjoJNU3N28oxW6jg+gn5lgD72p3qJaqVVAVPo6FF/3emyHRpQBD2cD4mNb7
         IRVTzpNODzZMupAvWupNBLw95txso3En7QQqMcpX9t5ZYMfyh6loaptk516PUjmywO9+
         urLfQD8rSW0TFYQ86vv5dgkRQkkTLRXRXymeNGlWMrbIuwL1m6wxbdLPAKZXmbt7YJoz
         5UZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tM3BwBCwPfYmLp/JUrqPsY+vOlOFS6aS5LHT1mNFJzY=;
        fh=2d424f4+tatGA3tbapML6w3CCHahpcpwLIyLe+6Of9M=;
        b=b3pTzop7kRVuBxV9sps1F0dsB0krAtewCjluNIGsKjPuGGYleF46mGP9A1JFwT9iyu
         j5viSspiOR0M0BXBpXSIkLYFPEct6nR2HnIwLsvnlZFzRQLnkTtXct7K3Ec4G69lBzRX
         fS5sp8FLPnR8h0/4iefzFwIZ2nMcXtml2+LKuC/cqmgzU1rwVEbM7JY0xwxaMp11k/sO
         ZEwT0ZQsku7FTx9pBLzaqB8Fz1lNzSo9ngDMImrcDS7tEcTGrqABp0Ch0JgX69brE82N
         8caFLInRLSoHfdU58Mi9KUZ8EWgdBeblxaFF6LqSgrOPz77E248QgE73TN5O91h4Srl9
         7w/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CHmzUpVr;
       spf=pass (google.com: domain of 3zhnfaqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ZHNFaQUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159208; x=1766764008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tM3BwBCwPfYmLp/JUrqPsY+vOlOFS6aS5LHT1mNFJzY=;
        b=hYbTEa5x8kTU8dnirhFWhKmAk5IptoR2aOCsAW9kgx7KgSKfGW/3nxL/tvNu49Kx1A
         i83eFua6zl7UAhgQECC+WC7Ndsof5ldRtjCHl2OD5ih9dJViVm9WgOyBVbd4nUM7COsX
         iaOhPWqOOOBre70J2uvoCt8dc6HDwWRC4gJgFWfqMj6u0b2CVscyBstBR9Nz4FyuDiVm
         TMQ3ACtUHKhnOYth69yDXEUenjzT9nb3BtnKx24viC+JCyfoO2iH0k9MAQBpWfgTOpFb
         VBf0C/kdC/pThdTL6YSxtu3ID+21kdlF+aZ8SQ7moTXjTlW4O/e6tZDYZmvHDx6/EJC3
         tubg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159208; x=1766764008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tM3BwBCwPfYmLp/JUrqPsY+vOlOFS6aS5LHT1mNFJzY=;
        b=Wax8fQtXKPQPcIQc3HK6HKDqOi2enFtFGprPPdjQUfJytOyBcAYPxD1MjHoIbOtoSR
         LzWBp+yZz2cLEMETM/0fNLBG4MOEbH7did5hGjF2eQ3cP71d6jx0QU0QndhdAduds+4i
         H+eH3kRS3Yvqalzxal5He4MO5e1R9F9tHk1BK7JmPVe2DX/r0Ow+TwQJkxaSDSxFZ36b
         XzKVvkC2Juid/jJgcrs7+Ghxt9JVRRhNwznGrmmaQIJ06g3w5mVXkDMhwyXvTGgzjR3+
         QQ16C2ESTKfqIF5JRfIgZ5wM/xfan3EfCaFpt7kT7f3vGfoY3uyQLmcr3mFT5sGCrqf+
         DG5A==
X-Forwarded-Encrypted: i=2; AJvYcCVav4CMAs4WmvOgMZE4VVfWIl295jnZowjTD58tAERiRG6ZnyEx1e3OT5Ykw7bNxd8F3G8UEg==@lfdr.de
X-Gm-Message-State: AOJu0YyQFk913zhpcud9fEJN+enlOKjE6YtmX6v5OS8mNMbG0hLXHJ9o
	8vkYG9gb3OTUibQa72CWOTrxh6IfCZwATxZwJJefSrHZQLt1lwIqsB3/
X-Google-Smtp-Source: AGHT+IHZl4jOtEhEFkgocJ1N/YLBvUYSG2e/YXGTEbIZDC1bBpdUxJCDMM9tT4rdO0C/eaXHQiKW+A==
X-Received: by 2002:a05:6512:2388:b0:594:4ebf:e6df with SMTP id 2adb3069b0e04-59a17d77963mr1295558e87.15.1766159208504;
        Fri, 19 Dec 2025 07:46:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWacRRUs9gGwxOdGeRKk3bsgYlWbna2UV+jdUo5nPk0mnw=="
Received: by 2002:a05:6512:ba2:b0:598:f802:e2dd with SMTP id
 2adb3069b0e04-598fa391dd1ls116377e87.0.-pod-prod-04-eu; Fri, 19 Dec 2025
 07:46:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX+HuI4bKNSkULdcLPFRU3z4UtPEh7qMW3c3ROFh0oVG8CBVGoe+oq3X7z+JEePxiySLDE0+4jcg1o=@googlegroups.com
X-Received: by 2002:a05:6512:e8c:b0:571:8fad:ecee with SMTP id 2adb3069b0e04-59a17d8f8c9mr1289344e87.21.1766159205474;
        Fri, 19 Dec 2025 07:46:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159205; cv=none;
        d=google.com; s=arc-20240605;
        b=fHjguEKJDLUPYsfh1kx4RzcW+MibE3YuE8dxy4/O5KGZyfU6FiAi78R4gGtXjdMuMi
         dpxnK06rYHBth0WMSIWljikoMbnywou5Vgd109LS+uPZzAc+fWDmmohgbGiMvcNAjijo
         ZxylnQqGkD+EeGpQ8+ecLqCBrH1xxIS4pkEJCdYjvqpjOg4huxtT0MGRvh/4O3fVhvzB
         bT02RpmLz9QTmvEZ58MNBLzR8m8EdW2NbaCO9HtCeEJayyiIRNYqUm2sZ7IWY1nqNMua
         9BRgQApU+GOtEpmv/MRHKrbTG4MgM4Ddk/Mjxb8RHK1ZYlKCWCVbD9msMkr1wx8xqMVr
         lbrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P8y2ehCZZyqeLeTmnnsrT76N1owOcsxeMFhfj7fOlbU=;
        fh=UeQCJXSHp4DoEb/51q9SfwztUCsOqHvyLDPpj5Vn7OA=;
        b=dvFqJP0rqNHX2Tc76V9B4RD+luZTn2iEgHvJizYyMODu+w3VMK62c5EP2URTBFz/M8
         EJ7NWUwid6usDV4YsiYPM/kMhVb2p52PhL0f9bXsg0JH8QnR3tgvWsw5A7iZrUMhPwFk
         jzVrVCbAWLKJVYOVSZLzPidqLm8Xcm1axeY/64XbG865+j4X/cwtHi7Jh8XWVkctCsWr
         HZeoQWL/QGyJCnXMXSK1/zhoc6ka2XgCg+facrZnmw+vRWMWgwNWlw0bK4gR7Miy1EwO
         c5QWUs5le7bi1bC+QFWcI2fpag4p/t6/ovoMmTSffX5Ybz/6A3PSTrAiZ9lvD3zD1O/O
         2ZGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CHmzUpVr;
       spf=pass (google.com: domain of 3zhnfaqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ZHNFaQUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a18613c00si68640e87.6.2025.12.19.07.46.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zhnfaqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-42fdbba545fso1521779f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWD3iXnpr6Gpz+fWB5a51U8pVbXwR5flomfxSYr2+ecdEALxDXg/PUAZfF3MoiARWNYTeHo8eOJ9Ig=@googlegroups.com
X-Received: from wrbay2.prod.google.com ([2002:a5d:6f02:0:b0:430:f3bf:123f])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:1789:b0:431:2ff:128f
 with SMTP id ffacd0b85a97d-4324e3ebfbbmr4354092f8f.6.1766159204463; Fri, 19
 Dec 2025 07:46:44 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:09 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-21-elver@google.com>
Subject: [PATCH v5 20/36] locking/ww_mutex: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=CHmzUpVr;       spf=pass
 (google.com: domain of 3zhnfaqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ZHNFaQUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for ww_mutex.

The programming model for ww_mutex is subtly more complex than other
locking primitives when using ww_acquire_ctx. Encoding the respective
pre-conditions for ww_mutex lock/unlock based on ww_acquire_ctx state
using Clang's context analysis makes incorrect use of the API harder.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.

v3:
* __assert -> __assume rename

v2:
* New patch.
---
 Documentation/dev-tools/context-analysis.rst |  3 +-
 include/linux/ww_mutex.h                     | 22 +++++--
 lib/test_context-analysis.c                  | 69 ++++++++++++++++++++
 3 files changed, 87 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index a48b75f45e79..8dd6c0d695aa 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,8 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`,
+`ww_mutex`.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 45ff6f7a872b..58e959ee10e9 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -44,7 +44,7 @@ struct ww_class {
 	unsigned int is_wait_die;
 };
 
-struct ww_mutex {
+context_lock_struct(ww_mutex) {
 	struct WW_MUTEX_BASE base;
 	struct ww_acquire_ctx *ctx;
 #ifdef DEBUG_WW_MUTEXES
@@ -52,7 +52,7 @@ struct ww_mutex {
 #endif
 };
 
-struct ww_acquire_ctx {
+context_lock_struct(ww_acquire_ctx) {
 	struct task_struct *task;
 	unsigned long stamp;
 	unsigned int acquired;
@@ -107,6 +107,7 @@ struct ww_acquire_ctx {
  */
 static inline void ww_mutex_init(struct ww_mutex *lock,
 				 struct ww_class *ww_class)
+	__assumes_ctx_lock(lock)
 {
 	ww_mutex_base_init(&lock->base, ww_class->mutex_name, &ww_class->mutex_key);
 	lock->ctx = NULL;
@@ -141,6 +142,7 @@ static inline void ww_mutex_init(struct ww_mutex *lock,
  */
 static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
 				   struct ww_class *ww_class)
+	__acquires(ctx) __no_context_analysis
 {
 	ctx->task = current;
 	ctx->stamp = atomic_long_inc_return_relaxed(&ww_class->stamp);
@@ -179,6 +181,7 @@ static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
  * data structures.
  */
 static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
+	__releases(ctx) __acquires_shared(ctx) __no_context_analysis
 {
 #ifdef DEBUG_WW_MUTEXES
 	lockdep_assert_held(ctx);
@@ -196,6 +199,7 @@ static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
  * mutexes have been released with ww_mutex_unlock.
  */
 static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
+	__releases_shared(ctx) __no_context_analysis
 {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	mutex_release(&ctx->first_lock_dep_map, _THIS_IP_);
@@ -245,7 +249,8 @@ static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
  *
  * A mutex acquired with this function must be released with ww_mutex_unlock.
  */
-extern int /* __must_check */ ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx);
+extern int /* __must_check */ ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
+	__cond_acquires(0, lock) __must_hold(ctx);
 
 /**
  * ww_mutex_lock_interruptible - acquire the w/w mutex, interruptible
@@ -278,7 +283,8 @@ extern int /* __must_check */ ww_mutex_lock(struct ww_mutex *lock, struct ww_acq
  * A mutex acquired with this function must be released with ww_mutex_unlock.
  */
 extern int __must_check ww_mutex_lock_interruptible(struct ww_mutex *lock,
-						    struct ww_acquire_ctx *ctx);
+						    struct ww_acquire_ctx *ctx)
+	__cond_acquires(0, lock) __must_hold(ctx);
 
 /**
  * ww_mutex_lock_slow - slowpath acquiring of the w/w mutex
@@ -305,6 +311,7 @@ extern int __must_check ww_mutex_lock_interruptible(struct ww_mutex *lock,
  */
 static inline void
 ww_mutex_lock_slow(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
+	__acquires(lock) __must_hold(ctx) __no_context_analysis
 {
 	int ret;
 #ifdef DEBUG_WW_MUTEXES
@@ -342,6 +349,7 @@ ww_mutex_lock_slow(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
 static inline int __must_check
 ww_mutex_lock_slow_interruptible(struct ww_mutex *lock,
 				 struct ww_acquire_ctx *ctx)
+	__cond_acquires(0, lock) __must_hold(ctx)
 {
 #ifdef DEBUG_WW_MUTEXES
 	DEBUG_LOCKS_WARN_ON(!ctx->contending_lock);
@@ -349,10 +357,11 @@ ww_mutex_lock_slow_interruptible(struct ww_mutex *lock,
 	return ww_mutex_lock_interruptible(lock, ctx);
 }
 
-extern void ww_mutex_unlock(struct ww_mutex *lock);
+extern void ww_mutex_unlock(struct ww_mutex *lock) __releases(lock);
 
 extern int __must_check ww_mutex_trylock(struct ww_mutex *lock,
-					 struct ww_acquire_ctx *ctx);
+					 struct ww_acquire_ctx *ctx)
+	__cond_acquires(true, lock) __must_hold(ctx);
 
 /***
  * ww_mutex_destroy - mark a w/w mutex unusable
@@ -363,6 +372,7 @@ extern int __must_check ww_mutex_trylock(struct ww_mutex *lock,
  * this function is called.
  */
 static inline void ww_mutex_destroy(struct ww_mutex *lock)
+	__must_not_hold(lock)
 {
 #ifndef CONFIG_PREEMPT_RT
 	mutex_destroy(&lock->base);
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 003e64cac540..2dc404456497 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -14,6 +14,7 @@
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 #include <linux/srcu.h>
+#include <linux/ww_mutex.h>
 
 /*
  * Test that helper macros work as expected.
@@ -531,3 +532,71 @@ static void __used test_local_trylock(void)
 		local_unlock(&test_local_trylock_data.lock);
 	}
 }
+
+static DEFINE_WD_CLASS(ww_class);
+
+struct test_ww_mutex_data {
+	struct ww_mutex mtx;
+	int counter __guarded_by(&mtx);
+};
+
+static void __used test_ww_mutex_init(struct test_ww_mutex_data *d)
+{
+	ww_mutex_init(&d->mtx, &ww_class);
+	d->counter = 0;
+}
+
+static void __used test_ww_mutex_lock_noctx(struct test_ww_mutex_data *d)
+{
+	if (!ww_mutex_lock(&d->mtx, NULL)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (!ww_mutex_lock_interruptible(&d->mtx, NULL)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (ww_mutex_trylock(&d->mtx, NULL)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	ww_mutex_lock_slow(&d->mtx, NULL);
+	d->counter++;
+	ww_mutex_unlock(&d->mtx);
+
+	ww_mutex_destroy(&d->mtx);
+}
+
+static void __used test_ww_mutex_lock_ctx(struct test_ww_mutex_data *d)
+{
+	struct ww_acquire_ctx ctx;
+
+	ww_acquire_init(&ctx, &ww_class);
+
+	if (!ww_mutex_lock(&d->mtx, &ctx)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (!ww_mutex_lock_interruptible(&d->mtx, &ctx)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	if (ww_mutex_trylock(&d->mtx, &ctx)) {
+		d->counter++;
+		ww_mutex_unlock(&d->mtx);
+	}
+
+	ww_mutex_lock_slow(&d->mtx, &ctx);
+	d->counter++;
+	ww_mutex_unlock(&d->mtx);
+
+	ww_acquire_done(&ctx);
+	ww_acquire_fini(&ctx);
+
+	ww_mutex_destroy(&d->mtx);
+}
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-21-elver%40google.com.
