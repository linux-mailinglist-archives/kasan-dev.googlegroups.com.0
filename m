Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLMOTO7AMGQEPH5L4IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id CCA83A4D812
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:07 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-390f6aa50c5sf2006219f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080367; cv=pass;
        d=google.com; s=arc-20240605;
        b=B8tPRqYg9RYTjsrV6YfaSu0hMbQFFJARLb8s2Gse6+lW8OnrLvbSwsOCsD+ctDN4v4
         MGvouswarJjnWVEmzc+ir9WsoE9cmct5Fp8JtccCbwfYgqenth/gv7g45z8DDWWR5ZyC
         9T5QUk2yI3CnewlyV8jv3NzOKkUcimSc6Gmf4Z84NzcHidRjGSsfv//6XmjS1gb/fMX2
         2XY2VnL85tslYwmpKWTmxI00fLN54udw792WPqHsdcVCB3HXIajYXmWZSDx7EaXgwUqd
         4qIR2Lj1u460XbVJHehu5dZV1i/s4DbXW/wNLCKyh2qfO9ojs1tWU9cp21/Kb70vGA68
         b0oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ri103XSh4oz5KysfkmNNkkVOGaSq9I77Uqs9nhMpVJQ=;
        fh=jSkX56z6lg/+Rvq65NknlWWoMBXIjiUaqCJv8r6OB0I=;
        b=Ka2K1V8wGHOW/Ffmknq6L1bkhr6xSXvb4c/XlSdYXde1B0FL+P5LX1WfVtomIjx/Bq
         wu2j/JyL/dcL2X2cvKchPU/1+QRlQucsg0O2PJmBT8bBNTwpqDOMOcTCOTEXgZMB6Ve0
         zs6Zj+oaYebW7sPU5plNQgFLgEzOh4IE+ZJJDNaocHlcjtihNIPdMPKlnXUbgbz3aWqN
         LdWuoc8xviyzr5qH8CNzmzgL+EyiObm+J+ZLyN8BKVEdzbZe2dqsNatobzFOJgFUSZG0
         zxdEPRDl4FYWoXDJmV2UyQ+/MRP7JfnNJ/Qz9s6XdT2ULbxOGAFuoSoCXGljl8lt0bZY
         F0QQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="QVQ/Rkmi";
       spf=pass (google.com: domain of 3k8fgzwukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3K8fGZwUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080367; x=1741685167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ri103XSh4oz5KysfkmNNkkVOGaSq9I77Uqs9nhMpVJQ=;
        b=BllsR4nt8INTa+tLmnnv8/fk2cAB2Qy7vxMRDm4M//L4CU0shkd/plFFycLE9Qedrc
         jC4bbh3TfUJoPaROKnVGxe2SAmBGF7nCSzeizAq7LcUF6R/0Ln5s7Vl8Tye1QI2zPqUy
         Fh2hNo7qEkTwjAaRW+RqbIxqsMJKJgtCHm1Uo7G3iBZYz7zOAZNDO3yzL4zDhVdgeD3C
         l16jU+o0ZbywAivZ/WOB689GYBZvbfUt/bRPJjAi5DeGr7xo5qBoH+fGdIYjJtsd+Nu3
         94zgrieyThl18y5fAjKzJ/DjQyeEsbxJ/upfMtx1UMPMv81GWSuVpZktuIrCLelI5J3x
         gbhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080367; x=1741685167;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ri103XSh4oz5KysfkmNNkkVOGaSq9I77Uqs9nhMpVJQ=;
        b=jwrzMMPJEp4C0eG2PAKaiV/R83/nLD3FJ5mrAuGdjDDeRavCo3E0OI6xgivUMcRP7j
         IhJiJToQ8xpjDPktOZxvINsTZXxvEoghIOQrs6xAmHeMsgQfj4Sv0aI2oYKEEgJD6zfg
         zlUEDOmvsh0gE6dAynmKH1cqPsdgyWI2b+Hcuvg/jak0C5KKlZ4G9+CVVg6XRUjOzZ67
         JJgv6CiqNdednXS8dMBnsVKKcoMHuU9Ju29wE9OBAxGJ8nKkh9CG9+8LIOsntZzfkVHL
         ZnXOzHKW+6ttV6SuC0iT7MCOTF7MB7tbpIlw2yE+G47gaZF7odnRZx5UWF64nnvhz7Ow
         9mXQ==
X-Forwarded-Encrypted: i=2; AJvYcCV6dQJMmPdyvzzenFGX/AmgnJN+5y8qJ9DMZfBnDo6LszfficKTTUkRxvjt5yA0veT43olVkw==@lfdr.de
X-Gm-Message-State: AOJu0YxgSERxe+pvaQNRfrAuDIWZY76Wlf982qTBn1wOTCflPSW/AmE4
	LjWur/fcixjwqTV22pRLoUKLPx2whLCkcA0JuBvu3oaMFxh6aYE7
X-Google-Smtp-Source: AGHT+IG2X9wFH8SFgvvrY9WZ3fOqsG7X0GucnindzMVvmLIX1WlYNwJc8NRv1dYwnJUt8INAGvqvJA==
X-Received: by 2002:a05:6000:1844:b0:390:fe4b:70b9 with SMTP id ffacd0b85a97d-390fe4b7820mr10114345f8f.21.1741080366337;
        Tue, 04 Mar 2025 01:26:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHP9Qm4mbuS2DNjPNK4U+xeezM58FCvZi21ecK7wprq4A==
Received: by 2002:a05:6000:400a:b0:38e:f923:e192 with SMTP id
 ffacd0b85a97d-390e12108c3ls2070037f8f.0.-pod-prod-07-eu; Tue, 04 Mar 2025
 01:26:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQhDZV9RWavMgY6myhV4xPLh4Q/ExU1NPmK/VzKnngiiP2FQm0VC5lXIdUs15alET6H8kb9pCW7Ao=@googlegroups.com
X-Received: by 2002:a5d:6d0b:0:b0:390:ff25:79ab with SMTP id ffacd0b85a97d-390ff257c51mr6902795f8f.17.1741080363861;
        Tue, 04 Mar 2025 01:26:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080363; cv=none;
        d=google.com; s=arc-20240605;
        b=FwNDuBKdfFBSYZThulXAffyFNA/6ipLF2fssNie5L2qdzLLXNLUy00Y5FK2hWLqMik
         Ttc4eRqG9TBab9Ex17xX49EpBSmQ8gDbEWYJQKNoCmDJlfLc7s7I4LmyYoitvi2iobQF
         L2tI+b/n9x6I5U8814WBaGloGN19uMAPQm+SRTnnlwzvke5uAXIyjw4HQttDZ9OfPmZi
         WDUKTOn8vG7Zq4KJWHXDGZUCU7FqEP1fGIA7Knyw+wxcUu8RDL6nt3VR7iHQMZaYpbQx
         AEg4rx7Jqv6LfOYlbx68xfZYKEYdFrTQ0igbeD51oDWSkcmlDds35is36zkwmLe1ztIq
         P2Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=8Nr2jdJ0PNmITUGav9EmcnRuPAHdAawXc4SBIYnGZjc=;
        fh=ZT4l0x8wDomiSK0akZaPhACdoSNADbhdv7yy0AhIDNw=;
        b=fwfJf4IvxcwIw0/zKhyxsKf6jk/kWeSxQF6uTf7HPu5jOvpcltRDa/Kblh5PgpHNFR
         8n03irb9jl1hSB7AlJ2ga5BbUV6XLcu7IrWtiNwBAf5IKsyGiEeFbzEuOUthKL0WubBo
         hxXiZTWS1cU17IigVYw74AB9qDIfHjC+poBA13EuF+pPj/DWrdE3vd2M25CujfG3VRj8
         13yF2qe92tEJijXxY1IXKZD0uSYSWf2x2I+k/0jmDb4s/1t399EjRjPzV5eLaLH5vwaY
         W9uX8Ty0UvdpGRjdnTkMIpfmM915L1+ewQNeQn9DURr7YIYSAuHrMxmMPu5N8rGxOiyB
         qQyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="QVQ/Rkmi";
       spf=pass (google.com: domain of 3k8fgzwukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3K8fGZwUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc139b49si808915e9.1.2025.03.04.01.26.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3k8fgzwukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abf6e9bbef5so251237566b.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWlxeJ9hPqgrvBcoOaKYpSIn3RK7E2sGQEB6ZQX2N4UwCiCWYfEshvxQxhlM2Z/aEhVYObkuz+0fFE=@googlegroups.com
X-Received: from ejcso7.prod.google.com ([2002:a17:907:3907:b0:abf:71ba:a144])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:2da1:b0:ac1:deb0:5c3e
 with SMTP id a640c23a62f3a-ac1deb0d856mr500700666b.16.1741080363274; Tue, 04
 Mar 2025 01:26:03 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:19 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-21-elver@google.com>
Subject: [PATCH v2 20/34] locking/ww_mutex: Support Clang's capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="QVQ/Rkmi";       spf=pass
 (google.com: domain of 3k8fgzwukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3K8fGZwUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for ww_mutex.

The programming model for ww_mutex is subtly more complex than other
locking primitives when using ww_acquire_ctx. Encoding the respective
pre-conditions for ww_mutex lock/unlock based on ww_acquire_ctx state
using Clang's capability analysis makes incorrect use of the API harder.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 .../dev-tools/capability-analysis.rst         |  3 +-
 include/linux/ww_mutex.h                      | 21 ++++--
 lib/test_capability-analysis.c                | 65 +++++++++++++++++++
 3 files changed, 82 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index e892a5292841..51ea94b0f4cc 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -80,7 +80,8 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`,
+`ww_mutex`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 45ff6f7a872b..e1d5455bd075 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -44,7 +44,7 @@ struct ww_class {
 	unsigned int is_wait_die;
 };
 
-struct ww_mutex {
+struct_with_capability(ww_mutex) {
 	struct WW_MUTEX_BASE base;
 	struct ww_acquire_ctx *ctx;
 #ifdef DEBUG_WW_MUTEXES
@@ -52,7 +52,7 @@ struct ww_mutex {
 #endif
 };
 
-struct ww_acquire_ctx {
+struct_with_capability(ww_acquire_ctx) {
 	struct task_struct *task;
 	unsigned long stamp;
 	unsigned int acquired;
@@ -107,6 +107,7 @@ struct ww_acquire_ctx {
  */
 static inline void ww_mutex_init(struct ww_mutex *lock,
 				 struct ww_class *ww_class)
+	__asserts_cap(lock)
 {
 	ww_mutex_base_init(&lock->base, ww_class->mutex_name, &ww_class->mutex_key);
 	lock->ctx = NULL;
@@ -141,6 +142,7 @@ static inline void ww_mutex_init(struct ww_mutex *lock,
  */
 static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
 				   struct ww_class *ww_class)
+	__acquires(ctx) __no_capability_analysis
 {
 	ctx->task = current;
 	ctx->stamp = atomic_long_inc_return_relaxed(&ww_class->stamp);
@@ -179,6 +181,7 @@ static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
  * data structures.
  */
 static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
+	__releases(ctx) __acquires_shared(ctx) __no_capability_analysis
 {
 #ifdef DEBUG_WW_MUTEXES
 	lockdep_assert_held(ctx);
@@ -196,6 +199,7 @@ static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
  * mutexes have been released with ww_mutex_unlock.
  */
 static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
+	__releases_shared(ctx) __no_capability_analysis
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
+	__acquires(lock) __must_hold(ctx) __no_capability_analysis
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
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 81c8e74548a9..853fdc53840f 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -14,6 +14,7 @@
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 #include <linux/srcu.h>
+#include <linux/ww_mutex.h>
 
 /*
  * Test that helper macros work as expected.
@@ -479,3 +480,67 @@ static void __used test_local_lock_guard(void)
 	{ guard(local_lock_irqsave)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
 	{ guard(local_lock_nested_bh)(&test_local_lock_data.lock); this_cpu_add(test_local_lock_data.counter, 1); }
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
+}
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-21-elver%40google.com.
