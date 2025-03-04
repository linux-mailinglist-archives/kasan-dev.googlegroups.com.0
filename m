Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJMOTO7AMGQEI7VNDRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 82E43A4D80D
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:59 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43943bd1409sf39363765e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080359; cv=pass;
        d=google.com; s=arc-20240605;
        b=l2E5hHE9vcckLNewgV6iOM2r61Ovmp+cstbNS4BoYk1IlLB0Wy9cPGynuneexc/pbG
         U3WWHobN2piqF4MxilqPivoY+VmeLokSfSJxjcYzpNo6z3uJVdGsaxE+KVsNtlR/hndB
         JAX6nyldfEODEev8FhupEvKlbFLyfEKk6cqRW8KvYpFfrYaSdrhc0/a/t87dE12Fnkd0
         yvE3E1xz/Hopt0B7NsfLWXY470kH2DA01eYcF+Fz1D1KM8AklRMMDRW5rITV3dMSIUzZ
         QQk8D9CWUFqkdbcZvDv60S8kSPF0xw6wsyZMxjF0Hi2DDl82sYZVkEWKI3V+S0xIlo0M
         NU4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0FxUfY36jcIuaHQ3VPQP8BAeEOqGK68Qh2on0QoxQ6I=;
        fh=ShfNiOfNEG7TfVYim2F9x0TgzCv8YnPlL+EKCm85heM=;
        b=dzZTo7ZqH4pcdy9W+8GTl907V0mLrfTQ8o5Pe/uG/fp7Ypyefv3vi/fiIjqX1M3vHx
         pytgwE1n5D3aAqsD3erTDTUsi1Ow7TFP5XXvURxb28LLrKUJijD1Anfjq6Ca0i7G6ZxP
         Smsm2nPhJie9Dvbp3ARXYWbiNzV9FO7QY4RZilwitUjlxAP/pPy0FEwOcRGQrFtfBX2J
         WkPGK0bpX7DRgFFXh3g/lHXcT1ZoBqgJPLmHF8Z+LSth1Kd8pucsH/Mo4sYQbvasDral
         N4JKmDCL0lYMv1/72M9Jfzk0y4DSL8+wUo38WgacMHrqoRNZIy/2EYEqC+Lsn3zLdG0D
         pm5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yWz3Tqve;
       spf=pass (google.com: domain of 3i8fgzwukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I8fGZwUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080359; x=1741685159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0FxUfY36jcIuaHQ3VPQP8BAeEOqGK68Qh2on0QoxQ6I=;
        b=q8K3V2cip1/jZBlRjh00PZ1ymy+fxt82v9b3t64JdDcoFoBsAm1adOKvCry4VwlKJF
         hNX3oV0xdTV4pcyCq+yeK79e8X9Nl5Cq9EvlB8GX34uC0V+I+/LRuQc/5fylgZaJxogo
         NTz+sfxNl3wpdT0e8vIWVuUEMfdFSNz7QP4jndjXJad8gsdb1YG5OkQb+ebHH/TfmG75
         4q1a/j9tZFy6CLoKhO61z/SOjaWqpSR3qQrSLdK0NpvBwpLVOcUCgMiB3ZLWkGg8+Iuu
         1NOif72qw05rsI8t2GbLDXYQwtwJ4wr6+OAXSI66eTH8SbUknCXV3JiJH91mPy8Ow0B/
         pQvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080359; x=1741685159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0FxUfY36jcIuaHQ3VPQP8BAeEOqGK68Qh2on0QoxQ6I=;
        b=wKnwHxfftGkDTWpj5B5wv/bH5TRf/LIPwRMnnrW/BEjjN3fTOB8pXw/qnRBkyqhU6+
         8btbRyAyXXKo5NryYkr9y0QN9jCRp850H4zN1MUkVk90CqZ8eqBvZON2cZkk83BXZMzx
         e1zpxMJcOx6hSxDDgHAmz6lcn2pXS6iUjzWSffvM18jXTBGOghdvq1B5u23eWZH0MevM
         pCMHoGv7IhLwyNDXP0FjJ2gw75a1QitdeXOeXGQ+vE2si1q3TAn6lZuUUrlftvrzCFSG
         Y0naD0nGSDK/4Lz1y2bojYMedV+OUpH4Tc4hTOncPoYtk7xJ+ptoUgKRDd6kRs+cYMQM
         cU3g==
X-Forwarded-Encrypted: i=2; AJvYcCW+K05bYerCKvuby01vwkm44azRcK83o5zAxQovokdkjpvAqgYTRAjhSYghhiYy4kMgHIsHCw==@lfdr.de
X-Gm-Message-State: AOJu0YznnE66AMuvTpLx6z6nKx99jL2HO2kPAIyX75FsnEUOP3WOEl6D
	7/C/X7YGnhcTTJjJOYBK3/Y8oEdNwskhYVnhbZGVigF1VMyfHZPn
X-Google-Smtp-Source: AGHT+IHzIurIRg+g4zf34wVW9TRhOkq8LFazOa8uUflG2U5cn4N9sANbviWGQ21oGJKj2PfbF5zdpg==
X-Received: by 2002:a05:600c:a03:b0:439:6712:643d with SMTP id 5b1f17b1804b1-43ba66df7d6mr134159055e9.9.1741080358107;
        Tue, 04 Mar 2025 01:25:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGheFLIM7H6Kro4mQ7MJAXyMkz9p0pZgKehIs/STg5kWQ==
Received: by 2002:a05:600c:2214:b0:43b:c52b:ed4e with SMTP id
 5b1f17b1804b1-43bc52bee35ls8066945e9.2.-pod-prod-09-eu; Tue, 04 Mar 2025
 01:25:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUorMlYdCnE4ouH9GHhYRQryHOQTwDkW/+pV8GM8YSjdS2aeQcM5P5eAxJ8yOKegObpf2npFuulNIA=@googlegroups.com
X-Received: by 2002:a05:600c:4ec8:b0:439:6101:5440 with SMTP id 5b1f17b1804b1-43ba66df834mr145847685e9.8.1741080355736;
        Tue, 04 Mar 2025 01:25:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080355; cv=none;
        d=google.com; s=arc-20240605;
        b=PSEg00/LcV6gU1i7rhBV5cy6bt/WVt81Iyfs5QBItoXkc9a4QWGrHlJ10ntwD6Xnin
         T1WI5t+Dvi4Tg1/tC2TTFOTNbocX+ffH1AcOKGVCAZsWRaW+JfGJ3nB54rr6GaZmXN5i
         ETI+1E5ObktFvyGzGU5LEFZc1QYxV6yG8eOv3bn18LKsFic2fYgNiN7pMhRnuC72ixHL
         jItviVz58+Z7kxeyfxNlIM+wDg+S9krFp0YUPL1H5LUrCu+ojNfPKI8w0bBEcLTpH9t+
         499/0DOsQ2B4myD3f3YsA9cjz38dbSd7/v4fiVe1tl9HKC98Z5TEgvr0pTbOIXTljqr9
         9KYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ezb4DcU7J/tAnP2VeDlPIfb7+eFzdx1whQ0121O6/zI=;
        fh=eQ0RUiAZP7+dC5OBNsyhB9hBBEI+57VAyNjnZjR698o=;
        b=dVZoLhRYhsrv56myYe0KWYbcwlj3NISTjZCL7ctWGhlZBan0p7gOwtqrdqchUHPvhT
         taCrCIE/eII8T/zvu8DJDE97Ldvl/iVvZukFauqtfuoAwBE/c+xRxaM9VtwN3M2Ufq+w
         OKTk5M366K4N1D2Zn+wOnVxGJGv/5vu8jDFJ/uM2xups1O3uvyotvQPGm3eC8NzRUWOX
         vkWkUUYpUGzeGeRx+0l2jv2n5bWmaZ1sWb4OrzEjGdBOI/wM8Nf9YswBI8EWR/vRnFQ8
         6S6zsb+IlxshR4LWxPvzZqd8FDqci0GmIsEDsA0FqtbzOtnWZ0CNVYDt/y6PIIySGVEO
         VW4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yWz3Tqve;
       spf=pass (google.com: domain of 3i8fgzwukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I8fGZwUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e47ff679si387024f8f.5.2025.03.04.01.25.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3i8fgzwukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e54335bf7fso2866834a12.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVipmiuhZQkpSnbw6LMhF+lKPbg4+/QaH4au1+ErACXxUZ9jSkqmwAhadsE0eD8fhjODoV0VWOcCaE=@googlegroups.com
X-Received: from edbfd14.prod.google.com ([2002:a05:6402:388e:b0:5e4:c2fd:b4ac])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:2711:b0:5e0:49e4:2180
 with SMTP id 4fb4d7f45d1cf-5e4d6b4bc0dmr43845190a12.25.1741080355166; Tue, 04
 Mar 2025 01:25:55 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:16 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-18-elver@google.com>
Subject: [PATCH v2 17/34] locking/rwsem: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=yWz3Tqve;       spf=pass
 (google.com: domain of 3i8fgzwukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I8fGZwUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for rw_semaphore.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/rwsem.h                         | 56 +++++++++-------
 lib/test_capability-analysis.c                | 64 +++++++++++++++++++
 3 files changed, 97 insertions(+), 25 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 918e35d110df..7e4d94d65043 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`).
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index c8b543d428b0..98aa623ad9bf 100644
--- a/include/linux/rwsem.h
+++ b/include/linux/rwsem.h
@@ -45,7 +45,7 @@
  * reduce the chance that they will share the same cacheline causing
  * cacheline bouncing problem.
  */
-struct rw_semaphore {
+struct_with_capability(rw_semaphore) {
 	atomic_long_t count;
 	/*
 	 * Write owner or one of the read owners as well flags regarding
@@ -76,11 +76,13 @@ static inline int rwsem_is_locked(struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__asserts_cap(sem)
 {
 	WARN_ON(atomic_long_read(&sem->count) == RWSEM_UNLOCKED_VALUE);
 }
 
 static inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__asserts_cap(sem)
 {
 	WARN_ON(!(atomic_long_read(&sem->count) & RWSEM_WRITER_LOCKED));
 }
@@ -119,6 +121,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assert_cap(sem);					\
 } while (0)
 
 /*
@@ -136,7 +139,7 @@ static inline int rwsem_is_contended(struct rw_semaphore *sem)
 
 #include <linux/rwbase_rt.h>
 
-struct rw_semaphore {
+struct_with_capability(rw_semaphore) {
 	struct rwbase_rt	rwbase;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
@@ -160,6 +163,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assert_cap(sem);					\
 } while (0)
 
 static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
@@ -168,11 +172,13 @@ static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
 }
 
 static __always_inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__asserts_cap(sem)
 {
 	WARN_ON(!rwsem_is_locked(sem));
 }
 
 static __always_inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__asserts_cap(sem)
 {
 	WARN_ON(!rw_base_is_write_locked(&sem->rwbase));
 }
@@ -190,6 +196,7 @@ static __always_inline int rwsem_is_contended(struct rw_semaphore *sem)
  */
 
 static inline void rwsem_assert_held(const struct rw_semaphore *sem)
+	__asserts_cap(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held(sem);
@@ -198,6 +205,7 @@ static inline void rwsem_assert_held(const struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
+	__asserts_cap(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held_write(sem);
@@ -208,47 +216,47 @@ static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
 /*
  * lock for reading
  */
-extern void down_read(struct rw_semaphore *sem);
-extern int __must_check down_read_interruptible(struct rw_semaphore *sem);
-extern int __must_check down_read_killable(struct rw_semaphore *sem);
+extern void down_read(struct rw_semaphore *sem) __acquires_shared(sem);
+extern int __must_check down_read_interruptible(struct rw_semaphore *sem) __cond_acquires_shared(0, sem);
+extern int __must_check down_read_killable(struct rw_semaphore *sem) __cond_acquires_shared(0, sem);
 
 /*
  * trylock for reading -- returns 1 if successful, 0 if contention
  */
-extern int down_read_trylock(struct rw_semaphore *sem);
+extern int down_read_trylock(struct rw_semaphore *sem) __cond_acquires_shared(true, sem);
 
 /*
  * lock for writing
  */
-extern void down_write(struct rw_semaphore *sem);
-extern int __must_check down_write_killable(struct rw_semaphore *sem);
+extern void down_write(struct rw_semaphore *sem) __acquires(sem);
+extern int __must_check down_write_killable(struct rw_semaphore *sem) __cond_acquires(0, sem);
 
 /*
  * trylock for writing -- returns 1 if successful, 0 if contention
  */
-extern int down_write_trylock(struct rw_semaphore *sem);
+extern int down_write_trylock(struct rw_semaphore *sem) __cond_acquires(true, sem);
 
 /*
  * release a read lock
  */
-extern void up_read(struct rw_semaphore *sem);
+extern void up_read(struct rw_semaphore *sem) __releases_shared(sem);
 
 /*
  * release a write lock
  */
-extern void up_write(struct rw_semaphore *sem);
+extern void up_write(struct rw_semaphore *sem) __releases(sem);
 
-DEFINE_GUARD(rwsem_read, struct rw_semaphore *, down_read(_T), up_read(_T))
-DEFINE_GUARD_COND(rwsem_read, _try, down_read_trylock(_T))
-DEFINE_GUARD_COND(rwsem_read, _intr, down_read_interruptible(_T) == 0)
+DEFINE_LOCK_GUARD_1(rwsem_read, struct rw_semaphore, down_read(_T->lock), up_read(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _try, down_read_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _intr, down_read_interruptible(_T->lock) == 0)
 
-DEFINE_GUARD(rwsem_write, struct rw_semaphore *, down_write(_T), up_write(_T))
-DEFINE_GUARD_COND(rwsem_write, _try, down_write_trylock(_T))
+DEFINE_LOCK_GUARD_1(rwsem_write, struct rw_semaphore, down_write(_T->lock), up_write(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _try, down_write_trylock(_T->lock))
 
 /*
  * downgrade write lock to read lock
  */
-extern void downgrade_write(struct rw_semaphore *sem);
+extern void downgrade_write(struct rw_semaphore *sem) __releases(sem) __acquires_shared(sem);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 /*
@@ -264,11 +272,11 @@ extern void downgrade_write(struct rw_semaphore *sem);
  * lockdep_set_class() at lock initialization time.
  * See Documentation/locking/lockdep-design.rst for more details.)
  */
-extern void down_read_nested(struct rw_semaphore *sem, int subclass);
-extern int __must_check down_read_killable_nested(struct rw_semaphore *sem, int subclass);
-extern void down_write_nested(struct rw_semaphore *sem, int subclass);
-extern int down_write_killable_nested(struct rw_semaphore *sem, int subclass);
-extern void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest_lock);
+extern void down_read_nested(struct rw_semaphore *sem, int subclass) __acquires_shared(sem);
+extern int __must_check down_read_killable_nested(struct rw_semaphore *sem, int subclass) __cond_acquires_shared(0, sem);
+extern void down_write_nested(struct rw_semaphore *sem, int subclass) __acquires(sem);
+extern int down_write_killable_nested(struct rw_semaphore *sem, int subclass) __cond_acquires(0, sem);
+extern void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest_lock) __acquires(sem);
 
 # define down_write_nest_lock(sem, nest_lock)			\
 do {								\
@@ -282,8 +290,8 @@ do {								\
  * [ This API should be avoided as much as possible - the
  *   proper abstraction for this case is completions. ]
  */
-extern void down_read_non_owner(struct rw_semaphore *sem);
-extern void up_read_non_owner(struct rw_semaphore *sem);
+extern void down_read_non_owner(struct rw_semaphore *sem) __acquires_shared(sem);
+extern void up_read_non_owner(struct rw_semaphore *sem) __releases_shared(sem);
 #else
 # define down_read_nested(sem, subclass)		down_read(sem)
 # define down_read_killable_nested(sem, subclass)	down_read_killable(sem)
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 63d81ad1562f..7ccb163ab5b1 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -8,6 +8,7 @@
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
 #include <linux/rcupdate.h>
+#include <linux/rwsem.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 #include <linux/srcu.h>
@@ -255,6 +256,69 @@ static void __used test_seqlock_writer(struct test_seqlock_data *d)
 	write_sequnlock_irqrestore(&d->sl, flags);
 }
 
+struct test_rwsem_data {
+	struct rw_semaphore sem;
+	int counter __guarded_by(&sem);
+};
+
+static void __used test_rwsem_init(struct test_rwsem_data *d)
+{
+	init_rwsem(&d->sem);
+	d->counter = 0;
+}
+
+static void __used test_rwsem_reader(struct test_rwsem_data *d)
+{
+	down_read(&d->sem);
+	(void)d->counter;
+	up_read(&d->sem);
+
+	if (down_read_trylock(&d->sem)) {
+		(void)d->counter;
+		up_read(&d->sem);
+	}
+}
+
+static void __used test_rwsem_writer(struct test_rwsem_data *d)
+{
+	down_write(&d->sem);
+	d->counter++;
+	up_write(&d->sem);
+
+	down_write(&d->sem);
+	d->counter++;
+	downgrade_write(&d->sem);
+	(void)d->counter;
+	up_read(&d->sem);
+
+	if (down_write_trylock(&d->sem)) {
+		d->counter++;
+		up_write(&d->sem);
+	}
+}
+
+static void __used test_rwsem_assert(struct test_rwsem_data *d)
+{
+	rwsem_assert_held_nolockdep(&d->sem);
+	d->counter++;
+}
+
+static void __used test_rwsem_guard(struct test_rwsem_data *d)
+{
+	{ guard(rwsem_read)(&d->sem); (void)d->counter; }
+	{ guard(rwsem_write)(&d->sem); d->counter++; }
+}
+
+static void __used test_rwsem_cond_guard(struct test_rwsem_data *d)
+{
+	scoped_cond_guard(rwsem_read_try, return, &d->sem) {
+		(void)d->counter;
+	}
+	scoped_cond_guard(rwsem_write_try, return, &d->sem) {
+		d->counter++;
+	}
+}
+
 struct test_bit_spinlock_data {
 	unsigned long bits;
 	int counter __guarded_by(__bitlock(3, &bits));
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-18-elver%40google.com.
