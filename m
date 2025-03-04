Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK4OTO7AMGQEZ3APGLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FAF7A4D810
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:04 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43bcddbe609sf3223085e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080364; cv=pass;
        d=google.com; s=arc-20240605;
        b=gBby1IwwJ6R/cXRlsfDbru0D6BpiMfxrKW4q7NYqVbWDyRjg0luAxDi33SKJH7EKaN
         egsKIihEFTVCOjkgjJAUEhIa/4QV4vo0azJFe3O6uQ0lCMTt+MClVpgpBP5DLuv03Di5
         0pwYh7BGZoxRgOnlPGKqBdR6mKZhanYsSyvOvuggo+7s9VeLcxrJxgznLl8jD1AhgFbJ
         9QczSILgWcHrKsdjg8pcgQz35whjKHeb3O7OBjorIeWBJdfRebjFqLw5FyJ2SBWCRiYm
         sFTtPHEkM1m0aenWRkJkhqTw10+Dr7BlUNg1dQwk5fABnGJOUyMbhWVyItM4+YKIr+TR
         tasw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PNoJjfZkpJPi2b17m0m+7ozIW/I6rWgsOvUx7UaqROE=;
        fh=fjELq9h7fImAOA1+NeHvKI3syJDDxYVtNqPh+CfXiFk=;
        b=Vq2FvnjsB4A0Ex28bJ5XReo9zUjfpfCjYOjm3NV78j54BElFpcCNpUEIjnLhu/omFZ
         luzgvOkdXcSP6e7FZ9uPMPt66xnOrRpUYSFmGLjPjPJ+zbkarvLR2kZEOXtl9lmjhabO
         tnBM7UAFDeIcSOXlI+AprKJaH6WOef0Wq7Qc9pbS/OTIzQuxlUrVt9ErF++FX0iKqE2n
         VKhiith9AwFZNOS2tdrV5/0afMtWJfaVF2bF/2RS8yJqBitweU5wUmW+/AFXLT+0HUpG
         36j7MmvyeYG5fJdugzVxdfi4Ht0zKv5E0m1DKxk7msDjbZ3OfUE7345ybnJIN5d7evQh
         i7LA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LFrwBVTg;
       spf=pass (google.com: domain of 3kmfgzwukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3KMfGZwUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080364; x=1741685164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PNoJjfZkpJPi2b17m0m+7ozIW/I6rWgsOvUx7UaqROE=;
        b=KlX7Id02EEZnCcZah4B+QXgUlP15U7wSblnG7NIgTzKCXhDGfEGtjGjSyNJxJkoP82
         X6yZ6AS4AHeLIPiGb1qza3ALImDgwKCwi6guNIQlU8PpqEtabpFyjJlFTAOJrQ8nERL1
         AN754itsVKg++tL3DUmDB9GY4CXo0MW4S4a/wfRcs3+2yq56dK3xEMDD1svv2ZhTxWIG
         JII8kAFPmuMAx+QyNAYFx3rgibGcXAlDeqWErgvaoc8ty75i4s4qUL8uA/Iq9xCtGM8D
         9SfZGSTHos25C0Y+0VcpBWemLqDgd9auvKZoQ2GNd45g20JlfUhYY4swsfxFvSiZ8sHG
         DRDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080364; x=1741685164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PNoJjfZkpJPi2b17m0m+7ozIW/I6rWgsOvUx7UaqROE=;
        b=RaJoNQsQ8tfJBm94zU5zampZysOl94BsUarPbokudSmBkI17f/T7Qfhd7nV1zZjB+I
         8ezpHNRS2xocZUJnF0xROSLuYzwwV327tMRN2nYEAwS51Bd85lf38DBkq3MdhAj0W9b8
         +uqHN9Ahze05uQSi+MmcI3kdaKu/N/cxmsBTJuGLTcnrYnc7EWO90wYpyzl4Eta6XPc4
         +ixWrpKT3zWEAPxSGHDcLse2VzktHjieMTz7qepFzAYpNBVBgsar/eU9WRSSt8tTu1ur
         lqYK3VAqOAICM4OAhMbpUEaeiaomj2ceBET9d2iLdR+lmmAsbcmbJ9wkazw+/Ufl7U+p
         1nCw==
X-Forwarded-Encrypted: i=2; AJvYcCWDS/qbHaHkbraLEoA5LfaxrSuCPw56Oy87Armrd1Efu0pL6bsLHYIf73Ms+jdgikWzrgN5mQ==@lfdr.de
X-Gm-Message-State: AOJu0YyiD34vAWfUsLUE79IPuz/jgBbnO8jO0Uk8a41qrmOdQnS8A9tR
	3Jye159ggwqV+pYx1gYzu/GeMpHlc60WVGiuCTsX2lWxTMnyTjtO
X-Google-Smtp-Source: AGHT+IFpbxmTZb5aWAyQNji0cf6nBLvuf0Z6P3u2lYfCGCbxrWBmWul7hOgQjwl8xfDNlyUX2OjpWg==
X-Received: by 2002:a05:6000:2c4:b0:390:f964:94cb with SMTP id ffacd0b85a97d-390f964965amr13326834f8f.44.1741080363588;
        Tue, 04 Mar 2025 01:26:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE0MXgMGEEakoN6d0fCVKA1SdjJkhyLcdvOei10msbKwQ==
Received: by 2002:a05:6000:1787:b0:38f:22fc:ecb6 with SMTP id
 ffacd0b85a97d-390e13164a2ls3299464f8f.2.-pod-prod-05-eu; Tue, 04 Mar 2025
 01:26:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1bl3HrRNwI0ZbbrA4PrV8eVqnkDwM1TLLftUoIksU31a5zJTwuBA5UcGVRokbND9Z4tXN/ek2BOI=@googlegroups.com
X-Received: by 2002:a5d:5f84:0:b0:390:e7c1:59c4 with SMTP id ffacd0b85a97d-390ec7cd0b1mr17432701f8f.13.1741080361001;
        Tue, 04 Mar 2025 01:26:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080360; cv=none;
        d=google.com; s=arc-20240605;
        b=PuNMsg3SUbPPtueS/dlkm+XP99DWS4s06hnQ+SOpT89iVODfRD0golR/IzJ9m4DJ7g
         aOq5yeTekiGSEggWveZvTfGyrSKZ2Cp5EltINh3sniBWRgnY7l/0LokpCr4hPdxySUV2
         hDZ/OkR7O3NYItnUYXmq6HYbfdGOal8lb6XF/TYCJIXzZHWfpjA29sx12z4geWG7Ahjo
         PFkIlrLJ7NbfZ31qP5JP3VPAIIWW9Y5d6Q0tbH2nlzejV9X094a+vuDbfuRB3EbeFRta
         BHK1Q+0FSdC9/dZg1k8Wu1UfGKZpyLRkrrRzZj9b9HeaNqhLL4UwAhRpPzboE4qZe/eO
         QVmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fevqVsEsX3/oCaV46XhekBmDNUcdyGVL5LKZ5XmlZNY=;
        fh=l4FRPEn6+6cOdsXZ8n0cLDoqyl7AytIS7fof80cxOuw=;
        b=V9qBYBuj8ST6spfgH/cn0jTNJVOp0sVpgwlyOc+yFVPI2KG19SbGYBtK8psOfPNhw/
         wCHeR+OLjtmlCQNzydLn3qqaxWXE9qab4GwF0Q504AaNhti06HnUthWBgUOIdKs+562P
         IEQihVgfGLZdg/YvcpyecyJp+zXmMmM7p2k7PM6+An7bD3JHna3DXGcHEUJG9Q5p3Q4X
         jNTyWZJqHgabc/UV2erR02Sj3B+Mw8dD1wHl8Lgu5DZBr2smeC89b6fECBUbGc3VRv48
         PBQeKhunnOaEzCbRc0lAaRnUBANPc4E+DL+MVD8wYgf/zRMXVjOVkH4ZXKnh+ZFlPplb
         cmig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LFrwBVTg;
       spf=pass (google.com: domain of 3kmfgzwukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3KMfGZwUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e47e8ff1si469124f8f.4.2025.03.04.01.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kmfgzwukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e583e090deso1143411a12.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVXQJ5hJUgcl0Czpi0nAMH+PEUWm077r2BPLx8oKPlLtpkNIMnOFnIEQ1In11NEL2BW/cQ67xfsVuQ=@googlegroups.com
X-Received: from edbfe12.prod.google.com ([2002:a05:6402:390c:b0:5e0:963d:6041])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3904:b0:5e5:335:dad2
 with SMTP id 4fb4d7f45d1cf-5e50335de72mr16333101a12.26.1741080360656; Tue, 04
 Mar 2025 01:26:00 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:18 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-20-elver@google.com>
Subject: [PATCH v2 19/34] locking/local_lock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=LFrwBVTg;       spf=pass
 (google.com: domain of 3kmfgzwukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3KMfGZwUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for local_lock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/local_lock.h                    | 18 ++++----
 include/linux/local_lock_internal.h           | 41 ++++++++++++++---
 lib/test_capability-analysis.c                | 46 +++++++++++++++++++
 4 files changed, 90 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 7e4d94d65043..e892a5292841 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/local_lock.h b/include/linux/local_lock.h
index 091dc0b6bdfb..63fadcf66216 100644
--- a/include/linux/local_lock.h
+++ b/include/linux/local_lock.h
@@ -51,12 +51,12 @@
 #define local_unlock_irqrestore(lock, flags)			\
 	__local_unlock_irqrestore(lock, flags)
 
-DEFINE_GUARD(local_lock, local_lock_t __percpu*,
-	     local_lock(_T),
-	     local_unlock(_T))
-DEFINE_GUARD(local_lock_irq, local_lock_t __percpu*,
-	     local_lock_irq(_T),
-	     local_unlock_irq(_T))
+DEFINE_LOCK_GUARD_1(local_lock, local_lock_t __percpu,
+		    local_lock(_T->lock),
+		    local_unlock(_T->lock))
+DEFINE_LOCK_GUARD_1(local_lock_irq, local_lock_t __percpu,
+		    local_lock_irq(_T->lock),
+		    local_unlock_irq(_T->lock))
 DEFINE_LOCK_GUARD_1(local_lock_irqsave, local_lock_t __percpu,
 		    local_lock_irqsave(_T->lock, _T->flags),
 		    local_unlock_irqrestore(_T->lock, _T->flags),
@@ -68,8 +68,8 @@ DEFINE_LOCK_GUARD_1(local_lock_irqsave, local_lock_t __percpu,
 #define local_unlock_nested_bh(_lock)				\
 	__local_unlock_nested_bh(_lock)
 
-DEFINE_GUARD(local_lock_nested_bh, local_lock_t __percpu*,
-	     local_lock_nested_bh(_T),
-	     local_unlock_nested_bh(_T))
+DEFINE_LOCK_GUARD_1(local_lock_nested_bh, local_lock_t __percpu,
+		    local_lock_nested_bh(_T->lock),
+		    local_unlock_nested_bh(_T->lock))
 
 #endif
diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index 420866c1c70b..01830f75d9a3 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -10,12 +10,13 @@
 
 #ifndef CONFIG_PREEMPT_RT
 
-typedef struct {
+struct_with_capability(local_lock) {
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
 	struct task_struct	*owner;
 #endif
-} local_lock_t;
+};
+typedef struct local_lock local_lock_t;
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 # define LOCAL_LOCK_DEBUG_INIT(lockname)		\
@@ -62,6 +63,7 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
+	__assert_cap(lock);					\
 } while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
@@ -73,40 +75,47 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
+	__assert_cap(lock);					\
 } while (0)
 
 #define __local_lock(lock)					\
 	do {							\
 		preempt_disable();				\
 		local_lock_acquire(this_cpu_ptr(lock));		\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irq(lock)					\
 	do {							\
 		local_irq_disable();				\
 		local_lock_acquire(this_cpu_ptr(lock));		\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_lock_irqsave(lock, flags)			\
 	do {							\
 		local_irq_save(flags);				\
 		local_lock_acquire(this_cpu_ptr(lock));		\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_unlock(lock)					\
 	do {							\
+		__release(lock);				\
 		local_lock_release(this_cpu_ptr(lock));		\
 		preempt_enable();				\
 	} while (0)
 
 #define __local_unlock_irq(lock)				\
 	do {							\
+		__release(lock);				\
 		local_lock_release(this_cpu_ptr(lock));		\
 		local_irq_enable();				\
 	} while (0)
 
 #define __local_unlock_irqrestore(lock, flags)			\
 	do {							\
+		__release(lock);				\
 		local_lock_release(this_cpu_ptr(lock));		\
 		local_irq_restore(flags);			\
 	} while (0)
@@ -115,19 +124,37 @@ do {								\
 	do {							\
 		lockdep_assert_in_softirq();			\
 		local_lock_acquire(this_cpu_ptr(lock));	\
+		__acquire(lock);				\
 	} while (0)
 
 #define __local_unlock_nested_bh(lock)				\
-	local_lock_release(this_cpu_ptr(lock))
+	do {							\
+		__release(lock);				\
+		local_lock_release(this_cpu_ptr(lock));		\
+	} while (0)
 
 #else /* !CONFIG_PREEMPT_RT */
 
+#include <linux/spinlock.h>
+
 /*
  * On PREEMPT_RT local_lock maps to a per CPU spinlock, which protects the
  * critical section while staying preemptible.
  */
 typedef spinlock_t local_lock_t;
 
+/*
+ * Because the compiler only knows about the base per-CPU variable, use this
+ * helper function to make the compiler think we lock/unlock the @base variable,
+ * and hide the fact we actually pass the per-CPU instance @pcpu to lock/unlock
+ * functions.
+ */
+static inline local_lock_t *__local_lock_alias(local_lock_t __percpu *base, local_lock_t *pcpu)
+	__returns_cap(base)
+{
+	return pcpu;
+}
+
 #define INIT_LOCAL_LOCK(lockname) __LOCAL_SPIN_LOCK_UNLOCKED((lockname))
 
 #define __local_lock_init(l)					\
@@ -138,7 +165,7 @@ typedef spinlock_t local_lock_t;
 #define __local_lock(__lock)					\
 	do {							\
 		migrate_disable();				\
-		spin_lock(this_cpu_ptr((__lock)));		\
+		spin_lock(__local_lock_alias(__lock, this_cpu_ptr((__lock)))); \
 	} while (0)
 
 #define __local_lock_irq(lock)			__local_lock(lock)
@@ -152,7 +179,7 @@ typedef spinlock_t local_lock_t;
 
 #define __local_unlock(__lock)					\
 	do {							\
-		spin_unlock(this_cpu_ptr((__lock)));		\
+		spin_unlock(__local_lock_alias(__lock, this_cpu_ptr((__lock)))); \
 		migrate_enable();				\
 	} while (0)
 
@@ -163,12 +190,12 @@ typedef spinlock_t local_lock_t;
 #define __local_lock_nested_bh(lock)				\
 do {								\
 	lockdep_assert_in_softirq_func();			\
-	spin_lock(this_cpu_ptr(lock));				\
+	spin_lock(__local_lock_alias(lock, this_cpu_ptr(lock))); \
 } while (0)
 
 #define __local_unlock_nested_bh(lock)				\
 do {								\
-	spin_unlock(this_cpu_ptr((lock)));			\
+	spin_unlock(__local_lock_alias(lock, this_cpu_ptr((lock)))); \
 } while (0)
 
 #endif /* CONFIG_PREEMPT_RT */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 7ccb163ab5b1..81c8e74548a9 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -6,7 +6,9 @@
 
 #include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
+#include <linux/local_lock.h>
 #include <linux/mutex.h>
+#include <linux/percpu.h>
 #include <linux/rcupdate.h>
 #include <linux/rwsem.h>
 #include <linux/seqlock.h>
@@ -433,3 +435,47 @@ static void __used test_srcu_guard(struct test_srcu_data *d)
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
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-20-elver%40google.com.
