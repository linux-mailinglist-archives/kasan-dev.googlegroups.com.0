Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWFDWDDAMGQE5FXH6DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 02B5FB84FC0
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:18 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3e980eb1d3esf214087f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204377; cv=pass;
        d=google.com; s=arc-20240605;
        b=ioKXghSOLAjV8G7jDptpY7a2tKcemuVuSdKa3QmXAClm3LOx4lphUWSRyNWin5CeLY
         ZaTOumpxF0ebsZQ/oFsJL6wwu/L54DrjKNjlnzxkgaH9ftGjaI3azCaM4XXZf18fSvQV
         gHn5RC5ARssIwcOPbZbT4UCRdTtH9dBzHXi2J9e4OPAB6lcpX3e7KJvwrF/oL0J7OClS
         odtMPwj+yrnkSsSSZb6sHQaqm3W1e3rQ9lg1ZKldGMune499u8d83IZPKkeiokciE4ap
         INmgdEBDM3Oaj0JJregaUgeNkm+vl2MQaPbMrDUDYYruG6V3KAkaaEbPb3bMuShhB8f/
         HkbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=oLrMLqmWlGw5hQyr1BSvYTOQ+/YeCbPcB8nV6+GcRxY=;
        fh=/8z8BB0b9RI5FckCoG/AKV957NcClCE3CRvo+X/CYj8=;
        b=EJJ42IgKe7V0k4h7WTK4+++u3YjXaBi1dYc6PzwK4/V1ZA2HkY3XFo3pHAYlRbgC0n
         gnLCU4HKEulxcUxfceKO3CfkVX1t1E2dJl610oTGHs7o3oPEW+k/YLtrKKwtpaBcCMUp
         EHONS5FoSqg+B9YWKv82kIkXHABVXQMSH3PVrxbqdot3RowTwRMC9diTJcyJCT6SJeGO
         He4lJKVsG50FQYIvba4l+42xjVt2azYtTC4TywrDfBXrHGBgnYjz3VHdrawZo99bDZ+i
         h6R6iZRk1ih0EgTfQvHt1igF3AKXQhk9L+I5TVQXd0JVDCWeKClKVcRM1u5iTMDPYZmN
         hBAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BBEol6qa;
       spf=pass (google.com: domain of 31rhmaaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31RHMaAUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204377; x=1758809177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oLrMLqmWlGw5hQyr1BSvYTOQ+/YeCbPcB8nV6+GcRxY=;
        b=G1hfB35gGY5LjpvQbEpRKUzKR30MbMxQUpsYGSnReSCeq3wh1Wg9538mPvP1kbkk96
         jYB6c1MafXZMOrAm3G6iHbCJ6ZuT05JwuPY/MJYqWKI7NEHOLdW2P3ZnBzSeSHiOECAh
         qSjc4d8xQC8eb8YrmiwQw2f8QMV4LUqS6bUmhLjQaycXZCGlryLl41Psj8+RE7TEUeVW
         eCNgGiok6EJiZ4Q6n8OAvyFQ2QpiD1mc4F5ZHx5vLODXjZa/ONkgilaAh49kbjFxwVWI
         NBSf8bee8BHZC+B/nnSr2/NwIWBSEBxbkxRpt6MHWC1S9r3h5i7Ys4SF9nDm8mgRXWtw
         2+TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204377; x=1758809177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oLrMLqmWlGw5hQyr1BSvYTOQ+/YeCbPcB8nV6+GcRxY=;
        b=u5700j7nhqRno7ofaLL/930Z3pMWMIGkb/Xk5ZSE/y4XCt/l2CYr/672k0YQhf7tIw
         vn+b6m4Oxm/3jUIiYBMfOlDRwZWBmlL9XXzwxFSoTrNbSOvlVvbDKQVh6NzaREAdVyzU
         mYEvph8pbgIafXmPMvuArg1DmNGpirydqD59qEBT0usmzU/E0tBHTRFfwbahOdThvFiD
         mQRZ7YGALLsEWAhLOyuwR2P5Jwe9X15Dr1baHV96GicCh3Kp1y7+lBluhuwIjYTa019O
         nwGmDJK8a0oIxaxAVckWGfp9HCLuz0FD9+a70MSxMA25wIfxVgCaKEXIIgZ6Wdoq5DN/
         cAmw==
X-Forwarded-Encrypted: i=2; AJvYcCXIxUE492j9zlTJBPARugFSYgHzyNPvbqmHUikfCGhUobQbK3Cn234tnvY8bGWdEUs6OGTjtQ==@lfdr.de
X-Gm-Message-State: AOJu0YwH6eTvr3TKej9PWn+JWGBM38kddpo+4LBQLMO8vVqecg59gp4r
	LFItxLoq3srki/inkg5sVSxGNspGZaVZE/DXaPl0lr/cJx1hBeJPBIoX
X-Google-Smtp-Source: AGHT+IEE8FXV3ClvGSbGdYc532fd2Kx/8WfMGWow0JshmXVU7rN9HUuFzTIA1JkYOSX9FLf5uBHHqQ==
X-Received: by 2002:a05:6000:430e:b0:3ee:13ab:cd35 with SMTP id ffacd0b85a97d-3ee13abd14bmr1335898f8f.1.1758204377210;
        Thu, 18 Sep 2025 07:06:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7MBadiZBTTMs540fdM1a6KyhmrbqfuTZu6jhnBJ1Nj4w==
Received: by 2002:a05:600c:4690:b0:45d:d27e:8ca8 with SMTP id
 5b1f17b1804b1-46543b01aaals5440655e9.2.-pod-prod-03-eu; Thu, 18 Sep 2025
 07:06:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCj5C3t7i1ylWjU5S1Ha31dI9xoTJbHNuqtJXpLnZRrHCuB60eRxiMsOsOGorKOKiWGdb/UEl3oGc=@googlegroups.com
X-Received: by 2002:a05:600c:350d:b0:45d:d2cd:de36 with SMTP id 5b1f17b1804b1-46202a0e76emr48587025e9.12.1758204374409;
        Thu, 18 Sep 2025 07:06:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204374; cv=none;
        d=google.com; s=arc-20240605;
        b=eDdDw0C1qIfB2XgNw1anZZV6OTaWXx0zyknM7a/WykyhHNZdXyUqHBlSuD70W1tlO9
         dj5dQsh0PJXLbXa9qZmzNQsU29t6tF1bpdWknARQlsVuERONEEENwMtuScK9MnXXb/e5
         cxa+KHgZ+lu2TCF7HnQRI3S7oxwSPK9WDzsT6AkWKl1SStA2+/nx+/eGvCfHo3zal2xC
         B9iPvrh8xFBDWxCBoqi3pT3SEmnjTRmECySlNPs+Ns9Ug1S8gQhIwcHRBinNjzt7UZuf
         iv8HqR6d2Wh6Mg0F7LtzYHEQtG7NDumLffMPrs4kbyV9vKfaSeQkPQW1//rPJApfdzS6
         sAmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MCChN5JBLfNZD2oPUgHX86ngAxvuyY3UmlRN7HFHi28=;
        fh=cBUaH3Fd1it7HXPMg/RqN8WL/1Vzhs/FrmOAmflXcFI=;
        b=ebSCI3T3zxHoXhOuHy81IfbqcchCgmyiBGYhLOx0fdi8+QXxs6ItJ/bXRUshgKkNXh
         tYex8rvSIkyRieYZvWlAk5xR/6wJuLMBYNAIReOPPCDM/r3ktvy42BXJBTLAKe2qZzpa
         jxvILOsJvH7DNpn/boImvtdftcoHrHzW0oRrUXDu62FYiGy4fjeV/GMUwzFcmTgwS9ft
         wNZpTjpGPPaNd4u5OJ5tucMtnfu7pGDW//3i5/Jnl0H5grbdjrt8Mox43IyXtM85FJ8X
         RD0rYQbJrJTH/TlDPVOIEVno7S52zA7Zq5YBldiWUlmClpezVbXgpMrQ3sASMRuhUpa9
         JiZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BBEol6qa;
       spf=pass (google.com: domain of 31rhmaaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31RHMaAUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f320858d7si1228895e9.0.2025.09.18.07.06.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31rhmaaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45dcf5f1239so4589425e9.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9Iz3SljnXkdYrmY9Nixbd7L9CsLR8T73+MvJgGk22sDHYW13YB1XUFIbJGLNWxEkd76nuFdjYnTQ=@googlegroups.com
X-Received: from wmth19.prod.google.com ([2002:a05:600c:8b73:b0:45f:28ed:6e20])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:548f:b0:45f:2c7c:c1ed
 with SMTP id 5b1f17b1804b1-46201f8b0f7mr54930115e9.2.1758204373378; Thu, 18
 Sep 2025 07:06:13 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:28 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-18-elver@google.com>
Subject: [PATCH v3 17/35] locking/rwsem: Support Clang's capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BBEol6qa;       spf=pass
 (google.com: domain of 31rhmaaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31RHMaAUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
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
v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/rwsem.h                         | 66 ++++++++++++-------
 lib/test_capability-analysis.c                | 64 ++++++++++++++++++
 3 files changed, 106 insertions(+), 26 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 779ecb5ec17a..7a4c2238c910 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -82,7 +82,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`).
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index f1aaf676a874..d2bce28be68b 100644
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
+	__assumes_cap(sem)
 {
 	WARN_ON(atomic_long_read(&sem->count) == RWSEM_UNLOCKED_VALUE);
 }
 
 static inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__assumes_cap(sem)
 {
 	WARN_ON(!(atomic_long_read(&sem->count) & RWSEM_WRITER_LOCKED));
 }
@@ -119,6 +121,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assume_cap(sem);					\
 } while (0)
 
 /*
@@ -148,7 +151,7 @@ extern bool is_rwsem_reader_owned(struct rw_semaphore *sem);
 
 #include <linux/rwbase_rt.h>
 
-struct rw_semaphore {
+struct_with_capability(rw_semaphore) {
 	struct rwbase_rt	rwbase;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
@@ -172,6 +175,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assume_cap(sem);					\
 } while (0)
 
 static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
@@ -180,11 +184,13 @@ static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
 }
 
 static __always_inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__assumes_cap(sem)
 {
 	WARN_ON(!rwsem_is_locked(sem));
 }
 
 static __always_inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__assumes_cap(sem)
 {
 	WARN_ON(!rw_base_is_write_locked(&sem->rwbase));
 }
@@ -202,6 +208,7 @@ static __always_inline int rwsem_is_contended(struct rw_semaphore *sem)
  */
 
 static inline void rwsem_assert_held(const struct rw_semaphore *sem)
+	__assumes_cap(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held(sem);
@@ -210,6 +217,7 @@ static inline void rwsem_assert_held(const struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
+	__assumes_cap(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held_write(sem);
@@ -220,48 +228,56 @@ static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
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
-DEFINE_GUARD_COND(rwsem_read, _intr, down_read_interruptible(_T), _RET == 0)
+DEFINE_LOCK_GUARD_1(rwsem_read, struct rw_semaphore, down_read(_T->lock), up_read(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _try, down_read_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _intr, down_read_interruptible(_T->lock), _RET == 0)
 
-DEFINE_GUARD(rwsem_write, struct rw_semaphore *, down_write(_T), up_write(_T))
-DEFINE_GUARD_COND(rwsem_write, _try, down_write_trylock(_T))
-DEFINE_GUARD_COND(rwsem_write, _kill, down_write_killable(_T), _RET == 0)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_try, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_intr, __assumes_cap(_T), /* */)
+
+DEFINE_LOCK_GUARD_1(rwsem_write, struct rw_semaphore, down_write(_T->lock), up_write(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _try, down_write_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _kill, down_write_killable(_T->lock), _RET == 0)
+
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_try, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_kill, __assumes_cap(_T), /* */)
 
 /*
  * downgrade write lock to read lock
  */
-extern void downgrade_write(struct rw_semaphore *sem);
+extern void downgrade_write(struct rw_semaphore *sem) __releases(sem) __acquires_shared(sem);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 /*
@@ -277,11 +293,11 @@ extern void downgrade_write(struct rw_semaphore *sem);
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
@@ -295,8 +311,8 @@ do {								\
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
index 5b17fd94f31e..3c6dad0ba065 100644
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-18-elver%40google.com.
