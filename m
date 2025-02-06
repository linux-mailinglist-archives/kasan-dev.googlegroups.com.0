Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6XZSO6QMGQEY63KD6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 54EA0A2B060
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:35 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-38da839b458sf518514f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865915; cv=pass;
        d=google.com; s=arc-20240605;
        b=FeqaC0eaX6mr0DPuY5EGdz5K2avmiwGgeuSyHyYMXlmqr9biLPX+O8vGsDmu0tWpgv
         clQss4/1noc/A2PJ0MaZzEAIIdKtmlmf3/RfwwIs4QSwvYQ0PZJR+3+6EdIAEuuk8qdW
         4H+GUoJoY6YE1eYYLzhdhybpnfXRD2v0daHvVJQ5w1ICIJ3iZvTDIVUAHsXUto6iUof5
         +EMuzjLg489P082hCM/Js/13nU7QOQNtJwXB1ZJ939LJiN0Ba96q1C40XFY7suhp17W5
         ut3LneEc38e/5Luv6lTywdTdLoNG19qhNNa2i2GQyRx2jNE7Fx3G3SR6d+7Yy/gECEGc
         DotA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=R+sEFRrjyD46DSHlZh3S1KrMKAmq0zZVOHa92DSeydM=;
        fh=BWvYj6zIA6Z9icO3ZXSUkJgMDEkf1VqqRlvuCfJ9QHs=;
        b=PtBN7fhrFYNhPhgiya0HAd9z8hmsnNXjbYWM6iP9eCncoIbzUxJyPEb+MjpFYl1UhL
         1wyVq1aZUZiWwSKtpT72WKx8UbE8r9HfQ1PjkQLRinCz6KMvINTbJqv9DcloMbTIvhfN
         ClP9qrZMroqXUSxaaKdFYHMAQYcwl5oJPIiNNyyD+ieSfRDp4Om82mAjP4ssBp0gJEYr
         SxZNKOemL36e8037+SN0vC6IqgBDSxasVSh4RzfAoGzfyJfkKV3gYh0ckBYpZy5wWbgB
         Mh6cjS4jB1FcIidJM+XWJAOtEbCLW1TGGLHL/UI28/LrjAeMzIctfhwnT8Q0BLzMpJse
         vY6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eXyeCbpz;
       spf=pass (google.com: domain of 39_ykzwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39_ykZwUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865915; x=1739470715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=R+sEFRrjyD46DSHlZh3S1KrMKAmq0zZVOHa92DSeydM=;
        b=xK+F9bgPINBZcHcs5KMkmCmFnkxao5xVnclXDkMdKKwDGRGKM20ZmEH4mAANhzzv/3
         OAWtZJJHiGA3by9VS9moF55FCuEwdB1RxYKLJwsye1toap/zFxg7CpIC2/8OBdXQncC/
         IP6MuBcj1pMtOAPdSfelfVIrCGGmEuzpN/U0HNVyssuEXVbvjyfinnb5VhmN1depFlaP
         iOnF5ScyH76yJT2UXvmmVkGBKkBAbC7W3+MN/cuNvmJ8bnjNY0EWt/B/buTANidOaMVV
         3x17BPzr6h0gOlXwmuXD17O/m5z1pov/HIr5ESDeqO4Z0jXLzcEivhIZLamStOka7oCo
         qEpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865915; x=1739470715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R+sEFRrjyD46DSHlZh3S1KrMKAmq0zZVOHa92DSeydM=;
        b=dKFoEjV6FEhsxBr6vd5GgHTq4vc/xyBQ0d4gVAJs/X0ctGGYAkEZEYPbc/xSdgDW+F
         CWhliq9Ojq75ecycHstf4uUmNXkQUtPoPte79Gn3zo0Wd9l+DrrZnNFGoJSkWaAj+v/i
         Ji3L6AtSPD17SeLmIPEOP2ACbSgHJb5n8Gz4x54GT3mh2LcPnA41yFpMl8tH+ZpfSIbV
         Ka12GMLx4xOX6tpJlKW+keUhriYdhg0UutOKWv7i0+DwMF8YvFTM5m1zRBNQkuwyRg30
         VXBriLnr2PFrY4PqbfmljgtcwIZggyg6EwfMUYIeh+Mkdv4JUL69k1kLHApIf7W3kR03
         x2AQ==
X-Forwarded-Encrypted: i=2; AJvYcCW60Ac/ChemypKJjfaIwxlVhByNgGX5gU3SPuRrC0CQhRUuToX/EBRO06Py9sqLlhyUKYG//Q==@lfdr.de
X-Gm-Message-State: AOJu0YxXhmbXMDJc8xrUyRoPCC7MTkG6PLhunLgJaS+sGCXmbnoW5Kp5
	pCoBOijepNaaw5rBI3LkEa341s85cuRtIeORO9s8iAohCEiD75p5
X-Google-Smtp-Source: AGHT+IH2xgzaInESPoii72lfTEDsrVR/HxxM7m79cX6/mhTPHu0dIcpAYqr8XeRvZ8ckIpSFMAM6WQ==
X-Received: by 2002:a5d:6d0d:0:b0:385:fa3d:1988 with SMTP id ffacd0b85a97d-38dc8da6410mr25271f8f.8.1738865914438;
        Thu, 06 Feb 2025 10:18:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ab0e:0:b0:38d:c747:1cdd with SMTP id ffacd0b85a97d-38dc8dd35fels1729f8f.1.-pod-prod-02-eu;
 Thu, 06 Feb 2025 10:18:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU6NOLEqSD6ZBIBWKax8ZT9icDYeJQvTbz91L9T9I4iE1LXN9K8XrOtgdmnj8pl24WTOJLe0MeIElc=@googlegroups.com
X-Received: by 2002:a5d:588d:0:b0:385:ecdf:a30a with SMTP id ffacd0b85a97d-38dc91031bdmr8916f8f.33.1738865911918;
        Thu, 06 Feb 2025 10:18:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865911; cv=none;
        d=google.com; s=arc-20240605;
        b=CQnnNrLUdFxZvIIBMzd3vp6d/a4bxzb275sUkRQrSL70+HbkR/AzIcG/zIxVTpKVTY
         qlejPNYoV/xWle/YeR088M57DQSXWLDKsofJ/99E9ulqvsAdgLnd7EELXHtsknkbZB1q
         sdNjC4n1wvxdStuqkMM/Fp0+/twvsqerJi1xlkylMkmYT8SdmfWC8gqiWtcPDgqjfR67
         1nr5wwgOBK0vySFpLobTDyS0/PxIbKSLEGjTb7+koJfEytA7m5WApKr4H0TIr52FUL52
         WOM2EWMzMaOFeZbKPECXleMXrNOqlxLz8C3kyO+lcuRLsQ3hYPzWSzWgGj1iqQZ7aF0J
         Wo3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=9TIY+XnKqDQPKONLGJPgemro/50zRzCvFBM/gxQTHJA=;
        fh=3xilOlNa3DRcAfUfL4un7/DS9p6sGOeBH80zlKw+DFc=;
        b=fsltbGMVZERcsPQJHfCnunt0emE/+BxlEPtpx8b0vC4LOV6cPo9t8naLDOf/lHBqBn
         ZUTuKCgn7uYILhWLFLi3i0anPP2/JWSezdX82OIV5PR2a8FOH/Fd8o8aw0HiG1hcQCEa
         fl0OSrTolWbIB8xL9LEcQvx30jFtScdj2lb8E4KiU2jZWdbZbTsqVV37ZqQ8I05reiis
         UhgSjDHe/lXP42gao1+i7xhUsPwwKUW0CFsVQqlZDFDGtbGXQlVdHI1MFQVDmu03vreS
         0HhfHhVqhLHex5jt/kXogv9b7dAG4i2JeWmQsqP9FeIaQS3q8BOl/aL12OsdfBPpTo/o
         qV1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eXyeCbpz;
       spf=pass (google.com: domain of 39_ykzwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39_ykZwUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dc891e410si609f8f.2.2025.02.06.10.18.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 39_ykzwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5dccdef8f04so1453740a12.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZY1g+PXzo3lNerATsY43QFsca6apZF8GfeSWMIOsnTFMc8r6vz5a9EKFjSVaCh6EWMrYsL3GOJCs=@googlegroups.com
X-Received: from edbij8.prod.google.com ([2002:a05:6402:1588:b0:5dd:2e6f:2549])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:42d6:b0:5dc:5860:6881
 with SMTP id 4fb4d7f45d1cf-5de45023562mr572207a12.19.1738865911608; Thu, 06
 Feb 2025 10:18:31 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:12 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-19-elver@google.com>
Subject: [PATCH RFC 18/24] locking/rwsem: Support Clang's capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eXyeCbpz;       spf=pass
 (google.com: domain of 39_ykzwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39_ykZwUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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
index 3766ac466470..719986739b0e 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -86,7 +86,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`).
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index c8b543d428b0..0c84e3072370 100644
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
+extern int down_read_trylock(struct rw_semaphore *sem) __cond_acquires_shared(1, sem);
 
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
+extern int down_write_trylock(struct rw_semaphore *sem) __cond_acquires(1, sem);
 
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
index 8bc8c3e6cb5c..4638d220f474 100644
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
+	int counter __var_guarded_by(&sem);
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
 	int counter __var_guarded_by(__bitlock(3, &bits));
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-19-elver%40google.com.
