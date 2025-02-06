Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37ZSO6QMGQE7WRN44I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 44033A2B05B
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:25 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-38dbe7b6087sf559646f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865905; cv=pass;
        d=google.com; s=arc-20240605;
        b=PNpV5DF1bGrZCPzsZg7bynXfQZDEM+xS2baxRsYD5OzzLap84pEn0FJcNxi70GKarU
         0nwcLscvKDrsi+BI5nirqq9oMIJnKvv0Z1mUKmRML3V38l/qgSZMaelTAArpO3xsL1qS
         uDDF3qK9ETVjpqW4NkZS4JCQ5yOpWR9cyA3ksUVjIfpSaGArxCdi588udf7I/fjQZnRG
         hbCLZfFpFBcrgVzKFFx6XUaUYCGcm/z2muN/cje2dSA0E3bn+USkqjPxiAzLKyl6YH/z
         Plq7RnhKwEoE8YifZ3TfTRkB+Fvi+M7TQvZ1YIRAqh1ru0pj76jckNrNquokyZ0TMd46
         UChQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SpX9pPHfcDS8PhK6/g5D7p22yXWzbggQdJQ6puF/VUU=;
        fh=gUwd7yXUNn7DJDTguTuGZNG67zlW06HKfq/c1GEJq6A=;
        b=I/xbS7L8MLwjvFrEHQq0VpSIMQ6V/jDYwSKHHMx0gaU/S/lKUzwyQdVzlFSBaRl+sR
         z4s+WrHnJKpLP9/vyZ3y8hWdRQO8ReAMnffQFMmNFecnFFn08ABmg4THWW3JkMeIT26j
         8RuzdRovbzfHL9FBAvNBgQa7K6L+vpoHjP8rVkOqZaZun/Rc7NzbVCILEz7PamBU6uds
         nuQkh42TucHx42SKvXCgznbgoXr3u7fulJh387OQz4AJLuEW3idS1T9XMepX1z7TCXA7
         x9jsdrGbVzN6ss4vvUWIeav65y6NH8AGLNcq9zVU/ZxTIzKkamfIPS43b5n7W5tZP030
         0U/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="AbH5vD/O";
       spf=pass (google.com: domain of 37fykzwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37fykZwUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865905; x=1739470705; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SpX9pPHfcDS8PhK6/g5D7p22yXWzbggQdJQ6puF/VUU=;
        b=b3rCof8i2Qt7lWN81GJ7x5mvbC9jTs0PPtHK0cZNlxUNJ800Y18j52ATB84g6GXOUi
         QNXftO4od/md0co6DC1Y16ipPdr9kMtQnM0U4JTbiVjnrMgWWNoHS8vcya2Lgz6EmtSE
         WzVoRDypp68BTb4oylRS8eqx+DPlclSYFEpucnrjNXk5JLpdf1zArdw7Jrm/L6OJ/Zqb
         5X8dtJe1KslOp1QlxU5/zWlkynT5+jKiqr1LqQ1M4seco6n0N0EkBz+mxBAVfDjvsPQk
         vnNT9nIU3gdpYivr+n1l0wXC+wnozBCAAYijlXdrYrc50c2QWt2Wr9ehFtXPbgLnU4tN
         OWIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865905; x=1739470705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SpX9pPHfcDS8PhK6/g5D7p22yXWzbggQdJQ6puF/VUU=;
        b=w/AQlK4fpVRCYrWzfYX0NkslSjMePes6z5JKwQSskjx3OXwYAHCD8xixKX2hhFpGXX
         KEFl//lTWHPjp4FNeASEgbKPbiPBFZlvKk3q8c9v+jCQZujs6JLrkxlN3LfxMZaAy3dm
         MIPmzuVLHtey1FPi/hLvUQS2tx8amwjPryrDAl76rRHoKux0AcCrENzr4/YsKXYDmxOW
         LikS6JTcVPrP4Tk29CoElIiqsESDxOWC/fRY23nYFjdgxxZSwGz4Rj6YWTlerAXawW9v
         /Wya268BDBx0AWxj9Iz+/tfZAiE2h6fdp+cguI6/S6xnHiv36mBc4aMwrnrGkw+AOmOd
         Jmcg==
X-Forwarded-Encrypted: i=2; AJvYcCWiRFmcEdGr94da4AoDHbo+c0sCxJlme88ATwXvzRuY51WfgKCO9nQmPXP22muvEs2PL51HuA==@lfdr.de
X-Gm-Message-State: AOJu0Yxgjof/1V/PBSzjEjcBeCI7pXHAXad1uPScT1cGVHlrfxhHsscC
	RPmEZjWcRU2Qalz4cU+K9zsp2htcgnmG7K895iQ/PDbgI/ORM473
X-Google-Smtp-Source: AGHT+IF0iNyVV+gBFgDTMMTZ9/UaaOZ68gK7LKdiX7hYx2VV7BzjJAqfNJFpeMoEjJLPKZ2xB/zX1Q==
X-Received: by 2002:a05:6000:1acc:b0:38d:c2ef:e291 with SMTP id ffacd0b85a97d-38dc2efe475mr1882550f8f.39.1738865904094;
        Thu, 06 Feb 2025 10:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ab0e:0:b0:38d:c747:1cdd with SMTP id ffacd0b85a97d-38dc8dd35fels1698f8f.1.-pod-prod-02-eu;
 Thu, 06 Feb 2025 10:18:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZMdJqcxeW3q9WsCfDo42xz6ufOeuhRTDJM6yEpiAhTcaz5x0kijIqVet23jlyR82e/12B2x4kenc=@googlegroups.com
X-Received: by 2002:a05:6000:1543:b0:385:faaa:9d1d with SMTP id ffacd0b85a97d-38db4929c07mr6942138f8f.35.1738865901715;
        Thu, 06 Feb 2025 10:18:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865901; cv=none;
        d=google.com; s=arc-20240605;
        b=aOt0TzpGhRf6MQodSV76vdUlN3Nw2ebf5fnWiLD6cQ/jPVFTO7E8DnwprhrDh3jQh4
         2XoHvxZH5N3DYHNiYNovVsljDy+U0E7ghAyp/nGTOW8VnN9o5KAFwfr9l/r8NXxXwzaN
         1UiQxwj6mfANUISPCWNKRQwvUOpjH/W35Q+vwlIEq7yUOvXHqfDqvXe1eDtaL8elk0CM
         z3v3l6DyifTwFOt9czqCdveFM3oRRLRvIXDrgfjAaxWx8IWMxRHwVByPVN7whq0IlmUQ
         fsg3Brpr67UHxrAlwKEkoJZUhrcqAvHxqECpNGbyb8KHxTVtOpvzBl293W/eEn0g5PA+
         Eq/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=wzjNorLMqe8QUgEHsGwtuhtrhRqTVkmGkehlX/wsBpI=;
        fh=Wil57G4kjKBpggV9luAu9c+JAweiGQKK0c5v8lM2ab4=;
        b=jeUPbvKLDYjjbMEE7wy8nmFLNixdFMe4B/sfctjIMNCYBQ0nQ7d0El0UbIhJMmc543
         pu22nxPEf46XzvltPhz8fvGVZ9Q1Jx8LX0LaCPSQXGSGP3TosYJAIVON9HT7HG3NKFQu
         uowdTU1DSlRCJEGyMb/spVxU9/TGmWS7NV3RG4a47ckK1Hi8qtXouVn61WnCLAqT22Tg
         QLO5sM4ysXL0bLN1AkYc6IwXl2N3awNLBf/Y3Bb6gWhX8eEBabE77EH2v0xa2ofpcan+
         zNOkMM5rkyZTc3OKSK1YHmS+xh/5YfuPnvcC7lQPWKtqIHFl+LuWyFSWVoo481FjhZjB
         o94w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="AbH5vD/O";
       spf=pass (google.com: domain of 37fykzwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37fykZwUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4390d96a63fsi1215745e9.2.2025.02.06.10.18.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 37fykzwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5da0b47115aso1317176a12.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV+8kNudM7jF3kjiOk8D9OKAIw6NKj+5B0iLaI/ujRzcC+/7+VRA2qWx1ARSHVGG8qfJuSiHdQLhvA=@googlegroups.com
X-Received: from edag33.prod.google.com ([2002:a05:6402:3221:b0:5dc:74ee:c4dd])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3903:b0:5dc:da2f:9cda
 with SMTP id 4fb4d7f45d1cf-5de450e1eccmr537344a12.27.1738865901391; Thu, 06
 Feb 2025 10:18:21 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:08 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-15-elver@google.com>
Subject: [PATCH RFC 14/24] bit_spinlock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b="AbH5vD/O";       spf=pass
 (google.com: domain of 37fykzwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37fykZwUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

The annotations for bit_spinlock.h have simply been using "bitlock" as
the token. For Sparse, that was likely sufficient in most cases. But
Clang's capability analysis is more precise, and we need to ensure we
can distinguish different bitlocks.

To do so, add a token capability, and a macro __bitlock(bitnum, addr)
that is used to construct unique per-bitlock tokens.

Add the appropriate test.

<linux/list_bl.h> is implicitly included through other includes, and
requires 2 annotations to indicate that acquisition (without release)
and release (without prior acquisition) of its bitlock is intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  3 ++-
 include/linux/bit_spinlock.h                  | 22 +++++++++++++---
 include/linux/list_bl.h                       |  2 ++
 lib/test_capability-analysis.c                | 26 +++++++++++++++++++
 4 files changed, 48 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 8d9336e91ce2..a34dfe7b0b09 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -85,7 +85,8 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
+`bit_spinlock`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index f1174a2fcc4d..57114b44ce5d 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -9,6 +9,16 @@
 
 #include <asm/processor.h>  /* for cpu_relax() */
 
+/*
+ * For static capability analysis, we need a unique token for each possible bit
+ * that can be used as a bit_spinlock. The easiest way to do that is to create a
+ * fake capability that we can cast to with the __bitlock(bitnum, addr) macro
+ * below, which will give us unique instances for each (bit, addr) pair that the
+ * static analysis can use.
+ */
+struct_with_capability(__capability_bitlock) { };
+#define __bitlock(bitnum, addr) (struct __capability_bitlock *)(bitnum + (addr))
+
 /*
  *  bit-based spin_lock()
  *
@@ -16,6 +26,7 @@
  * are significantly faster.
  */
 static inline void bit_spin_lock(int bitnum, unsigned long *addr)
+	__acquires(__bitlock(bitnum, addr))
 {
 	/*
 	 * Assuming the lock is uncontended, this never enters
@@ -34,13 +45,14 @@ static inline void bit_spin_lock(int bitnum, unsigned long *addr)
 		preempt_disable();
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 }
 
 /*
  * Return true if it was acquired
  */
 static inline int bit_spin_trylock(int bitnum, unsigned long *addr)
+	__cond_acquires(1, __bitlock(bitnum, addr))
 {
 	preempt_disable();
 #if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
@@ -49,7 +61,7 @@ static inline int bit_spin_trylock(int bitnum, unsigned long *addr)
 		return 0;
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 	return 1;
 }
 
@@ -57,6 +69,7 @@ static inline int bit_spin_trylock(int bitnum, unsigned long *addr)
  *  bit-based spin_unlock()
  */
 static inline void bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -65,7 +78,7 @@ static inline void bit_spin_unlock(int bitnum, unsigned long *addr)
 	clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
@@ -74,6 +87,7 @@ static inline void bit_spin_unlock(int bitnum, unsigned long *addr)
  *  protecting the rest of the flags in the word.
  */
 static inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -82,7 +96,7 @@ static inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
 	__clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
diff --git a/include/linux/list_bl.h b/include/linux/list_bl.h
index ae1b541446c9..df9eebe6afca 100644
--- a/include/linux/list_bl.h
+++ b/include/linux/list_bl.h
@@ -144,11 +144,13 @@ static inline void hlist_bl_del_init(struct hlist_bl_node *n)
 }
 
 static inline void hlist_bl_lock(struct hlist_bl_head *b)
+	__acquires(__bitlock(0, b))
 {
 	bit_spin_lock(0, (unsigned long *)b);
 }
 
 static inline void hlist_bl_unlock(struct hlist_bl_head *b)
+	__releases(__bitlock(0, b))
 {
 	__bit_spin_unlock(0, (unsigned long *)b);
 }
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 1e4b90f76420..fc8dcad2a994 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -4,6 +4,7 @@
  * positive errors when compiled with Clang's capability analysis.
  */
 
+#include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
 #include <linux/seqlock.h>
@@ -251,3 +252,28 @@ static void __used test_seqlock_writer(struct test_seqlock_data *d)
 	d->counter++;
 	write_sequnlock_irqrestore(&d->sl, flags);
 }
+
+struct test_bit_spinlock_data {
+	unsigned long bits;
+	int counter __var_guarded_by(__bitlock(3, &bits));
+};
+
+static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
+{
+	/*
+	 * Note, the analysis seems to have false negatives, because it won't
+	 * precisely recognize the bit of the fake __bitlock() token.
+	 */
+	bit_spin_lock(3, &d->bits);
+	d->counter++;
+	bit_spin_unlock(3, &d->bits);
+
+	bit_spin_lock(3, &d->bits);
+	d->counter++;
+	__bit_spin_unlock(3, &d->bits);
+
+	if (bit_spin_trylock(3, &d->bits)) {
+		d->counter++;
+		bit_spin_unlock(3, &d->bits);
+	}
+}
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-15-elver%40google.com.
