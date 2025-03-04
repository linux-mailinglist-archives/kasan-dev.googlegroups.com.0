Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGUOTO7AMGQEAJHZFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 63447A4D807
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:49 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-390e62ef5f6sf1994168f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080349; cv=pass;
        d=google.com; s=arc-20240605;
        b=L85NKH7J6mHdCQd9U1KpAJZtKT39VGHNovydpVwdtZeWVeu2YnQz44lVFGh+WzLzv1
         MU1ooTObXQrZ3I+fQW0nztTf1EIjm1Pp6qIVJD2ohIw7qfPMPQghEpM6EzuXfxMESML9
         0Km7jhhp+rp0D13vBty4tpeRieqo15H+E/lPOzmC2pmq+FWl6LaRaQiP3ZaOeM8+Ns54
         Rs5GWml1GfKb/QXryv3WpUJkfJMZx7XLBZR1IF9GZHhT+36nCiVWVVRjKKi8cMqY2uaj
         9kKbailWS6ghQmtEGVojOJksTz5jINFk5jCQ+9cZQHfNpM9+cqUsmi3AwGCvALqVnjqS
         MIbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yBzExgWkUJI8WXfjDGTNca8ysg3RPrtszduqxi4+6Pk=;
        fh=1DqnhXh5qTkb04mF8knxK5YL1TVdM04PEvF2VgZzj/g=;
        b=f79jT758ERV6sddxfs/vb6GMdjXaOU1TKQfkiMcGMgAZU908z+Rx4lfwN8EXm4Fdq7
         voCYzyPVfdDpgB0NW71ktk2Hsky4FVbpLYGl9j+21OF4U4qRw2KvRaqs1nHy6Ry1MXj6
         567iMnGyK9yrm4z/4QGLlgxrdJavhCdyi9CnL4Srzfv9DO06CihSNApLYf1oaZkFVaKm
         O/UzE7vCWUwjIF5lhDCmxFlKxKN4o75VBeYY3v2jbLQJqELvs2NLNYLnzhWJg1WyLx/E
         Xf0XdaQON3EHQ9R4cN6xGGI/DMMGfOBv3GTKxcimbdmqaPQrezl7gMd77NXmjTA9siB/
         sn6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s7eZDwZf;
       spf=pass (google.com: domain of 3gmfgzwukcqcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GMfGZwUKCQcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080349; x=1741685149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yBzExgWkUJI8WXfjDGTNca8ysg3RPrtszduqxi4+6Pk=;
        b=oZDOqk2M4H2oCf7mKtlLBdl/PUz2ElJsr1O9i8yoZtBShnwglMqVXlWZ/j2lAm6pze
         7KI41epMnwF6jN3gqv+fiDTx3SuqN1L0oHWdyfSy7gU9y/yk/2nx7iHbqzHNl81GGRu9
         zFoezj16dpzHItRA/crmCLate32t0A9+h+nZX86kCHvhdVTx41+1NM7zXTtJGV2utLeH
         t3dDqOPDFO8AA1rmrBrplvEyj7Ehs/6SOJecK0XeNWfrmXPEc1LkhhIZHH0TgGIuM9tB
         jjVGcYpp5IO+Gm0p9SukEkO3EA4qnAfkAc1SEEwnmiASdwR2jYlGhWdJQ/mD7UesMK9J
         yK7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080349; x=1741685149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yBzExgWkUJI8WXfjDGTNca8ysg3RPrtszduqxi4+6Pk=;
        b=wR3dc19RKyIdFxbu1yzsj10E/8HrHihwQYKbXPxRT+Hj6W7cxPaGOG5wksnW1fTPei
         gj6JrGuZaO6OZ6NhjeqWQU4qWiFGZgqkurYR5ifDP12BsYFPEkRkH/cW+WyBLuZMeJqK
         GW2ZoL0YVhxMScj+fDhCKrg+YjIdTEGHgU69d5PbX7hL/cKZB347kZCKeegW2VHDulyg
         eiWXEiY9IYK4dfXWX/5+vhNdFklspprbUl4SadGt3Iob+QP0QQS+i1bvxbzy4gB334gJ
         FJbwTE1iEs2+Z5c4zCLnZRmnEt7rexnsHDQ0XwttFUNJCogOuV1zg4xkdIvLV9dasv86
         G9KQ==
X-Forwarded-Encrypted: i=2; AJvYcCX0jDTG9zLOu1Fz8UsVVp+EfNExulSkJ69wduYVN0kVGlmlZidIE3tceeGy+pNg4Om6asa7ng==@lfdr.de
X-Gm-Message-State: AOJu0Yy0ZJehk8D9YCZ6tWZGSicWi0zFGnCVybr1QstP/WZiEBORCjtL
	+Oz5x3zYwfUQyxS1L9Eo/cDuXkjB285xtaut+XWBJ80oxigzjz/I
X-Google-Smtp-Source: AGHT+IHttBkILBFnucuvPyDA/5Cjkx7VXajh0bpLMZhWiMMkaS/OwiVBX4QsxeYnNSGSnmfTUEOb9Q==
X-Received: by 2002:a5d:5f56:0:b0:38f:21ce:aa28 with SMTP id ffacd0b85a97d-390eca0709cmr13311982f8f.36.1741080347412;
        Tue, 04 Mar 2025 01:25:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHgJhtp6skqTtlpK8mMbxF0I+ILU6fLeHVMwU+KyHda6g==
Received: by 2002:a7b:c408:0:b0:43b:c5a5:5129 with SMTP id 5b1f17b1804b1-43bc5a55340ls6463835e9.1.-pod-prod-03-eu;
 Tue, 04 Mar 2025 01:25:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX5ThF+SAuApU08i7LCE2fjjf3YPAb342vFGbnuMG92BY/BBN/EhgP3R566E/8st43QDPPeEuJSCZA=@googlegroups.com
X-Received: by 2002:a05:600c:3150:b0:43b:c826:8801 with SMTP id 5b1f17b1804b1-43bc82688c4mr43428445e9.12.1741080344887;
        Tue, 04 Mar 2025 01:25:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080344; cv=none;
        d=google.com; s=arc-20240605;
        b=Jzon5PMBw8IRMmKHq88lJBBl236PRIAviU+1ES2cMKye7Qs+A5Ki90aAgLkvrQ1d1+
         2iikINAyTmXrIeWYU8JhArXUdDEv/hyC9NYIAVhVvaWwlktp1IB0DYQObbGk3LPECNBV
         r7l0/T6v0DXXSNnFJYWILZs8mH4zLK6VyyKvIPw5ZbqAjSoLKvfdrOuyqPIg0zJ/brJP
         rAfrM1zj8ZwpmJXw8jO5c1pAyyii5Kz5ZscEkFA1EDBrWD0CX62kkCTfjUaMM7JAx6Z+
         8wcal6CvBgjwCqYqco+Uk7Hv4864pVUinHJt0RGq9X1rzQfb3f0UpOKlV6ZStMWWc6Wi
         iclw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=7aDkMzmRnQvghHkOpkqZKF4mFOekC+EgfFoIEWs+/yg=;
        fh=21EDkh7ivMa61qvv9VPwdQDAK3axEE4O54FUmDUiu8M=;
        b=h+DjGg7KpQPnKgLOp6JYi9tv7LeEShmGEHhO1R8++xqA/IY2ZpyB0vtd+FBUkXq2n4
         ibwKcr08HKAEkwdcRKVPOoSoDZKI0ZwJPmwpt+prFU+RGleFhKv2yVYxv5xlQlnHevbH
         Ltdvwjtw0/FDI1VxOdbEzJvIPJtO0Z8BzohlqbkTp7rF+cgvJTaR+fCaOTG51gAQWXPa
         On+xRGW8ZZ09uaEaZUE4R02IYQX1NOOyST1b5kSZBF0Ja4vjVZdtNvrNiNAKlF8BIdcX
         zB/KmHrdHIwojdoRckh6lTygPmmleiFqjeI1ivvdPX4Vb0HEbF7G0QlxMqHMBb/UugyF
         DHiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s7eZDwZf;
       spf=pass (google.com: domain of 3gmfgzwukcqcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GMfGZwUKCQcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcbcbfae8si334475e9.0.2025.03.04.01.25.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gmfgzwukcqcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5d9fb24f87bso2371141a12.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVB7mOqnsQ2MOHLHBfS83EZR4Tb23VQXxKV9tumZwSggm2icI0IRLUzmJJjlW4e9CEYZ6b11xwuY9A=@googlegroups.com
X-Received: from edbin4.prod.google.com ([2002:a05:6402:2084:b0:5e5:2b03:2ee1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:348f:b0:5dc:94ce:42a6
 with SMTP id 4fb4d7f45d1cf-5e4d6b4b980mr18647852a12.22.1741080344386; Tue, 04
 Mar 2025 01:25:44 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:12 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-14-elver@google.com>
Subject: [PATCH v2 13/34] bit_spinlock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=s7eZDwZf;       spf=pass
 (google.com: domain of 3gmfgzwukcqcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GMfGZwUKCQcls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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
index e4b333fffb4d..65972d1e9570 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -79,7 +79,8 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
+`bit_spinlock`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index f1174a2fcc4d..22ab3c143407 100644
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
+	__cond_acquires(true, __bitlock(bitnum, addr))
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
index 74d287740bb8..ad362d5a7916 100644
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
+	int counter __guarded_by(__bitlock(3, &bits));
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-14-elver%40google.com.
