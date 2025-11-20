Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXW77TEAMGQE2W7MWJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2170BC74C36
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:32 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-b735400de44sf94570466b.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651551; cv=pass;
        d=google.com; s=arc-20240605;
        b=FP8QU3kBOZvNcfr8GI4Rb42kSB/veUvOa7obhTlbw6PNh3v6Jm88UqiGAtJ2DP8dwO
         nCDFKLaxs5p0STxS95P3bCPwN6eECoq4KggYfilfh0HdTrl9K3RDA715ZPLfU1YMBneQ
         mA8G3gAfxJ9y3gJ7Im3Djbcc8RpHQVfzTwx3X1+TsZQsZGbA7cn7pt2YXADO+lplENcr
         VUEd4N0/LQ2zS82X9aLhtFZut8rMZymPnLCCa4fBmwPhj5wZJz8of5Kp2SC+t/WHG9Qe
         heSgYeX3dPeHioYoRAo36uAWG5TvESk8blx0oOs3AggveGy1YYVlTrJNZ9LcUzl0GEWm
         ghxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qa/Rv68h5jquu1Uw+mOmbo1vPbtVHIVLemPhR/W2+Io=;
        fh=szBiQ3trVlt5H8sc0nLJ3if24TZ+QgDO1IIaSqewHTA=;
        b=RH9YiTC4HWio+GbWkqqBBF14whyYCdlY73b7aYjH23S4nlTqwKYi4xWGNBeoXAC0F6
         +yENfbAioKdkv4CpjAl/yIL9rX9cNXm9k87zNMGZd8zeFn845jnaqR/Pee5s6lY5Wjpg
         hq4/VER1C09egbaCR1HgWMFukg4HJK6B62k8gr3e6M6qqo7UwtKBQUCXvbgafkSlIsbj
         +epXPuspzQhxhFFUIGyF2cPCJM7BsvNRWVPCupI4EiQZNV/kYvWqFSW54Vun59H2MExX
         nZ9UgNbEq1wx85WzQlMj1AJMt8S1N0J4TcaVDCirgb3fCU+fNIH4pgsz9soKK3JNnw7r
         wEEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="FSOcW/0c";
       spf=pass (google.com: domain of 32y8faqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32y8faQUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651551; x=1764256351; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qa/Rv68h5jquu1Uw+mOmbo1vPbtVHIVLemPhR/W2+Io=;
        b=YvYCXtWZCthlTy7fRq9Ec/WOhHB2vz4OxD864sIEyOqFLk+F4QUYuLQfRrKvLW3STv
         KZNHd+5lZRkUHhDnGMzSkJa6YIDERG6VNPj5lNaJOUZsmskqarEd3gPQdILsCzslSGJJ
         vQHRkyHepqFm/Z+la5Jla1IIlEk8/S14Dv9dxN1K+aB41USBx7BXWlSa41SOw+5qq7eu
         9wij7oDTWSNdG8oDzw7q8NgJV7riIMiFAfeFMGJ2VhB+SmaoIBfhtHaE4LEmCV8jwNM+
         OmB0ImdU6z77dT9KVmCHCzlb04e6qT169t/KQBZce0T9NiWjOygyYvr8LdmnDN2zvkLv
         qKPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651551; x=1764256351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qa/Rv68h5jquu1Uw+mOmbo1vPbtVHIVLemPhR/W2+Io=;
        b=brVyMOYMkS58Gla6JKa5N9xwqbmsR8+3m6gzZV+pQq7f8vw0gOGVsKvdDt205lI1NP
         XS6CKg24895C1pDysBS0PBozJWzJafLhR1PQsEWKzWLeRjKMk12CgN63GW+Zru1AhBpv
         5BY0ggugvB0rZfLstYDlifrnmszbTxRLUnvbkigdIICqfyzqVf73kMTD7SrEjRAAZjWf
         H4sydTEJKYbKVWoxeoTM7sloU8HR546Feur2kCHhL1GXz6zSz/vpLdDNMeaTSf4Bmz8Z
         gaFFt08xK0di50MnfQ5abn5Fo05BuFO0Lmqe9VFd1EP4RiCf7srMlrnNPz7HS4nfJIpt
         6XUA==
X-Forwarded-Encrypted: i=2; AJvYcCXQGRFByJnn8yVtvWrurmbs1WoZ0JMHc2mPE6mGbbyfAw6L/inH5KtcdsVrh2F0gTFP9q6uiA==@lfdr.de
X-Gm-Message-State: AOJu0YwspBu+H38ZHF3knEGNTKhDSOb8B5HNDzX+s6pnsPbQ9AJnwPrK
	567mYD2JIc/0BGi4CVI5CPepGFx2Cv9riu0v4C+qdGVu6wnAxV1mxDoP
X-Google-Smtp-Source: AGHT+IFU175hrod8XVCz1ugrekNjYG9YTdQ4UEc8gn5C5bsUM8F2BIH1WD+vEWhCjNqrFLWAU582rg==
X-Received: by 2002:a05:6402:3506:b0:640:93b2:fd07 with SMTP id 4fb4d7f45d1cf-645388e31a4mr2487275a12.33.1763651551561;
        Thu, 20 Nov 2025 07:12:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+atmul3DTNYQtB51fN5EpPhPGaW06Jp+aMR6+WkazC5pQ=="
Received: by 2002:a05:6402:5167:b0:641:68af:a582 with SMTP id
 4fb4d7f45d1cf-64536411056ls1062585a12.2.-pod-prod-02-eu; Thu, 20 Nov 2025
 07:12:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUa0pXJEaGLnDER6nTZxSZSHYAYwDioY9qm9fd1ZXmsFyG8mLMXORnIhFUuQoDeDbfIBYD1efYNNUE=@googlegroups.com
X-Received: by 2002:a05:6402:42c6:b0:640:95fc:2fcb with SMTP id 4fb4d7f45d1cf-645381bb2cfmr2625703a12.12.1763651548616;
        Thu, 20 Nov 2025 07:12:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651548; cv=none;
        d=google.com; s=arc-20240605;
        b=VfWOLW7+yuqkaYg9V0Lf8PPbrXyRd9xt8GRLTJXSxlgXpOwqhVH/8/iegcXMhRSskJ
         Y15nCz4WsGrVEa4ehEbnk/PAQYFZgyhmwHgSXH4y0llIScsROUpYWZTbhfSXs0ZU+Rid
         pT0zhilcfwptixTRdttIOxMtGt0gPupJUbnNOeTjKAOapOe2wTGajJP5Etn6RpR2Ovq/
         3d/lAQII4dH/lJXfYk6yV3cWApFWpBlt5gP9lZwhz1frLMztSp8N3ILLUI28lYjVXlgk
         ZFlulDviTjE+1XQXpfWbvAPA9KVrJ2W7gIw4qOYbvQLmPzOtXYmZ5DqWokXOFDZJHZbG
         CqNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=IMqqhFVNLAUw4V1kneJBauR05JGQwrZoFZiIsH/esVM=;
        fh=Lcm955xhSmQqIACFxBXARiI0w9RM6UbEljA+y/nRcM4=;
        b=GfXSqNMbmiaCsCKlWQZwWclS1WJ/fsXOxQE1F2BVqT/V0nSlvxAkuMBMiVhyCet9bp
         HIVQEggmNwx1AdgqvTXGDCmWcMVXmInVINjBsWJZnfsRIQ5blw4BoaQbradjI1wyZPJd
         N4iZDFMJ5MUxD8RBYVDUDvfALoiyCF16pyLZa269/CE3O9o6yXTuNICYnNbvCaZpXSRi
         Pnp//YgwXeqfsN1jQaaZ0Grq/NCNz5EqO+6uweorZaYQKI746bhrJk2JXvwiHCTzg0Ye
         0WCOzefafqX8CXP95AvGkV0h5wof0jVLn5hfCNzxMS2aMkk5m+dFt/qrp7qJo25UnFLg
         /nwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="FSOcW/0c";
       spf=pass (google.com: domain of 32y8faqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32y8faQUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6453648cf50si73440a12.9.2025.11.20.07.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 32y8faqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477a11d9e67so6445115e9.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWKN/juV2phiEQxrmSQqQvZOniEgG31+wr4TRwQaUH5YieHVBkHneTvmC+tdMnDkB+vt57H9JFiux4=@googlegroups.com
X-Received: from wmbgz10.prod.google.com ([2002:a05:600c:888a:b0:477:afa:d217])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b16:b0:477:632a:fd67
 with SMTP id 5b1f17b1804b1-477b895407bmr35716765e9.12.1763651547909; Thu, 20
 Nov 2025 07:12:27 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:38 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-14-elver@google.com>
Subject: [PATCH v4 13/35] bit_spinlock: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b="FSOcW/0c";       spf=pass
 (google.com: domain of 32y8faqukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32y8faQUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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
Clang's context analysis is more precise, and we need to ensure we
can distinguish different bitlocks.

To do so, add a token context, and a macro __bitlock(bitnum, addr)
that is used to construct unique per-bitlock tokens.

Add the appropriate test.

<linux/list_bl.h> is implicitly included through other includes, and
requires 2 annotations to indicate that acquisition (without release)
and release (without prior acquisition) of its bitlock is intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
---
 Documentation/dev-tools/context-analysis.rst |  3 ++-
 include/linux/bit_spinlock.h                 | 22 ++++++++++++++---
 include/linux/list_bl.h                      |  2 ++
 lib/test_context-analysis.c                  | 26 ++++++++++++++++++++
 4 files changed, 48 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 598962f6cb40..a3d925ce2df4 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,8 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
+`bit_spinlock`.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index 59e345f74b0e..07593d9003d5 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -9,6 +9,16 @@
 
 #include <asm/processor.h>  /* for cpu_relax() */
 
+/*
+ * For static context analysis, we need a unique token for each possible bit
+ * that can be used as a bit_spinlock. The easiest way to do that is to create a
+ * fake context that we can cast to with the __bitlock(bitnum, addr) macro
+ * below, which will give us unique instances for each (bit, addr) pair that the
+ * static analysis can use.
+ */
+context_guard_struct(__context_bitlock) { };
+#define __bitlock(bitnum, addr) (struct __context_bitlock *)(bitnum + (addr))
+
 /*
  *  bit-based spin_lock()
  *
@@ -16,6 +26,7 @@
  * are significantly faster.
  */
 static __always_inline void bit_spin_lock(int bitnum, unsigned long *addr)
+	__acquires(__bitlock(bitnum, addr))
 {
 	/*
 	 * Assuming the lock is uncontended, this never enters
@@ -34,13 +45,14 @@ static __always_inline void bit_spin_lock(int bitnum, unsigned long *addr)
 		preempt_disable();
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 }
 
 /*
  * Return true if it was acquired
  */
 static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
+	__cond_acquires(true, __bitlock(bitnum, addr))
 {
 	preempt_disable();
 #if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
@@ -49,7 +61,7 @@ static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
 		return 0;
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 	return 1;
 }
 
@@ -57,6 +69,7 @@ static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
  *  bit-based spin_unlock()
  */
 static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -65,7 +78,7 @@ static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
 	clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
@@ -74,6 +87,7 @@ static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
  *  protecting the rest of the flags in the word.
  */
 static __always_inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -82,7 +96,7 @@ static __always_inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
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
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 59c6642c582e..77e599a9281b 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -4,6 +4,7 @@
  * positive errors when compiled with Clang's context analysis.
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-14-elver%40google.com.
