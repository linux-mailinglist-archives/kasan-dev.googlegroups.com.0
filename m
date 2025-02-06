Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXZSO6QMGQEUC2HLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DED6A2B052
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:08 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-38dac77e561sf470805f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865887; cv=pass;
        d=google.com; s=arc-20240605;
        b=iokrp84eSFZjJXAJAiM/jycSvqKGauyRlJuUw4JT4y72zCuRFsPIXZRU6PHgGhDhzm
         2YIXGbXzolGvjeXqHEJiqjuBu1LNy4LJ244Q35svUunn0I9txuFVcDiZhvBac+6vcUjb
         lPSZVntbBkM4Pt+EhteNDtowZ/rXxRz+UTepqSY18nYuneG0sb79q2yqPmydX6T8L3xA
         LnokldyJ5CoPiIf79uctsDapXr3mnCrSwq47V7p9+UGZbmnvrleu0tbWtqL11I1N2Mkz
         V+BHtZ+M1frGRvMfwQXJPUHa+PPqEnRMVAdbLWi7E5b+RicjkTrniWQeKMueR46d5jdW
         2hyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=cjGdbdG6qCQmVa+syZApAQ3WrMlxt/Mkpc0h11SIwIY=;
        fh=wHfyobSCo/lV4TaUz4h3mXGX2f9b3a38EdtT/b9O39w=;
        b=IcudsFyogPSeaVTSlOOP5plciLHevN83JmKBmr2FCRKuvY1rLP6bel0s2pIdAFBEgI
         tsDSzAbwfb78RdCdCBeM+4cN/B/Y29x6S6CWIzGG/k3pu1WzBxJgBnEmCohDw7HDW1gR
         QD1iHIFUypaqS0TFrVpY0nqWtJqI9A63Tss8+eCOKty4o4zJkQsmUNFRoaqlBhB0vcc7
         ZZSrBODxAx2MSwOgpdnwEv1nOK+lvzZ/V0NmLDj4/8FnNR+5lTQOxThJG0R2hLhy0Umg
         ev6DHqaSnkx/svLzHbPoGrNY3Wf9R5Y30Wr+SjJ3qdN9luOlxnD/hdhBtadMiAd6Y8jP
         i8aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GLzgl30D;
       spf=pass (google.com: domain of 32_ykzwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32_ykZwUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865887; x=1739470687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cjGdbdG6qCQmVa+syZApAQ3WrMlxt/Mkpc0h11SIwIY=;
        b=MLo7926gGcCYgJHvKPWNniqZTGhZSSKJ9wKPVqZleBT7k1PmhW0yo2Uj3uUOvO2LZ6
         BF+L+4YP9RGZfENnoHKpAdrM3LfYVSJAK+PdS/2JPVQRgVryGRKHT3dnBGnqkUhUuMfl
         eFz3p7lndgPQSIzVzTkIUw3dgTx/QO3sILcUVbG5XxTHWaZ/fMfGe977vkaAL2FWfeLj
         rusURvUHcXhnn7VR6W0P7lhUjmTpJleuU7fXxyAhabbKJKOhcxFGknKji4/A49vBUj6G
         0/927JKV8hHFLBFsuVaOsWHdHrcpdBgHjRJGfMF0IZlpLQHWVSsI164HvhVCX1ZY8hTM
         GsJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865887; x=1739470687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cjGdbdG6qCQmVa+syZApAQ3WrMlxt/Mkpc0h11SIwIY=;
        b=iZcwFl9MmhMu9zVQjTkmYd9jmt0xHXXnmKCJLvL2zaOpX17nsK0UwfgHV+l9JNNixn
         6XkeKm3uc86zyhDEWfxe3uRvu8N955HOEZ9GNSXfuS5p3TgDf5JX8inUguSgVTjqQAhm
         26bNJmpLhKwy9UWmbHeJgSfsdQsn6o12cG5XrCf9z9B4hxWkLCUZ1KIKCjSVOe9Rfau9
         IyLONm00Ihic/rOx16przobLGkbsL58K86ym3uaXccV3pv2pn9b06PgqxSjaakAZI9HW
         fnt3kovILWN7j5ofMv1ijatQLIWKiFCTYDHeel6RrvcbSxZpfDnF/DU4UoITPKA5PNJ9
         UWDg==
X-Forwarded-Encrypted: i=2; AJvYcCXAORJIqutJU7u1hiDr0tb7h1Ua3UTx41mpdGL8UfyE85IDo/hc7bH8cALopNy09MPN7b1oBQ==@lfdr.de
X-Gm-Message-State: AOJu0YzyTHR46hDGjDAIol7htkGVFB/uQjAqusev9zFjy1LJktKEZ3gW
	EBETJ6763f0Sj757BP/L094hI45sS+QT1ksGEhaC0ziNyZUZjzUW
X-Google-Smtp-Source: AGHT+IFlYQOA2h2kUz+LL3t47hubCHyucIszSFbdtUQ1LjpSpLi8ZeZaQADjnmqdaiC8R6gEdmQqCA==
X-Received: by 2002:a5d:64af:0:b0:385:f6c7:90c6 with SMTP id ffacd0b85a97d-38dc8dcc29bmr16784f8f.20.1738865886528;
        Thu, 06 Feb 2025 10:18:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9bc8:0:b0:385:ee3e:ab95 with SMTP id ffacd0b85a97d-38dc6eff9dbls75368f8f.0.-pod-prod-08-eu;
 Thu, 06 Feb 2025 10:18:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbJklyjM65QF1VqNcACTuJlUXummLuA8HYz38x1XwxHCn0f3paForEkCVqcqvyF+BSDnFbO3vicO0=@googlegroups.com
X-Received: by 2002:a05:6000:154c:b0:385:ec6e:e872 with SMTP id ffacd0b85a97d-38db48fdf9bmr7591912f8f.38.1738865884041;
        Thu, 06 Feb 2025 10:18:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865884; cv=none;
        d=google.com; s=arc-20240605;
        b=U9BQKJQQXEGRtU7VLETMIRzi4Os2ej9Amz+LSXzYYFD2126XpYeA8gNZ285pppsTS/
         f6DcZiBWysv8Vni3UX3S71cdwgedNSyLc4huW+QQftuCW+g+Q1GY9eWcKnCNorHTzjEK
         ShmfIe4jMzq0hmq2xijXKVBHbW0DrH6W6U3SMHeMlSfo0kU1SAz2qRexeXO6kXRYhktJ
         x8NKHtS2aUgtRsJ2v6yMMANtzvfzfOySJkO8Hzszj7XeSvbnavRr4z2NFsI3cPBAJtnc
         hvnfT1kUvrnTZQeajQMvTCGuu3QgtsyBQSYFtdFT8BSGTfMWg3yiqEpyx2KOoK0fQcFU
         WbrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2DbQd0Feo/QZz3Rhlb0Ii9wR2JgNHixpKT0msEk4JbI=;
        fh=LBrO+A64/5SNzJSbWL8wh0vG1+DHrh1nFYhRNjwEMzI=;
        b=FPikL/9M2sAMZBBOiscmqIbn9/G1prhYSU6OhWNswN1RNERxb//+9msLjFnlqkt9i2
         DCC5gS7FwbHY43e7F+NcjA5k8Mow1D4M/a8af/PcuGBOcIWjMiAM/s8Wn1KE3XAwJYFS
         McPq3wCT8OM0tJZnEZUu6Pwe1lbaq/nZr2XRrhDy8kcaR5XMwfLkQ7BGPqs80Rly+La0
         GITMIA4Px2D4z8Af2LfKjTwEIP6JFy7EuH7r5y0Bmep6VmzKWQdQQ3xHLXp+KN7oEQN+
         omL8GXvR6ClwqOkZ2CDfWzgDr59AeNDgANtOMzzsiup/rSnhq/KI5DNq26q24ikPvQ1l
         L6HA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GLzgl30D;
       spf=pass (google.com: domain of 32_ykzwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32_ykZwUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43907f224a1si5584735e9.1.2025.02.06.10.18.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 32_ykzwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab7044083e5so161380266b.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXUabmxBuYa+y3HjrBVlU4KC7W7tc4/jKuz2B9AFU0YozIxILKnNFU7KKTTPrIBgj7DNEpggUNbC2E=@googlegroups.com
X-Received: from edbes17.prod.google.com ([2002:a05:6402:3811:b0:5d8:7c8:cde8])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:7251:b0:aa6:6885:e2f0
 with SMTP id a640c23a62f3a-ab75e35de7emr916219966b.46.1738865883628; Thu, 06
 Feb 2025 10:18:03 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:01 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-8-elver@google.com>
Subject: [PATCH RFC 07/24] cleanup: Basic compatibility with capability analysis
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
 header.i=@google.com header.s=20230601 header.b=GLzgl30D;       spf=pass
 (google.com: domain of 32_ykzwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32_ykZwUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Due to the scoped cleanup helpers used for lock guards wrapping
acquire/release around their own constructors/destructors that store
pointers to the passed locks in a separate struct, we currently cannot
accurately annotate *destructors* which lock was released. While it's
possible to annotate the constructor to say which lock was acquired,
that alone would result in false positives claiming the lock was not
released on function return.

Instead, to avoid false positives, we can claim that the constructor
"asserts" that the taken lock is held. This will ensure we can still
benefit from the analysis where scoped guards are used to protect access
to guarded variables, while avoiding false positives. The only downside
are false negatives where we might accidentally lock the same lock
again:

	raw_spin_lock(&my_lock);
	...
	guard(raw_spinlock)(&my_lock);  // no warning

Arguably, lockdep will immediately catch issues like this.

While Clang's analysis supports scoped guards in C++ [1], there's no way
to apply this to C right now. Better support for Linux's scoped guard
design could be added in future if deemed critical.

[1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html#scoped-capability

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/cleanup.h | 14 ++++++++++----
 1 file changed, 10 insertions(+), 4 deletions(-)

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index ec00e3f7af2b..93a166549add 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -223,7 +223,7 @@ const volatile void * __must_check_fn(const volatile void *val)
  *	@exit is an expression using '_T' -- similar to FREE above.
  *	@init is an expression in @init_args resulting in @type
  *
- * EXTEND_CLASS(name, ext, init, init_args...):
+ * EXTEND_CLASS(name, ext, ctor_attrs, init, init_args...):
  *	extends class @name to @name@ext with the new constructor
  *
  * CLASS(name, var)(args...):
@@ -243,15 +243,18 @@ const volatile void * __must_check_fn(const volatile void *val)
 #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
 typedef _type class_##_name##_t;					\
 static inline void class_##_name##_destructor(_type *p)			\
+	__no_capability_analysis					\
 { _type _T = *p; _exit; }						\
 static inline _type class_##_name##_constructor(_init_args)		\
+	__no_capability_analysis					\
 { _type t = _init; return t; }
 
-#define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
+#define EXTEND_CLASS(_name, ext, ctor_attrs, _init, _init_args...)		\
 typedef class_##_name##_t class_##_name##ext##_t;			\
 static inline void class_##_name##ext##_destructor(class_##_name##_t *p)\
 { class_##_name##_destructor(p); }					\
 static inline class_##_name##_t class_##_name##ext##_constructor(_init_args) \
+	__no_capability_analysis ctor_attrs					\
 { class_##_name##_t t = _init; return t; }
 
 #define CLASS(_name, var)						\
@@ -299,7 +302,7 @@ static __maybe_unused const bool class_##_name##_is_conditional = _is_cond
 
 #define DEFINE_GUARD_COND(_name, _ext, _condlock) \
 	__DEFINE_CLASS_IS_CONDITIONAL(_name##_ext, true); \
-	EXTEND_CLASS(_name, _ext, \
+	EXTEND_CLASS(_name, _ext,, \
 		     ({ void *_t = _T; if (_T && !(_condlock)) _t = NULL; _t; }), \
 		     class_##_name##_t _T) \
 	static inline void * class_##_name##_ext##_lock_ptr(class_##_name##_t *_T) \
@@ -371,6 +374,7 @@ typedef struct {							\
 } class_##_name##_t;							\
 									\
 static inline void class_##_name##_destructor(class_##_name##_t *_T)	\
+	__no_capability_analysis					\
 {									\
 	if (_T->lock) { _unlock; }					\
 }									\
@@ -383,6 +387,7 @@ static inline void *class_##_name##_lock_ptr(class_##_name##_t *_T)	\
 
 #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
 static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
+	__no_capability_analysis __asserts_cap(l)			\
 {									\
 	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
 	_lock;								\
@@ -391,6 +396,7 @@ static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
 
 #define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
 static inline class_##_name##_t class_##_name##_constructor(void)	\
+	__no_capability_analysis					\
 {									\
 	class_##_name##_t _t = { .lock = (void*)1 },			\
 			 *_T __maybe_unused = &_t;			\
@@ -410,7 +416,7 @@ __DEFINE_LOCK_GUARD_0(_name, _lock)
 
 #define DEFINE_LOCK_GUARD_1_COND(_name, _ext, _condlock)		\
 	__DEFINE_CLASS_IS_CONDITIONAL(_name##_ext, true);		\
-	EXTEND_CLASS(_name, _ext,					\
+	EXTEND_CLASS(_name, _ext, __asserts_cap(l),			\
 		     ({ class_##_name##_t _t = { .lock = l }, *_T = &_t;\
 		        if (_T->lock && !(_condlock)) _T->lock = NULL;	\
 			_t; }),						\
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-8-elver%40google.com.
