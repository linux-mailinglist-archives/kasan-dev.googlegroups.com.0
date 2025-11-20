Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK677TEAMGQEWNK3BLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 896E4C74C0B
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:11:40 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-640ed3ad89bsf2195752a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:11:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651500; cv=pass;
        d=google.com; s=arc-20240605;
        b=Upja8YZvj/AVWQwbI452G5+lu3rdXGblUA6DMZYIwPXsS5cfsD7m5LLdH1T8z4T/sE
         p+W6ok33S+JVmiD6KuIkR1DdiC+bV8HhxZdpHJ6V9rXmOzBqHnckg/pB18qOaXpYHwCP
         2M3cQISN9x7RqUmt25F6yZGlivE3N8+j2epxSsq2gQD7Mhs9BMr5yZp153eFmjbQHCUa
         PirPwXwt898ZqqRwB1/R1kE8vCp53X3AAe8iEEO2gyzzE21KfDKbRr4A3GMrtmoecRQJ
         Cf8VT4hPrU77hHAGsY2/wtLxng7g9LyhgzJlQqQVp2RZVrUvRGW4tAKsqzUkSEp6gSXX
         vULw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Jq8hAh0KheqJuh6Hyv/E27/efHHqeIy2GzCPmsnkQd0=;
        fh=x3uyJp27TaIN1jsryJZcMhDXesFxYOLA+1XLNt4li0o=;
        b=Pa3k+2ZdomAXfMgfbNtJR71LASbFZLy5+qOhcrtwEgs2/sc7uX5Iq9mClWIs/YBxxb
         Q/aJwCkHpTYK1wCC8WHTeG1MF/GnbE7EgazPn+F5qBQdAPKd/lQkgM2maaxC2UtdaO9z
         6J6XdGr9kJqiAXuB8yppSysS20sM8c2zc1SP6BrBb1neJPz4LQaNR1lPYhj++1hhZhKV
         zvC1GMy8eAUElqlx64mJenDGXXkfFTV81aGRG6NwRkQoXs5k4BLt8lkPODZE1hn7FOQ4
         qQFsrh+r595qoZRy5n4MQ177TNxWwBNOc6aLE9ouHH6qYUf/j/4QHjk7D7QGwVmDSpos
         qJoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="I1/EIyCA";
       spf=pass (google.com: domain of 3py8faqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3py8faQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651500; x=1764256300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Jq8hAh0KheqJuh6Hyv/E27/efHHqeIy2GzCPmsnkQd0=;
        b=mViOJXK1oiXCkwZ8SjpnHdRddyE2xNnp0qVNBv+NMPRfilOfl1Nu7BQdW9DkqbhezY
         2esrMsfiOPAGaD6vcPgmmvDc0W/3psE1XM1B3G+HRa3+X7aHHpztJxIwD3LKF3CoiMLF
         dlCINKAbzg/RO/ZfzXExNXrd4nh/unroLozu2BcjWiJfEhBW/q60F3uGIhy2J681zNop
         Na0ucOSpUfNmUVabmsM7i4r+Xu2SJacXeh9wC9ozQ7MHeVgPT5l6nXIsI56qWQ9tQpSl
         M9BfJxt/obajBkEqe8CtVIr69cMG/w8OHe2kdN2JVYm6ejQ+OVhruINfH8MU2qUS3Equ
         OEWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651500; x=1764256300;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jq8hAh0KheqJuh6Hyv/E27/efHHqeIy2GzCPmsnkQd0=;
        b=iV6cDuLFA1J4JvkcfT6V1tDkZsRUSE7uBg4KCImKixfHSGUY59Pn0J7Chu3UqoWfKR
         tq7Ww8VJoJNIw53a36ov7RIaW0NvNrox5C3TWl/kxOPKI3x37SOmsfV0h0VeFDmVHHhm
         qgqMU4hnN9u4xOsayWHE4ss13ee8Hw8z55OZY3aTUxv7Ijh4JXIQXFUmcBzzzNw8BUSC
         T8L0x4eHRH0gk2V/cQeVh+JzNh0XK4ZGoxATkFRF7yCbBMQh5gGN8J/045LX3K8Q0OIq
         S/Xap/46ZdlArTZ3fbovKh5BbuA1RM4oe5AX9koLxAz9CojbEzyEoHb2RPJwRg4bDQ6y
         Tdrw==
X-Forwarded-Encrypted: i=2; AJvYcCUMKCJX7Fg32xZgncOWz/I6kBSn1jW3KAZ+p+WRbTlUBX0gWfwL2IElhTcrAXOaBJtx9xTbJQ==@lfdr.de
X-Gm-Message-State: AOJu0YwjON5UNinkywp3r+NxeE702rF/aSHSWuJpYkHuh8KctNbY00TE
	fBTBdF6o1ziAoWazWQ2pIWG43EAkVzOBsGSUUk0vQ62VJ6SVI2kqhcEi
X-Google-Smtp-Source: AGHT+IEUddqDML+0e9p1VHytvR8Ayc3/roUb4j4xXrn6JsjKYdHKpA1b9ijJ8AOeZcfTIgQSFZjwxA==
X-Received: by 2002:a05:6402:1d52:b0:643:8183:7912 with SMTP id 4fb4d7f45d1cf-645363e4201mr2955707a12.9.1763651499691;
        Thu, 20 Nov 2025 07:11:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bC1CRQ2+b4jF+v6pKk1ZGnFsHubO9DWzIbNJfi8V5owg=="
Received: by 2002:a05:6402:2082:10b0:641:6555:a42d with SMTP id
 4fb4d7f45d1cf-645364617e2ls789035a12.1.-pod-prod-06-eu; Thu, 20 Nov 2025
 07:11:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVWjxWz1gO724S/aaTgEcKPC6nZoDZPSDsTKdbs3ki35Vpm+0wYUXUAImSBvv9dpDCOKn+w7RRvUjc=@googlegroups.com
X-Received: by 2002:a05:6402:146a:b0:641:1f6c:bccf with SMTP id 4fb4d7f45d1cf-6453643d17bmr3485779a12.16.1763651496779;
        Thu, 20 Nov 2025 07:11:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651496; cv=none;
        d=google.com; s=arc-20240605;
        b=ZOSp3/EJFtgY+QyRZZ/E22B/dGN0OUVrvLl3HwTQ5yoF7BHzg/Fu4++zJMC4AXLT3o
         OaSkhBgyX1iCXgrYRu5aNnH8QuE720gSaN2/kjWe1Rf2lNNTVkZJfNVaRCF/dnS4+One
         IwlCq+tuMRjLfcRnF+E7WeplsN3uCwXIkbJ4WkucrTmMv7aqtk1eRre9UNpb+YeDzlCe
         LBlf3hvM4j6iFegjTCNpdNieqzm449h4A1Rc/BadtgRnHekX3wCTMBPeS1SAprfHh5PS
         xrUPM2qmBaYIGLnJ9z8HpMzC0Yicl6Qt2ECjJuj5g0CvoyKdH5UrPJDIwwK6mH7T/7MO
         3FZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aQzgcISd2vbQZXtJWGq+JJNhDcvZ3ay3Xv8naW52gEo=;
        fh=YXj4joSGJHAAXMyqtgxXyYHKypNOJSzFkF3rDMnlCKM=;
        b=Eh+V526tsPiZ7HwPRVsT/c0Cv5wqV4VNhaIQ4G8ANaYKPE5Ta1ykSSE9c1ccKYMxRb
         jR3wL78sp9bWPVxb3Earm7qYobx67qIXdtywBuL5Rg1m8/+CS/G5UVhB6sWBKMLJNBMY
         cQziiiUgQMNcNuNHAJoMiY4LSFvjYR8Woy+jNRI399vZUThETA0e/M+vdhC+K6sowu8o
         bm/XMTroGoZFeT+ZVIR24e+39RVhqsKohao27yKRMwBpf/zngIwP2ssY2qmmz9Yu4qdQ
         2dkDVVum462VN2DTj+Mp/+MihwJi2vHRQBNoNbo6oHlAFfyCrX/hQ8e4yJGKc8XbyQ/u
         Lphw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="I1/EIyCA";
       spf=pass (google.com: domain of 3py8faqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3py8faQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64536478c11si41582a12.7.2025.11.20.07.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:11:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3py8faqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-b736eca894fso79244966b.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:11:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVhjV0FLIVAKRm/KBFElCPz4rQucfU89OBmXsvNHTqBEo0iBghNL+FzdwZ3b9De7+teSuKn4DOIjxw=@googlegroups.com
X-Received: from ejbrp28.prod.google.com ([2002:a17:906:d97c:b0:b72:41e4:7558])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:9812:b0:b6d:5b4d:7277
 with SMTP id a640c23a62f3a-b76550b65a3mr361991766b.0.1763651495821; Thu, 20
 Nov 2025 07:11:35 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:31 +0100
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-7-elver@google.com>
Subject: [PATCH v4 06/35] cleanup: Basic compatibility with context analysis
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
 header.i=@google.com header.s=20230601 header.b="I1/EIyCA";       spf=pass
 (google.com: domain of 3py8faqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3py8faQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Introduce basic compatibility with cleanup.h infrastructure: introduce
DECLARE_LOCK_GUARD_*_ATTRS() helpers to add attributes to constructors
and destructors respectively.

Note: Due to the scoped cleanup helpers used for lock guards wrapping
acquire and release around their own constructors/destructors that store
pointers to the passed locks in a separate struct, we currently cannot
accurately annotate *destructors* which lock was released. While it's
possible to annotate the constructor to say which lock was acquired,
that alone would result in false positives claiming the lock was not
released on function return.

Instead, to avoid false positives, we can claim that the constructor
"assumes" that the taken lock is held via __assumes_ctx_guard().

This will ensure we can still benefit from the analysis where scoped
guards are used to protect access to guarded variables, while avoiding
false positives. The only downside are false negatives where we might
accidentally lock the same lock again:

	raw_spin_lock(&my_lock);
	...
	guard(raw_spinlock)(&my_lock);  // no warning

Arguably, lockdep will immediately catch issues like this.

While Clang's analysis supports scoped guards in C++ [1], there's no way
to apply this to C right now. Better support for Linux's scoped guard
design could be added in future if deemed critical.

[1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html#scoped-context

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* Add *_ATTRS helpers instead of implicit __assumes_cap (suggested by Peter)
* __assert -> __assume rename
---
 include/linux/cleanup.h | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index 2573585b7f06..4f5e9ea02f54 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -274,16 +274,21 @@ const volatile void * __must_check_fn(const volatile void *val)
 
 #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
 typedef _type class_##_name##_t;					\
+typedef _type lock_##_name##_t;						\
 static inline void class_##_name##_destructor(_type *p)			\
+	__no_context_analysis						\
 { _type _T = *p; _exit; }						\
 static inline _type class_##_name##_constructor(_init_args)		\
+	__no_context_analysis						\
 { _type t = _init; return t; }
 
 #define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
+typedef lock_##_name##_t lock_##_name##ext##_t;			\
 typedef class_##_name##_t class_##_name##ext##_t;			\
 static inline void class_##_name##ext##_destructor(class_##_name##_t *p)\
 { class_##_name##_destructor(p); }					\
 static inline class_##_name##_t class_##_name##ext##_constructor(_init_args) \
+	__no_context_analysis \
 { class_##_name##_t t = _init; return t; }
 
 #define CLASS(_name, var)						\
@@ -461,12 +466,14 @@ _label:									\
  */
 
 #define __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, ...)		\
+typedef _type lock_##_name##_t;						\
 typedef struct {							\
 	_type *lock;							\
 	__VA_ARGS__;							\
 } class_##_name##_t;							\
 									\
 static inline void class_##_name##_destructor(class_##_name##_t *_T)	\
+	__no_context_analysis						\
 {									\
 	if (!__GUARD_IS_ERR(_T->lock)) { _unlock; }			\
 }									\
@@ -475,6 +482,7 @@ __DEFINE_GUARD_LOCK_PTR(_name, &_T->lock)
 
 #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
 static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
+	__no_context_analysis 						\
 {									\
 	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
 	_lock;								\
@@ -483,6 +491,7 @@ static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
 
 #define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
 static inline class_##_name##_t class_##_name##_constructor(void)	\
+	__no_context_analysis						\
 {									\
 	class_##_name##_t _t = { .lock = (void*)1 },			\
 			 *_T __maybe_unused = &_t;			\
@@ -490,6 +499,14 @@ static inline class_##_name##_t class_##_name##_constructor(void)	\
 	return _t;							\
 }
 
+#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)		\
+static inline class_##_name##_t class_##_name##_constructor(void) _lock;\
+static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
+
+#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
+static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T) _lock;\
+static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
+
 #define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
 __DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
 __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)		\
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-7-elver%40google.com.
