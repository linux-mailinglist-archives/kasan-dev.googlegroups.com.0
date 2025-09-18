Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVDWDDAMGQER6HRGRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id AAEBCB84F75
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:47 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45dcf5f1239sf4586865e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204347; cv=pass;
        d=google.com; s=arc-20240605;
        b=I2gvgQiTfXZGVZ0VxiZ6rJORQYM2c+rcB1dhA9Zz5SfDFawStndS/MhcdnpZsaDhN2
         kEnRx9py4bTY1QKLFS10bhgwwp4343K/0u4kzli3usjnDyjee3UDRoVS6ZuNsx8RlLU5
         NoUMZa35n9ueklQoCjboTYrKroTf+pPrGXfqfKwsEgKK1M+Kk4ZZ+WHnPd2tODygB2Ye
         hqQadwKbkgmecJ8pzvT8kwp7PnvT1yFF/77myrv/2Vu4MRc5d9dHORa4k0k7W+1Y/7hj
         E7ZBlF5NgxZQEMivPIKghpAY2BvSHkFFtmQ6V5Gci1AWD/BjlZeN//pBpYXBZO0E9tjL
         RKlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SXxl60EO6r9/MZ/bq1LG4OrIAnPZ9Y6ePdI617WzBco=;
        fh=fA5TwHrxBaEvoVel0Sr23mrOEh15kGDH3AEtTwZlgIA=;
        b=gvQEs/jXKDPYeKQdBwC1FSSmQjWeGgPFjJ57nKfl228pqG3szQ7sDhPSdxgMzDvw/V
         QibPD6lR/OwNA7iPrAVzg5o2k++ALR9hN1ywJ0ErTAmCapaPvut/URY+DKCYoG/qwggF
         Uii4Dn6vNXZmQGjyIQGsKtpDVhYMefRCIHekp5/Istx3IvY6z+L9TjSrCe43Us0e+b4I
         DFB+H7ysHRi3v9T/Kif9F1Sv+OaauhC0C4I2JbdTjw8P1NNvCoX3B2uvxK7VHgfSc/qX
         QHqsSveGkfhVgCpCN6faX6uRx6qR/Sf80887QIZiXvVG1iQYsW+HCcViwL9EzbLelxbp
         WVxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M9DARbZs;
       spf=pass (google.com: domain of 3thhmaaukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3thHMaAUKCVc3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204347; x=1758809147; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SXxl60EO6r9/MZ/bq1LG4OrIAnPZ9Y6ePdI617WzBco=;
        b=IGQ9RzvJEMgHF+YQFZIe5wl8D+2kypviZuw2p6J7twABrcfjW7egWfVil1t8wmcP26
         vYTr3h5W06X2G+YPCQ6iDYffWcyDxOBqJBZxfrK5+fphhiM2DyfV//w2L9AIxl83X6RZ
         hr1QgqbonS03cf33Dn5hRpgHIeRVEEAcFscSics7eUq0CYdz6HEcOu5nyzSagSDJdUsm
         IebqCouBw5PjvRLM0KbPrXatYhMCDUeFuJutkbDNdcJnj/mJ9dTn1PHAk/yP64uHqWGq
         Z04V6b3cPlEG/FJaw+R1Gez2M97c3G6cN+/gjtZi9XIGkLjD2EHeFqNR7WN/ziUT/iDr
         E/+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204347; x=1758809147;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SXxl60EO6r9/MZ/bq1LG4OrIAnPZ9Y6ePdI617WzBco=;
        b=eeJsE3TUH/3T5DoVE+g1tob4Ubj6ld3zAKTSbmahvQ+rjdTieIW/1JWIiHEwZIYfxa
         YE9rOd0Dic5SEq5yKiLOE7Z0mNdxM3h03rO461gcV2IXWPmZdlKBl+PZptu980+5qCRJ
         7wdNuW1pDw4Dy2B1UtFzJoRZZ+SuBCrZq97+adMC4U7eTtp7wA4e42zhyhy0maIQTw0M
         Zh21oxY2q0+RzH2aE4q8palYQTxZmNp728R+l4rm7gd9vOJ8HVz8t+6HzMy+XWCrxzvf
         mG6u2VoMK3EqunCsahYAJtKA3c++yHYylOQj+RpCOiZNw+C/1IsIuqBRXxUUBwlUcPk4
         LdvA==
X-Forwarded-Encrypted: i=2; AJvYcCXfOnjxx36Mn5DKOKZe8vWdoXk5v6WeOYMCc7Z4dOyDT+kGffvrU4ilq9cE0rqAmPyOOhVvvA==@lfdr.de
X-Gm-Message-State: AOJu0YymIu+SNf2ua0puQDfD+zx37FsmQVPQy3Ji1Tb3L5h/p7fOx0eo
	1mqfbe4tsZDsJpEhWg+xcD3rel7jr2YPMoIxyfg3rsR3UxSaiQCMYoum
X-Google-Smtp-Source: AGHT+IFeZXPc6jDlaQhjqKvejgafLif7lqGgWdyijRZIFH8NQyXDanaKU3ar+RQa+v3m+sH12pIy5g==
X-Received: by 2002:a05:600c:4e8c:b0:45b:47e1:ef71 with SMTP id 5b1f17b1804b1-462072d7939mr56048145e9.36.1758204346623;
        Thu, 18 Sep 2025 07:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7HCyJocxlvWKMJQ0IP+Vl/vjWo32FWF2n3wEDQakRmIQ==
Received: by 2002:a05:600c:45ce:b0:456:241d:50c3 with SMTP id
 5b1f17b1804b1-465455c3415ls6070225e9.1.-pod-prod-08-eu; Thu, 18 Sep 2025
 07:05:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxj9KM18PRZePk/v3YzQ77nqXCUNpbj2kmRDYuqzRquK8SXQRCREWZ9qwCXq4xxAUhLHu746mP+4M=@googlegroups.com
X-Received: by 2002:a05:600c:1993:b0:45f:2cd5:5086 with SMTP id 5b1f17b1804b1-46201f8b30bmr61782495e9.3.1758204343648;
        Thu, 18 Sep 2025 07:05:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204343; cv=none;
        d=google.com; s=arc-20240605;
        b=LRfXdosgZutzbe+U5BatsXXolHRFEihqRkm2zyThxCmpdJ1rCUT7BDx+Y3vrAwtimm
         JqB/k8kfJLok5MEbeG5iRczGvu3FgqweMhtDIPsTqlsvyCad6dvEPdvwezU0wzpe6+t0
         N4PPEs35o0hCM+wux/W9RyxiFA1UBuPDSIcAAe4CHJsR/7RR2vxjilOMs5QUsE9OTfPg
         WY0uCn76E7hGxQ4oFyM6pcqaxZFI8THe9iX0eSDwJJSPQHlPQ70lm8G0IgrpcILn1zTg
         GfRZWi+K+CrbVZ7H1umAOksExRYc7Di6QfmX/HtAF9jgKndGF8myY9KO8Bw34RR0zV/W
         AQBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UhQ+U9se/SSPfFCtaRf+8xWbg1y5S3svPblZWk1KYzo=;
        fh=0E1aqKexsY3Kdog57J5MN0toVPJPmVdBPqUcO9Ps4nI=;
        b=KZlDouG77ZPSw4YwpyBXJbWyrC2KwOzFUy2yEm4TL5/2HlPTsxh+BlhWa5c1KMjJe9
         y6NDwsYc7fuP4aWmQmXMBatH0pVehKUl4a3Un7MIxkgiZ0aTmeNN2eqNJqdT5b1GaA7S
         TTGTVC6d4xVEhLs5mslndYA+jjjJoNeK96ynf7/5K21mqhvovNMMoA55MgeB59diGCDd
         D9jvtjyblB15n0+kTn3LGqaCmSbMMnK62RkPaL85LgqBlCG2IE+6551cDO437i4N1QH4
         OTFwcOj707sa2r6fwLkAKEKpfTr7AaRXqHIl6Pv1/+3v2lVnFgSh0Bm03SwLElSMa3jk
         P8ug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M9DARbZs;
       spf=pass (google.com: domain of 3thhmaaukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3thHMaAUKCVc3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-466758dfd8fsi232165e9.1.2025.09.18.07.05.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3thhmaaukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-b07c9056963so92614066b.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXuE60TXZa1T08NlLrO/4qkQa8nykUE6h6JOUZmlGkz4VegCCX21jfPGRvdwcKlDCdYfVR9HiC9+eU=@googlegroups.com
X-Received: from ejcth16.prod.google.com ([2002:a17:907:8e10:b0:b07:e1ab:ac42])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:86a0:b0:b07:dbf9:a002
 with SMTP id a640c23a62f3a-b1bba0036fcmr627925566b.47.1758204342817; Thu, 18
 Sep 2025 07:05:42 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:17 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-7-elver@google.com>
Subject: [PATCH v3 06/35] cleanup: Basic compatibility with capability analysis
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
 header.i=@google.com header.s=20230601 header.b=M9DARbZs;       spf=pass
 (google.com: domain of 3thhmaaukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3thHMaAUKCVc3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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
"assumes" that the taken lock is held via __assumes_cap().

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

[1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html#scoped-capability

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Add *_ATTRS helpers instead of implicit __assumes_cap (suggested by Peter)
* __assert -> __assume rename
---
 include/linux/cleanup.h | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index 2573585b7f06..54fc70d8da27 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -274,16 +274,21 @@ const volatile void * __must_check_fn(const volatile void *val)
 
 #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
 typedef _type class_##_name##_t;					\
+typedef _type lock_##_name##_t;						\
 static inline void class_##_name##_destructor(_type *p)			\
+	__no_capability_analysis					\
 { _type _T = *p; _exit; }						\
 static inline _type class_##_name##_constructor(_init_args)		\
+	__no_capability_analysis					\
 { _type t = _init; return t; }
 
 #define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
+typedef lock_##_name##_t lock_##_name##ext##_t;				\
 typedef class_##_name##_t class_##_name##ext##_t;			\
 static inline void class_##_name##ext##_destructor(class_##_name##_t *p)\
 { class_##_name##_destructor(p); }					\
 static inline class_##_name##_t class_##_name##ext##_constructor(_init_args) \
+	__no_capability_analysis \
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
+	__no_capability_analysis					\
 {									\
 	if (!__GUARD_IS_ERR(_T->lock)) { _unlock; }			\
 }									\
@@ -475,6 +482,7 @@ __DEFINE_GUARD_LOCK_PTR(_name, &_T->lock)
 
 #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
 static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
+	__no_capability_analysis 					\
 {									\
 	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
 	_lock;								\
@@ -483,6 +491,7 @@ static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
 
 #define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
 static inline class_##_name##_t class_##_name##_constructor(void)	\
+	__no_capability_analysis					\
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-7-elver%40google.com.
