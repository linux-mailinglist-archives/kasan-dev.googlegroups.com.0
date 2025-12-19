Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLHGSXFAMGQEHOECQ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 85608CD0947
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:45:49 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5943838a6d1sf1318543e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:45:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159149; cv=pass;
        d=google.com; s=arc-20240605;
        b=FTyBY0YqFJ3uMJ0dg51VREN4HlP/ME4HI2ejCxpQrf6pNUZai52FCDWip05vjTFopq
         g09t1OAZY7R/FW3MT49hD5PkjCFy6/UNza+HLYhg1n+okbJpdDCr1ZDoGb5EK7mRFABB
         lsm62eZbqG0hr14PRkWt89V4vMT9yp0M77Wx6OF0dzWBZzuJ50GViqNujvET/EdKw9Tz
         HnZJ1lpZ0T+fa0NVVHGbijzIo2SjLAX/JyNQKCD0Glzr7/5UxqiQBFXdBg6yGH04dwG0
         LUTl09+PU26pQELGS+xD7ws2cQC4x9XJzMr1s35LNPPDogn91b5rLsqnoOeJieqJIRd0
         b/Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1N0IK12b/YGWub9o5qHEgHz0OhzCoLyIo5d2aEt3qZI=;
        fh=Eanbbi9sFqJXkxANNgtq1h4UENfpnJNWPcSuIifp7Po=;
        b=W/WoSNhy+jCSTCe76oacZ30KN2TD8zC60r183szaIu3C+ZJxYQ0dMf1EeVB+vCTLj/
         8KCzaywkIS1nmSF4IxYckMMUzwVNSHc+pQh0IvlYyvFtIw2XCK3ILjbxfsKXhzEqwSk1
         QvjXXF7hg34qz6LRnk/+TuZCUqIXp6exAjN5Ma/gZOOzW3o+AjL/N8PSMBDN02wj8Lhb
         fVI/ws5RwbQpr6UJFG37muYamyolvh6VvI9LiDhWMsRnZjGQovYO260OslezJrqYinmu
         lXSA0oI9CS9mazRItiEi2gDzvuuionJAnNKRF+RH2ZzM9cHz+u3lwqgZiG7jtDbLEr06
         bRXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="jUXHR/Zd";
       spf=pass (google.com: domain of 3khnfaqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KHNFaQUKCXUXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159149; x=1766763949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1N0IK12b/YGWub9o5qHEgHz0OhzCoLyIo5d2aEt3qZI=;
        b=jTP/Ot8qopvS2d/k7rbIjWv1X5WWO/VrmYAFtBqGlgkRb9relsvpBL4YITcvOCSt9K
         UFNgTySrq3gk02N0mnsoXfr0x2cE07MVxiaP+BC9bAK0appAXPmGNDL7qxJD/Y0xUuBR
         Oov6vyLTXR2qEfh3sOSWOM33aW8VOP17UcxXrDMm0c8COnfDMG+ANurX9QTtRaryENmb
         VvZAYgyJGWfw5Bo5h/K577DpFUM6NV3LkKQikdNkOTghm2CQ0AYpyfwyoeouWGwS1V+i
         /amYgLdAsAoucuqu1Bp/RbtlOEGVIYuG/kEN10x7nu+0uZBN/KFNwholk4O7ppzb/U1r
         Ex/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159149; x=1766763949;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1N0IK12b/YGWub9o5qHEgHz0OhzCoLyIo5d2aEt3qZI=;
        b=B3MOTkaBpyKjaAJ6kNXa1ixNGWzEQvITvrhIYebwm+UsqGINxF09HVGt9HPi4QX7op
         YGuZdqaj02POhTAhe4jotBcqElRwo9h7gIMTTeo6hQMCaeeKl0g/N6kxU1ulL+vfbWvO
         7UuP3784wNxiZivVhDmcdLWlyWhtVb9aM4pNREK2yeGwsOYEbu3BXOYFSu9BQV+5ZjI/
         wftci1/AhymETzXJa34dntD8xejbLQELLGPAI0s6F8eCF2mGwvXlhrgPL3tnrZTjRXEU
         buwBHIe6q8BR2W2FuoQCPSZg40rqExxSZnaIKtO1pM4/BrjxV08ECtohPwuYNKNRyyqV
         Ekww==
X-Forwarded-Encrypted: i=2; AJvYcCV8jUG2ylbRtqnrtRABv1K0UQTBuGGD/5XC/+ZhDV1bhzP2RvP16kn8vUCtkKg7znwoE/WdjQ==@lfdr.de
X-Gm-Message-State: AOJu0YzqKdJZpxlx1vSUDNnUNSiMuJzyq4Oc2tkc0prjFnmW4e0c3NVT
	BTfJgec0FpNRfzNbxw2UsZNaEKaeBtlRjP9Om7DOiuGXcTFax8EOtEvm
X-Google-Smtp-Source: AGHT+IEj4/hyNVfrjTAwW4gGmekYyJKvDIos3oPJU/NVeAuaAXCwsB2LuwJzei3DHo5Hm2SMtyot0Q==
X-Received: by 2002:a05:6512:688:b0:598:ee6c:ed6 with SMTP id 2adb3069b0e04-59a17d3dc60mr1272274e87.30.1766159148681;
        Fri, 19 Dec 2025 07:45:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZiMu8ggddQJiEPjGtH8tboU9z2SFRfZXbWFsORxHKAtg=="
Received: by 2002:a05:6512:1188:b0:598:f90c:1c6a with SMTP id
 2adb3069b0e04-598fa3fff39ls2900477e87.2.-pod-prod-05-eu; Fri, 19 Dec 2025
 07:45:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUOibKo6sfOb4aSJbHy9+0CPdIQCyqeOg0WaFrkZZdD7Xr5uBjWGxNZO8DN2AP5cNLiB1nKPXwtBag=@googlegroups.com
X-Received: by 2002:a05:6512:ea3:b0:595:81e5:7570 with SMTP id 2adb3069b0e04-59a17d1c0e4mr1213837e87.23.1766159145615;
        Fri, 19 Dec 2025 07:45:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159145; cv=none;
        d=google.com; s=arc-20240605;
        b=kZs1ig7QZQkkb+MKu+dvIEo/0X1st0DHfwJgzWYoaPtki3udlGQTGYWqkeiL1eiwvS
         fqRazb299f2OQiqtWuX3tF/lM9sVjEn6FX31ktL8m6o5LCZFv1qdWSljqujcusFseV1B
         1wPwzQoRkmI97Triq+4n1Gbdj56s+0P9/k9UR6MW4q0KvgOBWOT8LjueX1IBDZFzL+sV
         j0qqzmvXiUc3qZkhEHH4uIUmbc0PaaSJnl79qkjKu5479kpnMBXzAToRSmmouq8Vdef0
         1KDsNVTsq4abeMHcYkJ7hA4lM/4vMD0tB9nmfFZ9u7u6JXcej72232lEsX/6DEhpbS7k
         D30g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kb0gLsOvOvTOd9/IwL391pJi9FHpm7GL0bThZeAVvoU=;
        fh=O4j5Sxy1iAds8b4Jo+V9Rkujg6A75roKrqFFuhoaWCU=;
        b=gTPhDZOGLiXFExn2mHd6j2br7rObuCGfH8S2LAYjD13OVMpTe2rhuZjU5PZZzi5ey2
         Luv44Gmr904DNUF8ivgONsiTkjBuDagIBaeH7SwLH2iyVPB1X/3nmGzHf2KBSZH+gMet
         yhnHGcs2JfbOjLwlmm1r63MKcO0ApncpxUKcglF+EKF9dVNjbxNk+jPQv+ZoBZHVbtLE
         mrPXHjSkDVgxXBK3Vf1E6aTCjAukxZCCDO23B5lvEj8T/Kv3rpLmRSTjwtk4RlIzRRTD
         YrV1FW3tSnjdAGxa5Pb07LEpWobtP5M4qvLS9lSZ2WG4rSkUDcDVqDx3advsg9yxrnCj
         d8Kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="jUXHR/Zd";
       spf=pass (google.com: domain of 3khnfaqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KHNFaQUKCXUXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1861b956si58333e87.7.2025.12.19.07.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:45:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3khnfaqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477771366cbso12248725e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:45:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXWCwgBZsnUpDL+yrAFZp7SKTrDccyWrw7fFLIY/QR74BqgTdZqwjLP1mnZQ9IF3/1s6GlhGx4sEbE=@googlegroups.com
X-Received: from wmv18.prod.google.com ([2002:a05:600c:26d2:b0:475:dadb:c8f2])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:820d:b0:477:7c7d:d9b7
 with SMTP id 5b1f17b1804b1-47d1958e475mr30951665e9.33.1766159144675; Fri, 19
 Dec 2025 07:45:44 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:55 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-7-elver@google.com>
Subject: [PATCH v5 06/36] cleanup: Basic compatibility with context analysis
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
 header.i=@google.com header.s=20230601 header.b="jUXHR/Zd";       spf=pass
 (google.com: domain of 3khnfaqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KHNFaQUKCXUXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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

Introduce basic compatibility with cleanup.h infrastructure.

We need to allow the compiler to see the acquisition and release of the
context lock at the start and end of a scope. However, the current
"cleanup" helpers wrap the lock in a struct passed through separate
helper functions, which hides the lock alias from the compiler (no
inter-procedural analysis).

While Clang supports scoped guards in C++, it's not possible to apply in
C code: https://clang.llvm.org/docs/ThreadSafetyAnalysis.html#scoped-context

However, together with recent improvements to Clang's alias analysis
abilities, idioms such as this work correctly now:

        void spin_unlock_cleanup(spinlock_t **l) __releases(*l) { .. }
        ...
        {
            spinlock_t *lock_scope __cleanup(spin_unlock_cleanup) = &lock;
            spin_lock(&lock);  // lock through &lock
            ... critical section ...
        }  // unlock through lock_scope -[alias]-> &lock (no warnings)

To generalize this pattern and make it work with existing lock guards,
introduce DECLARE_LOCK_GUARD_1_ATTRS() and WITH_LOCK_GUARD_1_ATTRS().

These allow creating an explicit alias to the context lock instance that
is "cleaned" up with a separate cleanup helper. This helper is a dummy
function that does nothing at runtime, but has the release attributes to
tell the compiler what happens at the end of the scope.

Example usage:

  DECLARE_LOCK_GUARD_1_ATTRS(mutex, __acquires(_T), __releases(*(struct mutex **)_T))
  #define class_mutex_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex, _T)

Note: To support the for-loop based scoped helpers, the auxiliary
variable must be a pointer to the "class" type because it is defined in
the same statement as the guard variable. However, we initialize it with
the lock pointer (despite the type mismatch, the compiler's alias
analysis still works as expected). The "_unlock" attribute receives a
pointer to the auxiliary variable (a double pointer to the class type),
and must be cast and dereferenced appropriately.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rework infrastructure to properly release at scope end with reworked
  WITH_LOCK_GUARD_1_ATTRS() and WITH_LOCK_GUARD_1_ATTRS().

v4:
* Rename capability -> context analysis.

v3:
* Add *_ATTRS helpers instead of implicit __assumes_cap (suggested by Peter)
* __assert -> __assume rename
---
 include/linux/cleanup.h | 50 +++++++++++++++++++++++++++++++++++++++++
 1 file changed, 50 insertions(+)

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index 8d41b917c77d..ee6df68c2177 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -278,16 +278,21 @@ const volatile void * __must_check_fn(const volatile void *val)
 
 #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
 typedef _type class_##_name##_t;					\
+typedef _type lock_##_name##_t;						\
 static __always_inline void class_##_name##_destructor(_type *p)	\
+	__no_context_analysis						\
 { _type _T = *p; _exit; }						\
 static __always_inline _type class_##_name##_constructor(_init_args)	\
+	__no_context_analysis						\
 { _type t = _init; return t; }
 
 #define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
+typedef lock_##_name##_t lock_##_name##ext##_t;			\
 typedef class_##_name##_t class_##_name##ext##_t;			\
 static __always_inline void class_##_name##ext##_destructor(class_##_name##_t *p) \
 { class_##_name##_destructor(p); }					\
 static __always_inline class_##_name##_t class_##_name##ext##_constructor(_init_args) \
+	__no_context_analysis \
 { class_##_name##_t t = _init; return t; }
 
 #define CLASS(_name, var)						\
@@ -474,12 +479,14 @@ _label:									\
  */
 
 #define __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, ...)		\
+typedef _type lock_##_name##_t;						\
 typedef struct {							\
 	_type *lock;							\
 	__VA_ARGS__;							\
 } class_##_name##_t;							\
 									\
 static __always_inline void class_##_name##_destructor(class_##_name##_t *_T) \
+	__no_context_analysis						\
 {									\
 	if (!__GUARD_IS_ERR(_T->lock)) { _unlock; }			\
 }									\
@@ -488,6 +495,7 @@ __DEFINE_GUARD_LOCK_PTR(_name, &_T->lock)
 
 #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
 static __always_inline class_##_name##_t class_##_name##_constructor(_type *l) \
+	__no_context_analysis						\
 {									\
 	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
 	_lock;								\
@@ -496,6 +504,7 @@ static __always_inline class_##_name##_t class_##_name##_constructor(_type *l) \
 
 #define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
 static __always_inline class_##_name##_t class_##_name##_constructor(void) \
+	__no_context_analysis						\
 {									\
 	class_##_name##_t _t = { .lock = (void*)1 },			\
 			 *_T __maybe_unused = &_t;			\
@@ -503,6 +512,47 @@ static __always_inline class_##_name##_t class_##_name##_constructor(void) \
 	return _t;							\
 }
 
+#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)		\
+static inline class_##_name##_t class_##_name##_constructor(void) _lock;\
+static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
+
+/*
+ * To support Context Analysis, we need to allow the compiler to see the
+ * acquisition and release of the context lock. However, the "cleanup" helpers
+ * wrap the lock in a struct passed through separate helper functions, which
+ * hides the lock alias from the compiler (no inter-procedural analysis).
+ *
+ * To make it work, we introduce an explicit alias to the context lock instance
+ * that is "cleaned" up with a separate cleanup helper. This helper is a dummy
+ * function that does nothing at runtime, but has the "_unlock" attribute to
+ * tell the compiler what happens at the end of the scope.
+ *
+ * To generalize the pattern, the WITH_LOCK_GUARD_1_ATTRS() macro should be used
+ * to redefine the constructor, which then also creates the alias variable with
+ * the right "cleanup" attribute, *after* DECLARE_LOCK_GUARD_1_ATTRS() has been
+ * used.
+ *
+ * Example usage:
+ *
+ *   DECLARE_LOCK_GUARD_1_ATTRS(mutex, __acquires(_T), __releases(*(struct mutex **)_T))
+ *   #define class_mutex_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex, _T)
+ *
+ * Note: To support the for-loop based scoped helpers, the auxiliary variable
+ * must be a pointer to the "class" type because it is defined in the same
+ * statement as the guard variable. However, we initialize it with the lock
+ * pointer (despite the type mismatch, the compiler's alias analysis still works
+ * as expected). The "_unlock" attribute receives a pointer to the auxiliary
+ * variable (a double pointer to the class type), and must be cast and
+ * dereferenced appropriately.
+ */
+#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
+static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T) _lock;\
+static __always_inline void __class_##_name##_cleanup_ctx(class_##_name##_t **_T) \
+	__no_context_analysis _unlock { }
+#define WITH_LOCK_GUARD_1_ATTRS(_name, _T)				\
+	class_##_name##_constructor(_T),				\
+	*__UNIQUE_ID(unlock) __cleanup(__class_##_name##_cleanup_ctx) = (void *)(unsigned long)(_T)
+
 #define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
 __DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
 __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)		\
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-7-elver%40google.com.
