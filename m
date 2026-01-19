Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI7YW7FQMGQEXTVNDDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 84926D3A34D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:40:53 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-38310ae8f4fsf31925051fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:40:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815653; cv=pass;
        d=google.com; s=arc-20240605;
        b=IPUsLb6lmvIOCS+HALwbpwETebyRI7YDJx0n0S16M0Xh9e8WqR0viUX1/s7DgN0E/T
         0dP7WgDySvfAdI5YA9heXVUNiqTLZANzq9Cbgdjz0Fi8iv61Bpy6vm+d37xmUzcgcXjg
         iLS0XJ+wtOq07AoWy46cIiJxSjL9xuBtmBj+8IsVyqeYLfAss+HHd8UF2WDL3rVusF+3
         ThrjOXdOxZ/y0hHPUrTRT16Ro5ZPlZ8jyRsmhwX+3IqX3JT4E4wPiHUreMSMdVXTZFeb
         pw8IJjMruMBwp+VttNx00xtyD/CveLotZl7dnO4emDfnfTOTT6H3gPO9Npa4pu0/c3uM
         xtPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MHX33mnZC5rwetRZp2ZqtKg6nrhP7ZfKuMtKIxhJbo8=;
        fh=NT87zRYyrfINQfwTMY9FMGfRmwa7MmoIEwEeCvqVmUw=;
        b=arVAUsBrWil4vF603sph62Ioc+SdWNBM/zu+qbHhlMu0tTQQRQbE9aSqBmiX887w1M
         66vS7TobNE6T4CnSgs1V7V1WCQEgYGSJrUFM7lbJVy7Y0jsqMlf0KM7bBtjXIKfjAe1s
         OQwy0JQUefz2+V6vsy/5c6LFegJ+5cCWgudDrhMA2aexBcyn/fxBjVYwEgLVNWVm/xK5
         c0XkFvIyoEyCsSzetSyoVuPr+U4EWBd2P+rDIp02iodOWx+CaCDJIcOBlGfGQJW2tt0y
         OKYoUM232FgT3znJFusULyXIZBvPaZNrwQYAqKRUPWKGRDDwJBPOFgjqE64y2vAAv6je
         jG4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uSnviB4f;
       spf=pass (google.com: domain of 3ipxtaqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IPxtaQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815653; x=1769420453; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MHX33mnZC5rwetRZp2ZqtKg6nrhP7ZfKuMtKIxhJbo8=;
        b=MKQkykEvdKNZ6/tMLA174p38UDZH9KLgqxAHCa+ZcllnpMp+C2APbXVjMKo/3zT+Rj
         Xoi6cNgZFG2X7bqqD4IfjuNkWF9sYVH5kiJkfDCl0LbrN8+m8ZHwmuwHnOwAuW6i3Wxf
         tFoB9ur0o/h7viXMWOm8N84NDQ5ZOX4kfDWVHfjoXIh00igqGWWILbtBI0xcLg90wMsB
         TxVOeLC2QotpCzM5Bhwj8ePOT9ibxJR9Qy4UYUplR2ZlSJGR9zxUlCZs0ouqKuhMkUu6
         boHbwnhSKJO9109TfoP6LLpNppNEZIhvKhtw6lrhSc0i1ohHaZosUqYB2ZGac864rP5i
         c3Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815653; x=1769420453;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MHX33mnZC5rwetRZp2ZqtKg6nrhP7ZfKuMtKIxhJbo8=;
        b=Is9aiIRF2z5rTwvvBsoeS0n1pHu5ZUxaY6B+DyJ+l+kzlDBnKmCcpuHiwdp2H/fv8l
         GoPJMrBJzj7CWur3iaMbi+iAjtpgpkBeRkK2fmffzOtnWAuNFeBGa6u/u8nf898IvHAq
         oy1/Y9idCrJUBVOyq+8AEwflaUGOvPpcf5f4i14UP/gjv6NXA9tQuBsubupTmnQIAusU
         IUsMy9WrCsRe9pW9weTtamWUlhv3D1iaeybe+4G8GVnhP+3uZC1/lXdN6FhlBDKOjO6F
         bNlXKXb8BcX38tZukMsR9+GxtLCXEx/wYbjByMO+U2FY/Lhw3XhbX5mS1ITeTM1kii8Q
         TycA==
X-Forwarded-Encrypted: i=2; AJvYcCXA0fHDVg5r2SPe/sODMIzlgYyFEKr0kakunKlJMmmsx+jfv7f8fHDSpfl0HFcnhdSFSyxYKg==@lfdr.de
X-Gm-Message-State: AOJu0YwZ5ZbfynEY1++M/+9NuitdWb2tI/LWdTMmvRv+wNJ7dipmu0V/
	2/KT5I7XQVOVIIVzV/DU1v5QQtTdi64vAQOl2ZDJx2KyUyMhRueCuh9O
X-Received: by 2002:a05:651c:1b0a:b0:383:2bca:a610 with SMTP id 38308e7fff4ca-38384322c32mr29225861fa.41.1768815652465;
        Mon, 19 Jan 2026 01:40:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ETegiXHfOJVAbfdCjFY7WIdO7cqZ+WxeWw9cLTPK85ww=="
Received: by 2002:a2e:6e0b:0:b0:382:fcc7:93e4 with SMTP id 38308e7fff4ca-3836ee724b9ls9383621fa.2.-pod-prod-08-eu;
 Mon, 19 Jan 2026 01:40:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWp9IJeLTdrXX6burofPuonl3EeApmjGY/McSym4U9CAwCGwIMi3+LtoREdbxFnEPyT/9WfSbmHit0=@googlegroups.com
X-Received: by 2002:a05:651c:25d5:20b0:381:1b32:e28 with SMTP id 38308e7fff4ca-383842ed0a0mr31540701fa.32.1768815649041;
        Mon, 19 Jan 2026 01:40:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815649; cv=none;
        d=google.com; s=arc-20240605;
        b=JwEVJulCGef7UAvzakkJ2jT/dZvFp8rAin1jwUEwbgijK6kT4nkmRv8fqR45IV5HPI
         Gj1+3ORLe2ZwXzugN5JKCl8R7Zi7MqF+ggVkxo5ZsUJ+Bk9yXl/G6F1ryQiMt0MG3zYH
         rm/wVrkGK7tj2xezQ23jDYiVgNfuliLNtCqyscug0MnQLiQjelqnS8FYgcJrF51B1Je+
         uEFS/N1WrNKjWHbNxI/21uSsMM1D3AUJo3N+asj+seSlZTrabrpqcTYnfXdLGaA/N54a
         75oNmDPlBEYZrB8FjkHYfYphWrBkrQvoLio9pdOyjSPMVrPGY/jwMHXDN9kzOi74JmR6
         GO/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FVzjIjtVdiVPjpEIkbADcVmmkIUg4nu9DkgIt9tpdDQ=;
        fh=DEgDBgRn1OBdhZMIk4ZE8cQp9/aYjJWaB6Wv68S17ds=;
        b=hIMbwsDmzfWn9Nyn2LkJrn2Vb5tFqSEArYwJ/eFDWfV0Bq4+Or5MyOgbmnNRh7nghz
         Gpm3pEtjhhMMfxUxKZ76DFnHkxeWLEifPeFsKvEC+jOOMMe/wDxUnOpHmQq61K8jfud7
         Q6KekMMFnDf6FFbGlU2UQieYgkk9Qqp9RuxeC25WdqdONAQbQjL2sDbnovzMjdsbHtZ3
         uZ3ptxHC6G7hHWlEdn0kiuUHOe4Ln4QRifrDSYELnt63cTX6ihY6B9V3Nd3ziBHlS/F6
         /lJIHHBTg/i0O8lZEGNOpOUXUKRKj/1TL8XCVwjqbLCVTFWc+taC2AAeNyihHwn/0jXc
         HREw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uSnviB4f;
       spf=pass (google.com: domain of 3ipxtaqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IPxtaQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e78091si1840541fa.8.2026.01.19.01.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 01:40:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ipxtaqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-47d3c9b8c56so52466055e9.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 01:40:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWajpiOXsHi/6YEyfAW7coQ/PdF6RBf+JfwLa03/soJkMEsVI4hrZWHWbnMuJETO0k+65Q7VClX2sw=@googlegroups.com
X-Received: from wmaz14.prod.google.com ([2002:a05:600c:6d8e:b0:477:a1f9:138c])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4e89:b0:475:dd89:acb
 with SMTP id 5b1f17b1804b1-4801eb035ecmr125513305e9.22.1768815648401; Mon, 19
 Jan 2026 01:40:48 -0800 (PST)
Date: Mon, 19 Jan 2026 10:05:51 +0100
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
Mime-Version: 1.0
References: <20260119094029.1344361-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260119094029.1344361-2-elver@google.com>
Subject: [PATCH tip/locking/core 1/6] cleanup: Make __DEFINE_LOCK_GUARD handle
 commas in initializers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>, 
	Christoph Hellwig <hch@lst.de>, Steven Rostedt <rostedt@goodmis.org>, Bart Van Assche <bvanassche@acm.org>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uSnviB4f;       spf=pass
 (google.com: domain of 3ipxtaqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IPxtaQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

Initialization macros can expand to structure initializers containing
commas, which when used as a "lock" function resulted in errors such as:

>> include/linux/spinlock.h:582:56: error: too many arguments provided to function-like macro invocation
     582 | DEFINE_LOCK_GUARD_1(raw_spinlock_init, raw_spinlock_t, raw_spin_lock_init(_T->lock), /* */)
         |                                                        ^
   include/linux/spinlock.h:113:17: note: expanded from macro 'raw_spin_lock_init'
     113 |         do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
         |                        ^
   include/linux/spinlock_types_raw.h:70:19: note: expanded from macro '__RAW_SPIN_LOCK_UNLOCKED'
      70 |         (raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
         |                          ^
   include/linux/spinlock_types_raw.h:67:34: note: expanded from macro '__RAW_SPIN_LOCK_INITIALIZER'
      67 |         RAW_SPIN_DEP_MAP_INIT(lockname) }
         |                                         ^
   include/linux/cleanup.h:496:9: note: macro '__DEFINE_LOCK_GUARD_1' defined here
     496 | #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)                      \
         |         ^
   include/linux/spinlock.h:582:1: note: parentheses are required around macro argument containing braced initializer list
     582 | DEFINE_LOCK_GUARD_1(raw_spinlock_init, raw_spinlock_t, raw_spin_lock_init(_T->lock), /* */)
         | ^
         |                                                        (
   include/linux/cleanup.h:558:60: note: expanded from macro 'DEFINE_LOCK_GUARD_1'
     558 | __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)               \
         |                                                                         ^

Make __DEFINE_LOCK_GUARD_0 and __DEFINE_LOCK_GUARD_1 variadic so that
__VA_ARGS__ captures everything.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/cleanup.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index ee6df68c2177..dbc4162921e9 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -493,22 +493,22 @@ static __always_inline void class_##_name##_destructor(class_##_name##_t *_T) \
 									\
 __DEFINE_GUARD_LOCK_PTR(_name, &_T->lock)
 
-#define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
+#define __DEFINE_LOCK_GUARD_1(_name, _type, ...)			\
 static __always_inline class_##_name##_t class_##_name##_constructor(_type *l) \
 	__no_context_analysis						\
 {									\
 	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
-	_lock;								\
+	__VA_ARGS__;							\
 	return _t;							\
 }
 
-#define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
+#define __DEFINE_LOCK_GUARD_0(_name, ...)				\
 static __always_inline class_##_name##_t class_##_name##_constructor(void) \
 	__no_context_analysis						\
 {									\
 	class_##_name##_t _t = { .lock = (void*)1 },			\
 			 *_T __maybe_unused = &_t;			\
-	_lock;								\
+	__VA_ARGS__;							\
 	return _t;							\
 }
 
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119094029.1344361-2-elver%40google.com.
