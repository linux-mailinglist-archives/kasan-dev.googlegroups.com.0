Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLFDWDDAMGQE5PLJWGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C5C3B84F5D
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:34 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3ee10a24246sf556280f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204334; cv=pass;
        d=google.com; s=arc-20240605;
        b=k2NS/TWqQGFHzTQKHsHUbDK/tZcCu3Bd+WbW38Xuve4AmkSWgYSQMvXHgExtMhDQ6w
         UhmOr/+xaeWn3LkF5+1fJ6jpf3mm/T4URCCj4e0GO1lNIWwzh+2dlOoqDCuNdc+zKhdQ
         7sQ3id59jFVHO0UrL5QwgVE91oLCd+WkvFmt2EqsO+358WpfIS55tSdAEx68YXu0fI4d
         O+IpsH74A6BYC1R3j0t/EsbAFx3mAgzOlv5UPf63Nc3bmUdBCChkOEEyKYzjQJC2laRG
         AmePcH6Q8uUqdtZoAmJ7Lgdh3tD4vpDVaYiRsOVDW40IuP2E+Lo4LDqP9xNvaPITavNp
         IHPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+f8FYm3pUOH+rjDyBb9Dvx/IsJXY4WY1d1Gg78fHG8w=;
        fh=bTZbN+3uNbC+eZ1PNMqKonUuilHqyyawnxrjLziU3vE=;
        b=TtH7JzXTOe4a3Smy7+z0cr8DoLl4V5VHtMFl7CV7IGAci+N+EYjfWzcIuA0Schace5
         F+AWyd9IhVtC6RV4X6B4mkMxCwPqWD36OykDm+mRa724vfX1NU2WPQsoitPUbfAlHHfT
         SYdPXEOxYGNgGjrExYmaLHTHwzLEMbTeoZIHEQ/eEyRubyeQJJEWExXYhHvpvW2ivLu0
         ZL2byoH7pit5gAC59UGkzNAczx6MG1E/Uq1gxII654L2zONwuMU4rEmZbpUxTk5+Vdy8
         uDGGnnKJb/18u5YCWOhyayCuIDWpWTINF6FSCmzj2gYb72cgEhuYO/4uP43AtoyDcnaX
         1gIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U5DEwdcl;
       spf=pass (google.com: domain of 3qrhmaaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qRHMaAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204334; x=1758809134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+f8FYm3pUOH+rjDyBb9Dvx/IsJXY4WY1d1Gg78fHG8w=;
        b=OoE9Yx/L9Vltb6Ds4HKjFiBNrnIjeKbj8uIv/AZ67q8isMvqqkrp0Jel7PGZzwGG7x
         xvLVe1Yd/2XoniFtnBkd5flPX9nZcQry94LR4fm5LE4vNJb0HNUIwZHdy3iY6OKeZOTY
         rWkKX5WeQs+upj83bRgfjghIepD6qCrtNDZlG03ofyzpjFAmrBlwe+3toItBLovSrAGf
         lXWlex9kJHpXMxH/6waG/OIy+5oaEOhhzvFco8TcmvPHoJo7yuU0XHPI7y2IvPzS8Opm
         s8nAf2u8BSKjvIlXYTIopetiUcEGqHYBUVab0AhqqNnJAhlA0TLy7l8GM15nQEPCEB8F
         +j3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204334; x=1758809134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+f8FYm3pUOH+rjDyBb9Dvx/IsJXY4WY1d1Gg78fHG8w=;
        b=RLei8gvFoCe1y3SRLKhXGIu3xj7vZANuB7lPfRA6WPwdeqRba3LSTn15JIhTVA4ITd
         asiUxFZr3Ts29gfi6RMpbZ53e6VWHxebDEtxTO+OYvl0eH4V0rDN4M7nZu9+Nu5uqJUT
         l6ry773aPEzkk1IUnr5Jke4nWXaRofLYx6lSHx/AxhIFS1TH5Qki47+ebc90SC+oRX/p
         GJ/VxA0uWcf+fpJZFW37orS/RH2y5rcdpx+CYCy6/u6K83n3fBZsW4rmO6arbiLCGtbE
         hNBRiDDoT66qvs6UOkYdW9rAapP0m6k5LmQP/CcN2kzfy5Ci1j5Vlu6fo2GuJ03CydAR
         xN7A==
X-Forwarded-Encrypted: i=2; AJvYcCWMykLvTICgq7kY66HSKa6FLVCRpizn0fssWqs7FMutO6Uc9Qs7LuFIdmMv4KJwfZeCaC0Ovg==@lfdr.de
X-Gm-Message-State: AOJu0Yye3hn9XQI06LBKN0tuOa7IeTgCfbjKeaWkDBs5dsfwG+degFnL
	XfSUU8ZtaMW+tbEfxqAJ5km3fxc/XFRNzM3T4kvUaGj89lK9lqkHfhGS
X-Google-Smtp-Source: AGHT+IE920d5Bvih60PtfUcF0xRZYT6lOWDWb+HtXs5VJOVoUftMwakYfJeiO/53TMTvHfep70GvZA==
X-Received: by 2002:a05:6000:1889:b0:3ee:1492:aeac with SMTP id ffacd0b85a97d-3ee1492bd04mr1491379f8f.38.1758204333191;
        Thu, 18 Sep 2025 07:05:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5SEmbimxCGE218B5MKg7p0VJ6EN4b0izgAQZ4b09DQ/g==
Received: by 2002:a05:6000:40ca:b0:3ed:8e48:5e0d with SMTP id
 ffacd0b85a97d-3ee106bfb24ls558436f8f.1.-pod-prod-04-eu; Thu, 18 Sep 2025
 07:05:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXG4IUE9Ni865geMSBsXUvu+VFMtugNbeUzUBm21gG2W8ruDTZt+86rP73SUKuV6pcwubVuWC10ztw=@googlegroups.com
X-Received: by 2002:a05:6000:2489:b0:3b9:148b:e78 with SMTP id ffacd0b85a97d-3ecdfa772e7mr5656911f8f.53.1758204329938;
        Thu, 18 Sep 2025 07:05:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204329; cv=none;
        d=google.com; s=arc-20240605;
        b=fnEgb7gB/Nu4zFxST67fl/1c1szWjSKws49C8TuSXqTuNv3iLsOdcK9MqQBu9HjPqx
         ZgzUvsHPaN/CFD+84gCLHUnIDTOcNkNuRYocPYNvSOdVuvf4/sWyQ1W8D+S1a84R9c3T
         Uo53tcesiO+Hq7AFeXgvvA3VqOU/FDz0O7AiQMFc+2b6CVgZ3Cjeh191Y59PVU3enGTn
         9wIjW8H/e3WeEJdpTWaFm/4tBVAMQFr1hVsxxoLTBSbcn1HpJj2v7zjeGbh4ZV84sONr
         gdlnJmNPEyLf3DzBZpEaWlGNehgq8752TvZZhhfthYtrR2hmisOMOfHC/615TyaNIUrm
         NoLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sI2tSFnbkFXEHpzRn76LXPg2QDPG5jXGC+/0hf5kEII=;
        fh=ubd87IkISQe6po1C3br5ewGC6ynKlUWlDGor3VcxkxI=;
        b=cAbCtGqQq7hI8exsWMDMaeLAXy142K/4RfVwCPL8ZbqAZ3ZVhpfuczZvP5kJo9cm4k
         PFFYD8Vc9azOt3cGWDuGO3BTAr8WiFbPcCcJOdk/2vnTnWH5LPjpIab7jb32GxjTNX9b
         HYRIzBi83B0D1o0IH0k99CLVcYQrwY0mN5edu3/E5MrKaWsp2QE9Fmgmr6ZIYsiq7qXj
         IiYQ/HV1DPa07hp8zUlB/lzCazvOyUr7uvujmLqUM4olJ73FK3LSOrtZi/oktHO0uwqg
         e3fiAgefKwliV68hm5ph3+8RhnD5/ojRRe3mfK/xCQxYpUXauGBm0zSUFcWUN3QiJJ/F
         9JiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U5DEwdcl;
       spf=pass (google.com: domain of 3qrhmaaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qRHMaAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee073f5527si56268f8f.2.2025.09.18.07.05.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qrhmaaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45de13167aaso9987805e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWzMKELP5YOKmKS/WiwCXoE55ED6ht4zGJaDw09UjFnVR2m7L3pDXwaMjWffn+qsjFa694/S4efThE=@googlegroups.com
X-Received: from wmlv10.prod.google.com ([2002:a05:600c:214a:b0:45b:9c60:76bb])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:b86:b0:455:f59e:fd9b
 with SMTP id 5b1f17b1804b1-46205eb1674mr64702705e9.24.1758204329318; Thu, 18
 Sep 2025 07:05:29 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:12 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-2-elver@google.com>
Subject: [PATCH v3 01/35] compiler_types: Move lock checking attributes to compiler-capability-analysis.h
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
 header.i=@google.com header.s=20230601 header.b=U5DEwdcl;       spf=pass
 (google.com: domain of 3qrhmaaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qRHMaAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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

The conditional definition of lock checking macros and attributes is
about to become more complex. Factor them out into their own header for
better readability, and to make it obvious which features are supported
by which mode (currently only Sparse). This is the first step towards
generalizing towards "capability analysis".

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
---
 include/linux/compiler-capability-analysis.h | 32 ++++++++++++++++++++
 include/linux/compiler_types.h               | 18 ++---------
 2 files changed, 34 insertions(+), 16 deletions(-)
 create mode 100644 include/linux/compiler-capability-analysis.h

diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
new file mode 100644
index 000000000000..7546ddb83f86
--- /dev/null
+++ b/include/linux/compiler-capability-analysis.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Macros and attributes for compiler-based static capability analysis.
+ */
+
+#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
+#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
+
+#ifdef __CHECKER__
+
+/* Sparse context/lock checking support. */
+# define __must_hold(x)		__attribute__((context(x,1,1)))
+# define __acquires(x)		__attribute__((context(x,0,1)))
+# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __releases(x)		__attribute__((context(x,1,0)))
+# define __acquire(x)		__context__(x,1)
+# define __release(x)		__context__(x,-1)
+# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
+
+#else /* !__CHECKER__ */
+
+# define __must_hold(x)
+# define __acquires(x)
+# define __cond_acquires(x)
+# define __releases(x)
+# define __acquire(x)		(void)0
+# define __release(x)		(void)0
+# define __cond_lock(x, c)	(c)
+
+#endif /* __CHECKER__ */
+
+#endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 16755431fc11..c24e60e75f36 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -24,6 +24,8 @@
 # define BTF_TYPE_TAG(value) /* nothing */
 #endif
 
+#include <linux/compiler-capability-analysis.h>
+
 /* sparse defines __CHECKER__; see Documentation/dev-tools/sparse.rst */
 #ifdef __CHECKER__
 /* address spaces */
@@ -34,14 +36,6 @@
 # define __rcu		__attribute__((noderef, address_space(__rcu)))
 static inline void __chk_user_ptr(const volatile void __user *ptr) { }
 static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
-/* context/locking */
-# define __must_hold(x)	__attribute__((context(x,1,1)))
-# define __acquires(x)	__attribute__((context(x,0,1)))
-# define __cond_acquires(x) __attribute__((context(x,0,-1)))
-# define __releases(x)	__attribute__((context(x,1,0)))
-# define __acquire(x)	__context__(x,1)
-# define __release(x)	__context__(x,-1)
-# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
 /* other */
 # define __force	__attribute__((force))
 # define __nocast	__attribute__((nocast))
@@ -62,14 +56,6 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
 
 # define __chk_user_ptr(x)	(void)0
 # define __chk_io_ptr(x)	(void)0
-/* context/locking */
-# define __must_hold(x)
-# define __acquires(x)
-# define __cond_acquires(x)
-# define __releases(x)
-# define __acquire(x)	(void)0
-# define __release(x)	(void)0
-# define __cond_lock(x,c) (c)
 /* other */
 # define __force
 # define __nocast
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-2-elver%40google.com.
