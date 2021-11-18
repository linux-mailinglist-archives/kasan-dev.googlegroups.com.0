Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNMV3CGAMGQE6PZFNOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 285BF455678
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:34 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id m2-20020a056512014200b0041042b64791sf3440909lfo.6
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223093; cv=pass;
        d=google.com; s=arc-20160816;
        b=SE5WutDpO4YFn3CBcBrwjIfMoDSXzhBiCrze39AC2RVDN5k6o1zy6EYc3OARXN5tWH
         APzlSBIu94CuBUPyAGA/1BXFg2Y1VgOIyGuOIEl5EckolF6pYqMD4cUPEq4MS783Rsaa
         o63v8iZ1+rdVZix+U0YYLj036KYBbUpsaJ91W3Sm9c0OLtFPgT2KmM/SSie1uHx9sxW0
         HdUvwSIwVunJcfX0sJ9f2RI4iiE57oCUbaWKSLo+kQHiP+0SKuGfmMiNFGUyK3jKS0jl
         Thgx/hHdFCVePWv9t/KarUkws1p7KMISzsI1ubD4RVlHvn9fd3Oam2+2jQNxMefqLKYC
         fc3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=tmehg8RsQYH0Zv2LAFBgrz3vOSSGSfUny0hrviAu1GA=;
        b=oYuBPPquLFfWRV5f4wTdtH/4nEIs9U1bL+qKc6ajhRsRh/SoapLzpnjx81dY1xe+6H
         1+9o6dJtjswuKW7s6mObU/C5Y/yizl71xI72ol8fvPqgzpiP2vj8HZseArc4jIgt+2w5
         bx7MqaSBelFQy7RyAvpZEcgSl9Vatd/jKQJqqW6vC3W7k1GxzW5Nvbli2BxCmgo4oLxw
         5zd/xE9WyDP3rUXE29ab5sWu/1PGRlY3AvwPTXN3vkzNQZHbRpbwQppS9gJSNHMphUSP
         x4j2yhlVsGZoDqcXAZHJ7qoDUfam4PkAFpntCza7OIskcWZ9hpb2l0GLYap4BuHfyUyo
         tMyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ao5F3zNv;
       spf=pass (google.com: domain of 3taqwyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tAqWYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tmehg8RsQYH0Zv2LAFBgrz3vOSSGSfUny0hrviAu1GA=;
        b=FYIoOiP++WkT5AgNzCUYt3M6XQ5u5kOKBVmiz9UJh59kzkuQuRv+r5dWNtfNTlZCmq
         nQkQ7qGKAEqoOMqjdC2P0bq8tB+BtdIHKtZiHY++qqv7mUeqMbh1STiaKuAdEArPS/4O
         ZcLj/OLuNpC35H0NMD54tsmZJlfB7sQFLKlCO5HjP2OUH2LPYKul/CBnbgDMoVdzJbg0
         Te/P4xusNZ6hcu+85qiyp+iO4jIqeJPlrRQmo8nVoZT5Q/4e8Up1vhdl6kkvCCXnVgvO
         QLWCMLCLsqmS2zwt4xc6CKpQuLNdX5h+Pyd7QGBF7KRmjxGKIjOEXS9fPKRoSbe6wrjS
         fCrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tmehg8RsQYH0Zv2LAFBgrz3vOSSGSfUny0hrviAu1GA=;
        b=L19Yamg7S0m2nDbkLQF9MpIgwcqWyS/uT2S4btKlqewNJa4NuebaKH1K7iP1AAYrKV
         xWFku9VXk+IAVMXtpiLaHh2tCbreH1s9PP0XLx8MknoPxA9H/ZfrQ4iegEO2nQkTyvXk
         cIVYt/Px6jb8x0RmuhJUvDjwj1SZl43X+F+5HenRu17dTiYWiOo/CwQeYy1ouCeoLksU
         p15KmroCyDV2yX9X7bBjoI07GVMKNww0/Gl+9pBZ8r1OicnQ4DLBh5ZKU2S5lLlO082g
         K5ixo51Enm1jiatRkTW5C4XNV7HdlB4h7jp+YOghmo0CAx/dB+n5+RRCuo3ewCDPS8Uw
         xZ+w==
X-Gm-Message-State: AOAM533nEZMlTcjIhXBHbz3QHQr/7HY8Rw1hqKRLJpbN1lWTILqQAcmd
	UQwumHPa1Wj0dhERfyRJ1W0=
X-Google-Smtp-Source: ABdhPJyGCK8rL5sAYZ+r0pZoGfYtaZ1A9DaWouP5Mws9yxwy+daHqLhY9Mpj6YW+2Ca2L7MzNxd28Q==
X-Received: by 2002:a05:6512:b8e:: with SMTP id b14mr21639226lfv.654.1637223093783;
        Thu, 18 Nov 2021 00:11:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc09:: with SMTP id b9ls401523ljf.2.gmail; Thu, 18 Nov
 2021 00:11:32 -0800 (PST)
X-Received: by 2002:a2e:5712:: with SMTP id l18mr14255364ljb.268.1637223092686;
        Thu, 18 Nov 2021 00:11:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223092; cv=none;
        d=google.com; s=arc-20160816;
        b=V6hzeQgezGmlyDVyvighvkvAggRUUko+0fMhW4qFuWZhXrOVkQuDJC2xrYeLDp/yol
         nzYlubHTn/zVp2SBbXUEKhegT6lUtLJ6o14jeLxIJqiGjb1BBdZtA06ixTPBAVtZOvSn
         CBC28/+PhGIoV5e6H24edBRSpe5HA3YelhCgH3vZ5Sg6zMkwbt0TKW5aRzuQDEG/CD/i
         hF3GNe/jlYGS8WItzmTxXHEMsw0k6Oaa25Pabo+YnzcfoXjMcAPSFR4Nch1JbJ8bbOxD
         Nbkfsv66xk4P//uhD3aLMkxRQFudAB83NHlzOISHghQFBPspHCKXDTviC2w52vqs78Ro
         Zjeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=HO2j8fDcTjG33FWF1g1vyRfUzwW+oeuePm13p24Xfnw=;
        b=VrCRTnNyiZmRoEgsVsBxHp40MiR2/E/sf/AJ2Zft9GRENe0/qP3KtJFikDG4NEp8c+
         Ho1zc3vu2eXjCP2UM0A9Qwhpq3wObkRIRiym2LrC4fEn7Z4UdLLpBbclC9ZVoZ/d5eKl
         BWXzrz+MvKVY4OVbZndL9bP2MWTFXiswHe3JgsGlVKTo0ydZb7lTshSmjyhxXp0oKq3r
         4QSqe7l+pfGrrW1ljSf5bA4KVQBZn2ycES5611CCD1tnlekzre/BNa7G4AlzJKaV7dyk
         cbIdX8Ubrsk1kdQnJnJsjFXIEPof7J0aprEl6ALBilwNawdIvqnwzDVvrROHz0367Tit
         4edA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ao5F3zNv;
       spf=pass (google.com: domain of 3taqwyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tAqWYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i16si160796lfv.2.2021.11.18.00.11.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3taqwyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id o18-20020a05600c511200b00332fa17a02eso2718591wms.5
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:32 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:4149:: with SMTP id
 h9mr7592130wmm.100.1637223092073; Thu, 18 Nov 2021 00:11:32 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:18 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-15-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 14/23] locking/barriers, kcsan: Add instrumentation for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ao5F3zNv;       spf=pass
 (google.com: domain of 3taqwyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tAqWYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Adds the required KCSAN instrumentation for barriers if CONFIG_SMP.
KCSAN supports modeling the effects of:

	smp_mb()
	smp_rmb()
	smp_wmb()
	smp_store_release()

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/barrier.h | 29 +++++++++++++++--------------
 include/linux/spinlock.h      |  2 +-
 2 files changed, 16 insertions(+), 15 deletions(-)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 640f09479bdf..27a9c9edfef6 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -14,6 +14,7 @@
 #ifndef __ASSEMBLY__
 
 #include <linux/compiler.h>
+#include <linux/kcsan-checks.h>
 #include <asm/rwonce.h>
 
 #ifndef nop
@@ -62,15 +63,15 @@
 #ifdef CONFIG_SMP
 
 #ifndef smp_mb
-#define smp_mb()	__smp_mb()
+#define smp_mb()	do { kcsan_mb(); __smp_mb(); } while (0)
 #endif
 
 #ifndef smp_rmb
-#define smp_rmb()	__smp_rmb()
+#define smp_rmb()	do { kcsan_rmb(); __smp_rmb(); } while (0)
 #endif
 
 #ifndef smp_wmb
-#define smp_wmb()	__smp_wmb()
+#define smp_wmb()	do { kcsan_wmb(); __smp_wmb(); } while (0)
 #endif
 
 #else	/* !CONFIG_SMP */
@@ -123,19 +124,19 @@ do {									\
 #ifdef CONFIG_SMP
 
 #ifndef smp_store_mb
-#define smp_store_mb(var, value)  __smp_store_mb(var, value)
+#define smp_store_mb(var, value)  do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
 #endif
 
 #ifndef smp_mb__before_atomic
-#define smp_mb__before_atomic()	__smp_mb__before_atomic()
+#define smp_mb__before_atomic()	do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
 #endif
 
 #ifndef smp_mb__after_atomic
-#define smp_mb__after_atomic()	__smp_mb__after_atomic()
+#define smp_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
 #endif
 
 #ifndef smp_store_release
-#define smp_store_release(p, v) __smp_store_release(p, v)
+#define smp_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #endif
 
 #ifndef smp_load_acquire
@@ -178,13 +179,13 @@ do {									\
 #endif	/* CONFIG_SMP */
 
 /* Barriers for virtual machine guests when talking to an SMP host */
-#define virt_mb() __smp_mb()
-#define virt_rmb() __smp_rmb()
-#define virt_wmb() __smp_wmb()
-#define virt_store_mb(var, value) __smp_store_mb(var, value)
-#define virt_mb__before_atomic() __smp_mb__before_atomic()
-#define virt_mb__after_atomic()	__smp_mb__after_atomic()
-#define virt_store_release(p, v) __smp_store_release(p, v)
+#define virt_mb() do { kcsan_mb(); __smp_mb(); } while (0)
+#define virt_rmb() do { kcsan_rmb(); __smp_rmb(); } while (0)
+#define virt_wmb() do { kcsan_wmb(); __smp_wmb(); } while (0)
+#define virt_store_mb(var, value) do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
+#define virt_mb__before_atomic() do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
+#define virt_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
+#define virt_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #define virt_load_acquire(p) __smp_load_acquire(p)
 
 /**
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index b4e5ca23f840..5c0c5174155d 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -171,7 +171,7 @@ do {									\
  * Architectures that can implement ACQUIRE better need to take care.
  */
 #ifndef smp_mb__after_spinlock
-#define smp_mb__after_spinlock()	do { } while (0)
+#define smp_mb__after_spinlock()	kcsan_mb()
 #endif
 
 #ifdef CONFIG_DEBUG_SPINLOCK
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-15-elver%40google.com.
