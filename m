Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZE5TCGQMGQE7Q25KKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id F34424632EE
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:40 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id x17-20020a5d6511000000b0019838caab88sf3523260wru.6
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272740; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bz/Rh8Ub2WLjxHfIbajC9Vi8Ug9teHCw1drLfzRPmQqTw2RpEVoT3/lAZl4haavFsF
         hbrwGhHEqnR+Xozmqs1G20jJnKvW/IqnpWno5En87ydpUgQkn7av2UMWtJELn6sJMCVu
         nSLdQDtpmQwmrL49uZXHqOniF6NLekwJC72hEM3/HNU8rJKcvFrhNiK6+xnweHZuTEp6
         NgVo2DXt9uub06ZA1iUH64qquE2wsObf12sWKSLCo0lzj3Ia2VLbvO8BM+uVDck3uk3j
         UU99LH+K0FT5qfH91SDKg2vj+pkVAmqB4AokLOAUywGilIf6W8TALzR5HtEm76qODni0
         CXPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YIFoQBFlyqgy4IIfAOWL+McS+ccfUREy0RSQ9/CXpbE=;
        b=Kcnjbg1NokhaRC+nriKp3HjEZBWKQMsHuOV+pRwWEujPgoIIAEJWIQ6sZPQjP71w5y
         Y2PS5cuZXL4VqO4yss0KmRkYyvv/f08dgRZ3M2BTnQqSbpymfsjja9394NdkzTn5kj3m
         hjkTyb8wEgGmAbT6OH71PqznOj4I2ADF9h9y/pg+UOs0m7+PWmY0Q2BI24m5ltL2pi7R
         aMCoBhlNuK0BBicqyh5CH8IZursz7AQF4mHw5DizJVYAjVcP3lHsAagDCggO7jw5wX0N
         JSjAmch7wE9Sq0uGGTBIosK1hEHcefhuWglNBZcNyXkY17IKHN8UKzEuErg61AoyyDGF
         xo7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=r4Nym9IU;
       spf=pass (google.com: domain of 34w6myqukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34w6mYQUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YIFoQBFlyqgy4IIfAOWL+McS+ccfUREy0RSQ9/CXpbE=;
        b=H7XnFNL6DatBb1JagLSUR12cPNd0jDgevSpGc4LKs55rXkoBPEfotnNJuqtkRGu2Pw
         RIDgiqsdDXNBMwmiYRQELt4anyoWjK75xvqC9VGoH+fds0AwNJ489193bONBl5yBaIFm
         vQlHcMrRj4JC8tewLyDCczyQYSOcuEKOhUQEg24qriO/06k6eIYFALK40v96DBDMaiUu
         kMaDvA61jN7vDWurGXiIkon4fzv3BklOfnumkgARSf7wSZF3pX9Ht+rkqi0Cg1Vr8m+y
         rf/rZtEbRTMPblyp0KwwMABa63w/XG40qsOS5TTdAsj9dOKzxmPr+PW6LJs961zWCl+i
         UdbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YIFoQBFlyqgy4IIfAOWL+McS+ccfUREy0RSQ9/CXpbE=;
        b=rVc+RQKJCrljIfDy3AZbMvRIKNf1NlkBUkDp+YRQ2l3SO3Ps37p+egoW3Vr5ucN9BH
         DJzFipiBlFl4biz2A+4wArrmgR8K+RkDoU9xfxjznKTc1s27e42N2oC9QZ1kUZ/s34qn
         MOfjIMNBMRt2YCLVlbzqIRSAmeAR3BHoefT+b8kDgr0l0mg2C2eUynqP+p0/nHyhJZs9
         1fpZjnYDJM7wI1CGRzQv+aaxTlr51DBW6NvLU6SGL+y1ik+W4GlgiCf7n1facFlFsyor
         jcLRU7Dwp1mvuFJAn+Pj7Yccj659KBPUt+4fcMQZaTMUkzrNbJ369ynDAkzVvx79Yx64
         USAQ==
X-Gm-Message-State: AOAM531qNIDEkqg44Fm5FWG9/xR21mcB2VnKSTsZCisDsPTxu3zKsqHp
	L5V8t+hk3UQk3oUw+lgdMV8=
X-Google-Smtp-Source: ABdhPJygsUywGA2H5z9B0wE63+65UkWLMTij6Uh4hljYR63gNhqqnuhtVpd59wGN19p7cWSZZ+5XaQ==
X-Received: by 2002:a1c:3b04:: with SMTP id i4mr4383606wma.126.1638272740724;
        Tue, 30 Nov 2021 03:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls13076959wro.2.gmail; Tue, 30 Nov
 2021 03:45:39 -0800 (PST)
X-Received: by 2002:adf:a48e:: with SMTP id g14mr39846668wrb.474.1638272739914;
        Tue, 30 Nov 2021 03:45:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272739; cv=none;
        d=google.com; s=arc-20160816;
        b=E/G6DDIsiPYv+2p4x4Ad21s9hNniUjS4BTVWqa7QHX/IMzxKxhmG6TXdhpWrbr0nyJ
         9UejVyEQrlrfOU3izfZGWQc+G6ax2fTvuKUHsa6NjhTuKFfAV+PrcFHf6C7zsPoI6s/q
         Y1tJrsLn2Vqq8x5gs145Ooq/c3ekPl4x1e2knwVZiNkvvGqivM/EApehzzYS6FkLie4A
         crw7H7b54ABInxm8g4+fnZeF4dXRXhqtb3wlt0AZaHNPzTswP5eQ74sgLdf7aYvNsKSf
         y2Q4ppmUfR5nwiIiPHsmySdhw9r9mBOuvI5jSuw8CpE14C6kn/HwgvMQ0LA3gnxHQGYK
         EHww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=T9LcpiESjlbrW6ACmq5IFNnAkv2Wwnn3szo64Ts4MTU=;
        b=UvDJ/88VfNcWLplwosjh6p/Osp2XZZRWblFDCZCkRschspNEs9aKYKpSQheaMsa3Zf
         4EPqYmFi19CFXzXmNjrCJ0Qi82V3KqcHPmShxA2nNHGCQTpcHpEsjQfiQc2zThiWocJ1
         +Hb8gxGdiTIwc+qeMLeibeRoRiYX3PxwpDJpUzC9vmpxA5eja3/pEDrgbT+E0ZyAjqQj
         /W2sRu59QAW6FxNf2s+K7wmhTmk+Bz7nyBao1qQaVcrMY4a0QFrJjFGpocJGCiD7bIhZ
         DFuxP3xevs1diBiwUcmCmfIg2MGq5HVb6oypzFk/nTCTtKTQVcbhrQ13bPCCr2BlW44A
         FNvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=r4Nym9IU;
       spf=pass (google.com: domain of 34w6myqukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34w6mYQUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id o19si341755wme.2.2021.11.30.03.45.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 34w6myqukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id c8-20020a7bc848000000b0033bf856f0easo13620894wml.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:39 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:adf:c406:: with SMTP id v6mr39945592wrf.570.1638272739561;
 Tue, 30 Nov 2021 03:45:39 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:23 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-16-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 15/25] locking/barriers, kcsan: Support generic instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=r4Nym9IU;       spf=pass
 (google.com: domain of 34w6myqukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34w6mYQUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Thus far only smp_*() barriers had been defined by asm-generic/barrier.h
based on __smp_*() barriers, because the !SMP case is usually generic.

With the introduction of instrumentation, it also makes sense to have
asm-generic/barrier.h assist in the definition of instrumented versions
of mb(), rmb(), wmb(), dma_rmb(), and dma_wmb().

Because there is no requirement to distinguish the !SMP case, the
definition can be simpler: we can avoid also providing fallbacks for the
__ prefixed cases, and only check if `defined(__<barrier>)`, to finally
define the KCSAN-instrumented versions.

This also allows for the compiler to complain if an architecture
accidentally defines both the normal and __ prefixed variant.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/barrier.h | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 27a9c9edfef6..02c4339c8eeb 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -21,6 +21,31 @@
 #define nop()	asm volatile ("nop")
 #endif
 
+/*
+ * Architectures that want generic instrumentation can define __ prefixed
+ * variants of all barriers.
+ */
+
+#ifdef __mb
+#define mb()	do { kcsan_mb(); __mb(); } while (0)
+#endif
+
+#ifdef __rmb
+#define rmb()	do { kcsan_rmb(); __rmb(); } while (0)
+#endif
+
+#ifdef __wmb
+#define wmb()	do { kcsan_wmb(); __wmb(); } while (0)
+#endif
+
+#ifdef __dma_rmb
+#define dma_rmb()	do { kcsan_rmb(); __dma_rmb(); } while (0)
+#endif
+
+#ifdef __dma_wmb
+#define dma_wmb()	do { kcsan_wmb(); __dma_wmb(); } while (0)
+#endif
+
 /*
  * Force strict CPU ordering. And yes, this is required on UP too when we're
  * talking to devices.
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-16-elver%40google.com.
