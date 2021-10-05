Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSXA6CFAMGQE77SN5SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8868422433
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:26 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id r15-20020adfce8f000000b0015df1098ccbsf5600733wrn.4
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431626; cv=pass;
        d=google.com; s=arc-20160816;
        b=sE6ctUgHIQLQ84599lTX9G6yGJyavs0om6RfCE20Mw5c3f83BL1GrRnsvCUEfbZYlf
         kV5pFf5X7mS1Sdl4JmL40vV+ozQeq6jGVj4oForGoCkmHquDmUjD9EOaR8cykPqxN2BL
         h99perINDrtRRpjCkjr2Gp4sqjpbRXJgvJaPhoEEkv7Asb7xYXg9xDJiYq8sx18vDhG8
         ShBjdVtKRjEcsKVXWTS4ParfNfie5HOssiimS/VEWAyzdY1nzkoHKjvhHZ1tgpoirPxo
         V0PwPJCn7+ZRN0P3TuGEFV0qUA0nsLXEjRNJGRL+GNjhKfEvt6CAxi2fHgC7iK28HkaB
         snhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oEFwVn9/5n8K/9Vd0aSS4RtV+9fvklhNeQaqqjgdhqA=;
        b=Ox+Ac7AHqk20H9zawtKbQtBW2NB28mPH1XF5lIUvuTCegnLUja48OsYKVgwrP1vBfX
         dEwJqo6oO4bDy5PVYlQv/LmbLcIAFX1/nUp3jCBvHeqVnBYzboKMK6RyYv0j8BTOXgq8
         ++HW+6/NGmI11w2ZgBIF8982phbt6M4NN/Mp8Xc/R3zaOYA16f3yQyr6wlBLRiisHLPH
         Y5cyAYtWwGHXPEOQYNnW3VdVzkUMh/UZzkmDRW6SOYfoqIq4icQh8T6T6LYIE4YurYVm
         7BMWke49twlZdQqP6lSeIBEvwUWWfcQ0BdYFqycSm1WEb7iQ0Xmw83veIe5UIdBRr9UV
         jhog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bncNaURV;
       spf=pass (google.com: domain of 3stbcyqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3STBcYQUKCSwMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEFwVn9/5n8K/9Vd0aSS4RtV+9fvklhNeQaqqjgdhqA=;
        b=aSpTR2xgVBRiyaONoHlPe7T9rtne1LKPk0KF59iwyXd7NNh++pKm0CwqTp62DkhqDE
         vdHAgKH/qDXZ3VLT40ERezGVdlDZKT5l854P0CjpR3hfkbDkVE/IwDgr5DDCxAflohY4
         NCZpteseVyuGimMwFTch5woZX/zMLIZAeX2IxR0lo7bSudmMU3InlTwEBvjWOR3ijXr0
         BlJBvm8NrKrygzyvbPEbv2uD6PINue7AzyMq1irdkBUCXh7ozer/6XmvGLX5BgnpXmEo
         WIQxw/pDpuwR9OQZVwrwKaJJ8icpOTD1Wg79Oh/TtysxzYOU5ZTtuHvPIRC4J2ZtdqV/
         G3Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEFwVn9/5n8K/9Vd0aSS4RtV+9fvklhNeQaqqjgdhqA=;
        b=69a9VMqJJnz14lXiJVVYJiF5n7KtpNjok9LM0LsY5VmLdr/7CsOJqCxU3b+Q95PZi5
         H1nB0eFSeIYrOplIidymXQjyTIPX3a8qHaeYAoa9ush8sU/4j9JpNYfdny4FFRGNGNlQ
         JToWL2ivdHxGdxTwbwS790aRCvmcf+Q6S35NloiFNjaQxuAlAzGNkOUSUinuEbzBpBP8
         6joCJosdCGeK2rfR4SQJmkdcUwMxLS+Ya0330vpZ5cOrbVpHZkl8T3vwlxnhVzGl1cCg
         FqRxQqoV7bt82LWkxaudhXOpS1rrKnKeXsesi7/j65SJ3EKR8/azqMQL7opvXetizbcS
         ogRw==
X-Gm-Message-State: AOAM533JF4iZS9CP4+kQg5W8OcqDOd/943F084niHfo8WY550/cC9guI
	Ncdn2pQZWN21QicgUdTQuCo=
X-Google-Smtp-Source: ABdhPJx+VqFJdwlkd64dKF2FbLhqikMqeETUvaFVfjc9+TOyiWKCyCGynNDtXuHqlnLXjiFP3RL0Uw==
X-Received: by 2002:a5d:598c:: with SMTP id n12mr20076577wri.391.1633431626525;
        Tue, 05 Oct 2021 04:00:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c782:: with SMTP id l2ls1840101wrg.2.gmail; Tue, 05 Oct
 2021 04:00:25 -0700 (PDT)
X-Received: by 2002:a5d:56cc:: with SMTP id m12mr20345862wrw.22.1633431625735;
        Tue, 05 Oct 2021 04:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431625; cv=none;
        d=google.com; s=arc-20160816;
        b=bhzwn8oyreQKEwwXamgtG4Fiad7A3VOMO8hrMLM4+QE6oG+ZfAZAruYxf4BHq2t5Xc
         FHluubKSz7rF7O347BesOK39AGNGsJU0KxYzo8WHkZkI8LcQlDE06YNPowjXoLh47y04
         iHGyeu+y8TJhAO1JpsKzCuY/TZjuTpleUdE5gtxKVSTv0GVTdUxFW89wD9XKk9hMta/l
         maGMw/ISpvuWXVSbiIgM3jxxVRjawdZXTdw84XtSloehhyaoztBiyOOTSITh+QVHinYK
         7oZ2xvGQwZaHs9lUQejDivn1jvuG4zPL+7qPrLTD2vBW98TrjPAgkbIFwllOB1vZDOoL
         G8gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=FsZx+1aUI6aPLGHtJazoYidelDd+JHI3Oque8YR4DUc=;
        b=n+M6WKePTpY/8/rr/XC7peCWGkeFfidbuyijYDKfJHM6J0TLNUHPpJOkEprJgyw5jz
         85y2QW68ADdaYPQQzBGEbtz9NeJiuyG4MF4unGYYEcCBMBJGrG6GdKiRk+1TYnw03Y+D
         3nCBeGORzDfpzEITH9LwOn4iefZZspZwdR/N6UdnOficewCLRgCpHUHxTsDefNDvT0mG
         2hXHQrh8q9x516d3vF71hwKWS4RWqKn5UjpuxgxTKzsfCeQDiFQQm1d4jfcA4q26V6Qz
         j0gfWMgw1Pm4DTswJuTLgs7otxaCsSNFral22e8Uw6/1+fBJgYuFKLjjwwP6tBFKTs61
         5VCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bncNaURV;
       spf=pass (google.com: domain of 3stbcyqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3STBcYQUKCSwMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id a11si270476wrh.5.2021.10.05.04.00.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3stbcyqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z137-20020a1c7e8f000000b0030cd1800d86so8966317wmc.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:25 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:600c:4fc7:: with SMTP id
 o7mr2657914wmq.91.1633431625363; Tue, 05 Oct 2021 04:00:25 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:59:00 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-19-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 18/23] x86/barriers, kcsan: Use generic
 instrumentation for non-smp barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=bncNaURV;       spf=pass
 (google.com: domain of 3stbcyqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3STBcYQUKCSwMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

Prefix all barriers with __, now that asm-generic/barriers.h supports
defining the final instrumented version of these barriers. The change is
limited to barriers used by x86-64.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/barrier.h | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/x86/include/asm/barrier.h b/arch/x86/include/asm/barrier.h
index 3ba772a69cc8..35389b2af88e 100644
--- a/arch/x86/include/asm/barrier.h
+++ b/arch/x86/include/asm/barrier.h
@@ -19,9 +19,9 @@
 #define wmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "sfence", \
 				       X86_FEATURE_XMM2) ::: "memory", "cc")
 #else
-#define mb() 	asm volatile("mfence":::"memory")
-#define rmb()	asm volatile("lfence":::"memory")
-#define wmb()	asm volatile("sfence" ::: "memory")
+#define __mb()	asm volatile("mfence":::"memory")
+#define __rmb()	asm volatile("lfence":::"memory")
+#define __wmb()	asm volatile("sfence" ::: "memory")
 #endif
 
 /**
@@ -51,8 +51,8 @@ static inline unsigned long array_index_mask_nospec(unsigned long index,
 /* Prevent speculative execution past this barrier. */
 #define barrier_nospec() alternative("", "lfence", X86_FEATURE_LFENCE_RDTSC)
 
-#define dma_rmb()	barrier()
-#define dma_wmb()	barrier()
+#define __dma_rmb()	barrier()
+#define __dma_wmb()	barrier()
 
 #define __smp_mb()	asm volatile("lock; addl $0,-4(%%" _ASM_SP ")" ::: "memory", "cc")
 
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-19-elver%40google.com.
