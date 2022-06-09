Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VTQ6KQMGQE54UCPPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3B77544A23
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:10 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id k5-20020a05600c1c8500b003974c5d636dsf11233231wms.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774270; cv=pass;
        d=google.com; s=arc-20160816;
        b=pr3osBifYufdRyKLE/oYNHR36PfcKDTHN1mtbSIU62aEb904KHQSnoxluepPQYHsbD
         Kpiww1sn/+NnHPIZRTBqaYRfblNJlpRW4yrTjNAp0Lxz85kdz8h2W9bLXVf4TgdgRHtT
         XagW+JN3kFchCdx5SnSoJF+RJzL6VoAlGpau6T0cawn8ZEUNTibkoHEY0VlMfjLBfHrM
         so7vPUTqY0ZHaGfaibt7baz9TtpxRyarDSKaA3+mTjHJCffJzDQqaNPvplZ2j4xnmm7z
         3l0leNECCApsSOakIjg/WeZL8KaUapXUWcyRcvxHqF0Af0wyv79FB4myV/8vgBusFZ20
         uYNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SRKfHvThVqGP/44AU56VjrE6W8xAqRccPQg2C1UDFq0=;
        b=W1XIm+aPQJRblrm/zH00I9GsKSBPzzglpp6xtD5IjWCTlw/1ix/tpASSolfOnL4/bN
         l+WauqxDUiJ89bCHj7T4wvMYXnR7fl1/Awfb6/yA5LMwu312Kh+ZVP3jefHYFWpQpwpX
         j7m+1N57bctLda0J3MiaahhXiLEjgGM0tec/U9SviDsLmV7TrVf7FpcgsCI/GSSO04tU
         fUhh7GKL7VuVO66EQz91KuHKbemz9QlVnLa/DCQaB+3SnSasihgdP9TyBAZbZEM6JZFd
         sPKk6dOFYrw77gLsj0z3rnftmI7Ui95Z6RpyPFXbH3B4j4iBPAdJY4spU0zVm3QZKU39
         DtJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bk/INExY";
       spf=pass (google.com: domain of 3_nmhygukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3_NmhYgUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SRKfHvThVqGP/44AU56VjrE6W8xAqRccPQg2C1UDFq0=;
        b=NvTkTNX4eRfE+fyvdChWwK+7vZyZNwDq1T3TRvKV88gMmxoDyA3LFf7McMPvcb5CP0
         8BxDRAiIieo/H1oLZcvyWGpExGEzDVGXmaVqBGCl09IAi8+R+7fjRaKC7SxMUeiD6LkV
         L1JKOAiapXj4Ve7vy1GBfLdkd5YdLcoAbelhU/E4ttVcUCg+P8PsPzKFkvTmYjcvPXtB
         gRqZjOAlnsz9U3Pg4iS5UYV10JUK+jB0F8ze3QctVDv2dUow4audCyrNKQpSUacJAi00
         hA1/4JsZ2uReurwsyp6JqTiKIMVz/jadbsZ81egaGquOYyPxhXoho5CWllKO+WlantZk
         1IKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SRKfHvThVqGP/44AU56VjrE6W8xAqRccPQg2C1UDFq0=;
        b=vpHgUZVhUkK3rpn2CMTgxgZ9Ll5hUxcYK3xqmrq2JUv0l69py5HBJyCuMHPvIIFf+c
         hl3N2n2UfkfA75IAyyvfPZ1gBOCDAKPk+jPe9tf3t2ZucWXzrxtg4bqrpiWOJ34Lpz07
         9quTqx70HfOE87ngRnn9UFgpOhWrV5VDAWr+Q9eQ0BSJ/0OibeOycINaUXHiMqu8wbIc
         o0HM6MQaHIDdy0MtdzOKg41iRroU6Qsj2ZFtczsD8FiOZrwanJe8YWdjP9CSIVPufC5X
         SZnl5m+uaw5+xCUYjFXJfOBCs8YjVRLO/2oHRlcImUCQ7gTATMm9dDL4ZH87v6GBgtOX
         nO2w==
X-Gm-Message-State: AOAM532q+qBmigMliow2zgHHOxLWSE0/uhvJdvsXetVXzL9ofYB7Di7O
	Lar/TEkAyXn2YduZM6hEZEo=
X-Google-Smtp-Source: ABdhPJyVmsC3NV//5oXBtBHJG+3f7eglxC/UddceOuItcqExBYyCCEuj2LTVIWYBWpKZ5716hNKM/w==
X-Received: by 2002:adf:ce03:0:b0:210:32ec:50fd with SMTP id p3-20020adfce03000000b0021032ec50fdmr37831143wrn.407.1654774270218;
        Thu, 09 Jun 2022 04:31:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6dab:0:b0:212:d9db:a98 with SMTP id u11-20020a5d6dab000000b00212d9db0a98ls989669wrs.3.gmail;
 Thu, 09 Jun 2022 04:31:09 -0700 (PDT)
X-Received: by 2002:adf:facc:0:b0:218:3d95:729b with SMTP id a12-20020adffacc000000b002183d95729bmr20821449wrs.643.1654774268884;
        Thu, 09 Jun 2022 04:31:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774268; cv=none;
        d=google.com; s=arc-20160816;
        b=RR1culUbPw3qXGnantlS6jf1tjxaoMovbjp1s5EMz9vop8CXPGp0sJm/JGeo8lPEbs
         YNgsC2IwSMF6wrWGOrszVkk9+TAoRN4J78D9W9YR5FqVFFTo/OPn/cJQ+6qfaexbZHZ8
         ZvrJLX79G5t3QXWUZ+/vYWaDsAQkH6zddFP1bGjSi/5vHK4AlcCdBiQ653Bb0EsqEQ2o
         FJCpvY6EnQBT0EaBr+vy7AvzcKWoWY1e/B8OwyN6WVxbY6JWAVE5djK2vSRimCKGwP8s
         Rax8hgldcea8Bxx7NSnhwZZRxAgh8o2gB0AXcYQzbyruHedKJJbmEwVv9VnOyjMDM18V
         5DNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=95dYiJC9IDZol3AtuiRZW/23v+t4OmpxxOGgsAq7Fsc=;
        b=tq1PDMtdtMfoNzAxbnh5Q62gB26f5fREvd17pGrCFU68hikvkH4AgpMD00JnP4GhD/
         qtKXnmnY0Vg299alFZL4OixX9+EGwZXvW0NKYebeTjLdoRBOPZHxEnHTXctvu5WA/7Qm
         L38bDytRD1+HaE+RhSEqb9nqVup1sMLxr/oCmbgYrKzvD6Gv3dqfU+DsGI25z3o6p3xF
         9QsGXurLSpvxSfQYPtvOZ1EKk1dwsa0wond0u7G/554pJTIQX3WQdy2Mdlb4zFUSJyO/
         /z3C4UWuwe9xG0yGdl5LaAV8RR3mI6bHHU2zKYmh1oS/c+KtNwQNY+eQSHULP1j5/FyP
         UV8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bk/INExY";
       spf=pass (google.com: domain of 3_nmhygukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3_NmhYgUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b0039c4aeeff11si99103wmq.3.2022.06.09.04.31.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_nmhygukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id gr1-20020a170906e2c100b006fefea3ec0aso10790563ejb.14
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:08 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:aa7:c706:0:b0:42d:c4ad:ce0a with SMTP id
 i6-20020aa7c706000000b0042dc4adce0amr45226048edq.272.1654774268320; Thu, 09
 Jun 2022 04:31:08 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:42 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-5-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 4/8] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="bk/INExY";       spf=pass
 (google.com: domain of 3_nmhygukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3_NmhYgUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Due to being a __weak function, hw_breakpoint_weight() will cause the
compiler to always emit a call to it. This generates unnecessarily bad
code (register spills etc.) for no good reason; in fact it appears in
profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:

    ...
    0.70%  [kernel]       [k] hw_breakpoint_weight
    ...

While a small percentage, no architecture defines its own
hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
which makes the fact it is currently __weak a poor choice.

Change hw_breakpoint_weight()'s definition to follow a similar protocol
to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
hw_breakpoint_weight(), we'll use it instead.

The result is that it is inlined and no longer shows up in profiles.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/hw_breakpoint.h | 1 -
 kernel/events/hw_breakpoint.c | 4 +++-
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index 78dd7035d1e5..9fa3547acd87 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -79,7 +79,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
 extern int dbg_release_bp_slot(struct perf_event *bp);
 extern int reserve_bp_slot(struct perf_event *bp);
 extern void release_bp_slot(struct perf_event *bp);
-int hw_breakpoint_weight(struct perf_event *bp);
 int arch_reserve_bp_slot(struct perf_event *bp);
 void arch_release_bp_slot(struct perf_event *bp);
 void arch_unregister_hw_breakpoint(struct perf_event *bp);
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8e939723f27d..5f40c8dfa042 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -125,10 +125,12 @@ static __init int init_breakpoint_slots(void)
 }
 #endif
 
-__weak int hw_breakpoint_weight(struct perf_event *bp)
+#ifndef hw_breakpoint_weight
+static inline int hw_breakpoint_weight(struct perf_event *bp)
 {
 	return 1;
 }
+#endif
 
 static inline enum bp_type_idx find_slot_idx(u64 bp_type)
 {
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-5-elver%40google.com.
