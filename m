Return-Path: <kasan-dev+bncBC7OBJGL2MHBB65TQ6KQMGQEZKUEWVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C62ED544A22
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:07 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id j31-20020a05600c1c1f00b0039c481c4664sf4050982wms.7
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774267; cv=pass;
        d=google.com; s=arc-20160816;
        b=UUsHZNf+esqP5vBuEjIJfXDS0OeWu6qzqxP4t3MFgVVhh/rNbWna7JUYKppLeMkzPN
         reCAPfeYF5TS/HXAHW+Nqq4o3cUEubEzYYbW1fQf+j/YfWcukzmmpQTcP0vCJJqMOqfX
         lys3tcaKINZmySKSFZDHXbecotzKHwiw4H4acWcRUyj4FUqtsBsXz69DJUrfLHMGqwCa
         F0cbJzy1IWKwhKz2jhjJlTEnfsEwWrGp3WPQGd6q/HmiDX1lFVlq8rtSpad87JwhRqkw
         zMRhc8hByCHQ6X4veQAfjx9v1T/2DAHG4P18yskdI/zlaKcH+9t/ZbQ7hO8e51ZYEu6c
         1p4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OHd0uZjOjtPVBgLM1HyJSRMPuz54K3cot3agjTjn/yk=;
        b=i/qNjGn/0gIoCi+rNltkkW2rM1w0oaOCWd+yp41PC/GGeml1RuZEdDrNwmKxOjyn/4
         TzhKDI0f+dqWnY8ITAnZhikPy+0ZNlHRDqsx3unE/l7YA8ZG5AgO5thPi22jS4zGVbG8
         gfbHC75lzN4Zmeh/u2ZpzqG63YY+vkO4s8E7Lg17r1DX53J6NSLlykP2xf999dJbhFAV
         n3eA8IP9XxPr8W213UC9FWrDdogvILl69QcAMObuy6wzl7lxBEQJZ2q3ekA+n79M7k7W
         /PQhLFAB7of0xPwGYaL5cAL4vEm1Rs+kiU4xU5QCfTWyU8uU7j1waiV+4Qk6zKBzcZgy
         I0ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LyoQ4FOM;
       spf=pass (google.com: domain of 3-dmhygukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-dmhYgUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OHd0uZjOjtPVBgLM1HyJSRMPuz54K3cot3agjTjn/yk=;
        b=iJkJd8PVfMbdTug3nQfiTvlatLL7yE2dsrX0vqKr5IQC7qeBoXBQwMAjHTnoM8N1qF
         N0l/AXx03Kew5SIOQ+fW2OD795szmyOXZ34PoTiU6KlzOD2pld97YbepJuqxRlzlIkOu
         FG7P8zZJPQ5vl+rVZvAm96Kjxw0LoSQIlULdjmWVJ1XLOSmhQXGNZSp0V0XYG996ozz6
         kZrv+0DVGM8ax0sP/wh4+t6M2qih1vZKZ/wjbwHBQpFRPSds+9ICXwwS8WCDrQiwJYn2
         L0bndp2alaEwSGfcZIIjNeAbj/v7stNnGDWWGTExMtl5+v8qXh/0Rv1hib2mTO3rHRAB
         3imw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OHd0uZjOjtPVBgLM1HyJSRMPuz54K3cot3agjTjn/yk=;
        b=kxpdyX8z08tyEK2ELp42pDBe7OlqGvxAzhoIPVwh/8kNuAfscMo21zO2s/jTKnEw+h
         rxaaA1fZcxUl//GV2rrmANr5K771btL7M0E9hxfCNbmEcWxckPpl+xCse8xviRpd0vnc
         NV3YmGgRD9lDfJhTrCTgtX4abs/4ugCobb/AsS2q5N4kA1vSuHigih0ilZ//z/+3Wt+l
         +KcLAD0Xu90QadqJq1HbUU/7NqW36Tc8LsY88Dc3/e9Or8LGTHEbjURbtvL/x8PjeQzv
         WzkRfazU9WupSFMaOXpYvtT6o5r4yfN733k0KGRHL1lx2WLz734ZhtRIpfMYJTjusvhH
         mNOw==
X-Gm-Message-State: AOAM532R8xBJWeJUp/IPjxewkjhynt7B2US0LEmYkIGo8qZR44W5U1Xz
	5WWzmfyxcZR6jUWJEUbxQb0=
X-Google-Smtp-Source: ABdhPJzXCkLjZiXC8GyjyJ2mCwshx1YaH4KK1FCFCcAbK76vN7eeczm6xpomq5DJRJ5nlIp63Qq3Qw==
X-Received: by 2002:a05:600c:4982:b0:39c:3c0d:437c with SMTP id h2-20020a05600c498200b0039c3c0d437cmr2896003wmp.38.1654774267358;
        Thu, 09 Jun 2022 04:31:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d20:b0:39c:4b30:51b4 with SMTP id
 l32-20020a05600c1d2000b0039c4b3051b4ls734910wms.3.canary-gmail; Thu, 09 Jun
 2022 04:31:06 -0700 (PDT)
X-Received: by 2002:a05:600c:3048:b0:39c:4c03:d54f with SMTP id n8-20020a05600c304800b0039c4c03d54fmr2883947wmh.89.1654774266053;
        Thu, 09 Jun 2022 04:31:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774266; cv=none;
        d=google.com; s=arc-20160816;
        b=wSBD492njgt3PbAwkbfe0BXyGTpubHFtiK/uG/baal/96FBLYe4ABkxm6tuQbk6W57
         ScoOtd8G3M0TmkOG4okYJLcDvZaHon5fE5NYbf/DgjT64Vgi61l6INMnQT8Or/XgCMPW
         BVev6Ed3rNi/vTb95ANthmD3C/dEYccn9lL4+iFt1WfpHcPDtxRr0sRCpg5HYLmFM85f
         7deIL/yKz24a5tC22vhMgUyghDrR9gXMmCR1uOAVLWTY9yt5HypaqweKRvDI60sKtjPA
         Pe7vx+X4Mi5+xda/660vc8ugeWSloZJTAHhQGOVtG9aSbPfzMUXk7U5XH/yCrIduqKev
         pB1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/f8j1JHjR27jI6H3SEM6tLzJpymbckkYBJ4SkEYwIq8=;
        b=0Pr2G47fbZtin+YS0u+A0dUg93AC6rp0oqy2SoWL52/6NpULd3xU4sV/v+xXlwZvfE
         zgSnJrVIHu+3XmNJvPh3dMEbl6u0vaxSACjb/jyKNkA1wWHCETdUTQgeRMBsKkJ6+Liu
         xMRcMfb4jBvVU/79a4VjrwCAAv/h8knuN8XnjiP27eTqaB1XSzaoJR6MGKigK+5eJqt3
         1M/eu3T2Sf3mkmV1shBvYvx7YQwqs3bew1NadxeuQ0ClyRHSW4gvn+DvLPmNUOFPzcqw
         iFbvAdT3Dy4DQ+o6MeF0jMEuIpDb04Ls53Ia5npd7e+r5HCsPRopVaS8AbJ+IUjE9D2X
         GENw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LyoQ4FOM;
       spf=pass (google.com: domain of 3-dmhygukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-dmhYgUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id y3-20020adfdf03000000b0021719593c28si581818wrl.8.2022.06.09.04.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-dmhygukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id mh24-20020a170906eb9800b0070947edf692so10022578ejb.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:06 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:a17:906:3bd9:b0:6ff:4b5:4a8f with SMTP id
 v25-20020a1709063bd900b006ff04b54a8fmr29080565ejf.139.1654774265622; Thu, 09
 Jun 2022 04:31:05 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:41 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-4-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 3/8] perf/hw_breakpoint: Optimize constant number of
 breakpoint slots
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
 header.i=@google.com header.s=20210112 header.b=LyoQ4FOM;       spf=pass
 (google.com: domain of 3-dmhygukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-dmhYgUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Optimize internal hw_breakpoint state if the architecture's number of
breakpoint slots is constant. This avoids several kmalloc() calls and
potentially unnecessary failures if the allocations fail, as well as
subtly improves code generation and cache locality.

The protocol is that if an architecture defines hw_breakpoint_slots via
the preprocessor, it must be constant and the same for all types.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/sh/include/asm/hw_breakpoint.h  |  5 +-
 arch/x86/include/asm/hw_breakpoint.h |  5 +-
 kernel/events/hw_breakpoint.c        | 92 ++++++++++++++++++----------
 3 files changed, 62 insertions(+), 40 deletions(-)

diff --git a/arch/sh/include/asm/hw_breakpoint.h b/arch/sh/include/asm/hw_breakpoint.h
index 199d17b765f2..361a0f57bdeb 100644
--- a/arch/sh/include/asm/hw_breakpoint.h
+++ b/arch/sh/include/asm/hw_breakpoint.h
@@ -48,10 +48,7 @@ struct pmu;
 /* Maximum number of UBC channels */
 #define HBP_NUM		2
 
-static inline int hw_breakpoint_slots(int type)
-{
-	return HBP_NUM;
-}
+#define hw_breakpoint_slots(type) (HBP_NUM)
 
 /* arch/sh/kernel/hw_breakpoint.c */
 extern int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw);
diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index a1f0e90d0818..0bc931cd0698 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -44,10 +44,7 @@ struct arch_hw_breakpoint {
 /* Total number of available HW breakpoint registers */
 #define HBP_NUM 4
 
-static inline int hw_breakpoint_slots(int type)
-{
-	return HBP_NUM;
-}
+#define hw_breakpoint_slots(type) (HBP_NUM)
 
 struct perf_event_attr;
 struct perf_event;
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 1f718745d569..8e939723f27d 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -41,13 +41,16 @@ struct bp_cpuinfo {
 	/* Number of pinned cpu breakpoints in a cpu */
 	unsigned int	cpu_pinned;
 	/* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
+#ifdef hw_breakpoint_slots
+	unsigned int	tsk_pinned[hw_breakpoint_slots(0)];
+#else
 	unsigned int	*tsk_pinned;
+#endif
 	/* Number of non-pinned cpu/task breakpoints in a cpu */
 	unsigned int	flexible; /* XXX: placeholder, see fetch_this_slot() */
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
-static int nr_slots[TYPE_MAX] __ro_after_init;
 
 static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 {
@@ -74,6 +77,54 @@ struct bp_busy_slots {
 /* Serialize accesses to the above constraints */
 static DEFINE_MUTEX(nr_bp_mutex);
 
+#ifdef hw_breakpoint_slots
+/*
+ * Number of breakpoint slots is constant, and the same for all types.
+ */
+static_assert(hw_breakpoint_slots(TYPE_INST) == hw_breakpoint_slots(TYPE_DATA));
+static inline int hw_breakpoint_slots_cached(int type)	{ return hw_breakpoint_slots(type); }
+static inline int init_breakpoint_slots(void)		{ return 0; }
+#else
+/*
+ * Dynamic number of breakpoint slots.
+ */
+static int __nr_bp_slots[TYPE_MAX] __ro_after_init;
+
+static inline int hw_breakpoint_slots_cached(int type)
+{
+	return __nr_bp_slots[type];
+}
+
+static __init int init_breakpoint_slots(void)
+{
+	int i, cpu, err_cpu;
+
+	for (i = 0; i < TYPE_MAX; i++)
+		__nr_bp_slots[i] = hw_breakpoint_slots(i);
+
+	for_each_possible_cpu(cpu) {
+		for (i = 0; i < TYPE_MAX; i++) {
+			struct bp_cpuinfo *info = get_bp_info(cpu, i);
+
+			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(int), GFP_KERNEL);
+			if (!info->tsk_pinned)
+				goto err;
+		}
+	}
+
+	return 0;
+err:
+	for_each_possible_cpu(err_cpu) {
+		for (i = 0; i < TYPE_MAX; i++)
+			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
+		if (err_cpu == cpu)
+			break;
+	}
+
+	return -ENOMEM;
+}
+#endif
+
 __weak int hw_breakpoint_weight(struct perf_event *bp)
 {
 	return 1;
@@ -96,7 +147,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int i;
 
-	for (i = nr_slots[type] - 1; i >= 0; i--) {
+	for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
 		if (tsk_pinned[i] > 0)
 			return i + 1;
 	}
@@ -313,7 +364,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	fetch_this_slot(&slots, weight);
 
 	/* Flexible counters need to keep at least one slot */
-	if (slots.pinned + (!!slots.flexible) > nr_slots[type])
+	if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
 		return -ENOSPC;
 
 	ret = arch_reserve_bp_slot(bp);
@@ -688,42 +739,19 @@ static struct pmu perf_breakpoint = {
 
 int __init init_hw_breakpoint(void)
 {
-	int cpu, err_cpu;
-	int i, ret;
-
-	for (i = 0; i < TYPE_MAX; i++)
-		nr_slots[i] = hw_breakpoint_slots(i);
-
-	for_each_possible_cpu(cpu) {
-		for (i = 0; i < TYPE_MAX; i++) {
-			struct bp_cpuinfo *info = get_bp_info(cpu, i);
-
-			info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
-							GFP_KERNEL);
-			if (!info->tsk_pinned) {
-				ret = -ENOMEM;
-				goto err;
-			}
-		}
-	}
+	int ret;
 
 	ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
 	if (ret)
-		goto err;
+		return ret;
+
+	ret = init_breakpoint_slots();
+	if (ret)
+		return ret;
 
 	constraints_initialized = true;
 
 	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
 
 	return register_die_notifier(&hw_breakpoint_exceptions_nb);
-
-err:
-	for_each_possible_cpu(err_cpu) {
-		for (i = 0; i < TYPE_MAX; i++)
-			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
-		if (err_cpu == cpu)
-			break;
-	}
-
-	return ret;
 }
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-4-elver%40google.com.
