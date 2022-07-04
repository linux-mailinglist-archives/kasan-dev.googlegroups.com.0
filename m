Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZMDRSLAMGQEIC7LOTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D98656593A
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:14 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id i184-20020a1c3bc1000000b003a026f48333sf4192587wma.4
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947174; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7A5fkkp72V8lpyoxXObCfQ4PsAvEWjzKOxrw2y2k1FkHgGY9T1cNq0m9xtyBxZegk
         oGmBXhMdBrIH+raMdYFM+FST5W+oBYfTlPGAEOnDVxCILYPPZskjmBTyHU1LYeLYW/sZ
         8qit73FuVV9xyARNkOjS4/1SkJhKU8ut1FtLvuESprdBCtlRc3cZeYBmTWGSx3ryxG70
         mqU4vMID2SENqB9MMBLrIqDjowjrwCfhQ+tNn8LBEBivXMGSCs2kfs7Lw6CxBBCO4tqX
         Tu4HcS5IHZSkpUVfQJEpveFWxcD3XiIDbAErN/b2o5wvzeSLHFECt41vy0lXemkKYcM8
         91mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=i0+G4FM6ohEqROLHC6zEiS2EUNye3mQB5b3sAGlGnqU=;
        b=mq4Gf+ZtKeuCiDUfEThlBQR44xYvYklJgyR2XbCmxgVTyQ+sMd63gSnA3USHKo9Ypm
         GMvi3109VcSsEs0bEH+frJPshS0q+yPeGD1rj+i+1Z9PPoQ1P8EfGS88wMtm8hxMo2K6
         kUdVtLmZgnEfZpfk4i73OIYDvw6W/LGNudA22+yYdsjm25Wd/HXJI4DlajL25CxlAoYd
         RTEz/rETS0DfYgyK19I5xdFNZEsNk/cEX8/+Bt2JyE3Qjwb+9Btu3DysEYIgb6DSheE1
         yaDjDq9I0PzF1/9CVWDFmOd6TDqZSSNAhvY2524jYqr1o+VgNK60hNVZEqqvQuJ7hUHy
         ztsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RwcvwrqX;
       spf=pass (google.com: domain of 35ahdygukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=35AHDYgUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i0+G4FM6ohEqROLHC6zEiS2EUNye3mQB5b3sAGlGnqU=;
        b=rWJYjgRs7tfx3y17Nwe5Qx9+XXQ2uxKZwx2LqYtupC5qURliYwuL1Gxo3zO9tHxYEn
         lc/tZfwJb2jJf7dQqLt6297wsoYXSkDYuSdj0CFfgxobANWZstMS94DfSgj/G4KwuTbp
         dO176IxNTCirZvrww7SVOM8Zra/L2PcKDYd2MmBK8mNkyuvP9lVeO7f7/PBZ82/CxQqP
         cgAKIGOaD8M8eD4XWhwxfQNEdadONH5LermbEoD4mtu5wfOMbih4Xhf8wK/tgeluza06
         PHQC8mKGBnx22SXlpptPif7WkCzNOLLRIERd7U59koSVsIuG84E8jGsMxMZOtCPqf/Wx
         GLXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i0+G4FM6ohEqROLHC6zEiS2EUNye3mQB5b3sAGlGnqU=;
        b=RxxRCBFw1nIJBzLTXrJqsL1dbsE6rSzn8+vCcnuY7NRZPaoc5FnihK6q6GYdYjIfU2
         N/2GHsh3f41e14R2rKdPF8tgVX+R0iMyYeBylZwX/jCfnCww7nHjUbqAO9mumbqGuCwz
         cShzIUxHBUGNVjf0RppKaicQRAIpwdOX9IAUffsWjb5FgceOs09cb2SlGRHa6L6p5Hn9
         +3a0YdqoAJvEbM2qZ3KUPznSdK/QKPtLRsH8MdyL23opY5BFpq58cdg1dXqFiAn/UtYx
         9GVu02E/aMOX30HWh5TI8tvXcE3LCP9rnb5wGbkMzaYTMN6qY13yMEf1l4T1iBBoFcY0
         szow==
X-Gm-Message-State: AJIora/t7gG3A5VhKEXCMFRIvgTt+7f6dfKU4NnnDYgpBtZX2awNLJog
	TLMNYcrVQsXAVupgK7ypUg0=
X-Google-Smtp-Source: AGRyM1ttKW/NPEDvOFQr1yIB1i4i19/bq0yoTsgQ7CxXAOsh/bA/7uHpa22a9G3oyzAGUI570vXVaQ==
X-Received: by 2002:a05:600c:4f85:b0:3a1:a8e7:232a with SMTP id n5-20020a05600c4f8500b003a1a8e7232amr6730317wmq.158.1656947174073;
        Mon, 04 Jul 2022 08:06:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls22992228wri.1.gmail; Mon, 04 Jul 2022
 08:06:12 -0700 (PDT)
X-Received: by 2002:adf:e40e:0:b0:21d:6de7:e787 with SMTP id g14-20020adfe40e000000b0021d6de7e787mr2296476wrm.488.1656947172876;
        Mon, 04 Jul 2022 08:06:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947172; cv=none;
        d=google.com; s=arc-20160816;
        b=NIOmSZ3zHNrVxxSYGpRHBzpuZ8S3z4GmJLQ5cJ6XfbJse/4onFMr2Ow0i4IpAe0a3i
         0LPNDMQ477OxorM0+D0s1rIE4F+/wge39oak4mrIIg8FGTClIm7aibe6n6szj1LQ/Z/u
         u4euxavNoSbIutPm9AIAEUl4wTUUiOH3hQIIhazVLlB8Mh0UTRVYrta0admYrBfgoobh
         WX8pLcXlW7lRUQAtPcd48t5yrt2yf+YvcneIa/kmHf3QK1m3JxqGDsTuL6BknfJvuvyt
         HTHC2XLU2xnvZ3ifyOx9Oc9osZ725VPxd4iobbXd8zbFaw36YO+hojLSIH1Pg6Pox17t
         4Ayw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=YlRTKvNx8tiz4oSdBAerktmQbu3PRvQhLNbba30Undg=;
        b=M4hLNKk4p8b7yHkEekwqMbhJzM2eGHPLwaSHwnZ7156UkgWFz/wy0hJqHPEOauj1YC
         lGjaNOg926Q/B3IpGFLffX1c7fo5D+hvH62pMKX9UP/aIcSjYhsNUvJGd0cRTxE8OxI6
         +CsSVA6X3cxg0n5OVvwWNSdtXaZP7UwsS4mwKBkqxiNbxnkhrjERAZLhqDpn+eaOraY8
         +t2ZiiFO4AMI+Jq36xgeWvcjOsXHfSH11QSE0zx+1hblBK/6OQqioa2wAbNBN+XSJVil
         JI5nxUfu6PRyNwt6/1erW9axqplBUIFgzgAfvpcdB0B+ealE0dmFoO/+pAUR3M+z9bPK
         SxaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RwcvwrqX;
       spf=pass (google.com: domain of 35ahdygukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=35AHDYgUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b003a04819672csi714048wmb.0.2022.07.04.08.06.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35ahdygukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id b7-20020a056402350700b00435bd1c4523so7359855edd.5
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:12 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a17:907:97c9:b0:726:b4f8:f675 with SMTP id
 js9-20020a17090797c900b00726b4f8f675mr29337299ejc.427.1656947172380; Mon, 04
 Jul 2022 08:06:12 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:06 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-7-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 06/14] perf/hw_breakpoint: Optimize constant number of
 breakpoint slots
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RwcvwrqX;       spf=pass
 (google.com: domain of 35ahdygukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=35AHDYgUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 arch/sh/include/asm/hw_breakpoint.h  |  5 +-
 arch/x86/include/asm/hw_breakpoint.h |  5 +-
 kernel/events/hw_breakpoint.c        | 94 ++++++++++++++++++----------
 3 files changed, 63 insertions(+), 41 deletions(-)

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
index 7df46b276452..9fb66d358d81 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -40,13 +40,16 @@ struct bp_cpuinfo {
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
@@ -73,6 +76,54 @@ struct bp_busy_slots {
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
@@ -95,7 +146,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int i;
 
-	for (i = nr_slots[type] - 1; i >= 0; i--) {
+	for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
 		if (tsk_pinned[i] > 0)
 			return i + 1;
 	}
@@ -312,7 +363,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	fetch_this_slot(&slots, weight);
 
 	/* Flexible counters need to keep at least one slot */
-	if (slots.pinned + (!!slots.flexible) > nr_slots[type])
+	if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
 		return -ENOSPC;
 
 	ret = arch_reserve_bp_slot(bp);
@@ -632,7 +683,7 @@ bool hw_breakpoint_is_used(void)
 			if (info->cpu_pinned)
 				return true;
 
-			for (int slot = 0; slot < nr_slots[type]; ++slot) {
+			for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
 				if (info->tsk_pinned[slot])
 					return true;
 			}
@@ -716,42 +767,19 @@ static struct pmu perf_breakpoint = {
 
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-7-elver%40google.com.
