Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEHLWKMAMGQEYFANTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 45C7B5A4C3E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:22 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id nb19-20020a1709071c9300b0074151953770sf1223550ejc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777297; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ek5PaormoIPeaQA5n8yWc28zihtvO3rEkMD28ZrQezdka5IILGEz1wmseiB2MDv2Qm
         ZnqlhGpdB37M/Hgvxpmv4WCya0mIhAPiQ3vgIesQIZyn3i5TbCeJKXvY8eINuE5oPYxI
         dPBggXQwREkLRWhytLGvG3/l3dF7EacPourjZIBxhzdBBxcQNvPDkfjHnXjSb5J8Q9EQ
         oqDYFd5mCXNH2Aoq5g0/wBEHk50QCDlzdiE+9C+wxTPM3u+ac7pciBDQrwGwGMKq5feP
         wSz0cEocC4gkjs7P6r9+6UZeA3jWOXnIBVftwC/S+gyPhKLC2fHkKGuLgAO8Xms6acpK
         RHLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dkvcjhVX0OenHFAPmgKU4Ii44fK5p+t5rncDvZTNxME=;
        b=ODUZ3B18OtUW0OUykBL1IGcRt2QKRRKd1AZekCWqv/tXBHhuC9UHSAeRGX70NI+DJe
         Zu09fnSi+tOzd/WDic12cYjXPUdorTw+4O3ffPZ0rrBwBTpALz3dgzGeu/EoWX8ZnzBb
         d3XQ/n0iNFE9TxeLQJP/D3GxP5HxPr1fRstcMKYUwXeIswgNBm4q/X1mcHwP53kmcysc
         JrAxke2TAL0gt38vwSoT4ncRO2/mE1wJl0DKS9Q2GpUrdBaVDdqaJLB2nnh877OogY3p
         SC7LUO7nbjIgnoFtpiGK83N4aMib5nsanY5nMpso28a+niQZLAk82Ob1p+a3Wy37negL
         K7DQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d6tp/6qX";
       spf=pass (google.com: domain of 3jrumywukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3jrUMYwUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=dkvcjhVX0OenHFAPmgKU4Ii44fK5p+t5rncDvZTNxME=;
        b=H41xNY3ckSUjYljxvY7YYxb+kNzrpNaJ2Z3zsCF4pUbpgeej5RLAN5JzSgb82n9R79
         Uf9qCXmpRP3PlCfBmy2PfuEhy2LRmsONuMyPdNxdNGVstVGfWkThQGDTUk6iMlRVJX9P
         mZBQJyE6th6um6A4fi5dLe6v9ha5HNrFq3hBukEPsA1B5ZcDlWFVc3gCpv+4XeVwmxFn
         NzdADomxTLNUX0WziEjmZ6fkGZyQsaTO+yPcdAhWU3cRHokWtB6pWcijIxyRJlCtbnf3
         6WrINnUnbSm/6XjiFoGaTDflS5SBJLsitxDKekAqVEtdXVhexd7VyITvEd/qjIpMpp0X
         3ivQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=dkvcjhVX0OenHFAPmgKU4Ii44fK5p+t5rncDvZTNxME=;
        b=ivwW+/7D4BSX3v8UDZVhdELCCWsLB/443O+GhyRvLwkonkLN7iCfi2/FnKBDqwxzHf
         vl95YUXgpguSvQzHEkZ+rYqk0Knik4u3WEWBzMYSPrumI7Sp+EQteVavSoehzgQMrPNi
         MY/MNaqwC570xX/nZmLQJ3npDiFOfz5a/UU6IGOKBdE8vOmoSrhjdNq+va6V9cDLmSBj
         KTxVKZjG+DHWc2jkwrsg/gE2c3GNvTbkma3/pBaErbQDzuGu1Q9iGWzLzFilqL8L+nHS
         LRA9MMNEQPRtuQiojDJLhIkHUIwGLeMvpQaykNS06LM7HoZ+eL0ZrK2KCkA+P4hsU2Lf
         egbw==
X-Gm-Message-State: ACgBeo3BHHW50LrElQu2a0G2+SFhZHFcTi41FouwxkqoB+Y3mUMby9d1
	Tz0vvOlSrutCaVO9wpbJEDY=
X-Google-Smtp-Source: AA6agR6ekPBYohZf37cEMgBdnua8PlVw9gEg9GFwvdmj76jtTtUFAVEa7j0fCWgPqE9J/u8se0+Bug==
X-Received: by 2002:a17:907:9607:b0:741:7926:a64c with SMTP id gb7-20020a170907960700b007417926a64cmr4301320ejc.718.1661777296729;
        Mon, 29 Aug 2022 05:48:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4303:b0:448:5d46:86b6 with SMTP id
 m3-20020a056402430300b004485d4686b6ls3540343edc.1.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:15 -0700 (PDT)
X-Received: by 2002:a05:6402:5202:b0:448:ab5d:3b89 with SMTP id s2-20020a056402520200b00448ab5d3b89mr503862edd.343.1661777295350;
        Mon, 29 Aug 2022 05:48:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777295; cv=none;
        d=google.com; s=arc-20160816;
        b=g+PM4SjFEV6ozQYodwX8Ac5A66n129NC9z+Hf/ZgtAIdKe4HsYliwtVX3KIayzQ41Z
         C0iGfI3IMrsRT/xf3x6+ZFtxTgj3BMMXiVlcZGkyQn3rZjU6E+LVpTZtJVh5MjKcKk8L
         uE/REG7qS573vHBNVZTWmKnRNivy30UjBwVT/igxncCLm8VsAhRKIQqrj89lWzbjd6ti
         wZ6/5ufyA0qZON+iEqMxHcduwXJZGF40fND6Sr/ku9/bXsuIJ/lPQcbqSD8PIzjpNduO
         crOyEnqgEH2cPY1j6s8rX/TcXIZF7xsKsKDfomn+liJRqvf2Jic3lVRuI6/HZNoA5sLI
         5Q4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NAgg+axkJ/HbuBi/N/cfy43ZzHoR1EkHXaJqULg0eJ8=;
        b=K6Fao9P0OPbWTNvA5uqI5qbgRb5evtiSxf02GNr8d2OTn/14ySI9z+HwkB551l41IC
         GLBIDdCJzCnXfPdPBeYzLOMu8ubeP2tGRlB5d5M8R40/2DDAgHaOJnJDpoC3NzPVQeRI
         TcrZ5L2lSZoQE1xjINtCh3aqz3VaYpxKMVX3WFRiZqexDDOa8RRIcfnqyHe1k10Isdko
         2Cl4ZeR2jexcCM/smvSpnZs+ZduCArfhdWt0qS0AAxZ569a6vyeHeyc7qOMldStkBlmY
         jyXpFfJ1w2C1Taf41Rm6+KuiqudIpIv1Udv8DYTmLJ7Uy04G6/IhSokSD2fJlyDsBTwV
         fajw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d6tp/6qX";
       spf=pass (google.com: domain of 3jrumywukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3jrUMYwUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id g13-20020aa7c84d000000b0044609bb9ed0si278300edt.1.2022.08.29.05.48.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jrumywukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id m1-20020a2eb6c1000000b00261e5aa37feso1872485ljo.6
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:15 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a05:6512:3b10:b0:494:6105:1f62 with SMTP id
 f16-20020a0565123b1000b0049461051f62mr3032181lfv.172.1661777294789; Mon, 29
 Aug 2022 05:48:14 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:11 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-7-elver@google.com>
Subject: [PATCH v4 06/14] perf/hw_breakpoint: Optimize constant number of
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
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="d6tp/6qX";       spf=pass
 (google.com: domain of 3jrumywukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3jrUMYwUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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
Acked-by: Ian Rogers <irogers@google.com>
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-7-elver%40google.com.
