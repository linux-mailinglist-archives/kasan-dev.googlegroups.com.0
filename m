Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY4DRSLAMGQEIP47ZEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D91D0565939
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:11 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id az40-20020a05600c602800b003a048edf007sf4194380wmb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947171; cv=pass;
        d=google.com; s=arc-20160816;
        b=OL24diO2A2KVdoh8zLJYryydPm12WL4cSPO+8NUP7zCYtrFygUA/N9Vrm7l4A5Rck/
         vw9Y6RP9ik8owG67z+OPCy91zNAla2I84ayI8koHvg10rtZT/VO9wnP9HFXoA4LzWQSJ
         JyuqKubU7NCdSP9CcUbFPW+xWDRfiHBtOH02Jfncr/+zZe/lNRbVQC6MNkVc4qtHpYEc
         5e+jkXa9k+tWhaOvWQ8gFa2DwwVDMc1raawCCubGgRQErOJAU0kHrRxSDb6eJUEwSJwy
         fSzuLVuVsJKu6mTEBVrWYVcmdyO2mX6nmPjlzBy4TAuF/LkIrxDfgXX6dkAXinHgDaoF
         jvmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=I8MZcAIE1jZoMKRdYu1tsNaspI/3MGHC8vGf+MqvdM8=;
        b=j49HD7XU+uAcKFu98GAwiTEjP3JmOYKocQRypOVmKviQIw9kxwTPkBvwLKoEW1cxvI
         16HKFOKFND9y5eWcZdlU+p3YJ+WsRXm/q+vu+QkTFC361yt3hV953S1hIzhyzan+FBqU
         VqiUYqtkVxaN6q7OMjXXe6q6hBFSan93GSSdCNzTTwupSm8Z1TWbXzirSZxmhs0tSGeG
         F6l3XDxmQnSc0haJXZeW+Auhf9USDmWetTqgjb7ZEn3gwUiU05olV3PPieonSJlNoMZ9
         E4Mr60RI2X8OcAo99vHog4YRb+8/1U3uMKpVjslgoDdaQKB/+ks7PLYwdsL4VxjpV1PZ
         NZOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="o4x3EbC/";
       spf=pass (google.com: domain of 34qhdygukcq4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34QHDYgUKCQ4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I8MZcAIE1jZoMKRdYu1tsNaspI/3MGHC8vGf+MqvdM8=;
        b=N5KGc+FBqPotg1zCCbYlySA5FIbo3FEXYeDlxDvvMv01CpCiCTrXyL5S6PBFpNnIpk
         Ho1TdzhdZymWsPu+4LxdCcaqmgfQnknlk7aaRpBF/wx4730cmDohJccIhyI525qvlWR0
         AhhzXFBQwxMbWkN4/5/Jxa5qkrdDmR6j+pSk8A0gqV+yWaWyvwl0pI/tJmmc7OkRZT/C
         DoSuWHc/WQ6H3jQ9PGi27LLn7w0KpzIydEyWPGEA/luaMrLMUI2YirIVSjNsd491+Sns
         3oauP9QhzlCAqS+vN4a85kAyOY9QiQnesp9AB0TEEv5Cfu9HXDZkCtdXMrZE+Kdtaqed
         ApLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I8MZcAIE1jZoMKRdYu1tsNaspI/3MGHC8vGf+MqvdM8=;
        b=Yrq22v754+/UNRm27vMnN/zqNvaT8vHkBmqK1Q2aM5HoijSC0WAW7OHgp5xlUPeqOj
         MwwxcxsWsM38Y8v5wtez00UMhIYbmK3pBT/TBz3dXdCJPf9/ssBJsX/0YtU9J5H9cdgD
         MiLBXKHmBDt8CQ7e8589JmvVxCxO/DruVDpOeFhg+BODGCEM2IqI541bqfYkgv4CHTj9
         3tcn5ZTU4UQDTw6wr4eUaKOpbcDyABwOIf5ZrDPmr7bp8RXn1JHi1/iYlKcf83/iQno2
         Kq2O4hHnnitqI5Ea5bfTq5nZcV6BmCuPAe92R3Zv8Kl11eJorkcopAgTqn/UxkVyXqIp
         sMbg==
X-Gm-Message-State: AJIora+9xy425itcACvyvSEDcDTXO/djTqvDzpInsGZ3n7eFX75pw3CB
	eDtDyCvdfg5LgHTIFnFnAgI=
X-Google-Smtp-Source: AGRyM1tnh1unvC+MImnIOTVSZh+bnYGjnz6kWveowZWSrRc6Ep7rwh6zQdtJ+SthUsIB2Uds/2K2bw==
X-Received: by 2002:adf:dc0d:0:b0:21d:ea5:710f with SMTP id t13-20020adfdc0d000000b0021d0ea5710fmr27493152wri.48.1656947171258;
        Mon, 04 Jul 2022 08:06:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls23026551wrz.3.gmail; Mon, 04 Jul 2022
 08:06:10 -0700 (PDT)
X-Received: by 2002:a5d:4e03:0:b0:21d:6d7b:e9b8 with SMTP id p3-20020a5d4e03000000b0021d6d7be9b8mr3084418wrt.259.1656947170064;
        Mon, 04 Jul 2022 08:06:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947170; cv=none;
        d=google.com; s=arc-20160816;
        b=OAbsugfmh6CUIfZ3y059EPPTnopJYffQpN/Fq+D7dFh4ujbuZZ4PSFxLvyUDwokNhM
         BfYOQuP9lp+xGt2T/RPNUxcx00gbQFoMgq21x0Kiscs7YsVLEsWC4eCdnwlTb/UByAgw
         iOGkeTM7iOut+PT3Vt3Ihgsc00bNBJ56dV/6Hr3FiChPVI8oNm5fTALhcNOZQ1tWcBBu
         hwYww9k3SURfHQ43SwKdv+3R7yVqAakh0mmvoy27cHPGZdHkteq7RmLv2lLrWDCOFM1D
         0C27s/HR/odduIr9tcZbp1FUEcCgbGpity8Z0+wDqaVoA7wS9AJnMWWG2zDQF3PR/AGj
         4fbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mWoq8j7y43ZVuqvviGPucxALD5XppzdZ4sJTYXDQo5I=;
        b=oxMQjC1d/NVRE034UbbUNWvYW1bLVI9kzXHpLMVnWNgF3bQqBTkFalpBObzirAXGJQ
         R1jawAmSVPf4+lb+Sb+WoUvIs0/sU2hWj8MzxcrGln9WsfUCbsXLVaAmo6DvdeOtyjg+
         yzLE47DWdPZStj19etnjMGeR76x7LvSwJO9+TbjCOMJqStG5A95IBL41u9lQ/1OPvOrv
         UUsKpR8SuAU8knSkO8MOxcLRfGcPRmQLyoosAblO/xs6MfU10Wr8d4tku+t4+P/a11j9
         Tl/5HQpIftkpQqHPmDffVZ7slYwFaX5zIsklZ586Vi32ZeeCojhKsrAk3kJefMBLIN2D
         n9WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="o4x3EbC/";
       spf=pass (google.com: domain of 34qhdygukcq4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34QHDYgUKCQ4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ay11-20020a05600c1e0b00b0039c4133ae38si724808wmb.2.2022.07.04.08.06.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34qhdygukcq4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m7-20020a05600c3b0700b003a1994306e5so1324983wms.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:10 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a5d:47aa:0:b0:21b:ad9a:d48c with SMTP id
 10-20020a5d47aa000000b0021bad9ad48cmr29662846wrb.610.1656947169805; Mon, 04
 Jul 2022 08:06:09 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:05 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-6-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 05/14] perf/hw_breakpoint: Mark data __ro_after_init
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
 header.i=@google.com header.s=20210112 header.b="o4x3EbC/";       spf=pass
 (google.com: domain of 34qhdygukcq4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34QHDYgUKCQ4sz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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

Mark read-only data after initialization as __ro_after_init.

While we are here, turn 'constraints_initialized' into a bool.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 kernel/events/hw_breakpoint.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 6d09edc80d19..7df46b276452 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -46,7 +46,7 @@ struct bp_cpuinfo {
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
-static int nr_slots[TYPE_MAX];
+static int nr_slots[TYPE_MAX] __ro_after_init;
 
 static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 {
@@ -62,7 +62,7 @@ static const struct rhashtable_params task_bps_ht_params = {
 	.automatic_shrinking = true,
 };
 
-static int constraints_initialized;
+static bool constraints_initialized __ro_after_init;
 
 /* Gather the number of total pinned and un-pinned bp in a cpuset */
 struct bp_busy_slots {
@@ -739,7 +739,7 @@ int __init init_hw_breakpoint(void)
 	if (ret)
 		goto err;
 
-	constraints_initialized = 1;
+	constraints_initialized = true;
 
 	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-6-elver%40google.com.
