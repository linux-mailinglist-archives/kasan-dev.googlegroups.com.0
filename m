Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDPLWKMAMGQEAIL2W3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 666145A4C3B
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:14 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id l13-20020a2ea30d000000b00265bdf8e136sf374890lje.22
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777294; cv=pass;
        d=google.com; s=arc-20160816;
        b=MW2m07CFRe03m6aWcoZMYDAEyIGuVI5oKiJBiACjAyvHLQokmT70OYLpVLag8M0J4l
         bWrGqLzzBD9DdXYQQ830Rtj1nsJoEiaxKZifst+wZjquBpxiAIT3EqvZBb82cOTygnGr
         5hZ7YctxSjUPuLmUZ1eJ9h96S51bLev6jQ63vFD6t++KJF2fXXmvz1wJ4NjBiPpUYpR3
         yBaSgPf2lviPRJzc49YSeouJePpvneHMFQO4nXT1u9tVzwg4CqulpyHHL2htiJfTGlMu
         RD68Wi+MehxpuythiQ9X6TgAzfP8JmSKFXFowZTwvof8vbZQDiLGTbsWq+QqwddXzJhk
         dZrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=swOf0kAGtBOIhs3KJeuCBE94Q3p9FtrGctMWBGLucBY=;
        b=qQg7No7PvcbKctFy9uVVJ0v/j5rqBCpBjssCiDe8BuyytJBQJ8AwbF1GW+unlAm+fe
         aev+TMrQXkUpLprS5iADlT9ilnjVtPxyGQWuhaHQVohXmnFcVp5011GqWjtE1od//lUo
         RWbxRxUgKgAgk8pveQHb5wg6R0P5mipv1hRU1nPMUqjugTbx2DvWkS0vVo0o3I2f8gDU
         c7aX/Ug5z+lPhHEMwOpzTEXov8N+YD3vuOV8UjqqaEdn+CMyJ8GiEaFVuIuHD3mQFZ0+
         qt5zbrqTAE6rhMMUEEjpPbKaGQxnQEGyZFcEXuArqlRl4omCGIV0TkupladDBGHhTIwR
         bWjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bkzY5qKI;
       spf=pass (google.com: domain of 3jlumywukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3jLUMYwUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=swOf0kAGtBOIhs3KJeuCBE94Q3p9FtrGctMWBGLucBY=;
        b=FgZNN/jPmKLnbPXhmndF7kXiF2tk+Vu+UkKFiDK10rWL/Xy/mqygxpbNWvXKzAkdXN
         L/yu8jPSA4bHI6Oz7Ta+Zk1o3+XGBgqAP5mTieXvBsROG5dUZQ72jWFayvZYkHGbcEoC
         tU1Z+tlnlWfWdAzEJxfPY5s9xKaAX4I/gmg0KaGCNb6GEeKzNiluk/nQlvmFnBCNPZia
         74VsC8rg4i8jYQLKtQI3BAl5VwJszjJ2MYxWVjoOR0iMEibkOKLrePX07ehqWYbcN+57
         nSyN5SRHrH/FJOp0XTo58or3dbbdq1JeymuoWIboWRyWNy1zTKseAHRsbq5ZJIpXsI2j
         hfgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=swOf0kAGtBOIhs3KJeuCBE94Q3p9FtrGctMWBGLucBY=;
        b=ss0sU55LIy+FUqVQFszpuzcAKyZFj6eWaCvvNB3EAwbTr8dUBHFPA+TKFbHRNLec9q
         ptOwqPogMh2KYx2+XZNilU1qrXbk2Tkdiru4P6Gv4o2vh7ZcwaPNjf3zgP+CNmZfZyID
         BO49g9S3J1qxoj4paMz7FBMI1GuOrTkxzYoX9N/r2IvHPQSdqHXHItLsxXkMVM9IUtKU
         TILS0LV/F+AMGpirYvaCq2CKBZtjKn7fe+In0MwctOx8KQ11Qd8tWLafp/8efwCsVwF/
         FO7QkokUkPw0mE7o0QQs12aCJoi+pmHOx4Epofuty0C5Fig0xZbGyAW+pl2OjbARmkQh
         adMQ==
X-Gm-Message-State: ACgBeo15M3yBmvnVW1SCk+Po58pM5blQZCJGZ4zt//fKNbalq2gKxQPZ
	RC2G6Ysgl7reQHnPQGPCyC8=
X-Google-Smtp-Source: AA6agR4628Tnsn/eP8hq0RauMk5ULXbCjLCEVUK1RNMVVF6sybDDvlGWxHrDI902tdczqpSF9KHxmw==
X-Received: by 2002:a05:6512:b15:b0:492:ebc3:80d9 with SMTP id w21-20020a0565120b1500b00492ebc380d9mr7195977lfu.77.1661777293932;
        Mon, 29 Aug 2022 05:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3588:b0:48b:3a68:3b0 with SMTP id
 m8-20020a056512358800b0048b3a6803b0ls4737094lfr.0.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:12 -0700 (PDT)
X-Received: by 2002:a05:6512:3f85:b0:492:c17e:d566 with SMTP id x5-20020a0565123f8500b00492c17ed566mr5865741lfa.341.1661777292620;
        Mon, 29 Aug 2022 05:48:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777292; cv=none;
        d=google.com; s=arc-20160816;
        b=Vg8Ig/MlkV3AAINRJaLk7hOMeSjIJ13SnGurYfPV2B1/zi6Xy1NLPXoy7HaT89xHBy
         jDCS9JKhIExKoGxBPN6R/bm0UdqG/zYZozEFEdNA5KHVSjk8Gw6a49qMMLWYpwVFnuvP
         5rZ+Few3VfWZ/xuGGS6HwBo/V30hUCOuSZnq98Sn7dY/jLLMd9blXyGlTAIOd+d86jKC
         HvuOJatz9KxrN70it8FDazq9sA5sx1wLb+SD8wwrbaDDiED+K7gVhwJeez9MP94OnotM
         9q9DrbMp28QBalHnTFdG/hjtkQWW+FlZ3x8/+D/oH4Pn+jWHbZOShZUZ+ESI8H0QT24L
         zf6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xCb3PCmBWSP36RKUEWOlpZN7hfh85Z1tvKAaYcX0zpk=;
        b=L3UjXi0xl5lcKZCBW6MS6d0huydnYMoLpCe8MtGLHa1QdGOQfNSMr+KK+hHzhHVbcA
         JZVCUC0Bq4u8rMvFczGN6HaglNhbGyCWPEqyKOBHwL5vzFGO+TL1+6C0mogC37f2S/qN
         80ytsVjcMCtn1UpqRlpo9d7/nEz8rCsjhJnaWI5m2u0NQaWYqSw0SmSTLUKo13ZxKJou
         2/+nGz3HXVKE5jlUnAws+y8BMLY7ynCXQ52M7m/+sPSbZK0WIpy0rgs+c/DxGgaZq/+6
         aklEa/nF+ZcTBvW7VDLHwJTGV+TJZFQb4y3iaDXV/aFZD6YM+DauNHCxbcplWrpY3UQ0
         yH2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bkzY5qKI;
       spf=pass (google.com: domain of 3jlumywukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3jLUMYwUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id u1-20020a05651c130100b00261e5b01fe0si361789lja.6.2022.08.29.05.48.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jlumywukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id w19-20020a05640234d300b004482dd03feeso3419296edc.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:12 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a17:906:ef90:b0:730:9d18:17b3 with SMTP id
 ze16-20020a170906ef9000b007309d1817b3mr13769351ejb.141.1661777292013; Mon, 29
 Aug 2022 05:48:12 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:10 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-6-elver@google.com>
Subject: [PATCH v4 05/14] perf/hw_breakpoint: Mark data __ro_after_init
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
 header.i=@google.com header.s=20210112 header.b=bkzY5qKI;       spf=pass
 (google.com: domain of 3jlumywukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3jLUMYwUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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
Acked-by: Ian Rogers <irogers@google.com>
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-6-elver%40google.com.
