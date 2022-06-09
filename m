Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FTQ6KQMGQEIL6CQPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 58746544A21
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:06 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id b12-20020a2ebc0c000000b0025662e0a527sf979634ljf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774265; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDzEVoYAx8+lbG4bKv2X7W+lGkImMFBaH26mbrer9VwDDM8fWDHZhcpqGe1dBWMcWI
         00eHVBPjjW9aVE125eDz4JCYoEqLMtqzTA/vU8ALzMHmXD5WhV9SSK09sMJT984OaxyP
         XdbtvpfqMdT9ipfZUS308pR/jfgaiebW/nn5ikrPfJ3XYlAvyiFkgaBivWrnRpndmECv
         xaH2nDd9BC1fFE/jTCAV1WTfYo6cpNPMTjZooeTtzb47ehJAzKeTL5x8TGOyhYS+wSG1
         auGRd2j+rdUI79W1kIUsDg/xKT0ch0UbNTT/GWpkpqgLekB+DqDkIJiL9VCxxtb/grPk
         Lglg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=i4lTFPGP9vhGrEIvUQ5ZS4kQBsDmmiCHd2WVygPN5M0=;
        b=i9/MFGPG+FEtB7oEXbVa4TKM9qbQyi/1TfvurcL3xJYDGpUPZMc0k2kbSpg9LKDIkh
         DHMqdgvBRkOU4+PmEbAv3SlPa9FM9yb6dxP0Mh9QQHcePnQiIUpRFO96oS0NOumu/Vrz
         mD5rm/UXccrYQF9/15+7mWIzZd/NOLUXcBd7bwKZv6EQ7eTGhZKBNrKaFU5OX1r8oRSw
         MRba6rsqoTPQ23KJ1m7KHXE1US42m6SHot2Q4AZ5B8dW7rs9bkleTHM7osnox8ScOjhV
         ZJVOUuYtwA9556xNjSuDpIUjsbX7Ly/b5olwwn9NrT7JezgiJUCqs1j0HH+O/cjyWetk
         KcFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WkMVlpXn;
       spf=pass (google.com: domain of 39tmhygukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39tmhYgUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4lTFPGP9vhGrEIvUQ5ZS4kQBsDmmiCHd2WVygPN5M0=;
        b=K37449gv9dPP6o9iqiofgxlIYHT5GIbRZ0r5NjbYj/7XUgdxUhWq3BUOY5T2INFALr
         i0i+7mO4GJny4KqQLnS9orm5PL1GDmNXE81w0RpeKJ5N/v3SPx3HPAhGJpp6LspH4NY9
         K3JrHHzsbN6uwZIRl5qf285Kg8+hYRirTLw/jl6vyMkl0ThsoP5y4vXiDznl6dhG71P1
         UId/Nd54hCqPTbDCIb+yfhlGDO2eiI4nS+XTZpuzAM85NONr8kOFSw+vbwSNs2hoSDzu
         mPbAQsSVGZiX4CJ31xqkXjxhDxdc7sPTMzC/3pbmuVaI+zHYO8QdBLrnoAbRdMOczkGJ
         hsRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4lTFPGP9vhGrEIvUQ5ZS4kQBsDmmiCHd2WVygPN5M0=;
        b=mwYRbFEcc8fjDydQ7r3yxA/SxYBuHI134+iWEU6rvjABtJksCeW8mJuXC1JJET+0MS
         nDf4gV6Oge/lg/RxP1L+1j64SfVnpK9o3U71P0SzsS9DHM0VTJaZvFnWH7X7yisunYCV
         9oL21zo2Z/jixRjUAw5cGJggoW8LXm0j6ZtdGRNxogdreIIjFslGBKr1wbsfNyiYB/yf
         E5xm9WNZGsv0pPA/Z/jEOMDm9fqJK/V2TBwgWj4EnjcpjnIzJ4h81Y5M4ucSiJqDE2vC
         7KCx3ehhsMVYbfLHnkgGrsr7jVAo/ZhtISEBQr9npboAKyx618xfDdNmI7SCylcs3AfW
         ElTQ==
X-Gm-Message-State: AOAM5300CXzAsh+inoR7XaxvDZwEPhs7gwpve7o3HKPl8lsi8JkeuIEa
	y0KmuYY1E/DsBa5zHMNr5TA=
X-Google-Smtp-Source: ABdhPJzyPJLTRSoW280ncEpTQQSRdwbE4TgDddw18IH07YYZMSmFivXaaHMl/hp8LBgjCPRVzRr79A==
X-Received: by 2002:a05:6512:3d8b:b0:479:45ed:d1e8 with SMTP id k11-20020a0565123d8b00b0047945edd1e8mr13611031lfv.610.1654774265077;
        Thu, 09 Jun 2022 04:31:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls3322247lfb.1.gmail; Thu, 09 Jun 2022
 04:31:03 -0700 (PDT)
X-Received: by 2002:ac2:5a0f:0:b0:478:ee47:a9d with SMTP id q15-20020ac25a0f000000b00478ee470a9dmr25122282lfn.418.1654774263496;
        Thu, 09 Jun 2022 04:31:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774263; cv=none;
        d=google.com; s=arc-20160816;
        b=kL7+52drvnWd7ZfXVt5rz6rEzorSWC2xY4mcPuAwoLd7nffHiS4bXeiIITznVw4mOz
         g6wZCZJGNbk2b4dFtCMX6h/6PuVteuPzPRsKWFmp7lAZrEfL004Ro5gGunRZmPaavXW0
         vZ+TSfv6Pm+HYBcg9UHikbeIp95BLidVFZvuXAEgKGMGpTZTlpTo9MEdnB7Giw3KTy/n
         4lsWaNKRZAmdxvd3XYqYynm9ywSIqL3+yeaTMSqWHGWdf0YLii+3KQjw/kTL/uvw7RJb
         mxWfWRTKqykKP1QTLeITkMzoNtt7lq6akDMfboMDwHMOAUyAiXX1twB+/9eF89wvtHMv
         gUyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=wnAKNm59aHUnnDDyhy7DQsgawVHUm92RhZIM8y499GE=;
        b=obVpMWTpWWcfjn9WfVI0TgmtzM9DNI7sCbHghEy/J1Ypro+AnddWBGOwrP2t3ZYa74
         2Gf17wQn6iVRq1CwkDXVvZCUjsPVnEcd4OsdCFRXyViq2BmDtIaMGT796Lf5f1hue4qY
         w+uEwQqtyjNg6+hrkkwYeRMCFgW7WX7VUCpPSkNFhDJeG/Bd2Xm9jQVyW3axrn1U+un3
         047IDW2bUINPXRoZgOH2ifFpgIeHH6ARN1JSm+ReIdzi3ue9NQh8b3UGUmWhqq1F2Ce5
         0hAa5hjHqME92LsbrSC5/4Jqq22HzeuqZJfjg7JcKrak+kklnCXjNnCF7wnwDo1AAQE9
         IJXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WkMVlpXn;
       spf=pass (google.com: domain of 39tmhygukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39tmhYgUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id bn38-20020a05651c17a600b0025590b6eb39si627472ljb.8.2022.06.09.04.31.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39tmhygukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id g3-20020a056402320300b0042dc956d80eso16807246eda.14
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:03 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:a05:6402:500b:b0:431:78d0:bf9d with SMTP id
 p11-20020a056402500b00b0043178d0bf9dmr17528643eda.184.1654774262890; Thu, 09
 Jun 2022 04:31:02 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:40 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-3-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 2/8] perf/hw_breakpoint: Mark data __ro_after_init
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
 header.i=@google.com header.s=20210112 header.b=WkMVlpXn;       spf=pass
 (google.com: domain of 39tmhygukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39tmhYgUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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
---
 kernel/events/hw_breakpoint.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 25c94c6e918d..1f718745d569 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -47,7 +47,7 @@ struct bp_cpuinfo {
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
-static int nr_slots[TYPE_MAX];
+static int nr_slots[TYPE_MAX] __ro_after_init;
 
 static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 {
@@ -63,7 +63,7 @@ static const struct rhashtable_params task_bps_ht_params = {
 	.automatic_shrinking = true,
 };
 
-static int constraints_initialized;
+static bool constraints_initialized __ro_after_init;
 
 /* Gather the number of total pinned and un-pinned bp in a cpuset */
 struct bp_busy_slots {
@@ -711,7 +711,7 @@ int __init init_hw_breakpoint(void)
 	if (ret)
 		goto err;
 
-	constraints_initialized = 1;
+	constraints_initialized = true;
 
 	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
 
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-3-elver%40google.com.
