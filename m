Return-Path: <kasan-dev+bncBDBK55H2UQKRB26MQGPAMGQEXK2OTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C7456667FF9
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:36 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id w2-20020a0565120b0200b004cfd8133992sf58765lfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553516; cv=pass;
        d=google.com; s=arc-20160816;
        b=z77u4r2ONGScslHRDAl8zrh5A8H7os8nxgq2ZnreNYjfpRYICKn6XxccvScmfF65Qt
         ffJmdhABK43vcA1aGoE21EWPoVdV7SxCGmwXzMAoslxv5suTvkXUekcYPtyFPAf/s3Pz
         BzOnK0JFUyNGg7PP9VF/YeYOK0m/VDLGXZgXHl6RIpnxio7L1yigW8CnMG2K4BwFZqAq
         b5WccwDCEBRz0hQJhNiL7WF6v1CNVcHD6lmhcEBPUhfX5WmgmnvjXVylH/hA3aB1Ws7v
         eCP6zgqqiWN4R4FJRw7YJxpa1Vj2QOr78l4sc3xo+piANV8vOIvu/EDPoKVJhh47D7du
         oWxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=9Uae9XZgqUEUp+Lx4QYZTsxgEAWIgPAm+qoUgXb1C4I=;
        b=WDipBDkSR2UxMUUyy4dgmHBiZDFmBkDjl8wYMQeejpMayiOCFCC9sA0PmgsT3oibxv
         Sxf+5FchLilQoJoAV3dE5QJJox2Pu7gE51C3cnAjco+WKruF4miqWjt92xouC7WpUwHC
         8jQa2B+qTElwMxfXBbR33KAzPJQgzZn/hNWncq3+ZK5bTTLT88ti+EPbcxIVqnSZntkn
         c0X+XrxnfmYtROxcQ8uO8ijuGEx79D6v6LDSVUdEIcfv9J31qJS8I0dV/QNthVZ4aOAB
         C6mN79PIfu6XAWLPl5IHpQ5FK33kiJOoEgRKXGcZuDGDWgsR/+uYKoQdXxnu1VLfICAZ
         Iezw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=h16ohqN1;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Uae9XZgqUEUp+Lx4QYZTsxgEAWIgPAm+qoUgXb1C4I=;
        b=rwuWprz0LViiNf/b26b1gCS2L7vcY4fOV2fe46tCy7Zxj7E1cJT0ZuuONexwgnA+G4
         XCrn9BA2BO1tHW3S2zWVPQTAmfcmJYRvVr1CGuepK3JfwugoZiwlbrLh3cUhPL7GQneZ
         ycQE9OCH0+HnDW+DeDv3d4TZuCVwfObM1YwHV8uXcjnrzXV5L5qaLZZY5cXH7JUhjaob
         6vhpnkLU6KBz20I/649havJYPlCxOHboMrCbuTDNKcV8rPZj0f+DhsGmNwqMB2NKzSOg
         dedLpjJcBQQTxMleejMTyrg5gb0QEPQpqfX6HO64pISGEvGuysoHBW02j6XcY18lxuDf
         w2yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Uae9XZgqUEUp+Lx4QYZTsxgEAWIgPAm+qoUgXb1C4I=;
        b=eYmDomTkNSKaGu1Z5wDB1nw5x0jPoIwpc23Iqaf4tK7gfA9TpIVET//Q5qyVxuKaP7
         pYK1WtM5G+kuSSaWYSjdHquN69nI0Ryyi/Xl2S0iWmBJXLHBxpoOVlA9QXJcfzPtdB16
         GSqOoop5vPbWrANZzf0ZGsLi+2UIAd2cUYn8V/IBSM3oWeXbGIsDypH/GqDG3yZ7eAcm
         wqtEmiX61Er5zwwlph/0JqI8pssGOWqzBL29GSndQ01JbuFyBPU0HH9BjHN0ZOy6JR68
         QQHHO7P6MPmqkDrTT9wSbbVP73LimpSVwWBr3wASfelwMsjqhGmRcHowDodqfbFnEMnI
         wHPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kopytzPHKC0hz5JcoKqGJQqofabaYDN7DF4kVfGOUEG01SDidHS
	T7kcUBoDDEFZ813Yw33R4c0=
X-Google-Smtp-Source: AMrXdXuiw++BdHAM/M1osb4YM8ptsozfU9MjQ28Kq9u3/U6ckANtBYbiJV0FiZ9xefWi4MNqGFyBKA==
X-Received: by 2002:a2e:bc81:0:b0:27a:945:2192 with SMTP id h1-20020a2ebc81000000b0027a09452192mr5078627ljf.398.1673553516199;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1937476lfr.3.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a05:6512:2396:b0:4b5:a331:759b with SMTP id c22-20020a056512239600b004b5a331759bmr22775329lfv.5.1673553514964;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553514; cv=none;
        d=google.com; s=arc-20160816;
        b=YTLnd7K3c0Gwx8ZOv3P+d8UFVj2ZPJ/uWqluMFriJpXhjnrJWt+jp61VA3kBPn1uxM
         Vf+mzVwKWEwkCuM1TNhN9tSlk7Y9nJyCFAMhJ6uynngpsLFusjNVpJzSlNWWslAXGBvZ
         1wy5Yn12uv7e+htDxWMaSjXA9cCdDwE+XvtmMXnyuvCZ/NUOZx6m9J8vNjsq4Lf9XJDC
         WMpMWwSKYX3Ts1bw0oQSrA/gExGKtTwGH9biyhAjDI0+8oZLMOz3CKjdZxVQf7OZo1I5
         6zXjAK/4RwdYwhlkCBAL2vcDZ7Dsm0VsMT3YrdK4piswebUE+fGDsaDQ5DlTr/XnyKPO
         GMPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=RrpmTujnodPvC1LE/jXScgO4ZKUrxiQVlZ4+SEf4m04=;
        b=QxdB04gi69dha8v4e2a/WyWzi24HQC4Utm38SVDLbzsKEDh22vI9CZ+gHPSzqeVw7/
         X+AjEvauE4ejgqJH3HuqxlLEiEDvbGERY3R9C11OMJjpdCn1hv53d1R1IAC1RpJuDecn
         wTryQz6pyd1wCL6TiMlyxghbzwNXonR0eN4nuYZQyzjR+W7NfmG0ZFl1oQKBJg1v63tB
         wEFbS6tCR2cW3oNaIeYWnv6Rw989Fi4pEwmg23BEJDz2eYgmY5Z85hzeKZtx+901JlAy
         JNNQjw9fi1MOzu/ZT4hHaofNzyjJphCiyaDDyRoCuTio08ptiHWjpUMcHthc6vd+Epi+
         R2NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=h16ohqN1;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a14-20020ac25e6e000000b004cfe6a1a3e7si4468lfr.13.2023.01.12.11.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hY-005Oca-7T; Thu, 12 Jan 2023 19:57:28 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 10FCE3033FA;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id B27F62CCF1F50; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.883561913@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:23 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-samsung-soc@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 09/51] cpuidle,omap3: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=h16ohqN1;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

Doing RCU-idle outside the driver, only to then teporarily enable it
again before going idle is daft.

Notably the cpu_pm_*() calls implicitly re-enable RCU for a bit.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Reviewed-by: Tony Lindgren <tony@atomide.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-omap2/cpuidle34xx.c |   16 ++++++++++++++++
 1 file changed, 16 insertions(+)

--- a/arch/arm/mach-omap2/cpuidle34xx.c
+++ b/arch/arm/mach-omap2/cpuidle34xx.c
@@ -133,7 +133,9 @@ static int omap3_enter_idle(struct cpuid
 	}
 
 	/* Execute ARM wfi */
+	ct_idle_enter();
 	omap_sram_idle();
+	ct_idle_exit();
 
 	/*
 	 * Call idle CPU PM enter notifier chain to restore
@@ -265,6 +267,7 @@ static struct cpuidle_driver omap3_idle_
 	.owner            = THIS_MODULE,
 	.states = {
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 2 + 2,
 			.target_residency = 5,
@@ -272,6 +275,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 10 + 10,
 			.target_residency = 30,
@@ -279,6 +283,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 50 + 50,
 			.target_residency = 300,
@@ -286,6 +291,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU RET + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 1500 + 1800,
 			.target_residency = 4000,
@@ -293,6 +299,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU OFF + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 2500 + 7500,
 			.target_residency = 12000,
@@ -300,6 +307,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU RET + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 3000 + 8500,
 			.target_residency = 15000,
@@ -307,6 +315,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU OFF + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 10000 + 30000,
 			.target_residency = 30000,
@@ -328,6 +337,7 @@ static struct cpuidle_driver omap3430_id
 	.owner            = THIS_MODULE,
 	.states = {
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 110 + 162,
 			.target_residency = 5,
@@ -335,6 +345,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 106 + 180,
 			.target_residency = 309,
@@ -342,6 +353,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 107 + 410,
 			.target_residency = 46057,
@@ -349,6 +361,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU RET + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 121 + 3374,
 			.target_residency = 46057,
@@ -356,6 +369,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU OFF + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 855 + 1146,
 			.target_residency = 46057,
@@ -363,6 +377,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU RET + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 7580 + 4134,
 			.target_residency = 484329,
@@ -370,6 +385,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU OFF + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 7505 + 15274,
 			.target_residency = 484329,


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.883561913%40infradead.org.
