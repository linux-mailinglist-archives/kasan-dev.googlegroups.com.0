Return-Path: <kasan-dev+bncBDBK55H2UQKRB5WMQGPAMGQEHTMEISQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 316F066801C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:47 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id d27-20020adfa35b000000b002bc813ba677sf2667624wrb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553527; cv=pass;
        d=google.com; s=arc-20160816;
        b=b8TxKR+76DT5w8gG3bf9eZwOqquD/+oLVhyeePjVWHq3b/T+pbE0TONCSI/S8iveRk
         SW++SH2QqbAZvkLLX3RDCU2CgRHXfPtn8ln1sEKdnbQMYM+8elwzfEFW+tVtLAkPq/OA
         CZLdoAW2ye/2D7/Cti0oBfBKXuo+RMBiuK/UJOcjoPYousSls1l+/OquhRsGU6zqZCgx
         /BcNHom3SloS9/C9jY6wLO/zvZsyD57nAeHebBfKfDwL/BR/ZS+g5fKPRPhGinnA+kMV
         yKomjnOEHZowpbp76kyv2Q+sxvajeX8H4DZ8dYRhhrMDkPU8E7kU6NoebDuSeJBooy61
         IZIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=Hgnhhi0Y2zdpbwwKu4VAvBNevttEEdbKEHaWTVhHI2Y=;
        b=dMQ/fcZf3yfY1uMXKW6xAIuXk7gjHPG15bVYsDKGNDS5JNI6dmUR6a0RwXIvPVoFDu
         xky6BObJjdircWe9GAPwDvV30ay8iCBkEG4WS1G+3HaTcPFhKKUoH2YomK1DYLpnXRZJ
         +qCH13asdX3U0RDEL/gTnOmMu+ETUiuhMwzhSRCReM+th99DYbMsPjxVr2Lg6BciSJyN
         ZSuDQm60e04EFjj1fytXn8jImz/pgaJDJHp8hbkXluez6+fD+DONENpGqz8GR+SQgUeA
         7H8hR+vcVirRAEvG1WKeNbigIOeBxsU4nHyNjCk/3AKxDfaSU5UMtWDx2AO/wOrufGW2
         QIZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jkdiNqhE;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hgnhhi0Y2zdpbwwKu4VAvBNevttEEdbKEHaWTVhHI2Y=;
        b=W7b95Pu9H2qxtBsIj1AxGA4ku5RrINsPXICYQBUAoCU2XZuM8GgHw9jKbL8kbiaMUQ
         8qGrA05bVThCd33zqJa1vtvJ92V6Yeg0KlBmKfIe4I3G07/ZAWQy73CaTOFPG8yAsztj
         LWHQVldTsp8eRQZPrxSf6UU7+NOxxCTC51DSj6Jui2A0kLMYYhpVOpjGFEWebpEvk3Um
         nne7Fkb0Y2L1g5RN+qgP7qTYOpopRH6Rs3a1/R4Q8iil5ZDVc1Wl7gyPwaYGeaCONWXE
         iAvDyVpSPhDy9gSLJ7iGYNTGP9FoKW3mvGOxDW6nG2r7Bph1gYpVJXgs+zGzGCRQmQ3B
         0S1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hgnhhi0Y2zdpbwwKu4VAvBNevttEEdbKEHaWTVhHI2Y=;
        b=5/Qa7QnganzgB1LRZYBAXnLtKUOeJ1PYZ3kgsaYPWcqzd69RfiJSqxE89FiTxdxtcW
         3M504LKP7CGrdE6mq3m475HzA4t4MifHUCbrY/qIR5UM2iyxevBZG7t+ZyWapwqmTsTp
         euOtdmjRyi6uEXmVWqpul9v3idfiOOBzTREY5xb8StAvHsBOX3xw9duUE0AgEa0Pm75M
         yPSr5sSFrHw0OCfLBWqZ1my9IYSlyeAqt6aJyKiSTypcSkAWwquMt7wAA0oCmVitpsfV
         q7TaFvq1EV9C3xKVhVu0Z5ZCnHkRL09ZJ2OM7vlrzTae+7UOySSgrrvBQXaYWd2yjoZQ
         Q1Fg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr2vOXBGfR7evJGx5xr/5w74tTFTwiCy9Czm8N/b+UAZhJjaeHY
	tPHMJL9qTh2Znd9PfFeus2s=
X-Google-Smtp-Source: AMrXdXsBfYS3xsCTc3qdt5ug9Ndey4wzgvhpOM5BTNzLxwlSL8wtgUmubfaFSrL1HrUAto7nl7LySw==
X-Received: by 2002:adf:fbc9:0:b0:2bd:db97:5cbd with SMTP id d9-20020adffbc9000000b002bddb975cbdmr61494wrs.179.1673553526863;
        Thu, 12 Jan 2023 11:58:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7708:0:b0:3d9:bb72:6814 with SMTP id t8-20020a1c7708000000b003d9bb726814ls1603879wmi.3.-pod-control-gmail;
 Thu, 12 Jan 2023 11:58:45 -0800 (PST)
X-Received: by 2002:a05:600c:1d25:b0:3d3:50b9:b192 with SMTP id l37-20020a05600c1d2500b003d350b9b192mr67092125wms.18.1673553525620;
        Thu, 12 Jan 2023 11:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553525; cv=none;
        d=google.com; s=arc-20160816;
        b=NJZ6d+HHhUyz7+hKrHs/ZVviGgHVCbaTLpG4wBgmcbKmkIOSqkSEbk0vUjp70WKIJL
         kFqxflQLZMCyN57dxUINGwIMqKIJv9bn5M5dO1nb5DqyVCbhOLIgxKGgc5S/yZbOvf4y
         nDshReQTGs6J1DHrWFlesensOijQA9VOHQ8bimrEl/vGyNPdUFECEaXSpfDUqBqHQ5ls
         PoGXdBZS3dIdmKqNtdpx9J0j3XLGjm57XWJ6xWADIr8Bhp657RxL8BirCLKhnd/jdf3/
         2A/hmv/+5PgRYtrIRcYOwAjYs0VTMRMaiSnloU4VzhXygiaL8m4DC8u8sPvxC6LUvY4j
         /6gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=53PdPXBrlefs7aSWYtbVMctVqERBXlbNfkzlUyuHUdw=;
        b=b/BjXX/tOuWqYF66TugJnJJ5tjh9faJG3wenvKU5dju7e4E4++N+oO2UaGaB35ELGM
         tVOkQT54ArHZ7hiiPP0mj5DqcfjfzBwrZkDp6gvydHifIoqU5jXTP+ZVjvxZIXLEbgJo
         9lbaumk02JQHv3FySJEKyxUqCu8gVR07QU//G3XkNuyBeY8Hvzdy3xDsLEt7VYMUNwKi
         AehsE+VwFe/nHc8kVxHCfHfr/KHFpBJ+P0Mq4U+JPOPhAAxpB7IwjjOhjkZiJjZSz8Ud
         RpQ1RNxH10fpL4jek+y84C6gBOUEZMoXR2VKI9O/9RZU226hNSb6UXq5nwlW+ONeEspQ
         Qotw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jkdiNqhE;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id j31-20020a05600c1c1f00b003da0515e72csi328996wms.2.2023.01.12.11.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:45 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hZ-0045wN-16;
	Thu, 12 Jan 2023 19:57:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 40258303480;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 767D32CD066F4; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.335211484@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:44:03 +0100
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
 kasan-dev@googlegroups.com
Subject: [PATCH v3 49/51] cpuidle,arch: Mark all regular cpuidle_state::enter methods __cpuidle
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=jkdiNqhE;
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

For all cpuidle drivers that do not use CPUIDLE_FLAG_RCU_IDLE (iow,
the simple ones) make sure all the functions are marked __cpuidle.

( due to lack of noinstr validation on these platforms it is entirely
  possible this isn't complete )

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/arm/kernel/cpuidle.c           |    4 ++--
 arch/arm/mach-davinci/cpuidle.c     |    4 ++--
 arch/arm/mach-imx/cpuidle-imx5.c    |    4 ++--
 arch/arm/mach-imx/cpuidle-imx6sl.c  |    4 ++--
 arch/arm/mach-imx/cpuidle-imx7ulp.c |    4 ++--
 arch/arm/mach-s3c/cpuidle-s3c64xx.c |    5 ++---
 arch/mips/kernel/idle.c             |    6 +++---
 7 files changed, 15 insertions(+), 16 deletions(-)

--- a/arch/arm/kernel/cpuidle.c
+++ b/arch/arm/kernel/cpuidle.c
@@ -26,8 +26,8 @@ static struct cpuidle_ops cpuidle_ops[NR
  *
  * Returns the index passed as parameter
  */
-int arm_cpuidle_simple_enter(struct cpuidle_device *dev,
-		struct cpuidle_driver *drv, int index)
+__cpuidle int arm_cpuidle_simple_enter(struct cpuidle_device *dev, struct
+				       cpuidle_driver *drv, int index)
 {
 	cpu_do_idle();
 
--- a/arch/arm/mach-davinci/cpuidle.c
+++ b/arch/arm/mach-davinci/cpuidle.c
@@ -44,8 +44,8 @@ static void davinci_save_ddr_power(int e
 }
 
 /* Actual code that puts the SoC in different idle states */
-static int davinci_enter_idle(struct cpuidle_device *dev,
-			      struct cpuidle_driver *drv, int index)
+static __cpuidle int davinci_enter_idle(struct cpuidle_device *dev,
+					struct cpuidle_driver *drv, int index)
 {
 	davinci_save_ddr_power(1, ddr2_pdown);
 	cpu_do_idle();
--- a/arch/arm/mach-imx/cpuidle-imx5.c
+++ b/arch/arm/mach-imx/cpuidle-imx5.c
@@ -8,8 +8,8 @@
 #include <asm/system_misc.h>
 #include "cpuidle.h"
 
-static int imx5_cpuidle_enter(struct cpuidle_device *dev,
-			      struct cpuidle_driver *drv, int index)
+static __cpuidle int imx5_cpuidle_enter(struct cpuidle_device *dev,
+					struct cpuidle_driver *drv, int index)
 {
 	arm_pm_idle();
 	return index;
--- a/arch/arm/mach-imx/cpuidle-imx6sl.c
+++ b/arch/arm/mach-imx/cpuidle-imx6sl.c
@@ -11,8 +11,8 @@
 #include "common.h"
 #include "cpuidle.h"
 
-static int imx6sl_enter_wait(struct cpuidle_device *dev,
-			    struct cpuidle_driver *drv, int index)
+static __cpuidle int imx6sl_enter_wait(struct cpuidle_device *dev,
+				       struct cpuidle_driver *drv, int index)
 {
 	imx6_set_lpm(WAIT_UNCLOCKED);
 	/*
--- a/arch/arm/mach-imx/cpuidle-imx7ulp.c
+++ b/arch/arm/mach-imx/cpuidle-imx7ulp.c
@@ -12,8 +12,8 @@
 #include "common.h"
 #include "cpuidle.h"
 
-static int imx7ulp_enter_wait(struct cpuidle_device *dev,
-			    struct cpuidle_driver *drv, int index)
+static __cpuidle int imx7ulp_enter_wait(struct cpuidle_device *dev,
+					struct cpuidle_driver *drv, int index)
 {
 	if (index == 1)
 		imx7ulp_set_lpm(ULP_PM_WAIT);
--- a/arch/arm/mach-s3c/cpuidle-s3c64xx.c
+++ b/arch/arm/mach-s3c/cpuidle-s3c64xx.c
@@ -19,9 +19,8 @@
 #include "regs-sys-s3c64xx.h"
 #include "regs-syscon-power-s3c64xx.h"
 
-static int s3c64xx_enter_idle(struct cpuidle_device *dev,
-			      struct cpuidle_driver *drv,
-			      int index)
+static __cpuidle int s3c64xx_enter_idle(struct cpuidle_device *dev,
+					struct cpuidle_driver *drv, int index)
 {
 	unsigned long tmp;
 
--- a/arch/mips/kernel/idle.c
+++ b/arch/mips/kernel/idle.c
@@ -241,7 +241,7 @@ void __init check_wait(void)
 	}
 }
 
-void arch_cpu_idle(void)
+__cpuidle void arch_cpu_idle(void)
 {
 	if (cpu_wait)
 		cpu_wait();
@@ -249,8 +249,8 @@ void arch_cpu_idle(void)
 
 #ifdef CONFIG_CPU_IDLE
 
-int mips_cpuidle_wait_enter(struct cpuidle_device *dev,
-			    struct cpuidle_driver *drv, int index)
+__cpuidle int mips_cpuidle_wait_enter(struct cpuidle_device *dev,
+				      struct cpuidle_driver *drv, int index)
 {
 	arch_cpu_idle();
 	return index;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.335211484%40infradead.org.
