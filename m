Return-Path: <kasan-dev+bncBDBK55H2UQKRBQ4DUGMQMGQEMJLUQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D5D615BC678
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:39 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id c128-20020a1c3586000000b003b324bb08c5sf4443579wma.9
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582659; cv=pass;
        d=google.com; s=arc-20160816;
        b=kg6GOmzBF/55x5iTWsLznJIe66t9vXFJhbcXHVCTLwwV16eq6PReOWXiuJm+whXbPW
         lycIbK85BEcoYlZhSenJuthA6y7ZsV+uyn95SIqo/kJSKksOW55IYzpDOlKe4MbFhzgi
         IfDY7YhQ+b7sA4QQNiUQ7ETge8NX6Pj6PkFohiNnLIBN/wifB714NVWO2K6D/B4P7auQ
         +RrRz3FmscOUB+E9qaBzk1VLthYanYmlXZIgwPrqaXmgtydMrntWFvmgpJcs+ENR1/AS
         nOyIm29pARASsX7cN1b1Em7zha7wdbAlXbOd/wKI7AkkCAhANE/loFTdOZ/XIK666VVR
         Eiwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=rKNyQDcZg4JvUkKuv0gotbih4hpso6WHDrHkkO/7q4Q=;
        b=QCyylHy1sSHabwHEXZVCaaQRvHC2O8vvzrfwMtWuMfWdxvGnE62+dxyd2hYXSDG8Em
         Y7FtMcBI3MEDzkBuFQAH1J/gFO225cV2pukQ8kdZd0Bt0LsBFeH+uctaUo+T7u1DFq80
         zUzT4GKoVIfljOhN+D2IjX/FR6CP24xm/gzrBoYqrBhSGWmlwilzYTdcwxePcEyn++iR
         l96MIyfMIvoUIlLivoMSg1xsmk5qKSQ74dZVsMEG+Dq7im0xF4A4csCsPW1Qd1Pnk+kd
         kvunmSPP0r2wKi4IRLgceLn3lR2GTR2cqgpi2lQ7/jA/248Qmzs1OwyAGk4/Y/JS8V7M
         dLpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=fLDVs7Aj;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=rKNyQDcZg4JvUkKuv0gotbih4hpso6WHDrHkkO/7q4Q=;
        b=DaCriB5+LJ39SvLNos1RkqmIEBdhfhrxD9ONT+nei/La6qGHSnKODnCMTgMlv9IXfb
         sjgerVCK2BLp6dbRtVZ1pE9yhq0dABeUgbIEJcnWEh+/wGGNpd/Rzbd0dfKs6s+j1rjm
         dmybLrB79o3rlWC5sKVEazBL8d8hdw2D+fdR9X0JevvQzGSTPFQRzJMWmgtVaAgQ1ImQ
         OvpBrLcgpKGyZ4HeJ8zcuYsU/2sNy2CNit4WEwotzRQ4WnKtgBWmKRRjUdaRzF9mFSru
         mejoZh1A0XMMmk6N1up9HQPPzWuB/opD+gAKIoQ0LWbEEI+ckj7KK+XIsEdingiOKqTY
         9SaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=rKNyQDcZg4JvUkKuv0gotbih4hpso6WHDrHkkO/7q4Q=;
        b=dfoBAaYEUtDCOy2aW9pwkKN5TqjcR6m/cSrOpV0FNzZwa8kh5EYLsVNNYlc54Y2HeA
         VNtuBExka853gIcw7agE31aPWUURi3SSOyW6u8DHxWobVKgji8W2boPSnX7lIgANA4Q9
         5xjiNuSZ4hjt/Hatf/yuWthmNr4JuokK+mBHYpbeM/VTiOV2xYrHu4ieXCWeAjKIDH25
         3yn5r2TkX5MGylPfbfuEzj3plO5DOkJv+7yc1G1B95n2A/qAQ2arfA1CPG519bp8YrJE
         7M0jPJnK2NcgDZ9RUeZnEbVHDHEi53sl3LEZwinLwtEB49iraAKPu6vCZnPPYJ/F7Pga
         NV+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0MGQV4LTpoZszxo5BW8FLQ/cRBnIOx0sVdaO4vEmLbjPI1M9Fh
	wut/tKAIbFZu1cPseDiL33w=
X-Google-Smtp-Source: AMsMyM7mbPcuOSqiFMqsR2gFdn5/FGjvHj9NdFrdMdjbfui2R3pUQRVd1NlSBzZmRuLyAvl2mUZvXQ==
X-Received: by 2002:a1c:7c04:0:b0:3b4:aaa4:9ec8 with SMTP id x4-20020a1c7c04000000b003b4aaa49ec8mr11592322wmc.44.1663582659437;
        Mon, 19 Sep 2022 03:17:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20c:0:b0:228:ddd7:f40e with SMTP id j12-20020adfd20c000000b00228ddd7f40els7610163wrh.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:38 -0700 (PDT)
X-Received: by 2002:adf:e112:0:b0:21d:7195:3a8d with SMTP id t18-20020adfe112000000b0021d71953a8dmr10552624wrz.371.1663582658277;
        Mon, 19 Sep 2022 03:17:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582658; cv=none;
        d=google.com; s=arc-20160816;
        b=YJoEr6JzWlGA2PERmyMqIFaEcJwkGuMK/jsbsOM7ECn6OqNSqpmXdDXFWMi29dgPJE
         QbOPoo9uHg+oHRLAYkYv253TT+wWbAoGkImAZorSvNnRZV+CZLp/98vTJbAxXMvNr4Ki
         GgLVBv+lEqVryFywZIDhXoWEz42gCnif2oV8FkdvFrwOxZNKTkEPAAzyVwkwqUVxkAxk
         17dpkhxC0jupymgqdAtwqD8cHfK+WzFvOCyTWp4TpDqx6jEanCg1g3MQPfDW87bwPzme
         jddYGLAorDvzae+3+zPxEid0qcgTOa5WZ25qVd/KL/wwLS0S74jbkvTMn/w4Bxkk2NAj
         7wxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=TtR3uUdCvUM2x08kEUTStDUmM7q30GrToBg+SVCjhcg=;
        b=eP2B9EDACWiCi3BXC/V+fQYR61oOXwA0V9668M/bAP1Qw70PHC3mjpc2lUdjmojQVP
         yYstC10jpOAVhKbDvO4CMqLhPNAKrl9OwmCZo2WRfewm/OipPR902Z64n4/83guhH38+
         yTFyXs5G9rDc/kSK6ut1t3lcDO/1HTIatmx8h8puPygho5SXo2XpndO3XG8jJbX2lzOI
         VKKgaQmIEUj/6/1YgmdTXfGYy4Cv/QPUHPWGp6ILhvsgutzfTdhgjHvn08K4cP9HvDHt
         9YR0ano/iYWpGpT1oQfvMdpD3tDZloBPnQ85uFrzev2f4gwLQGY5w6K62M6J38jEcpjX
         v2ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=fLDVs7Aj;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bv26-20020a0560001f1a00b0022afc97eb06si83828wrb.1.2022.09.19.03.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq9-004bCJ-NN; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 76077302F5F;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 883CE2BAC75B8; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.775353582@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:15 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
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
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
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
 fweisbec@gmail.com,
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
 kasan-dev@googlegroups.com
Subject: [PATCH v2 36/44] cpuidle,omap4: Push RCU-idle into omap4_enter_lowpower()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=fLDVs7Aj;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

From: Tony Lindgren <tony@atomide.com>

OMAP4 uses full SoC suspend modes as idle states, as such it needs the
whole power-domain and clock-domain code from the idle path.

All that code is not suitable to run with RCU disabled, as such push
RCU-idle deeper still.

Signed-off-by: Tony Lindgren <tony@atomide.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Link: https://lkml.kernel.org/r/Yqcv6crSNKuSWoTu@atomide.com
---
 arch/arm/mach-omap2/common.h              |    6 ++++--
 arch/arm/mach-omap2/cpuidle44xx.c         |    8 ++------
 arch/arm/mach-omap2/omap-mpuss-lowpower.c |   12 +++++++++++-
 arch/arm/mach-omap2/pm44xx.c              |    2 +-
 4 files changed, 18 insertions(+), 10 deletions(-)

--- a/arch/arm/mach-omap2/common.h
+++ b/arch/arm/mach-omap2/common.h
@@ -284,11 +284,13 @@ extern u32 omap4_get_cpu1_ns_pa_addr(voi
 
 #if defined(CONFIG_SMP) && defined(CONFIG_PM)
 extern int omap4_mpuss_init(void);
-extern int omap4_enter_lowpower(unsigned int cpu, unsigned int power_state);
+extern int omap4_enter_lowpower(unsigned int cpu, unsigned int power_state,
+				bool rcuidle);
 extern int omap4_hotplug_cpu(unsigned int cpu, unsigned int power_state);
 #else
 static inline int omap4_enter_lowpower(unsigned int cpu,
-					unsigned int power_state)
+					unsigned int power_state,
+					bool rcuidle)
 {
 	cpu_do_idle();
 	return 0;
--- a/arch/arm/mach-omap2/cpuidle44xx.c
+++ b/arch/arm/mach-omap2/cpuidle44xx.c
@@ -105,9 +105,7 @@ static int omap_enter_idle_smp(struct cp
 	}
 	raw_spin_unlock_irqrestore(&mpu_lock, flag);
 
-	ct_cpuidle_enter();
-	omap4_enter_lowpower(dev->cpu, cx->cpu_state);
-	ct_cpuidle_exit();
+	omap4_enter_lowpower(dev->cpu, cx->cpu_state, true);
 
 	raw_spin_lock_irqsave(&mpu_lock, flag);
 	if (cx->mpu_state_vote == num_online_cpus())
@@ -186,10 +184,8 @@ static int omap_enter_idle_coupled(struc
 		}
 	}
 
-	ct_cpuidle_enter();
-	omap4_enter_lowpower(dev->cpu, cx->cpu_state);
+	omap4_enter_lowpower(dev->cpu, cx->cpu_state, true);
 	cpu_done[dev->cpu] = true;
-	ct_cpuidle_exit();
 
 	/* Wakeup CPU1 only if it is not offlined */
 	if (dev->cpu == 0 && cpumask_test_cpu(1, cpu_online_mask)) {
--- a/arch/arm/mach-omap2/omap-mpuss-lowpower.c
+++ b/arch/arm/mach-omap2/omap-mpuss-lowpower.c
@@ -33,6 +33,7 @@
  * and first to wake-up when MPUSS low power states are excercised
  */
 
+#include <linux/cpuidle.h>
 #include <linux/kernel.h>
 #include <linux/io.h>
 #include <linux/errno.h>
@@ -214,6 +215,7 @@ static void __init save_l2x0_context(voi
  * of OMAP4 MPUSS subsystem
  * @cpu : CPU ID
  * @power_state: Low power state.
+ * @rcuidle: RCU needs to be idled
  *
  * MPUSS states for the context save:
  * save_state =
@@ -222,7 +224,8 @@ static void __init save_l2x0_context(voi
  *	2 - CPUx L1 and logic lost + GIC lost: MPUSS OSWR
  *	3 - CPUx L1 and logic lost + GIC + L2 lost: DEVICE OFF
  */
-int omap4_enter_lowpower(unsigned int cpu, unsigned int power_state)
+int omap4_enter_lowpower(unsigned int cpu, unsigned int power_state,
+			 bool rcuidle)
 {
 	struct omap4_cpu_pm_info *pm_info = &per_cpu(omap4_pm_info, cpu);
 	unsigned int save_state = 0, cpu_logic_state = PWRDM_POWER_RET;
@@ -268,6 +271,10 @@ int omap4_enter_lowpower(unsigned int cp
 	cpu_clear_prev_logic_pwrst(cpu);
 	pwrdm_set_next_pwrst(pm_info->pwrdm, power_state);
 	pwrdm_set_logic_retst(pm_info->pwrdm, cpu_logic_state);
+
+	if (rcuidle)
+		ct_cpuidle_enter();
+
 	set_cpu_wakeup_addr(cpu, __pa_symbol(omap_pm_ops.resume));
 	omap_pm_ops.scu_prepare(cpu, power_state);
 	l2x0_pwrst_prepare(cpu, save_state);
@@ -283,6 +290,9 @@ int omap4_enter_lowpower(unsigned int cp
 	if (IS_PM44XX_ERRATUM(PM_OMAP4_ROM_SMP_BOOT_ERRATUM_GICD) && cpu)
 		gic_dist_enable();
 
+	if (rcuidle)
+		ct_cpuidle_exit();
+
 	/*
 	 * Restore the CPUx power state to ON otherwise CPUx
 	 * power domain can transitions to programmed low power
--- a/arch/arm/mach-omap2/pm44xx.c
+++ b/arch/arm/mach-omap2/pm44xx.c
@@ -76,7 +76,7 @@ static int omap4_pm_suspend(void)
 	 * domain CSWR is not supported by hardware.
 	 * More details can be found in OMAP4430 TRM section 4.3.4.2.
 	 */
-	omap4_enter_lowpower(cpu_id, cpu_suspend_state);
+	omap4_enter_lowpower(cpu_id, cpu_suspend_state, false);
 
 	/* Restore next powerdomain state */
 	list_for_each_entry(pwrst, &pwrst_list, node) {


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.775353582%40infradead.org.
