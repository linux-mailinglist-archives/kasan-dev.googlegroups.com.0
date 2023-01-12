Return-Path: <kasan-dev+bncBDBK55H2UQKRB4OMQGPAMGQEML4QINI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 26D6D668015
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:42 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id a20-20020ac25214000000b004b57756f937sf7285638lfl.3
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553522; cv=pass;
        d=google.com; s=arc-20160816;
        b=kO5WMg/Ehjj7JGgteunvQ8LhUdsl/HqLvQznc+VfauSJsl5yBbWO+5DHnlDfqwn6Qq
         xFnM/Jw/x/1nLnlcWDo9hXMe5iMINpNUpdPiJo7jol9nZEKfOaZh40M/6FlCsis0pzgk
         M07A8RsnzetknopRYwRTfhQ8JnhJFKGQN8c5D/NAq3/nmzFjo95acNTjr29ZTK08B+zr
         RIcHLOmnPtk+7P09nmBm/fbqt7oA3JE6+MXqWIkn5IkUdfR//Pba3GH5v/Hggw5v0wBm
         xUzyWvkPaWRgf0M8sglA1DtKy6MwGoLvkmowAmTpRGTQhvY4b/6YV75Zmw0tY33bk8C8
         zTgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=lt3yT86ymNintdHbCoo+uzSPCU75z+AiNLzBqlcTEiM=;
        b=ji7T33rvYea7vMYalOVXdtoi739A+kly/chLhDcAoEkeq4VHLm6uLVXxv46hvNtJrC
         m8ynhNhy4qSZTdsthYPAMPJvo8fHOqTO7Nwv1p0wM69FShjG3RnYM/zz/JVcW8xtCETi
         KE2RCcdomijK81c7eyQNqGNXkYtd9fGWLUu0fTrcdzmlC/6Ini3ePoAKvY1IUusE0WZ9
         H7ClmXGqlVPPnCq1r/czgLjWh3ofc7qvpTJBdOG3RvzZOuCfaEisx4ZvfLbo3GFFF4Yf
         EsZll1zh7JhEEypTCjlJonrlEU7mv1hrH52Mze/deiu//eSIkDUPjFrM9bVaYL50mPSc
         GY/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Vj4eR6v5;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lt3yT86ymNintdHbCoo+uzSPCU75z+AiNLzBqlcTEiM=;
        b=Ge7CWezT85/aQWKLGWZMDYeO1cYa3y9DMph2KVu1tgwrYe4Y4p6CBu5avKdz7OmVv9
         5lOOFDYYUm1+z56H24TvGGMo28j9Ts0McrHrXWYcQMqMPDP+ze0ogzp6Ar4nkSRTUmdo
         Mbi4OaKrK7vonVqeMFgqVR+vsSUxMevdv5ZlWfQ5SqUP4Sqo77hdX1quvVSATg4lBrOS
         QQyJyB3RN1LLNx6K67yJ8rhiVn1lcdnjv8BLoouV8bby3Vf6BMkNPr9F4GeXYDtxxuYH
         +sf+kX9bPUnJ3MDmq1aswhAcYPRVPLfbQw/fxA9x9VvcL+h58/9hWMU1YJ6rRx9AEND/
         fCmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lt3yT86ymNintdHbCoo+uzSPCU75z+AiNLzBqlcTEiM=;
        b=jZc03et/UrbHoHSUZ4mY/EwGQtzKbrxyIdvefxJjSwTp5+WSKB36VA6BKgt0/A/Fsg
         b3/xbA5EyxA7WdYbGOHRLyDRz80k6sQmOBQrA/DtneEGhsONdewamcQsmkoPtFUHfiem
         gQOTakJh83uyS5N2rQ5vt2+JvbNG+vYTyJjvhDps3cYsvb24uNvnXEha1nvLlusVYLI5
         zzE1uvtKK9AyiJY114moJsLszYo+j8GZsIEehOPEs/uzEzaCE4/vXhpGlyrL9oZSu2OU
         Pirzp4l3RQCC6XTPJS8MZw6a7Eb/LwaXbwF/BgdruFLV3WKP28BnIJRsvz8FQm2p/n7W
         YFXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqzdIgDjxxm/gac5DRKDVIcHq3ZWf/Ux5i+F1lizmZ9jmvmPAdK
	cgM35i4HbSWQ9CXTLZyHGME=
X-Google-Smtp-Source: AMrXdXvbH9b2obN8H+g/McGe2bq0XEW+SLMlt4KL0WRRsUnP/t28639KZnrJFC+MpEAanG2jdzmVIA==
X-Received: by 2002:a05:651c:550:b0:27f:d2bc:98c5 with SMTP id q16-20020a05651c055000b0027fd2bc98c5mr3706387ljp.42.1673553521848;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls1755257lfr.2.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:40 -0800 (PST)
X-Received: by 2002:a05:6512:1049:b0:4a4:68b9:66e5 with SMTP id c9-20020a056512104900b004a468b966e5mr24212934lfb.48.1673553520600;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553520; cv=none;
        d=google.com; s=arc-20160816;
        b=ut+8CqSGWhzX5uert/lKylTibv5XVYaGJEi9GPnHi0UdvZyDpEKwenyi7niqX2lnwi
         zdMknld7ChlcjLkHIq0vgABcUPmbJ3YDM/F2FB8BOezxYhMuo2PFSAmYoMOSjG6o3L47
         2CAeuXOTtjrzcwiZBaqrirBZL6aboDvINqCsnxIVI7yB6LO9Py17PUyp7SPs48CmcqHe
         oo41dU/oclF04TV97fkoTBpvkuVTi7bkbvv3DJ0yG4H5FfgoUdqlo/YxHpJ+D6+B4idU
         68hR/mtKvBLXvyF2HTtJvP9iEOaRuauQFBsFalky/0iI8SgxKSj/BqT3upvL2AybZ7iE
         O+IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=ChWtbTrciVV3G1vvtlVpdXBjaP89UEdojcC0eA3JIzQ=;
        b=iA8aiEKInoVur0WfBfU+zUN3rdbZPhzY3q+tDbbl7cejNmz9J1BKCmqBLBqn4hEFoc
         rBSxmovaAGv9TE9vWyb19YSethgsQGD0K5EPnEYP4dEct/k+Bwt+2Wn3L7uYneTLh1EK
         525IE9rUpoNKqbMIDgp0zB5Y72QNsfTt43axk5URRb8Bg96vsp98JLNWiJN3D5Mp3L73
         cLC2MyfQgHj2jPhH+t/zbCs2eUPkjLMwUCaJ4wKNl37jqcacC54WE3Wu8UUx8D3aSzYW
         e1OBGUJOBO/GJGWqhKCMYCvKmCF5joze4vBdDz26hO/8E/m/iJyLOSIAyIayBqfcfAQX
         Q5eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Vj4eR6v5;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id e9-20020a05651236c900b004cb0f0982f3si793456lfs.4.2023.01.12.11.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hK-0045pd-0Y;
	Thu, 12 Jan 2023 19:57:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E712130345D;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 45C182CD01216; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.660272394@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:52 +0100
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
Subject: [PATCH v3 38/51] cpuidle,omap4: Push RCU-idle into omap4_enter_lowpower()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Vj4eR6v5;
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

From: Tony Lindgren <tony@atomide.com>

OMAP4 uses full SoC suspend modes as idle states, as such it needs the
whole power-domain and clock-domain code from the idle path.

All that code is not suitable to run with RCU disabled, as such push
RCU-idle deeper still.

Signed-off-by: Tony Lindgren <tony@atomide.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.660272394%40infradead.org.
