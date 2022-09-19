Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DA1985BC6CF
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:08 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id g19-20020adfa493000000b0022a2ee64216sf6449588wrb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582688; cv=pass;
        d=google.com; s=arc-20160816;
        b=pkcZtLUmvr0AZyvzxwhAXVmToFnnlzhZt8efbuWQfyG6/iSNVipycbjr7HZ3oz1g2L
         h3w5dpypKSTmR0ZS7a1wrTxDdz2uzaTxZcSYNkxWzHI+ow1IvlpEwycx/iDvyyCM/XXW
         myWjjFImGQK39ZVg3WB/ImvfcYW1ir9tBKUoyg4eZkhC17zC9b+gFFBv69HE+f8bg7NX
         STaYgR9p63MesD29PRT9Fy3gbjLWQXFCA//HGiNvuFyaJxMJuGJmVQG5qP6QJCcETR9B
         EcVZMjuRHtOhWtpU/xM9CzaZYf46KO0fkM/PycyZ6t0jMfDdkg+vD2Yt1NbBJoyBhpgI
         4aag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=JiGWDifZP/2w8UNzbMMcFaYyffrNExihz4gQ0B+W1C0=;
        b=TjMRJU8q8QhK48/fGYfnEcuLZzninuLpUADmwjl7dre4Iuw0dDsTJjJFY08vv54ZOn
         K/TLYVQ2C+TJ+dppZWoel/zCeFsVtqEi7V3cii/7M0vwObyZXu1ThTYEA02oK+e3WUVG
         BWPcr7gyD1CvepI94h5kZhV64uiKu7aMsrrBvp+WxKa43AZfFaT+gsqP7xZi07mBcglV
         mphOrdCVNyCS11U7ZUbaLHHlZA7ZJM7h9KyrbIn7+qIL3Bk79+QfeAtnsD802268GtJ1
         QTfweEZghaRGuYtWVEePMcUDjoGTMPoW4HF0qya8C/agXZh3sKphp1LjxBD6eYc6kw1o
         UfkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=rf6QsvYl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=JiGWDifZP/2w8UNzbMMcFaYyffrNExihz4gQ0B+W1C0=;
        b=seJ8bo7WQNyWEnHSrvctTVD733TmxK4B6duIIUloM6F+hoF7DKA8X0vZvfH3M6yCB9
         omu6jNfuNeRVZE4Hxw5Ul3LXA8dqPsbKDF+o20K3AQFPvaEpvYygPETh4wyCcrl8+ZwI
         E9e9kMBgNq96MA66n6Sxi+WcRXtw6X4qBRSYr9hnw6OYrnKyOj0yLK0rhOnqp0TgZ+Sb
         3bx5zt/gyp392trfxZ1bTkCOw3KFFRwE+i68ruyxX8DuK7IugXZQw2U2XwO6H6q5aKmO
         xFi3nFUdJr0cipS/uVEue8SxLR3/HVfB60EqR3/ugcunVSr/yAi2KPorio0Fub+gYfeo
         p4Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=JiGWDifZP/2w8UNzbMMcFaYyffrNExihz4gQ0B+W1C0=;
        b=cM0Iu6hB3/6iYDKhcUnlADgv4CYRm/ChK1v2ZilbTzrEVtyEXxQjI1iHm0vfsnAZp5
         KQCeWCRQ8CQkwogic1g+Mfk1Kj8ltTZ8HahXNVNCSFE9fXp8cUKUh7UZSt3uw49Sjy37
         SdCDqFPcPElG2qOY+tXJJt7pYIzw5Or6VDqTUnb17mp4UmKDrCpo1Cyhls5cIqUfDguE
         mucIq1vjlKLHGCXXKVesnZk5TJ6//XX0VrKrpbVTGCkudH6/ElsOcQBEebQgDh+TtVqR
         2R8zFEI8znZR+n/9edtfOA8HK011oHr5WUrY2iH2iPDeCq0hJQuJzUKj1CMlOGfUvWg2
         VFSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1o2HtDSeCG+F5yshFggPXIHlu1tFxEdxIoAcvwFtQJ6LKrTRT9
	83Q8ZTMx60njHNHihut7WMs=
X-Google-Smtp-Source: AMsMyM5EOQsKwyK74tIDHLdTE7Hdg32TIRjU6QYohhkj4MzMitewQRegF8hIWE1F3dJdAM6qHUbjbw==
X-Received: by 2002:a05:6000:1b03:b0:22a:7d12:db2b with SMTP id f3-20020a0560001b0300b0022a7d12db2bmr10385394wrz.268.1663582688442;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:255:b0:228:a25b:134a with SMTP id
 m21-20020a056000025500b00228a25b134als7688969wrz.0.-pod-prod-gmail; Mon, 19
 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a5d:64a9:0:b0:22a:c3c3:4943 with SMTP id m9-20020a5d64a9000000b0022ac3c34943mr10760549wrp.655.1663582687343;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=iGadNSt30jhcy1gSCkhPCU8cNEKk7Ku7jfRgOOsOcQjkGTt4GbocaMbyXC/Xw14JQy
         jAF0EnC0sTnaobR3BIbhIX3gLo7Xr7eRhWZJgYfCeaRzDei0hEDl/i2JeV0Gdle4uK9X
         ilm0DMwp7/dxdIagGo6savaxmjjmWqig2f/f4xI1ziSDUAk1o5+vNdCR8sbKvohw3vdt
         k+lVPAoUICKH3L5PmcbOtUK7xFDw4oPqkZ71SndGot338GX7CrVptOrLZZyU15oecqzE
         BnF0tz5TOFSp5hk2yuR9eA7BYouRm+aJtEx1hBDNV8V+ufON3i08eMO3ZI2zhsZdbVdt
         IlUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=WVCZz4VCnGePSihfWXfUVWek2uxL69eYF/NrdeQus6U=;
        b=vX9xk2UNgUIzF9Qy6M7OURVtVfyJiz0GyVCYrKc5qo4kHTKJvOlpF1ia4rCk7Z1V4V
         7a/uCpiBRZ8aSzYyZwfspGopIKLVrPxynVo4WKdoiHy6sr9BR+pPjsCFnMM95bIkAb2q
         j9Sk8556ysfUkNw7+uihR9X5aBpYUmOVP2pdPI7Pu97+ZdLHiKqCSY6G26BrfxYrm5IX
         5ITKUpmdmvKs8Hz7GKXd9n2DTMwpYkQPnh2x9iuf26jxKBVZ08hhDwWJdq3OTURtIK3k
         5Tgk3zo7GPgMrf+tgqG6AprrCQ9+/PmNVjDmJN+b1OEIiUd7EehPByB6vFSClre8oyOM
         9LuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=rf6QsvYl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003a5ce2af2c7si331992wmi.1.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpE-00E28z-QH; Mon, 19 Sep 2022 10:17:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D7948302EA3;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 002B62BA49041; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101521.072508494@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:50 +0200
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
Subject: [PATCH v2 11/44] cpuidle,omap4: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=rf6QsvYl;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

Doing RCU-idle outside the driver, only to then temporarily enable it
again, some *four* times, before going idle is daft.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Tony Lindgren <tony@atomide.com>
Tested-by: Tony Lindgren <tony@atomide.com>
---
 arch/arm/mach-omap2/cpuidle44xx.c |   29 ++++++++++++++++++-----------
 1 file changed, 18 insertions(+), 11 deletions(-)

--- a/arch/arm/mach-omap2/cpuidle44xx.c
+++ b/arch/arm/mach-omap2/cpuidle44xx.c
@@ -105,7 +105,9 @@ static int omap_enter_idle_smp(struct cp
 	}
 	raw_spin_unlock_irqrestore(&mpu_lock, flag);
 
+	ct_idle_enter();
 	omap4_enter_lowpower(dev->cpu, cx->cpu_state);
+	ct_idle_exit();
 
 	raw_spin_lock_irqsave(&mpu_lock, flag);
 	if (cx->mpu_state_vote == num_online_cpus())
@@ -151,10 +153,10 @@ static int omap_enter_idle_coupled(struc
 				 (cx->mpu_logic_state == PWRDM_POWER_OFF);
 
 	/* Enter broadcast mode for periodic timers */
-	RCU_NONIDLE(tick_broadcast_enable());
+	tick_broadcast_enable();
 
 	/* Enter broadcast mode for one-shot timers */
-	RCU_NONIDLE(tick_broadcast_enter());
+	tick_broadcast_enter();
 
 	/*
 	 * Call idle CPU PM enter notifier chain so that
@@ -166,7 +168,7 @@ static int omap_enter_idle_coupled(struc
 
 	if (dev->cpu == 0) {
 		pwrdm_set_logic_retst(mpu_pd, cx->mpu_logic_state);
-		RCU_NONIDLE(omap_set_pwrdm_state(mpu_pd, cx->mpu_state));
+		omap_set_pwrdm_state(mpu_pd, cx->mpu_state);
 
 		/*
 		 * Call idle CPU cluster PM enter notifier chain
@@ -178,14 +180,16 @@ static int omap_enter_idle_coupled(struc
 				index = 0;
 				cx = state_ptr + index;
 				pwrdm_set_logic_retst(mpu_pd, cx->mpu_logic_state);
-				RCU_NONIDLE(omap_set_pwrdm_state(mpu_pd, cx->mpu_state));
+				omap_set_pwrdm_state(mpu_pd, cx->mpu_state);
 				mpuss_can_lose_context = 0;
 			}
 		}
 	}
 
+	ct_idle_enter();
 	omap4_enter_lowpower(dev->cpu, cx->cpu_state);
 	cpu_done[dev->cpu] = true;
+	ct_idle_exit();
 
 	/* Wakeup CPU1 only if it is not offlined */
 	if (dev->cpu == 0 && cpumask_test_cpu(1, cpu_online_mask)) {
@@ -194,9 +198,9 @@ static int omap_enter_idle_coupled(struc
 		    mpuss_can_lose_context)
 			gic_dist_disable();
 
-		RCU_NONIDLE(clkdm_deny_idle(cpu_clkdm[1]));
-		RCU_NONIDLE(omap_set_pwrdm_state(cpu_pd[1], PWRDM_POWER_ON));
-		RCU_NONIDLE(clkdm_allow_idle(cpu_clkdm[1]));
+		clkdm_deny_idle(cpu_clkdm[1]);
+		omap_set_pwrdm_state(cpu_pd[1], PWRDM_POWER_ON);
+		clkdm_allow_idle(cpu_clkdm[1]);
 
 		if (IS_PM44XX_ERRATUM(PM_OMAP4_ROM_SMP_BOOT_ERRATUM_GICD) &&
 		    mpuss_can_lose_context) {
@@ -222,7 +226,7 @@ static int omap_enter_idle_coupled(struc
 	cpu_pm_exit();
 
 cpu_pm_out:
-	RCU_NONIDLE(tick_broadcast_exit());
+	tick_broadcast_exit();
 
 fail:
 	cpuidle_coupled_parallel_barrier(dev, &abort_barrier);
@@ -247,7 +251,8 @@ static struct cpuidle_driver omap4_idle_
 			/* C2 - CPU0 OFF + CPU1 OFF + MPU CSWR */
 			.exit_latency = 328 + 440,
 			.target_residency = 960,
-			.flags = CPUIDLE_FLAG_COUPLED,
+			.flags = CPUIDLE_FLAG_COUPLED |
+				 CPUIDLE_FLAG_RCU_IDLE,
 			.enter = omap_enter_idle_coupled,
 			.name = "C2",
 			.desc = "CPUx OFF, MPUSS CSWR",
@@ -256,7 +261,8 @@ static struct cpuidle_driver omap4_idle_
 			/* C3 - CPU0 OFF + CPU1 OFF + MPU OSWR */
 			.exit_latency = 460 + 518,
 			.target_residency = 1100,
-			.flags = CPUIDLE_FLAG_COUPLED,
+			.flags = CPUIDLE_FLAG_COUPLED |
+				 CPUIDLE_FLAG_RCU_IDLE,
 			.enter = omap_enter_idle_coupled,
 			.name = "C3",
 			.desc = "CPUx OFF, MPUSS OSWR",
@@ -282,7 +288,8 @@ static struct cpuidle_driver omap5_idle_
 			/* C2 - CPU0 RET + CPU1 RET + MPU CSWR */
 			.exit_latency = 48 + 60,
 			.target_residency = 100,
-			.flags = CPUIDLE_FLAG_TIMER_STOP,
+			.flags = CPUIDLE_FLAG_TIMER_STOP |
+				 CPUIDLE_FLAG_RCU_IDLE,
 			.enter = omap_enter_idle_smp,
 			.name = "C2",
 			.desc = "CPUx CSWR, MPUSS CSWR",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.072508494%40infradead.org.
