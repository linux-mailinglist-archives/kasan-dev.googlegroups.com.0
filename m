Return-Path: <kasan-dev+bncBDBK55H2UQKRB36MQGPAMGQEA3JMCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 01F6766800A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id m8-20020a05600c3b0800b003d96bdce12fsf9721885wms.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553519; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYXLoz5caPkMV42S/zNZk2v3DuPbOv5fFuO6KEpOI4HPsT/fmo2yxy2H40W8QC6JYM
         SrgutsrbCJ10wygtvlayuuW0trsux/CJR449+Eyqny/IrpkE6glKhpssHjcHbHFPA/5h
         6tJoOM2il2EnCkjCvC7+nnuav7xnwRaChPxVJeIMnSMKHR97QQ5fVWnlGf4k5KUCb18S
         zOMtL4sFyCRK7eYcNczcoPhfi9zuWraK5dO0uFZJm62Q6FqQXGFacgaZFR7oDpZ+r97g
         xjIw3MDfi9vlT03qZZHYeRKGHq2ehadW7SHjBUXenH+WYLb+uXdUg3PEPJhRj/rvF2MU
         t2zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=KaJMwOZZhSEOGh280/6idKpbeKzBMNaZeA4CCFVbI2k=;
        b=TGRuCpkFt2d5tYItFxnwZI8eaSMwVyCqg7gQKpiqO3P4YnNY36wLPdZ+Aj4+bjWFuV
         FPamTbzMVzzMcVZ8XnhlSAcyAVuMcTby12fJFfwqNScSoYrQ3nevH9QIlfZU8kf43wjr
         IBYC3urrX2eACJpFRa+b1XpOAHhq4yyte3sGkPJ/aqv9bClVX9mEfxA5SkyhOgUb9akm
         MOa0KIvSE0FzXhImw33X2bTCu01bVXN698yPToTBYmSz9L8dDHF9+uk75aGsvKTCFuL5
         GfVdimgy/Li7wTED7aRiF0G3O4d0tOHHPK87n3qukvUQsrwKaTwRow21DpsmcTtlwsd3
         PVAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=reo76Y6t;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KaJMwOZZhSEOGh280/6idKpbeKzBMNaZeA4CCFVbI2k=;
        b=sT8hx0pIp2ntwTHmT0IWkrrhVBadhXyELnQrAVPcDCB/T+Ep1iIMZWLTLdoiI77TYc
         wjvnBtkRtLZt05NUEQhi+zymHVEJ/hITDZlpjn3DzeBqWXrbIZtbmtOBf3aSSArlBSAQ
         n2xvrVoZnkepKs8UolBtjWkvgkhi06d6aifzE64ny5VfQEH/mMWcEwN2YwkJV266Bxtb
         ms1IQ0z3AaaL0dfLVCuXLRk1xfPvZVIVJnhw5VY58mWdn534nauSBuYr/A1vrAvAlk5H
         S7tWNrBVOjj8SL57uMCMiIJrn5JZ51vHOJLf8Vi7or46B5C8F73z7OUvDTDefQDOjiOH
         eq2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KaJMwOZZhSEOGh280/6idKpbeKzBMNaZeA4CCFVbI2k=;
        b=YmAP4FSB9Mvz9+6VS+6vqoc7/y+kGNXhSUbJ8Z70jxgNPiu/FpMKgPW1BSIZLAzoTw
         qP2SPKkCRX0MmLFVSZdgwyEZjXg1pMqvSF0lee744FK3kEAn8NRC18mSPcykw66FhhJf
         MyXqk5zFrHnjs4FyAXGr43ubGuYiBWxlyDVE8kwByZyjzDMwIAanoRipBO/Rc4+PiVcS
         wUUfA5VVCKLunOpR+Juy5fswLYhqTT1nTdsMWV/vuXCW2NAkCQft5pLndvs1LOHuxfqN
         IjDP1hmakD3nxBO/UaNoZTyigscHJbQ5713dSRaSj+u4ADgjplPGJJyVQTRBWIZnXxwE
         uScA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqx9oNPM9Q0dFSm8ZpjVJNMRs22sBVj4u6Ox4BkhQFub4d2V1Xi
	9zpecNRob4W2P2vz0UwMYyU=
X-Google-Smtp-Source: AMrXdXtXrqQjympM+omEk8PKzQfKHNpTdEWCAiLxnogN62GQIGMle4p1P3/loERWXheX1wWgJC3Dhg==
X-Received: by 2002:a05:6000:1c07:b0:2bd:d756:e47b with SMTP id ba7-20020a0560001c0700b002bdd756e47bmr146167wrb.368.1673553519771;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4081:0:b0:225:6559:3374 with SMTP id o1-20020a5d4081000000b0022565593374ls1472470wrp.2.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:38 -0800 (PST)
X-Received: by 2002:a05:6000:18c9:b0:242:88af:d88b with SMTP id w9-20020a05600018c900b0024288afd88bmr48956203wrq.43.1673553518684;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=NPg5tFwcbHTkG0q5UFUpmHcfN4c1NXL7kDuoPPauIvLk666olLwPfY/qomfTTfQQVK
         T1QQ555+Cg5qeaqyXSDfpF8broCv2SEhE6QLOWF4KoRR7w87/qcBqOUryVW63uwhnDOr
         yE64UOreJ4AiVekoImLDJRG2F6w6vDiWjjwLiBjDYfc0ABFByRlbM96Pnl4LWE7tNNFS
         CQNBer+iSxqQZiXas9DLeOlWWerJV5t/pmUQD4qUy7Ogk4XqN0t/E8GHOq3UvP2lpbaz
         xqSXt1/4pVImvwUoNm43Gjv3SFWyfA+9eNivL7/h8s2nML1zjw7ueGpsH8OCqLn76cIm
         NEUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=CWtXQ9ScESvHC863qag21jQX+KK5xw/Ija2/01ku3yk=;
        b=Y1N/dRhqx07oFqMsZa6fkFFG7LN7of4Bhb4X4szLhL7UH00XZDFJTHRifBeG3GEb22
         WJ/Ogh7f1AhVry9btv/qlzWdvjdj9RMB9NKcc1qfqMZEaoGZmokPYiZNEOYcX5SStX6s
         HJNKe5Ed8s+oNFlhOy6esx/CyrKXFIosj0lb3q4USpPa1zmhZJEMb1g4CjWPvvHDT93h
         K2z2gaVfN7GjWxXL9UvEoieb1ou+Wc6v6ap62UMORzCXoaPUU35uPM9tDavw/xr7u81a
         zuYzWq2PQvyck3Zc6JAtHFeHr16qCz3du/XQyYh//JOiaJEeARsNBtb9e0LG/bARKbij
         WvTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=reo76Y6t;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id s1-20020a5d4ec1000000b0024222ed1370si827144wrv.3.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hD-0045oE-0P;
	Thu, 12 Jan 2023 19:57:08 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1C501303400;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id BAFC42CCF1F5C; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.007918454@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:25 +0100
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
Subject: [PATCH v3 11/51] cpuidle,omap4: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=reo76Y6t;
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

Doing RCU-idle outside the driver, only to then temporarily enable it
again, some *four* times, before going idle is daft.

Notably three times explicitly using RCU_NONIDLE() and once implicitly
through cpu_pm_*().

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Reviewed-by: Tony Lindgren <tony@atomide.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.007918454%40infradead.org.
