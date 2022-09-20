Return-Path: <kasan-dev+bncBDBK55H2UQKRBOMRU6MQMGQEN2TB2UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E8DFE5BE7F3
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 16:05:46 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id d4-20020a2e9284000000b0025e0f56d216sf923424ljh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 07:05:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663682746; cv=pass;
        d=google.com; s=arc-20160816;
        b=aaZmh2XR5Ay3c6wGrpjWXsP5/LpZDsPLao2E7FXVsIstLBO5AE3r3FoERk4uEUZ7GT
         zJeojk+psbeFvc2mDrrIe+XJbhIImdcDvHF17O/7RGTKyfh2UBLt1ZXIXeqtBUMZaNA7
         YuMHIm9DtbvlG/HBDUF1B/Fw1qdy5o0bYYKwrHqZrIa7uztx4wZK1J9NoVm0e8XOky/Q
         4++M20KiXPFYK+GlurCy8IkKg6nPV9PwbUiXi9lnf9o1WTq9yfiYrKVri+ZyRgMHE1gR
         S7JQMbO3bMLTBSO9ild1JNDadRkILaUTHSs0yJwdLwyQHxTUwwpW/35KtCFmC7F2ESrq
         nygA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:to:from:date:sender
         :dkim-signature;
        bh=TwBoquvUrba+gL4EDYQSpdB/5HnrKyXFgzORCxWQ1M0=;
        b=DQ3M4911m3NNxA7twMR2XUU0dBfN/JgHEuIThTVO3wsPWDQA7qjpqkICLsrvEHkZG7
         118RPVSwggTWH6/PJe1UGLvR34W+SeOSM31M8McbqbUqMy37EWSV2Ek0zHSoGriZvblT
         +kWX5/nUoUuTbR9rcytnbYbmICpSnfzmyetee3K6bkLjF/U8rIyHD31UBnjlD1RTbOXi
         1PO7LsNRkOGfDRLs2SA8+Qg7VbZpcXhD2L89B78LcyKaGybKJKQRfu/3FSZE260No5rY
         ly1UC4KOX5usfba05zdTYzLX5Z+o05WT30GqHGYDOT7u/QCba8IcmqGgQRThaAHibAZD
         rwPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=HASBL4Zg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:to:from:date:sender:from:to:cc
         :subject:date;
        bh=TwBoquvUrba+gL4EDYQSpdB/5HnrKyXFgzORCxWQ1M0=;
        b=PzmEr/5N2xj1ArS+AYX5MhfiG972s9DA6nRCsjK1hQjiNnk0o0dX1HTBu7d6ZFbNUV
         rd/DV+kQkA3JWeQnbbMp2XFP/ws3N1rQmJkNMtDcVFTwTWRUpXNW/NdfQeMO14GIJ9Mr
         3gYf52l0CTQSuJTKo/Xl0USpV+wh9pb6Unk2tO5omxoqApABgloDT5I2GjJQFFchufzq
         joQpE99jJ2UG2dKyOaZ9sexBx/VZ3aJsW2kE2w2hNfCpdDixy5c5t1XY6Fx7AKT2OHCI
         1RBDdRWZJzviYSR/hzbzd43BbhFGFUhRl0Wp/ude9phHuMHKsdfYcdtGnrF1Qvxgt0nL
         x+2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=TwBoquvUrba+gL4EDYQSpdB/5HnrKyXFgzORCxWQ1M0=;
        b=0Y+izs8IamWVPassQdnUS6fSQaGSKMFCQFGzvKmlAfRT1ZSWeX5rcg2Y1ZTaugQcsB
         WotkLzUi9wSiIoc8a3RvxU6CVCz5joEi5hQqI3WU6qY0Wu3ZGw9B2vBrxzjCyG15NSDK
         bUyoaV5bJTerX0jXJMpcDzUULWBFmMa8p7PlWTgSjqVv1n9UTnBQptpivAVwCzEHsU1V
         CIPSiSOKBf3UePlH4ikQml+1PSq8G+A8Fr46tbd07sipLwP5CN1n+Kavh1WqBdzSteSY
         FPZY6VgxJ07cnkcRDmNHXljRnDGRXid3sfnRIpLc1HBOGHnlRxsXjNITYeXDzVgBOWp1
         n0uA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3uQmH+3E016tePRgZrIIsTnv1pVgsCN2cFRI3KDlOGfmaLrTy1
	VOslXp6kSclGMskAOtzsY+M=
X-Google-Smtp-Source: AMsMyM6kTObESNRzS/8wtuG0Atw9tkNfrkvpi1hefgsSYBZe8czk4pdrwsJuHfR1GEK5nmCh4R8dSw==
X-Received: by 2002:a05:6512:ad0:b0:497:a620:157d with SMTP id n16-20020a0565120ad000b00497a620157dmr8835030lfu.643.1663682746172;
        Tue, 20 Sep 2022 07:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:0:b0:494:6c7d:cf65 with SMTP id v13-20020ac258ed000000b004946c7dcf65ls2400637lfo.2.-pod-prod-gmail;
 Tue, 20 Sep 2022 07:05:44 -0700 (PDT)
X-Received: by 2002:a05:6512:401c:b0:49f:4b2e:7153 with SMTP id br28-20020a056512401c00b0049f4b2e7153mr7724461lfb.443.1663682744364;
        Tue, 20 Sep 2022 07:05:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663682744; cv=none;
        d=google.com; s=arc-20160816;
        b=RXZFSw1UIhBb0GFDK78qR+wNJ03IUt790mxdshHu1yiU3lhTOPorDjWqoln9ElVNFk
         Id2vGQm35aNv5ECJGx1wDADzXqhZALQ1aM1JjDew0Blc9GAoNclrn23CrGLprtcrTtSd
         sHC+bChvBlBTTFCzPqsh8+nq0X2kMGNufB+ip7IYWg/ecvX852zpq5p3GC8RPYIe1GZG
         M7OCl2NpQEfAs+vAlWTFTY4Qx8KwU174OQLnA9obRvag5qLMGTm1SrGldaZklZ/cmFpv
         vvwkqSOy4XgveDba6GBSTaW5pQ2MuhNRThlTBUZ3vITP/scrSnYTmWbCLWdiBFGw222I
         hqiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:to:from:date:dkim-signature;
        bh=pUyjVDld9zFCUTkkA07ck30DRQCGaey9CaHvnqryoew=;
        b=RSAxKdKjy3MSXyOMKwEzfPkeAEzf9mHgCSQhA4JLw6W6SJwmQTkbR+1pu5+SgcvR6h
         l5zzlt5U2EbDm8l1oMFp8ZUUIF5926OTiVEhICGqHdwz2ZSxD4NuMgPmmzncaQByFP4f
         bqz3f/HWR2b1915ELRdsOJ9H5D6kdh6y9Ob1VnNxnC+4X0b8iVgaYi0iRQE5ILYNnIX5
         ThdngVrsCrK8CiZwnxHuN+cHfUB5NQKncdLQc/F/I630pUxNLvKg1D3FOfyzpzeKHbmQ
         rWNGgYOILhgZ41qbubCbc15pMP9/8/bm+Hq1g3rz4a3qrz/nKC6GnyqUMJXgaWOYA8zI
         OVVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=HASBL4Zg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id b20-20020a2eb914000000b0026c2cb5925esi4525ljb.5.2022.09.20.07.05.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Sep 2022 07:05:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oadrq-005XkP-CQ; Tue, 20 Sep 2022 14:04:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C899D300202;
	Tue, 20 Sep 2022 16:04:47 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A0C2020161C88; Tue, 20 Sep 2022 16:04:47 +0200 (CEST)
Date: Tue, 20 Sep 2022 16:04:47 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com,
	will@kernel.org, guoren@kernel.org, bcain@quicinc.com,
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org,
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de,
	dinguyen@kernel.org, jonas@southpole.se,
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
	James.Bottomley@hansenpartnership.com, deller@gmx.de,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
	konrad.dybcio@somainline.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 00/44] cpuidle,rcu: Clean up the mess
Message-ID: <YynIf5WiWbNdiWsq@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919095939.761690562@infradead.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=HASBL4Zg;
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


Because Nadav asked about tracing/kprobing idle, I had another go around
and noticed not all functions calling ct_cpuidle_enter are __cpuidle.

Basically all cpuidle_driver::enter functions should be __cpuidle; i'll
do that audit shortly.

For now this is ct_cpuidle_enter / CPU_IDLE_ENTER users.

---
--- a/arch/arm/mach-imx/cpuidle-imx6q.c
+++ b/arch/arm/mach-imx/cpuidle-imx6q.c
@@ -17,8 +17,8 @@
 static int num_idle_cpus = 0;
 static DEFINE_RAW_SPINLOCK(cpuidle_lock);
 
-static int imx6q_enter_wait(struct cpuidle_device *dev,
-			    struct cpuidle_driver *drv, int index)
+static __cpuidle int imx6q_enter_wait(struct cpuidle_device *dev,
+				      struct cpuidle_driver *drv, int index)
 {
 	raw_spin_lock(&cpuidle_lock);
 	if (++num_idle_cpus == num_online_cpus())
--- a/arch/arm/mach-imx/cpuidle-imx6sx.c
+++ b/arch/arm/mach-imx/cpuidle-imx6sx.c
@@ -30,8 +30,8 @@ static int imx6sx_idle_finish(unsigned l
 	return 0;
 }
 
-static int imx6sx_enter_wait(struct cpuidle_device *dev,
-			    struct cpuidle_driver *drv, int index)
+static __cpuidle int imx6sx_enter_wait(struct cpuidle_device *dev,
+				       struct cpuidle_driver *drv, int index)
 {
 	imx6_set_lpm(WAIT_UNCLOCKED);
 
--- a/arch/arm/mach-omap2/omap-mpuss-lowpower.c
+++ b/arch/arm/mach-omap2/omap-mpuss-lowpower.c
@@ -224,8 +224,8 @@ static void __init save_l2x0_context(voi
  *	2 - CPUx L1 and logic lost + GIC lost: MPUSS OSWR
  *	3 - CPUx L1 and logic lost + GIC + L2 lost: DEVICE OFF
  */
-int omap4_enter_lowpower(unsigned int cpu, unsigned int power_state,
-			 bool rcuidle)
+__cpuidle int omap4_enter_lowpower(unsigned int cpu, unsigned int power_state,
+				   bool rcuidle)
 {
 	struct omap4_cpu_pm_info *pm_info = &per_cpu(omap4_pm_info, cpu);
 	unsigned int save_state = 0, cpu_logic_state = PWRDM_POWER_RET;
--- a/arch/arm/mach-omap2/pm34xx.c
+++ b/arch/arm/mach-omap2/pm34xx.c
@@ -175,7 +175,7 @@ static int omap34xx_do_sram_idle(unsigne
 	return 0;
 }
 
-void omap_sram_idle(bool rcuidle)
+__cpuidle void omap_sram_idle(bool rcuidle)
 {
 	/* Variable to tell what needs to be saved and restored
 	 * in omap_sram_idle*/
--- a/arch/arm64/kernel/cpuidle.c
+++ b/arch/arm64/kernel/cpuidle.c
@@ -62,7 +62,7 @@ int acpi_processor_ffh_lpi_probe(unsigne
 	return psci_acpi_cpu_init_idle(cpu);
 }
 
-int acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
+__cpuidle int acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
 {
 	u32 state = lpi->address;
 
--- a/drivers/cpuidle/cpuidle-arm.c
+++ b/drivers/cpuidle/cpuidle-arm.c
@@ -31,8 +31,8 @@
  * Called from the CPUidle framework to program the device to the
  * specified target state selected by the governor.
  */
-static int arm_enter_idle_state(struct cpuidle_device *dev,
-				struct cpuidle_driver *drv, int idx)
+static __cpuidle int arm_enter_idle_state(struct cpuidle_device *dev,
+					  struct cpuidle_driver *drv, int idx)
 {
 	/*
 	 * Pass idle state index to arm_cpuidle_suspend which in turn
--- a/drivers/cpuidle/cpuidle-big_little.c
+++ b/drivers/cpuidle/cpuidle-big_little.c
@@ -122,8 +122,8 @@ static int notrace bl_powerdown_finisher
  * Called from the CPUidle framework to program the device to the
  * specified target state selected by the governor.
  */
-static int bl_enter_powerdown(struct cpuidle_device *dev,
-				struct cpuidle_driver *drv, int idx)
+static __cpuidle int bl_enter_powerdown(struct cpuidle_device *dev,
+					struct cpuidle_driver *drv, int idx)
 {
 	cpu_pm_enter();
 	ct_cpuidle_enter();
--- a/drivers/cpuidle/cpuidle-mvebu-v7.c
+++ b/drivers/cpuidle/cpuidle-mvebu-v7.c
@@ -25,9 +25,9 @@
 
 static int (*mvebu_v7_cpu_suspend)(int);
 
-static int mvebu_v7_enter_idle(struct cpuidle_device *dev,
-				struct cpuidle_driver *drv,
-				int index)
+static __cpuidle int mvebu_v7_enter_idle(struct cpuidle_device *dev,
+					 struct cpuidle_driver *drv,
+					 int index)
 {
 	int ret;
 	bool deepidle = false;
--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -49,14 +49,9 @@ static inline u32 psci_get_domain_state(
 	return __this_cpu_read(domain_state);
 }
 
-static inline int psci_enter_state(int idx, u32 state)
-{
-	return CPU_PM_CPU_IDLE_ENTER_PARAM(psci_cpu_suspend_enter, idx, state);
-}
-
-static int __psci_enter_domain_idle_state(struct cpuidle_device *dev,
-					  struct cpuidle_driver *drv, int idx,
-					  bool s2idle)
+static __cpuidle int __psci_enter_domain_idle_state(struct cpuidle_device *dev,
+						    struct cpuidle_driver *drv, int idx,
+						    bool s2idle)
 {
 	struct psci_cpuidle_data *data = this_cpu_ptr(&psci_cpuidle_data);
 	u32 *states = data->psci_states;
@@ -192,12 +187,12 @@ static void psci_idle_init_cpuhp(void)
 		pr_warn("Failed %d while setup cpuhp state\n", err);
 }
 
-static int psci_enter_idle_state(struct cpuidle_device *dev,
-				struct cpuidle_driver *drv, int idx)
+static __cpuidle int psci_enter_idle_state(struct cpuidle_device *dev,
+					   struct cpuidle_driver *drv, int idx)
 {
 	u32 *state = __this_cpu_read(psci_cpuidle_data.psci_states);
 
-	return psci_enter_state(idx, state[idx]);
+	return CPU_PM_CPU_IDLE_ENTER_PARAM(psci_cpu_suspend_enter, idx, state[idx]);
 }
 
 static const struct of_device_id psci_idle_state_match[] = {
--- a/drivers/cpuidle/cpuidle-qcom-spm.c
+++ b/drivers/cpuidle/cpuidle-qcom-spm.c
@@ -58,8 +58,8 @@ static int qcom_cpu_spc(struct spm_drive
 	return ret;
 }
 
-static int spm_enter_idle_state(struct cpuidle_device *dev,
-				struct cpuidle_driver *drv, int idx)
+static __cpuidle int spm_enter_idle_state(struct cpuidle_device *dev,
+					  struct cpuidle_driver *drv, int idx)
 {
 	struct cpuidle_qcom_spm_data *data = container_of(drv, struct cpuidle_qcom_spm_data,
 							  cpuidle_driver);
--- a/drivers/cpuidle/cpuidle-riscv-sbi.c
+++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
@@ -93,17 +93,17 @@ static int sbi_suspend(u32 state)
 		return sbi_suspend_finisher(state, 0, 0);
 }
 
-static int sbi_cpuidle_enter_state(struct cpuidle_device *dev,
-				   struct cpuidle_driver *drv, int idx)
+static __cpuidle int sbi_cpuidle_enter_state(struct cpuidle_device *dev,
+					     struct cpuidle_driver *drv, int idx)
 {
 	u32 *states = __this_cpu_read(sbi_cpuidle_data.states);
 
 	return CPU_PM_CPU_IDLE_ENTER_PARAM(sbi_suspend, idx, states[idx]);
 }
 
-static int __sbi_enter_domain_idle_state(struct cpuidle_device *dev,
-					  struct cpuidle_driver *drv, int idx,
-					  bool s2idle)
+static __cpuidle int __sbi_enter_domain_idle_state(struct cpuidle_device *dev,
+						   struct cpuidle_driver *drv, int idx,
+						   bool s2idle)
 {
 	struct sbi_cpuidle_data *data = this_cpu_ptr(&sbi_cpuidle_data);
 	u32 *states = data->states;
--- a/drivers/cpuidle/cpuidle-tegra.c
+++ b/drivers/cpuidle/cpuidle-tegra.c
@@ -160,8 +160,8 @@ static int tegra_cpuidle_coupled_barrier
 	return 0;
 }
 
-static int tegra_cpuidle_state_enter(struct cpuidle_device *dev,
-				     int index, unsigned int cpu)
+static __cpuidle int tegra_cpuidle_state_enter(struct cpuidle_device *dev,
+					       int index, unsigned int cpu)
 {
 	int err;
 
@@ -226,9 +226,9 @@ static int tegra_cpuidle_adjust_state_in
 	return index;
 }
 
-static int tegra_cpuidle_enter(struct cpuidle_device *dev,
-			       struct cpuidle_driver *drv,
-			       int index)
+static __cpuidle int tegra_cpuidle_enter(struct cpuidle_device *dev,
+					 struct cpuidle_driver *drv,
+					 int index)
 {
 	bool do_rcu = drv->states[index].flags & CPUIDLE_FLAG_RCU_IDLE;
 	unsigned int cpu = cpu_logical_map(dev->cpu);
--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -137,11 +137,13 @@ int cpuidle_find_deepest_state(struct cp
 }
 
 #ifdef CONFIG_SUSPEND
-static void enter_s2idle_proper(struct cpuidle_driver *drv,
-				struct cpuidle_device *dev, int index)
+static __cpuidle void enter_s2idle_proper(struct cpuidle_driver *drv,
+					  struct cpuidle_device *dev, int index)
 {
-	ktime_t time_start, time_end;
 	struct cpuidle_state *target_state = &drv->states[index];
+	ktime_t time_start, time_end;
+
+	instrumentation_begin();
 
 	time_start = ns_to_ktime(local_clock());
 
@@ -152,13 +154,18 @@ static void enter_s2idle_proper(struct c
 	 * suspended is generally unsafe.
 	 */
 	stop_critical_timings();
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
 		ct_cpuidle_enter();
+		/* Annotate away the indirect call */
+		instrumentation_begin();
+	}
 	target_state->enter_s2idle(dev, drv, index);
 	if (WARN_ON_ONCE(!irqs_disabled()))
 		raw_local_irq_disable();
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
+		instrumentation_end();
 		ct_cpuidle_exit();
+	}
 	tick_unfreeze();
 	start_critical_timings();
 
@@ -166,6 +173,7 @@ static void enter_s2idle_proper(struct c
 
 	dev->states_usage[index].s2idle_time += ktime_us_delta(time_end, time_start);
 	dev->states_usage[index].s2idle_usage++;
+	instrumentation_end();
 }
 
 /**
@@ -200,8 +208,9 @@ int cpuidle_enter_s2idle(struct cpuidle_
  * @drv: cpuidle driver for this cpu
  * @index: index into the states table in @drv of the state to enter
  */
-int cpuidle_enter_state(struct cpuidle_device *dev, struct cpuidle_driver *drv,
-			int index)
+__cpuidle int cpuidle_enter_state(struct cpuidle_device *dev,
+				  struct cpuidle_driver *drv,
+				  int index)
 {
 	int entered_state;
 
@@ -209,6 +218,8 @@ int cpuidle_enter_state(struct cpuidle_d
 	bool broadcast = !!(target_state->flags & CPUIDLE_FLAG_TIMER_STOP);
 	ktime_t time_start, time_end;
 
+	instrumentation_begin();
+
 	/*
 	 * Tell the time framework to switch to a broadcast timer because our
 	 * local timer will be shut down.  If a local timer is used from another
@@ -235,15 +246,21 @@ int cpuidle_enter_state(struct cpuidle_d
 	time_start = ns_to_ktime(local_clock());
 
 	stop_critical_timings();
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
 		ct_cpuidle_enter();
+		/* Annotate away the indirect call */
+		instrumentation_begin();
+	}
 
 	entered_state = target_state->enter(dev, drv, index);
+
 	if (WARN_ONCE(!irqs_disabled(), "%ps leaked IRQ state", target_state->enter))
 		raw_local_irq_disable();
 
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
+		instrumentation_end();
 		ct_cpuidle_exit();
+	}
 	start_critical_timings();
 
 	sched_clock_idle_wakeup_event();
@@ -306,6 +323,8 @@ int cpuidle_enter_state(struct cpuidle_d
 		dev->states_usage[index].rejected++;
 	}
 
+	instrumentation_end();
+
 	return entered_state;
 }
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YynIf5WiWbNdiWsq%40hirez.programming.kicks-ass.net.
