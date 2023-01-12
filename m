Return-Path: <kasan-dev+bncBDBK55H2UQKRB4GMQGPAMGQERVECTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9625666800E
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id w2-20020a0565120b0200b004cfd8133992sf58835lfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553520; cv=pass;
        d=google.com; s=arc-20160816;
        b=o2CV308/JWmhOiRSxd4e8QxFxc4Knfo5VNcvYtlFVA/gefzODGXbDhZrzsHHJEUc6m
         ICmz01UPKBzkzCNZydX2fvwMsB9R38T4Xtwvx3EZKP87D/IItDtZ2pg9e+UQnuH+o09w
         zgA5P25B+ZuOwgf0j+NUfv+AHcVWIPNWSpnt4j7e4Dnk8buFaHycSnTkWY+2l3TiBYwt
         zBLmptEaLXIYvb0X7irPRF1qcILg1WbQW/I84za1YhgRJcywrrfO5NJNDxqbFm/yERTP
         U4X/Xzo7lcQWlGtqKyj0iAouxQakoH2wFmiMG9FdPZbwAUZhwn4dsC1ql2IUxC9pCX+C
         TeSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=yUYOUcw7W0A8yFgOgRjEDI5Bnp90sBkgmdHPxyBctjQ=;
        b=Q6m8pvQflCX15ulISTPWMDFNiK1zd5Wsap2IxjJiYfHfDknV5ieBPBytnbc15UOPhf
         R4J27gSTia97VuvgGfxieQySgXZB8WDHsOMhhrhqgqv54tsVMMy8RX0kjFEIsxAZAiIq
         Qygnc3s9++rOI97KzyD33JNlJan9VxiclQrVF9uuvlHA6HGALb1z3AQPrPT1NSH0FB/d
         hg3qygoI6fTCDS23Dl4vW8S90N2Ru4VfmZWrpmyIhSUO4zfE55XKmF9c6oAIaAnh8qLq
         pSXU4976S+Bd36h+NbXWe8k8L2rstwKQCJHTK8syDtLC+6Ay/PRTon+3hwiHwnlxYik4
         FogA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=X3sYuy6f;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yUYOUcw7W0A8yFgOgRjEDI5Bnp90sBkgmdHPxyBctjQ=;
        b=eMbi33o+cdZxtKgwAx1Z5bWytVH0feuoPQjNBjs5a4LNAmcr7hi8tH4naKm490RFrR
         CitnMGlVf3RTqk5HMGqBNaj6zjBlQpWKiKCfd8V93iKLBU1w/9g+JRFRgs9LCeFkwJ+U
         MPGyf4YG+VyP8n2BLWmzvCvDo6q4L4yPlK6tvIpaQnXk8yuqd7Gtt28Fhj9s6mdL8nC1
         6YXGNBMGdZTDCOvobaSJGXKSmRmVlnOo1t2+/HHNIhegRkzqIa9VDcpfn/huYVJwMbDk
         m9iJ3SFRjvnzO8roQe2Mg2x4gG/4AGjxlrARdpYNYe3ZyHON0Rj9WbqLZ73bFaWa6w47
         Yk4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yUYOUcw7W0A8yFgOgRjEDI5Bnp90sBkgmdHPxyBctjQ=;
        b=1AvWhedUgREgDcYeMnMvALTDcy/Cf8lqk7alSowpK7E9Yo6Pklf+y4X508E8xtee0v
         8+pTFAGERLHxgQ7836OnCGvhwMWdPTY7N5NyKVFj9oliPGg2Ybs+PfQg/S0emXduL6TU
         SLnN47meCipVK0pMZDG4I0VXXlQYxtZqi15Y5o1ZcPvH45s8QJagvP6u6z2ppxvjaut7
         OZHbCVYcgEfF5k98XgAtDZOG3kaS8cnpv4l0oMMZFT3ADl0t9u8RPsOZpqVgfN2XavzN
         QtEfRgr/C0zz0qqEmV+W6NhfE/LNsefrEgRYRaTo0rY18onNQgSP77OplfbyOsR4LLkX
         ddhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq/HmaUCAvurrDTYjkt9va55upXjU1GPjdz2HkTdrhHU8SUu4Sk
	jWL7crQbzpMeNvSSq8pK3yU=
X-Google-Smtp-Source: AMrXdXur9xfX4vPWZfuTkLi5Q5uO00UxVScaefT7UKPc9X2dHVA9vr/4w/RwAyyd65rGLz5+7AUOtw==
X-Received: by 2002:a05:6512:ea0:b0:4ca:fff2:901c with SMTP id bi32-20020a0565120ea000b004cafff2901cmr7331252lfb.473.1673553520266;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1937569lfr.3.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:39 -0800 (PST)
X-Received: by 2002:a05:6512:110c:b0:4cc:a1a1:9aaf with SMTP id l12-20020a056512110c00b004cca1a19aafmr1235284lfg.23.1673553518994;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=zY+SwxP7MfJx1Gdo23vuFOxYz0CjLxuoWyYwnXFy87uAYLOiduoFNseH2YE/oKlS56
         KyL2CdKwfUU5vVEYRObrHmQry71l3BNemSCosvXs2BxDhXeCUHRL1bunFikd1zHTK/0H
         aJ15sVmTVhH3GN78AMHo3OA/xUuxMWIvjfiTIcNrSRR6nPrCPhgnpZU3zuSv/N+QGrex
         dj5nyBEaR1LPMv4pMxPbTV/09dNKVu0ILDwiaOpFb+SmqC4CyUbpwX9PyXLcNzrvmEDT
         A9j56nJVo4y+YsOkN0jp9JPncC9ozUQA+IybMgAua8PQ2aL3AN/jQkiOBi/IZ2RbcVLH
         pFtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=U+TfVkp0QsADQiBGN/hq9wf1EsYpsa4vTkdZ0mLdl1k=;
        b=SIWmRPC97TfgkBRC/3yVAR1viCP16hexK9Gtwxck0+G/3ES+HE5cvZRfHNucNelgDv
         v+EBA5cGv6DJj9SYLM2M8zQaNF6lsWezxh+rr2fEilsEEIALf3oBNdWGMpPfvPkA7+Vy
         B65BwNTmv/ksrMRfVuFkNqOTa7C6DBtAiAAaZcCynGrZmRlewaFlGZu0pwPim2OQ96EJ
         NAdSeoO2rgmhBNN2nHbyeVynznptf3lZeWhISdIU/nLb4zKuLp8OB0tKserQSpqv5+Rp
         yA5h/tus5P/eQQjrwFj2HASF2SyJAYRxehKBauLYo+dceesXNDooF61VD9L72UWT0BqZ
         Jt/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=X3sYuy6f;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id p13-20020a2ea4cd000000b00286e157db47si437286ljm.6.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hD-0045oI-2B;
	Thu, 12 Jan 2023 19:57:08 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2A77A30340E;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id C388F2CCF1F60; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.130014793@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:27 +0100
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
Subject: [PATCH v3 13/51] cpuidle: Fix ct_idle_*() usage
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=X3sYuy6f;
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

The whole disable-RCU, enable-IRQS dance is very intricate since
changing IRQ state is traced, which depends on RCU.

Add two helpers for the cpuidle case that mirror the entry code.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-imx/cpuidle-imx6q.c    |    4 +--
 arch/arm/mach-imx/cpuidle-imx6sx.c   |    4 +--
 arch/arm/mach-omap2/cpuidle34xx.c    |    4 +--
 arch/arm/mach-omap2/cpuidle44xx.c    |    8 +++---
 drivers/acpi/processor_idle.c        |    8 ++++--
 drivers/cpuidle/cpuidle-big_little.c |    4 +--
 drivers/cpuidle/cpuidle-mvebu-v7.c   |    4 +--
 drivers/cpuidle/cpuidle-psci.c       |    4 +--
 drivers/cpuidle/cpuidle-riscv-sbi.c  |    4 +--
 drivers/cpuidle/cpuidle-tegra.c      |    8 +++---
 drivers/cpuidle/cpuidle.c            |   11 ++++----
 include/linux/clockchips.h           |    4 +--
 include/linux/cpuidle.h              |   34 ++++++++++++++++++++++++--
 kernel/sched/idle.c                  |   45 ++++++++++-------------------------
 kernel/time/tick-broadcast.c         |    6 +++-
 15 files changed, 86 insertions(+), 66 deletions(-)

--- a/arch/arm/mach-imx/cpuidle-imx6q.c
+++ b/arch/arm/mach-imx/cpuidle-imx6q.c
@@ -25,9 +25,9 @@ static int imx6q_enter_wait(struct cpuid
 		imx6_set_lpm(WAIT_UNCLOCKED);
 	raw_spin_unlock(&cpuidle_lock);
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 	cpu_do_idle();
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	raw_spin_lock(&cpuidle_lock);
 	if (num_idle_cpus-- == num_online_cpus())
--- a/arch/arm/mach-imx/cpuidle-imx6sx.c
+++ b/arch/arm/mach-imx/cpuidle-imx6sx.c
@@ -47,9 +47,9 @@ static int imx6sx_enter_wait(struct cpui
 		cpu_pm_enter();
 		cpu_cluster_pm_enter();
 
-		ct_idle_enter();
+		ct_cpuidle_enter();
 		cpu_suspend(0, imx6sx_idle_finish);
-		ct_idle_exit();
+		ct_cpuidle_exit();
 
 		cpu_cluster_pm_exit();
 		cpu_pm_exit();
--- a/arch/arm/mach-omap2/cpuidle34xx.c
+++ b/arch/arm/mach-omap2/cpuidle34xx.c
@@ -133,9 +133,9 @@ static int omap3_enter_idle(struct cpuid
 	}
 
 	/* Execute ARM wfi */
-	ct_idle_enter();
+	ct_cpuidle_enter();
 	omap_sram_idle();
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	/*
 	 * Call idle CPU PM enter notifier chain to restore
--- a/arch/arm/mach-omap2/cpuidle44xx.c
+++ b/arch/arm/mach-omap2/cpuidle44xx.c
@@ -105,9 +105,9 @@ static int omap_enter_idle_smp(struct cp
 	}
 	raw_spin_unlock_irqrestore(&mpu_lock, flag);
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 	omap4_enter_lowpower(dev->cpu, cx->cpu_state);
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	raw_spin_lock_irqsave(&mpu_lock, flag);
 	if (cx->mpu_state_vote == num_online_cpus())
@@ -186,10 +186,10 @@ static int omap_enter_idle_coupled(struc
 		}
 	}
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 	omap4_enter_lowpower(dev->cpu, cx->cpu_state);
 	cpu_done[dev->cpu] = true;
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	/* Wakeup CPU1 only if it is not offlined */
 	if (dev->cpu == 0 && cpumask_test_cpu(1, cpu_online_mask)) {
--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -642,6 +642,8 @@ static int __cpuidle acpi_idle_enter_bm(
 	 */
 	bool dis_bm = pr->flags.bm_control;
 
+	instrumentation_begin();
+
 	/* If we can skip BM, demote to a safe state. */
 	if (!cx->bm_sts_skip && acpi_idle_bm_check()) {
 		dis_bm = false;
@@ -663,11 +665,11 @@ static int __cpuidle acpi_idle_enter_bm(
 		raw_spin_unlock(&c3_lock);
 	}
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	acpi_idle_do_entry(cx);
 
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	/* Re-enable bus master arbitration */
 	if (dis_bm) {
@@ -677,6 +679,8 @@ static int __cpuidle acpi_idle_enter_bm(
 		raw_spin_unlock(&c3_lock);
 	}
 
+	instrumentation_end();
+
 	return index;
 }
 
--- a/drivers/cpuidle/cpuidle-big_little.c
+++ b/drivers/cpuidle/cpuidle-big_little.c
@@ -126,13 +126,13 @@ static int bl_enter_powerdown(struct cpu
 				struct cpuidle_driver *drv, int idx)
 {
 	cpu_pm_enter();
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	cpu_suspend(0, bl_powerdown_finisher);
 
 	/* signals the MCPM core that CPU is out of low power state */
 	mcpm_cpu_powered_up();
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	cpu_pm_exit();
 
--- a/drivers/cpuidle/cpuidle-mvebu-v7.c
+++ b/drivers/cpuidle/cpuidle-mvebu-v7.c
@@ -36,9 +36,9 @@ static int mvebu_v7_enter_idle(struct cp
 	if (drv->states[index].flags & MVEBU_V7_FLAG_DEEP_IDLE)
 		deepidle = true;
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 	ret = mvebu_v7_cpu_suspend(deepidle);
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	cpu_pm_exit();
 
--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -74,7 +74,7 @@ static int __psci_enter_domain_idle_stat
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	state = psci_get_domain_state();
 	if (!state)
@@ -82,7 +82,7 @@ static int __psci_enter_domain_idle_stat
 
 	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
 
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
--- a/drivers/cpuidle/cpuidle-riscv-sbi.c
+++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
@@ -126,7 +126,7 @@ static int __sbi_enter_domain_idle_state
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	if (sbi_is_domain_state_available())
 		state = sbi_get_domain_state();
@@ -135,7 +135,7 @@ static int __sbi_enter_domain_idle_state
 
 	ret = sbi_suspend(state) ? -1 : idx;
 
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
--- a/drivers/cpuidle/cpuidle-tegra.c
+++ b/drivers/cpuidle/cpuidle-tegra.c
@@ -183,7 +183,7 @@ static int tegra_cpuidle_state_enter(str
 	tegra_pm_set_cpu_in_lp2();
 	cpu_pm_enter();
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	switch (index) {
 	case TEGRA_C7:
@@ -199,7 +199,7 @@ static int tegra_cpuidle_state_enter(str
 		break;
 	}
 
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	cpu_pm_exit();
 	tegra_pm_clear_cpu_in_lp2();
@@ -240,10 +240,10 @@ static int tegra_cpuidle_enter(struct cp
 
 	if (index == TEGRA_C1) {
 		if (do_rcu)
-			ct_idle_enter();
+			ct_cpuidle_enter();
 		ret = arm_cpuidle_simple_enter(dev, drv, index);
 		if (do_rcu)
-			ct_idle_exit();
+			ct_cpuidle_exit();
 	} else
 		ret = tegra_cpuidle_state_enter(dev, index, cpu);
 
--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -14,6 +14,7 @@
 #include <linux/mutex.h>
 #include <linux/sched.h>
 #include <linux/sched/clock.h>
+#include <linux/sched/idle.h>
 #include <linux/notifier.h>
 #include <linux/pm_qos.h>
 #include <linux/cpu.h>
@@ -152,12 +153,12 @@ static void enter_s2idle_proper(struct c
 	 */
 	stop_critical_timings();
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
-		ct_idle_enter();
+		ct_cpuidle_enter();
 	target_state->enter_s2idle(dev, drv, index);
 	if (WARN_ON_ONCE(!irqs_disabled()))
-		local_irq_disable();
+		raw_local_irq_disable();
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
-		ct_idle_exit();
+		ct_cpuidle_exit();
 	tick_unfreeze();
 	start_critical_timings();
 
@@ -235,14 +236,14 @@ int cpuidle_enter_state(struct cpuidle_d
 
 	stop_critical_timings();
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
-		ct_idle_enter();
+		ct_cpuidle_enter();
 
 	entered_state = target_state->enter(dev, drv, index);
 	if (WARN_ONCE(!irqs_disabled(), "%ps leaked IRQ state", target_state->enter))
 		raw_local_irq_disable();
 
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
-		ct_idle_exit();
+		ct_cpuidle_exit();
 	start_critical_timings();
 
 	sched_clock_idle_wakeup_event();
--- a/include/linux/clockchips.h
+++ b/include/linux/clockchips.h
@@ -211,7 +211,7 @@ extern int tick_receive_broadcast(void);
 extern void tick_setup_hrtimer_broadcast(void);
 extern int tick_check_broadcast_expired(void);
 # else
-static inline int tick_check_broadcast_expired(void) { return 0; }
+static __always_inline int tick_check_broadcast_expired(void) { return 0; }
 static inline void tick_setup_hrtimer_broadcast(void) { }
 # endif
 
@@ -219,7 +219,7 @@ static inline void tick_setup_hrtimer_br
 
 static inline void clockevents_suspend(void) { }
 static inline void clockevents_resume(void) { }
-static inline int tick_check_broadcast_expired(void) { return 0; }
+static __always_inline int tick_check_broadcast_expired(void) { return 0; }
 static inline void tick_setup_hrtimer_broadcast(void) { }
 
 #endif /* !CONFIG_GENERIC_CLOCKEVENTS */
--- a/include/linux/cpuidle.h
+++ b/include/linux/cpuidle.h
@@ -14,6 +14,7 @@
 #include <linux/percpu.h>
 #include <linux/list.h>
 #include <linux/hrtimer.h>
+#include <linux/context_tracking.h>
 
 #define CPUIDLE_STATE_MAX	10
 #define CPUIDLE_NAME_LEN	16
@@ -115,6 +116,35 @@ struct cpuidle_device {
 DECLARE_PER_CPU(struct cpuidle_device *, cpuidle_devices);
 DECLARE_PER_CPU(struct cpuidle_device, cpuidle_dev);
 
+static __always_inline void ct_cpuidle_enter(void)
+{
+	lockdep_assert_irqs_disabled();
+	/*
+	 * Idle is allowed to (temporary) enable IRQs. It
+	 * will return with IRQs disabled.
+	 *
+	 * Trace IRQs enable here, then switch off RCU, and have
+	 * arch_cpu_idle() use raw_local_irq_enable(). Note that
+	 * ct_idle_enter() relies on lockdep IRQ state, so switch that
+	 * last -- this is very similar to the entry code.
+	 */
+	trace_hardirqs_on_prepare();
+	lockdep_hardirqs_on_prepare();
+	instrumentation_end();
+	ct_idle_enter();
+	lockdep_hardirqs_on(_RET_IP_);
+}
+
+static __always_inline void ct_cpuidle_exit(void)
+{
+	/*
+	 * Carefully undo the above.
+	 */
+	lockdep_hardirqs_off(_RET_IP_);
+	ct_idle_exit();
+	instrumentation_begin();
+}
+
 /****************************
  * CPUIDLE DRIVER INTERFACE *
  ****************************/
@@ -289,9 +319,9 @@ extern s64 cpuidle_governor_latency_req(
 	if (!is_retention)						\
 		__ret =  cpu_pm_enter();				\
 	if (!__ret) {							\
-		ct_idle_enter();					\
+		ct_cpuidle_enter();					\
 		__ret = low_level_idle_enter(state);			\
-		ct_idle_exit();						\
+		ct_cpuidle_exit();					\
 		if (!is_retention)					\
 			cpu_pm_exit();					\
 	}								\
--- a/kernel/sched/idle.c
+++ b/kernel/sched/idle.c
@@ -51,18 +51,22 @@ __setup("hlt", cpu_idle_nopoll_setup);
 
 static noinline int __cpuidle cpu_idle_poll(void)
 {
+	instrumentation_begin();
 	trace_cpu_idle(0, smp_processor_id());
 	stop_critical_timings();
-	ct_idle_enter();
-	local_irq_enable();
+	ct_cpuidle_enter();
 
+	raw_local_irq_enable();
 	while (!tif_need_resched() &&
 	       (cpu_idle_force_poll || tick_check_broadcast_expired()))
 		cpu_relax();
+	raw_local_irq_disable();
 
-	ct_idle_exit();
+	ct_cpuidle_exit();
 	start_critical_timings();
 	trace_cpu_idle(PWR_EVENT_EXIT, smp_processor_id());
+	local_irq_enable();
+	instrumentation_end();
 
 	return 1;
 }
@@ -85,44 +89,21 @@ void __weak arch_cpu_idle(void)
  */
 void __cpuidle default_idle_call(void)
 {
-	if (current_clr_polling_and_test()) {
-		local_irq_enable();
-	} else {
-
+	instrumentation_begin();
+	if (!current_clr_polling_and_test()) {
 		trace_cpu_idle(1, smp_processor_id());
 		stop_critical_timings();
 
-		/*
-		 * arch_cpu_idle() is supposed to enable IRQs, however
-		 * we can't do that because of RCU and tracing.
-		 *
-		 * Trace IRQs enable here, then switch off RCU, and have
-		 * arch_cpu_idle() use raw_local_irq_enable(). Note that
-		 * ct_idle_enter() relies on lockdep IRQ state, so switch that
-		 * last -- this is very similar to the entry code.
-		 */
-		trace_hardirqs_on_prepare();
-		lockdep_hardirqs_on_prepare();
-		ct_idle_enter();
-		lockdep_hardirqs_on(_THIS_IP_);
-
+		ct_cpuidle_enter();
 		arch_cpu_idle();
-
-		/*
-		 * OK, so IRQs are enabled here, but RCU needs them disabled to
-		 * turn itself back on.. funny thing is that disabling IRQs
-		 * will cause tracing, which needs RCU. Jump through hoops to
-		 * make it 'work'.
-		 */
 		raw_local_irq_disable();
-		lockdep_hardirqs_off(_THIS_IP_);
-		ct_idle_exit();
-		lockdep_hardirqs_on(_THIS_IP_);
-		raw_local_irq_enable();
+		ct_cpuidle_exit();
 
 		start_critical_timings();
 		trace_cpu_idle(PWR_EVENT_EXIT, smp_processor_id());
 	}
+	local_irq_enable();
+	instrumentation_end();
 }
 
 static int call_cpuidle_s2idle(struct cpuidle_driver *drv,
--- a/kernel/time/tick-broadcast.c
+++ b/kernel/time/tick-broadcast.c
@@ -622,9 +622,13 @@ struct cpumask *tick_get_broadcast_onesh
  * to avoid a deep idle transition as we are about to get the
  * broadcast IPI right away.
  */
-int tick_check_broadcast_expired(void)
+noinstr int tick_check_broadcast_expired(void)
 {
+#ifdef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
+	return arch_test_bit(smp_processor_id(), cpumask_bits(tick_broadcast_force_mask));
+#else
 	return cpumask_test_cpu(smp_processor_id(), tick_broadcast_force_mask);
+#endif
 }
 
 /*


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.130014793%40infradead.org.
