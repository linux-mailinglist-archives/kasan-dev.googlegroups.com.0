Return-Path: <kasan-dev+bncBDBK55H2UQKRB2EDUGMQMGQE744X3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C1CF25BC702
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:17 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id i33-20020a0565123e2100b00498fb105ef4sf9570984lfv.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582697; cv=pass;
        d=google.com; s=arc-20160816;
        b=DjLa1+5Tt95TL8XcFx/EqySYAzwjXw9nsW3BLAp7Jb0W2LCRZ6HQjnJlr+szh1CBsl
         tJPcbPMBElTohyoi8uF2uIC89EGHSsGWAyrHXBrxAKROjwgmLdoewVoaKUha1rlmw40K
         gqXO2rV7N4jlSVNbRP1hpAfixa8t2Pq/qz2g2haGr/C9Q420RM1wSgVsUF739ff/g4w8
         ERcV5oZhsTMFZe69xQFjNSp0zNJQAoosVok8L6/DYdNWONCN/K5g6MuefK4i64AViEqJ
         b//wFMnarZKG1Lt8kC0DgxOE85GhmFAFuTohaKjsU1PKRTCAtVGa/MfHkTm3xzbD4r/g
         gh+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=ixyuINqlckFIJPDwsGNISlbpCPCoXhr/A3PNvPur2qA=;
        b=HYyVk8efRvGucoUneDlL4L05zEpCyg/fY4woKhXU/O3K23MLLCzeq6bzlCw3GrmuB8
         t9I19f+dXdqaWxE4JoOACcxYte1yh1oXl72XPjfUp6RhHpH024NPCiVoVHgneIgupv+Q
         Pmxks3JoUg+TTmIIfZuWQuc7PYhHowCt0JDHb23VJxijRJ1+sVhIvSxaESsHssER0M1g
         CAT+ivUMnfjQzAWAhn48LB2E0axC4jf9Nj+VaWAI41G/nqS7WiXtb9wac/pHuOIMXGZV
         EoNs3IitoEwtg6kbC6frGaCl2ImrLwJ7l6QXWK4l7qZClDN9M/tnIhr4Mdo3jFId4b6a
         MYxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=fh6jTDX0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=ixyuINqlckFIJPDwsGNISlbpCPCoXhr/A3PNvPur2qA=;
        b=Y7lK+hP/rCYRM/CwJK1L7/zQklWaOPscm8GsYz8/z8c3qPTVMGXQLNHCziw5myQ7qH
         h8vBOyXnP7grUWzourKDPkOLpIlxT9EOaP8dJayPl8gWXc8aOdn0RRSqTKhhWHWarDuA
         NrvBcJuD3VdZ8pkXs6W4xGzOF9ZAXIyXJti/mhkbFkKOUmG4qblspcRxqJWvRC/BYI0x
         VUXBo6i6AEIvKr78cmOumtT89lrsgM9OTIITVshxT1usz1LQQyrcQLThGuh9xnfDzj2G
         W8nSEc03QeR80O/Ne5vYzPATI2v/QMw1hZdHZwWHYF9Q5X33bCb9xjlsp/rb1u9lEOqk
         ZsNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ixyuINqlckFIJPDwsGNISlbpCPCoXhr/A3PNvPur2qA=;
        b=TDUReVm+heKbv7lOfFGFG+87ZFKeqGJsGljeZj/zbq6WP2TXeriHRX01wNHt3E8C9t
         z5kDb6KVasTdosYXarTZHXZvB/ljLjZtfRqewpymYx/7oMPRcKX0cVQI+KKFUsGQh1UI
         OnUNxteYHJbk3n1OEyChBCv3oqqZDjPz1r1Cjmm+fELhoRl0cxJFUa5xv3fuBPaGjYLr
         nNrhYW9yAObJlQcbI2TEodOCNPe01qbV8HO4z1nRPCIILspfeSzbYcuou69rZnrP0sI0
         TduUWPe8r/aeNPHeCvgURjnTT84VmYhCJVYnCRueT6mkcAsh0RzN02zU4YvyEcJt9u6V
         L2kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3CtA66eRfpuvgb4z/n52e7L56NoLGT8RtQ4bacTGAUyIpT/9Gs
	M+mT/Lie+MzhPzXbVv+e7no=
X-Google-Smtp-Source: AMsMyM64nrJ/RCPtBESQdItex6KFrftfcMVY4UWl62hv7PVq8GKakSTgBCCugFlcXp7dWf5SkAUoGQ==
X-Received: by 2002:a05:6512:3b0a:b0:49a:7ce8:c450 with SMTP id f10-20020a0565123b0a00b0049a7ce8c450mr6550138lfv.231.1663582697161;
        Mon, 19 Sep 2022 03:18:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f7a:0:b0:49a:b814:856d with SMTP id c26-20020ac25f7a000000b0049ab814856dls556392lfc.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:16 -0700 (PDT)
X-Received: by 2002:a05:6512:401f:b0:49e:ea65:cd49 with SMTP id br31-20020a056512401f00b0049eea65cd49mr5756273lfb.419.1663582695914;
        Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582695; cv=none;
        d=google.com; s=arc-20160816;
        b=DQW0rgNPMtfCyyoivEjFbGYtNrLPp/UR3ZnJ7s0qUxQPcqtHYUnwS+nckeSaYg5b2a
         lAUjgvQFJzJZ+xzvZNoaotVzu7qoPj1efsZimcu0E8r/CdxkBlk4KxuhcpKGkI0vX7Iv
         rNORaJPsdg6NxCpiqeE5LfMSNANX9f8rQb+nVJY6COP9vCYJI51TdUeyc8HMYIxNdghW
         IbDCkrFm7PEb8F+j4HofAWy3Xj3tqtDceIejduKNaFfXuWhZwnfg02I61Q309uRqp1tb
         2ve6Gx93aNKL7p/kWpbkBdZR1uwBM8uEwaFssMxU/rdLfoZB2OnACClc8ak1ssS3NVzW
         q57g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=6o9qTJ/QjCltP+zmu0PkeSqB0nVcTaPJ8iw1lVGI/YI=;
        b=wFHrzGGOZ3HufcsKjaS0Z74V3y0GQC465COvcmShIT43+pauizeB8IKTB6/mzdTOfV
         itfBEH+ZfVVqp7xq8tqTUBp68R1ZdDxnsSdncL+m4orv23o/LuwmZiruZtsUc5cUgRBM
         f6mwnmbtIq1zBmJANeIyFlPvjMCIJEOk+QYvLjK7quhPpupzamiV/eXZnxoNo1ad2Spi
         xwSSqUe2utB5Vc6JHeKebO1Up2JhD7MZ5XhXx/zUPsZDCBhpa241/+H9YQsEambTLEpq
         hyAgO4sZxDYFFNoiDo7l7bRBiWID3xAD+u2vea6F1vwLGnapOQXc0TfHdLlJssR6m5sl
         4JeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=fh6jTDX0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id z13-20020a056512370d00b00498fd423cbdsi743318lfr.7.2022.09.19.03.18.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpF-00E291-1B; Mon, 19 Sep 2022 10:17:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DF7A1302EAE;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 052C92BA49043; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101521.139727471@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:51 +0200
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
Subject: [PATCH v2 12/44] cpuidle,dt: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=fh6jTDX0;
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
again before going idle is daft.

Notably: this converts all dt_init_idle_driver() and
__CPU_PM_CPU_IDLE_ENTER() users for they are inextrably intertwined.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/arm/mach-omap2/cpuidle34xx.c    |    4 ++--
 drivers/acpi/processor_idle.c        |    2 ++
 drivers/cpuidle/cpuidle-arm.c        |    1 +
 drivers/cpuidle/cpuidle-big_little.c |    8 ++++++--
 drivers/cpuidle/cpuidle-psci.c       |    1 +
 drivers/cpuidle/cpuidle-qcom-spm.c   |    1 +
 drivers/cpuidle/cpuidle-riscv-sbi.c  |    1 +
 drivers/cpuidle/dt_idle_states.c     |    2 +-
 include/linux/cpuidle.h              |    4 ++++
 9 files changed, 19 insertions(+), 5 deletions(-)

--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -1200,6 +1200,8 @@ static int acpi_processor_setup_lpi_stat
 		state->target_residency = lpi->min_residency;
 		if (lpi->arch_flags)
 			state->flags |= CPUIDLE_FLAG_TIMER_STOP;
+		if (lpi->entry_method == ACPI_CSTATE_FFH)
+			state->flags |= CPUIDLE_FLAG_RCU_IDLE;
 		state->enter = acpi_idle_lpi_enter;
 		drv->safe_state_index = i;
 	}
--- a/drivers/cpuidle/cpuidle-arm.c
+++ b/drivers/cpuidle/cpuidle-arm.c
@@ -53,6 +53,7 @@ static struct cpuidle_driver arm_idle_dr
 	 * handler for idle state index 0.
 	 */
 	.states[0] = {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter                  = arm_enter_idle_state,
 		.exit_latency           = 1,
 		.target_residency       = 1,
--- a/drivers/cpuidle/cpuidle-big_little.c
+++ b/drivers/cpuidle/cpuidle-big_little.c
@@ -64,7 +64,8 @@ static struct cpuidle_driver bl_idle_lit
 		.enter			= bl_enter_powerdown,
 		.exit_latency		= 700,
 		.target_residency	= 2500,
-		.flags			= CPUIDLE_FLAG_TIMER_STOP,
+		.flags			= CPUIDLE_FLAG_TIMER_STOP |
+					  CPUIDLE_FLAG_RCU_IDLE,
 		.name			= "C1",
 		.desc			= "ARM little-cluster power down",
 	},
@@ -85,7 +86,8 @@ static struct cpuidle_driver bl_idle_big
 		.enter			= bl_enter_powerdown,
 		.exit_latency		= 500,
 		.target_residency	= 2000,
-		.flags			= CPUIDLE_FLAG_TIMER_STOP,
+		.flags			= CPUIDLE_FLAG_TIMER_STOP |
+					  CPUIDLE_FLAG_RCU_IDLE,
 		.name			= "C1",
 		.desc			= "ARM big-cluster power down",
 	},
@@ -124,11 +126,13 @@ static int bl_enter_powerdown(struct cpu
 				struct cpuidle_driver *drv, int idx)
 {
 	cpu_pm_enter();
+	ct_idle_enter();
 
 	cpu_suspend(0, bl_powerdown_finisher);
 
 	/* signals the MCPM core that CPU is out of low power state */
 	mcpm_cpu_powered_up();
+	ct_idle_exit();
 
 	cpu_pm_exit();
 
--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -357,6 +357,7 @@ static int psci_idle_init_cpu(struct dev
 	 * PSCI idle states relies on architectural WFI to be represented as
 	 * state index 0.
 	 */
+	drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
 	drv->states[0].enter = psci_enter_idle_state;
 	drv->states[0].exit_latency = 1;
 	drv->states[0].target_residency = 1;
--- a/drivers/cpuidle/cpuidle-qcom-spm.c
+++ b/drivers/cpuidle/cpuidle-qcom-spm.c
@@ -72,6 +72,7 @@ static struct cpuidle_driver qcom_spm_id
 	.owner = THIS_MODULE,
 	.states[0] = {
 		.enter			= spm_enter_idle_state,
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.exit_latency		= 1,
 		.target_residency	= 1,
 		.power_usage		= UINT_MAX,
--- a/drivers/cpuidle/cpuidle-riscv-sbi.c
+++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
@@ -332,6 +332,7 @@ static int sbi_cpuidle_init_cpu(struct d
 	drv->cpumask = (struct cpumask *)cpumask_of(cpu);
 
 	/* RISC-V architectural WFI to be represented as state index 0. */
+	drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
 	drv->states[0].enter = sbi_cpuidle_enter_state;
 	drv->states[0].exit_latency = 1;
 	drv->states[0].target_residency = 1;
--- a/drivers/cpuidle/dt_idle_states.c
+++ b/drivers/cpuidle/dt_idle_states.c
@@ -77,7 +77,7 @@ static int init_state_node(struct cpuidl
 	if (err)
 		desc = state_node->name;
 
-	idle_state->flags = 0;
+	idle_state->flags = CPUIDLE_FLAG_RCU_IDLE;
 	if (of_property_read_bool(state_node, "local-timer-stop"))
 		idle_state->flags |= CPUIDLE_FLAG_TIMER_STOP;
 	/*
--- a/include/linux/cpuidle.h
+++ b/include/linux/cpuidle.h
@@ -282,14 +282,18 @@ extern s64 cpuidle_governor_latency_req(
 	int __ret = 0;							\
 									\
 	if (!idx) {							\
+		ct_idle_enter();					\
 		cpu_do_idle();						\
+		ct_idle_exit();						\
 		return idx;						\
 	}								\
 									\
 	if (!is_retention)						\
 		__ret =  cpu_pm_enter();				\
 	if (!__ret) {							\
+		ct_idle_enter();					\
 		__ret = low_level_idle_enter(state);			\
+		ct_idle_exit();						\
 		if (!is_retention)					\
 			cpu_pm_exit();					\
 	}								\


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.139727471%40infradead.org.
