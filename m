Return-Path: <kasan-dev+bncBDBK55H2UQKRBYMDUGMQMGQEDGHNIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B40F5BC6E2
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:10 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id v22-20020adf8b56000000b0022af189148bsf705963wra.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582690; cv=pass;
        d=google.com; s=arc-20160816;
        b=rsvqfFR8+YuMYbojVhSV4BW5U9ku8Iq8zAvYJl2j4A5oUpscBMdfWg2lXORUTlTkJv
         VV+UGHIHhDs4FbS8w3kGrmxMYzCY2Nw0eE1bdQfHE38o5U9AHPMt+Mp1JWpMckn92vuG
         w+6TgGIzrtPVmpofecc8MKjBx41YIvFP/6ztG0Ux0/wafctPqbJaeBCtKPGtAJ77iKEG
         y2XSVp/YyZISL/JUGGo9mXoOv4AM3DClsjJJY6jSLbf8KlMvYUmpqST7o7TuHImW8ajE
         evYqlLfHX5/nDI9qQmFC02WT+s5SSEvbBZiGM90KAsvjx7/Ys5j0Zro4QJNPkMph7/DI
         yjvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=cu+ivppBZ+HyvyThFwpZPqbGZo5T+AkXI9wsQ1PQEsY=;
        b=KmX1KpL5ZlujWDuCW76xJEUXEDiMn1M2IR/JSF5FDpr9BVy2DovJARRpJTfi5/HqRS
         0topalb3xoxFRFkNVG0OQ/tX3noxVDv7k3KQbH8x+TcuH2FwGo/RKJBSScKkuTNwvd1b
         Y8iLnoasyI6QbepBFmNt0sX49xyvBQOcSnyYZsWYd0PHLMwTj3Netqolt7R0pUyA2Oer
         ndz0468zN9R68pwnTO3BT+7wDGFF614IpqCEgIQFJkQ5ulk/Kp8Fnqe2sS1p83U20nOI
         yU6YiSzoGJyIuh14MP7GZcDr8SzU6J3ciEUn8JIF4xdV/D+nEbAOW+9AD2AYumhqCZbI
         r/BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=B6P4IEbp;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=cu+ivppBZ+HyvyThFwpZPqbGZo5T+AkXI9wsQ1PQEsY=;
        b=I03YwDszM9n4zjcU6/wq3c/C/GAQJ9GgDcO4BPFxGYlX3TBJ3CvDs4YmZPKjDdE3Hw
         YqpzuGrm9UBjirUUKC1YzjeePXiogsKHmxoHc/6dW9xWRoilIimwRxLDDJ4qmoqE0dEQ
         31/NTpRwPGw+S+dj9Pe6PeZl2eLhNd7Qe+MDo/vX6uuyxX0YVhoIe0bNhXTjVfQkZbWI
         CQcmwKgN77nt1SXAYzRYnCsQvJ4x0dwSKEulK7YU84307Yw7rhhsrQrh6xhumQmm1VUf
         b2ffvSNVHF2iYgIKPDyrwv9/b26tPxHJymokNn8v37a5oxdDxGg24KN9XuWDZtYTm6f5
         Ym6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=cu+ivppBZ+HyvyThFwpZPqbGZo5T+AkXI9wsQ1PQEsY=;
        b=7FzVgxpHavn7kK8de/APQCN1jDDQJtgzDZwm72P2+ev/kBWuOvkjQv1QZWBWe6SMQy
         U/CCjnjLEvZ06RWhoINNl3jMjNwR0jkR4TdnGmXEhkVlrz/o0zTGk8kQ+uQK7uHlh2Ad
         qoJ20kUOjYveFJIQYKJvGG5kCuPC7i3rUgthCdrvOsL3z4tajeBFrpl50j7UV4enF7vp
         SdF6gVl0yHiwEIeRIVVgAKq9qD/tUH4dQwZLZtJwZ6u46jmseG6/WUInJgeHjQ+5ImIl
         xu5+b/5e4euroRnUp0e99ttqc5x5RC+xWGmv/GCBn+o1sKR0r4H1Gt4IedEGlCdzS0JG
         ucug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf22DZm0cgEVjqMyDZ1Q3WYMs8tCzzAj0uwLiKlIt9meLSi6IKbW
	5LfQj5cLOAyqSRUvQ0AXnUo=
X-Google-Smtp-Source: AMsMyM5J8/s8z9CPRZLlODCpE9i3sonVzrms3bD4jMfxzJbmDlqNzC++9LAsBeZ6KJhwAdPx1J8SUQ==
X-Received: by 2002:a5d:6545:0:b0:228:dab8:af03 with SMTP id z5-20020a5d6545000000b00228dab8af03mr10304815wrv.29.1663582690063;
        Mon, 19 Sep 2022 03:18:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2883670wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
X-Received: by 2002:a05:6000:1004:b0:22a:f5a7:747c with SMTP id a4-20020a056000100400b0022af5a7747cmr5413500wrx.612.1663582688966;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582688; cv=none;
        d=google.com; s=arc-20160816;
        b=dsVUwA9Art9eWwMNLCcJGCRZVgBKPxXSsfNGm/kq15NvO/+DkjsAAc6WfYXNfS+uJR
         HfG276Y1yKuH0kEwbYzhsq8uESCtvELp76TkfuJSyN25L74c8SwJwUiUL4kgSF0jQTr4
         3QWz4VCVc0hE5taB6cXy4XtMWLBU8wi9OoYxgxR3Fj7NIzeaQldzklqTbQ5dXjyrRCBI
         4kov49zPquWS03pxb6KoJW9wsuEP9ma9s6dLBYqGmyiPnjthl7wvjHTdRC0e3CRM6XzJ
         lUv1D1D8KnIL06EaLHKyyqhrZUrahv0L93O1tiCqcWKyaf0QdvAsBehANyxXxQECZqxt
         U3fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=aIisfZps5gh8CFbGfWo9r3lQVFXbgWOaMv4QJgU4z04=;
        b=csJJlK+Veu7FQ57xaTLQdrdy5VHt/ICJIYzRdGtdKJjRaxS0uOw33JV1a9jEnZm51M
         c15krjguismz+zaKR2qpqMvYxfOO1xv97hbQKGz53dQSVoBp0uOupQBxMOpnMI+7ZY82
         +6r7hr2JuoaVrhKtNzRN/PZIZzFAIWDPz1tIcxbs2gaGauEVFwqh2d5gBui6xyzlhk3w
         VTNUQe8aW+7188LCVueuQeuw7RLjKc9YCUfvRbE/Jwr5ruQPlIzEX1Mlay/bqoembHsg
         BcpwcBnqkqIEracd5MrIuQeg3F/XUZmB7dD/IosTVtDyUHdChuTi9OMLyIhKeYbwb2pT
         w9nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=B6P4IEbp;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bk9-20020a0560001d8900b0022a69378414si350981wrb.0.2022.09.19.03.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpF-00E295-MJ; Mon, 19 Sep 2022 10:17:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E286A302EC5;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 0AC522BA49044; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.206622076@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:52 +0200
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
Subject: [PATCH v2 13/44] cpuidle: Fix ct_idle_*() usage
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=B6P4IEbp;
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

The whole disable-RCU, enable-IRQS dance is very intricate since
changing IRQ state is traced, which depends on RCU.

Add two helpers for the cpuidle case that mirror the entry code.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
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
 include/linux/cpuidle.h              |   38 ++++++++++++++++++++++++++---
 kernel/sched/idle.c                  |   45 ++++++++++-------------------------
 kernel/time/tick-broadcast.c         |    6 +++-
 14 files changed, 86 insertions(+), 66 deletions(-)

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
@@ -627,6 +627,8 @@ static int __cpuidle acpi_idle_enter_bm(
 	 */
 	bool dis_bm = pr->flags.bm_control;
 
+	instrumentation_begin();
+
 	/* If we can skip BM, demote to a safe state. */
 	if (!cx->bm_sts_skip && acpi_idle_bm_check()) {
 		dis_bm = false;
@@ -648,11 +650,11 @@ static int __cpuidle acpi_idle_enter_bm(
 		raw_spin_unlock(&c3_lock);
 	}
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	acpi_idle_do_entry(cx);
 
-	ct_idle_exit();
+	ct_cpuidle_exit();
 
 	/* Re-enable bus master arbitration */
 	if (dis_bm) {
@@ -662,6 +664,8 @@ static int __cpuidle acpi_idle_enter_bm(
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
@@ -121,7 +121,7 @@ static int __sbi_enter_domain_idle_state
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
 
-	ct_idle_enter();
+	ct_cpuidle_enter();
 
 	if (sbi_is_domain_state_available())
 		state = sbi_get_domain_state();
@@ -130,7 +130,7 @@ static int __sbi_enter_domain_idle_state
 
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
+	lockdep_hardirqs_on(_THIS_IP_);
+}
+
+static __always_inline void ct_cpuidle_exit(void)
+{
+	/*
+	 * Carefully undo the above.
+	 */
+	lockdep_hardirqs_off(_THIS_IP_);
+	ct_idle_exit();
+	instrumentation_begin();
+}
+
 /****************************
  * CPUIDLE DRIVER INTERFACE *
  ****************************/
@@ -282,18 +312,18 @@ extern s64 cpuidle_governor_latency_req(
 	int __ret = 0;							\
 									\
 	if (!idx) {							\
-		ct_idle_enter();					\
+		ct_cpuidle_enter();					\
 		cpu_do_idle();						\
-		ct_idle_exit();						\
+		ct_cpuidle_exit();					\
 		return idx;						\
 	}								\
 									\
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.206622076%40infradead.org.
