Return-Path: <kasan-dev+bncBDBK55H2UQKRB36MQGPAMGQEA3JMCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 27B5366800C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id g24-20020adfa498000000b002bbeb5fc4b7sf3193923wrb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553519; cv=pass;
        d=google.com; s=arc-20160816;
        b=MWq0x+NBIaor/Avbw7h45DvYweqSvlGjFHaFCFQ8PXEnrNe1pLvP93ubesZrCNAk4v
         xupdHJZd5STU+fPl49Q0BR/DRtwM5oa7roPi3DbWuStDG4toVr9Yn1av93NYQIaNE9yh
         utbYavKEvODqghbEQBY+yO+pQasdpDdS+iMyRvkHaqa5XICXfDJtPwrUJs/s894lsZ2J
         7djIH2pddI5dTAthA4KEfg0XzMLkcz7/w4t3v3dRwU/Qs4XMWVFbPxYQHVgvrV/572UE
         tfXLp7+iOX1w+Oi/IAhI2ufnF1g+yTADgKxYPCfbknaQM+W/0Q7itmKyY+CI4RCS0dNU
         xMEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=EyFmgm/B6jadtSxRPcvX9+gObgQHEypt+IA24V46aZo=;
        b=NE6MxGuQqbQ7c5wazr3ZLSuwkXMHaH4ziAtXV4XJuKs9RqWQ0ePUpGOmqUFjQdHsnz
         LxM3rw4xCCL23AaujPc1jhjft2Bbf+8vYQEmCxXfiwD54i3RoZSxl7hN/JNhrA0mLyH4
         +cpTw/p7yMV5ReOmdN+nDmBid4bdqt4GNf9+fiBH6RNeyzw8/JNONKpsIQ+2+IsNX+GQ
         X/GUkTopL9I9JKywwl88lOMvPOhsGcfUPjGe+04k2CCU3tAlU1urCzMpz5s1o3Fg/nSg
         bpq9aW+JTTQiLbKgP8+pVPFPX6zyHm1FxTak5o2lvMeMLiXln5sX3zk0Bge45mtqcwly
         I+BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZubM8vIp;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EyFmgm/B6jadtSxRPcvX9+gObgQHEypt+IA24V46aZo=;
        b=Cgb5AkXm+fetuiBaYt1qBwOvy/posyZSVOf+xCR79sVOidvylkWcLCGHlnA/w/xF46
         mpegxSWim/vPdQBe8kTOPgio/zsqowFR4fzSuBIc1UCjpy3mBcZM/+D7dzsGs6lS3NrN
         DXLkeZ6mEvSLoOQkIunOkpirlUN2XnPRjd4esgc7ONJTWoyCPVAGNr7K6ItQfarz4nIe
         vItjW+oatozQMINDTGJH5a6H8tJMzQHZSsv4dpswQldUkoV/7tMvgeenyQQxupWwYnpL
         8HC8Z12/vCu6HyXaHH7XX/BO514hZBUxyrlVkdaYmcW3ZFxwsNmX4A2cVeLg58e4Dl+d
         IROg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EyFmgm/B6jadtSxRPcvX9+gObgQHEypt+IA24V46aZo=;
        b=NwfPnY7oDPoUHkXIHQJ4Z4XZqxV1eC5/1JALSpFQD+RvZjF5woN9X0EQSXmsM/vn5f
         ef0JlAZoNwPHdXVtTptWL8UwYN9nVvMfYrgzOg3RAmLY3VDg0FgHvj5Ub7El/7OeBRt/
         mDVS2sWHosMYaaxcSlgkPhnjjDpuSncKgwp0h9sgCfw4Mo0ZMhu2ij5HI2DUmdMKWBFy
         GKg48a1FBP56UElMyRciHvpBBkg3EsjrhuDE/EPEw6W9QGubpsd/KL3tbl0uzqRPJIVa
         TUUC+M7kzFfK2zRsKci3uhyPvl1rpjoR0aa/N12uqwb6rn+KXAuSeTKIOh22YecOWMjE
         XfCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko73XlQq4XS+yufzwy9/cukYsQ6OeMssr6OR/L4YeJRgPb6TtXi
	2uqYOlatiR4ZK8A28Qy+Gqg=
X-Google-Smtp-Source: AMrXdXtr5v7Gnf8HhGDlUWGpZMb6P6iMtChwOGQqkSl5N3jjdcNXYHq089RZsutHc5P6cFlCrNEDHg==
X-Received: by 2002:a05:600c:4615:b0:3cf:8e62:f748 with SMTP id m21-20020a05600c461500b003cf8e62f748mr3611944wmo.175.1673553519680;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:e909:0:b0:3d9:c8dd:fd3f with SMTP id q9-20020a1ce909000000b003d9c8ddfd3fls1628106wmc.0.-pod-control-gmail;
 Thu, 12 Jan 2023 11:58:38 -0800 (PST)
X-Received: by 2002:a05:600c:3596:b0:3d2:3b8d:21e5 with SMTP id p22-20020a05600c359600b003d23b8d21e5mr55368317wmq.14.1673553518510;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=pmA2FgGgJ4faSZIZHlGutrJ9BfD4MgcMxCR442aeCuRAEQILjtQd+hghATG3yGHKk1
         jMjQoc5xzZSaoSVQ8jB7uGobThGnCDImLAMKMRWcQTjCgaYGAlVUlyQpdURMNm6X/Uyt
         Y7v7PKFIDDnW8TBLSxXkLmI6KR7gKjk3PC9XY/Nivk0Kl4JmGUcZtiA9nogHV5GG/ArW
         72qejl0DxURsw7SlZQjeIW0MioQtU9w5ihIhm5hU2AAC1/fO55u3TnPdvyKNSZyrv6om
         YeICe8QqkZclnXAmdS6tD3UxiuRtu1a3bNMQ89yfi0/Y/j/i5aplO7N5Zke1idqemzYy
         xrTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=REiFsq8Cu55BI5UIL8KISCBnMH5PlDDv/02JyaHCfws=;
        b=ka4PJckBZCipuEX1opfx9SksOJCKiEB0nlxIEUEK4oDB/P6NpA6sFl2VXf9eR/YPWu
         4PYCXoM6t+bWLG6uSiit7KoS2Xs4evUGirKkUG/FaE9AUajgMudloCxO4t83m55UsSdd
         /J0j+n3z0Sm+P59/vu+79dpszqJUTQn3oZs6qHvxUOUHVpUh/fcwVK4AbgHdzOJA9GxI
         ltrOdRqLNA2SeLaYLwTy6AuMfY4ORdKhy+VlM4DnlT+7WDnvyqFTDmqhoHTSDpeucwAH
         Dlgbfw8CKBar0qMqEjbJ+HMYSbGrU6YJLdXWrRNf9bQyu2Y+oHGc8FA9R00FFnvGk61a
         7+Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZubM8vIp;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay38-20020a05600c1e2600b003c9a5e8adc5si1075734wmb.1.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hC-0045o7-1O;
	Thu, 12 Jan 2023 19:57:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 016663033EC;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A81F92CCF1F5A; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.760296658@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:21 +0100
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
 Kajetan Puchalski <kajetan.puchalski@arm.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 07/51] cpuidle,psci: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ZubM8vIp;
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
again, at least twice, before going idle is daft.

Notably once implicitly through the cpu_pm_*() calls and once
explicitly doing ct_irq_*_irqon().

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Reviewed-by: Guo Ren <guoren@kernel.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Kajetan Puchalski <kajetan.puchalski@arm.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/cpuidle-psci.c |    9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -69,12 +69,12 @@ static int __psci_enter_domain_idle_stat
 		return -1;
 
 	/* Do runtime PM to manage a hierarchical CPU toplogy. */
-	ct_irq_enter_irqson();
 	if (s2idle)
 		dev_pm_genpd_suspend(pd_dev);
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
-	ct_irq_exit_irqson();
+
+	ct_idle_enter();
 
 	state = psci_get_domain_state();
 	if (!state)
@@ -82,12 +82,12 @@ static int __psci_enter_domain_idle_stat
 
 	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
 
-	ct_irq_enter_irqson();
+	ct_idle_exit();
+
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
 	else
 		pm_runtime_get_sync(pd_dev);
-	ct_irq_exit_irqson();
 
 	cpu_pm_exit();
 
@@ -240,6 +240,7 @@ static int psci_dt_cpu_init_topology(str
 	 * of a shared state for the domain, assumes the domain states are all
 	 * deeper states.
 	 */
+	drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
 	drv->states[state_count - 1].enter = psci_enter_domain_idle_state;
 	drv->states[state_count - 1].enter_s2idle = psci_enter_s2idle_domain_idle_state;
 	psci_cpuidle_use_cpuhp = true;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.760296658%40infradead.org.
