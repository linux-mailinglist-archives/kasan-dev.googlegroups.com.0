Return-Path: <kasan-dev+bncBDBK55H2UQKRB4GMQGPAMGQERVECTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 19845668012
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:41 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id a11-20020a05651c210b00b0027fc4f018a1sf5154252ljq.8
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553520; cv=pass;
        d=google.com; s=arc-20160816;
        b=YFfzqvtQQ3pw2jWZ7nIY13CYzK1FTW8+1/LtwJlPYsfOERBpMgX/VmNVXzR0ZQFQ5D
         XF1gwAAm4YXI8h34UpxcqsaTtCxGuwHT3WQuRgaRJWu7YIJxEeRv2r+y1PzMvVDkUgkk
         DDOMKvah+DQZOYm1BJTjMeAkP2YU3B12KBrfEv5R5ccD3cefCGBNMeDaH/dhZihlcgGU
         fd+Cmi5EUzcJMot5ATPpcQVxhqAt5nn8nSJ2LTIFfGz/XVx+yS8vQdVcJ8EV/lQVdk/a
         Ygqdh4SGzHf1o6kPGKUHQ07akqLJRpJ2yBzA8ZBuAUz1DI8GMUruoTpqHixpVLsdL5P5
         gagg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=AIjGIgDza+9MayOYZC9h4HEz3B4Q7keerwMUXQdHjxk=;
        b=jbQYVLCmBQeses7BFErQOPV73yOF+vsN8nlsvAqRpQ3kTrA9tIQ/f6QgaJNX6zrUFh
         ADj+ZvIeiGUAnyTQ2/OGip9q11Fi4uadIn7WKBcKS0WxBhZT+DIF1zlQf5jz3rlufB0k
         uJ0Hajk7z3qGxV86/qFMdS25SxM0bNqwKt6d6h/U94Om2P36ecmZthjaQHyDj0LMZNuZ
         LSscXu/E8NT+vRz29xuXSwwT1fyZFQ3TnT6YO2b59Hz1GMDkyYfBIn38SKPJFBx/cLVC
         CPWl5ArC+Q+jRCzMenmVOu/KWrkyKF9si3t1AD+sLMgnS+YAmxrPudXqPzItq6p20rXk
         zxHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=FKLIwXsL;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AIjGIgDza+9MayOYZC9h4HEz3B4Q7keerwMUXQdHjxk=;
        b=QsR/sGg8hfFiM6ffhMOeVb1/UF4fVJJ/J7U0vx54Afx4XjifKkyzZf4Iz2V3Mx0beB
         dEHf7F21rTpEKrbTBQgK1bf6CfRu3ZzpE3zxTW3OZGKobvSfpcKt0fP0Lhq8iEOsx/uj
         9ptBmLaERpqXEGqTT8c+ECxAyhyDsiDL99aPvpwR19Br4s8uCKxk+aKMI5Z1cfIk37xg
         gLSyySztet203eM1Jr35jtCI82X+R563R73PbRSvu34AcziNJ8ViBpiki8ZMhNO/BjZJ
         vyY5IYE9imtb41Gyq1uEVnInmmcanB3PT2kbiYHUEQuJGKrfD98vq2LumNecvf83j44z
         Ht3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AIjGIgDza+9MayOYZC9h4HEz3B4Q7keerwMUXQdHjxk=;
        b=ROhDPHFdKZfsY73FO7goXOaYzotdOTK9c7ovj2PMuP2ZYo6efMAG8vDD7jbYkbIVCf
         ZTM6eOBFKtkgiQl51SScG57EWMiLBkLWM9fyyp7k/ZGLq9OsKk9CXdpSNMsdd8rpZExi
         GBf1rGPNEerO+W7h/UFCi4M1ftX81ULJPpjHNFc/+UkFBl7nJgp6kJNJH2abVsPajAW/
         uN959XJO8Bm6hUti2gCjd3Fji1VHtfN3uLL1CTU0AA9ITNOc1wQtSvnP69M9IzE4t4Gl
         Ouos7HDkne0474V/SJgYxNO7IDaxp0MHamEs11J53WBebj7ezUUv5wLiqI0FxkIAGItZ
         hytw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krP3QY9nTRb3dhPvGQ5cDH2Wtjeo7ryDkJ2TrqMa7H1LrixHwOq
	3nqey4NonFvR+Joj7y42aIk=
X-Google-Smtp-Source: AMrXdXu6QExHkUdaQk/qdc+TORvsl3lz+qEzH2kwI7wGrCc29EsVLLpFyktSSg2VTqaSeP4lIjHmaA==
X-Received: by 2002:a05:6512:39cc:b0:4b5:88da:17e0 with SMTP id k12-20020a05651239cc00b004b588da17e0mr5323605lfu.71.1673553520523;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:864e:0:b0:27a:3eb5:4759 with SMTP id i14-20020a2e864e000000b0027a3eb54759ls571115ljj.0.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:39 -0800 (PST)
X-Received: by 2002:a05:651c:202:b0:27f:fc5c:837 with SMTP id y2-20020a05651c020200b0027ffc5c0837mr10294896ljn.15.1673553519107;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553519; cv=none;
        d=google.com; s=arc-20160816;
        b=Ppq+kp6VdiQCkp2S3qPSXTGRn/fthQ2fTc4wKv4957g9YfzH/TC6qdloc2Tiips+YA
         eixbVIJQ7uc0STZZWWTDzrgDA/DPTyWf13qSEHTB85T1b0eSiDEKR5v0HpdeM9mw+HYx
         4F3Er/tP9jW49kuGcrTeS+FQ+oCKJNMAPT+w8i2eH5UBEcsqUMHOasqQ3TJTLd3Z6IxC
         gDin5NlQWuKBCupZeRWmeu6HjSS4sUu9z6mXpUF7SgFIJk3VAApo2fShDV+VzEphYW6X
         agsXroisTjCFsWcBR8ehZNEHOcrn3oFONJJv0QMdUn7cUJreE3jBz2rnSkaYxDqI5ndL
         +R7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=NQmAgIg3861PdWRPD/+8zQmqygF5xIi/7qaj1X27QYY=;
        b=jdRlWVNp+XeQELYwXepqQ+xmlEYzE8sLAdA9m2OD2mpJnN5K7J5pfd/0VbuUrH5iF3
         e7u0yv+Gqwb0lxMZkOVXZquIyeSUZ+t2A+MZNmFMvXdo39wxkhEbOItaV6ng4uW9hNBA
         5jIhVmtjYwtHkvZLk22Gn2ZkLdcJvIN6ms365V5kZdtFXJXMgeZzpdyKwFm0YHp+GM7T
         gdaw32uRf3uVyKzJoc7oLPPfPKl/3TGSNSqfMASkRkQ5HZHiUW/RVGzo6Lx0jLU++Kir
         dgVYR9sXlZfkf9In+MwZhWdE5RvjjIqGMDeXQxMPbJavcGIMg7qWC78pA81I9lzSAYnf
         DuoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=FKLIwXsL;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id b1-20020a2eb901000000b002837b090b3dsi801675ljb.8.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hD-0045oG-16;
	Thu, 12 Jan 2023 19:57:08 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 23CD5303406;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id BF3F52CCF1F5E; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.068981667@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:26 +0100
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
Subject: [PATCH v3 12/51] cpuidle,dt: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=FKLIwXsL;
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
again before going idle is daft.

Notably: this converts all dt_init_idle_driver() and
__CPU_PM_CPU_IDLE_ENTER() users for they are inextrably intertwined.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/acpi/processor_idle.c        |    2 ++
 drivers/cpuidle/cpuidle-arm.c        |    1 +
 drivers/cpuidle/cpuidle-big_little.c |    8 ++++++--
 drivers/cpuidle/cpuidle-psci.c       |    1 +
 drivers/cpuidle/cpuidle-qcom-spm.c   |    1 +
 drivers/cpuidle/cpuidle-riscv-sbi.c  |    1 +
 drivers/cpuidle/dt_idle_states.c     |    2 +-
 include/linux/cpuidle.h              |    2 ++
 8 files changed, 15 insertions(+), 3 deletions(-)

--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -1219,6 +1219,8 @@ static int acpi_processor_setup_lpi_stat
 		state->target_residency = lpi->min_residency;
 		if (lpi->arch_flags)
 			state->flags |= CPUIDLE_FLAG_TIMER_STOP;
+		if (i != 0 && lpi->entry_method == ACPI_CSTATE_FFH)
+			state->flags |= CPUIDLE_FLAG_RCU_IDLE;
 		state->enter = acpi_idle_lpi_enter;
 		drv->safe_state_index = i;
 	}
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
@@ -289,7 +289,9 @@ extern s64 cpuidle_governor_latency_req(
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.068981667%40infradead.org.
