Return-Path: <kasan-dev+bncBDBK55H2UQKRB26MQGPAMGQEXK2OTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11662667FF3
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:36 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id v19-20020ac25933000000b004b55ec28779sf7280510lfi.8
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=oSUm3iJEnHLSuTirMlp/K4fDAgigNv7XyZaopIZl1525g/mdCQpmhE89JIVF1Uah9H
         41BK6fNrrTr2PI/0PfgYYVnNqvqwNFSdjJMcs0qHtSOLj5p5dkpP7lDLimrxiqVRCjC2
         s5attMwY818i0azai+njNmzOZSBj5yqQuJ66+lb2jwFZX+DAnQlRX/jlLqqNoaxLMQyp
         a7J/vZUgiA3DVoyHkJKIh84EaRZaRoo+jZy5pw36a1sVzbolEZ1eMhEoCXYnTqi9U6OI
         GSA77XbGBGZC6DUkW8NlOcPYtjBruzIg0cuA1rFnv1ePB5lSG806/4dF6H+9ugKR12TL
         lUmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=G9V7aIxTv0s8UOpxEAv3x3sSBSDTkdxW09HaeDDADdk=;
        b=JzZ9FIA4PN54qunDPKYjMekUMhILmmEFPgggZauCRhinIZ3/cCkIP7fHU5QkIBbSmC
         GQ99KPpIDkrySzwQrB4DoRc9RxSNH8BkvKnbqHWMJv/ECDNi1BpQ3eCX8+SU6Fg8neJf
         o4PzK135K3EbV63HflhDENm0CMY+S19/YNrULsIb2W3qf2njUZ2m7k21ZZpcSaaOLztc
         cn88BVKpvkG7O9Sg4ehuH9Oj19KR5zyVgKMlOOH7JI7fw7fjvRUp6XQ9AKxr8rRLnWSB
         DT2O50s8hkppgNTgX+vkkfe5PL2IzJ0i2FsBD0+e3tAk9ONr5RU6UnqOaB1C/9ya4VJd
         CbWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="d/lf+QKI";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G9V7aIxTv0s8UOpxEAv3x3sSBSDTkdxW09HaeDDADdk=;
        b=KuXmlGa57Z2SsYWmfTkdMW5dSxsLrYfZfWS1S78q2wR5xagungFjzYRhdqF30iYEZw
         8TnWC/atCYmTwuqRAQldqb1r3o/9XsANOk1/DhtUz/jRszubg0Osd7LHP4lCD+foC8We
         1sEOqDNGZgRKg+eoidaSuuZLsZq5cZmp61P0YmxPpL7xniF5Yi1vmFE44z2vdNTMvqJe
         Z0qvxZbxBZAu9wa8o6guv59fCE0Ec+5fIH0XpY+r5zmAwxGhhl3DW/QdhxOVOwpltsnM
         9nns1XYYfVBCn/O523J+HoXFFgrCUx2SdwCydGNBmBnZhon+1XVp+vsKHxedorboRhQ3
         pbjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G9V7aIxTv0s8UOpxEAv3x3sSBSDTkdxW09HaeDDADdk=;
        b=lJedGc6AUlysJeNmYSTk3G/Bw1JQzTTugiYt5x4A18KOeWRZNawlGTaXH+OsHG/Ag4
         JxA4JCx2pc4+hy2i0l4TyXdTrmZ7CpcK48oaXbgU3PGCJg2Cl++4YXtXDgPFaGL9WauL
         oAPM2L0QYfXoxrG6DWqSdJw0UgNGVf3ffvscEz0PQF+X9plCLJfw3/ieX4Rh7jnwT/LL
         Z/tHWuxLLtCZhwfBTphubZfrPw8dl4IPzFRsuBVSUN2/ocwz/PN+5OgrFsRM7XQtaClH
         J7Wzb+v1t1NvHgWGmYjjK4UwYcwjiZEX3lG4gIqMatIVb4JR9TyyiAh5OpmoKYhNJdtZ
         z4UA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpfxB+zY1kae65OAYAbKtH+RJ3+FgYKZwqxnIpwR3NKvc7rhkaA
	4IOBYsnhenUZQ24+SeFUuKk=
X-Google-Smtp-Source: AMrXdXuU6ZhmO/5XSzKI+aQ0Niw16Z1WizXorKiZizvHBzDqty6YJ+54fBv9Plk48PFoEUSjSlX/cw==
X-Received: by 2002:a2e:9d0c:0:b0:279:f1ed:b540 with SMTP id t12-20020a2e9d0c000000b00279f1edb540mr5103836lji.125.1673553515445;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935371lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:34 -0800 (PST)
X-Received: by 2002:a05:6512:3c89:b0:4b6:fddc:1fcd with SMTP id h9-20020a0565123c8900b004b6fddc1fcdmr5030347lfv.23.1673553514215;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553514; cv=none;
        d=google.com; s=arc-20160816;
        b=r/D0Dg4RdKkC5IB15bazzhMEdNZUSGkzE8BGK7TmW1AdoA2VKVjMbZJ1asBJeIBH73
         xqWYT4hyfMNs9JOUlmyAjGfWMIC9nPsyaknV1rMaqhYFxYJ+ydRwcB/0fWhQypQ7mqYM
         B9Rx98owYBkNhUJidQI/m0lJBXfGvYJJtGgPgdkCo6ucOilYSrn+vNoqK/qTbmZldlTH
         l8xmRgLEWMYHK7Scb5R5u4qaz8blV2xHsZI+DYnlKM3h76vyUl19brBJmFrnetcvwDiX
         3J0bmBuwdUlKwZsHN4Hf7iIuXrJ76/8c0czJomE5/SUtn4uwZAGH8v2DSIrF/h+VJpP+
         wi4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=tPOdw9LFGiPCDTfwXmDjC03yH+Atd2yWpwgqK4SP6Bs=;
        b=zMQWFovJLjD5K+lEwAnLoov66rOdtbPELB8XWr7aDk7jq25ms56itKpMcuPSG1AwMs
         kksCLQrjAINc1E1oqCaexzMEZyx/YODSfvuBWRtwiIDk6coyrZV4NceKNDG9SFuWH2Np
         JM1LMolhgNNWPnsHtnzi1U7CSckQ4Dh3zzLU5iEJuOVWqwKRdc7GZ6j2FSEZkhaNhY/e
         IoFB/eFDlP2HvH2lyGC/Y17GAiOUZi+YSQDeglma9RL9085totVrmcaSoR/B1lunlMcE
         UgeGkS2O/owQijUYzM2IiUMm+x6uFn8DhZLJnwiphEMNKY0GcTRHFQrovQtKfE9LiGfT
         o3YA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="d/lf+QKI";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s5-20020a056512314500b004b59c9b7fbdsi795312lfi.7.2023.01.12.11.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hX-005OcI-5h; Thu, 12 Jan 2023 19:57:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 23ADA300C6F;
	Thu, 12 Jan 2023 20:57:11 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 9180D2CCF0C22; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.453613251@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:16 +0100
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
Subject: [PATCH v3 02/51] x86/idle: Replace x86_idle with a static_call
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="d/lf+QKI";
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

Typical boot time setup; no need to suffer an indirect call for that.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/kernel/process.c |   50 +++++++++++++++++++++++++---------------------
 1 file changed, 28 insertions(+), 22 deletions(-)

--- a/arch/x86/kernel/process.c
+++ b/arch/x86/kernel/process.c
@@ -24,6 +24,7 @@
 #include <linux/cpuidle.h>
 #include <linux/acpi.h>
 #include <linux/elf-randomize.h>
+#include <linux/static_call.h>
 #include <trace/events/power.h>
 #include <linux/hw_breakpoint.h>
 #include <asm/cpu.h>
@@ -692,7 +693,23 @@ void __switch_to_xtra(struct task_struct
 unsigned long boot_option_idle_override = IDLE_NO_OVERRIDE;
 EXPORT_SYMBOL(boot_option_idle_override);
 
-static void (*x86_idle)(void);
+/*
+ * We use this if we don't have any better idle routine..
+ */
+void __cpuidle default_idle(void)
+{
+	raw_safe_halt();
+}
+#if defined(CONFIG_APM_MODULE) || defined(CONFIG_HALTPOLL_CPUIDLE_MODULE)
+EXPORT_SYMBOL(default_idle);
+#endif
+
+DEFINE_STATIC_CALL_NULL(x86_idle, default_idle);
+
+static bool x86_idle_set(void)
+{
+	return !!static_call_query(x86_idle);
+}
 
 #ifndef CONFIG_SMP
 static inline void play_dead(void)
@@ -715,28 +732,17 @@ void arch_cpu_idle_dead(void)
 /*
  * Called from the generic idle code.
  */
-void arch_cpu_idle(void)
-{
-	x86_idle();
-}
-
-/*
- * We use this if we don't have any better idle routine..
- */
-void __cpuidle default_idle(void)
+void __cpuidle arch_cpu_idle(void)
 {
-	raw_safe_halt();
+	static_call(x86_idle)();
 }
-#if defined(CONFIG_APM_MODULE) || defined(CONFIG_HALTPOLL_CPUIDLE_MODULE)
-EXPORT_SYMBOL(default_idle);
-#endif
 
 #ifdef CONFIG_XEN
 bool xen_set_default_idle(void)
 {
-	bool ret = !!x86_idle;
+	bool ret = x86_idle_set();
 
-	x86_idle = default_idle;
+	static_call_update(x86_idle, default_idle);
 
 	return ret;
 }
@@ -859,20 +865,20 @@ void select_idle_routine(const struct cp
 	if (boot_option_idle_override == IDLE_POLL && smp_num_siblings > 1)
 		pr_warn_once("WARNING: polling idle and HT enabled, performance may degrade\n");
 #endif
-	if (x86_idle || boot_option_idle_override == IDLE_POLL)
+	if (x86_idle_set() || boot_option_idle_override == IDLE_POLL)
 		return;
 
 	if (boot_cpu_has_bug(X86_BUG_AMD_E400)) {
 		pr_info("using AMD E400 aware idle routine\n");
-		x86_idle = amd_e400_idle;
+		static_call_update(x86_idle, amd_e400_idle);
 	} else if (prefer_mwait_c1_over_halt(c)) {
 		pr_info("using mwait in idle threads\n");
-		x86_idle = mwait_idle;
+		static_call_update(x86_idle, mwait_idle);
 	} else if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
 		pr_info("using TDX aware idle routine\n");
-		x86_idle = tdx_safe_halt;
+		static_call_update(x86_idle, tdx_safe_halt);
 	} else
-		x86_idle = default_idle;
+		static_call_update(x86_idle, default_idle);
 }
 
 void amd_e400_c1e_apic_setup(void)
@@ -925,7 +931,7 @@ static int __init idle_setup(char *str)
 		 * To continue to load the CPU idle driver, don't touch
 		 * the boot_option_idle_override.
 		 */
-		x86_idle = default_idle;
+		static_call_update(x86_idle, default_idle);
 		boot_option_idle_override = IDLE_HALT;
 	} else if (!strcmp(str, "nomwait")) {
 		/*


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.453613251%40infradead.org.
