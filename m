Return-Path: <kasan-dev+bncBDBK55H2UQKRBLUDUGMQMGQEUE3RGAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 70C065BC64D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:19 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id v22-20020adf8b56000000b0022af189148bsf705342wra.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582639; cv=pass;
        d=google.com; s=arc-20160816;
        b=EaMoighCpWptWegO1t9uVm5k2OAIbQO3ymqVseqV5hbPRJJIG6GFdI0r4ajqpY2xod
         I3jV1O9FIoP4oTdB8pJJ7TwPi4yp16HVgrFSnt3z1fqaj5XLR8RocAxwPFdGtpkJTF1D
         u4kzxnJg7QfyWDSn8j8G/wvWW6McTJveWTaKGk2zZ+v2bCikOPjrfgOmecBlGuXVpLRq
         Gq8oM46MAPmXJ/NSSGHtbB9HlpIvAMI2Nawt/pOT42fBbgg95hJu+038ItLcKkEPUvjN
         NYkSMzyiDzKLf5sTfmclbyr+/id0Pg2USJsu+DCr9b+PQgw5sJM4tknyjVQqIKVoIdRi
         P/VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=4ueGPg0IEp+e9sVl0EIVLzuILXsOa2bK2kL9OTkw2H4=;
        b=nvbJSq3hbJXe+/EQpHzCCXK85F181xbkMS2PetTzfOLS7b+UVmOrcJtaM3jeluwci5
         C2F++JWNN9MqWvHnipIlgIO1AoQnVmBDoUmjKucTcv5YZyedq/NKsBPNxumG/HaeNYGO
         KJuNDU5WPKlrb4KQON6vcLe4yJ/h2QZeFuNpt5FnVPjDJcVdDXKClGglWkKVTHD5ChM0
         8MeRek6wU85ak5tYntilhZWXReYHcOITHi9yhZT1c8gV1+l0EbnTlQzuYfmKsa44xjpP
         UqkW4n8igmx2idsBq5FMU/AUbv3R+3F6VY5Q4Fi9+Ai1LzFm/QHjPnHGqjTfSJ1EPeAM
         u6BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Pu2ax4C+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=4ueGPg0IEp+e9sVl0EIVLzuILXsOa2bK2kL9OTkw2H4=;
        b=RWZ4FMNVGAXzsNQsAXJc9buZu3mle74x/INb6RmZtHyfDI/t/9Hs/SETefa6NjJDFX
         Ep8kNaXRKk6WkK3TARcZBBaToJuaJTPbsP9uFY36rCQPbjppfxMeppunDELPhbnnudWT
         8E4Uy8DXG/AI0BFiOKtms2AquQ63iaETiSZm/NwOAviD9qkySGOtG76jiSwnTblJeUSN
         WJWgXcr5u6qF8mk1Qllg4OGSgKle+E8mufX6/7gTb0EaDE3/0UACot/a7ALpz5q8z7CH
         /5KD5UfbkOLN8JGocAA2HOybECwDqThgMCRNiuxUr2/v8tmSIlVTj4GBENLsosQ7Lov7
         eINg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4ueGPg0IEp+e9sVl0EIVLzuILXsOa2bK2kL9OTkw2H4=;
        b=fk8q02vWXRJzVVT8dmdkQpzdPEqN9rz4l5TrTNWdSdLItbOpP18qGrlKjtmHybfdZ/
         XIJCybKFkwo5J+NpGraX3VffvlUHvjj4DcWH+B2le4aTnYNQ8MHWVUMOXdOVr38EoR06
         T6ckvAgQtpD74I5vCkp9xs6Qe5bL2UzXDn55z9R25/UeJG8RCXjXXiGGv9p7N/BzbXD0
         YEvxOt+nUyC/0TdPvnLbBEfz00AwKg3V2ratlDsZp6cZYO96MUtMMaYP7gCs17DxKW3k
         mPMBzEw/hh1FRaZWL5lrDG4ruAxHF10O+eRIwPydugWbombBslfeZWRhKw8B7yfoBE76
         vtxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf37qADnaqbb2ALrNZsDM4IATlKm08/WNTnTucn+tf0u2Ra8LQHv
	WLQY22RkRJLWeO3phFDgwuE=
X-Google-Smtp-Source: AMsMyM77DVgtrVvYmKYQ+KBDKM0nwntTDLuw7KseKZcjBicAvqxxijUt3gucJpuEdPnTmGv/A7azIA==
X-Received: by 2002:adf:d22d:0:b0:228:7882:a57a with SMTP id k13-20020adfd22d000000b002287882a57amr10049095wrh.429.1663582639068;
        Mon, 19 Sep 2022 03:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:490a:0:b0:225:6559:3374 with SMTP id x10-20020a5d490a000000b0022565593374ls7607183wrq.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
X-Received: by 2002:a5d:4688:0:b0:22a:f718:7f36 with SMTP id u8-20020a5d4688000000b0022af7187f36mr4293539wrq.315.1663582637922;
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582637; cv=none;
        d=google.com; s=arc-20160816;
        b=A4v2bksnaUjRsU6NgPfHQllrf+69l8i6JoZ+uT5Ez0XtjB9n6dyb7oA4MEg5othnn/
         HBTESoVFwOu2JpN42LtiTb5agZWbGopJz23s6HdPOyhfitT9wxkktKD5wWp6opgo1F39
         clLfvITsxWkvYqJziVLZ4r6horKsTn3X57Ox6wL4QqaJQifI/RIpYNM8wA4w1ruirrLV
         gAMNz2yJAS8yiw3xTSquEt1bsL5SDga5W8ZpG+9UEUmHIsJudEFMFATCHoD7hYeWvz9U
         ZDMNIeSUE/L2h4h+BmP8DNAFnSbBy0UwLHgD5ehdUUFva3yNbhs3nVVa3rCwHL94j/Ce
         kpTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=t0hoKUhhRPcpNA2sMhDiSnk+WMkt/R0zO6loPF3PH9w=;
        b=MO6yt3QatN2dkuEMOy+9/qeKaM91bnkuf/oYNt6iV8UuTlEhxXXfOibe+Ml0Nas741
         hwhMw9BoGS2KMYgsa+cTSRG0HHXA2jQgmncnlYEtNmZdBB1QKqcIwdtSGF1BuMHdTsmu
         8YWnMGP/7wQPa3hpQRklzXC+feb/xCWAcg03iFYFKGEeFzO97AVq9a8RLgutCnxG8aK9
         x4hY7DVv+n4kXaGcJYM+fguCNzsWs7DcmExJETD51OolftcbENu8olzp4bRATP9qGap4
         YmIs+QICnOY3JQgjNlbQY1vKSL7ShwnrL668e0Ijkw404z2wuA0utfnR5fcIQWjG0i6n
         ZntQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Pu2ax4C+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bz7-20020a056000090700b0022ad6de79d6si354843wrb.3.2022.09.19.03.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ahv-1h; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5FDE7300B5C;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id C99462BA49037; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.466971769@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:41 +0200
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
 kasan-dev@googlegroups.com,
 Frederic Weisbecker <frederic@kernel.org>,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v2 02/44] x86/idle: Replace x86_idle with a static_call
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Pu2ax4C+;
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

Typical boot time setup; no need to suffer an indirect call for that.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.466971769%40infradead.org.
