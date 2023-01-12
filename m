Return-Path: <kasan-dev+bncBDBK55H2UQKRB3OMQGPAMGQEUOPKHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 60311668006
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:38 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id k38-20020a05600c1ca600b003da1c24f23csf990923wms.8
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553518; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfCtpmUMYEz1PUf1nRHwB0elC/FoXouFH3OojkRJanwIZ1IBnX4CqS3SOJrd+yKq1p
         L3ARdzEaPyEk/E0BeyirJ93ibwE1dIQqyLE9IAkG+YHa+kE2m+Dr6CiozRCQdVf14KZB
         JxPYiEADhDUVBDy8H8G1CuOZvb2pTcuPyY90sRlpLo9DAo4mugNqDlfPMcBj+kdKblCo
         Jw0R3J7kY5/KR9xX995k1Fgn5MynzppeWW6Gl8Amr9pqno2CqJ8dqaSqO/GSv1GbWd5n
         PCT88ANK/AHsm3CKl0thM0VgIoXMJ8rBn04qTpzRo301ii0YxMcZQM3NJ2XCtGd8/tvu
         bbfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=xcVK1jMSUDkuL2QX44F1Ec5wp5Th/HI0W8FzDS00wYo=;
        b=wV2wyMFwRVyUOJiK5IR1uHSkpQUM1jPYlIlCgRVHjnKNzXEZsrPSy+G+UTkbhhNDwH
         U2wiStgwyHI4PhkWh2fzl1EUCk7HQvD0zgrtZGGSSG5fdFegkALHGLSDZDm/fg3Fy/qZ
         Ne8Pg/JS2jqbYcV4BP6Fa1Y/q4QCXxmN5slD2cnuKBletLvfxbgF7RJsd8IiPUD7ADHV
         x6xe0ybx73DXdxXT0XFgEcbuovpsQKTZPxSnqmoRDoPCzA9qOMtAzlKl9M8Z281oB0za
         MgD5ApsawspG4i/4dFBJ8ZXNqJln1W1whEHHEMs8dAiDzXHEAZwhWquRj9+EM1J0Jxg1
         oXHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EVbsZA80;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xcVK1jMSUDkuL2QX44F1Ec5wp5Th/HI0W8FzDS00wYo=;
        b=i13Ce6q1PGl1HJLZnVQtZLC99mLRNHaxCI4u4Ywbiqdtcm3GFsenMjl9MuQgANgan5
         BVmc18DMhvw6DOdCAjtmjEhKnOmi1SRSHS0AYXeQPb/XHMjDX4MU4MAtsMRQn3ArB+kF
         pmzTSQj5g5mWbVyBitBdwDpdbD5+9bmqrOtQYLOukZSgaVNDGlT/9TSW3oVhbw38dLvQ
         WFBpWzmBC0tZFjI6+cQ3zh1r40KXXTa13PoCwMLruhTACrhvjXQQa87uSJfLxRVokn/C
         8TpZ4ZV2xc6XCc6mLXCMrGgHekhFEWrUsxbs3TwHsN/TAzvsx5yEY75QltX1P1VmHZk4
         1AaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xcVK1jMSUDkuL2QX44F1Ec5wp5Th/HI0W8FzDS00wYo=;
        b=HyLzLJqGTbCnIaLAH1qvXPjcCuSBndnXGNTVfHExuyhEVmH6z5iRBUa1h4cFJgpDj0
         2cU7a6hRi3l/vVEg10NPI9t2DAkI4uMWQqS8TxOKI/ocHdDdgflZLTdvL+IFG+segRvw
         KzeBVygbevrfy/Ewtl4tEHDbuPEi+umYUA5zO9c5rTEMYNhQu5C+YK+HcQSm0t5yNQGs
         BPvzY0yy+RuLzYClDtL/ZmgiTzuvtj87fMCxW94DqawC9T2UliKj9iYCdNKb/2ZmvgmM
         NQzDH39WbUoyeRsCSRtdEqTynhFI5suVGoAQ9uxAdUGEPrVa0BqWRLAJ2easD4csRBkx
         qXVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koAJxzoOIoRLm4WNlUGSuhf+c8J/H7ZioJ2uJWjLL4R8N9KxZXF
	Xtl5tk2mafnKYHrtBTQjY60=
X-Google-Smtp-Source: AMrXdXsD2kvB8i2DlvHQJ1ECGcXJytYxDYVG1DbNnYQpOMx082fM1Jb99TaZ8HWlxdsVh1N31a6edA==
X-Received: by 2002:adf:f410:0:b0:2bc:848e:f2f8 with SMTP id g16-20020adff410000000b002bc848ef2f8mr715793wro.567.1673553518027;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:2b6:8e51:dcb with SMTP id k20-20020adfd234000000b002b68e510dcbls1471241wrh.3.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-Received: by 2002:adf:dcc4:0:b0:2b5:8ba4:3b12 with SMTP id x4-20020adfdcc4000000b002b58ba43b12mr19367548wrm.23.1673553516997;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553516; cv=none;
        d=google.com; s=arc-20160816;
        b=fLmZKeuReiF3gGYAKpY65StY/5Tu2LDQoz6ivYP9rkdpNEy9xJdySwpZue72+Snotd
         6Fz83RqdpJ0+sm6K0jMEdB4SMcFUTMTOyMPRBaIaTtHmtwh63v3pP6ow131pwk4V2M3f
         1l7bEKCcF2jjJSeZfFnM81OuMDhjndo0ZR9w8lDWV4/A3LLQm2qVQB8hTDD3Ap6mnaMx
         ksNk3N8vN4wVQKJlVE1WohaFne2tPEDNIl7+k1Wo7DP1PLSzrD0WVoUKmkoLfm5fn6Vy
         cyv8ivr76pRBAlOxmS1S4ivV1CfIc8fuGl5BkK2RtLIiEdiZt9a6Z6UebGnfdaGMiJd9
         8K4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Y7pmXu6dfTZxDcbDXfqgJM0mS6VL3mXOpIjOPL8GveM=;
        b=KxFlO8z9zt05G9U0+p21nAHYJ1lkbpERj9bm6mFktQ0ieM65x2sMuD4ISWfi+Jeeom
         7Pfuz30h2PGIDh3JzcnWHih+E0StJ6Dg2eZxJD/no9gKfZ9Hu8amHsoB8NUA8pmf0XED
         HmXOv6u8RQQp0dTRNeJQgjIvx5UKnamkwja49NfSEuYX3XF8XbUFnM/Vf7H22B8xT93Z
         6gePMhH4y5SAvypnB8NIVdFliZctKY1wVWr1kSyY6moiai0IDp/OH1VQP2KtvrNzbrrl
         lfrBGYlOsGTCgB7QYSJ6YJKmY/4ZEigsyG5DExxnGBdn8PCHvL1ic6yKQNBMp3ABCRKM
         obKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EVbsZA80;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id d10-20020a5d644a000000b002bddc018216si50930wrw.1.2023.01.12.11.58.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hH-0045p8-1K;
	Thu, 12 Jan 2023 19:57:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 980EC30343D;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 1D1292CCF62B1; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.050542952@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:42 +0100
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
Subject: [PATCH v3 28/51] cpuidle,mwait: Make noinstr clean
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EVbsZA80;
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

vmlinux.o: warning: objtool: intel_idle_s2idle+0x6e: call to __monitor.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0x8c: call to __monitor.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0x73: call to __monitor.constprop.0() leaves .noinstr.text section

vmlinux.o: warning: objtool: mwait_idle+0x88: call to clflush() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/include/asm/mwait.h         |   12 ++++++------
 arch/x86/include/asm/special_insns.h |    2 +-
 2 files changed, 7 insertions(+), 7 deletions(-)

--- a/arch/x86/include/asm/mwait.h
+++ b/arch/x86/include/asm/mwait.h
@@ -25,7 +25,7 @@
 #define TPAUSE_C01_STATE		1
 #define TPAUSE_C02_STATE		0
 
-static inline void __monitor(const void *eax, unsigned long ecx,
+static __always_inline void __monitor(const void *eax, unsigned long ecx,
 			     unsigned long edx)
 {
 	/* "monitor %eax, %ecx, %edx;" */
@@ -33,7 +33,7 @@ static inline void __monitor(const void
 		     :: "a" (eax), "c" (ecx), "d"(edx));
 }
 
-static inline void __monitorx(const void *eax, unsigned long ecx,
+static __always_inline void __monitorx(const void *eax, unsigned long ecx,
 			      unsigned long edx)
 {
 	/* "monitorx %eax, %ecx, %edx;" */
@@ -41,7 +41,7 @@ static inline void __monitorx(const void
 		     :: "a" (eax), "c" (ecx), "d"(edx));
 }
 
-static inline void __mwait(unsigned long eax, unsigned long ecx)
+static __always_inline void __mwait(unsigned long eax, unsigned long ecx)
 {
 	mds_idle_clear_cpu_buffers();
 
@@ -76,8 +76,8 @@ static inline void __mwait(unsigned long
  * EAX                     (logical) address to monitor
  * ECX                     #GP if not zero
  */
-static inline void __mwaitx(unsigned long eax, unsigned long ebx,
-			    unsigned long ecx)
+static __always_inline void __mwaitx(unsigned long eax, unsigned long ebx,
+				     unsigned long ecx)
 {
 	/* No MDS buffer clear as this is AMD/HYGON only */
 
@@ -86,7 +86,7 @@ static inline void __mwaitx(unsigned lon
 		     :: "a" (eax), "b" (ebx), "c" (ecx));
 }
 
-static inline void __sti_mwait(unsigned long eax, unsigned long ecx)
+static __always_inline void __sti_mwait(unsigned long eax, unsigned long ecx)
 {
 	mds_idle_clear_cpu_buffers();
 	/* "mwait %eax, %ecx;" */
--- a/arch/x86/include/asm/special_insns.h
+++ b/arch/x86/include/asm/special_insns.h
@@ -196,7 +196,7 @@ static inline void load_gs_index(unsigne
 
 #endif /* CONFIG_PARAVIRT_XXL */
 
-static inline void clflush(volatile void *__p)
+static __always_inline void clflush(volatile void *__p)
 {
 	asm volatile("clflush %0" : "+m" (*(volatile char __force *)__p));
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.050542952%40infradead.org.
