Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 97F785BC6D9
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id o21-20020a056512053500b0049c6aae1c40sf6330401lfc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=XvcOr8aUOD0XDK0rpCfJp6F6kcVQPytZ7XmWj4gFbMvRA0YRonOGkLbOcB4PUSbmWV
         q7YBTAQqVDlljXndLNul7vAcFfybZENz/vPnbJMgsTR2THDtVPX8WvpFHdBOuzUqPYod
         4B8kUUnoR7VQE8UxnUShdzGIHivQe5L9wmYnewds7Xy+F/DS7mbtHHKIDP1QLdmpp1J0
         sXWNkRDCeMLzPGAKd5BBIgTQDoJjwCY58s8hzlRLfBbWArtnzmNZFyqTdjlv4XQnSeCL
         8PnCAtXNfy3gxLKlxyHMSt3WJmpAZJwhxkQLm1MYcVEEAwpUuuvjp31XNLs1LqAq0KvI
         TZMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=JcRa9cYYg3FcR0AeQaZ2ONSgh8p/TmzcpXBmPjq3YDg=;
        b=cYXPr3H9nnnHlsViMIKHXoYHwipATj/S6CPWtdw/FNS7/wxtoTAI5qEYfi2wMPgdug
         1ypMhuGLkKaetZrctAKJcu/KUhBMdI8M5sy8pGs8ZJ5hpP/z+wIjyQ+4srV4+sxuO+kC
         f9zpSp11bu+H0k9YzZgSU4U0jkFLVj2AX0MJZnOvHwAENcwojCuFsQARtsqws/fE2my8
         Ng7KM8i83hnTLhAQaLnLVmGRABGjbqkf733b0GD0vsNjzCUec9OJpAoPOLHwUPJUEXGQ
         3PUYMUqP3EWZReetuS903mvSfa2O3ppQgpjvuKSFYi4xNJVc6TgJc5I8ARTfK25NW3f6
         ZQDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=M5fXrpQM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=JcRa9cYYg3FcR0AeQaZ2ONSgh8p/TmzcpXBmPjq3YDg=;
        b=n/cTqrhwKt0lmZGjvz9pE5IOt5TeNKhcDwQcYlMIPMHkr+W9MkZAxpzq+usbQKKRRd
         ewzFhkllYaypygCJRQk6lXvd/AM3jksGGtIDLU3edDDetrOwq1eNCsYzPKDd92oxFcSj
         PywXL66N61uhwteYpXotZrWWx8+D+0466yTalS/6oDKwbzNoQ/0EHuBiOwQX65++L9wd
         f1y3ecZ+/y6H1lPHUO3XjU3IYJ/IJJtYTGdOVpjPxDs5aVkmcBZbWqyQPgsUCwYnV9az
         YOc0hhMzUlUifckABVh/0Q3+FL91o8l90zXfZwOzt06d3sgogNAi8wqN3QVtdUei1l/y
         G1gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=JcRa9cYYg3FcR0AeQaZ2ONSgh8p/TmzcpXBmPjq3YDg=;
        b=qpZnMbmNqT0G88cj553QVvLN6kyvvPgKbHhJXmTvhZSbuFVbab6E6zGLOuWQGFStKO
         nUUDGeSy2PM+rCLWE5t2aNbOQ3vR0SWQufv/DsoAgyPI9nUz7ri1c3Bu/emsZPkDl1do
         5mm2KFMrlm25hzTbdPO/syDKpu8vC+Aas+HIeJ7uOhPJBn9Rj8wjOf5OFfc0JpJB/xNs
         k49iFBCXjyQ82jBFjSlkkSziXwnIQuNsVAiEwYL52F4UVZOcJWpsxL3yWO+Fw86dKEjP
         qEHypPx2W9TWvaJutBOe8N0CmQXQvM1ECDccvqhJ4PYNaMyQ7IJ+TfgRB0rvjLIxwhuX
         b7IQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2BR6tXdOkleqP4HBZny2xMUrCrSfJ/Qxf2GUD3WR0YmGiRiMlf
	BDvica6eh2kxt/mFhtWRwy4=
X-Google-Smtp-Source: AMsMyM7rgl6iqBPoSBd0YSvQe0Y2dnR5G2vHsXS0xtS41/R5j+vUxeFxA+4JDSIg5Vzqh+Sdc1D4ow==
X-Received: by 2002:a05:6512:280d:b0:498:fd40:51d4 with SMTP id cf13-20020a056512280d00b00498fd4051d4mr6606459lfb.167.1663582688996;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f7a:0:b0:49a:b814:856d with SMTP id c26-20020ac25f7a000000b0049ab814856dls556137lfc.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a19:4918:0:b0:48c:e6a0:c8d8 with SMTP id w24-20020a194918000000b0048ce6a0c8d8mr5967968lfa.679.1663582687738;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=yFdEuQegoY3WDwpmYoT9n9TScpRg1WxJKp1owijc0qLhLQH99CrCc6aS1lnyZ2M0pd
         r7KEEU/92BaEPb8p8hbJghgdLWOfvcXyZsY3uIq6j4Vpf3A827Gwr0hV8h+ILbfOsHxv
         7xmAU+WwBYeehBkDQSrb20w7YHfnauotXzZWzp/2nrLyF3poYHPBz6MgB4MVNFU2RIYL
         64fIGM82PSiE9yXMCntSA3WMg1TLqTYt1s7tnx2ujMwrcENdnOK9gWqUvBknOyUzY3Jy
         fKeEpsgqGGDCK+AmABLbF3QrkYt9YNCdppO1sATc1A5zh3Es37JvacioF9I05RwkhQqM
         CJhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=/I1E7kMyDvpkyM4o9FUteLnfSJJBslYUHIxNSMQuhnw=;
        b=o5mX1WOXPVVCsdtOSxQ8uuiLuAMjaGZoU2JOfh6w5jCkHJGsRXpvRpSOFEe3uTr3CP
         nRuKT0Vw/MYngckkhMlQrNkWdlvMtm1gs1n5WLRsyipjoIR2/ZO/I83f6QvzvcR2TmEg
         Hmf11OvGLzlQ85MVdYJFSo45tPgcr9gbAy4j81StiWrGN9UtR5/yocF+FeOtzkCe+EBG
         mz/jP0PjZst6FNRp2a61ekGLyWQRKDK8Irjr8wYTNoFBHr79AeZKQQaFrSsv02R5rN3d
         U36Qbqt6w5efvfc2SGJFFJRa5ZSo5iuibbYMlE8DOt8SLNEAID2j2c6kSk+I7j843Cgq
         Ewww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=M5fXrpQM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id d15-20020a056512368f00b0048b38f379d7si768327lfs.0.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq3-00E2Ap-HU; Mon, 19 Sep 2022 10:17:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1D7D5302F13;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 3E8432BABB0C8; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.813876881@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:01 +0200
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
Subject: [PATCH v2 22/44] x86/tdx: Remove TDX_HCALL_ISSUE_STI
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=M5fXrpQM;
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

Now that arch_cpu_idle() is expected to return with IRQs disabled,
avoid the useless STI/CLI dance.

Per the specs this is supposed to work, but nobody has yet relied up
this behaviour so broken implementations are possible.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/coco/tdx/tdcall.S        |   13 -------------
 arch/x86/coco/tdx/tdx.c           |   23 ++++-------------------
 arch/x86/include/asm/shared/tdx.h |    1 -
 3 files changed, 4 insertions(+), 33 deletions(-)

--- a/arch/x86/coco/tdx/tdcall.S
+++ b/arch/x86/coco/tdx/tdcall.S
@@ -139,19 +139,6 @@ SYM_FUNC_START(__tdx_hypercall)
 
 	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx
 
-	/*
-	 * For the idle loop STI needs to be called directly before the TDCALL
-	 * that enters idle (EXIT_REASON_HLT case). STI instruction enables
-	 * interrupts only one instruction later. If there is a window between
-	 * STI and the instruction that emulates the HALT state, there is a
-	 * chance for interrupts to happen in this window, which can delay the
-	 * HLT operation indefinitely. Since this is the not the desired
-	 * result, conditionally call STI before TDCALL.
-	 */
-	testq $TDX_HCALL_ISSUE_STI, %rsi
-	jz .Lskip_sti
-	sti
-.Lskip_sti:
 	tdcall
 
 	/*
--- a/arch/x86/coco/tdx/tdx.c
+++ b/arch/x86/coco/tdx/tdx.c
@@ -169,7 +169,7 @@ static int ve_instr_len(struct ve_info *
 	}
 }
 
-static u64 __cpuidle __halt(const bool irq_disabled, const bool do_sti)
+static u64 __cpuidle __halt(const bool irq_disabled)
 {
 	struct tdx_hypercall_args args = {
 		.r10 = TDX_HYPERCALL_STANDARD,
@@ -189,20 +189,14 @@ static u64 __cpuidle __halt(const bool i
 	 * can keep the vCPU in virtual HLT, even if an IRQ is
 	 * pending, without hanging/breaking the guest.
 	 */
-	return __tdx_hypercall(&args, do_sti ? TDX_HCALL_ISSUE_STI : 0);
+	return __tdx_hypercall(&args, 0);
 }
 
 static int handle_halt(struct ve_info *ve)
 {
-	/*
-	 * Since non safe halt is mainly used in CPU offlining
-	 * and the guest will always stay in the halt state, don't
-	 * call the STI instruction (set do_sti as false).
-	 */
 	const bool irq_disabled = irqs_disabled();
-	const bool do_sti = false;
 
-	if (__halt(irq_disabled, do_sti))
+	if (__halt(irq_disabled))
 		return -EIO;
 
 	return ve_instr_len(ve);
@@ -210,22 +204,13 @@ static int handle_halt(struct ve_info *v
 
 void __cpuidle tdx_safe_halt(void)
 {
-	 /*
-	  * For do_sti=true case, __tdx_hypercall() function enables
-	  * interrupts using the STI instruction before the TDCALL. So
-	  * set irq_disabled as false.
-	  */
 	const bool irq_disabled = false;
-	const bool do_sti = true;
 
 	/*
 	 * Use WARN_ONCE() to report the failure.
 	 */
-	if (__halt(irq_disabled, do_sti))
+	if (__halt(irq_disabled))
 		WARN_ONCE(1, "HLT instruction emulation failed\n");
-
-	/* XXX I can't make sense of what @do_sti actually does */
-	raw_local_irq_disable();
 }
 
 static int read_msr(struct pt_regs *regs, struct ve_info *ve)
--- a/arch/x86/include/asm/shared/tdx.h
+++ b/arch/x86/include/asm/shared/tdx.h
@@ -8,7 +8,6 @@
 #define TDX_HYPERCALL_STANDARD  0
 
 #define TDX_HCALL_HAS_OUTPUT	BIT(0)
-#define TDX_HCALL_ISSUE_STI	BIT(1)
 
 #define TDX_CPUID_LEAF_ID	0x21
 #define TDX_IDENT		"IntelTDX    "


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.813876881%40infradead.org.
