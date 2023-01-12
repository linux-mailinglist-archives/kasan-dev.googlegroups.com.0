Return-Path: <kasan-dev+bncBDBK55H2UQKRB46MQGPAMGQESRABRYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BEDF666801A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:43 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id q9-20020a19a409000000b004b6ee156e03sf7266236lfc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553523; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hh4vF7gwIwIqnQcMqmnj7S6kE1+muDs/uFFwz6SBIYIBoAY/6mQt8nHoFmnGc1SRL2
         q+1oNXdWo5IoiohaYg1Phj/PIrmKndchBUrFUPqJYXIHLMznvqZI8Mw1Sns3gTAJ9JXA
         SXAGag9yIFsWQufucGeZ97+DkJ6ZdnGQ77+bf2lC8XJhKTPwgAyRthW+j4NmfwZ2uhzb
         WbNOpayyFjc+SKJHg1Yhw+6S+mbJLebjqibi455jY5VtlcgdqoRbOzoNaqbNsSJ+JMyi
         VSrA2Jh9MmjZ09z3lbSNSZ3iy7eF18lR0CBHuW1rE3SMmw5mhSgx/FwMm5CUiNRyXgR7
         1Jtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=7HFKct2QebDDqtZPvlIPuLiDltgkaRln1VllFsdBx3U=;
        b=XlEhbML/fjyazzLoiiUtyPoPgZYlb7M4/yAs0WIkseEM3vNL9QwkZY5JLkTy/Evw+R
         RGiiPp+iisVy7klOyiXgDkmzlC1KwWivKhF31ERZqRUmbYFFPa8c5C6Wl7EmBWc0xFAt
         Rr+Xt/wmoaGkX+PSo8/IQ6J+et6hYavq0IbrfhjS41qbJfxDAJJtwpUXgEfbNvK1e5y4
         D3KIocVf7i9gED+QvilVXUv64ACCFaZuU/F0VCgzPHFZqAD04z7z1R9Nhd5bnk85+Yzi
         Tv7cPPP5WxKgTYz0bLpPHFif7ZtIC6EZjsYJg0wYA+Qr3ijdUjvaFDQCSRN4xOZU75OZ
         SzUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=bXVWmsZj;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7HFKct2QebDDqtZPvlIPuLiDltgkaRln1VllFsdBx3U=;
        b=QB86q8MtHqOzCN2sm34k3BO6ZMwxxCauTSFsWa0fG4YIr+VyOiva1HVVzCwIUSwfgN
         RUAw1spppqeBGunhb4suVlIXRqWUm3gx6CdmfvRJclprGTvnahLOUkm1rV+e1LgyuHy2
         OcLt3eUYR6MzYb9FRp5ZjOhgvnsGs69/4ZLRpgo8COeBJPEULS0miEaAiTR2GiWOWDU6
         0CNwShoTg9fQNExUjurN+ky+ty0ObmPhOGU5pOCXTzakHFM6rdDxNlih2mHTK2RzqshV
         yX6YzOxLEHZoEkuzh/Cous127pJb0Syud7b84s79o2ILcQ8lt2VhI/NvrzWx18g+vbnt
         uzrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7HFKct2QebDDqtZPvlIPuLiDltgkaRln1VllFsdBx3U=;
        b=QVpTpc2WtEefUuSmRP8HKdfatUV0mepZatYWpTulUpQ+t7oYafCZMA+EJA0xUqDGor
         vBfCn25sDyu9znccCKc9JCLY/qODYHmJzenSTuBZkn8obgDEsSe+YaMwxzKMOz8a4gOh
         Yo2hSCbt7Nr872yjOqEUjAd9vwj7TVT7Yw5XROhTgRfAPHI3bPrlK2R16hZDKhtpYqgT
         Yyr1cvMES4TXl+5XBquyJ+trm0WkPP7BL35Dr/Uv8P2+eT6lpsa25UcmKTYVKEQnmrlw
         77Zery45r9ZM0gNE06p5CXvWwsZydfU/TTIur6dWGqjBN34RzmiLR82/mgnI1yz/LCOS
         J4/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqMzOuum7piIxlPV0PcMTulsxqRWZyiBW5U7gCJo5A3puY2YTPU
	f2GVkuiB6+snIe+MHB8V57M=
X-Google-Smtp-Source: AMrXdXtGj7GWj1PgsWH3XUeRiqBsVg76Nh7VeqkDfHpp5vnkUQpR84kLgYOC+OIi3aKsbjIEKFlajQ==
X-Received: by 2002:a2e:a376:0:b0:289:6267:4156 with SMTP id i22-20020a2ea376000000b0028962674156mr469021ljn.82.1673553523241;
        Thu, 12 Jan 2023 11:58:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314f:b0:4cf:ff9f:bbfd with SMTP id
 s15-20020a056512314f00b004cfff9fbbfdls13459lfi.1.-pod-prod-gmail; Thu, 12 Jan
 2023 11:58:42 -0800 (PST)
X-Received: by 2002:a05:6512:b81:b0:4b5:869e:b5ec with SMTP id b1-20020a0565120b8100b004b5869eb5ecmr4662239lfv.61.1673553521992;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553521; cv=none;
        d=google.com; s=arc-20160816;
        b=EpI/KGi3zfE4jMGC/bpw2iKOs8VV/syT8TtY68JmzWF7oulKBqq1NwXLyRVXEZ4o/S
         rN2RCiWO/hVO2KNLe1KuUdrxuu1am8Oe/n2L63oxp5TBn0GN1R1gqqxwO3jWmvJzwwCk
         coQy/MM0d/71VIgHUjEPHQ+mCqDD7DwzcyqCGR1lx5mQBkk/MFstf1p5dLfAS+pnwEMv
         G1NHT5IKK7XWDV6Mu4kqEvq2Jhzenk3/iGE/M9pv9vbdiJo7thoFTYhP3q5OhsOVAgGX
         ImHxlD5yEGM5I7ICcAzIh5Rli2fmHNyadcG8j7cVyIvL7/9jrRIekpPPjlwA/c6QxiVm
         XhjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=G2cvNgJ/FV6t8OtxjUTEWOoXfe4MyL5zef0iqwcucnw=;
        b=xWAOq2XEOZeoYJkG9wsdKzI0+or/r/JNxomO+/F2ref/esv9AfljgcfBM2We5wy8da
         6d8JGHCgtW5hmgxfQghr6LOd58uYRmP52bUa1t1QkRhgwrPwQJAqhtMoVCM7x41OUHJ4
         5UFn/C+jsNHqa/i5NrPO1OoxV0VrRSCpIjrOJ9PNwDM8i0yU3lQ2zUoD9weT5q1XMUNK
         Dhxz30K7N3BT5wBoL9PXeqdVGOCs9EnjhKvhiJU+AEL3Je8Mf4huJeM/0l/uxdd8rYE4
         UgK8SHqC+HKcF03YZ/9NeKXwT4I5Gf2EGqksokFhIPSQ2SoCcgFIPuNcahlTV/bGX3kQ
         EX8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=bXVWmsZj;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id s5-20020a056512314500b004b59c9b7fbdsi795325lfi.7.2023.01.12.11.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hF-0045on-1w;
	Thu, 12 Jan 2023 19:57:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6E62C30342B;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 062AF2CCF1F64; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195540.682137572@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:36 +0100
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
Subject: [PATCH v3 22/51] x86/tdx: Remove TDX_HCALL_ISSUE_STI
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=bXVWmsZj;
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

Now that arch_cpu_idle() is expected to return with IRQs disabled,
avoid the useless STI/CLI dance.

Per the specs this is supposed to work, but nobody has yet relied up
this behaviour so broken implementations are possible.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.682137572%40infradead.org.
