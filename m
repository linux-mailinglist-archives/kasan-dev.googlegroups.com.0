Return-Path: <kasan-dev+bncBDBK55H2UQKRB3OMQGPAMGQEUOPKHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 862FF667FFF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id p13-20020a056512138d00b004cc82055b2fsf5320397lfa.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=0bturgJ9ViYbr9eJaNYiSIG3OY4nenhZHMe6pR89jmfsKWn18RhSfe3W93Dx1v00jt
         LK+q5RJWF6vF46OtKNkn5CiVkJ1EomsPXfepm/5+tl71bFWyHX8YvDHwqJelpRS+smNL
         MAbreDmmYKTvnjFqQjxmvksvKsKdPKurvtoT3sTGjeW/F6ySWWq4mIbfgELPNLYEKv9M
         aNEXpl0N7fUx2uFOQnav2yrv2B7om6a3hG8Hy2sKvzFumrPd5sNqaRaXg2wytk26bj5p
         K8Sabc/hBlAMjsy/CU13/2wiliyEry/ISNWA6Pone4zAmIJl2lm/O4fuzFglRnSUWAd6
         cC2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=FOkFqaymoHODVHNqph098H9XYECxmIH2Zip1umQzdjc=;
        b=bQUqYdmDL7KGe5eLZTeHEw0Yii4KvwugcHfXSWbGZrNc29xqUCD7xNe7PWnLXlbQfB
         gdFKqI66blP7Q7HQD7IZu0fzWRfs5mVp0Qvp/k+IrB9QVY7etljIGNYeBdVzreUFVD7f
         iAUlnWUV3hl+rtG9lJZnC6iL1lbbDzmIIGBeHWE8QWNyvMRt7SvGx6uX02NEHz25KlOE
         spM/xinqfsFtLmR33AXOwb3UAiyv9jKZixom2tGHXuvZIty2P2Jpco2V1K7NuDJ1B6FY
         7k+ai8MF2bshpFcYtvtAb9cjIT1dEaC7Qc25+KaFgyXe3HKUxCcc92o+nkxm07mQpwPC
         fqPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=XiEO26MC;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FOkFqaymoHODVHNqph098H9XYECxmIH2Zip1umQzdjc=;
        b=N51OTy/MpKlHZ86D6x01d5Pa7PPv0tnNBO7KkPju4vjhLtIpwMioJ+Fom/ynUdT6Yd
         bSAN+lsWx9zZIzCPdJzlMi9zmB63qCYssS0rGybHmSjrGiDazyHVgvfbbsIy9CSHA6CU
         C/8ZT2GEihYNEnmllQBAMTqZp2/Nv1OIa9NAL0B1/kaI8x3p4rjQmoaEJ2HHHSjEUBGu
         LiTkjjW//mrPwTMnfi+xZKLxWhmJRwZ8/bbL/xGNXrp52Erqyw6b9VA88Vzqx5NUE+mZ
         r/YrQRL2tDwYyzcJGtCqhSi9zbomAOJsl++nW/CVLZ/INxHdPz34f5Qi/RjmbSaxQgrM
         +Jaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FOkFqaymoHODVHNqph098H9XYECxmIH2Zip1umQzdjc=;
        b=6WPhZjDbSei3K5ukYtLH82NaZJfDGWCnZU79TjnWy/uePrH3F5R1D/WIyDu6vRJNUi
         zrwvVifHLCrloP9sygMEt/TUInDyjSpfEEEt34X7CuNn+sZz74r9dCXeb41z8nbECMMP
         q+fH/w1Ybk6FLVh5mipJsKQTn85JAMDNjVc1SWi6/lmB8hV1IlIorA3rTHQqpaN3PLP5
         Ud89stpv0S95aLUypw2bjTUEYV+WhLGe/wFZmlqQRzp6qUNrPMQgPqA4z37g3jtgqXb4
         Dub2MFnpLWWyxFaymY5xQGVDycHp+zQ7PnA12ov4FgTDW6V3m1EMLHs3dfrrKNGfACyf
         6LCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqKJu3KiOR12OPgjIkk07AA9PjDZQHrrsOHfJSlymCxt4rB4QE9
	jzt5CLLLhX7DNV/77Mr3UV0=
X-Google-Smtp-Source: AMrXdXt4d8LDPmb1jiHigOqgLrRwMgl4/DOYWUUManys9IAZYmR4nAwRG+m0yBp8M1OZwriXKHQYZA==
X-Received: by 2002:a05:6512:2510:b0:4b6:ea6b:b9b with SMTP id be16-20020a056512251000b004b6ea6b0b9bmr5803162lfb.30.1673553517233;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:98c4:0:b0:27f:e5b1:aff6 with SMTP id s4-20020a2e98c4000000b0027fe5b1aff6ls545564ljj.6.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a05:651c:1593:b0:26f:bd7f:78f0 with SMTP id h19-20020a05651c159300b0026fbd7f78f0mr22331686ljq.0.1673553515806;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=TIk9clSObkf2w2xKyNMlovuqPs4sOeFZ/P7kLTc3zu/aO9qcI3/fYn51UZeqlW3Ylr
         KS1MrxgYxlieT6a1IqZ7SIF23MZTRkkF01pwfCJvCzwuI/+UJ0lUiqznkjq6IVjy/bmG
         HKzm7k7KsinOmfuvJsnYnU+CIhwpBrjHqvt3tA6pr6Q+HfQ4dYixr6KK1+YWuC6f0mnq
         60dFdS92oBtmqpvIeaRXhY3EUCCPy4QF6kFKEUz/6rRczsHvZeNPYDjrXvqjI9Xc6piy
         uFPpuZmeYsUHJqnieDDYO3aU0JhXnnqA5ys3cDIG0xAhdKYwW7riR2IuFQFnP/DSNttk
         qbkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Hsr5V6aaf/kVSU2t73jNDRAWfLY8tgaZMY/8xmM8jWo=;
        b=iTa1t3JU2NxSXKwwhD2Cc3lVnkmho+shSt4PKgMaAJCEhJrpgOKX+t+FMcQ8jhcn4t
         VrtyH6tUA3lMTQR/BM5oiDTafouhLKflm7b9k2Rat1UYvB1j/3c52vGvw3cD0lEUJeUi
         MS8s1HpMjEEVZJnNMwHr2MCpwlbnApFDtiqhEDCsykIIFD1dmY2e6X6Vr3+j/apt9dwa
         KdvB3LDo/YgaU0rEIXNn0JWltRcaoZQCEsGzCxiGL+zR3y3XwtWdnRK9dksnMRGGoh2U
         qtATLhW4dfZsOEaaQItRPlEEZQTexm8BMFFV55WH2cervw8eNYZcQaclRjDh7O+dWaE2
         YNAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=XiEO26MC;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bf26-20020a2eaa1a000000b0028586d0af2fsi541791ljb.7.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hF-0045os-2Y;
	Thu, 12 Jan 2023 19:57:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 77B90302D60;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 09BA02CCF1F7F; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195540.743432118@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:37 +0100
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
 Ulf Hansson <ulf.hansson@linaro.org>,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v3 23/51] arm,smp: Remove trace_.*_rcuidle() usage
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=XiEO26MC;
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

None of these functions should ever be ran with RCU disabled anymore.

Specifically, do_handle_IPI() is only called from handle_IPI() which
explicitly does irq_enter()/irq_exit() which ensures RCU is watching.

The problem with smp_cross_call() was, per commit 7c64cc0531fa ("arm: Use
_rcuidle for smp_cross_call() tracepoints"), that
cpuidle_enter_state_coupled() already had RCU disabled, but that's
long been fixed by commit 1098582a0f6c ("sched,idle,rcu: Push rcu_idle
deeper into the idle path").

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/kernel/smp.c |    6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

--- a/arch/arm/kernel/smp.c
+++ b/arch/arm/kernel/smp.c
@@ -639,7 +639,7 @@ static void do_handle_IPI(int ipinr)
 	unsigned int cpu = smp_processor_id();
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_entry_rcuidle(ipi_types[ipinr]);
+		trace_ipi_entry(ipi_types[ipinr]);
 
 	switch (ipinr) {
 	case IPI_WAKEUP:
@@ -686,7 +686,7 @@ static void do_handle_IPI(int ipinr)
 	}
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_exit_rcuidle(ipi_types[ipinr]);
+		trace_ipi_exit(ipi_types[ipinr]);
 }
 
 /* Legacy version, should go away once all irqchips have been converted */
@@ -709,7 +709,7 @@ static irqreturn_t ipi_handler(int irq,
 
 static void smp_cross_call(const struct cpumask *target, unsigned int ipinr)
 {
-	trace_ipi_raise_rcuidle(target, ipi_types[ipinr]);
+	trace_ipi_raise(target, ipi_types[ipinr]);
 	__ipi_send_mask(ipi_desc[ipinr], target);
 }
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.743432118%40infradead.org.
