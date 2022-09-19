Return-Path: <kasan-dev+bncBDBK55H2UQKRB24DUGMQMGQEM3IVUJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D12D5BC70B
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:19 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id a13-20020adfbc4d000000b00228631ddfafsf6394185wrh.9
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582699; cv=pass;
        d=google.com; s=arc-20160816;
        b=g604bZbTTll6Rh0DEueCnmx36g2QY5yWiZ3N6x0VkDynfudnw+Uti33B4OZQBO6bFZ
         CNhLD0aI3gAMRB9zOqZhD6eBJdv2Jr8mOS3040D58zgZ7y8tGD1k3snC58e6Smyeirzd
         wJsaxcTth1j2Dr+lXsiwuDb5hf5RIwZZA6qtqpghGnQsbCF5s3JnUQNv4lX1XgUryo8m
         4+bR0ucBb5cu1dvdtOcSnjxv4skS5v19aa7KKLiNUaSxRMqS0cqAgnhpYGqkvuGnldwq
         I60iTBhldDu5GK2NU4tLAQVNmG5+0BQ3xgh24xrRJGPs4cd6XR4TgryreZWPr+sN1x8Y
         5Vxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=XyZCXzZUTKjO5TCLbTvsexDZL7bnBiRtYG5iR0VSi/Q=;
        b=c2BCqH38kUVwMRT1HZTjmshfnCBuo2BjyIWosyGn2xEjQobKRwt4P7+MHRypVKsCnN
         w4/Z6cgHsv/VVR3qCw0YizUN5NNegL41gp/hzj+ua5IhjqD34LGA7M/cFKQtR6jWpF2m
         vsfpZtDRL053BBUOvFgTksXB5EKNvwFs2KVRZlrNP39WRzyJNGKtpenAv0awz1rlXXm9
         Q4GJwg/gvlG7QHzSGyNXFc7+iGa9qaPgZ9nkFfZSEhaxLZiFYiXj9Xm7QnuWdu0589oQ
         2YHWuDc9oBujsV8ArOOlmWXF9naY0l3YtIjWDwaokHZ8BmzQ8S7Zig3U+169+z+N9QRF
         pAeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UWI2IQDg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=XyZCXzZUTKjO5TCLbTvsexDZL7bnBiRtYG5iR0VSi/Q=;
        b=dWF/L4kgRzR8eOyf8EoYVQw2kfErNksAj1s1wB7rivOyCLSf90qLvJnKHZ2z5MNKIG
         Dyl+/HBhPKEcGIBEJnAGEfSfCofTQHpC6iCwbanaAf7NcNWyFiq+hE2M/fOKIgdL9r0F
         byE9uRNA7Fz7ksycsyk6lw3FzPlcDc55bUuurmKJYHLHCfNGP8ZzApZNP8pqrcTTdQwM
         q69tcMWmIFqSNx4ml8IEMEzrdcU13eWSuh86ZojDZEXeBzNyd7S7ABOz67kHyFc4BSP6
         RaMYhBja2xq6U+kWi9lFs9yo5r3SQgrpvBQDiPMlfCoJn75ZUDof+liun6sAWavtAbBn
         DkTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XyZCXzZUTKjO5TCLbTvsexDZL7bnBiRtYG5iR0VSi/Q=;
        b=wJj/DvDsJq7SLjJXzRraHG5G3hJx61ehjM8XVVLOQhNSZzS3UzhU6lvJDsKqUPokYz
         moXy7y8N/60AHz4tidX5JdZFVa+bh0/4SfyzXjqAFmnx7PmffjavTZxckXmqlYsafHEQ
         YE3Kj7q44k6/7Nyh2oQmCU/gXz+5B6X2F/EDG+U9A0kReKeMTjq8jeBi5fWjiWjI+AdC
         BAcXrNLuIFAAUuBcLQMQ3ryvHgsSFVjoVBmVyRE+kclm+YQQ42u/393X8CSIl6Ukan/V
         ImaCTMezbfl8tnh0aiK9e2+DYlZyWBmMF/9ob1wTSVTWlf1ve8B442YGzLAA4rN9Q1hU
         8y2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0V3rgIntAQeTW5l1w+DXWRxuxSTGtcW867SBNYBW47Y1RVq1aQ
	MbjdR6ZdvAy91lZykOiuiiY=
X-Google-Smtp-Source: AMsMyM7bl/TlqBZmS23/hVfT6iKUcN/KO2uYeH6mYT12FgBr3VAd5CDXzYlQTIhHSa+htUxHISHI3Q==
X-Received: by 2002:a5d:4311:0:b0:226:133d:9e69 with SMTP id h17-20020a5d4311000000b00226133d9e69mr9990453wrq.700.1663582699273;
        Mon, 19 Sep 2022 03:18:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3786:b0:3a5:2d3d:d97a with SMTP id
 o6-20020a05600c378600b003a52d3dd97als1730563wmr.3.-pod-prod-gmail; Mon, 19
 Sep 2022 03:18:18 -0700 (PDT)
X-Received: by 2002:a1c:6a17:0:b0:3b4:84af:8f75 with SMTP id f23-20020a1c6a17000000b003b484af8f75mr18548604wmc.53.1663582698074;
        Mon, 19 Sep 2022 03:18:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582698; cv=none;
        d=google.com; s=arc-20160816;
        b=XXyYC/3ia/5gTY8RAQ2TDqXMccsw0+TMcAtnyGPpIziZHyryub5dNoUBrXEihDhKbL
         0cN9OcgDQWxTTqSlLeRQwfISqiMHTzkl79Rk4AvZuxpFqZ6svGtrGGi696AIlvuWIn25
         8H6RF4sZAM7+8Ss9olacgt0tQ1fxtay3Cf73yALvflkLeXIr+EJ6kWLJsOEDoQIGAJRL
         VhntI7nh8dZOJbFo+0oQpEMV7RKYWg8vlX7zNbzL5yJcOk2jj4hAaV0b7Y8tbthwVX2W
         pfNCIQWWFGDBzhm1bjcUurFcPwbdVnOgwdI7EbE+eYSatqQLBYWgxAXczAwEDJuSbK48
         d6lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=qeP5TW9pPwNmun+WKlC/DjHHSTDp0gQF0cfrlfUPbu0=;
        b=CLrM+t0tWqR5rAJm41n6BwaztlkHl09mndnBgvAx4ko/fXtPUKOke4qCfR20acDT3F
         mJTFrX52MTMb4InoBHxqTy8xHC7mG659Ef5uadj+1l+wPgCtQVrnDyNQ8rBAjZzNHWR/
         ixfEX1hJ2TcZqLeajf+H1lyeAtAEV1eQnaIe+MOg/4lXenP49LMVXKIqN6y4NSPpTRZ+
         DjagQ5jbjPTR3bl6SzRuptuO6RzWI3yS0cDB2LljQCNyPYj6UwEefKFycXIY2/GKk2RN
         JOahtCgJuQZNjDSYlsI6Kl6n+KvyHy/vniwlrwYOO0sobJjYEtZu34IylAgSELT98b/I
         Fq0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UWI2IQDg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id q25-20020a056000137900b0022a450aa8a8si253875wrz.6.2022.09.19.03.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:18 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-00E2BC-Th; Mon, 19 Sep 2022 10:17:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4C26F302F44;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 690642BAC75A9; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.358582588@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:09 +0200
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
Subject: [PATCH v2 30/44] cpuidle,xenpv: Make more PARAVIRT_XXL noinstr clean
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=UWI2IQDg;
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

vmlinux.o: warning: objtool: acpi_idle_enter_s2idle+0xde: call to wbinvd() leaves .noinstr.text section
vmlinux.o: warning: objtool: default_idle+0x4: call to arch_safe_halt() leaves .noinstr.text section
vmlinux.o: warning: objtool: xen_safe_halt+0xa: call to HYPERVISOR_sched_op.constprop.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu>
---
 arch/x86/include/asm/paravirt.h      |    6 ++++--
 arch/x86/include/asm/special_insns.h |    4 ++--
 arch/x86/include/asm/xen/hypercall.h |    2 +-
 arch/x86/kernel/paravirt.c           |   14 ++++++++++++--
 arch/x86/xen/enlighten_pv.c          |    2 +-
 arch/x86/xen/irq.c                   |    2 +-
 6 files changed, 21 insertions(+), 9 deletions(-)

--- a/arch/x86/include/asm/paravirt.h
+++ b/arch/x86/include/asm/paravirt.h
@@ -168,7 +168,7 @@ static inline void __write_cr4(unsigned
 	PVOP_VCALL1(cpu.write_cr4, x);
 }
 
-static inline void arch_safe_halt(void)
+static __always_inline void arch_safe_halt(void)
 {
 	PVOP_VCALL0(irq.safe_halt);
 }
@@ -178,7 +178,9 @@ static inline void halt(void)
 	PVOP_VCALL0(irq.halt);
 }
 
-static inline void wbinvd(void)
+extern noinstr void pv_native_wbinvd(void);
+
+static __always_inline void wbinvd(void)
 {
 	PVOP_ALT_VCALL0(cpu.wbinvd, "wbinvd", ALT_NOT(X86_FEATURE_XENPV));
 }
--- a/arch/x86/include/asm/special_insns.h
+++ b/arch/x86/include/asm/special_insns.h
@@ -115,7 +115,7 @@ static inline void wrpkru(u32 pkru)
 }
 #endif
 
-static inline void native_wbinvd(void)
+static __always_inline void native_wbinvd(void)
 {
 	asm volatile("wbinvd": : :"memory");
 }
@@ -179,7 +179,7 @@ static inline void __write_cr4(unsigned
 	native_write_cr4(x);
 }
 
-static inline void wbinvd(void)
+static __always_inline void wbinvd(void)
 {
 	native_wbinvd();
 }
--- a/arch/x86/include/asm/xen/hypercall.h
+++ b/arch/x86/include/asm/xen/hypercall.h
@@ -382,7 +382,7 @@ MULTI_stack_switch(struct multicall_entr
 }
 #endif
 
-static inline int
+static __always_inline int
 HYPERVISOR_sched_op(int cmd, void *arg)
 {
 	return _hypercall2(int, sched_op, cmd, arg);
--- a/arch/x86/kernel/paravirt.c
+++ b/arch/x86/kernel/paravirt.c
@@ -233,6 +233,11 @@ static noinstr void pv_native_set_debugr
 	native_set_debugreg(regno, val);
 }
 
+noinstr void pv_native_wbinvd(void)
+{
+	native_wbinvd();
+}
+
 static noinstr void pv_native_irq_enable(void)
 {
 	native_irq_enable();
@@ -242,6 +247,11 @@ static noinstr void pv_native_irq_disabl
 {
 	native_irq_disable();
 }
+
+static noinstr void pv_native_safe_halt(void)
+{
+	native_safe_halt();
+}
 #endif
 
 enum paravirt_lazy_mode paravirt_get_lazy_mode(void)
@@ -273,7 +283,7 @@ struct paravirt_patch_template pv_ops =
 	.cpu.read_cr0		= native_read_cr0,
 	.cpu.write_cr0		= native_write_cr0,
 	.cpu.write_cr4		= native_write_cr4,
-	.cpu.wbinvd		= native_wbinvd,
+	.cpu.wbinvd		= pv_native_wbinvd,
 	.cpu.read_msr		= native_read_msr,
 	.cpu.write_msr		= native_write_msr,
 	.cpu.read_msr_safe	= native_read_msr_safe,
@@ -307,7 +317,7 @@ struct paravirt_patch_template pv_ops =
 	.irq.save_fl		= __PV_IS_CALLEE_SAVE(native_save_fl),
 	.irq.irq_disable	= __PV_IS_CALLEE_SAVE(pv_native_irq_disable),
 	.irq.irq_enable		= __PV_IS_CALLEE_SAVE(pv_native_irq_enable),
-	.irq.safe_halt		= native_safe_halt,
+	.irq.safe_halt		= pv_native_safe_halt,
 	.irq.halt		= native_halt,
 #endif /* CONFIG_PARAVIRT_XXL */
 
--- a/arch/x86/xen/enlighten_pv.c
+++ b/arch/x86/xen/enlighten_pv.c
@@ -1019,7 +1019,7 @@ static const typeof(pv_ops) xen_cpu_ops
 
 		.write_cr4 = xen_write_cr4,
 
-		.wbinvd = native_wbinvd,
+		.wbinvd = pv_native_wbinvd,
 
 		.read_msr = xen_read_msr,
 		.write_msr = xen_write_msr,
--- a/arch/x86/xen/irq.c
+++ b/arch/x86/xen/irq.c
@@ -24,7 +24,7 @@ noinstr void xen_force_evtchn_callback(v
 	(void)HYPERVISOR_xen_version(0, NULL);
 }
 
-static void xen_safe_halt(void)
+static noinstr void xen_safe_halt(void)
 {
 	/* Blocking includes an implicit local_irq_enable(). */
 	if (HYPERVISOR_sched_op(SCHEDOP_block, NULL) != 0)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.358582588%40infradead.org.
