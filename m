Return-Path: <kasan-dev+bncBDBK55H2UQKRB3GMQGPAMGQEEHHDFPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E776668000
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id j11-20020adfa54b000000b002bd9b1e1656sf2192789wrb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=M4pHGuH+DKDsUVirMmrplDQRVREwBre7raRyi5ovUc+rdTWghzrL8vo91KP7ysjRSc
         /9sBj8vXznV/Wc1oMLjMhEO59zcwrfp59LgwYr5u9pCMshoBebnezhOeshSlUG4eWLhE
         A3ma+WZ6xTOMRZWWsoHV9+qZbhB0fJJDr8jyhU5N+mQ68cPplo2zdquj/XkBz1L2k8r7
         R8MPHv8sqz8sSNFGY+4bUHoAfqxvmI4KV4Eui0U6XcX34rPhwfLgBiPMU1OSMBwPVLnk
         5ZCJ/pMBW9h2NgtU/6wQD8rgl6mrPsTKNBo0YhZwxstVe83GLc3yhxyGbzkyQkMhzQPr
         R15w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=fC5vxz+67xsZkJL8fIRRZ1mwGCh125sEW4nTjSCaZ0Q=;
        b=p25t71dJ8LRL73Zi3ankIhrpTiPQZpmeyCPthZcdDsYdC+y1oDyxJX+7Lw6g6vurZI
         DyZ9p0neGUkf9wJrjz0a2ZzzV0BJbHQ0EJSko7jQKfMTDQSCm5tuF5AmCsGoz3fKhWRH
         E6EwuDdC7DF/uTr3KR3sCQft4stlecNb0f+8SwWryXFdr9fL5m+n/SwcFbMHLRwlJ1WN
         N/8ZC/KiIEGf4S83Lyg5M4XCcJjy0Y2Ba+hl1fVBZbw5szdBZIWqw8T6XqEWFNXzaVdE
         I/xfcUt0+jObKuXhhZt3Ihh4MCFmkypJWGzYc1k/oaKehxlwFCmaoKTJRd21Y2wmNIkX
         fKAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Ck0DUh4W;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fC5vxz+67xsZkJL8fIRRZ1mwGCh125sEW4nTjSCaZ0Q=;
        b=bzV8tLKpN7EPsjhPpZWUjAIvYiPyoKT4ukPYCBX+On3PhA2T1RsYvIIDrie16NyLmG
         HP1/hayGZd+7KzVynE390XlpdXWSI3vK6lFpPIgh7DqQbyb8ANEZi/lqasD9GOxXdM2i
         sp8ynHuTXm8gCxdh89nHDePy63Vz6y7FSjSRj6GIrecN+WHkAqjFmCsRkvoYZ2dzzUpL
         MW6IQR5meHGpM/rKfRkGt/XYkxJGctD/dlD/Wh1e7H4y+L/et3zxZfYIy74zf2gqA4FZ
         Tn/WiTUA/SNyz5+Cfi0xWA2YRSeBZ4+I9sbYqWWWluefd8QaWy3vp0lmol+9Q/UUz8bV
         RFNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fC5vxz+67xsZkJL8fIRRZ1mwGCh125sEW4nTjSCaZ0Q=;
        b=YGhe9C/zJeydwh2Iu9dPk3NNx392a/kyRYNqOoUgfaHbdKsEZ1qYAB15yun3Mu+jQt
         uuMq9FzL2JrOTzIUMn0y65QxHNpokQIoxQhjv+JvqCHMLjPyTpI8dGnZ2ZCOI+lDoNbn
         EqkovF+xG1L8NFySBn0tDPpsDr1mw3sONLqHbgtkW8z84NkEq4dFzDo42dOkQUjHL0ui
         oCLnIM2xHYJ919LbuobZHh5T71J4U7Cb2fyfxP1mgbcSkx9rW5FJOavuO0m9v4jsdq91
         OmW+UG+o2eEQKKyhOfdh6uYZdOpX3p2E7NwqJ1Z4GM4l3QJnejihy5wu3m7YKcVVqxnz
         LnBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krXMJkx7GnB4W8z38qTL2o0/IglCGbVA1Ngae6e2QIT0NP1EwEY
	ePLHI/DsOOJ0Kd2I433kzJE=
X-Google-Smtp-Source: AMrXdXtI8JS3D024enqHS/6VCixJmT64zaePeqvQ3/KKJbUAOf1J9m5uv3q7SYfGOafYXJ0c8PxrRA==
X-Received: by 2002:a5d:4143:0:b0:2bd:c097:8487 with SMTP id c3-20020a5d4143000000b002bdc0978487mr456906wrq.17.1673553517030;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:250:b0:269:604b:a0dd with SMTP id
 m16-20020a056000025000b00269604ba0ddls1474212wrz.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a05:6000:16cb:b0:242:1b0d:9c58 with SMTP id h11-20020a05600016cb00b002421b0d9c58mr57473544wrf.69.1673553515815;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=vRjuSdo/Hp9hB2zSKZDnJTlUh/XtNdc/YnwNapWP/3AIg7N64iFrD4HzEC57Yamd10
         Z/VAmD7VKaM8YL88exrU4JA5IAJO5SXapjSuxL2aLSod7bnknep6DxdURCvSyqQrvcxk
         Ui2DnmOv0G2i1lzYoXfq04yHUD8ZiUnDHa8PbZdI6TFvt3w9wfCRkHfTGJMwwtH5Mz9k
         xvYNDE1ZRdMi4/chWAGmKEi/k80Qe0fj1yyzmot8nPiwRA/j/6/o/+r6u3+pF/a9xeVv
         doU2f9tD5V5W9zhY84TkKURZVm1zQa21fvZOKUOrfv92kWxSrhJ1DhfYV2G/Kmc91z/P
         KFjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=el0CIt1mM51BvZPcHKbhuF9lp1fNYUjgpLSAPy3Ccmg=;
        b=Uzw/fhfBiHtrk0CwQO50P3s2Rh90Yi8A9CuZfbngnD+avjyisBwA6wza3HHhfTpN2h
         DGM3sk4572TKthl1iqSxn92sqziJLGFa0aruL1H/QAM8zv3O0P+laMFw1qpn57ORym/0
         TttXvMRXjPbEi4gzi4rw/2VghVxAi5metg1R6HNb61K1x/Qo6QbRAJqHJb1bxJFKwTA8
         x9z3M4ug6t/3LmIdyvh4LpjrTPSCB71gdXpcuH7xwy+TUOxFDMrCSxhIoQ+NOc5IS8+n
         xMV2UF0GVo9D6fH0THOhzv3TVqOTrPQLjBhwZy5FwdXatfRpW9Bcp5RyDHyJBwD5GUBh
         ijPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Ck0DUh4W;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bt2-20020a056000080200b0025dd2434f36si843608wrb.2.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hH-0045pH-2V;
	Thu, 12 Jan 2023 19:57:14 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id AC616303442;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 24C2C2CCF62B5; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.171918174@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:44 +0100
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
Subject: [PATCH v3 30/51] cpuidle,xenpv: Make more PARAVIRT_XXL noinstr clean
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Ck0DUh4W;
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

vmlinux.o: warning: objtool: acpi_idle_enter_s2idle+0xde: call to wbinvd() leaves .noinstr.text section
vmlinux.o: warning: objtool: default_idle+0x4: call to arch_safe_halt() leaves .noinstr.text section
vmlinux.o: warning: objtool: xen_safe_halt+0xa: call to HYPERVISOR_sched_op.constprop.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu>
Reviewed-by: Juergen Gross <jgross@suse.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.171918174%40infradead.org.
