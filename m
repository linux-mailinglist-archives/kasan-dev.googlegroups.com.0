Return-Path: <kasan-dev+bncBDBK55H2UQKRB3GMQGPAMGQEEHHDFPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1215A667FFB
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id p13-20020a056512138d00b004cc82055b2fsf5320384lfa.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553516; cv=pass;
        d=google.com; s=arc-20160816;
        b=dKIjE2Jmfeg4KWL1hZX6Vr2DYcRUlJz6y8xG+LVOITWLW9jmP01b4J2i2ZsGVUtAmE
         m9bllB27KVNhw3LMuD0JJjTy8XOlU0W3ZHvwjJE+TBwLBwlePdyjGDZHcheN74IXr1F5
         jdSUwqOGlqu3FaJx5rNuvDH0wiimehchN6WQPojmHO67+YetN3jwvKmP78PARfWoScRH
         oz9tBe009rP3gLKNSIpSj2BNA9OEJPBJsD7rcxLJ3I9f3FE8pqP7AmaVT+RYncKg4QV2
         4DGQVJzVN3464p7xw2D0hF2XC595ALRzQKpc1RPsXdAz/lcPkZEVXjVfnUrYX3s7gpQP
         DXlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=a+qn2EllxRuAsQx5irjPqyJAlFVehuOcCGkmbqWA8Qc=;
        b=xOjxt8hPAZSyfQFEtWz5s14Sv2JckMkIJgQicMwY03MUdxgZTKNWF79rzzXIAYCsOl
         +HHdY/1iVMmRbJiZWij9jB3BK3aG0aA8oX2C6lNRx5ZQD2oRwyKKtegLIntSzwY9okQT
         rICuLx9Keh6dzSJcDxBaiIyN+Q8IUbWMhbEk/zAAOM3vZyZJ3gLN81pVWsOkpCcX7Yxi
         xgvzCHXECNyXn8PjZHn7+WQ0uDkHrrSGurT/sNirvdFr5yNOnbubKuTOc/GMo2WTOQe2
         B+/I+LrkjjBy4Gjt3rBo7AMef/UCNDgDQULrYl83zFgNtx5xC1Hz4/s8byn9/u1mH/a+
         9Lxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=oqN2YQaX;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a+qn2EllxRuAsQx5irjPqyJAlFVehuOcCGkmbqWA8Qc=;
        b=kM97Xoma7AYaKQ3SINvo1yF4hSRe2u4L8kDxs4H4iMfXum1dMI+74vycnndpicAnlu
         M2ZxBxkkhW7VS8E8YN11AGd6VLQeqQArI3EV5+w5gNa9Oue773tY7NJSovz02W2lG4Gj
         vbkjIjLJt95I+CpS0FO84OhE2MjoSDY7CXnaKedpgwL6WSdSDmHqNXuKhbutS72AzFjK
         xMpNUu/Kb2SbFIbDWjRzJ14G4edoYAyLR4cz4FdaQr+wzarA+rFAY+aIGA5+b3gnN5iB
         cUBYGuXXk80laTPlK5ST3oSEVG7+VbAH4dKCNELK1nmspp7Wy46jv5bw/YI40WxCTdow
         7qAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a+qn2EllxRuAsQx5irjPqyJAlFVehuOcCGkmbqWA8Qc=;
        b=jawYrs4KfAvL+s/9QNbozxtvv+OaiI33WdIrnInti17W6hCU9byYcB5ologd3v6WG9
         AIpfXNb0moHAhqnmC4yWkQ2M/UbNvMCI8BUHc9N1EGlJEAP0D8wqIJ/SKdBxN25OKkdH
         enrnS0nepDUGqwfY7xllwtQM/zgJ+7AoTuzKsM0eZioEjMrWVKYCWijvUAEmnd8diq7b
         TOjTBiHEY5cSnHi0epLxm3ZdKCp77/jdxeMZQSuyNKaWzh524ZVKTeQgSIO/NbSTOn70
         rTIlNTiqy88Y2q8sD7U3lTq2ROtYjJiL59a4FA6VkswIKjMDCQDP86MMTFeCIQReQ7nq
         rE1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp2ykxhu39mDKYt0hnbYa/V9UvYRmVV+jE/2ItlUbthdhbCWVpv
	OEUPxKoIS79jbX+GxLcbUmo=
X-Google-Smtp-Source: AMrXdXt2I5fBA5lVswQXeOQ+9bEih1R0c2b+IMIzyZVC0DLZuhb3s4YpdSGKWIk70sa0uK4bmaGsLQ==
X-Received: by 2002:a05:651c:309:b0:28b:63d8:ffe8 with SMTP id a9-20020a05651c030900b0028b63d8ffe8mr31240ljp.260.1673553516478;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935414lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a05:6512:3c9e:b0:4b6:a6e4:ab7a with SMTP id h30-20020a0565123c9e00b004b6a6e4ab7amr26090319lfv.8.1673553515260;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=DVDNFo7wT1kxaWmxF7Ev/Mp7j6s+cqrUFpPLXaWX8VMBl0YaNqak5tR9ausv3Nd5c+
         Sq4fs6evNj8yv2eJvKti9N8RXf5oQkvWFzsLvzFpTIHabY066VFirYCGM8o4d/l5920b
         BQGckenXcUs89BIljQ5tVgdGpswe2qbUsH8GtbXI5Nn9F20/W+0Xw8Zclu4cfvjGecCK
         Nqoq/1jYQ3lmsWepDWlQFAvSeokZqeXykG8pJXgsUc0F50N0Dcigu6LrcGC7tj5cRXQV
         Kz9JQoc4vrpVE9vbU7fnlmATgNX41QxNP7YGX10TeizvUDpdIUd4XDJQGr4vDZTt1Yot
         8CEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Pd5LzlqFWhoOW/IghE5YxUytF5dcFo0PCwRqcxBfbik=;
        b=kFlpyjdWsHNnKc+LJy5sETxK7q7ZOaAtPDiqyvjvf6ZxdXtRUuRsOnwPzUTxDrhru/
         HObh36U+306Z9tMEjGJhD8Se5lJqAMANsVtNPwN0nKdknKUD6V6ulB9ln5L6v5pWwhnu
         787yXPuT4/kbofQ5/dNNgzdya3tuIqOJ9jqm8l3xAdJNZ8T7XhA7NX6F6olo3QgaXBJk
         xzfYBPmoZabJiA+VD15lvhlKd9qaG1zmwsDtVRMwxF7GNRJ0grnIUuycJ6b1RKGix+EG
         OsZNG6c0HKC/3Yy0DUII0HfpsN7N2TQeZsGbJGvedwGhkEaLHFS0TM4pLPUVR8SrE6RU
         vgIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=oqN2YQaX;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bj36-20020a2eaaa4000000b002810d5101ffsi771367ljb.2.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3ha-005Odn-DS; Thu, 12 Jan 2023 19:57:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5721C303421;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id EBA4A2CCF1F77; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.494977795@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:33 +0100
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
Subject: [PATCH v3 19/51] cpuidle,intel_idle: Fix CPUIDLE_FLAG_INIT_XSTATE
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=oqN2YQaX;
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

vmlinux.o: warning: objtool: intel_idle_s2idle+0xd5: call to fpu_idle_fpregs() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_xstate+0x11: call to fpu_idle_fpregs() leaves .noinstr.text section
vmlinux.o: warning: objtool: fpu_idle_fpregs+0x9: call to xfeatures_in_use() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/include/asm/fpu/xcr.h       |    4 ++--
 arch/x86/include/asm/special_insns.h |    2 +-
 arch/x86/kernel/fpu/core.c           |    4 ++--
 3 files changed, 5 insertions(+), 5 deletions(-)

--- a/arch/x86/include/asm/fpu/xcr.h
+++ b/arch/x86/include/asm/fpu/xcr.h
@@ -5,7 +5,7 @@
 #define XCR_XFEATURE_ENABLED_MASK	0x00000000
 #define XCR_XFEATURE_IN_USE_MASK	0x00000001
 
-static inline u64 xgetbv(u32 index)
+static __always_inline u64 xgetbv(u32 index)
 {
 	u32 eax, edx;
 
@@ -27,7 +27,7 @@ static inline void xsetbv(u32 index, u64
  *
  * Callers should check X86_FEATURE_XGETBV1.
  */
-static inline u64 xfeatures_in_use(void)
+static __always_inline u64 xfeatures_in_use(void)
 {
 	return xgetbv(XCR_XFEATURE_IN_USE_MASK);
 }
--- a/arch/x86/include/asm/special_insns.h
+++ b/arch/x86/include/asm/special_insns.h
@@ -295,7 +295,7 @@ static inline int enqcmds(void __iomem *
 	return 0;
 }
 
-static inline void tile_release(void)
+static __always_inline void tile_release(void)
 {
 	/*
 	 * Instruction opcode for TILERELEASE; supported in binutils
--- a/arch/x86/kernel/fpu/core.c
+++ b/arch/x86/kernel/fpu/core.c
@@ -856,12 +856,12 @@ int fpu__exception_code(struct fpu *fpu,
  * Initialize register state that may prevent from entering low-power idle.
  * This function will be invoked from the cpuidle driver only when needed.
  */
-void fpu_idle_fpregs(void)
+noinstr void fpu_idle_fpregs(void)
 {
 	/* Note: AMX_TILE being enabled implies XGETBV1 support */
 	if (cpu_feature_enabled(X86_FEATURE_AMX_TILE) &&
 	    (xfeatures_in_use() & XFEATURE_MASK_XTILE)) {
 		tile_release();
-		fpregs_deactivate(&current->thread.fpu);
+		__this_cpu_write(fpu_fpregs_owner_ctx, NULL);
 	}
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.494977795%40infradead.org.
