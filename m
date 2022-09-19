Return-Path: <kasan-dev+bncBDBK55H2UQKRBQEDUGMQMGQE24LN7JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B31755BC675
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:37 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id bp4-20020a056512158400b0049f93244164sf1520724lfb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582657; cv=pass;
        d=google.com; s=arc-20160816;
        b=savIZrIvuT2+52H8r0hIPpYw+sUoM5hkpluwcBHQ54L0snDPWQr9MzjbYXj8A7SPXz
         x8p3vYJ04DswS4Yl9C3EjLNjpAQLYlVoklk0FoRDsZMVvocrwzpflFp9kc2NnQO2aK3W
         r0rBYeMWSZJR97N7fRjXuT86HK0zbm2X2sBrDc8juJg6x6vEQVWored31giup3C3Jdl3
         4Ku8i+S+HoJD6XfPkS+4J2R6L8zftxwvgR0z+Ga0RQrAMEj2b7+ChrDkMWTbBDiCEeEL
         fJdgetySiPG1R6P3B3znssnR/LsmNVy3HMfi1cV4W4zroM++hhIh2acGJNpDtaUPJ99C
         /qSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=lMbZFuEKGeGoVoAjEharY4G8swJOGikR9j7IYrt3Q+I=;
        b=RjgP5jRqTEwgNJieeNb2VkZMRp7DHrT6c83bZlCgUJpXOU4Au8pwyPZJYm7ziAROvn
         DffqDGiGRVFTNQgiHjX58t4CwyaNHvHqavHJ3uPpW2O21YXD+O3If3S0b9ggdDdTS1/d
         VfxbKGz07Z0xDMv+uHXXpff+Y1QGJcLe6p/TG8Y5PZaYiadlGgCavnQa+GoB3PR1Due+
         l99yY3Ui5ry118EcH5zkUm2u0+UWI8PfxqowV5YAGgLVvvxxwu8mxoYl3CvQZFWDjZ4I
         DzVbbBj1RTlugdKxsqA2xnXHjouHXAb65ze5C5Jnd0EAI5Gm9N9jDduo7DVZ5wcAyaU3
         3Axw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ocGTItbn;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=lMbZFuEKGeGoVoAjEharY4G8swJOGikR9j7IYrt3Q+I=;
        b=FPZ/wCCYiZkTlWMwUpLrOpDkKGnUihnbn2vXTmDZm2X2bkxH/xm8tNanyUGm5oEPGU
         1jqSnqf0t2sguUBTBiXoe8IhWQwBy3P30/yH/vTMo3V9QbfLdEcAnucMBvdv+MAOD8T4
         mXnhBn6fKOENpzop1+QtwLL2YUdHyD0GRUhzQMKM+9TPq7DX6Ki3W++sYS/3ln25gGqT
         TscIo8m36d80+CP1VKSedt+vWFPOqC3smzwtfL/a47pQxqPj9vwKvdBe2tgXlVvbl6l8
         V9QgkhuaLFqON7yyAQWZvX6WSPo1zZS9pK1y2O3xb2m0PbgH4nnycoSF9dCwjrwZn854
         uL1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=lMbZFuEKGeGoVoAjEharY4G8swJOGikR9j7IYrt3Q+I=;
        b=vb1o4Vps0audwBdmXwF3FhUBkrZy6mahyhE+IBVQwEVnWoY4K6C17M6jR21UQ2WAYr
         5BNWPtNospw/amYxMbOzavrOMxrc9wvKLBB7QNEmdt/76gxZ6LsTOlvRggGO2+0NhuD0
         2FFJ8K7+WxW0ZeXWDofE9MelE90fbgyX4uemZrCvAEjBaNukqH1NYkS2dm0ae9uDfc/R
         C2gNVYrFIkRuvXpUvmKnrPJrjuZIYWbeQA9a19tjUAJAnnWz3MrQgFDxUHtmahQN7/k1
         vtfti9LuaCS4NzJ0UCNfNRNU1E7S1LKO627VzmKVCIAhPc7ytYyQYqes5TvVl0YhVWSL
         rPJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0L1IzRLc8/lQhd61es4d/trYUbV6FmxhAsHx6DOTR7SB8Tz0gK
	DpiK3ofZe0ADrCfOPl4P3nQ=
X-Google-Smtp-Source: AMsMyM7/2IPnWk1PygdtFsWfKmyLauhgEJVFoDfjaIdqgl/FEJdbLQYPZm+D5Q1lJF1vrDaZCWMlMw==
X-Received: by 2002:a05:6512:31cf:b0:496:f023:5471 with SMTP id j15-20020a05651231cf00b00496f0235471mr5987244lfe.133.1663582657097;
        Mon, 19 Sep 2022 03:17:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc27:0:b0:26b:fc94:e182 with SMTP id b39-20020a2ebc27000000b0026bfc94e182ls584654ljf.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:35 -0700 (PDT)
X-Received: by 2002:a2e:beaa:0:b0:25e:34d0:4d57 with SMTP id a42-20020a2ebeaa000000b0025e34d04d57mr4927511ljr.329.1663582655683;
        Mon, 19 Sep 2022 03:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582655; cv=none;
        d=google.com; s=arc-20160816;
        b=uhzqk0WmiADOJZyWBDwgWhEdbb6qD725zQOOKovxi5q4sDYTO7hzf+G66wkB7TYe9k
         apGSxiU5XzZXJ/vzfgDe+WL4dD0mmk+og4K/uAs4RldjMv4Vkz9l0m5X0xnD7AF7mdBP
         JHnIeXOkV96jqdK6zN3HrruTwQAlWN8ictrKS6JNSJwG098ntuqDc9Tp5q+1lQ/Jh2ur
         /034UDB/FcPH8VZFy5y9y3IrPiCzLACluLrHCkKwNcOkRgTWgvMZkhWbVna9tSRkHY3u
         AjZUUfl9jL2y40BRUmE03161q+3Yh0YpV1NuXOoLjhcGEcZEaeUPDKBAJhHjv7OuWyCP
         dydg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=5J6w0/E9GHUuxcPhak3+lKL/wLFktsWBVlnujWsvOEE=;
        b=aGnGXq6ll83negQCpIQms2Rd5zhcNb+6WBGE7ihyNVN4XEqL7S+EpRr8/lWGj9rZVm
         ufRnSDLDn2G5KX+WcWGB0GhL2CpqJC6BHDS/HlinpdNwhJ2plBNqraID/v/r7z8rXQkQ
         wWac056A2AMvlTG9jF24mCsNIvz+7fERq46ohrTX0E8/e5JwnZfTjK+hPJvRT5Nuux+t
         RkSG/bU1lRUbUBLq2wdU7jtfCmhdon4PCMGKuesioP8YG/AX2F/Z9keIWzNXcZ8qNPTT
         GNPSFWaX/f0PfLx5YVN/MIPu9rVSQvFwv3nTdDTHZbK9ZrAe4Qie0eVwcfYgnNrb0Z3Q
         lUUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ocGTItbn;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id d15-20020a056512368f00b0048b38f379d7si768296lfs.0.2022.09.19.03.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:35 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq7-004b9g-VA; Mon, 19 Sep 2022 10:17:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 480BA302F3E;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 646262BAC75A6; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.291054325@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:08 +0200
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
Subject: [PATCH v2 29/44] cpuidle,tdx: Make tdx noinstr clean
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ocGTItbn;
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

vmlinux.o: warning: objtool: __halt+0x2c: call to hcall_func.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: __halt+0x3f: call to __tdx_hypercall() leaves .noinstr.text section
vmlinux.o: warning: objtool: __tdx_hypercall+0x66: call to __tdx_hypercall_failed() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/boot/compressed/vmlinux.lds.S |    1 +
 arch/x86/coco/tdx/tdcall.S             |    2 ++
 arch/x86/coco/tdx/tdx.c                |    5 +++--
 3 files changed, 6 insertions(+), 2 deletions(-)

--- a/arch/x86/boot/compressed/vmlinux.lds.S
+++ b/arch/x86/boot/compressed/vmlinux.lds.S
@@ -34,6 +34,7 @@ SECTIONS
 		_text = .; 	/* Text */
 		*(.text)
 		*(.text.*)
+		*(.noinstr.text)
 		_etext = . ;
 	}
 	.rodata : {
--- a/arch/x86/coco/tdx/tdcall.S
+++ b/arch/x86/coco/tdx/tdcall.S
@@ -31,6 +31,8 @@
 					  TDX_R12 | TDX_R13 | \
 					  TDX_R14 | TDX_R15 )
 
+.section .noinstr.text, "ax"
+
 /*
  * __tdx_module_call()  - Used by TDX guests to request services from
  * the TDX module (does not include VMM services) using TDCALL instruction.
--- a/arch/x86/coco/tdx/tdx.c
+++ b/arch/x86/coco/tdx/tdx.c
@@ -53,8 +53,9 @@ static inline u64 _tdx_hypercall(u64 fn,
 }
 
 /* Called from __tdx_hypercall() for unrecoverable failure */
-void __tdx_hypercall_failed(void)
+noinstr void __tdx_hypercall_failed(void)
 {
+	instrumentation_begin();
 	panic("TDVMCALL failed. TDX module bug?");
 }
 
@@ -64,7 +65,7 @@ void __tdx_hypercall_failed(void)
  * Reusing the KVM EXIT_REASON macros makes it easier to connect the host and
  * guest sides of these calls.
  */
-static u64 hcall_func(u64 exit_reason)
+static __always_inline u64 hcall_func(u64 exit_reason)
 {
 	return exit_reason;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.291054325%40infradead.org.
