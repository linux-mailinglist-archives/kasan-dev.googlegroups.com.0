Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FA00667FEC
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id f15-20020a056402354f00b00485864db618sf13106378edd.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=ycPx8ZKXplv4FtE/xPmBfL+Vo51MZD0DjSRIEs4NlscHydfg2YwAPVm8slcIQ5u6/V
         FUHtgKon5/RlphirGlK9XvFNvXuuwA37PUnPb+JYgaJLxUAKzsKVnkbfk+gvQ6QXALTr
         pDrngyFencSMT0iT8gWZx5BGrCg2w8VC7ib87KFjD0owkMs3Vcyhf8fhZxROEc9kcVkN
         TP0duyqmq+WEOR/Kwpx6J+pY+qq4VERBZXOjqR4/7lVLwZAbnB5cSg2/iQCD3UT8TcxU
         XNPNp9HbSnBMQMeIw1u/xVHf86Vg7iot52ijKsaXtXJjmryRLaH0Rl+Q16oxhcGJYbeF
         2DMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=nUA8nnIdwItM4z8xB2mbNcV45UBZt+VZ+QLxeKq4vxo=;
        b=zmKMnAbu7IUSNgXVGWVn8eHLc0UXAXXyrSOMmWqoF0m0qdrzoqWgkjHhQzxsvR//+Q
         9msvyR682wgqH9BIHrPayAUYiO7axik9TyGqe13uRHugZMcVTTl/oLoGcRyCStI3MoWV
         Vt72tVlVjjGHRb2JG3px1sNU/bmIQqG8Bzkd58YVbyoL2B7St/0AYfVjKIqA5zas7/L7
         z33nH1jO6xYaEe68Qx7Aejn9R6DXBxM8SO0NDIli57k+WXniDDEzCtO3S3LJn+4TtyGI
         Igaeu8Ul9ExRmnVj5pQn0JDRIdM67mFB9bJtfb2i2KJDd873OtiXTFKqYHy+sle6Ms+M
         w5Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DFTaqgOr;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nUA8nnIdwItM4z8xB2mbNcV45UBZt+VZ+QLxeKq4vxo=;
        b=FMRaGR9iyMDIjMkx1V9ZUu5by5igh9k2TUmKIIB6V4MHj4Fim72shQ4PjM6eHmGKp1
         9YCl35PnVCtmz10q+cRI9S41FtqsZLkUilVPTajeO3h9UoIEZPLpdKFwTFpOG3VGrDen
         6VQX4Op5h+OLUHt/fH+jce6MZxxD+0ZnpCZjZz8I/yePeyszTDzTN3h7TKq2wbtzbI1H
         jag9sSwND3fV+dx8xwBh+cg1EKqIjJJubb408GNxjWdIt/39YH1lQ0p0i+0rva81gQyr
         LD0Hf6LeGKEkscZot6h/6CmnTsnZMpD5wmADixkdcBy84N3gAz/ZVXSWvdyMEIcZmrV2
         ErPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nUA8nnIdwItM4z8xB2mbNcV45UBZt+VZ+QLxeKq4vxo=;
        b=6AyKqQ9jrvzaSVHNdq22/AGP6J6Toj/Ea1BSKVDDG+CFc9EWwvgfxWjY3ZmfQarf0p
         wc/zNHkPpX0xa/3anxHDziMTxflskoXABH3AaVM3joxA4KAGJ106NYrpeYyB1zSIWOk4
         tf4yQHJlWvWO7pZdXomjwNvouV1cBjc634UjzRnMn9n96AtIdKsda8u9OoY3Z4V0+55h
         IxZgotXIeGgv0+dxjWKR2dzKqx+MDZQG7WsnxsTC012dAWrbSKGer/X6sJ5o5MeyScDQ
         XIwloDLK1FgMDXnnBE0jp0mJgMN23yGTnd4I93eJHPGcDYkU37LqarkfmvA9vKPqCpy/
         BFKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krQUqw93vPEeGbodAhUX9CmRKM+bRE7hKdoLNtblbiItMDivboc
	/VXdhp6Zp9kZn60kn/gb6hE=
X-Google-Smtp-Source: AMrXdXti+zo8KDbp5ZFa3C7k1Q5ohbV75h3tbBBiKeGU3Y6ygbGnhEcvH4zC/FC+tASWoW8Y0W8WCQ==
X-Received: by 2002:a17:906:52c8:b0:7c1:275d:976c with SMTP id w8-20020a17090652c800b007c1275d976cmr8546157ejn.280.1673553514776;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b49:b0:869:2189:ba11 with SMTP id
 v9-20020a1709060b4900b008692189ba11ls808055ejg.9.-pod-prod-gmail; Thu, 12 Jan
 2023 11:58:33 -0800 (PST)
X-Received: by 2002:a17:906:c18d:b0:843:770e:777d with SMTP id g13-20020a170906c18d00b00843770e777dmr65409434ejz.11.1673553513306;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=ozZmDSs7uwUZh+wXP9NN/mJZ9UbBoX+sCi8vtHaeZQGJ7lRVRqkCcPqQ0hcmQxODy0
         dSjYV09BN7ryvktLECPaA4S9jIEY/e9O0eWc7zNfK+EbBwBBLGR23AL5hs0DY29Rw/EO
         a4f3Sxbj/tiqfh8IEio6/eP598dwaKHAR3H63mgBI3w/4Vu1PAkCc40H7kDSqwmTdDFT
         JAcg72PUmDnR3zKVLhoDRLjB4BXgx5+VABaR7Pemf8g4WhikjRADU4fno0eiNdWICY/U
         fL3PH4WVpQxXIQLJqclzRxUcz6ZGFj0yFtv/5Agt67zCesTM8Zy5WiX9BVJuk+SIRd0J
         kGEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=VEFTHHrPJN8MUcU5Q+nJT8cn7XDeQYtM8FLMMPm5jQc=;
        b=Cs7XuyJAeYuOLDn0qXXiB/H/2D0oMFoag++JiKcw/4DHt9X+NjdDsqcEXULMo5KCgB
         fGYJFnlRS18PRaR6hlH6cax+1TNeEr0sXVDNiQs3hk46pQ26OVUMSC9BI+GsL7ZAL9/s
         DkPPJdureWnhxup1GrD3bIj4lnp73yogp7jb7/cvvaRr3G99NhBOF6t5KeS1pQaRblwI
         Un4ODDJ9x+uYxOlZmPZ6fX/+quqvBnJntrUrEadbAn+PBdN8syBL/zjQEOywwweeUxIq
         ZFIosbPEXs5Z3BsB9F4MYffZrtjTyPHsuAtZOzpxJjaWMH+vjdaGfUPfInMAPMRhVkA7
         hUaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DFTaqgOr;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id q5-20020aa7d445000000b0045a1a4ee8d3si744781edr.0.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hc-005Oel-Je; Thu, 12 Jan 2023 19:57:32 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9E22330343F;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 20F0F2CCF62B3; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.111485720@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:43 +0100
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
Subject: [PATCH v3 29/51] cpuidle,tdx: Make tdx noinstr clean
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=DFTaqgOr;
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

vmlinux.o: warning: objtool: __halt+0x2c: call to hcall_func.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: __halt+0x3f: call to __tdx_hypercall() leaves .noinstr.text section
vmlinux.o: warning: objtool: __tdx_hypercall+0x66: call to __tdx_hypercall_failed() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.111485720%40infradead.org.
