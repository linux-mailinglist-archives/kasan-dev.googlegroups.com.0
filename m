Return-Path: <kasan-dev+bncBDF57NG2XIHRBLU46GMQMGQETBS4QRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id A73275F4647
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 17:15:59 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id k11-20020a5b038b000000b006bbf786c30asf13419746ybp.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 08:15:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664896558; cv=pass;
        d=google.com; s=arc-20160816;
        b=e+dk2LooH7OMvXiwKzydVFhguvnrwKYa2UPudGcuo6OG97XiAJD5RIC+iLrxgTeM0l
         3zcf0WtfV0ssMjBZ+SzSJIdrVMmr3kP2VpwOGahb6OWjvYsYfFuN+Z0Ol7IzS10fIJNz
         xNY3l+/ewsNcURPIQky2Revdp0Y+u1NY2j5G3KUSzV77zfVE36AUFmWyUMCV6dTdix8O
         7/ARe/lCX1ctpoL5lAWK4GnHMUEvJlJ2UBIAt0E+eDOAm04QGA3FuKYE+9nwv/BxYZR7
         ZQcKqa6690BoThJXDujjuu7/zboflMR7lu86fplMV+BkquLLSdGf4f8bESbThd4V4T7j
         EYTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=tEW1X8C6lamve9BLjDWF2cC5XOURQ18kh5BZnc2xV1A=;
        b=bixoMJ7q1mcVtEeMOofS4klsrdL004lKpRAJDOO47X1nGyKwEjZyd3z2Ylzd+StXT5
         9r7Bk23G0HUAWlmvYvxfWxqtjnwOJX+amOK5RuATTn3z4CcHXNRJTaU9LfFijHLbjS20
         RQRXSkIY10CZqmdG/306BE7WTPyPFaH3dYKvVtwBI3dFjvZhqWDAr4JvL6+uw8qOUcyX
         yVxFs9XUw+O0kITE1VAX0arfEJ/auSwypb5lc6Znq83D5g8fPbnd/lsEreM5CDwbxizP
         WrOb9pepYgMr+LSaz9Vb5M9i0GdMwDZzwOAvq46RJzFuNVW1YmwAb63pcemLol2kMngj
         4YiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=UiXw6aHZ;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=tEW1X8C6lamve9BLjDWF2cC5XOURQ18kh5BZnc2xV1A=;
        b=KMy93RIWFq+p7lZxfkJMu/TW8TJcoOt5oCuXsflf6oc5BoGpNpoHntH0x4mdABXZ5S
         C9sjk/Ou/oNrDG7aypb7M/Yj1rzZhQQAAPcIHoP5wz8X7Rpff1QfUGDLU4RGL/5V7E7u
         5u8pl1BjIx1aRZONnmla5Irfcx2a0xB0JjreN4T2mkXcu/445aI+CzOzF0fGByhNHMWi
         TGpbfH0yAXNJw+B6r3nbxeN7QsQvBW7ethQ6za0NXbs8KBD+IrvNWIqg6k0zkkYMbAUh
         6SvR+MxA+c82gyYUVqWVi+gn65p1nBKNNqm/iX3y18h5HyKpdDbVwJBAx8gqGwkm0lKh
         kPIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=tEW1X8C6lamve9BLjDWF2cC5XOURQ18kh5BZnc2xV1A=;
        b=g+e/oUTlVFTb5tTrHnF3wmFkBeEjT8tFvxiSSrQ5CwlGgQo4kZzuhyb3CgVSAJPQL3
         dSLRbgzWfR0MhVKTYQzV2GpbtVZrBJdXxj2I4kuNQcjhCDb8Vmvq17u1IqaGdbPsK4GW
         LgiV79QFEfLwWv2KQgfTWad1ZPwkpBFhUitwCUq82TlXmoaXQXqMNvsiyvzhUiyRBq5E
         H+anOrjSZS74idSUFavr9pzhboPC0Keg49yJg9I7C+6+BKXy89NP5mRczA+5vJHdMPDe
         OicD0aHbOOr4JFWVYGnBzfZ6m7huS1KCKsLLFfybvur56yxjpDWGvtyLLs5BZm/AtyTO
         AMAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1FoalXP3Zo2QyYZRZ7pArOvRXT7EwR4In3gR3YvX4I1eJkNkZL
	Ij+dIQX4tBu5eEgdD9+iXak=
X-Google-Smtp-Source: AMsMyM4sAHLcHcD4EonbJLl0o+ek+yGI6AKoFY0uI5iIu6GyR9mL2VBqgF4+J9tkYHTr10690dP8tg==
X-Received: by 2002:a25:cb89:0:b0:6bd:7f28:f5b8 with SMTP id b131-20020a25cb89000000b006bd7f28f5b8mr11915774ybg.571.1664896558517;
        Tue, 04 Oct 2022 08:15:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a025:0:b0:6bd:2495:653f with SMTP id x34-20020a25a025000000b006bd2495653fls6499336ybh.5.-pod-prod-gmail;
 Tue, 04 Oct 2022 08:15:58 -0700 (PDT)
X-Received: by 2002:a25:2497:0:b0:6bc:d31a:19ce with SMTP id k145-20020a252497000000b006bcd31a19cemr23553026ybk.83.1664896557908;
        Tue, 04 Oct 2022 08:15:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664896557; cv=none;
        d=google.com; s=arc-20160816;
        b=C6RGYZXYUhOzkJU61+ldm4DlUd2dDy8QW6eCSUfbLBYQ9KspMeD4KPOlXgttG9/a+Z
         t08YSlJZai4KQP7nWfeN4vlhU4PMKACJgimiQtK7N42pP1YJsA7yeGo4kDOEUUm9cgss
         caX9qP8RlxOHGwn+v/emLePSOOkgidp0euNIY5hygcKouuLCwtw6+SpJsylFDv2ETAfq
         YaXgpNlZyBql5vEhjq+mtL1eQHHIShiiUxxjdkd5yAsVgkyC3qkCgDlBUJAIvlTY7INx
         86AKpDmX2yAxLAk7hzLETB4L+lTqNtfsPsyx85odNNZEuJqbULsvGAbXDVgNmhNeE1mJ
         4klQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J2ppHC6gj92crGPpSrELKUpyhixWpF3W0/4C0ZdDtPI=;
        b=UB+XV3RzvZRKOIXO4R6EBWQut3TNJuL8LjtAmXsKsTE//nsKc4wv2KxIytJ+oSRqnw
         wRoDjY2n4a4J9L65NJUWF2Wod2t3jx7CAAeZhmdUhm6DThm8S2Tzaaa3PbLJA3SiKwK9
         p1nMAorGa2BjkBCjXlDxtPKKZX83fqRRvKIEdJ8KoewBtFZ8jlofMxU2XEcI39WjqxeA
         h7QjttNpIObUWKvptH5Uit0GVWiPaCkHW7xkRq/YIFhRlf01wuUNSNRazJanjaD9HX3w
         +AQ1UB9pvV9e97zcGlV0z3AZ3bsb+rg3FUz/PKfbyCr5K3YC8rbpFRBe2doS/W82fzs2
         igYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=UiXw6aHZ;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id bp1-20020a05690c068100b00330253b8e8asi769384ywb.0.2022.10.04.08.15.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 08:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id p3-20020a17090a284300b0020a85fa3ffcso7244717pjf.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 08:15:57 -0700 (PDT)
X-Received: by 2002:a17:90b:1b06:b0:202:cce0:2148 with SMTP id
 nu6-20020a17090b1b0600b00202cce02148mr262733pjb.84.1664896556863; Tue, 04 Oct
 2022 08:15:56 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org>
In-Reply-To: <20220919095939.761690562@infradead.org>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 17:15:20 +0200
Message-ID: <CAPDyKFqwV27k5r8Pqo0bOqKQ2WKfcMdQoua665nA953U36+rXg@mail.gmail.com>
Subject: Re: [PATCH v2 00/44] cpuidle,rcu: Clean up the mess
To: Peter Zijlstra <peterz@infradead.org>
Cc: juri.lelli@redhat.com, rafael@kernel.org, catalin.marinas@arm.com, 
	linus.walleij@linaro.org, bsegall@google.com, guoren@kernel.org, pavel@ucw.cz, 
	agordeev@linux.ibm.com, linux-arch@vger.kernel.org, 
	vincent.guittot@linaro.org, mpe@ellerman.id.au, chenhuacai@kernel.org, 
	christophe.leroy@csgroup.eu, linux-acpi@vger.kernel.org, agross@kernel.org, 
	geert@linux-m68k.org, linux-imx@nxp.com, vgupta@kernel.org, 
	mattst88@gmail.com, mturquette@baylibre.com, sammy@sammy.net, 
	pmladek@suse.com, linux-pm@vger.kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, linux-um@lists.infradead.org, npiggin@gmail.com, 
	tglx@linutronix.de, linux-omap@vger.kernel.org, dietmar.eggemann@arm.com, 
	andreyknvl@gmail.com, gregkh@linuxfoundation.org, 
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org, 
	senozhatsky@chromium.org, svens@linux.ibm.com, jolsa@kernel.org, 
	tj@kernel.org, Andrew Morton <akpm@linux-foundation.org>, mark.rutland@arm.com, 
	linux-ia64@vger.kernel.org, dave.hansen@linux.intel.com, 
	virtualization@lists.linux-foundation.org, 
	James.Bottomley@hansenpartnership.com, jcmvbkbc@gmail.com, 
	thierry.reding@gmail.com, kernel@xen0n.name, cl@linux.com, 
	linux-s390@vger.kernel.org, vschneid@redhat.com, john.ogness@linutronix.de, 
	ysato@users.sourceforge.jp, linux-sh@vger.kernel.org, festevam@gmail.com, 
	deller@gmx.de, daniel.lezcano@linaro.org, jonathanh@nvidia.com, 
	dennis@kernel.org, lenb@kernel.org, linux-xtensa@linux-xtensa.org, 
	kernel@pengutronix.de, gor@linux.ibm.com, linux-arm-msm@vger.kernel.org, 
	linux-alpha@vger.kernel.org, linux-m68k@lists.linux-m68k.org, 
	loongarch@lists.linux.dev, shorne@gmail.com, chris@zankel.net, 
	sboyd@kernel.org, dinguyen@kernel.org, bristot@redhat.com, 
	alexander.shishkin@linux.intel.com, fweisbec@gmail.com, lpieralisi@kernel.org, 
	atishp@atishpatra.org, linux@rasmusvillemoes.dk, kasan-dev@googlegroups.com, 
	will@kernel.org, boris.ostrovsky@oracle.com, khilman@kernel.org, 
	linux-csky@vger.kernel.org, pv-drivers@vmware.com, 
	linux-snps-arc@lists.infradead.org, mgorman@suse.de, 
	jacob.jun.pan@linux.intel.com, Arnd Bergmann <arnd@arndb.de>, ulli.kroll@googlemail.com, 
	linux-clk@vger.kernel.org, rostedt@goodmis.org, ink@jurassic.park.msu.ru, 
	bcain@quicinc.com, tsbogend@alpha.franken.de, linux-parisc@vger.kernel.org, 
	ryabinin.a.a@gmail.com, sudeep.holla@arm.com, shawnguo@kernel.org, 
	davem@davemloft.net, dalias@libc.org, tony@atomide.com, amakhalov@vmware.com, 
	konrad.dybcio@somainline.org, bjorn.andersson@linaro.org, glider@google.com, 
	hpa@zytor.com, sparclinux@vger.kernel.org, linux-hexagon@vger.kernel.org, 
	linux-riscv@lists.infradead.org, vincenzo.frascino@arm.com, 
	anton.ivanov@cambridgegreys.com, jonas@southpole.se, yury.norov@gmail.com, 
	richard@nod.at, x86@kernel.org, linux@armlinux.org.uk, mingo@redhat.com, 
	aou@eecs.berkeley.edu, hca@linux.ibm.com, richard.henderson@linaro.org, 
	stefan.kristiansson@saunalahti.fi, openrisc@lists.librecores.org, 
	acme@kernel.org, paul.walmsley@sifive.com, linux-tegra@vger.kernel.org, 
	namhyung@kernel.org, andriy.shevchenko@linux.intel.com, jpoimboe@kernel.org, 
	dvyukov@google.com, jgross@suse.com, monstr@monstr.eu, 
	linux-mips@vger.kernel.org, palmer@dabbelt.com, anup@brainfault.org, 
	bp@alien8.de, johannes@sipsolutions.net, linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ulf.hansson@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=UiXw6aHZ;       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, 19 Sept 2022 at 12:18, Peter Zijlstra <peterz@infradead.org> wrote:
>
> Hi All!
>
> At long last, a respin of the cpuidle vs rcu cleanup patches.
>
> v1: https://lkml.kernel.org/r/20220608142723.103523089@infradead.org
>
> These here patches clean up the mess that is cpuidle vs rcuidle.
>
> At the end of the ride there's only on RCU_NONIDLE user left:
>
>   arch/arm64/kernel/suspend.c:            RCU_NONIDLE(__cpu_suspend_exit());
>
> and 'one' trace_*_rcuidle() user:
>
>   kernel/trace/trace_preemptirq.c:                        trace_irq_enable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
>   kernel/trace/trace_preemptirq.c:                        trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
>   kernel/trace/trace_preemptirq.c:                        trace_irq_enable_rcuidle(CALLER_ADDR0, caller_addr);
>   kernel/trace/trace_preemptirq.c:                        trace_irq_disable_rcuidle(CALLER_ADDR0, caller_addr);
>   kernel/trace/trace_preemptirq.c:                trace_preempt_enable_rcuidle(a0, a1);
>   kernel/trace/trace_preemptirq.c:                trace_preempt_disable_rcuidle(a0, a1);
>
> However this last is all in deprecated code that should be unused for GENERIC_ENTRY.
>
> I've touched a lot of code that I can't test and I might've broken something by
> accident. In particular the whole ARM cpuidle stuff was quite involved.
>
> Please all; have a look where you haven't already.
>
>
> New since v1:
>
>  - rebase on top of Frederic's rcu-context-tracking rename fest
>  - more omap goodness as per the last discusion (thanks Tony!)
>  - removed one more RCU_NONIDLE() from arm64/risc-v perf code
>  - ubsan/kasan fixes
>  - intel_idle module-param for testing
>  - a bunch of extra __always_inline, because compilers are silly.
>
> ---
>  arch/alpha/kernel/process.c               |  1 -
>  arch/alpha/kernel/vmlinux.lds.S           |  1 -
>  arch/arc/kernel/process.c                 |  3 ++
>  arch/arc/kernel/vmlinux.lds.S             |  1 -
>  arch/arm/include/asm/vmlinux.lds.h        |  1 -
>  arch/arm/kernel/process.c                 |  1 -
>  arch/arm/kernel/smp.c                     |  6 +--
>  arch/arm/mach-gemini/board-dt.c           |  3 +-
>  arch/arm/mach-imx/cpuidle-imx6q.c         |  4 +-
>  arch/arm/mach-imx/cpuidle-imx6sx.c        |  5 ++-
>  arch/arm/mach-omap2/common.h              |  6 ++-
>  arch/arm/mach-omap2/cpuidle34xx.c         | 16 +++++++-
>  arch/arm/mach-omap2/cpuidle44xx.c         | 29 +++++++-------
>  arch/arm/mach-omap2/omap-mpuss-lowpower.c | 12 +++++-
>  arch/arm/mach-omap2/pm.h                  |  2 +-
>  arch/arm/mach-omap2/pm24xx.c              | 51 +-----------------------
>  arch/arm/mach-omap2/pm34xx.c              | 14 +++++--
>  arch/arm/mach-omap2/pm44xx.c              |  2 +-
>  arch/arm/mach-omap2/powerdomain.c         | 10 ++---
>  arch/arm64/kernel/idle.c                  |  1 -
>  arch/arm64/kernel/smp.c                   |  4 +-
>  arch/arm64/kernel/vmlinux.lds.S           |  1 -
>  arch/csky/kernel/process.c                |  1 -
>  arch/csky/kernel/smp.c                    |  2 +-
>  arch/csky/kernel/vmlinux.lds.S            |  1 -
>  arch/hexagon/kernel/process.c             |  1 -
>  arch/hexagon/kernel/vmlinux.lds.S         |  1 -
>  arch/ia64/kernel/process.c                |  1 +
>  arch/ia64/kernel/vmlinux.lds.S            |  1 -
>  arch/loongarch/kernel/idle.c              |  1 +
>  arch/loongarch/kernel/vmlinux.lds.S       |  1 -
>  arch/m68k/kernel/vmlinux-nommu.lds        |  1 -
>  arch/m68k/kernel/vmlinux-std.lds          |  1 -
>  arch/m68k/kernel/vmlinux-sun3.lds         |  1 -
>  arch/microblaze/kernel/process.c          |  1 -
>  arch/microblaze/kernel/vmlinux.lds.S      |  1 -
>  arch/mips/kernel/idle.c                   |  8 ++--
>  arch/mips/kernel/vmlinux.lds.S            |  1 -
>  arch/nios2/kernel/process.c               |  1 -
>  arch/nios2/kernel/vmlinux.lds.S           |  1 -
>  arch/openrisc/kernel/process.c            |  1 +
>  arch/openrisc/kernel/vmlinux.lds.S        |  1 -
>  arch/parisc/kernel/process.c              |  2 -
>  arch/parisc/kernel/vmlinux.lds.S          |  1 -
>  arch/powerpc/kernel/idle.c                |  5 +--
>  arch/powerpc/kernel/vmlinux.lds.S         |  1 -
>  arch/riscv/kernel/process.c               |  1 -
>  arch/riscv/kernel/vmlinux-xip.lds.S       |  1 -
>  arch/riscv/kernel/vmlinux.lds.S           |  1 -
>  arch/s390/kernel/idle.c                   |  1 -
>  arch/s390/kernel/vmlinux.lds.S            |  1 -
>  arch/sh/kernel/idle.c                     |  1 +
>  arch/sh/kernel/vmlinux.lds.S              |  1 -
>  arch/sparc/kernel/leon_pmc.c              |  4 ++
>  arch/sparc/kernel/process_32.c            |  1 -
>  arch/sparc/kernel/process_64.c            |  3 +-
>  arch/sparc/kernel/vmlinux.lds.S           |  1 -
>  arch/um/kernel/dyn.lds.S                  |  1 -
>  arch/um/kernel/process.c                  |  1 -
>  arch/um/kernel/uml.lds.S                  |  1 -
>  arch/x86/boot/compressed/vmlinux.lds.S    |  1 +
>  arch/x86/coco/tdx/tdcall.S                | 15 +------
>  arch/x86/coco/tdx/tdx.c                   | 25 ++++--------
>  arch/x86/events/amd/brs.c                 | 13 +++----
>  arch/x86/include/asm/fpu/xcr.h            |  4 +-
>  arch/x86/include/asm/irqflags.h           | 11 ++----
>  arch/x86/include/asm/mwait.h              | 14 +++----
>  arch/x86/include/asm/nospec-branch.h      |  2 +-
>  arch/x86/include/asm/paravirt.h           |  6 ++-
>  arch/x86/include/asm/perf_event.h         |  2 +-
>  arch/x86/include/asm/shared/io.h          |  4 +-
>  arch/x86/include/asm/shared/tdx.h         |  1 -
>  arch/x86/include/asm/special_insns.h      |  8 ++--
>  arch/x86/include/asm/xen/hypercall.h      |  2 +-
>  arch/x86/kernel/cpu/bugs.c                |  2 +-
>  arch/x86/kernel/fpu/core.c                |  4 +-
>  arch/x86/kernel/paravirt.c                | 14 ++++++-
>  arch/x86/kernel/process.c                 | 65 +++++++++++++++----------------
>  arch/x86/kernel/vmlinux.lds.S             |  1 -
>  arch/x86/lib/memcpy_64.S                  |  5 +--
>  arch/x86/lib/memmove_64.S                 |  4 +-
>  arch/x86/lib/memset_64.S                  |  4 +-
>  arch/x86/xen/enlighten_pv.c               |  2 +-
>  arch/x86/xen/irq.c                        |  2 +-
>  arch/xtensa/kernel/process.c              |  1 +
>  arch/xtensa/kernel/vmlinux.lds.S          |  1 -
>  drivers/acpi/processor_idle.c             | 36 ++++++++++-------
>  drivers/base/power/runtime.c              | 24 ++++++------
>  drivers/clk/clk.c                         |  8 ++--
>  drivers/cpuidle/cpuidle-arm.c             |  1 +
>  drivers/cpuidle/cpuidle-big_little.c      |  8 +++-
>  drivers/cpuidle/cpuidle-mvebu-v7.c        |  7 ++++
>  drivers/cpuidle/cpuidle-psci.c            | 10 +++--
>  drivers/cpuidle/cpuidle-qcom-spm.c        |  1 +
>  drivers/cpuidle/cpuidle-riscv-sbi.c       | 10 +++--
>  drivers/cpuidle/cpuidle-tegra.c           | 21 +++++++---
>  drivers/cpuidle/cpuidle.c                 | 21 +++++-----
>  drivers/cpuidle/dt_idle_states.c          |  2 +-
>  drivers/cpuidle/poll_state.c              | 10 ++++-
>  drivers/idle/intel_idle.c                 | 19 +++++----
>  drivers/perf/arm_pmu.c                    | 11 +-----
>  drivers/perf/riscv_pmu_sbi.c              |  8 +---
>  include/asm-generic/vmlinux.lds.h         |  9 ++---
>  include/linux/compiler_types.h            |  8 +++-
>  include/linux/cpu.h                       |  3 --
>  include/linux/cpuidle.h                   | 34 ++++++++++++++++
>  include/linux/cpumask.h                   |  4 +-
>  include/linux/percpu-defs.h               |  2 +-
>  include/linux/sched/idle.h                | 40 ++++++++++++++-----
>  include/linux/thread_info.h               | 18 ++++++++-
>  include/linux/tracepoint.h                | 13 ++++++-
>  kernel/cpu_pm.c                           |  9 -----
>  kernel/printk/printk.c                    |  2 +-
>  kernel/sched/idle.c                       | 47 +++++++---------------
>  kernel/time/tick-broadcast-hrtimer.c      | 29 ++++++--------
>  kernel/time/tick-broadcast.c              |  6 ++-
>  kernel/trace/trace.c                      |  3 ++
>  lib/ubsan.c                               |  5 ++-
>  mm/kasan/kasan.h                          |  4 ++
>  mm/kasan/shadow.c                         | 38 ++++++++++++++++++
>  tools/objtool/check.c                     | 17 ++++++++
>  121 files changed, 511 insertions(+), 420 deletions(-)

Thanks for cleaning up the situation!

I have applied this on a plain v6.0 (only one patch had a minor
conflict) and tested this on an ARM64 Dragonboard 410c, which uses
cpuidle-psci and the cpuidle-psci-domain. I didn't observe any
problems, so feel free to add:

Tested-by: Ulf Hansson <ulf.hansson@linaro.org>

Kind regards
Uffe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFqwV27k5r8Pqo0bOqKQ2WKfcMdQoua665nA953U36%2BrXg%40mail.gmail.com.
