Return-Path: <kasan-dev+bncBAABB3MVUWMQMGQEE4Q3L2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7549A5BDC0E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 07:09:02 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id u9-20020a5edd49000000b006a0f03934e9sf876922iop.4
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 22:09:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663650541; cv=pass;
        d=google.com; s=arc-20160816;
        b=tNYD6PXpmzmxZWFSPD1AkhTpainfnyS/ZoZWXeIhBnlDVPyHCRVkp5PeiXdWJpjjtB
         Hp9owwFLQfuCmAV4PO06+xZTDZl1dvx5NqxEya7swn+1B36h9w2rinn/Mp8lDBDDTwf/
         YT7Djkv3hq/bIgXMrodNg2sXLuz+lqzKlG0bk+y4C+5JAoxuR2oO0CQqHJFdaY91PBvR
         UzlhKtDZMmeYLnOR5T1OxUE+ZrmA7x9bjBBjdw6hMNo1myhurVNhLh/bcoLZXQMVr9ke
         fHzP8fFdiGuohGWTqg6dPmP2Hg6btzwVSoMArfLx5D7+w4StAd+5/GttVoBH6qyMwcCD
         AxCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=yoo92g1+EauXIKF2QoPao+zY3NnhLnGTIpbFnu2mjkk=;
        b=KlCt/8HbzWH42v2IGHFc5Qlpk190RU8+wjPp4jvBIIO8EsoZBANsUni90wlRqWZakP
         d8BVjmx5bDrgC6fVgoZU3AB3vnXqBiPnUPvWN1H365PEzofbxwmTxVmeSHbpqKk2GDH9
         9cI2xFYPH0kT5nzCKFLs8XkRKrRBpAkHjNCYolr0qU67DKW2h5BdFcmLJlzaN0PsAAmm
         7bVewF0tbsR1DvVoqlgy2obhortRW8rfBRCIZOhu2dvytQounVZRNjaYhR1ZjkX42d5J
         ExplWmeY1HaDRdG+lJNvatUiDRj6QRsaLjtTLHipEAGT7UoWTTzBrLUpGDidA2YlP4pk
         z5+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aF8efSaL;
       spf=pass (google.com: domain of guoren@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=yoo92g1+EauXIKF2QoPao+zY3NnhLnGTIpbFnu2mjkk=;
        b=UL7AiTocbbsfS4/obP22Lult9pCAWLBc1uPc3Cp9yMfzQM1QX0zRkkFXpvfqRy81+5
         WjAzl0Ul8M+WMxJ+RfRbMgCZDfmR4BDMFNkx+rQFiCQunW9x+Loiu2jBuUallujQvdNY
         dV+ZPRB8hPppqzdLvLZKv970c9IF5JDTOSkI38XVJlbergPYfZ6WviSvj++26oJ5DwiE
         FtHPUuZoGyr7C8upLOmJ1aR1zKYvjcBNjbwnJez+Bx+9vzpcRp4ccjqRGJo3JZS+b31J
         6JV3ztsz0Wq/bjsabGcz7gi3f7fGXJXmhp0eXJkBlOf8jK4YZIMkYbEas111Z0ZgqiT1
         dJiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=yoo92g1+EauXIKF2QoPao+zY3NnhLnGTIpbFnu2mjkk=;
        b=CRZm39a/gJvyI7m6rDTjiADep/zkz1e01rrvVSwfcVABxJ2cnmMHwHE2PCnzIa14DZ
         GyRBBjatgncOrZikpfzqrX/5e9aSvO0tatyRcEFOmLO+pAd6UhbleWIQhEXvMLh3jRAp
         SRVsDTwAK0x6cAHT2es2EhNs3ktfN8d2ywh5H6yRzaLyRS/rD3IT65ijlRvSg0BmTtVI
         UsdH+IBfV9EEuQvjxjP7XQaKGZ5+SUU/5YFNnv81VadAepWiho6Y4w8rJgpWCYO7wjeV
         nZfC9I0UX3iMoPXtdg13Q4UPx5walsA7tOtwRban3DEPbLHpH+CGYVKxgAeyUVWrosPH
         QgqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2n/dUS2bAA3EEMsgN3K/Mkxwga/7+nfSVa5A4EOKISFZLT/L6b
	JCLCy7h6AFLUJ/ZZBiG0Q/c=
X-Google-Smtp-Source: AMsMyM4mpugUwMrYOEb3FcZKhtqYri7/jv11iy1q177R5lPVCqfej8DFKuZH3ueR9uo745zCWQ/wqQ==
X-Received: by 2002:a05:6e02:c84:b0:2f1:3e7d:8bf2 with SMTP id b4-20020a056e020c8400b002f13e7d8bf2mr9519735ile.272.1663650541138;
        Mon, 19 Sep 2022 22:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a47:b0:2f1:3be2:5483 with SMTP id
 u7-20020a056e021a4700b002f13be25483ls1337278ilv.10.-pod-prod-gmail; Mon, 19
 Sep 2022 22:09:00 -0700 (PDT)
X-Received: by 2002:a05:6e02:184a:b0:2eb:94e4:6b17 with SMTP id b10-20020a056e02184a00b002eb94e46b17mr9255385ilv.229.1663650540650;
        Mon, 19 Sep 2022 22:09:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663650540; cv=none;
        d=google.com; s=arc-20160816;
        b=T6v93XzNgswLxCfCuW5r7NrRIuKCFiMCsdywHOUY1ZEn9mbqNHKxJ8t4JRfdvQnseW
         N9YHpsataYPrpILnfQKwGUmNGyxEHsSs4aWxpz4XfFJwmML5tB3zB0avb/gptfPWk0vI
         QLGHO/KifTDCUt18lZZos0C0+htDQwGABNOt5oESyYHlD/RhfTGBFxl0+IG078byGZ4i
         ej+dUIS7WqQWJk5PDCYUQbExkWBlbklU3tF7o+M3PwM8izhMGqZG0gyd/aCifAphp0fs
         nXmL5+AfDodsUKg1/2zOHWA/KYD452U1G4amlSEj4dKPMMsP0FNqjKVgv99vYAjQjEsw
         fOGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wsye+YjLqaipj+RxKxN5aUaqIg06ns06SYaLciljBaA=;
        b=ASJ/NB92qUK8eKrIJaK1CwZltLcfmq+ps4E6OpYEJ3aje5YowrOBDLq1qvXI7OIFKj
         x9n5MHnTUxrn8+bUJu+8RYJc0SOQUg6NyqUzbY1H4WTOBP7EBhS74lzULaphHh4B46li
         uAFFrWeU9SEKdx+jUTMQEArCvnvXZsngOKQa7uUNDYJA0V2Aud1yQtZZK/sVnqOfxKTl
         v9xbVKN6zqf5rhguul4rpvlmN1/vdx6eh3/Q1UJ6V+A+Wl/wbIYQ6TIlQoBuSr9O5LR3
         UfCvm9DtDUqXF37LZ9YFzmycIPyb2Dlr9kG2o+aRBcVD+OqyQpNtQEYT4DoQCAqGGj0P
         tt3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aF8efSaL;
       spf=pass (google.com: domain of guoren@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id q3-20020a056e0215c300b002f61616fb0bsi63764ilu.3.2022.09.19.22.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 22:09:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of guoren@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3D7C06230E
	for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 05:09:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E5FF1C43162
	for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 05:08:58 +0000 (UTC)
Received: by mail-yb1-f171.google.com with SMTP id 130so1739698ybw.8
        for <kasan-dev@googlegroups.com>; Mon, 19 Sep 2022 22:08:58 -0700 (PDT)
X-Received: by 2002:a05:6830:1213:b0:65a:9a2:daf3 with SMTP id
 r19-20020a056830121300b0065a09a2daf3mr3825507otp.308.1663650526863; Mon, 19
 Sep 2022 22:08:46 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101521.743503410@infradead.org>
In-Reply-To: <20220919101521.743503410@infradead.org>
From: Guo Ren <guoren@kernel.org>
Date: Tue, 20 Sep 2022 13:08:34 +0800
X-Gmail-Original-Message-ID: <CAJF2gTSjyDR5vK6ccFqC21T4-s5AQWOANfBoBRWHcU514As39Q@mail.gmail.com>
Message-ID: <CAJF2gTSjyDR5vK6ccFqC21T4-s5AQWOANfBoBRWHcU514As39Q@mail.gmail.com>
Subject: Re: [PATCH v2 21/44] arch/idle: Change arch_cpu_idle() IRQ behaviour
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru, mattst88@gmail.com, 
	vgupta@kernel.org, linux@armlinux.org.uk, ulli.kroll@googlemail.com, 
	linus.walleij@linaro.org, shawnguo@kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com, 
	linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org, 
	catalin.marinas@arm.com, will@kernel.org, bcain@quicinc.com, 
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org, 
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de, 
	dinguyen@kernel.org, jonas@southpole.se, stefan.kristiansson@saunalahti.fi, 
	shorne@gmail.com, James.Bottomley@hansenpartnership.com, deller@gmx.de, 
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu, 
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu, 
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com, 
	borntraeger@linux.ibm.com, svens@linux.ibm.com, ysato@users.sourceforge.jp, 
	dalias@libc.org, davem@davemloft.net, richard@nod.at, 
	anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, acme@kernel.org, 
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@kernel.org, 
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu, 
	amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com, 
	chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org, 
	pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com, 
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org, 
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org, 
	konrad.dybcio@somainline.org, anup@brainfault.org, thierry.reding@gmail.com, 
	jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, 
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com, 
	linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com, 
	rostedt@goodmis.org, pmladek@suse.com, senozhatsky@chromium.org, 
	john.ogness@linutronix.de, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de, 
	bristot@redhat.com, vschneid@redhat.com, fweisbec@gmail.com, 
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, 
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org, 
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org, 
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org, 
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev, 
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org, 
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, 
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org, 
	linux-perf-users@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org, 
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, 
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Gautham R. Shenoy" <gautham.shenoy@amd.com>, "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: guoren@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aF8efSaL;       spf=pass
 (google.com: domain of guoren@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=guoren@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 19, 2022 at 6:18 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> Current arch_cpu_idle() is called with IRQs disabled, but will return
> with IRQs enabled.
>
> However, the very first thing the generic code does after calling
> arch_cpu_idle() is raw_local_irq_disable(). This means that
> architectures that can idle with IRQs disabled end up doing a
> pointless 'enable-disable' dance.
>
> Therefore, push this IRQ disabling into the idle function, meaning
> that those architectures can avoid the pointless IRQ state flipping.
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Gautham R. Shenoy <gautham.shenoy@amd.com>
> Acked-by: Mark Rutland <mark.rutland@arm.com> [arm64]
> Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
> ---
>  arch/alpha/kernel/process.c      |    1 -
>  arch/arc/kernel/process.c        |    3 +++
>  arch/arm/kernel/process.c        |    1 -
>  arch/arm/mach-gemini/board-dt.c  |    3 ++-
>  arch/arm64/kernel/idle.c         |    1 -
>  arch/csky/kernel/process.c       |    1 -
>  arch/csky/kernel/smp.c           |    2 +-
>  arch/hexagon/kernel/process.c    |    1 -
>  arch/ia64/kernel/process.c       |    1 +
>  arch/loongarch/kernel/idle.c     |    1 +
>  arch/microblaze/kernel/process.c |    1 -
>  arch/mips/kernel/idle.c          |    8 +++-----
>  arch/nios2/kernel/process.c      |    1 -
>  arch/openrisc/kernel/process.c   |    1 +
>  arch/parisc/kernel/process.c     |    2 --
>  arch/powerpc/kernel/idle.c       |    5 ++---
>  arch/riscv/kernel/process.c      |    1 -
>  arch/s390/kernel/idle.c          |    1 -
>  arch/sh/kernel/idle.c            |    1 +
>  arch/sparc/kernel/leon_pmc.c     |    4 ++++
>  arch/sparc/kernel/process_32.c   |    1 -
>  arch/sparc/kernel/process_64.c   |    3 ++-
>  arch/um/kernel/process.c         |    1 -
>  arch/x86/coco/tdx/tdx.c          |    3 +++
>  arch/x86/kernel/process.c        |   15 ++++-----------
>  arch/xtensa/kernel/process.c     |    1 +
>  kernel/sched/idle.c              |    2 --
>  27 files changed, 29 insertions(+), 37 deletions(-)
>
> --- a/arch/alpha/kernel/process.c
> +++ b/arch/alpha/kernel/process.c
> @@ -57,7 +57,6 @@ EXPORT_SYMBOL(pm_power_off);
>  void arch_cpu_idle(void)
>  {
>         wtint(0);
> -       raw_local_irq_enable();
>  }
>
>  void arch_cpu_idle_dead(void)
> --- a/arch/arc/kernel/process.c
> +++ b/arch/arc/kernel/process.c
> @@ -114,6 +114,8 @@ void arch_cpu_idle(void)
>                 "sleep %0       \n"
>                 :
>                 :"I"(arg)); /* can't be "r" has to be embedded const */
> +
> +       raw_local_irq_disable();
>  }
>
>  #else  /* ARC700 */
> @@ -122,6 +124,7 @@ void arch_cpu_idle(void)
>  {
>         /* sleep, but enable both set E1/E2 (levels of interrupts) before committing */
>         __asm__ __volatile__("sleep 0x3 \n");
> +       raw_local_irq_disable();
>  }
>
>  #endif
> --- a/arch/arm/kernel/process.c
> +++ b/arch/arm/kernel/process.c
> @@ -78,7 +78,6 @@ void arch_cpu_idle(void)
>                 arm_pm_idle();
>         else
>                 cpu_do_idle();
> -       raw_local_irq_enable();
>  }
>
>  void arch_cpu_idle_prepare(void)
> --- a/arch/arm/mach-gemini/board-dt.c
> +++ b/arch/arm/mach-gemini/board-dt.c
> @@ -42,8 +42,9 @@ static void gemini_idle(void)
>          */
>
>         /* FIXME: Enabling interrupts here is racy! */
> -       local_irq_enable();
> +       raw_local_irq_enable();
>         cpu_do_idle();
> +       raw_local_irq_disable();
>  }
>
>  static void __init gemini_init_machine(void)
> --- a/arch/arm64/kernel/idle.c
> +++ b/arch/arm64/kernel/idle.c
> @@ -42,5 +42,4 @@ void noinstr arch_cpu_idle(void)
>          * tricks
>          */
>         cpu_do_idle();
> -       raw_local_irq_enable();
>  }
> --- a/arch/csky/kernel/process.c
> +++ b/arch/csky/kernel/process.c
> @@ -100,6 +100,5 @@ void arch_cpu_idle(void)
>  #ifdef CONFIG_CPU_PM_STOP
>         asm volatile("stop\n");
>  #endif
> -       raw_local_irq_enable();
Acked-by: Guo Ren <guoren@kernel.org>

>  }
>  #endif
> --- a/arch/csky/kernel/smp.c
> +++ b/arch/csky/kernel/smp.c
> @@ -309,7 +309,7 @@ void arch_cpu_idle_dead(void)
>         while (!secondary_stack)
>                 arch_cpu_idle();
>
> -       local_irq_disable();
> +       raw_local_irq_disable();
Acked-by ..., because:

                local_irq_disable();

                if (cpu_is_offline(cpu)) {
                        tick_nohz_idle_stop_tick();
                        cpuhp_report_idle_dead();
                        arch_cpu_idle_dead();
                }

>
>         asm volatile(
>                 "mov    sp, %0\n"
> --- a/arch/hexagon/kernel/process.c
> +++ b/arch/hexagon/kernel/process.c
> @@ -44,7 +44,6 @@ void arch_cpu_idle(void)
>  {
>         __vmwait();
>         /*  interrupts wake us up, but irqs are still disabled */
> -       raw_local_irq_enable();
>  }
>
>  /*
> --- a/arch/ia64/kernel/process.c
> +++ b/arch/ia64/kernel/process.c
> @@ -242,6 +242,7 @@ void arch_cpu_idle(void)
>                 (*mark_idle)(1);
>
>         raw_safe_halt();
> +       raw_local_irq_disable();
>
>         if (mark_idle)
>                 (*mark_idle)(0);
> --- a/arch/loongarch/kernel/idle.c
> +++ b/arch/loongarch/kernel/idle.c
> @@ -13,4 +13,5 @@ void __cpuidle arch_cpu_idle(void)
>  {
>         raw_local_irq_enable();
>         __arch_cpu_idle(); /* idle instruction needs irq enabled */
> +       raw_local_irq_disable();
>  }
> --- a/arch/microblaze/kernel/process.c
> +++ b/arch/microblaze/kernel/process.c
> @@ -140,5 +140,4 @@ int dump_fpu(struct pt_regs *regs, elf_f
>
>  void arch_cpu_idle(void)
>  {
> -       raw_local_irq_enable();
>  }
> --- a/arch/mips/kernel/idle.c
> +++ b/arch/mips/kernel/idle.c
> @@ -33,13 +33,13 @@ static void __cpuidle r3081_wait(void)
>  {
>         unsigned long cfg = read_c0_conf();
>         write_c0_conf(cfg | R30XX_CONF_HALT);
> -       raw_local_irq_enable();
>  }
>
>  void __cpuidle r4k_wait(void)
>  {
>         raw_local_irq_enable();
>         __r4k_wait();
> +       raw_local_irq_disable();
>  }
>
>  /*
> @@ -57,7 +57,6 @@ void __cpuidle r4k_wait_irqoff(void)
>                 "       .set    arch=r4000      \n"
>                 "       wait                    \n"
>                 "       .set    pop             \n");
> -       raw_local_irq_enable();
>  }
>
>  /*
> @@ -77,7 +76,6 @@ static void __cpuidle rm7k_wait_irqoff(v
>                 "       wait                                            \n"
>                 "       mtc0    $1, $12         # stalls until W stage  \n"
>                 "       .set    pop                                     \n");
> -       raw_local_irq_enable();
>  }
>
>  /*
> @@ -103,6 +101,8 @@ static void __cpuidle au1k_wait(void)
>         "       nop                             \n"
>         "       .set    pop                     \n"
>         : : "r" (au1k_wait), "r" (c0status));
> +
> +       raw_local_irq_disable();
>  }
>
>  static int __initdata nowait;
> @@ -245,8 +245,6 @@ void arch_cpu_idle(void)
>  {
>         if (cpu_wait)
>                 cpu_wait();
> -       else
> -               raw_local_irq_enable();
>  }
>
>  #ifdef CONFIG_CPU_IDLE
> --- a/arch/nios2/kernel/process.c
> +++ b/arch/nios2/kernel/process.c
> @@ -33,7 +33,6 @@ EXPORT_SYMBOL(pm_power_off);
>
>  void arch_cpu_idle(void)
>  {
> -       raw_local_irq_enable();
>  }
>
>  /*
> --- a/arch/openrisc/kernel/process.c
> +++ b/arch/openrisc/kernel/process.c
> @@ -102,6 +102,7 @@ void arch_cpu_idle(void)
>         raw_local_irq_enable();
>         if (mfspr(SPR_UPR) & SPR_UPR_PMP)
>                 mtspr(SPR_PMR, mfspr(SPR_PMR) | SPR_PMR_DME);
> +       raw_local_irq_disable();
>  }
>
>  void (*pm_power_off)(void) = NULL;
> --- a/arch/parisc/kernel/process.c
> +++ b/arch/parisc/kernel/process.c
> @@ -187,8 +187,6 @@ void arch_cpu_idle_dead(void)
>
>  void __cpuidle arch_cpu_idle(void)
>  {
> -       raw_local_irq_enable();
> -
>         /* nop on real hardware, qemu will idle sleep. */
>         asm volatile("or %%r10,%%r10,%%r10\n":::);
>  }
> --- a/arch/powerpc/kernel/idle.c
> +++ b/arch/powerpc/kernel/idle.c
> @@ -51,10 +51,9 @@ void arch_cpu_idle(void)
>                  * Some power_save functions return with
>                  * interrupts enabled, some don't.
>                  */
> -               if (irqs_disabled())
> -                       raw_local_irq_enable();
> +               if (!irqs_disabled())
> +                       raw_local_irq_disable();
>         } else {
> -               raw_local_irq_enable();
>                 /*
>                  * Go into low thread priority and possibly
>                  * low power mode.
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -39,7 +39,6 @@ extern asmlinkage void ret_from_kernel_t
>  void arch_cpu_idle(void)
>  {
>         cpu_do_idle();
> -       raw_local_irq_enable();
>  }
>
>  void __show_regs(struct pt_regs *regs)
> --- a/arch/s390/kernel/idle.c
> +++ b/arch/s390/kernel/idle.c
> @@ -66,7 +66,6 @@ void arch_cpu_idle(void)
>         idle->idle_count++;
>         account_idle_time(cputime_to_nsecs(idle_time));
>         raw_write_seqcount_end(&idle->seqcount);
> -       raw_local_irq_enable();
>  }
>
>  static ssize_t show_idle_count(struct device *dev,
> --- a/arch/sh/kernel/idle.c
> +++ b/arch/sh/kernel/idle.c
> @@ -25,6 +25,7 @@ void default_idle(void)
>         raw_local_irq_enable();
>         /* Isn't this racy ? */
>         cpu_sleep();
> +       raw_local_irq_disable();
>         clear_bl_bit();
>  }
>
> --- a/arch/sparc/kernel/leon_pmc.c
> +++ b/arch/sparc/kernel/leon_pmc.c
> @@ -57,6 +57,8 @@ static void pmc_leon_idle_fixup(void)
>                 "lda    [%0] %1, %%g0\n"
>                 :
>                 : "r"(address), "i"(ASI_LEON_BYPASS));
> +
> +       raw_local_irq_disable();
>  }
>
>  /*
> @@ -70,6 +72,8 @@ static void pmc_leon_idle(void)
>
>         /* For systems without power-down, this will be no-op */
>         __asm__ __volatile__ ("wr       %g0, %asr19\n\t");
> +
> +       raw_local_irq_disable();
>  }
>
>  /* Install LEON Power Down function */
> --- a/arch/sparc/kernel/process_32.c
> +++ b/arch/sparc/kernel/process_32.c
> @@ -71,7 +71,6 @@ void arch_cpu_idle(void)
>  {
>         if (sparc_idle)
>                 (*sparc_idle)();
> -       raw_local_irq_enable();
>  }
>
>  /* XXX cli/sti -> local_irq_xxx here, check this works once SMP is fixed. */
> --- a/arch/sparc/kernel/process_64.c
> +++ b/arch/sparc/kernel/process_64.c
> @@ -59,7 +59,6 @@ void arch_cpu_idle(void)
>  {
>         if (tlb_type != hypervisor) {
>                 touch_nmi_watchdog();
> -               raw_local_irq_enable();
>         } else {
>                 unsigned long pstate;
>
> @@ -90,6 +89,8 @@ void arch_cpu_idle(void)
>                         "wrpr %0, %%g0, %%pstate"
>                         : "=&r" (pstate)
>                         : "i" (PSTATE_IE));
> +
> +               raw_local_irq_disable();
>         }
>  }
>
> --- a/arch/um/kernel/process.c
> +++ b/arch/um/kernel/process.c
> @@ -217,7 +217,6 @@ void arch_cpu_idle(void)
>  {
>         cpu_tasks[current_thread_info()->cpu].pid = os_getpid();
>         um_idle_sleep();
> -       raw_local_irq_enable();
>  }
>
>  int __cant_sleep(void) {
> --- a/arch/x86/coco/tdx/tdx.c
> +++ b/arch/x86/coco/tdx/tdx.c
> @@ -223,6 +223,9 @@ void __cpuidle tdx_safe_halt(void)
>          */
>         if (__halt(irq_disabled, do_sti))
>                 WARN_ONCE(1, "HLT instruction emulation failed\n");
> +
> +       /* XXX I can't make sense of what @do_sti actually does */
> +       raw_local_irq_disable();
>  }
>
>  static int read_msr(struct pt_regs *regs, struct ve_info *ve)
> --- a/arch/x86/kernel/process.c
> +++ b/arch/x86/kernel/process.c
> @@ -701,6 +701,7 @@ EXPORT_SYMBOL(boot_option_idle_override)
>  void __cpuidle default_idle(void)
>  {
>         raw_safe_halt();
> +       raw_local_irq_disable();
>  }
>  #if defined(CONFIG_APM_MODULE) || defined(CONFIG_HALTPOLL_CPUIDLE_MODULE)
>  EXPORT_SYMBOL(default_idle);
> @@ -806,13 +807,7 @@ static void amd_e400_idle(void)
>
>         default_idle();
>
> -       /*
> -        * The switch back from broadcast mode needs to be called with
> -        * interrupts disabled.
> -        */
> -       raw_local_irq_disable();
>         tick_broadcast_exit();
> -       raw_local_irq_enable();
>  }
>
>  /*
> @@ -870,12 +865,10 @@ static __cpuidle void mwait_idle(void)
>                 }
>
>                 __monitor((void *)&current_thread_info()->flags, 0, 0);
> -               if (!need_resched())
> +               if (!need_resched()) {
>                         __sti_mwait(0, 0);
> -               else
> -                       raw_local_irq_enable();
> -       } else {
> -               raw_local_irq_enable();
> +                       raw_local_irq_disable();
> +               }
>         }
>         __current_clr_polling();
>  }
> --- a/arch/xtensa/kernel/process.c
> +++ b/arch/xtensa/kernel/process.c
> @@ -183,6 +183,7 @@ void coprocessor_flush_release_all(struc
>  void arch_cpu_idle(void)
>  {
>         platform_idle();
> +       raw_local_irq_disable();
>  }
>
>  /*
> --- a/kernel/sched/idle.c
> +++ b/kernel/sched/idle.c
> @@ -79,7 +79,6 @@ void __weak arch_cpu_idle_dead(void) { }
>  void __weak arch_cpu_idle(void)
>  {
>         cpu_idle_force_poll = 1;
> -       raw_local_irq_enable();
>  }
>
>  /**
> @@ -96,7 +95,6 @@ void __cpuidle default_idle_call(void)
>
>                 ct_cpuidle_enter();
>                 arch_cpu_idle();
> -               raw_local_irq_disable();
>                 ct_cpuidle_exit();
>
>                 start_critical_timings();
>
>


-- 
Best Regards
 Guo Ren

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJF2gTSjyDR5vK6ccFqC21T4-s5AQWOANfBoBRWHcU514As39Q%40mail.gmail.com.
