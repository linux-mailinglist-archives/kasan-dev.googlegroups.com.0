Return-Path: <kasan-dev+bncBDDL3KWR4EBRBW4FT35AKGQE5LLULGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D1D482542CA
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 11:54:36 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id l6sf2458772oia.15
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 02:54:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598522075; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYKkAE+7TMMF4aSkiDnqwlZb1TsbTU54gFQE/PMiKDag2Vj1j8H+kwa9CxLatViNHd
         Ur0gRLvK8kXNiOXauFPC6TPkvqC7za5OAmyiDK6Nm60e1MjCLNXu96tqurbSCYfh9Kvv
         WQjqyIC+t+SeRZm5u+RnuO9I2cK1YSE643WN0066Tf/8qBdeD6BiuhAYFG8MHCNeUonn
         496ddxTeqEDd1h952sUuSpK9o61yClcOaPS2B3/gv7fwI8ah2JM8R+kYt/HGOlwN4zwI
         4/K+hWQNJ8hkt2Ucb4+HtxLeQhJ+aVRbI6ND9Oh+hMVO1/Bm5Yn+haXrf6XFgbR5Oz7W
         l/Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=B3xRJKS5ItkeIgoUXo8KEbV1uKp1JWJ/gO7gFC8awLU=;
        b=IQRg2PuGsi15JzntOD9eVbI4s2S31SQ/nGAtAAw8XqmuT4Yo1V9gUJhgeL4V+gwi5r
         TFdDNExJCMwpiQf1ibnUJr61qTvjfkM1xI8Po63kw5FYDlCivqbdNLc43lpXRn1sQHTU
         m2LECHJXO0BO9zvbB9l5raTNw3qKZBqJprMsZeFNSVsGydDcP4CMpZbMX8KNzkZTBWVL
         lZJxLhlega4yTWvAr6nIcZyle5uIU7cAbDKnOobD8C/PQQ5M5mnz8CqCZihJPWgM0/vJ
         3IVfEAE6JKHXRihbphyoJHM9/2j8kvYUcfmMks0ZspiAUtrbZ1DxSHmEzPNh77lg7VGF
         d3eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B3xRJKS5ItkeIgoUXo8KEbV1uKp1JWJ/gO7gFC8awLU=;
        b=ZUuTLHEBcARALUITqb1nOs6OzGl6IpdHnKt2LMXsWkIw/IdWhdU6zLcv1Jri9G7SF1
         yI10HXzcFbLbZT8rFCV4PwtSa/ZjH3HBBasu7BCP5vXA08ZJJOoxOcFkc3cTBRLZADyQ
         WNbHj4kDTk946dXCslErB1Ag/PshUJg3aYukKZtWveYjVHP27i7Eaw5LSCZkSg4EW27S
         oEzGuLvzlaAuMHspOKOnaF+SItYN3AQdiabWAGRSyxao8FNdaYaje4jsQJr2pYD8X47m
         GKwu/BVGOys0gPFRpZ5K0l9P/mFF7QR+i9t+fSh0z09mBCGagVhiORCPFPXtAmwQ2xDe
         UN7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=B3xRJKS5ItkeIgoUXo8KEbV1uKp1JWJ/gO7gFC8awLU=;
        b=I70+3Jz/RWJcsY0zOwlRxxqBxx5JgaGeCmwUzX67OII/LSk263Lk3yk/2/QZHKk362
         oxyZ+eYSwebUUjTC5kmIQkCughYsKljeI8f/Azu73UmOA2SVlJR4CE3ia7dCRKFVja2C
         cGykpIHhzs52kchNxDtNUI06QvIhS1DkD9WqTYBgo5PQhvtrd989wQXz/fnhihqvuSa0
         aGEsHZbWbrhJJt/f9rAQtovQsi0HZZrSIuyhxcM7Q1EH4VNkNy+pZA6DyJzdrnOP31Pp
         Icsd5k9w6Z6AzV7MjB4/3fFXMyRBvg8wb4H6u9yc41aDRfQlZbhABTAyJQS1kaeX+pya
         vAOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XZto3F0Hp5LI5XV0R6/VXSyTBrz4lDzCTDlS09JkNg7UKO4e0
	Cqbf6VQhGjcH6WHSVcsnyIw=
X-Google-Smtp-Source: ABdhPJzxlPRuQ9Pdx4V5rymVMqEqaoMnv+3EpUM2n+tKCfWE4LvpIHyLFR7YZK6dJOyr8FVgMzZrew==
X-Received: by 2002:a9d:a2b:: with SMTP id 40mr13291133otg.308.1598522075473;
        Thu, 27 Aug 2020 02:54:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f31:: with SMTP id e17ls482388oth.2.gmail; Thu, 27
 Aug 2020 02:54:35 -0700 (PDT)
X-Received: by 2002:a05:6830:1012:: with SMTP id a18mr8682728otp.280.1598522075198;
        Thu, 27 Aug 2020 02:54:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598522075; cv=none;
        d=google.com; s=arc-20160816;
        b=qu1B6ywWImpH+ISONVYK4rNCtz0zTQnF2rCrMcVzKY4s0UcyYMhAOdZVFMgTdLV04K
         OzczVgRo+KYhIZO2iiJKijrrYM0jszk0k0/yWcpZe5Y6yRDt52BVze6K5grE/8GXNjcX
         opSOsJVc0L55Y4+/rRvxy2pyLXXB4/Wzx65DIEwyMqJZ0QzpSKcAG+hM86LHvxPP40/s
         w9HaYa0QX7w0ROdjLDap87apukNCxWYF23N7+Wp6obeJ9nUIEbtnduuW18ConavM0Riz
         bJlYYc92/9Mmhm2p4xa0kdtOTlpj+XC/itZgfHC1VHB9R6QlNkeLUAZ6jWRZeT32dSn8
         LKxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=uFRzcGiihkwUfBGa9/IBa5BcYdbYHLW6QRQUaRAviRI=;
        b=VDOORvCh5eXtbn48xpySAalZ+HaV0G6+XipX1z0R7onWQkDR+jk9yLROhIsnZGeQCz
         VqEoSk4XN5nbXJ91rt2tuxlHwAFUi+lReT0DVYf4uMr4bZ0DciSb3Ld4e7g53zKKS59b
         ura63EsS66ddJ9RGfXD1EVMbOM7GeaWTwn1Xw1NkzqKnf+SwnqUB3M6jlToJjbmCUmit
         bxD1a1jAZonlsZTh0q2J2JirxG8t/MmZd5bKrg6TaQEoD1C6kIjyIJnPAOBtDCjUmLET
         0f/D00yoctcthGIhnp6W1iJyGlsQH9MBZAH+2cUSgqqxfOsa/RWKDiuU+7rnxGP4rkSb
         qM3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j139si108578oib.1.2020.08.27.02.54.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 02:54:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BD3A0207CD;
	Thu, 27 Aug 2020 09:54:31 +0000 (UTC)
Date: Thu, 27 Aug 2020 10:54:29 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200827095429.GC29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 5e832b3387f1..c62c8ba85c0e 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -33,6 +33,7 @@
>  #include <asm/debug-monitors.h>
>  #include <asm/esr.h>
>  #include <asm/kprobes.h>
> +#include <asm/mte.h>
>  #include <asm/processor.h>
>  #include <asm/sysreg.h>
>  #include <asm/system_misc.h>
> @@ -222,6 +223,20 @@ int ptep_set_access_flags(struct vm_area_struct *vma,
>  	return 1;
>  }
>  
> +static bool is_el1_mte_sync_tag_check_fault(unsigned int esr)
> +{
> +	unsigned int ec = ESR_ELx_EC(esr);
> +	unsigned int fsc = esr & ESR_ELx_FSC;
> +
> +	if (ec != ESR_ELx_EC_DABT_CUR)
> +		return false;
> +
> +	if (fsc == ESR_ELx_FSC_MTE)
> +		return true;
> +
> +	return false;
> +}
> +
>  static bool is_el1_instruction_abort(unsigned int esr)
>  {
>  	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_CUR;
> @@ -294,6 +309,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
>  	do_exit(SIGKILL);
>  }
>  
> +static void report_tag_fault(unsigned long addr, unsigned int esr,
> +			     struct pt_regs *regs)
> +{
> +	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> +
> +	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
> +	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
> +	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
> +			mte_get_ptr_tag(addr),
> +			mte_get_mem_tag((void *)addr));
> +}
> +
>  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
>  			      struct pt_regs *regs)
>  {
> @@ -317,12 +344,16 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
>  			msg = "execute from non-executable memory";
>  		else
>  			msg = "read from unreadable memory";
> +	} else if (is_el1_mte_sync_tag_check_fault(esr)) {
> +		report_tag_fault(addr, esr, regs);
> +		msg = "memory tagging extension fault";

IIUC, that's dead code. See my comment below on do_tag_check_fault().

>  	} else if (addr < PAGE_SIZE) {
>  		msg = "NULL pointer dereference";
>  	} else {
>  		msg = "paging request";
>  	}
>  
> +

Unnecessary empty line.

>  	die_kernel_fault(msg, addr, esr, regs);
>  }
>  
> @@ -658,10 +689,27 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
>  	return 0;
>  }
>  
> +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> +			   struct pt_regs *regs)
> +{
> +	report_tag_fault(addr, esr, regs);
> +
> +	/* Skip over the faulting instruction and continue: */
> +	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);

Ooooh, do we expect the kernel to still behave correctly after this? I
thought the recovery means disabling tag checking altogether and
restarting the instruction rather than skipping over it. We only skip if
we emulated it.

> +
> +	return 0;
> +}
> +
> +
>  static int do_tag_check_fault(unsigned long addr, unsigned int esr,
>  			      struct pt_regs *regs)
>  {
> -	do_bad_area(addr, esr, regs);
> +	/* The tag check fault (TCF) is per TTBR */
> +	if (is_ttbr0_addr(addr))
> +		do_bad_area(addr, esr, regs);
> +	else
> +		do_tag_recovery(addr, esr, regs);

So we never invoke __do_kernel_fault() for a synchronous tag check in
the kernel. What's with all the is_el1_mte_sync_tag_check_fault() check
above?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827095429.GC29264%40gaia.
