Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQGZRX5QKGQEZVFC5LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id DAEAE26DD6B
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 16:03:45 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id q16sf1448309pfj.7
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 07:03:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600351424; cv=pass;
        d=google.com; s=arc-20160816;
        b=mBFoGklbeaiC7t6Zvia0PeKuN6dFrrWzWmB9ltw9zoFwax52zv7zgLDzpD8l0+agH+
         m/XD01Y4xEIbE4w+y90Zu66jAvBcGAVcz01VzBy/3ppwiSMTrz4bqxCXBVFsCj8aAhSt
         9CdKOzvxZVV0Ng53ikBZd8VXihnXZxtYpknl+IqsrnZqi4yuq2bmAiIQge8p/vCFab3y
         iJX4FgFu6meBZgwLf3YwRu57P6fSOYzwdHG1nw11/JbDGkUR+tsdYejWC4dPgIWP1A9A
         Xr490p9n9o2LuNLUQN+vZU0GlSWMLxojXyOlq6WUF8In1e9sGnx7cBigNbqJZVUvZ6Mp
         4Kdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6joZ/he+59kkn8HvKCyfQi9QczP2sZs5ril61Tq/4VA=;
        b=TpBw+8VsC/74vH+dqoN4Ct7u4g9EJFjsF8nP4vkxwCLfWIs3k7QB9q7tU6a2WLAj6t
         TPLyw1q+qyC/fqj2nEIRQ8LJD8SSrNRsn71ABlyTWDhBajXh3p6dXFa9yPf2HR8oz6Cb
         kFjXulmwN35smLSRrHZR6TmXXB3frJi1LG3QMYmpR09GyODWRdYxxNUayfVviGXcUuLE
         G0k1iB54KsM4hwaHe0X5F9eHCwxRUE33h4Sd4ILPMBC0AQMqQYcrt73Lga4RSc5owaA2
         BBE7eeeu6grhzO9gchj+y3LDFhv6kYFwALtlin1twiU1GAS383AGxAtZ8WL5PFuctlIR
         oBmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6joZ/he+59kkn8HvKCyfQi9QczP2sZs5ril61Tq/4VA=;
        b=bs/OAZ3AgwLnMe0LB9TH/qmtjIYGRjA4E/dq9Yx7KxOKhkvCIsD77X40MrCpw888wH
         jRpnmG1W2iv8fE3wj9tLZV05e7PIgZn6C98Y/43o4SuFUz0E3FM4daN4z9nmQtJOtchv
         ZLuCAxhLe3RtiUBCp1Nrto/m1RxNQMppDV2yUwlSvJVF8SCwX3RSYnj7NlGq6+xs3IfZ
         S872HkjMmzi4z9GQrS5DFg20LBziBRz5b4sE2c1IpaUgZnuPanniZvCsDqxNwSmeC871
         10QscY7kQyjkEjzXXtbI4SVf9dH8cujO5JmDV127QjJDL8vrjFRN8xOWha0hTXVOOUdG
         7goA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6joZ/he+59kkn8HvKCyfQi9QczP2sZs5ril61Tq/4VA=;
        b=c3z+F+z3Ji6kV2v336eODG6GBFwhE0u3heK3K/JHFDdCYcyVYwTlWAcroWMvbjLNba
         P6iy0DcqOLC2wNp+ezsDdHxvBCQe+88kIi5kNeoYC235auXzcIsH7gNpcrSCX4q3Qqz+
         I07UcjdW3ue3jiWksu8xmfqhzgsRxAQ2ifPS0W0aIbdQEug7h+q53fr4ireZEbv7p9Xt
         2bBqHhzRKpbpV9E6WF1FwWLFyeQZd+KKNdpa00hqFM/kI7u0j4cacuwh7SNeVRTET251
         Th3n/BXSugS7HbBXEE1WDqWIi/5ilGEvp47HXaUuihevVzTlM9neUqdLJyN8dO8jZgVk
         s5pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308tCD6JzyU7yDLsB5EU9yfDKdxdK8j1JjqhUmuLzgY99nQLSqk
	TpCmfvOrzbByHVoaEgwHXHE=
X-Google-Smtp-Source: ABdhPJx0FVAoQu4BUI+LtqsGbauc56VxIMzEgArnN4PMK0HQDnZlRvYr65nDSsEd7b6AC23ZtwbyBg==
X-Received: by 2002:a17:902:28:b029:d1:e5e7:ca3e with SMTP id 37-20020a1709020028b02900d1e5e7ca3emr10632094pla.50.1600351424333;
        Thu, 17 Sep 2020 07:03:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9706:: with SMTP id a6ls870982pfg.9.gmail; Thu, 17 Sep
 2020 07:03:43 -0700 (PDT)
X-Received: by 2002:a63:1455:: with SMTP id 21mr23834139pgu.52.1600351423563;
        Thu, 17 Sep 2020 07:03:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600351423; cv=none;
        d=google.com; s=arc-20160816;
        b=eyfUSaGRfKULnzg+9Mds73VCbVcry6buwA7nzkP+rwqRsECfcCp0K7y7RIeAv6zyJy
         Fh/gxqMBalVe0srTeZBenKiduV3vOxzmVd0deZeP+uHey8/VG6JTIfDBFk6Qp8QD7HsV
         uNDwRza5q2/daNmIs5muguK8wG7l1JJjvC/L33RaXTxiPMqbRIsziBKJ43Ul+HxbDVG9
         Xj1gtXY20OFBjwXEyqIUJLV88xFYhU8hMm4cnplxheiYNn7mJ1/9xf9NBhvMIr3xZBbb
         yzP2tVrpqkQJrlthLIPc+NL7HvicRcPG7u5ZLwxxHYkafF6vM24XJJyItgiL1SC8lznr
         PcOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4t9xQHuLekDI0QrXg20EzaF7kVWVD1bOD1uD/y/RTJw=;
        b=DErrvtAjT3kI6+vvYhRr88DvKda3X/RGcuRyxOSzz6TbnppuJyr7Jb4qeexw211ImN
         LpT3e3ds84LvLqt+W0cWE2RVEbkl74KIvUArOirZCuroqslVSysYit+4LbJsFkDHU77S
         fcIoshep9Ytte3hoP0tx6uN7F8FgVxLyzMFRs0wlJuhY4NL2+W/2+7zraj3kC1B/O56v
         VzW0RKOgTyjw1ivubmTmHHykjBLW/pyIBN+nu998ggKtm3EXkH9EgjzI6uZQtEfB57/J
         6tY4MmoUBQT/G0YiqveELb7Ci7IT5OuuHWAhS9va4doA/b5RauKn5//H19NtjZ8W3FSz
         wvow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d60si498564pjk.0.2020.09.17.07.03.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 07:03:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 785E62065C;
	Thu, 17 Sep 2020 14:03:40 +0000 (UTC)
Date: Thu, 17 Sep 2020 15:03:37 +0100
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
Subject: Re: [PATCH v2 24/37] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200917140337.GC10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl@google.com>
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

On Tue, Sep 15, 2020 at 11:16:06PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index a3bd189602df..cdc23662691c 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -294,6 +295,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
> @@ -641,10 +654,31 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
>  	return 0;
>  }
>  
> +static void do_tag_recovery(unsigned long addr, unsigned int esr,
> +			   struct pt_regs *regs)
> +{
> +	report_tag_fault(addr, esr, regs);

I'd only report this once since we expect it to be disabled lazily on
the other CPUs (i.e. just use a "static bool reported" to keep track).

> +
> +	/*
> +	 * Disable Memory Tagging Extension Tag Checking on the local CPU

Too verbose, just say MTE tag checking, people reading this code should
have learnt already what MTE stands for ;).

> +	 * for the current EL.
> +	 * It will be done lazily on the other CPUs when they will hit a
> +	 * tag fault.
> +	 */
> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_NONE);
> +	isb();
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

This part looks fine now.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917140337.GC10662%40gaia.
