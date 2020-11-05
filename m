Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJ7LSD6QKGQELMQBDWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 597582A84D2
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:26:00 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id l67sf1229503qte.6
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:26:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597159; cv=pass;
        d=google.com; s=arc-20160816;
        b=UkTBMDIjycixvXGhTIaqendRHWrJthAINqmt8ZLp9lsiafe90jqgwbi8RLXity9suA
         REj+/l0eRzPFCHrBJ4KUbxYWEw4QXFiyOXuCoJnN8BcinNTjBk0spEwnbJXrqfDmDE7N
         Iqfb53XN7QbYASQ4NjnNQAoCLk07gWbmkzgpu7ZPiffyNEOZzPPyooXyiX50AyqMq6bR
         OzjJXbJauA9wEpm09Q660whoX/Ls1Rz47nolpnuLpMQwXZ5WJZUx2QZ6c5zjneeZ6BPv
         SafqGF+yR7XvPkXOIYfgZPLy9JNWCEH7tqeBmzsaCoCmQo2GtJPuKD+7B2+ZoK6Ghhec
         HF/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=MxCIspOpAPgqK//lEKwSGVvdsftDCDrdox3O9V/BFGE=;
        b=umAy9Fxe/BwsHGRB+EnWRAzt9gxeT1lpx4i4ojRcJ0i+0qjMKcjuic46an/qC0Exy4
         M3g9WamkmIT3sqiUrIjWB76wd9AlrIw+Cdm0vH3YW/afmzUyaN3rlElswNwX6+MFMH6T
         7qkBqgHUwaW6+AgASGn0ANyP3dM6OT0FJZ2AmMqwTkuM9Q/YXjK6+taUe9r3WWTcyRlV
         blTTQCIt/inFrpd8b7vWMwVDDdoUJaXh5pVlH1at8QoVoY+pUgGHBTB9KiUuzSTJVG+Y
         c8KCL/wayCETtNee8+O1qEIm79/LBr0GaoJ/MA8A9fBuPOJtU+o2+8LTRjut7jAMCWHP
         4Z3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MxCIspOpAPgqK//lEKwSGVvdsftDCDrdox3O9V/BFGE=;
        b=Tr/XFT74p4Lr0er8zmy55TH5UbT/L0rocdbBWFFByJ4zOMNWoPibF2SdULwRItZLzW
         TDSGYyfrH2alBagNxwq07z6Ufwo0w5X4iR3ggZduIyuRWxUAdk2y+TCW8cApr7rr2MrD
         B5KxFa8s2//YeKwDA2q8s6IvA7WKjiRGIAdHttEmvgvEu3R14DibGpNadbg5GTQFnAL5
         5WwJd+miI/56GO8dP04vDKxE6AQsLdt8g8WB5R0ALJ1BBgwKhRKeAbeCnLRFgGnm4LPv
         b0e+aTcohEr1xW0AsoGpqnUEIGp0b5foHmiFmQRoorAvpuT1o07Kebui1eOWJB92cwuK
         4k8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MxCIspOpAPgqK//lEKwSGVvdsftDCDrdox3O9V/BFGE=;
        b=MJrWaXXg0hqB3XjXqlkY+HkkVjtz5Dah7dIbJ2xFV0c6RMLo3VPmL/fYsk+7M+0RsQ
         rUsdfn0xeW0xAAQxccZYwgTheysRgBL3W6EeRSaV2Bauv5cBH/V8AWoInzEmetB2uEgb
         XMxbui0yUYZYFioK962xA0kTuXNNwkyFg5wgUNNkv0nSazHwoTTul9SPtI6y+VSWz65i
         UlOVr+FxFpHx21sBYpoQfjEhB2Xc+3pSr+UkPSZTtQ26owLeZWZiWTiO2aRGVFm1IiVo
         zgNXuormpi2JeW/T+AD5m7VyEhJh7ECi+0meThoPqQ9RYHcWzxeTJXnofpULA5qbfPYI
         EYAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y/lFYMfgWhNle9eAUDJPmyQ6WVYWf7D/Mw+MQwC12hAramyk1
	fNVVZZJHI1Ttbf27PR8Tl6A=
X-Google-Smtp-Source: ABdhPJxayWmi9RiHYO1NWuota2Kqr0zofx5s+5PSS+UJ1Z1TPWH5l1jLPYdfLpzeAZzLaGg7+w3XEA==
X-Received: by 2002:a05:6214:144b:: with SMTP id b11mr3228300qvy.3.1604597159154;
        Thu, 05 Nov 2020 09:25:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:94:: with SMTP id o20ls873095qtw.7.gmail; Thu, 05
 Nov 2020 09:25:58 -0800 (PST)
X-Received: by 2002:ac8:6b51:: with SMTP id x17mr2778518qts.203.1604597158668;
        Thu, 05 Nov 2020 09:25:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597158; cv=none;
        d=google.com; s=arc-20160816;
        b=wfLir8IsjVnHaLHDigA8IJ8Lok8Irys20lgDSzkGth4WA3fBUUGIHDivx04nBp4et2
         7iqTj05wleLxCaPDEuD7cdKEMNVVCpXawuOHT1mddA0jgTLF4zfimuY9nn9HmfCCJ4b+
         q39n6G6yG4FxQGAgQO3LqfI+r1KAhhJFbZVP7faGso7wR/WujM8ZwDirR1g07hmTBf/l
         hJsHH8o9gBCMrM0rbaK/27Xr74dIE/c3sG+j0EM/0q5NZySJYqEtftB/8EmzQLQJm8OZ
         ujxXHSM+xaTiIx6VZR8doDi0bEqvQiiEDm94m5DRck8BtOIt6bkg9LtPsP/k1G1iNvbz
         Zm2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4oH40jeHVdFKASRpD2mzvKogj5of8UpH9hoDAwsgxCQ=;
        b=FiDVzDdQJeT9P2hmfcakqlTq26ZnNS4WNsrmqhc1eKpQYcUlYcVpDzoLBHQATN6Sti
         /b8U4oQS4wJedvAHB02WRnMQAQ6HxQ9Dir5m8El6o8bmw794VJnhT+WbWVwUcXTQhcfJ
         /Ri+b5Nd3C+OyhHSRUslcEaDEEEX5VAzcnVQk6lB2PQDLOVxWsy7Aa2SU6dEhfyR5nX4
         N0P4AkOUcEQuVvGlJ+sgi9cHKpbyJNwbv+ejJ22OqRixlpWyjpMAvSbLUGbtpvMq5Sla
         z7naB4ujdV04CITvfskl/eMPk6LkJ8JT34av6Q9oQst5Cq/5fB8JhZ1fId8t1QEotTWe
         FG8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p51si153508qtc.4.2020.11.05.09.25.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:25:58 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BC05D206B6;
	Thu,  5 Nov 2020 17:25:53 +0000 (UTC)
Date: Thu, 5 Nov 2020 17:25:50 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
Message-ID: <20201105172549.GE30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 05, 2020 at 12:18:45AM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 06ba6c923ab7..fcfbefcc3174 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void __init mte_init_tags(u64 max_tag)
> +{
> +	/* Enable MTE Sync Mode for EL1. */
> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +	isb();
> +}

Is this going to be called on each CPU? I quickly went through the rest
of the patches and couldn't see how.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105172549.GE30030%40gaia.
