Return-Path: <kasan-dev+bncBDDL3KWR4EBRBD6SYGBQMGQEAWHLIMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id B555535A16A
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 16:47:44 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id j2sf3209215qtv.10
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Apr 2021 07:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617979663; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUkUm0c57hQ8YvZvHyacv9KsCksgNK7398rEKWa+fIJroh0PUk1pcwDlzHUrpICEK/
         bIFMGPS2HEstTP4puiJchHgNxdOG6ZHfeV77Y0PmHYWd/dfFDwWI32oj5+Vt68db9bZ3
         as9sO/bDPXndnrfCEloYUBHAoadhkh2qrLhvkoykQmNLj6gVBMEjtEIispSi0yscnUt2
         fwUi4OXIIghkDlqJ2XdWytLdprPhcolvzC/Kji71sXoBql81bYre56515C4wLM4I76Wz
         eWfoxCzWkjgo4W8DM+flbRbwQ6HXJxKB+LPc34blohLaMroWTQfDOvCqmnTr1v+pu7eD
         Uy7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=z1+AgbOb8CiyN9XIfRQ+d4PMiK2gGo4PmV8DL8KSdXs=;
        b=AOLPW2xJOutwBGa3x0Di/SjDionWkPBTdNMZa0QcPzDauyNa5AHvKJNcKxYdxJy0jc
         QhD6OecZaZZvx+mWnG21S4iowalW5FlfuO2+ZgXuw/lLn4PEUVxHvtBbaGbTw8ggdptn
         YIbqo8hl+6VTrtUIKAKsfJoPZAhqJWs3NndoqxFtzy6XXtbLqTdUE2JLM2fkveR5zgl2
         QumcUc6k8as0RF6i5n+sLic8BUGxHG/jBodUo+hU1NvibAjnRJZJCYRsP2/uy1ZbyflR
         b7SW5Q44ALic8gBdAa0aA8guccK3wXTE2zIKDuyFa9qwVPDqU1fkW73UUZiq1O8Bxbe8
         k/Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z1+AgbOb8CiyN9XIfRQ+d4PMiK2gGo4PmV8DL8KSdXs=;
        b=mp92oBisaZTDYtSKnMisAjNz5620VDTigONlL8JgJR0L1kpgA0ROmNjdge5EmLQAiJ
         n9lRTSAXINM8Q/DwrnyI9ozv1gVjGT3GQQvU+NbUZBgzj9DcPPkWS0ijE5m4xCu9aJXg
         gtWiz5ZChaghgHszs7BDLo70rapU9JIpSeG/f7E9pQHPaRCiWz7Snerefja4nMXaHcSV
         YvQp9Ug3CXc1R/ImvL+oeWzPDZ3LAO7+llmOdUwsRRWG4KUZ3jfNC00sgepzXgllDmbo
         ZFO5Tct2K+yqhxr7rkPBLJ7Xdp8EygZyIO3Kp5n9yNsWAIIzeRKKrIkhCkqnPXvdYkAK
         NB6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z1+AgbOb8CiyN9XIfRQ+d4PMiK2gGo4PmV8DL8KSdXs=;
        b=pAZHtFSQ7wiZbEOgaC3e0wfNPV3SdjoDyPvMxis6FL8k0Ey0X7PMsDh+4lyL3AbhiL
         NZNPQjeIGs9qT6bLIy7qv8cLyXZg7nUX43+FajANH935sKvDr+z60+lhEdoin1WNtTDB
         N3Dl69bDlkBig5eaixbky0U0UrdCYKOA9ewP8vleKOvIVpBJ31nCLkbF/SsoUKkLFvBY
         FcTEBhF/JyqL+WdGmPC9M9oBVR3nXCWRfHZuooDd4v+kDBtchwIfF488rbnvFRc971tD
         mpTF0FCgadFVxCD1dIgwfTt6eR4OLMzLXBEUK3KZ90n/ZlHvUyGqHRMXygq/NAwPGXe/
         XrMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vUcVI0yw8a0q7guOi/oRQ45kwLrnqoWXDsVC9p9McShrWNE4L
	HhUBZS3ZfjBh0oikbJQ+uVU=
X-Google-Smtp-Source: ABdhPJye2j0N0K68wao/dypqxcpC/3GqA196PzzJye8byDXbXTxL1hPaGx+XKng/eMlpdB5TkGYXMw==
X-Received: by 2002:ac8:4e0a:: with SMTP id c10mr13292455qtw.381.1617979663843;
        Fri, 09 Apr 2021 07:47:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c207:: with SMTP id i7ls5237926qkm.9.gmail; Fri, 09 Apr
 2021 07:47:43 -0700 (PDT)
X-Received: by 2002:a37:6191:: with SMTP id v139mr14370709qkb.32.1617979663402;
        Fri, 09 Apr 2021 07:47:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617979663; cv=none;
        d=google.com; s=arc-20160816;
        b=s1OYjlewdWalABwbIhv5EaIkPFCs3QGNCkvl8+t3LkvSml7lRjneZQCDpMoN67/BMw
         i/Y12B/Ye4G1o6O4jmODXr5DzK+vEDMgZzCM4uMwVAOlHYWN4HVWHnpxtNw0+18OF9YP
         x0ZgHe/aAAVHTGe1bbfaStP+z9Ks7GX3CUMJjIQ57QtrHZkTd0LWyWOfcG2SCFfdyUmS
         SPibD5YEixiZSExNiRX7DLMkMUB9YKUgQ+ADA6VXX4fU1p5REheXpEj9zZZYcnvjJm29
         prsBvtsO45EoYX/McfZo60CGngwCbxhNbsf0qYRv50yhQw9SLKS6AZeP1hcJVyc9sPWJ
         eDNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=oRh416PNzI2PZEXFBtYAA+fhYGm9TwWVvbjFwk9VVBo=;
        b=Fa9ilAYyJT1mOZEnO4pDbeSdmaGIPOjZSED8/nLo+LjLn5KodHxL0W0YL3PzkP46AA
         mol/M/KWLW1n/ktvAlfS5qB8zyyKp/HcAdn0dVV37GmQo5Itk+7rAveXHGcjpr1f3/hp
         GhhN2bQpkV+P+Q9I8LDDbhQNsv9mcdg/AmO0oGNxydUHRc60N6T97507abP3fCshlhQK
         m3nc5p15d6XEInaaFS8mpyguwVRVgIwNALiQsovy0DvMTgIrK2IFbi3RbM1q9nBAUjKq
         Ct64NVbjS1HbQ8Yy+Z60HBc02/JJheCRMiLgLAwldHEgp6NKEpcbElBQmOKdoN8K+fcf
         Zzdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r26si308689qtf.3.2021.04.09.07.47.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Apr 2021 07:47:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 895DD610D0;
	Fri,  9 Apr 2021 14:47:41 +0000 (UTC)
Date: Fri, 9 Apr 2021 15:47:39 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	stable@vger.kernel.org
Subject: Re: [PATCH v3] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210409144738.GB24031@arm.com>
References: <20210409132419.29965-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210409132419.29965-1-vincenzo.frascino@arm.com>
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

On Fri, Apr 09, 2021 at 02:24:19PM +0100, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index b3c70a612c7a..84a942c25870 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -166,14 +166,43 @@ static void set_gcr_el1_excl(u64 excl)
>  	 */
>  }
>  
> -void flush_mte_state(void)
> +void noinstr check_mte_async_tcf0(void)

Nitpick: it looks like naming isn't be entirely consistent with your
kernel async patches:

https://lore.kernel.org/linux-arm-kernel/20210315132019.33202-8-vincenzo.frascino@arm.com/

You could name them mte_check_tfsre0_el1() etc. Also make sure they are
called in similar places in both series.

> +{
> +	u64 tcf0;
> +
> +	if (!system_supports_mte())
> +		return;
> +
> +	/*
> +	 * dsb(ish) is not required before the register read
> +	 * because the TFSRE0_EL1 is automatically synchronized
> +	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
> +	 * is set.
> +	 */
> +	tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);
> +
> +	if (tcf0 & SYS_TFSR_EL1_TF0)
> +		set_thread_flag(TIF_MTE_ASYNC_FAULT);
> +
> +	write_sysreg_s(0, SYS_TFSRE0_EL1);

Please move the write_sysreg() inside the 'if' block. If it was 0,
there's no point in a potentially more expensive write.

That said, we only check TFSRE0_EL1 on entry from EL0. Is there a point
in clearing it before we return to EL0? Uaccess routines may set it
anyway.

> +}
> +
> +void noinstr clear_mte_async_tcf0(void)
>  {
>  	if (!system_supports_mte())
>  		return;
>  
> -	/* clear any pending asynchronous tag fault */
>  	dsb(ish);
>  	write_sysreg_s(0, SYS_TFSRE0_EL1);
> +}

I think Mark suggested on your first version that we should keep these
functions in mte.h so that they can be inlined. They are small and only
called in one or two places.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409144738.GB24031%40arm.com.
