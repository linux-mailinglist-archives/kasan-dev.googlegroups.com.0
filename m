Return-Path: <kasan-dev+bncBDDL3KWR4EBRBKOQST7AKGQE6ZXPLVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A5B12C8A89
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 18:13:15 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id r8sf9502336pfh.9
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 09:13:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606756394; cv=pass;
        d=google.com; s=arc-20160816;
        b=gWlMzbfdGcZxyOTpnxK7Ym4rOsSjjcFqdKdIua79Bbk6FogNL/CPCriXdnuB2Hqxa+
         GVBPbF7Uyqa1ZQuogujEHJ7RARTtIyAoU00JgPEotzfH//RhNhXt0NBITsnQZoNGQIJf
         InzvHJeg+e5AHIyaOLuWp1JRvOVAyQzTjlil1tjL1lSSRgTrEl1Zq5Lq2cAyFUkjIN1h
         XIdpZjDgC7p3Ud+alcd9dflrmq2IFV094ZYQCt7VROr28PHynQIJHbCPIFa2ve871luJ
         eHX08Z/KamM+7YtsO0HJroL3TTFQZ+tq3lAcsL/590EvmTyXauCd9z59GGemEBBalIXR
         A6dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FlC/es8OKsbqsv8R4fCUXCbdVJeVXWbacA7ZfDv+GVY=;
        b=Hnr/xbTIksmcxoTVTj+O02jqXYnLIUYk5RRI2CTNW6iSP9LDMmuXu7KzqL7jC4rhYW
         DhXcNAdllsTtosri33fP0MV6fuTQoPDuf3T+7K45vMroRHE4wxl0syfqA55fQBelZfHe
         f0j161H5T3aRojIKJGJKazgFAGzKfU0kMH78Rci+iA7XA796YbnyQ3Vdt/27yZ9S4LxA
         qLbiUcB2+AAY2u4VeQi/a+7kU2AFRx3Vg264D8rsVlH6BMLuXZXDEoV82IxNkzdNVswz
         7QRMkGGlPAtWUrNPMPBbkupmpLbcAUhT1522GbS7YnSmchOCbwXh0LNHuekp8+jXSSvV
         OJaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FlC/es8OKsbqsv8R4fCUXCbdVJeVXWbacA7ZfDv+GVY=;
        b=iMxTx/ufctmWlFJnQj5Y502XOFbV33v5aGq/N6mVtAJhV0vrF0ZBIrAMYyNYxepTHb
         mHZGp0HWSeKJcQwP8PyJp/dfTRjltcqKP/WRD5JJnA8CTzFJ3W8rCYFi0+5WCZjgFx+k
         AWhj2t1RzQ01wmyroUF930cn+6gxe4ct3ig0M33B8+z5av91wIdaJr9/YIgC7RqpWkOY
         WHLo4026Hcned712KfQqx1G8X9ziIQCmrMbstct2prpNDsr4xu6adM/ywzMEfSuh4PpT
         XricepSdDdW9uKoYGkPaiaDaTu5QHByDZYtAFrwdiK8jIDpefV3AuvmJc04C/fdrioOP
         fR+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FlC/es8OKsbqsv8R4fCUXCbdVJeVXWbacA7ZfDv+GVY=;
        b=WYUUClo5DghwYU4EVZnBFRurrYswocP/+Ae0S5ozBRrhqf2k3XV+eTKrg6maEQ10H4
         sDM7gPkTUpyZQr5T/YRipgEiv+3aW4Y4twAPLSG66X2l1dg17uAeEo8rqmOmz4AC9C9N
         DCm7fOJbYuhdcoD6ANQTdtti/dg8VQ003Ppra1U9hERkqd/LiNtmxeZdVqGw76nmhEK4
         fMrxnWTbKnBhgVCxjyUATYFeMIZxvlNEyY6n0TwjGyINFITJaEpnEMLlP2gXD6d6gc16
         paj3qRERkZy/h773p/BPsQ98WUoXw0WJ9azshMBHV7fAi35GZLbhv2qyJ0GHD8mWVZ0R
         p4YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533owiPk4bwJYjsso32nAHrc8/YGH9d9PRP5HDMli2OTapwHJXoO
	c2rJ2GTgv+h6LYgegX4TQTA=
X-Google-Smtp-Source: ABdhPJxTaSUp2gmlpqzX3SW0VR6wAYNEBT3SwUKO6h0hZtm7mpMpb8Ag5NBfkD3AOZ2LcBFqGZHjIg==
X-Received: by 2002:a63:5315:: with SMTP id h21mr19087000pgb.43.1606756394008;
        Mon, 30 Nov 2020 09:13:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e905:: with SMTP id k5ls6161139pld.4.gmail; Mon, 30
 Nov 2020 09:13:13 -0800 (PST)
X-Received: by 2002:a17:90a:e604:: with SMTP id j4mr27109202pjy.19.1606756393371;
        Mon, 30 Nov 2020 09:13:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606756393; cv=none;
        d=google.com; s=arc-20160816;
        b=Ciwnd5ioiQ3wHo7uToQWukfIek+FWtzQWB9V3ftaHSQU1Z0bIFtJPnDm3Xi/yXPDGL
         lvKL43dWB15wJ/jOz4bb0KhDq6yfuI4wp8iH82mh3JvkSUZoYVFn+wubtDJQAqCUhyC3
         jrXQZfMRK0Q9kbAJbMwYqZ58R+NGWjnpCEHNwW485nrH3sVRkcmKwZ9pdEshjkynIfxE
         Qn1kBOu7u0FqDyOFIWbe2ds4q7WaM4GO8GtIqx2hBc9fsGHp+oLdghqvGoFwUWi+Wazn
         TPnI/UTxe+3BlUVDkDmlRVndoxMCblwYuujEEDLkUgv/2RnULtDVPcehJ1y+3WiDbUjq
         0fVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=kJTAQxX2FkuGXHTrnrwBboUVHSytoXkQkqS91actI50=;
        b=tnuiJo04Mv3yclWsl53kbeSS44Wfd+FDeL88LjFKr5ikfY0BgT/IhmhHZhpfx/c0fT
         8tVzmCxC4ix32XoWOjFtdHzwo39W/Rcu2VzokwK9B4qP54exFwau3ppctqleJ5UFyONs
         jcXJdudRyBNDEXfqYpBNeM2jWeR6zJwbpn3uZwg698cT3welFFiybFfLpr4wTmsivlDC
         NGRZX2tgXCdA6k1Nvk2lsa/ZFefMewsibyoDBDzWnLYfw7+Hl8UWDWHIytLVuvJJ6KRX
         q0WP3qdVEqNLLJa8M+jug3yI1DeKVQ7IvyUkkcZ4sm/lHgq18YLJMgfK2hTBZWJO3rZL
         a+qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d12si717097pll.0.2020.11.30.09.13.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Nov 2020 09:13:13 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.146.230.165])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 133102073C;
	Mon, 30 Nov 2020 17:13:11 +0000 (UTC)
Date: Mon, 30 Nov 2020 17:13:09 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>
Subject: Re: [PATCH v2] arm64: mte: Fix typo in macro definition
Message-ID: <20201130171309.GG3902@gaia>
References: <20201130170709.22309-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201130170709.22309-1-vincenzo.frascino@arm.com>
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

On Mon, Nov 30, 2020 at 05:07:09PM +0000, Vincenzo Frascino wrote:
> UL in the definition of SYS_TFSR_EL1_TF1 was misspelled causing
> compilation issues when trying to implement in kernel MTE async
> mode.
> 
> Fix the macro correcting the typo.
> 
> Note: MTE async mode will be introduced with a future series.
> 
> Fixes: c058b1c4a5ea ("arm64: mte: system register definitions")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/sysreg.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/include/asm/sysreg.h b/arch/arm64/include/asm/sysreg.h
> index e2ef4c2edf06..801861d05426 100644
> --- a/arch/arm64/include/asm/sysreg.h
> +++ b/arch/arm64/include/asm/sysreg.h
> @@ -987,7 +987,7 @@
>  #define SYS_TFSR_EL1_TF0_SHIFT	0
>  #define SYS_TFSR_EL1_TF1_SHIFT	1
>  #define SYS_TFSR_EL1_TF0	(UL(1) << SYS_TFSR_EL1_TF0_SHIFT)
> -#define SYS_TFSR_EL1_TF1	(UK(2) << SYS_TFSR_EL1_TF1_SHIFT)
> +#define SYS_TFSR_EL1_TF1	(UL(1) << SYS_TFSR_EL1_TF1_SHIFT)

I think we should first rename it to EU and then fix it properly ;).

While nothing breaks without this patch currently, we should merge it as
a fix.

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201130171309.GG3902%40gaia.
