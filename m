Return-Path: <kasan-dev+bncBDAZZCVNSYPBB57CY6AAMGQE6PGWP3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B5842306779
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 00:04:25 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id w84sf1575333oib.14
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 15:04:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611788664; cv=pass;
        d=google.com; s=arc-20160816;
        b=0rzk8JAM6bFwslyiwc/uqyvXfNAHvySBFxuszlDXC2Gjc3Q3nqOgHv12LKO1W2pBJn
         zLu9b0n8V26PkMKAoVfnwc5iITjw1+urznZtbgjfzg3CA357i6cs61aLZlKyy6hX12BZ
         vHfkZ0Pl1qUnZKaXCVD4BJd54gvTPHm5cclP9goHegKZWCsvqXCpgPmKfxyda+jko4oO
         SUQ6nM2shVGqjLS8vWKOrktXERTsPjiikkSgi3voLSWhboTsoDl4Ih9ornAIMmd6+pxk
         Psbvvkj/39adleF+VDJMDjec24jBLyYDxGLr55fTCGUUpJdAifqfkdKtetS808Njq1FW
         2FPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4EFNX5ARAPVbzoJiyeyveVnBWuTdN4tn47Hqjqv1Xuc=;
        b=VCgmwiMOtej3HEdGKlghA2TLmY+KO7ob4b5H/zVTXSAizt/nf/Qc9/SvJMVjK1hy5g
         e/b/eiLKRd1dxJoFe16dTXu0yhG2ImHsFdO8RI1t/Yv82st4U7P4sk88obIF3GVHaPai
         xEk4RLWRel2ahIHqBaIHVWpHNEMupSlqtJ7QLPlPkdoWJjaM13k0amZh/N+X40TI1xug
         sSEeyrl1yzriwPWi82CPyj4oM1Ngt0tkpVcbpz90S9931OZaV8MIosNCIoksyH1qVR3i
         mN+r7cSDpMOi2O2rxkPvcsl1F6WzyOF+mc/3zZM5LmsgcqyTUUCb7Bd3pNoPLe+m9nvK
         lC7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Or6G1XJC;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4EFNX5ARAPVbzoJiyeyveVnBWuTdN4tn47Hqjqv1Xuc=;
        b=VDbtlwffUiIXpLN0HTQDKmNZ63zgUHftEyT5Ix3B5zOpUrPVpDTxRWtD2x1Y4kpOp8
         EbShrCQiWQ4frGqehRc/evWVjcKmIzdN/DnsI/iUMzVEsIQy2VVjDeE4grMpIJhcjWR6
         wxDsoL/fyeNJQjc+cwBLwtNzp75dleXZcvx7xZUxvsqSFp1ZjKVLVXaMaEcmsKhwznus
         OUjyI1ztlgJZbEQCQzXJlK7BdUa4Tl9oTs1rwL491sNfYExGvjpNwZeo7y3DI3Z36MZZ
         2uCatiAseNQNJY+dC+hYfFZ5gfMyNP5ATC/rbfIfXFphPc9Cow0ZZWT4PGc/jrztI/rB
         sU9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4EFNX5ARAPVbzoJiyeyveVnBWuTdN4tn47Hqjqv1Xuc=;
        b=S0Qd3nbX1rKxJzBIOBBKt92HdAYJG281bvJ9lJcaH8QTSi+6YEtJEp+pr8DJ+lSm7w
         BiZp2ebAQtd9IV4nuU3nR39+zqvdfvwmlpfjPQxDvKrM07i3VcRKL3mKFf7tZA94hoyM
         HndDSWwYvPXyVmHuK/lKm8qJdj3Up3oOA/l5bO1+dr562OHi0RuJ7XyD0Z50WYQP1kZE
         n3LKVbNhVcKAMNU7rrC+dppfx4jvH0lciirEiGW4w0IRlWUOsMR53rthGxGVwGOQ6Vtq
         SghnOfWQNlaEzuxfQa0HG1p1NfxZcwBf8fjUeRT62MEBtrLF6BY6k9K5iCeLDUu2xbZH
         XINw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530agrIhv6C4nSqW8uMDXU8F2rXT273aDaD3+WO0dg3v/rIomvvs
	kSuoRQjjHMyytpQcnORFewg=
X-Google-Smtp-Source: ABdhPJzhVTVJXGFyPIsCLfp+iGRf+sh9dTNw5g8Q4LfJn1d8b89jlW9H6csfTDkcExxIKUiO6ElOXQ==
X-Received: by 2002:a9d:3284:: with SMTP id u4mr9227175otb.187.1611788663194;
        Wed, 27 Jan 2021 15:04:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1309:: with SMTP id e9ls867158oii.4.gmail; Wed, 27 Jan
 2021 15:04:22 -0800 (PST)
X-Received: by 2002:aca:be87:: with SMTP id o129mr4691432oif.36.1611788662781;
        Wed, 27 Jan 2021 15:04:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611788662; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/cnlf1EYsiJFpu3CopCRMEhq84SmWdxHzRN7itCIQYBoZ2bnEaajm5sll/srVJD+O
         LVi0guneg5sUTwQc/ZdgzVjKWjPmnpYYgsmudRSiG84s5GCNXlZFLsciCLSDvY2cxOcB
         f0Led3LOgMhlPDWJFKqo5xQW5kz4QpCLurTp4mIhMRRJNSzZsoTHEUktN9kedCxJJIo4
         MUgVxaOr/b+i3jYssr5BuQCqji8REz506Xh0++B3d1wqrfzOrQOQCQDoJrNZSX6HTKcg
         9pRulBye95vEAyF20Gc2PJ1RCJSyEVoVO74yNtOJpHqTuTS5TnxfryQX952/VGwRVEu/
         Sttg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GOoeAMPwGyrQGfEzLQIMIYV9BXSotH6rNhDNBFFGJLk=;
        b=yyfZHe/jTE2fa7MagPr/69oFxMtSZatgk3hWyIr2I+V2kB3wu4l1QbAqY93TwxaEj6
         PcIzwiEN6lyZM7YU4mRO9JoIqJ/k5ujXbMCxQUNeDtq2eAxC+NqzP1CQiF2VlRx51ICK
         prdLdop3JMUt7s/Xu1/Jb7ppL7DSk/P2kUewHdmM7YQjzhpxvNTquvcvdGz+tspLICQy
         bAZOLVUVeVgrEoqcTVLopwLyBkyJJKF0J1f3iY3xD7ura9DMN95fJjOziBo/30aEfZjX
         +XTFaKj+fI3vXoOCRbdfZ7uqty+HDMwPYvwYplJET/TlulSGH6N+aUFea3xdPw8NolaD
         lCEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Or6G1XJC;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l126si203868oih.3.2021.01.27.15.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jan 2021 15:04:22 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4A84E64DCE;
	Wed, 27 Jan 2021 23:04:17 +0000 (UTC)
Date: Wed, 27 Jan 2021 23:04:14 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	dan.j.williams@intel.com, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com,
	catalin.marinas@arm.com, ardb@kernel.org, andreyknvl@google.com,
	broonie@kernel.org, linux@roeck-us.net, rppt@kernel.org,
	tyhicks@linux.microsoft.com, robin.murphy@arm.com,
	vincenzo.frascino@arm.com, gustavoars@kernel.org,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: Re: [PATCH v2 4/4] arm64: kaslr: support randomized module area with
 KASAN_VMALLOC
Message-ID: <20210127230413.GA1016@willie-the-truck>
References: <20210109103252.812517-1-lecopzer@gmail.com>
 <20210109103252.812517-5-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210109103252.812517-5-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Or6G1XJC;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Sat, Jan 09, 2021 at 06:32:52PM +0800, Lecopzer Chen wrote:
> After KASAN_VMALLOC works in arm64, we can randomize module region
> into vmalloc area now.
> 
> Test:
> 	VMALLOC area ffffffc010000000 fffffffdf0000000
> 
> 	before the patch:
> 		module_alloc_base/end ffffffc008b80000 ffffffc010000000
> 	after the patch:
> 		module_alloc_base/end ffffffdcf4bed000 ffffffc010000000
> 
> 	And the function that insmod some modules is fine.
> 
> Suggested-by: Ard Biesheuvel <ardb@kernel.org>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
>  arch/arm64/kernel/module.c | 16 +++++++++-------
>  2 files changed, 19 insertions(+), 15 deletions(-)
> 
> diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
> index 1c74c45b9494..a2858058e724 100644
> --- a/arch/arm64/kernel/kaslr.c
> +++ b/arch/arm64/kernel/kaslr.c
> @@ -161,15 +161,17 @@ u64 __init kaslr_early_init(u64 dt_phys)
>  	/* use the top 16 bits to randomize the linear region */
>  	memstart_offset_seed = seed >> 48;
>  
> -	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> -	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) &&
> +	    (IS_ENABLED(CONFIG_KASAN_GENERIC) ||

CONFIG_KASAN_VMALLOC depends on CONFIG_KASAN_GENERIC so why is this
necessary?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210127230413.GA1016%40willie-the-truck.
