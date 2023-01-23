Return-Path: <kasan-dev+bncBDCLJAGETYJBBF4OXSPAMGQEZOU6M3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C2F1678A98
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 23:15:52 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id t26-20020adfa2da000000b002be9cd25e90sf1550778wra.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 14:15:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674512152; cv=pass;
        d=google.com; s=arc-20160816;
        b=bfVb/QfU6TojNqL5KVfHhT+99EYWFUoV6rXYOYl5hR4LxLpbBLoszLhUADOHAonFop
         T2xMT5rML3wmWYtQQ6ZKR59w3eRuYk6ozMAU6EiMTNBqSaLWzNLdATkSAoo2iqFbG+jO
         OOU9aWz9tm9fpUiPesyWUeogLC/xi0b6Gst2pN5lJJ1z5NyAsqugYoSlr3VBGBhDFxQk
         SzfPypM69gKXuKmDDhtY7ie+EEEuJPFS2ADMiVR/NutFuzHVqflPvzmCLO3lxBpPzWhp
         b5gmkQMUakvI964WM+I19iLCOy6faIam1hGSuC0FWUKWJxK+qvMc2yWSVJZfiBv8wWf6
         nPbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uwLaFOucNpmjccF6QOQWSqfn5dxYTg6VmPsdHNJLdM8=;
        b=gmZ1D7O6+yNvmubJjsuLGEvmDLGwgkgXTIeZ2WPxgIluLbiKUqqcIe0HiD9TLAEOgu
         KuAh4p5U3l6dv+5YiFuW2Vk9QmDDWxR7VM6Ilt/U2uSoPJf2M4Wkr4z1V5Eh0Vy42PtL
         qeiTvMcyXqfhZA+UMvP9mzj3AFYnqhIDtIFz2IqxCy36CXiE/x33+ZpEzTbNwBd/GKSW
         g0QkrfQopi12EDC1ayqQM67R3G82V9kRr0/teKm97grNcgMeA0furJoneMlC1RtDyY89
         GFXa/HrE/dZkG0fosNQagXLmqixvcTBW4a/SoeYbH3fHCEiXjKbqj+/DMY0QBxk433mk
         Xomg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WODNM7Zm;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uwLaFOucNpmjccF6QOQWSqfn5dxYTg6VmPsdHNJLdM8=;
        b=hGWOgACG1W0JgIE8hUIxPMtbNePT7SD2MQKlJUFvSGw8zRUr1Yo3udCAu+KiTiy9K4
         80RfLQy4//tULntVXy8//bj5U3tPaaj86eJY6Y3kGC+fbqSnagWMORPlqfXEbGgkqvTm
         vfg8xw6CzLsBJG1KSXX8EgysPXOD0YVZXMTy9mviJbkFOx5HWvilnGfprPZiwwKRNmh4
         O1S6S3xtp8gst83fx7omxYVin4mfQgbPrxYQWxib0huAOjEgbE91MfHJO74EceStXDln
         FTx3Ui6wFeMVPwWCoj7/UDQqPF15hPboL/cBZL2tg9hl7ZGWihQbRgQAxjwyCvzrSwpL
         Pmdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uwLaFOucNpmjccF6QOQWSqfn5dxYTg6VmPsdHNJLdM8=;
        b=4tTg4FBcJaSRr0NyuApj+94Htfr8Hb7wiiwgxndPwymDu0Bscx+Ys1tmlIPX0VXmE8
         YRVscJOdxjLC5ODu6fG/t2ypAd9GgpQP5wLfiY3/84GxoDX17H82Vzz6Z2iW8Pj+G4R0
         fpSilVXTWAy29qRiF4oUGdTFFSgIGNk+i+VjBQYT1QcnnCJr3HYV2Xky8J8tX+CSFE56
         f99q+cCpTj+BLT5oPqJfPSw1xJA+JThTH2+ZNLb9bdWWGrpB95L/y3g9O1bWgP8zuSiA
         W+v65Cup+b7Yh9sZU0j28zJl1AX626n5XMyZJdiEk0pPZF/7EfnHigbpQSYMBLIopuaM
         Qnnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqWgA3B9UyG6vP+l3TKOlsnDApcDg+GsrWEYTej1RUf0V4rmAl/
	xdStmQpvveOhasxxRTKMEek=
X-Google-Smtp-Source: AMrXdXuJKbol8BEEuXvYNkrGewMEbb5dCJ6/L0XT25a9q1hyH7eUmOQBoicvvUI4+VxAaTjUHE5AyA==
X-Received: by 2002:a7b:cbc7:0:b0:3da:fef7:218 with SMTP id n7-20020a7bcbc7000000b003dafef70218mr1763374wmi.94.1674512151755;
        Mon, 23 Jan 2023 14:15:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd91:0:b0:2bf:adc3:9107 with SMTP id q17-20020adfcd91000000b002bfadc39107ls1328426wrj.0.-pod-prod-gmail;
 Mon, 23 Jan 2023 14:15:50 -0800 (PST)
X-Received: by 2002:adf:cf0f:0:b0:242:5d8e:6c35 with SMTP id o15-20020adfcf0f000000b002425d8e6c35mr23573428wrj.28.1674512150602;
        Mon, 23 Jan 2023 14:15:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674512150; cv=none;
        d=google.com; s=arc-20160816;
        b=n3CrB0NejZHkrnFce2evnh+uejz4Ii91PZNwonlQDy7mw/9bfohn0I5lsdsgfp3IHU
         eZOGJfb+uxXxSm6CMyxk5qlEhBDco4JHcXIxh3hu0xPjnGy2a5oKxLWXr4vJvHsOhaRx
         YD+PXP5M5ic8pxPojyHWe9A2Mf+IttTgpdDzbz4/echc8zKWW9KEkZGyYQO4OxcaOOTo
         /uj1pgcfx1reOgBE0YbZchAbVgXksx16tqwnH4FmA1p/zt0nX7TzA1hkJkuhtwa8HoAp
         ynSSgAK6J73xdjbd/jwzSMJ12iyey+ERniRDUFp6o26eoSs6Lgq5SQSKeRHN83nxjc3x
         1fLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=peyIGltCEXVwyRJm3g1xSxXN5vxQoEGDcrs27anqh80=;
        b=aUvsEz1YFWaDEJoxYERvZ7YmVuRiEhicJHZ53JMLy0uMuGScCtY81jgaD/9m81Y5gN
         0IwheF1UQOr66mg9zDSDvcz6RUzbhOjZtKBTv8/VrkeLOtddO+zBNES6Mz18v6LTSSm8
         2/pp+W3FY8KPJwRSKLRLFBRV7LA0wt9QTV+QIgqn7qqhhtft42zYTynLf4drQl18XVUX
         UBiD8Ioz2/pAVSILB2RnQuBkqLsEP5pVeTmlmhyVw0/I61nzDQrk96C5khQtA/H0Yyru
         vPW6bXySJqg+SRmfPyyDHiQvIwxIwO65qV0kKW9xe8pSmztyX91i9m/5lFZTIgkkSyLs
         vXvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WODNM7Zm;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id ba25-20020a0560001c1900b002be1052742esi23252wrb.4.2023.01.23.14.15.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Jan 2023 14:15:50 -0800 (PST)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4FFBDB80DFC;
	Mon, 23 Jan 2023 22:15:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4D2B3C433EF;
	Mon, 23 Jan 2023 22:15:46 +0000 (UTC)
Date: Mon, 23 Jan 2023 22:15:43 +0000
From: Conor Dooley <conor@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Subject: Re: [PATCH v2 1/6] riscv: Split early and final KASAN population
 functions
Message-ID: <Y88HD2ocLQilIuDr@spud>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
 <20230123100951.810807-2-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="/CdvQ7qYoN72WHHO"
Content-Disposition: inline
In-Reply-To: <20230123100951.810807-2-alexghiti@rivosinc.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WODNM7Zm;       spf=pass
 (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE sp=NONE
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


--/CdvQ7qYoN72WHHO
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hey Alex,

FYI this patch has a couple places with spaces used rather than tabs for
indent.

>  static void __init kasan_populate_p4d(pgd_t *pgd,
> -				      unsigned long vaddr, unsigned long end,
> -				      bool early)
> +				      unsigned long vaddr, unsigned long end)
>  {
>  	phys_addr_t phys_addr;
>  	p4d_t *p4dp, *base_p4d;
>  	unsigned long next;
>  
> -	if (early) {
> -		/*
> -		 * We can't use pgd_page_vaddr here as it would return a linear
> -		 * mapping address but it is not mapped yet, but when populating
> -		 * early_pg_dir, we need the physical address and when populating
> -		 * swapper_pg_dir, we need the kernel virtual address so use
> -		 * pt_ops facility.
> -		 */
> -		base_p4d = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(*pgd)));
> -	} else {
> -		base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
> -		if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
> -			base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
> -			memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
> -				sizeof(p4d_t) * PTRS_PER_P4D);
> -		}
> -	}
> +	base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
> +	if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
> +		base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
> +        memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
> +                sizeof(p4d_t) * PTRS_PER_P4D);
> +    }

^^  here.

Thanks,
Conor.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y88HD2ocLQilIuDr%40spud.

--/CdvQ7qYoN72WHHO
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCY88HDwAKCRB4tDGHoIJi
0g3jAP9qpKIGB01xKifUub9QHdmf+VkgP+aCUvX0haiSSlOv5gEA5jDr/uhR9d5+
klCEHGmOIU7GXyYShrKt3au2MQpcXQY=
=NeIJ
-----END PGP SIGNATURE-----

--/CdvQ7qYoN72WHHO--
