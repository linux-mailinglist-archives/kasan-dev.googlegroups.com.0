Return-Path: <kasan-dev+bncBCRKNY4WZECBBT46777QKGQEMWIWHSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B4342F5A10
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 05:57:53 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id z7sf1884673oic.21
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 20:57:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610600272; cv=pass;
        d=google.com; s=arc-20160816;
        b=k3t6TpWQvnSqGu2t4rrveRYD3DpqU4e1qW0FX8zsI73VPTMnLz13GAI+gEPdA8zwCt
         2DGJMeaXc1NEiGzDmpbwg6HJhKQVYdEC5oVDUCUTBpW6gO2ysijPzYRBNmwfGwGDRZ+x
         n2aYSshM9lgmpfrU7z7s8j6luUbjECGeQaFxDbdnsEn6TDYdzcGmnxoZkEk3+TC8Vs/o
         sCiUpOnVsL3Tc+FUTlBdQlk2kJJpRPM+fFjnVz5CrvaZXlRoRENr0bSTM1fyy34zo4L4
         Fgh3NoJ+KA1zVHgXOx+bN1fibHL7z0LoWL4uslB96Qz9AqLsRX5z+tflAdiF9JY7Ac9R
         r+xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=hG0fQfGOPAnnM5gQFP86FwjbJ/ecrdklEHexwwHakDM=;
        b=jAEKhuCeOkvDr7dawvuhe0pM1Mi0bfgkAyRe6dXhVfXvN8g797DrBehyYaaMcJLWFS
         bqDY7J1uxiPPd4xnYGWIE+/ZYiUPklNDKMh9Z2k6xOU9uZSsysgNBbk2S2l1HWCpGnpM
         7Vn0CbsmpU8Worm8Q2A0UoLARefpy2wZn5eqUGagO5u4xOvWqEFpA3QyiU5AGIwR6iWt
         wPPf1IsKiCvcoQ9eA7HnEmrzOBXL4st/NX88wRKv/a909qPlVxDf5SVoz5toIr6F9FMn
         3Pz3/Kn2A0VbDySqXdl00s+Xkplt+//EqCluwVwtVnrCue9iw2WqZdXc9sQSGwrl99St
         lhIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=rkJ6uQ+C;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hG0fQfGOPAnnM5gQFP86FwjbJ/ecrdklEHexwwHakDM=;
        b=OrO/lY3gsXymouOihC1h9y9G0xiwfGcAQh9dwRKqWjG4+iJaI/if0sblafHhYnWnm0
         lJEn7k2Zc2/CoirgRxHekgjD2PnJrrbaOnMd68NbzR4TFojXDBebHP95nVVdoZwdmezX
         HKU21Fqku0OlstQwKqXCBY7YWJ95syknBgG6PzEe47ffK7F9UM9/d+k3bJUh9mCw2Wix
         NMql23FiBHdXnTyM/nBN9QKQqzeo1A0DWQXMCui7vj1J6uVKhC6ZjwXemXlwP2Agv1l9
         toWtc3Ix7MVEf+JWB8dkdQlOhynpMFpxKV04DohbRGaVqFkb5E2d/GL4YXQw/+d+6wSn
         W1dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hG0fQfGOPAnnM5gQFP86FwjbJ/ecrdklEHexwwHakDM=;
        b=VcJNqx7cJClGSH2EvA21CNpxGdCgBEhymRnmV8e1Ok0EJOpvmqRFuHeukp6n1Ezby6
         m1FscY+uy8e8rEzywVwI+y18dmXN1LPdKZFubsNAmLq4+nqJApS8MircoveuwGzNfD7N
         wwBjzIV3v+pXkoak01B2mUA/8bhbegeTsZey+tF6USlgswdTBBNSMj9GYvmyikSk4gLt
         MRJZF3ROSPAKomq2nbNRVYHoQ4N+0IekFX5liUDOGPdF18L8D8KOrkCs3pznA4rk9mKX
         qgBPzMdc1520CBT5zSugOqQ1R+N+cFZ8PWx3RMr1GkX2gw7Es6W0PwXpRObAaGZSCflm
         iVCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eo6wZvuxHNLA8AMx4Ckw6UmdLFrDDi2NNyhwtn0gTQOxh+WK/
	xNOvYTbFUcFYCDckN6aF0ro=
X-Google-Smtp-Source: ABdhPJys93sQINEAkGE6mJG/OtvxD4/s11mdmLqXviH/peEO0DVYlYhW8Sdk2yr9GWHYAkoE+obXmA==
X-Received: by 2002:aca:cc01:: with SMTP id c1mr1686793oig.18.1610600272062;
        Wed, 13 Jan 2021 20:57:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6841:: with SMTP id c1ls1096305oto.8.gmail; Wed, 13 Jan
 2021 20:57:51 -0800 (PST)
X-Received: by 2002:a05:6830:12:: with SMTP id c18mr3669101otp.283.1610600271655;
        Wed, 13 Jan 2021 20:57:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610600271; cv=none;
        d=google.com; s=arc-20160816;
        b=RVYi8ni5NqQ4522lKoJjChQBIG6EbV6Pt2cErOHyeyXYb+JMOekBxBjAJwW3nwsWWm
         Q1lUyrHDsbK3H2P0LAzSogZcoCFZZrSkiQT/0hTvPiXRrtUOArWmTzL1MS54tEfavOgn
         +XFlVSPXlxCEG1fmzlv09VeWOq/ebBLPkjjGqqUuKO1lBdfhlCJ3VdtWuBRpdW5quvgj
         1SYikHU1r2VGLy6Jtow+VhhifctFWPg73DMElmCyboEVXzwaeXnRZC8gsFl4i7TgJIug
         gUOSRCtBlTrRAWiCQmT/clkdpQo5qW+e0FnofJSIYfuMeRdYV061flt8xxmoKM1viyo2
         m7pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=ZmdvymZ2qR4M/qVQyd7uYkLb/p5vBHQAHMPmoaJ6QXk=;
        b=imh1ZCxctiXAW6DZDmHoRg3QilSnoVC8CS/hsoaWVRx/TQXRJ/kx342bVeyQsJPkeg
         q9qUVuXDts/u2v/5BZp+ouAT3ZPdzBNpCTKBmLqznnsIIWnDWvSou6dQshTULLzBh6Kp
         v+8GqZB8en+YW2u3OMjK4nWFO9HahidoCfCrn58LusVHYoEkuBWXDVvYAUzlM7GLkeYW
         eBmTCCD7jPCTPCZ3ccDyY59ovHCEi6zTDCFhDMu6lX/FW5fXJKtoaLqwANnwYUYPMaFS
         MV7uF0eGuoxcRq6vBiljRNqWMe1QGT53ujGt01nfjHfVZwDPb3Ns9/672xMzTtFfY59a
         MeYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=rkJ6uQ+C;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id c18si272185oib.5.2021.01.13.20.57.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 20:57:51 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id c22so2936545pgg.13
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 20:57:51 -0800 (PST)
X-Received: by 2002:a63:e40e:: with SMTP id a14mr5586177pgi.345.1610600270765;
        Wed, 13 Jan 2021 20:57:50 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id az6sm3857596pjb.24.2021.01.13.20.57.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Jan 2021 20:57:49 -0800 (PST)
Date: Wed, 13 Jan 2021 20:57:49 -0800 (PST)
Subject: Re: [PATCH 1/1] riscv: Fix KASAN memory mapping.
In-Reply-To: <20210113022410.9057-1-nylon7@andestech.com>
CC: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, aou@eecs.berkeley.edu, Paul Walmsley <paul.walmsley@sifive.com>,
  dvyukov@google.com, glider@google.com, aryabinin@virtuozzo.com, alankao@andestech.com,
  nickhu@andestech.com, nylon7@andestech.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: nylon7@andestech.com
Message-ID: <mhng-40ebb582-4df3-4189-9521-5446cbe1a9e6@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=rkJ6uQ+C;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 12 Jan 2021 18:24:10 PST (-0800), nylon7@andestech.com wrote:
> From: Nick Hu <nickhu@andestech.com>
>
> Use virtual address instead of physical address when translating
> the address to shadow memory by kasan_mem_to_shadow().
>
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> Signed-off-by: Nylon Chen <nylon7@andestech.com>
> ---
>  arch/riscv/mm/kasan_init.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 12ddd1f6bf70..a8a2ffd9114a 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -93,8 +93,8 @@ void __init kasan_init(void)
>  								VMALLOC_END));
>
>  	for_each_mem_range(i, &_start, &_end) {
> -		void *start = (void *)_start;
> -		void *end = (void *)_end;
> +		void *start = (void *)__va(_start);
> +		void *end = (void *)__va(_end);
>
>  		if (start >= end)
>  			break;

Thanks, this is on fixes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-40ebb582-4df3-4189-9521-5446cbe1a9e6%40palmerdabbelt-glaptop.
