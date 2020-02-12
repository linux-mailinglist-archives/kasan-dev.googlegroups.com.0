Return-Path: <kasan-dev+bncBCXLBLOA7IGBBNVZR3ZAKGQEV2D2TOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AC99115A15D
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 07:35:34 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id d21sf1067309edy.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 22:35:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581489334; cv=pass;
        d=google.com; s=arc-20160816;
        b=NHDlZgqpXlMy9NHW7mNg5Hj/Ge3R8cxVeYd1xY0tat4nZjehu0Sgr/c2uPIv19lkv1
         HBkw6pE4Jy0T0WItRCsBRvoATEqXZ5AjsD9Al8RRQ/CRdqT1rEcCbWy0XwvW1CR2UMIV
         HHYf3NsYOv8sRUoeVdCrnbtQHelh3yoi7EqqoIW0HPEgkjvieSDiRVtwpxgA9p+IRcOS
         WLXY2K+fTdcKrD2Id5Ls43xBD6mLTzIZsPV6xlNcck7V5Xavh0nM0I+b3zuRRnhkrFz5
         Qfct0I8wwHFxow+1Y1Gdtw0/YGBk/r2Wl9Itp2kILH2LxHqMdQXlU7CkGRUdSvdrK0yE
         gc7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=lp5qaBjkxw0icbORRHD6va1jT62YsOuRHmEi6lNhalc=;
        b=YRSKg8WL/374Ox9g1mcjRJAzPh7aclrDnmxzWif0VIJ8+12kzmKlhj3NPI77ahoU4i
         4nPV7u8VJCrp24zy5Bemgms+NBlLa5VXybAdQp4tfzd6L/bHfMvt4WofcxmmjF32DqvL
         wrdg6y6AlXSuNMyMxHcN32G2IOFKXnUdX2CxEQQYJpu1SfqqymPOrg1SBo0W0eA1KXxV
         QMOXxxLTj9unDKieOqKyNDPIBytvGyyiRjnDBxpCPXWNnAJV+/MntVL39QqMWbQtsHH3
         h6yEYU0BtanxRVycYEqnCxvjZ33woIYxXloMdKlFBAjYSGKJrZjbg1hCYjmu6JP/0z1R
         Z3Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=gFtlJ2xh;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lp5qaBjkxw0icbORRHD6va1jT62YsOuRHmEi6lNhalc=;
        b=EHus9bB4idqYK2Ck47eNxFu995PYdofchBgR0NoTYMPHLZwl/0qZjIEFh9Y4KtjEEy
         +11ylVLwRhAtePRxXi10SwqLw5rMlJb7E1XEOB1V1v2R6aTsrRYnA4Z5Ckp8qFAUTuoC
         io8MYQJcO9zMUOdhcJxl8o0u0hvBAzMu3qOt9h1Kte15OUgbg+TSvnuxODgtGmolgPxU
         ChBKv/YpAcP2dkZgD4e3GpnTRDr+jeg95Mg4mzjqozU+4fqAq4WtOEVmCc6WtVMs53x4
         YhhmaPSuT1k9xiKrCyt0jT5Vhn/MhZGYxBAFaHQv9RKMEuE34N3ku8uWPMH6mhl2kbkg
         Maog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lp5qaBjkxw0icbORRHD6va1jT62YsOuRHmEi6lNhalc=;
        b=LN5zdfZ71vYdDlgQukaGS/j4Zt3NuGV4/OPbDVBTEdBV1OHn6lqvPtVJyy8c90uGoY
         8K7ROihZw3NzCmtUiPu+JWDy949OulqWwXWiwg71fPB5G35gu/iYOHnAtqB6/EHs6K+a
         6ZbbH4Csi9dfy6CBUU3cPW4dKjQlF0ThssJ7byG7bSYWwwjDdbyXKQpmEcu0NB2n9SP1
         Cc+PXxI/QDVj6RaoDPCQb/6DMUU6vSyW87c28UksclsLlU4kbzZKdGtMZaeRnjpCZgJv
         F1YZKEOeU3TfNBjoAjRnYK+YbQlCHkRkRE1rbc3iNcWCeLrxcpkItBd4Z8D/tG9nPZjo
         N1Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUc76b3ISYtBzWrpRhguCoSiIFFSfmkDqvMIghAkh1D1Z9CF8X5
	ufDitLk8aCX6gk3kTmymg7E=
X-Google-Smtp-Source: APXvYqx73p2RRHw+ilGLYd8KCIqZXb7WiQvGAMkg2YLX1nPA11cyXd1e/fCPMiBWxJ1G9TIz2QSxSw==
X-Received: by 2002:a17:906:27d5:: with SMTP id k21mr9748181ejc.328.1581489334342;
        Tue, 11 Feb 2020 22:35:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1b06:: with SMTP id by6ls8199567edb.1.gmail; Tue,
 11 Feb 2020 22:35:33 -0800 (PST)
X-Received: by 2002:aa7:ccc7:: with SMTP id y7mr9492997edt.45.1581489333831;
        Tue, 11 Feb 2020 22:35:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581489333; cv=none;
        d=google.com; s=arc-20160816;
        b=cDu2RTsGfEIiZ9qX948skB4AyzCQ3DaoPLqtF2L7fJwi00bpA5Lt1AmaJJostAv7pp
         F89LVS1NHju3Q58Wh677XLR7LU0g+t3KcuiTGlZJcSXNk0jSCcjRFNX8joB0FWM7d2E9
         RHvL7xLrJ3+w7VfFGru/6Jp7SMiWn0bOz+HBjIxFz0HFp78t07y4DMl5Kz2FMcFpWccv
         Kvzr96QSU0HLYWChF2hKws+m2NqNjhIPae10nRpjyd/6elTU7AN1bc9jsqFeMXRuz56+
         9DVh6F2pxuOoOS/g4AvPWI77NaT6rTZHodaSvTTFdWv/1L5ZyVFbcFKYU4WpF0V40yKa
         by/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=mlBXvnRSGUCMJcLvyWdPUsSnuUQABm7mYvYTkvnlvKQ=;
        b=ikgzvjs0Uff93ZwLSMVwRUXuaF9TnFRKFMGyGpCevT766gmkJU4YpJcuTlRhiYwlYb
         xrGjzNzKUcWdJatljaGamNAHdk2RBWToxDmxGhXiMQNGamST/nqPJmY44E5B2hTAdikJ
         xXb2SmnSCRrSokLpuoBaXxBdf5jZSCn3h0rNNFC7gVd7gDjGFigH3+46bxTD65XFKSSg
         ocn6wOgiBF+dgTSURAKTOTci+WEYuwCYFInip0P8qoCQCoqMkDNWN8nEfjOQvCJZog/n
         mhTI2rd9tBSU+owCTZMdIxXimNExpXUy0ijpA60CTrqERw9EW+hzMfuCBuDITrh/2rNY
         yEQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=gFtlJ2xh;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id n21si276212eja.0.2020.02.11.22.35.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Feb 2020 22:35:33 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 48HVJN3wSdz9v06n;
	Wed, 12 Feb 2020 07:35:32 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id PvBBu-t-JaUP; Wed, 12 Feb 2020 07:35:32 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 48HVJN2lyTz9v06f;
	Wed, 12 Feb 2020 07:35:32 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 37B568B7FF;
	Wed, 12 Feb 2020 07:35:33 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id mOVzraGcf1N3; Wed, 12 Feb 2020 07:35:33 +0100 (CET)
Received: from [172.25.230.102] (po15451.idsi0.si.c-s.fr [172.25.230.102])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0D1FD8B75B;
	Wed, 12 Feb 2020 07:35:33 +0100 (CET)
Subject: Re: [PATCH v6 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
References: <20200212054724.7708-1-dja@axtens.net>
 <20200212054724.7708-5-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <224745f3-db66-fe46-1459-d1d41867b4f3@c-s.fr>
Date: Wed, 12 Feb 2020 07:35:32 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.2
MIME-Version: 1.0
In-Reply-To: <20200212054724.7708-5-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=gFtlJ2xh;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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

Le 12/02/2020 =C3=A0 06:47, Daniel Axtens a =C3=A9crit=C2=A0:
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index fbff9ff9032e..2911fdd3a6a0 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -2,6 +2,8 @@
>   #ifndef __ASM_KASAN_H
>   #define __ASM_KASAN_H
>  =20
> +#include <asm/page.h>
> +
>   #ifdef CONFIG_KASAN
>   #define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
>   #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
> @@ -14,29 +16,41 @@
>  =20
>   #ifndef __ASSEMBLY__
>  =20
> -#include <asm/page.h>
> -
>   #define KASAN_SHADOW_SCALE_SHIFT	3
>  =20
>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>   				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>  =20
> +#ifdef CONFIG_KASAN_SHADOW_OFFSET
>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
> +#endif
>  =20
> +#ifdef CONFIG_PPC32
>   #define KASAN_SHADOW_END	0UL
>  =20
> -#define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
> +#ifdef CONFIG_KASAN
> +void kasan_late_init(void);
> +#else
> +static inline void kasan_late_init(void) { }
> +#endif
> +
> +#endif
> +
> +#ifdef CONFIG_PPC_BOOK3S_64
> +#define KASAN_SHADOW_END	(KASAN_SHADOW_OFFSET + \
> +				 (RADIX_VMEMMAP_END >> KASAN_SHADOW_SCALE_SHIFT))
> +
> +static inline void kasan_late_init(void) { }
> +#endif
>  =20
>   #ifdef CONFIG_KASAN
>   void kasan_early_init(void);
>   void kasan_mmu_init(void);
>   void kasan_init(void);
> -void kasan_late_init(void);
>   #else
>   static inline void kasan_init(void) { }
>   static inline void kasan_mmu_init(void) { }
> -static inline void kasan_late_init(void) { }
>   #endif

Why modify all this kasan_late_init() stuff ?

This function is only called from kasan init_32.c, it is never called by=20
PPC64, so you should not need to modify anything at all.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/224745f3-db66-fe46-1459-d1d41867b4f3%40c-s.fr.
