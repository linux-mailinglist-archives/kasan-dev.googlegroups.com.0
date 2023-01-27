Return-Path: <kasan-dev+bncBDM6JJGWWMLRBEW3Z6PAMGQEBSGIWZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 54B9A67E971
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 16:28:19 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id q11-20020a05651c054b00b0028d095d72c0sf1437146ljp.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 07:28:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674833298; cv=pass;
        d=google.com; s=arc-20160816;
        b=QN2D6FVPUjcw5W8YHZsNr7oiXOTtfXzQcF+y8n0i7GSz3FcppbfuQpGelM+0EDhFOi
         20Q2O09Zbmvz6nwfhKfiZf5OS3n7OxwjZ6+skpap6SC7xmhKdRgOj/hNNEEAgWXHQdjC
         9rqfWF8bD9063n1bhMTrHSuTppAwXjy2QgtHp/wdihWHKlB0ntjYvhl7NrXYTsO/6JJI
         Ot5+B+tVinaUJJ5Y2Kg+MC/kWpAuitAINAale6vXbz4dZb/KHl+xgQCpmZc6F1cTJLyV
         da1jqpDvMZj1NW8vRCKPSbC/XbHZt4yGRt+tsg8+eOG6tnE64CnRHiZb79kHhhc9NHAL
         GKAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+53++LUwaoBCU4Acmujtf5UOOzK3xcIYQiLrA05B8wg=;
        b=Vt5PEhnLqWqgF0wn7uq6zY/FyTKAqMcIq8KpxplLAyeQCbQTyeoqHAgOcMk1b3f40u
         4QU1oHDlec9JIBnEvz6NKa5W4RzWGB0+dQxpQnIGFQAuvqJqkXB8yj/meWFTLTShzLql
         5K95nL3Bu+yFP8BDjnOyD2amETSCEJCcJsPUIPHXRcvoUlxMw5Naq9styPHmhnr7NmG1
         FSt0S4PsGx7FvyIDpkQ7ws8/62th1ChUIWpNBkALocbyp9KWla0SfmiJDDUDZ/wqLVI7
         W/YymrzR7n/s2DriNC7LGkexskKV/v/IuRI40p24sP422s1/r/MjE3cf8mj5bruzmh5p
         /vyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@microchip.com header.s=mchp header.b="nHG/YoUu";
       spf=pass (google.com: domain of conor.dooley@microchip.com designates 68.232.154.123 as permitted sender) smtp.mailfrom=Conor.Dooley@microchip.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=microchip.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=+53++LUwaoBCU4Acmujtf5UOOzK3xcIYQiLrA05B8wg=;
        b=juGnJbrQl1Sq578U0ZQH/LsZx15K1gFzj1LjkLJlbQUTw6ax87qdE4/e3wQ797xA3A
         m/ZI/kW565zydRV9vbcuULhY4PnbkuB0fHEHSx/YUE9EmtfFCY0Qz5QeC1Z7eEZq7oec
         ThfOcq/P6xwtmU4s2an3TaD1DfvDB3QBdVM3mluyALfD8/G2aLaIxHtvQXaK+ZiO/4+F
         OCSne/H8RQSGPNv0qYeJF4c9HghhqLLBNmeIlZR5ircxlQkeZVSHiArJA7u7V83HT0xo
         yjwJ+gAhxO9cYuDTKIKZxo9QSMAuLZ3F5Kqb7UIBURUTjYBRqPObt1bifgPMu/R6X1Ib
         tJsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+53++LUwaoBCU4Acmujtf5UOOzK3xcIYQiLrA05B8wg=;
        b=LgB7efKqRu3YfgClGc1SgazGDy89BfremSoWMYsguuC6jpfQD8eLXNkBXBfJjaARA9
         TY6rxbzCP7oXXyIvYVblCto2ptsM/D9Puk0rDqWTFvhiJG098oz2BiqFmqSYx1CBzl5W
         sJKXE3Zy1FAwoMFSoGMBKKoOH95ilBf1J9L+pr33CHYcjiR/93a0N6TRnyyhF/K1IJ3Q
         li8CESObVWvgBjSNIVyOSzWTZMtIN3Yuo/+1R4Qgn1rLD5z84PSyD2AUYX1kPRvdQo2s
         Nm1h9KPvO57ZfdPeodOPhPCFeEV+Nv0w5inwoJG/f3ZX9t1DZyIyv8YCRNAoJMQy48pF
         CadQ==
X-Gm-Message-State: AO0yUKUHJsOhEXW4vAz7D0rFYJhuyX9OS50lbA5YGD7aztSW1ERnPRhi
	C0cPEyXAQRXouJfi1sMMVOU=
X-Google-Smtp-Source: AK7set9YYBgfMVvU+gxCN6rZOuB0+8x226aaJO9HNVjiLdrmYtK/GXG+PwgN5P8vK255LMDfm7F6Xw==
X-Received: by 2002:a2e:7d13:0:b0:28d:d748:8b7e with SMTP id y19-20020a2e7d13000000b0028dd7488b7emr650745ljc.129.1674833298459;
        Fri, 27 Jan 2023 07:28:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4f13:0:b0:4d5:7ca1:c92f with SMTP id k19-20020ac24f13000000b004d57ca1c92fls199914lfr.2.-pod-prod-gmail;
 Fri, 27 Jan 2023 07:28:16 -0800 (PST)
X-Received: by 2002:a05:6512:2821:b0:4cc:58b9:117a with SMTP id cf33-20020a056512282100b004cc58b9117amr17493130lfb.36.1674833296303;
        Fri, 27 Jan 2023 07:28:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674833296; cv=none;
        d=google.com; s=arc-20160816;
        b=QG/tadyGM1ajXL25XgOjGjDc8H0MOf1XKSshnPW8dg+gHO8sZhdu9p15Qy1NaFW+PI
         LJ8I28vKab/ZdLkojjlB4YExpT1V1TR43omGseS914V2OG+yj7UgaeQlppisweZ79Jyv
         8c2MI2wI5zmesQxZTC7O/JR8bC9CWJd+O6r/Prb/cLqiDJ/w+YSyR7lYfCjX5+HPwFIh
         umdfaDcsjHaKPjKEP/6qW8xXwiS/Rb8OyBy2/UF0owAbbcB7AwsoFoOsqD3rs466g9Og
         FHyeq6iQ6CAVGfCLdCbVnTC4306JYyvBCD7vEDVBTqxJ7Hs58ID3YFtP7LcJbEKVyd56
         esBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1CF+go139JBlcObPr93EZ7VhBghRAe58pqDLOeytHS4=;
        b=Yu0oabos8e0MC+V87fVGTt9NCpYLvXB3gB1vYTA4O1PCkshd/138pYSNWQV81sDR4+
         Xci2uqMFwkG8oI9lFUR5S3b3f4umxPIvGgAecPC8E+FWkuLsro5DFUWDQb4qa6ygYq0C
         gtnVV8m/5a8WbklR9yUePOm5u6jEboIsQ+10hf8W1O3sHR0Qd4ZBGGgB7jZmwISS/ChQ
         tSZ9X4Uu74MuPojQK5lonq62aTAc34zF2UYfDogVuwFq6yu3Ss0+rsjdK6esVIOeCM31
         IrkD/4AfuUiEZex2+EbmRCrsvgYBEsf9kmbzQSX2yhzcKuphdEg9jhBc/djke/v9eE/S
         gc5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@microchip.com header.s=mchp header.b="nHG/YoUu";
       spf=pass (google.com: domain of conor.dooley@microchip.com designates 68.232.154.123 as permitted sender) smtp.mailfrom=Conor.Dooley@microchip.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=microchip.com
Received: from esa.microchip.iphmx.com (esa.microchip.iphmx.com. [68.232.154.123])
        by gmr-mx.google.com with ESMTPS id h6-20020ac25966000000b004d5786b729esi289494lfp.9.2023.01.27.07.28.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 Jan 2023 07:28:14 -0800 (PST)
Received-SPF: pass (google.com: domain of conor.dooley@microchip.com designates 68.232.154.123 as permitted sender) client-ip=68.232.154.123;
X-IronPort-AV: E=Sophos;i="5.97,251,1669100400"; 
   d="asc'?scan'208";a="197710525"
Received: from unknown (HELO email.microchip.com) ([170.129.1.10])
  by esa2.microchip.iphmx.com with ESMTP/TLS/AES256-SHA256; 27 Jan 2023 08:28:11 -0700
Received: from chn-vm-ex01.mchp-main.com (10.10.85.143) by
 chn-vm-ex04.mchp-main.com (10.10.85.152) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16; Fri, 27 Jan 2023 08:28:06 -0700
Received: from wendy (10.10.115.15) by chn-vm-ex01.mchp-main.com
 (10.10.85.143) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.16 via Frontend
 Transport; Fri, 27 Jan 2023 08:28:04 -0700
Date: Fri, 27 Jan 2023 15:27:40 +0000
From: "'Conor Dooley' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel
	<ardb@kernel.org>, Conor Dooley <conor@kernel.org>,
	<linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-efi@vger.kernel.org>
Subject: Re: [PATCH v3 3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel
 address space
Message-ID: <Y9PtbMSe9DUk3bCn@wendy>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
 <20230125082333.1577572-4-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="Z01ixQvrSdrQQAm3"
Content-Disposition: inline
In-Reply-To: <20230125082333.1577572-4-alexghiti@rivosinc.com>
X-Original-Sender: conor.dooley@microchip.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@microchip.com header.s=mchp header.b="nHG/YoUu";       spf=pass
 (google.com: domain of conor.dooley@microchip.com designates 68.232.154.123
 as permitted sender) smtp.mailfrom=Conor.Dooley@microchip.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=microchip.com
X-Original-From: Conor Dooley <conor.dooley@microchip.com>
Reply-To: Conor Dooley <conor.dooley@microchip.com>
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

--Z01ixQvrSdrQQAm3
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hey Alex,

On Wed, Jan 25, 2023 at 09:23:30AM +0100, Alexandre Ghiti wrote:
> The early virtual address should lie in the kernel address space for
> inline kasan instrumentation to succeed, otherwise kasan tries to
> dereference an address that does not exist in the address space (since
> kasan only maps *kernel* address space, not the userspace).
> 
> Simply use the very first address of the kernel address space for the
> early fdt mapping.
> 
> It allowed an Ubuntu kernel to boot successfully with inline
> instrumentation.
> 
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Been poking around in this area the last few days trying to hunt down
some bugs... Things look functionally the same w/ this patch and we do
get rid of the odd looking pointer which is nice.
Reviewed-by: Conor Dooley <conor.dooley@microchip.com>

Probably would've made the cause of 50e63dd8ed92 ("riscv: fix reserved
memory setup") more difficult to find so glad I got that out of the way
well before this patch!

Thanks,
Conor.

> ---
>  arch/riscv/mm/init.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 478d6763a01a..87f6a5d475a6 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -57,7 +57,7 @@ unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
>  EXPORT_SYMBOL(empty_zero_page);
>  
>  extern char _start[];
> -#define DTB_EARLY_BASE_VA      PGDIR_SIZE
> +#define DTB_EARLY_BASE_VA      (ADDRESS_SPACE_END - (PTRS_PER_PGD / 2 * PGDIR_SIZE) + 1)
>  void *_dtb_early_va __initdata;
>  uintptr_t _dtb_early_pa __initdata;
>  
> -- 
> 2.37.2
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9PtbMSe9DUk3bCn%40wendy.

--Z01ixQvrSdrQQAm3
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHQEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCY9PtbAAKCRB4tDGHoIJi
0u7KAPY1hCi3Va5fAfv37uYg8QCBL7X4ZCQl3ls8gDg6rGp9AQDsdy5FKbSVrpX1
z1qeXbmq0/jC3ZakOc10BTCtvty7Dw==
=w080
-----END PGP SIGNATURE-----

--Z01ixQvrSdrQQAm3--
