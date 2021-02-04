Return-Path: <kasan-dev+bncBCCJX7VWUANBB7VW6CAAMGQE6Y3RFAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F060530F72A
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 17:06:23 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id a9sf3445307ilm.11
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 08:06:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612454783; cv=pass;
        d=google.com; s=arc-20160816;
        b=FJ02ubYjsm2GZ5+F9GwP6QyD+AXKcyoWnECp0vkVtJKV7Cy68LTeDYTQSvisfH0dRM
         rK23XiozxlZ5TjOTTq2qFKtIB9rze+FwcCdsGlFT1+klaaxyPU1vVo3fBNHEnTY7wmpj
         Mf8LwSR3EHNM3WZMJATR/mUV49+I2wK8SZnYwtr7MfIf+3BQRwyPKDJD4A2aodnH4r43
         jee7NAQFj+aWX90Qbsl9HoAoX6dTjzEagel6DcWSh6Fnh6AggjODQyJmL6xb3iramPVT
         a+9Len1m3xbCTHAbRSrHKAdN7Aj5vdOqN/Lo73vCAP8F6338upSBO85T3QcIsElf+Kww
         EYhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9omAKO1BoruslxnBg96iNLYuDR5vNpb8if0Z4FGTG9w=;
        b=za6228GAy2sPZ9eAwjDiAaVxSHaBujYm9TSlsGQ1owNdWlOGy/IGZlBT4mBxz5L/wO
         t5gboNjs2kW1bAKuk53/NadGqcbqKCfmrmANUFvm2mg3qEQkShowgOKc2NxO2hvz7rGg
         b02lu4E3P59tGpBSi0b7A1Mn5w2LGGhnYA36o6PY+xN3oEIVsxlcjtPlvKkXolmxyii6
         VIhwmGCszhv+1HOtsBfsK0L4u//GO80ZcLU20VfPcPOtZC/zQeuGe8MEQwvQxyoDZ2lN
         9wy/VqYHTEOjZR8krUOLx1inwQpRk5L0jP+4ssBqNJvCapCXt9blaFZk13NfUBmh2B5j
         MU4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JgOhI2CE;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9omAKO1BoruslxnBg96iNLYuDR5vNpb8if0Z4FGTG9w=;
        b=jJZE5/CXcoJnQTNRVckw3rDP6+KJJcf+KeRJt5hTGaviJD17N/il0hIeARz404lND9
         /SoihXel8HdorP/ros2sb75XAC3kX/8t7pVGgV4r7TPMIVyMABKQyW1cq9lWykeb2g23
         8NnImLX9TxN9Fadr+uPbbMfpbZM+u4zaCLiC/BThK6FjYjZd98nzoYtcoSHKEBJ7wiNZ
         E2ZnlGiTJjGyUay8LlNFe++hdcrRmhHnzTpjaAGDdHJ1tFX+DVbsfSQfbzkG65S499ub
         TtKKua1DdveNWs3fSvBtbP3I4KCDG7s2vXcvTkLpwCSybnUQMvG1xAS2S0AEZKgbsU9C
         yNRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9omAKO1BoruslxnBg96iNLYuDR5vNpb8if0Z4FGTG9w=;
        b=nTWHN9DdaZJ8NY28uFPZKZsauv9HiE/yrrnIGQoMV+wPaEezIGFYmVzwx7adfJAmO7
         VaitILpci/L3X+0dkCQDCLPmWAX9/kXzqE7DEp3hzbxZ6ac00lPXLNPKbq+JDuudAbMW
         nnN+MgRo3TkkX5fjibfZCALY33N5msW+yP907HnGCFeO8ZNhd8H1LYr2QcYJkGM3G1bz
         7oBuMjOMEYnbMgdoe9KDTvn5d/BO1FJ03vYx6Y8/LQrktoNtiQ+j/bRsllxatRh/akk9
         ZuX4uZ+Y2ZeggrDEvg0DJRKNDT3rwO/Bxt/YGNO3xhT+SKxb7YabqFppjcdDc802PZm4
         Y7Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9omAKO1BoruslxnBg96iNLYuDR5vNpb8if0Z4FGTG9w=;
        b=NFApNgmm5xV+xQwMZ+8e6UMbvydGc8QsxKwo/pbNX0IdxziJjr4ogcOxNy25mFe8Ll
         QPtk3OOXZKWnplD3n+EF6zse2ClTYQxK8JXIhjNaiVEbXLMjpQi3iAnsExKZ/DGsbGD6
         75SLERowdOiLchzMhErbyI7uBdnEp8SYAkPTJSI+vVdUbnLnq42vJb+Eu0y7/fdvfln1
         p/x9OEA5RC5QMVQvbJE4YUsIh9Gn+BgWqHO95GjdPuinY/mLbg8Oscn5lGJTX4dGu344
         zjV7l7Sdf+7nDtyEs9bJZguxAkL5qKhR3FFF/RrZ37P4vncueXGqAJa8MEs45q50vY84
         F9uQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dwIoXwvRbCzQfDP2gyqR2AVsFZQoX4L024v9Fp8bEJ3c5O0Ed
	Q876yhrrpCnZmZWvM4IWiTw=
X-Google-Smtp-Source: ABdhPJy91rzyJUFB8NrkRwX91toR2nKOF28MJaR6rDIjnnWsITmULHzkQlBcpBLYjMjeQd1PQN5/BQ==
X-Received: by 2002:a92:8e42:: with SMTP id k2mr7992222ilh.250.1612454782644;
        Thu, 04 Feb 2021 08:06:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:8216:: with SMTP id l22ls982229iom.9.gmail; Thu, 04 Feb
 2021 08:06:22 -0800 (PST)
X-Received: by 2002:a6b:bb85:: with SMTP id l127mr37578iof.116.1612454782184;
        Thu, 04 Feb 2021 08:06:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612454782; cv=none;
        d=google.com; s=arc-20160816;
        b=0ZsUkKzmufQT1kt2H8K71+E1/16TekoTD2lPaa4+ett6qbFgqLCgygxF0z4hSW+znr
         uNuczLjhaYNADeZQIMyBZYK7Lgp9LJmeqw7Wk4+kaSG1mZOkK85BK757d6K+vOeGxB70
         Yxrd6qUWqQ/z1LgOScbDJdrrNnVN1tC4sTc62dNZI34Sa/RlSlIP9hPMmnqhNL4iPrwO
         nsNbWceFESou3AvWXl8OYalZVQhS2vpSITK2VabH6YQOU7oWx04stwtsERD+Q6kyHeeu
         P2ljqvLJ4ABQfCObNPjsKIBKPHJsbiJQzPkE2HcpnOEMsKzFqIbunIyp8tZa1nL3d0VM
         ZnTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W/NQRUXI9589A4ZazyD5B/LtPSn045ZMqU/tdzMr9Nk=;
        b=gGrE/vAV72YwaWKEKQVCTpsb8dtHGYm5iw2SdMaKeqDGDswJgPg0N2Ytw+623wyD7c
         NjO/gHs5ILXgCLTVuU3koNnE1Y/VelyAJtmq9B3yy0cNRsPTZc5QffhT/ju40mB1y0lm
         HD0OYsroiLZordG7UiE9u1kal1+3zQgwMdT2btbBDdS96ATpjFWokDfvwqi2bHxRqvQ6
         EpEorFL/QtZ6OAvf4OI3DcuQE5AdmaeBOTj2VMP67a6hpmfv1+tYBkpIbTnVOxdnwgQp
         qrDt1m9AJsKXfuifkuqqfn2TbwF39SQ8V5FnsfTyiI/p2xkwMFCCcqS4ydNYUNST/m/8
         l5PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JgOhI2CE;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id o7si248326ilu.0.2021.02.04.08.06.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 08:06:22 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id r38so2390582pgk.13
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 08:06:22 -0800 (PST)
X-Received: by 2002:a63:5c0a:: with SMTP id q10mr9681668pgb.277.1612454781557;
 Thu, 04 Feb 2021 08:06:21 -0800 (PST)
MIME-Version: 1.0
References: <20210204124658.GB20468@willie-the-truck> <20210204145127.75856-1-lecopzer@gmail.com>
 <20210204145547.GD20815@willie-the-truck>
In-Reply-To: <20210204145547.GD20815@willie-the-truck>
From: Lecopzer Chen <lecopzer@gmail.com>
Date: Fri, 5 Feb 2021 00:06:10 +0800
Message-ID: <CANr2M1-=ONun5fLNoODftmfcuWw49hj9yXsrxkqrfCEtELX1hw@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] arm64: kasan: abstract _text and _end to KERNEL_START/END
To: Will Deacon <will@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, ardb@kernel.org, 
	aryabinin@virtuozzo.com, broonie@kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, dan.j.williams@intel.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, gustavoars@kernel.org, 
	kasan-dev@googlegroups.com, Jian-Lin Chen <lecopzer.chen@mediatek.com>, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mediatek@lists.infradead.org, 
	linux-mm@kvack.org, linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org, 
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com, 
	yj.chiang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=JgOhI2CE;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

I think it would be better to leave this for you since I'm not
familiar with the relationship
between vmemmap() and NUMA_NO_NODE.

So I would just keep this patch in next version, is this fine with you?


Thanks for your help:)

Lecopzer



Will Deacon <will@kernel.org> =E6=96=BC 2021=E5=B9=B42=E6=9C=884=E6=97=A5 =
=E9=80=B1=E5=9B=9B =E4=B8=8B=E5=8D=8810:55=E5=AF=AB=E9=81=93=EF=BC=9A
>
> On Thu, Feb 04, 2021 at 10:51:27PM +0800, Lecopzer Chen wrote:
> > > On Sat, Jan 09, 2021 at 06:32:50PM +0800, Lecopzer Chen wrote:
> > > > Arm64 provide defined macro for KERNEL_START and KERNEL_END,
> > > > thus replace them by the abstration instead of using _text and _end=
.
> > > >
> > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > ---
> > > >  arch/arm64/mm/kasan_init.c | 6 +++---
> > > >  1 file changed, 3 insertions(+), 3 deletions(-)
> > > >
> > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.=
c
> > > > index 39b218a64279..fa8d7ece895d 100644
> > > > --- a/arch/arm64/mm/kasan_init.c
> > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > @@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
> > > >   phys_addr_t pa_start, pa_end;
> > > >   u64 i;
> > > >
> > > > - kimg_shadow_start =3D (u64)kasan_mem_to_shadow(_text) & PAGE_MASK=
;
> > > > - kimg_shadow_end =3D PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
> > > > + kimg_shadow_start =3D (u64)kasan_mem_to_shadow(KERNEL_START) & PA=
GE_MASK;
> > > > + kimg_shadow_end =3D PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_EN=
D));
> > > >
> > > >   mod_shadow_start =3D (u64)kasan_mem_to_shadow((void *)MODULES_VAD=
DR);
> > > >   mod_shadow_end =3D (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > > > @@ -241,7 +241,7 @@ static void __init kasan_init_shadow(void)
> > > >   clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> > > >
> > > >   kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
> > > > -                    early_pfn_to_nid(virt_to_pfn(lm_alias(_text)))=
);
> > > > +                    early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_S=
TART))));
> > >
> > > To be honest, I think this whole line is pointless. We should be able=
 to
> > > pass NUMA_NO_NODE now that we're not abusing the vmemmap() allocator =
to
> > > populate the shadow.
> >
> > Do we need to fix this in this series? it seems another topic.
> > If not, should this patch be removed in this series?
>
> Since you're reposting anyway, you may as well include a patch doing that=
.
> If you don't, then I will.
>
> Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANr2M1-%3DONun5fLNoODftmfcuWw49hj9yXsrxkqrfCEtELX1hw%40mail.gmai=
l.com.
