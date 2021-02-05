Return-Path: <kasan-dev+bncBCCJX7VWUANBBPMU62AAMGQEIV4QUDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AAED310F94
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 19:11:11 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id r24sf5653756pgv.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 10:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612548670; cv=pass;
        d=google.com; s=arc-20160816;
        b=uw+rQI4HM8jolym0Tjc/Os6uUa0NP4GAKApP7zKI6yYOfY0AVZVY0fmaY4IcLT5KrV
         eschkvIdqnktELW8xcJksY2SXWSNzrYYzCj5QtygMWvBBgkoXcGKnz15eB/u8gekCiFF
         riw4vq/f/7JvmiYLKK+XHmfz5NA1OZoczVNnNkkj9/F7CiiLosM4ASrDwuggckLft6yN
         rDNx+bRUrsZ6hu0J5gpT1lbNC1oLJxVYQ6O/YuPcPJexEiI9MRsXIrVQ+O9l560rik02
         5HAosh2I69czcZERYVAo6siK4kMlLub7mZjaBn+NzYvqZOpC83+Mb74KMmxB04SZHsLQ
         DHtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FICkJXcNN0S0vPqZ+dYnZdYIBgrFv/4705UtL17a9WM=;
        b=pixvph7EBDxPXZ/lyhsSdcM0NdA1Rhy24pvKK8sxsDytuEVsfXlR8L6USoOTOI41jz
         UJo66OR6doCyQolpue7VeM6qqy0TsT4Fywc1+HeSC8y514Ey9TASRigX5F/l1vsBe0Ah
         wZt8JPorYsG8SG7RpldKoVJsUASiUJUeGEIcpjO06bZQeUNpXRFAYcp4y/UKqY4JN5Ld
         /rS5+5e9zDBmKcE3H0YlDBInzvIYs6FLPzeCo06IbEwl/eCcbbsxBDfwMTQRGz4HgnDh
         JOEeZjOs1FWzHSFQvwHoTq/w9DPHulrKEXCx7JWdd4VKDRAKE89+vn/u9Q9upGdmtnIQ
         gcUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qknmJZd3;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FICkJXcNN0S0vPqZ+dYnZdYIBgrFv/4705UtL17a9WM=;
        b=lUX0ETQqklW12EImJEW+yG4IW9qHO0gxMlxKgRQKZTzySrorhW1orjOCiN3M98jcy0
         m2zLJCbD+CR5RrF7bCull/SquYj7ARUqr23jr1xwVmHPYx16TPTN+BZL0ZAV3lj+c1vR
         mbLhXV1aYeMJmiJHN2boYPqa8x5fTccBCTX1jkJQZvKXhfAxfNLn5cBlMjoxrFygFKfU
         uJgQpRxVY+Z3odWEPtoXIArpGMzXFgu0n+W5fuWpSTa1aaF+LZd3l3JUk+vDi3/ffaPt
         CagNwrl585nKUc54qtz6N+802hxjbJGBj2Alp3650GCmIOa/FhF23V4VMrBGIbmf+Tea
         9EbA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FICkJXcNN0S0vPqZ+dYnZdYIBgrFv/4705UtL17a9WM=;
        b=HDrDxeViZPthxWUn2MtGR0D8NwD68ef5dp67/UL3TAdglIhyZ+dc+G1BUvfbbu06t/
         VNOM3lAMWAejcWz2UA5f9VUX3b0+sOoTIW4z+MJ/xLUQMluH7l3AJpTy518turDQ1MRA
         PhJvSo+dIboMJhFs3Ux56hJR2TecGeCCYRUZZ6x/5lp2T3NeHDvQGFIYmSTL41dhaXlX
         Mjac1p4sfvDhniZEDQ189gZEimX7C4f6QlrktYUwGsx8xbtufWpl4CFgTXg3MH7D3Mch
         h0SI31+aC8eRhCjW/tpjdh4UWEKZc2jLmMgBdUB6KHyE/TmAI1cjNdX4bqW6/eLMdurR
         6LVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FICkJXcNN0S0vPqZ+dYnZdYIBgrFv/4705UtL17a9WM=;
        b=W9XYhNOPghKeJFYlU4f4FJGYSkD9wxTffZbebomx0rmmSndywYwh1vNKkKGcgeFfjS
         JWo0C1T+KEfeL12ADV9jmFkWRAF+CpFiKANyZe5KHbqCdl1VdGjd5or6aLm5XwXTIjMC
         WIZP+5/GOEPl1FG1L2IHzR/YQCRELk7V/VKK9nYmpWWZiic+Jtn6NJvQ9Mx7qHW6xyWi
         Xe5uknzydJrjSqHd01GHbZkLd9GMG7WIiLHZDsFbZiLBeaAg/q5azQ9354oAGL8lX9zg
         Eva0NSsYZLLWX/1E1qlB1jwYYmIi+zSbwk2UJcsUb58A5m40NYNHuFlIa0U3CLTRIUZG
         5F5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532t3qB2oA+usiGUifMlC0B7jMesW6PMmZmOPsMMhmaPIGlu/zb5
	yLVsNo+5PG2qEGtiwYuZkxI=
X-Google-Smtp-Source: ABdhPJxD50W9+r21HmT4o2PqaugHdbAMRSl2hoR/DO0yJECIqaP3rXRndcLzDJOPsQD/p5SB1YjnEQ==
X-Received: by 2002:a05:6a00:88b:b029:19c:780e:1cd with SMTP id q11-20020a056a00088bb029019c780e01cdmr5756178pfj.64.1612548669907;
        Fri, 05 Feb 2021 10:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:92d5:: with SMTP id o204ls4076509pfd.6.gmail; Fri, 05
 Feb 2021 10:11:09 -0800 (PST)
X-Received: by 2002:a63:480f:: with SMTP id v15mr5537415pga.341.1612548669329;
        Fri, 05 Feb 2021 10:11:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612548669; cv=none;
        d=google.com; s=arc-20160816;
        b=XO5O6NyM1OX8qnvOKudJSumbrUf8clfLzLKOOI/qdMJaixBxY97KFBzLScrypVfQBZ
         xKh9JKejP7hhR9G4SO6CIuHpiIf1SKrIWVXWryjiTKbkwiEAH37/gwT3MJJvoFfpiUcx
         mBYyOsUby+HbXzdmi93RvyARa1V7AHzwnhMIFZDRa0XSHhGYhh+L2b04Hqrm3LwvWWIs
         tezFXmrTUwu+AZ277RchYAHQD2RwUigle/lL2vr5ElD7WhpUwJEaS5zD27+f3gxq7pPU
         FFiGtrOsRlMxck83GK+VdipGEG3N8tHUxISrTbPgM2PKZzsPvTCeld/4d+/0gle3lWZQ
         kYtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=F4x29TTVEpw+IQOs4pBG2aQj/4xmoAAS+aT8UOnwOmY=;
        b=Q8EZtbJcDXDDf0TygM/iQ7Gikt9BZBNDj93vpWkGUH1q3HiDTDTrWH+SW+Ff//gS/8
         QhCmZRlqJBSepc5ils2qvYglyq/8GyLN6oIrpOoqdxSb6o0t5+XU59dYoLzom+fnjy0v
         iwaoVdYmFfSSSjPRrnNtEtJm0jyJfB010scDQcITzJqktA3c0pgC8fFjASfQJ3TNwOKv
         oDcRNJWC3as7AvDK2dS054vqlFrZNpah2kV6Z3TTQRvx9vesGMbLM9bukxNwg+3+kUrw
         KQVaSNa0+JBo4c0eXpEE4nK/imE3XHaUgw51ik8kM6xbYD77jQyOsXJ934Ldiw3hZR6M
         E1Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qknmJZd3;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa34.google.com (mail-vk1-xa34.google.com. [2607:f8b0:4864:20::a34])
        by gmr-mx.google.com with ESMTPS id w2si491597ply.1.2021.02.05.10.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 10:11:09 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::a34 as permitted sender) client-ip=2607:f8b0:4864:20::a34;
Received: by mail-vk1-xa34.google.com with SMTP id n63so1665368vkn.12
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 10:11:09 -0800 (PST)
X-Received: by 2002:a1f:9c57:: with SMTP id f84mr4084825vke.2.1612548668509;
 Fri, 05 Feb 2021 10:11:08 -0800 (PST)
MIME-Version: 1.0
References: <20210204150100.GE20815@willie-the-truck> <20210204163721.91295-1-lecopzer@gmail.com>
 <20210205171859.GE22665@willie-the-truck>
In-Reply-To: <20210205171859.GE22665@willie-the-truck>
From: Lecopzer Chen <lecopzer@gmail.com>
Date: Sat, 6 Feb 2021 02:10:56 +0800
Message-ID: <CANr2M1_9Y9s1jYXOYJDxTtZbnxyc4Xwb2Ask+nZ_eSaZCnCd7A@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
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
 header.i=@gmail.com header.s=20161025 header.b=qknmJZd3;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::a34
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

Will Deacon <will@kernel.org> =E6=96=BC 2021=E5=B9=B42=E6=9C=886=E6=97=A5 =
=E9=80=B1=E5=85=AD =E4=B8=8A=E5=8D=881:19=E5=AF=AB=E9=81=93=EF=BC=9A
>
> On Fri, Feb 05, 2021 at 12:37:21AM +0800, Lecopzer Chen wrote:
> >
> > > On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > > > > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > > > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > > > ("kasan: support backing vmalloc space with real shadow memory"=
)
> > > > > >
> > > > > > Like how the MODULES_VADDR does now, just not to early populate
> > > > > > the VMALLOC_START between VMALLOC_END.
> > > > > > similarly, the kernel code mapping is now in the VMALLOC area a=
nd
> > > > > > should keep these area populated.
> > > > > >
> > > > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > > > ---
> > > > > >  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > > > > >  1 file changed, 18 insertions(+), 5 deletions(-)
> > > > > >
> > > > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_i=
nit.c
> > > > > > index d8e66c78440e..39b218a64279 100644
> > > > > > --- a/arch/arm64/mm/kasan_init.c
> > > > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > > > > >  {
> > > > > >   u64 kimg_shadow_start, kimg_shadow_end;
> > > > > >   u64 mod_shadow_start, mod_shadow_end;
> > > > > > + u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > > > > >   phys_addr_t pa_start, pa_end;
> > > > > >   u64 i;
> > > > > >
> > > > > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > > > > >   mod_shadow_start =3D (u64)kasan_mem_to_shadow((void *)MODULES=
_VADDR);
> > > > > >   mod_shadow_end =3D (u64)kasan_mem_to_shadow((void *)MODULES_E=
ND);
> > > > > >
> > > > > > + vmalloc_shadow_start =3D (u64)kasan_mem_to_shadow((void *)VMA=
LLOC_START);
> > > > > > + vmalloc_shadow_end =3D (u64)kasan_mem_to_shadow((void *)VMALL=
OC_END);
> > > > > > +
> > > > > >   /*
> > > > > >    * We are going to perform proper setup of shadow memory.
> > > > > >    * At first we should unmap early shadow (clear_pgds() call b=
elow).
> > > > > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void=
)
> > > > > >
> > > > > >   kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_=
END),
> > > > > >                              (void *)mod_shadow_start);
> > > > > > - kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > > > > -                            (void *)KASAN_SHADOW_END);
> > > > > > + if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > > > >
> > > > > Do we really need yet another CONFIG option for KASAN? What's the=
 use-case
> > > > > for *not* enabling this if you're already enabling one of the KAS=
AN
> > > > > backends?
> > > >commit message
> > > > As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> > > > KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vm=
alloc va).
> > >
> > > The shadow is allocated dynamically though, isn't it?
> >
> > Yes, but It's still a cost.
> >
> > > > There should be someone can enable KASAN_GENERIC but can't use VMAL=
LOC
> > > > due to memory issue.
> > >
> > > That doesn't sound particularly realistic to me. The reason I'm pushi=
ng here
> > > is because I would _really_ like to move to VMAP stack unconditionall=
y, and
> > > that would effectively force KASAN_VMALLOC to be set if KASAN is in u=
se.
> > >
> > > So unless there's a really good reason not to do that, please can we =
make
> > > this unconditional for arm64? Pretty please?
> >
> > I think it's fine since we have a good reason.
> > Also if someone have memory issue in KASAN_VMALLOC,
> > they can use SW_TAG, right?
> >
> > However the SW_TAG/HW_TAG is not supported VMALLOC yet.
> > So the code would be like
> >
> >       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>
> Just make this CONFIG_KASAN_VMALLOC, since that depends on KASAN_GENERIC.

OK, this also make sense.
My first thought was that selecting KASAN_GENERIC implies VMALLOC in
arm64 is a special case so this need well documented.
I'll document this in the commit message of Kconfig patch to avoid
messing up the code here.

I'm going to send V3 patch, thanks again for your review.

BRs,
Lecopzer

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANr2M1_9Y9s1jYXOYJDxTtZbnxyc4Xwb2Ask%2BnZ_eSaZCnCd7A%40mail.gmai=
l.com.
