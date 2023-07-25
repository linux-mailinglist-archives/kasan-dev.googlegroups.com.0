Return-Path: <kasan-dev+bncBAABBGG47SSQMGQEMPP646Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1027576050A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 04:06:18 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5676ac40f63sf8897275eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 19:06:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690250776; cv=pass;
        d=google.com; s=arc-20160816;
        b=zBTir2fCe4FYI8ei77pHQvf3i19k7axS3qg1cijBoe5aEuMyCrfq3CaNDzN6q5wNT7
         Fg9EX+V7UhAT5X7PRFQE8776UnHglcmELYuUwX45SOiNc1qcqLGVzSKDlfgWOZH9fECl
         ptSEWQiAgktdRDNWGhbVSlLvmHBepbjlwvoZjGc8IPrxsXDspdDewWeAGusTqeYfCtxw
         EArT0ZHc2LSXXV0ur1rBOMZTWWlwWMaackxEKMBuL6p6REJeaQUgGGsIWTHt/7LAS1Gx
         6YZgqKvLpeaXXWgqO/O6FiObrNE8qvMezNAewUtXCvKMhyAkK2zf2znfHZwNB/wTg2v4
         JEvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=50bYKoQT6Nb8I5H48uq7c4MUs9fHkkdUo0Ekpvi90EA=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=WTlt7k6lbC6XSGDhzLW/64DXHMbOfCbQzcOGGzroVDK7nLapDAmhbsQsAGK+QbefZG
         DTJLkXjpFXmzNroWmm8UHcrOPi2w+3dYG5RywQUGDT39qc139fwbwoGmkPEAu0md6YcC
         C2eqw3mevm9OnNmnkwSdY3L1XzzKWkzo5IFwpZYIWKkoS52JUwxJFFXT5HwIeMXK77IZ
         CcVnJmDjruOVolU838+5U+CV8rbHHwmM5iEL6GJ6Cfmk1fRED0pza4oR9b/nFGXBsHnF
         C/d4yQxORxxSgv5//O9VEKjFvhQs0qk/6kgcH4xF2jdC0W4CL2RHBMwN09tpu/fMihvG
         hm7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DsRSOBxt;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690250776; x=1690855576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=50bYKoQT6Nb8I5H48uq7c4MUs9fHkkdUo0Ekpvi90EA=;
        b=a9fvkqOZhscRpJ43x41qjctP8XImldbeznwyycYqlxLMB3FGTaLBIsMb9Gpm2WoJLx
         AMf10Hac2NyrEQZ8OrI4ePvGOg2yTFk5dCMM2RtP5rdtQTWXOUh5gjspr9CgGv1cQc8d
         IYLYMxD2hzJyp5dyh9slBj+8QW8ltKw8V0UP49nxm72VWSLlSmNYXfRcOxIWbZybpthe
         s8sxEN3Ql+iAnoM2ptGCqj304RJSuWUEgj3x9vwV2saZU+Mqu/DZ7Jvpjf7w/Qh4KQ+9
         TuGju6bdMSApovLb2EYYA4eFU4Ys6jMW4iPHNZWOX8jODuD9wfL5lpeolJiqlC6RKbPj
         C4HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690250776; x=1690855576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=50bYKoQT6Nb8I5H48uq7c4MUs9fHkkdUo0Ekpvi90EA=;
        b=huQRLMuPBn2eUn5ONXE26Q7EOzZ/rUfuTp4Pk4pEQK+97wDPtSoKYdZ+NQCDQw99uG
         mW5ba7e9axbxuvICOceMlbJjX5rRcnkYri5gV6z2qYJ7jU3uSrBqAvw0qLZBEG+kdFIq
         FCkMdwssUzXtuqvISEkOhdJw+Hy9WBqnusH3md/CskI7ddGJZjGZPi56ZPBCdE0xJhOq
         +cwpojd/5hDoXklN4tUHh7fkhxcjokDQoXf1fUgSr872mzgcPQWO55nOD9+o1krHndFT
         tjRNMmUzNe4ETV9Z/YwhHtYDzvGsC1Jen+AfQ3ACiOvH7YSus/Xf1+H/3io0EprAsWa/
         z7kA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaAGFWYt8t/4Rnw0iW3hfVL93UY6waIO/bvdbEu9wLQtQb2pM70
	fr6zQHtEx4GdkoZfOKv0MDA=
X-Google-Smtp-Source: APBJJlFJySvOXyCb636VV3cUD5s1b4nTXePTRcUuRju9ELN/AwG9P1VE2jWFT1QP7m69xV+WmBd5Sw==
X-Received: by 2002:a05:6871:29b:b0:1bb:3b94:c651 with SMTP id i27-20020a056871029b00b001bb3b94c651mr7480171oae.41.1690250776462;
        Mon, 24 Jul 2023 19:06:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f619:b0:1bb:933b:e6ae with SMTP id
 ek25-20020a056870f61900b001bb933be6aels430593oab.2.-pod-prod-03-us; Mon, 24
 Jul 2023 19:06:15 -0700 (PDT)
X-Received: by 2002:a05:6830:d:b0:6b0:c67c:96f3 with SMTP id c13-20020a056830000d00b006b0c67c96f3mr7833288otp.18.1690250775823;
        Mon, 24 Jul 2023 19:06:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690250775; cv=none;
        d=google.com; s=arc-20160816;
        b=FbdmehKLP/3mCIB2CAy28jFtaoyHAoc/r8671n88HLdxrP8Iefw9ikZYwdFC+nAqT5
         IDjuDvOU2JULcpFd0Og8M3l1aKOoC9e0oTpoe+gGmbrzRoFYpjtCiQSXT4bJKTUzqeZt
         dW/ZKDCGUHsZLxayG335DhGtsHv3ZhFkyfxdDP0+q+LQNuaJWS+L+Wq9GvtoLtDQiELh
         NxGbLK9OXO7da9yPSGriT6/S41ipFBpSbVmAiLM/qalKFivAXCZZVgJDBJ11J1zcx+IG
         2YPQl+iHvxWxqoJpRQElt3hrtW3/Fbk8+Se8vClt9gRy1cWo07SQ3dHMBoi0iiwdsW1S
         DCSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KoCEiMybIdUv0N7yMnHc+eR/nYbLG9fCxUcyOSAKK0U=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=0w/VGYSUwxDq5/zNsLMhE51q22QCZmEhPj48nRQKcbmK4XIjZXG1Y8zS6sSOAwYi45
         eKV/4psFLRmQk8EiDU/YJuEOXThfjvqpuu2p4ZEhqpWcHWGRgnGAISdeHZ0ZtKyTKMBh
         Jf+XDwwT0+VK7qt3IOVRqw1YaprMKjeLbO9xX2BdxdSy+FUfOUfVE5qoHZ49A25Z1Ugr
         B1xegoK82l4TmGoSCjlaEHH2AlKXvD/rJmJcMm5UzqTdQdcWCGdpDr+RszxHPJIziUMq
         HPjCMa1NO+XdoIYjPZLcWsCXkY2bzwcysGZez/fFanXzB1GAEJinOLwIGFkFDR+JxbSh
         OBkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DsRSOBxt;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id j10-20020a056830270a00b006b9ea5121c2si834709otu.0.2023.07.24.19.06.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jul 2023 19:06:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 78E94614AE
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 02:06:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9C918C433CB
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 02:06:14 +0000 (UTC)
Received: by mail-ej1-f42.google.com with SMTP id a640c23a62f3a-99b9161b94aso280147866b.1
        for <kasan-dev@googlegroups.com>; Mon, 24 Jul 2023 19:06:14 -0700 (PDT)
X-Received: by 2002:a17:906:7396:b0:987:e23f:6d7a with SMTP id
 f22-20020a170906739600b00987e23f6d7amr11431395ejl.25.1690250772773; Mon, 24
 Jul 2023 19:06:12 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-2-lienze@kylinos.cn>
 <CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_=j2V-urA+D87_uCMyg@mail.gmail.com>
 <87pm4mf1xl.fsf@kylinos.cn> <CAAhV-H4+8_gBMMdLhx=uEAsCN5wK7kFONsKDyGPqm0kxW8FU=A@mail.gmail.com>
 <87lef7ayha.fsf@kylinos.cn>
In-Reply-To: <87lef7ayha.fsf@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Tue, 25 Jul 2023 10:06:01 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7mpjeqnv1MXn--EPDUam6TTcHwqiMsEL4OsmAFS5XNMA@mail.gmail.com>
Message-ID: <CAAhV-H7mpjeqnv1MXn--EPDUam6TTcHwqiMsEL4OsmAFS5XNMA@mail.gmail.com>
Subject: Re: [PATCH 1/4] LoongArch: mm: Add page table mapped mode support
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DsRSOBxt;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Sun, Jul 23, 2023 at 3:17=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
>
> On Fri, Jul 21 2023 at 10:21:38 AM +0800, Huacai Chen wrote:
>
> > On Fri, Jul 21, 2023 at 10:12=E2=80=AFAM Enze Li <lienze@kylinos.cn> wr=
ote:
> >>
> >> On Wed, Jul 19 2023 at 11:29:37 PM +0800, Huacai Chen wrote:
> >>
> >> > Hi, Enze,
> >> >
> >> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> =
wrote:
> >> >>
> >> >> According to LoongArch documentation online, there are two types of=
 address
> >> >> translation modes: direct mapped address translation mode (direct m=
apped mode)
> >> >> and page table mapped address translation mode (page table mapped m=
ode).
> >> >>
> >> >> Currently, the upstream code only supports DMM (Direct Mapped Mode)=
.
> >> >> This patch adds a function that determines whether PTMM (Page Table
> >> >> Mapped Mode) should be used, and also adds the corresponding handle=
r
> >> >> funcitons for both modes.
> >> >>
> >> >> For more details on the two modes, see [1].
> >> >>
> >> >> [1]
> >> >> https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-E=
N.html#virtual-address-space-and-address-translation-mode
> >> >>
> >> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
> >> >> ---
> >> >>  arch/loongarch/include/asm/page.h    | 10 ++++++++++
> >> >>  arch/loongarch/include/asm/pgtable.h |  6 ++++++
> >> >>  arch/loongarch/mm/pgtable.c          | 25 ++++++++++++++++++++++++=
+
> >> >>  3 files changed, 41 insertions(+)
> >> >>
> >> >> diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/inc=
lude/asm/page.h
> >> >> index 26e8dccb6619..05919be15801 100644
> >> >> --- a/arch/loongarch/include/asm/page.h
> >> >> +++ b/arch/loongarch/include/asm/page.h
> >> >> @@ -84,7 +84,17 @@ typedef struct { unsigned long pgprot; } pgprot_=
t;
> >> >>  #define sym_to_pfn(x)          __phys_to_pfn(__pa_symbol(x))
> >> >>
> >> >>  #define virt_to_pfn(kaddr)     PFN_DOWN(PHYSADDR(kaddr))
> >> >> +
> >> >> +#ifdef CONFIG_64BIT
> >> >> +#define virt_to_page(kaddr)                                       =
     \
> >> >> +({                                                                =
     \
> >> >> +       is_PTMM_addr((unsigned long)kaddr) ?                       =
     \
> >> >> +       PTMM_virt_to_page((unsigned long)kaddr) :                  =
     \
> >> >> +       DMM_virt_to_page((unsigned long)kaddr);                    =
     \
> >> >> +})
> >> > 1, Rename these helpers to
> >> > is_dmw_addr()/dmw_virt_to_page()/tlb_virt_to_page() will be better.
> >> > 2, These helpers are so simple so can be defined as inline function =
or
> >> > macros in page.h.
> >>
> >> Hi Huacai,
> >>
> >> Except for tlb_virt_to_page(), the remaining two modifications are eas=
y.
> >>
> >> I've run into a lot of problems when trying to make tlb_virt_to_page()
> >> as a macro or inline function.  That's because we need to export this
> >> symbol in order for it to be used by the module that called the
> >> virt_to_page() function, other wise, we got the following errors,
> >>
> >> ----------------------------------------------------------------------=
-
> >>   MODPOST Module.symvers
> >> ERROR: modpost: "tlb_virt_to_page" [fs/hfsplus/hfsplus.ko] undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [fs/smb/client/cifs.ko] undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [crypto/gcm.ko] undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [crypto/ccm.ko] undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [crypto/essiv.ko] undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [lib/crypto/libchacha20poly1305.ko]=
 undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [drivers/gpu/drm/ttm/ttm.ko] undefi=
ned!
> >> ERROR: modpost: "tlb_virt_to_page" [drivers/gpu/drm/amd/amdgpu/amdgpu.=
ko] undefined!
> >> ERROR: modpost: "tlb_virt_to_page" [drivers/scsi/iscsi_tcp.ko] undefin=
ed!
> >> ERROR: modpost: "tlb_virt_to_page" [drivers/scsi/qla2xxx/qla2xxx.ko] u=
ndefined!
> >> WARNING: modpost: suppressed 44 unresolved symbol warnings because the=
re were too many)
> >> ----------------------------------------------------------------------=
-
> >>
> >> It seems to me that wrapping it into a common function might be the on=
ly
> >> way to successfully compile or link with this modification.
> >>
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> @@ -360,6 +360,8 @@ static inline void pte_clear(struct mm_struct *mm,=
 unsigned long addr, pte_t *pt
> >>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
> >>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
> >>
> >> +inline struct page *tlb_virt_to_page(unsigned long kaddr);
> >> +
> >>
> >> --- a/arch/loongarch/mm/pgtable.c
> >> +++ b/arch/loongarch/mm/pgtable.c
> >> @@ -9,6 +9,12 @@
> >>  #include <asm/pgtable.h>
> >>  #include <asm/tlbflush.h>
> >>
> >> +inline struct page *tlb_virt_to_page(unsigned long kaddr)
> >> +{
> >> +       return pte_page(*virt_to_kpte(kaddr));
> >> +}
> >> +EXPORT_SYMBOL_GPL(tlb_virt_to_page);
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >>
> >> WDYT?
> >>
> >> Best Regards,
> >> Enze
> > If you define "static inline" functions in page.h, there will be no pro=
blems.
> >
>
> Hi Huacai,
>
> After failed over and over and over again, I think I've found the reason
> why we can't define tlb_virt_to_page as macro or inline function in
> asm/page.h or asm/pgtable.h. :)
>
> I'll go through this step by step.
>
> If I put tlb_virt_to_page in asm/page.h as following,
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> +static inline struct page *tlb_virt_to_page(unsigned long kaddr)
> +{
> +       return pte_page(*virt_to_kpte(kaddr));
> +}
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
>
> and compile kernel, gcc says to me the following error.
>
> --------------------------------------------------------------------
>   CC      arch/loongarch/kernel/asm-offsets.s
> In file included from ./include/linux/shm.h:6,
>                  from ./include/linux/sched.h:16,
>                  from arch/loongarch/kernel/asm-offsets.c:8:
> ./arch/loongarch/include/asm/page.h: In function =E2=80=98tlb_virt_to_pag=
e=E2=80=99:
> ./arch/loongarch/include/asm/page.h:126:16: error: implicit declaration o=
f function =E2=80=98pte_page=E2=80=99 [-Werror=3Dimplicit-function-declarat=
ion]
>   126 |         return pte_page(*virt_to_kpte(kaddr));
>       |                ^~~~~~~~
> ---------------------------------------------------------------------
>
> "pte_page" is declared in asm/pgtable.h, so I put "#include
> <asm/pgtable.h>" ahead, like this,
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> +#include <asm/pgtable.h>
> +static inline struct page *tlb_virt_to_page(unsigned long kaddr)
> +{
> +       return pte_page(*virt_to_kpte(kaddr));
> +}
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
>
> then compile again, gcc says,
>
> ---------------------------------------------------------------------
>   CC      arch/loongarch/kernel/asm-offsets.s
> In file included from ./arch/loongarch/include/asm/page.h:98,
>                  from ./include/linux/shm.h:6,
>                  from ./include/linux/sched.h:16,
>                  from arch/loongarch/kernel/asm-offsets.c:8:
> ./arch/loongarch/include/asm/page.h: In function =E2=80=98tlb_virt_to_pag=
e=E2=80=99:
> ./arch/loongarch/include/asm/page.h:127:26: error: implicit declaration o=
f function =E2=80=98virt_to_kpte=E2=80=99; did you mean =E2=80=98virt_to_pf=
n=E2=80=99? [-Werror=3Dimplicit-function-declaration]
>   127 |         return pte_page(*virt_to_kpte(kaddr));
>       |                          ^~~~~~~~~~~~
> ---------------------------------------------------------------------
>
> "virt_to_kpte" is defined in linux/pgtable.h, consequently I add "#includ=
e
> <linux/pgtable.h>" as well,
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> +#include <asm/pgtable.h>
> +#include <linux/pgtable.h>
> +static inline struct page *tlb_virt_to_page(unsigned long kaddr)
> +{
> +       return pte_page(*virt_to_kpte(kaddr));
> +}
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
>
> and continue,
>
> ---------------------------------------------------------------------
>   CC      arch/loongarch/kernel/asm-offsets.s
>   CALL    scripts/checksyscalls.sh
>   CC      arch/loongarch/vdso/vgetcpu.o
>   CC      arch/loongarch/vdso/vgettimeofday.o
> In file included from ./arch/loongarch/include/asm/page.h:124,
>                  from ./include/linux/mm_types_task.h:16,
>                  from ./include/linux/mm_types.h:5,
>                  from ./include/linux/mmzone.h:22,
>                  from ./include/linux/gfp.h:7,
>                  from ./include/linux/mm.h:7,
>                  from ./arch/loongarch/include/asm/vdso.h:10,
>                  from arch/loongarch/vdso/vgetcpu.c:6:
> ./arch/loongarch/include/asm/pgtable.h: In function =E2=80=98pte_accessib=
le=E2=80=99:
> ./arch/loongarch/include/asm/pgtable.h:436:40: error: invalid use of unde=
fined type =E2=80=98struct mm_struct=E2=80=99
>   436 |                         atomic_read(&mm->tlb_flush_pending))
>       |                                        ^~
> ---------------------------------------------------------------------
>
> The first line above shows that it compiled successfully for the
> asm-offsets module.  That's fair enough.  Actually, the point is the
> next one (invalid use of undefined type 'struct mm_struct').
>
> As we all know, before the compiler compiles, it expands the header
> files first.  For this example, it firstly expands from the header file
> vdso.h, then the mm.h file and so on.  We can see that the line 436 of
> asm/pgtable.h are using 'struct mm_struct'.  When we backtrack to a file
> that has been previously expanded, it's obvious that the definition of
> mm_struct does not appear in the expanded file.  Instead, it appears
> afterward (mm_types.h).
>
> To be clear, I'll exemplify this case with a cheap ASCII diagram.
>
>                                                                  ... <-|
>                     we're using 'mm_struct' here >>>   asm/pgtable.h <-|
>                                                                  ... <-|
>                                                                        |
>                                                                |->...  |
>                                                                |->asm/pag=
e.h
>                                                                |->...
>                                                        |->...  |
>                                          |->...        |->mm_types_task.h
>                              |->...      |->mm_types.h-|->...
>                     |->...   |->mmzone.h-|->... |
>             |->...  |->gfp.h-|->...             |
>   |->...    |->mm.h-|->...            But 'mm_struct' is defined here.
>   |->vdso.h-|->...
>   |->...
> vgetcpu.c
>
> I've also tried to include mm_types.h in advance, but in this case that
> doesn't work because the _LINUX_MM_TYPES_H macro already exists.
> The "forward declaration" was also taken into account, in the end it was
> found to be unavailable as well.
>
> In summary, I'm afraid that rewriting tlb_virt_to_page in asm/page.h as
> a macro or inline function is not possible.  The root case of this is
> that both 'struct mm_struct' and 'virt_to_kpte' belong to high-level
> data structures, and if they are referenced in asm/page.h at the
> low-level, dependency problems arise.
>
> Anyway, we can at least define it as a normal function in asm/pgtable.h,
> is that Okay with you?
>
> It may be a bit wordy, so please bear with me.  In addition, all of the
> above is my understanding, am I missing something?
Well, you can define the helpers in .c files at present, but I have
another question.

Though other archs (e.g., RISC-V) have no DMW addresses, they still
have linear area. In other words, both LoongArch and RISC-V have
linear area and vmalloc-like areas. The only difference is LoongArch's
linear area is DMW-mapped but RISC-V's linear area is TLB-mapped.

For linear area, the translation is pfn_to_page(virt_to_pfn(kaddr)),
no matter LoongArch or RISC-V;
For vmalloc-like areas, the translation is
pte_page(*virt_to_kpte(kaddr)), no matter LoongArch or RISC-V.

My question is: why RISC-V only care about the linear area for
virt_to_page(), but you are caring about the vmalloc-like areas?

Huacai
>
> Best Regards,
> Enze
>
> >>
> >> > 3, CONFIG_64BIT can be removed here.
> >> >
> >> > Huacai
> >> >
> >> >> +#else
> >> >>  #define virt_to_page(kaddr)    pfn_to_page(virt_to_pfn(kaddr))
> >> >> +#endif
> >> >>
> >> >>  extern int __virt_addr_valid(volatile void *kaddr);
> >> >>  #define virt_addr_valid(kaddr) __virt_addr_valid((volatile void *)=
(kaddr))
> >> >> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/=
include/asm/pgtable.h
> >> >> index ed6a37bb55b5..0fc074b8bd48 100644
> >> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> >> @@ -360,6 +360,12 @@ static inline void pte_clear(struct mm_struct =
*mm, unsigned long addr, pte_t *pt
> >> >>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
> >> >>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
> >> >>
> >> >> +#ifdef CONFIG_64BIT
> >> >> +struct page *DMM_virt_to_page(unsigned long kaddr);
> >> >> +struct page *PTMM_virt_to_page(unsigned long kaddr);
> >> >> +bool is_PTMM_addr(unsigned long kaddr);
> >> >> +#endif
> >> >> +
> >> >>  extern pgd_t swapper_pg_dir[];
> >> >>  extern pgd_t invalid_pg_dir[];
> >> >>
> >> >> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtabl=
e.c
> >> >> index 36a6dc0148ae..4c6448f996b6 100644
> >> >> --- a/arch/loongarch/mm/pgtable.c
> >> >> +++ b/arch/loongarch/mm/pgtable.c
> >> >> @@ -9,6 +9,31 @@
> >> >>  #include <asm/pgtable.h>
> >> >>  #include <asm/tlbflush.h>
> >> >>
> >> >> +#ifdef CONFIG_64BIT
> >> >> +/* DMM stands for Direct Mapped Mode. */
> >> >> +struct page *DMM_virt_to_page(unsigned long kaddr)
> >> >> +{
> >> >> +       return pfn_to_page(virt_to_pfn(kaddr));
> >> >> +}
> >> >> +EXPORT_SYMBOL_GPL(DMM_virt_to_page);
> >> >> +
> >> >> +/* PTMM stands for Page Table Mapped Mode. */
> >> >> +struct page *PTMM_virt_to_page(unsigned long kaddr)
> >> >> +{
> >> >> +       return pte_page(*virt_to_kpte(kaddr));
> >> >> +}
> >> >> +EXPORT_SYMBOL_GPL(PTMM_virt_to_page);
> >> >> +
> >> >> +bool is_PTMM_addr(unsigned long kaddr)
> >> >> +{
> >> >> +       if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits=
)) =3D=3D
> >> >> +                    GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
> >> >> +               return true;
> >> >> +       return false;
> >> >> +}
> >> >> +EXPORT_SYMBOL_GPL(is_PTMM_addr);
> >> >> +#endif
> >> >> +
> >> >>  pgd_t *pgd_alloc(struct mm_struct *mm)
> >> >>  {
> >> >>         pgd_t *ret, *init;
> >> >> --
> >> >> 2.34.1
> >> >>
> >> >>
> >>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7mpjeqnv1MXn--EPDUam6TTcHwqiMsEL4OsmAFS5XNMA%40mail.gmail.=
com.
