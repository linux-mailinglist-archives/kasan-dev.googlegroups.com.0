Return-Path: <kasan-dev+bncBAABBQ6X46SQMGQEJ4M6HBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AABD75BC38
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 04:21:57 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-635e244d063sf17648566d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 19:21:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689906116; cv=pass;
        d=google.com; s=arc-20160816;
        b=kOrJNPNYBiZs6XUddml5BYprPFU98kOF0qR21CHKr5Wsc1yARYZetlwcpiqvkenxDn
         GGd7V68wZxT3EV4o1FruvlJ/cuMm6cv0u7oZqSjn/06Y0vKSo0dCOVrtheoWVSbMxXTT
         84C/HfOyMADV8tetAnVDbVYxdq66+ufW3q1eG8YvPIeIxhKmggDzX6PfGi2qj76W63Fg
         8Fbab8yjqJS50nt5UHepYxtVL/PIFzhpM0/wJ4tvLpamrThCuWZbLx+evZlh8v3rAAf2
         94f2MkYe02FyYD+MkVAI8m24midGjH4/56k7BDZIWUX1y+QgQ0ivkjhP4Cc8TPv16CNB
         ki8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=c47ks7qrioEB7QNhjsYbNDPuWJEcTHESDTscmIDv3b4=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=uR7ocTMXNtb7CiwQ7Dg3TW7O5YGOVBToezvmvksrROyy3UVuyDlxOOazf8FoPWxwgh
         XcFK0CtQriR2F1j74y/Jo31K3Nd1Ji+FaW4dUVw9A3Gmz8WiAW1mq54bXVJ7UanX8zj5
         +Ey/HO5paTK4bZTH+merghK819R9j1alcey8RC9qWR9afYMEx2+pnFGVdDC6cQiB2FIO
         +DJvT5S08+w8phuhT2jwQvFADs0xKqIemTWDXrwmxjJGOjrGxKU1322wVDfygscVZqCH
         Ivd3Omt4Rpvd0cJCdrQaJN50aSzTzXGnzxmed32rTA2KTqc/GIZRHOUnVkvgc4IoaFe6
         InUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ebHf21S4;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689906116; x=1690510916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c47ks7qrioEB7QNhjsYbNDPuWJEcTHESDTscmIDv3b4=;
        b=PYWroWU3xDkbi8E2K/QCIhZi2gizo2CH2rtX+AuR4cCyDCzr+Xvp7vfhmlwvQe0Myr
         yjnmHZtrLHL6UG1xuateQgVuau/az+0S3sEx5LZUvNL3W+3EVEQIxl/9rS6hWr+ZPy0m
         47kC8RNIqrJq7f1/vCnex3A8CY++7gcEqbyd8Ywg6jyFwN+XWbtQh3HKTIQ24MkY41Y7
         Aj5APpH/etGITclbkwSs+eZ99qf517LWTHM4p8oCDQofWN5EkbZYPdKJPFm5qmB3bqAK
         VLcR13I57Ft3t8wkE9GJ6IMldQeIEnqHBOEIBurbgHqwuXC05HrKT7sM4BCK9X+sF+yW
         TdOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689906116; x=1690510916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c47ks7qrioEB7QNhjsYbNDPuWJEcTHESDTscmIDv3b4=;
        b=UWCoxIKfOS+SGeuecVC3un23FuPIuG4ia+4BmJ9Yz9A22Oxu5qF1rPLFJBLZtv95eP
         JwYopBWf+htchl85OBMQm25SrJPgB3czCUgMzVBZv9vvAcfvCHt9CIHNqdpIlIQomI2y
         SJ3uw2Op9Sq0lasCB9Q6UZIxi/qZalRX8rQ45DM3BXNM04lZ2/Rl9/bLHr3JhS7U7LsH
         hBaz5yR+UMPgQiLL14RsIiIlIy23rp/c4LHdDmEoXnmRH6tS1B/OMsFTqd90H6SxLzBv
         poN3+SuOOl1TVZZpV05ccqnMS7r8D3vzAULjAHkjOvoADSkrnn7gZ1i5Co7WWXluuPCT
         IKzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaLMKj92aB0YRWw3x29bhh/ZqWCqSXzLc7R36oi7cqNG0QdhLrZ
	pUIc8O7xl0+WGZNF25jWByQ=
X-Google-Smtp-Source: APBJJlGcNRpQBkjEiDYIWfnkTUFHGOvW2Phws3l9V/da+zZTs5o61kHqDgGZTAVc3TdEJ6+0uylDuw==
X-Received: by 2002:a0c:f013:0:b0:630:7a8:f602 with SMTP id z19-20020a0cf013000000b0063007a8f602mr845831qvk.7.1689906115778;
        Thu, 20 Jul 2023 19:21:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:cb8d:0:b0:631:f072:e45d with SMTP id p13-20020a0ccb8d000000b00631f072e45dls1249602qvk.1.-pod-prod-01-us;
 Thu, 20 Jul 2023 19:21:55 -0700 (PDT)
X-Received: by 2002:a0c:eb83:0:b0:63c:81ca:cf6c with SMTP id x3-20020a0ceb83000000b0063c81cacf6cmr782046qvo.20.1689906115230;
        Thu, 20 Jul 2023 19:21:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689906115; cv=none;
        d=google.com; s=arc-20160816;
        b=g8kAyNYFBw+ybaASXivNoi2BTnpmZ8ogaisgPbHH69rbT2AASuQdoe6+Yp5JV01nDX
         /++jpqjunia+JOo2bQtfvAz6DyVTRgpEiw369/hCTcreFqAG6fU2Rq1tZrQLCtf1ovkY
         8p42t/NnpQgmH2EjwjAdZGa+WbQmwA/SAwHNq7+Wt3tIfP7Jv6BdJsDZ/pqacQrkeAAt
         T2yeYQmwA89zzO39Oppqb9vxwcbcyNVdLQnjqFeRSREP4gyDIZp9HjX9GyTcnCQUjVNi
         6UluA2jdcHGh+DXexn5x3GVojOQwXXtOq4iuO60cP2hhk7YLE3UPUDC5hb6XYYr+tAt1
         CxmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TgmV99YbvrQKh7GSSW2p8BecjRPWR72BKa11V5tjWmA=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=0XcXbuNvOR2vDQ/NpYjGovKbXZHAcFwRu8fYiYJ+yMJtFKYT5S5ZZdIQUr9SY9Wgq6
         owzvO3aBUoGON/CpqEDp3BntBwmZBNamcn5Q0quIZhF3Vfk5Y0ntosarZrc1dlSMBSH3
         CeZRkIW3lSIH0Fbzgd5VhvRv+98E4H6T/FChv++yGVR3zSVbuCjIC7enWNazTrrCCd1D
         eOwWthYWcl5QLp5wZP+5R8p+NS+k2oRKAzClAor/45lxPjfd3jFuinP0sL5lAuDLEym6
         PTH3+ljfeVObr7bfr9nDEwdxpH1gSA0Oq5Qf9AXIp+5p49NzLUd/CRhSeo4F0wBhfUsM
         8qRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ebHf21S4;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id on28-20020a056214449c00b0062dec72a6b6si168512qvb.1.2023.07.20.19.21.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Jul 2023 19:21:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C071361CE5
	for <kasan-dev@googlegroups.com>; Fri, 21 Jul 2023 02:21:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1D2EC433D9
	for <kasan-dev@googlegroups.com>; Fri, 21 Jul 2023 02:21:51 +0000 (UTC)
Received: by mail-ed1-f42.google.com with SMTP id 4fb4d7f45d1cf-51cff235226so3145226a12.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Jul 2023 19:21:51 -0700 (PDT)
X-Received: by 2002:aa7:d1c3:0:b0:51d:e185:a211 with SMTP id
 g3-20020aa7d1c3000000b0051de185a211mr581293edp.21.1689906109831; Thu, 20 Jul
 2023 19:21:49 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-2-lienze@kylinos.cn>
 <CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_=j2V-urA+D87_uCMyg@mail.gmail.com> <87pm4mf1xl.fsf@kylinos.cn>
In-Reply-To: <87pm4mf1xl.fsf@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 21 Jul 2023 10:21:38 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4+8_gBMMdLhx=uEAsCN5wK7kFONsKDyGPqm0kxW8FU=A@mail.gmail.com>
Message-ID: <CAAhV-H4+8_gBMMdLhx=uEAsCN5wK7kFONsKDyGPqm0kxW8FU=A@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=ebHf21S4;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

On Fri, Jul 21, 2023 at 10:12=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrote:
>
> On Wed, Jul 19 2023 at 11:29:37 PM +0800, Huacai Chen wrote:
>
> > Hi, Enze,
> >
> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wro=
te:
> >>
> >> According to LoongArch documentation online, there are two types of ad=
dress
> >> translation modes: direct mapped address translation mode (direct mapp=
ed mode)
> >> and page table mapped address translation mode (page table mapped mode=
).
> >>
> >> Currently, the upstream code only supports DMM (Direct Mapped Mode).
> >> This patch adds a function that determines whether PTMM (Page Table
> >> Mapped Mode) should be used, and also adds the corresponding handler
> >> funcitons for both modes.
> >>
> >> For more details on the two modes, see [1].
> >>
> >> [1]
> >> https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.h=
tml#virtual-address-space-and-address-translation-mode
> >>
> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
> >> ---
> >>  arch/loongarch/include/asm/page.h    | 10 ++++++++++
> >>  arch/loongarch/include/asm/pgtable.h |  6 ++++++
> >>  arch/loongarch/mm/pgtable.c          | 25 +++++++++++++++++++++++++
> >>  3 files changed, 41 insertions(+)
> >>
> >> diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/includ=
e/asm/page.h
> >> index 26e8dccb6619..05919be15801 100644
> >> --- a/arch/loongarch/include/asm/page.h
> >> +++ b/arch/loongarch/include/asm/page.h
> >> @@ -84,7 +84,17 @@ typedef struct { unsigned long pgprot; } pgprot_t;
> >>  #define sym_to_pfn(x)          __phys_to_pfn(__pa_symbol(x))
> >>
> >>  #define virt_to_pfn(kaddr)     PFN_DOWN(PHYSADDR(kaddr))
> >> +
> >> +#ifdef CONFIG_64BIT
> >> +#define virt_to_page(kaddr)                                          =
  \
> >> +({                                                                   =
  \
> >> +       is_PTMM_addr((unsigned long)kaddr) ?                          =
  \
> >> +       PTMM_virt_to_page((unsigned long)kaddr) :                     =
  \
> >> +       DMM_virt_to_page((unsigned long)kaddr);                       =
  \
> >> +})
> > 1, Rename these helpers to
> > is_dmw_addr()/dmw_virt_to_page()/tlb_virt_to_page() will be better.
> > 2, These helpers are so simple so can be defined as inline function or
> > macros in page.h.
>
> Hi Huacai,
>
> Except for tlb_virt_to_page(), the remaining two modifications are easy.
>
> I've run into a lot of problems when trying to make tlb_virt_to_page()
> as a macro or inline function.  That's because we need to export this
> symbol in order for it to be used by the module that called the
> virt_to_page() function, other wise, we got the following errors,
>
> -----------------------------------------------------------------------
>   MODPOST Module.symvers
> ERROR: modpost: "tlb_virt_to_page" [fs/hfsplus/hfsplus.ko] undefined!
> ERROR: modpost: "tlb_virt_to_page" [fs/smb/client/cifs.ko] undefined!
> ERROR: modpost: "tlb_virt_to_page" [crypto/gcm.ko] undefined!
> ERROR: modpost: "tlb_virt_to_page" [crypto/ccm.ko] undefined!
> ERROR: modpost: "tlb_virt_to_page" [crypto/essiv.ko] undefined!
> ERROR: modpost: "tlb_virt_to_page" [lib/crypto/libchacha20poly1305.ko] un=
defined!
> ERROR: modpost: "tlb_virt_to_page" [drivers/gpu/drm/ttm/ttm.ko] undefined=
!
> ERROR: modpost: "tlb_virt_to_page" [drivers/gpu/drm/amd/amdgpu/amdgpu.ko]=
 undefined!
> ERROR: modpost: "tlb_virt_to_page" [drivers/scsi/iscsi_tcp.ko] undefined!
> ERROR: modpost: "tlb_virt_to_page" [drivers/scsi/qla2xxx/qla2xxx.ko] unde=
fined!
> WARNING: modpost: suppressed 44 unresolved symbol warnings because there =
were too many)
> -----------------------------------------------------------------------
>
> It seems to me that wrapping it into a common function might be the only
> way to successfully compile or link with this modification.
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -360,6 +360,8 @@ static inline void pte_clear(struct mm_struct *mm, un=
signed long addr, pte_t *pt
>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
>
> +inline struct page *tlb_virt_to_page(unsigned long kaddr);
> +
>
> --- a/arch/loongarch/mm/pgtable.c
> +++ b/arch/loongarch/mm/pgtable.c
> @@ -9,6 +9,12 @@
>  #include <asm/pgtable.h>
>  #include <asm/tlbflush.h>
>
> +inline struct page *tlb_virt_to_page(unsigned long kaddr)
> +{
> +       return pte_page(*virt_to_kpte(kaddr));
> +}
> +EXPORT_SYMBOL_GPL(tlb_virt_to_page);
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
>
> WDYT?
>
> Best Regards,
> Enze
If you define "static inline" functions in page.h, there will be no problem=
s.

Huacai
>
> > 3, CONFIG_64BIT can be removed here.
> >
> > Huacai
> >
> >> +#else
> >>  #define virt_to_page(kaddr)    pfn_to_page(virt_to_pfn(kaddr))
> >> +#endif
> >>
> >>  extern int __virt_addr_valid(volatile void *kaddr);
> >>  #define virt_addr_valid(kaddr) __virt_addr_valid((volatile void *)(ka=
ddr))
> >> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inc=
lude/asm/pgtable.h
> >> index ed6a37bb55b5..0fc074b8bd48 100644
> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> @@ -360,6 +360,12 @@ static inline void pte_clear(struct mm_struct *mm=
, unsigned long addr, pte_t *pt
> >>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
> >>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
> >>
> >> +#ifdef CONFIG_64BIT
> >> +struct page *DMM_virt_to_page(unsigned long kaddr);
> >> +struct page *PTMM_virt_to_page(unsigned long kaddr);
> >> +bool is_PTMM_addr(unsigned long kaddr);
> >> +#endif
> >> +
> >>  extern pgd_t swapper_pg_dir[];
> >>  extern pgd_t invalid_pg_dir[];
> >>
> >> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
> >> index 36a6dc0148ae..4c6448f996b6 100644
> >> --- a/arch/loongarch/mm/pgtable.c
> >> +++ b/arch/loongarch/mm/pgtable.c
> >> @@ -9,6 +9,31 @@
> >>  #include <asm/pgtable.h>
> >>  #include <asm/tlbflush.h>
> >>
> >> +#ifdef CONFIG_64BIT
> >> +/* DMM stands for Direct Mapped Mode. */
> >> +struct page *DMM_virt_to_page(unsigned long kaddr)
> >> +{
> >> +       return pfn_to_page(virt_to_pfn(kaddr));
> >> +}
> >> +EXPORT_SYMBOL_GPL(DMM_virt_to_page);
> >> +
> >> +/* PTMM stands for Page Table Mapped Mode. */
> >> +struct page *PTMM_virt_to_page(unsigned long kaddr)
> >> +{
> >> +       return pte_page(*virt_to_kpte(kaddr));
> >> +}
> >> +EXPORT_SYMBOL_GPL(PTMM_virt_to_page);
> >> +
> >> +bool is_PTMM_addr(unsigned long kaddr)
> >> +{
> >> +       if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits)) =
=3D=3D
> >> +                    GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
> >> +               return true;
> >> +       return false;
> >> +}
> >> +EXPORT_SYMBOL_GPL(is_PTMM_addr);
> >> +#endif
> >> +
> >>  pgd_t *pgd_alloc(struct mm_struct *mm)
> >>  {
> >>         pgd_t *ret, *init;
> >> --
> >> 2.34.1
> >>
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4%2B8_gBMMdLhx%3DuEAsCN5wK7kFONsKDyGPqm0kxW8FU%3DA%40mail.=
gmail.com.
