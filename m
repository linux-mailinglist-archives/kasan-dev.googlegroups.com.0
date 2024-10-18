Return-Path: <kasan-dev+bncBAABBJ4CZC4AMGQEWPV7F4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id AC9C49A3574
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 08:33:13 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-20c7ea6b060sf20269195ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 23:33:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729233192; cv=pass;
        d=google.com; s=arc-20240605;
        b=a6P1yN7dDWLOFfTnB/3HSJiF72P4iS0YwHkKQ1OpgrsnI3olp4j3tlQGSMlb0irFQJ
         Jq56WCC27WtKYli8pvypojy1XmE4P0IYLfaPt8QLdnVsiC2ch0S8bXFSR6ozXAkkfYz7
         akv5C8bcz/Sba1s3wNKrMy2q2mlHRuYT/XQPWQAXwFZnjwGlKvZtH+j/RveHNyMePbjg
         NXLDgBRgywJkNqxNuKmMvXPVmahDL7Y/bQSvARyJO/w/3oOpkm7YcIrYrnVcjb1NJ1gu
         HfjxqaBi+hki8lMfYk/ujyn0CiCDlvtYXSJUp6azjh2fhDfE0iXG0jn0Yups+8a/bUum
         7ovw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dDFJYYr5ZOwonAuxbtOSJbIiYy5x66lVD7omwGO9eaM=;
        fh=9bOY0b4j9fQ42Mu0cXLEgjJh/QQLFgfXtMPl5YmkmqY=;
        b=O1BvT44W4unBKExVZbsc7k61TscOWjZE5V2iJkGIYRGK9YL7oSy2dK0jSianbEHO+2
         lzwGCslehX5YRxmzNhrh2/MuakvqBuyKgrnUgb2K8FXwLR/gwp2g/EQJgQm7ADax6L3X
         7OvjcSo9xZC+IhcDvzGp/n2H5TyBCkt9Td3xNM1Rhkjmfe7bORx3rFNKPMy62v5FKA2h
         bOmqx6chwWWQwfa07GaC/y18uEik3GwLKpjg8NLguE9Rr9OujBVgN5zPgdYx1P2l4Ao5
         zwJWYMOnIUduUmtN8TfCdyRYshkOs7hEooqno7xlB65BoTp0f+08jkj+d4NalqHjGr+E
         NDsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J6w08C7i;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729233192; x=1729837992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dDFJYYr5ZOwonAuxbtOSJbIiYy5x66lVD7omwGO9eaM=;
        b=fQD9EVSN4CFrnFAPaY6qh1bGA0TiRrZtzSGLFE6+++Nik8E8RBTlW+q7UPkOaQuSfc
         FJEjbKqcU3HT471MRBtb1+TrCEpNoH3lmIoIRIzdFTIzhLpmuvY54HGQYTgaoNaGBYxi
         eCPboo4Hul5yrXaMXucSOMetxm0HGDh2B6YsIJ/BhvEtd2Y7aCGE4pF2RAhx/dvgnDrs
         ZPH04tQlj2HSV4MtHyvt+SEWOxPWyEDfmQZ1iFqVjm1XUzi8AbUxc7hEXCvOcMpxEe/Y
         mK9nPcfh7TUUoEPgrPAQc/b0+PUS0k7H8P8LAaJpnDXLxUh0g2TGJstFtYBXYYyXp9sg
         07zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729233192; x=1729837992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dDFJYYr5ZOwonAuxbtOSJbIiYy5x66lVD7omwGO9eaM=;
        b=Xnkomk45Wtki+hg91JjMQGVnukM8giJz3iu+tjWbPIzudfk34PygdVu6JyK4Sqbivo
         Ya/75lH7jFtO80t70icxVmYA19q+AHvv4ZOaM6JUic1AJFfIq+Fh0G8/W1L/wZxnT1iD
         +RzHzV3aM2J9HewIMsHYYRxzITUi95yksqO1k/zReiPNG/hFpvH0Rcu2aVK9puJrUnXd
         +Jx28i1OllSPxCIRCmhLfAMCgsmOt1ivJKF01InU9oLsf6F89Alg1M7nE/MZ338EDmpF
         uxRrOO1ykT9b1z0CjQ3d/DZ8OV/iztPCqjRc9N+lHD9tp3tS3LxiifiZy2yK7+fuPqbm
         /+LQ==
X-Forwarded-Encrypted: i=2; AJvYcCWOXb2NE8NGZ1Vv6tvshtX8v/ykcr0xivChq7tTIf0J/SY32o5iSxMTkvUtWG63JH4n/nIpsw==@lfdr.de
X-Gm-Message-State: AOJu0YyYK5mteLNFy8NcJ0+ZnRmz1u2mnAmQsruzgMe7AhLYnEwOnTPZ
	cy5r5jbzgmUdb5HDOrCSOryl0ohyXUzVzZs2YOuWZJygmwmrC+S5
X-Google-Smtp-Source: AGHT+IH0N6Cr4IwPSKQy4d2PTGFXsmvUFHUAhOkoMABl1AJ5Giv32ULVJDaMttdjpgf0GvUMi8biiw==
X-Received: by 2002:a17:902:f54d:b0:20c:aed1:812b with SMTP id d9443c01a7336-20e5a8a40d4mr16084015ad.29.1729233192141;
        Thu, 17 Oct 2024 23:33:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:244c:b0:201:e7c1:566f with SMTP id
 d9443c01a7336-20d47ba2913ls8178265ad.1.-pod-prod-06-us; Thu, 17 Oct 2024
 23:33:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURpQHF+vOWnvvkH0KOLIvVff+Tzzi3FzsXHUjq9lL4mS5XvDcHyYoe28EAzgmW/Ty0CniYdIUFnRw=@googlegroups.com
X-Received: by 2002:a17:902:da8f:b0:20c:6bff:fc8a with SMTP id d9443c01a7336-20e5a70d7e4mr19654765ad.2.1729233191049;
        Thu, 17 Oct 2024 23:33:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729233191; cv=none;
        d=google.com; s=arc-20240605;
        b=YMn4MkC7bhRRcJZjVBr3f7FLIVxQLQBn/CON8mBusd3S/Hz6rJgBijjVlZAY2CBJdE
         953gAxSgINnRWi9VuDV5r7Dd5Hvkxmj29VXvtp5mC7Cjfoi7ldqJEGs0+0f9vHjI8Yb7
         SLGawfoGU+iQXZnLGAvGLIixOL10gbLXJwu92+R4+2fi9bypfa+QaynhvKgm34cw/mjT
         nVxBMfGOdj0KvB4KqePkBRDvUMw6/r6YpIJ2Flcw14F2qDTq2YPqot+SOFPaLuLPTef3
         gUNsLO95iSAbN3yibeNu6QmBQw0w4gSSIwhvLTBuJ7s6ax1qe4QcZcklWyymAfcJpbeA
         f9lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bm5icURfyweJ1CmKvjrBSbfZN3542l2J6HuUi/lmM4o=;
        fh=dFAwpByItUfZZAD4j56lc7JExpLeD7qx4TXW8Syb7pg=;
        b=hagkhflVV7xbtAYqfz+n9/GhV/DSNDMoHIYbztEhxlySncUnnWTT017LtEX9nJQnFJ
         TqCqqflfYIYOWWPhDjXi0f7bO5u62a1RMRG1SW26lksdPaQxBUdY0hA/ZcAiHFjEX2vM
         fbHEqcDiT5CZ2HR/Q4nX+0IS9dzKMnD65KJN4kPkp0Mrv80wqIA8FGFlVVN4W+ozurHN
         +AtA+g4+jcrQ/wmSu8yy1Xg7o4kCTBox2E2P8f9/shByHx+eie23wgpqs4Fbo/FEFnm5
         V0C7JSkUKZrlXYWHzh5+E/BhAsEMLWDBC24+SG39MKjQkepRY+OyeWvFhuLC/zvyXZve
         +4Zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J6w08C7i;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20e5a90d96dsi351105ad.11.2024.10.17.23.33.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 23:33:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C8B415C51B4
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 06:33:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E1D67C4CED0
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 06:33:09 +0000 (UTC)
Received: by mail-ej1-f41.google.com with SMTP id a640c23a62f3a-a9a68480164so51356966b.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 23:33:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV2FDd3N9Q7XbK5SxurlHrEPpFtyaxycfJIxG23wmZKCU7vHyip544tAobr+ZVzsijvtvnBm34FFwo=@googlegroups.com
X-Received: by 2002:a17:907:1c24:b0:a9a:6d7:9c4 with SMTP id
 a640c23a62f3a-a9a69a63af8mr114144866b.12.1729233188396; Thu, 17 Oct 2024
 23:33:08 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
 <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn> <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
 <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn> <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
 <5f76ede6-e8be-c7a9-f957-479afa2fb828@loongson.cn>
In-Reply-To: <5f76ede6-e8be-c7a9-f957-479afa2fb828@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 14:32:54 +0800
X-Gmail-Original-Message-ID: <CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH=psjAbEJUdwgg@mail.gmail.com>
Message-ID: <CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH=psjAbEJUdwgg@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: maobibo <maobibo@loongson.cn>
Cc: wuruiyang@loongson.cn, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=J6w08C7i;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

On Fri, Oct 18, 2024 at 2:23=E2=80=AFPM maobibo <maobibo@loongson.cn> wrote=
:
>
>
>
> On 2024/10/18 =E4=B8=8B=E5=8D=8812:23, Huacai Chen wrote:
> > On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.cn> =
wrote:
> >>
> >>
> >>
> >> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
> >>> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.cn=
> wrote:
> >>>>
> >>>>
> >>>>
> >>>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
> >>>>> Hi, Bibo,
> >>>>>
> >>>>> I applied this patch but drop the part of arch/loongarch/mm/kasan_i=
nit.c:
> >>>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-lo=
ongson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50a=
fc403067
> >>>>>
> >>>>> Because kernel_pte_init() should operate on page-table pages, not o=
n
> >>>>> data pages. You have already handle page-table page in
> >>>>> mm/kasan/init.c, and if we don't drop the modification on data page=
s
> >>>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN=
 is
> >>>>> enabled.
> >>>>>
> >>>> static inline void set_pte(pte_t *ptep, pte_t pteval)
> >>>>     {
> >>>>           WRITE_ONCE(*ptep, pteval);
> >>>> -
> >>>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
> >>>> -               pte_t *buddy =3D ptep_buddy(ptep);
> >>>> -               /*
> >>>> -                * Make sure the buddy is global too (if it's !none,
> >>>> -                * it better already be global)
> >>>> -                */
> >>>> -               if (pte_none(ptep_get(buddy))) {
> >>>> -#ifdef CONFIG_SMP
> >>>> -                       /*
> >>>> -                        * For SMP, multiple CPUs can race, so we ne=
ed
> >>>> -                        * to do this atomically.
> >>>> -                        */
> >>>> -                       __asm__ __volatile__(
> >>>> -                       __AMOR "$zero, %[global], %[buddy] \n"
> >>>> -                       : [buddy] "+ZB" (buddy->pte)
> >>>> -                       : [global] "r" (_PAGE_GLOBAL)
> >>>> -                       : "memory");
> >>>> -
> >>>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>>> -#else /* !CONFIG_SMP */
> >>>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(bu=
ddy)) | _PAGE_GLOBAL));
> >>>> -#endif /* CONFIG_SMP */
> >>>> -               }
> >>>> -       }
> >>>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>>>     }
> >>>>
> >>>> No, please hold on. This issue exists about twenty years, Do we need=
 be
> >>>> in such a hurry now?
> >>>>
> >>>> why is DBAR(0b11000) added in set_pte()?
> >>> It exists before, not added by this patch. The reason is explained in
> >>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/co=
mmit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> >> why speculative accesses may cause spurious page fault in kernel space
> >> with PTE enabled?  speculative accesses exists anywhere, it does not
> >> cause spurious page fault.
> > Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
> > means another patch's mistake, not this one. This one just keeps the
> > old behavior.
> > +CC Ruiyang Wu here.
> Also from Ruiyang Wu, the information is that speculative accesses may
> insert stale TLB, however no page fault exception.
>
> So adding barrier in set_pte() does not prevent speculative accesses.
> And you write patch here, however do not know the actual reason?
>
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
I have CCed Ruiyang, whether the description is correct can be judged by hi=
m.

Huacai

>
> Bibo Mao
> >
> > Huacai
> >
> >>
> >> Obvious you do not it and you write wrong patch.
> >>
> >>>
> >>> Huacai
> >>>
> >>>>
> >>>> Regards
> >>>> Bibo Mao
> >>>>> Huacai
> >>>>>
> >>>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson=
.cn> wrote:
> >>>>>>
> >>>>>> Unlike general architectures, there are two pages in one TLB entry
> >>>>>> on LoongArch system. For kernel space, it requires both two pte
> >>>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
> >>>>>> tlb, there will be potential problems if tlb entry for kernel spac=
e
> >>>>>> is not global. Such as fail to flush kernel tlb with function
> >>>>>> local_flush_tlb_kernel_range() which only flush tlb with global bi=
t.
> >>>>>>
> >>>>>> With function kernel_pte_init() added, it can be used to init pte
> >>>>>> table when it is created for kernel address space, and the default
> >>>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
> >>>>>>
> >>>>>> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
> >>>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
> >>>>>>
> >>>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >>>>>> ---
> >>>>>>     arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
> >>>>>>     arch/loongarch/include/asm/pgtable.h |  1 +
> >>>>>>     arch/loongarch/mm/init.c             |  4 +++-
> >>>>>>     arch/loongarch/mm/kasan_init.c       |  4 +++-
> >>>>>>     arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++=
++
> >>>>>>     include/linux/mm.h                   |  1 +
> >>>>>>     mm/kasan/init.c                      |  8 +++++++-
> >>>>>>     mm/sparse-vmemmap.c                  |  5 +++++
> >>>>>>     8 files changed, 55 insertions(+), 3 deletions(-)
> >>>>>>
> >>>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch=
/include/asm/pgalloc.h
> >>>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> >>>>>> --- a/arch/loongarch/include/asm/pgalloc.h
> >>>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
> >>>>>> @@ -10,8 +10,21 @@
> >>>>>>
> >>>>>>     #define __HAVE_ARCH_PMD_ALLOC_ONE
> >>>>>>     #define __HAVE_ARCH_PUD_ALLOC_ONE
> >>>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
> >>>>>>     #include <asm-generic/pgalloc.h>
> >>>>>>
> >>>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
> >>>>>> +{
> >>>>>> +       pte_t *pte;
> >>>>>> +
> >>>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> >>>>>> +       if (!pte)
> >>>>>> +               return NULL;
> >>>>>> +
> >>>>>> +       kernel_pte_init(pte);
> >>>>>> +       return pte;
> >>>>>> +}
> >>>>>> +
> >>>>>>     static inline void pmd_populate_kernel(struct mm_struct *mm,
> >>>>>>                                           pmd_t *pmd, pte_t *pte)
> >>>>>>     {
> >>>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch=
/include/asm/pgtable.h
> >>>>>> index 9965f52ef65b..22e3a8f96213 100644
> >>>>>> --- a/arch/loongarch/include/asm/pgtable.h
> >>>>>> +++ b/arch/loongarch/include/asm/pgtable.h
> >>>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, u=
nsigned long addr, pmd_t *pmdp, pm
> >>>>>>     extern void pgd_init(void *addr);
> >>>>>>     extern void pud_init(void *addr);
> >>>>>>     extern void pmd_init(void *addr);
> >>>>>> +extern void kernel_pte_init(void *addr);
> >>>>>>
> >>>>>>     /*
> >>>>>>      * Encode/decode swap entries and swap PTEs. Swap PTEs are all=
 PTEs that
> >>>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
> >>>>>> index 8a87a482c8f4..9f26e933a8a3 100644
> >>>>>> --- a/arch/loongarch/mm/init.c
> >>>>>> +++ b/arch/loongarch/mm/init.c
> >>>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned l=
ong addr)
> >>>>>>            if (!pmd_present(pmdp_get(pmd))) {
> >>>>>>                    pte_t *pte;
> >>>>>>
> >>>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> >>>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
> >>>>>>                    if (!pte)
> >>>>>>                            panic("%s: Failed to allocate memory\n"=
, __func__);
> >>>>>> +
> >>>>>> +               kernel_pte_init(pte);
> >>>>>>                    pmd_populate_kernel(&init_mm, pmd, pte);
> >>>>>>            }
> >>>>>>
> >>>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/ka=
san_init.c
> >>>>>> index 427d6b1aec09..34988573b0d5 100644
> >>>>>> --- a/arch/loongarch/mm/kasan_init.c
> >>>>>> +++ b/arch/loongarch/mm/kasan_init.c
> >>>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *p=
mdp, unsigned long addr,
> >>>>>>                    phys_addr_t page_phys =3D early ?
> >>>>>>                                            __pa_symbol(kasan_early=
_shadow_page)
> >>>>>>                                                  : kasan_alloc_zer=
oed_page(node);
> >>>>>> +               if (!early)
> >>>>>> +                       kernel_pte_init(__va(page_phys));
> >>>>>>                    next =3D addr + PAGE_SIZE;
> >>>>>>                    set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys),=
 PAGE_KERNEL));
> >>>>>>            } while (ptep++, addr =3D next, addr !=3D end && __pte_=
none(early, ptep_get(ptep)));
> >>>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
> >>>>>>                    set_pte(&kasan_early_shadow_pte[i],
> >>>>>>                            pfn_pte(__phys_to_pfn(__pa_symbol(kasan=
_early_shadow_page)), PAGE_KERNEL_RO));
> >>>>>>
> >>>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >>>>>> +       kernel_pte_init(kasan_early_shadow_page);
> >>>>>>            csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_=
PGDH);
> >>>>>>            local_flush_tlb_all();
> >>>>>>
> >>>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtab=
le.c
> >>>>>> index eb6a29b491a7..228ffc1db0a3 100644
> >>>>>> --- a/arch/loongarch/mm/pgtable.c
> >>>>>> +++ b/arch/loongarch/mm/pgtable.c
> >>>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
> >>>>>>     }
> >>>>>>     EXPORT_SYMBOL_GPL(pgd_alloc);
> >>>>>>
> >>>>>> +void kernel_pte_init(void *addr)
> >>>>>> +{
> >>>>>> +       unsigned long *p, *end;
> >>>>>> +       unsigned long entry;
> >>>>>> +
> >>>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> >>>>>> +       p =3D (unsigned long *)addr;
> >>>>>> +       end =3D p + PTRS_PER_PTE;
> >>>>>> +
> >>>>>> +       do {
> >>>>>> +               p[0] =3D entry;
> >>>>>> +               p[1] =3D entry;
> >>>>>> +               p[2] =3D entry;
> >>>>>> +               p[3] =3D entry;
> >>>>>> +               p[4] =3D entry;
> >>>>>> +               p +=3D 8;
> >>>>>> +               p[-3] =3D entry;
> >>>>>> +               p[-2] =3D entry;
> >>>>>> +               p[-1] =3D entry;
> >>>>>> +       } while (p !=3D end);
> >>>>>> +}
> >>>>>> +
> >>>>>>     void pgd_init(void *addr)
> >>>>>>     {
> >>>>>>            unsigned long *p, *end;
> >>>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
> >>>>>> index ecf63d2b0582..6909fe059a2c 100644
> >>>>>> --- a/include/linux/mm.h
> >>>>>> +++ b/include/linux/mm.h
> >>>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size=
);
> >>>>>>     struct page * __populate_section_memmap(unsigned long pfn,
> >>>>>>                    unsigned long nr_pages, int nid, struct vmem_al=
tmap *altmap,
> >>>>>>                    struct dev_pagemap *pgmap);
> >>>>>> +void kernel_pte_init(void *addr);
> >>>>>>     void pmd_init(void *addr);
> >>>>>>     void pud_init(void *addr);
> >>>>>>     pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
> >>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> >>>>>> index 89895f38f722..ac607c306292 100644
> >>>>>> --- a/mm/kasan/init.c
> >>>>>> +++ b/mm/kasan/init.c
> >>>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pm=
d, unsigned long addr,
> >>>>>>            }
> >>>>>>     }
> >>>>>>
> >>>>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>>>> +{
> >>>>>> +}
> >>>>>> +
> >>>>>>     static int __ref zero_pmd_populate(pud_t *pud, unsigned long a=
ddr,
> >>>>>>                                    unsigned long end)
> >>>>>>     {
> >>>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud=
, unsigned long addr,
> >>>>>>
> >>>>>>                            if (slab_is_available())
> >>>>>>                                    p =3D pte_alloc_one_kernel(&ini=
t_mm);
> >>>>>> -                       else
> >>>>>> +                       else {
> >>>>>>                                    p =3D early_alloc(PAGE_SIZE, NU=
MA_NO_NODE);
> >>>>>> +                               kernel_pte_init(p);
> >>>>>> +                       }
> >>>>>>                            if (!p)
> >>>>>>                                    return -ENOMEM;
> >>>>>>
> >>>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> >>>>>> index edcc7a6b0f6f..c0388b2e959d 100644
> >>>>>> --- a/mm/sparse-vmemmap.c
> >>>>>> +++ b/mm/sparse-vmemmap.c
> >>>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_z=
ero(unsigned long size, int node)
> >>>>>>            return p;
> >>>>>>     }
> >>>>>>
> >>>>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>>>> +{
> >>>>>> +}
> >>>>>> +
> >>>>>>     pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned lo=
ng addr, int node)
> >>>>>>     {
> >>>>>>            pmd_t *pmd =3D pmd_offset(pud, addr);
> >>>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *=
pud, unsigned long addr, int node)
> >>>>>>                    void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE,=
 node);
> >>>>>>                    if (!p)
> >>>>>>                            return NULL;
> >>>>>> +               kernel_pte_init(p);
> >>>>>>                    pmd_populate_kernel(&init_mm, pmd, p);
> >>>>>>            }
> >>>>>>            return pmd;
> >>>>>> --
> >>>>>> 2.39.3
> >>>>>>
> >>>>
> >>>>
> >>
> >>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH%3DpsjAbEJUdwgg%40mail.gmai=
l.com.
