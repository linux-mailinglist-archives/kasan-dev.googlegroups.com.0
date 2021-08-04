Return-Path: <kasan-dev+bncBDDL3KWR4EBRBAHNVGEAMGQEA5ORMOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FC713E0006
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 13:14:09 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id b9-20020a5b07890000b0290558245b7eabsf2584193ybq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 04:14:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628075648; cv=pass;
        d=google.com; s=arc-20160816;
        b=RUdzhZrfMCwPeRcLIm3n6F5fMvgu5ey6CiGmKJf0RqHZ4Y7Ler9+BiZIGbFGCP0d7O
         lzZEKTkRFaIYy/bELRx1UY7rrHAGuwjRJJiEH2/cCMuyv+jXwzRgMfrDqYUTCt6rnbsY
         caJoTNCWxSpOgffyDvJpajQcYPB3SFIJJ8v+TFHOF19Hd1bj3H2d5A94rEa288TLxN3P
         X1ZzgNGaWwWUgsI7MTtgI2m44PnNElssaX/xt63zlXpQe+buON1MYBklmEQBg2EVwyHc
         l8cuqeqEdFbBV4er1EZafUpAsNrhlQAVeReMty1Nq5RjjRzV88Z7mUUhY1M8Qy+aXLlt
         9s2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=g9ItWJvuw8gRUB1rJe3KyukTXGtR2DFnpKkYpk2JtII=;
        b=McFxNuAPFy1dsuNkptZOAzXE34uWr3unhXJjTojpwHJ+X7ZtinEP/uueZBHkkooGUB
         n5PqO5w1Sw+ddvBeT4xqCUI4VtsiNBkxBZJ9+bm0VO9FTZMCggK1ZPwp/0I0ZNjMSHVl
         e5w23KN2M07pmy3W4P4GGY1hX7Sln8ACIPbdh97hMdxNF3qIu/V07L6WMby4sXxNtdbx
         B0Nkb5USXNlj8FBetUQ6Vt2IHh2C7QR2Noi94GKG/4KbnSyR2dSO7x5v5KNJ3pjjPfGI
         0fso0t/idlfdjW0nS1Wh0ks4gnXXkwEnR/Zb1IKDOtVtpASDEm5c7jzqiCNSRpScQcOr
         1eNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g9ItWJvuw8gRUB1rJe3KyukTXGtR2DFnpKkYpk2JtII=;
        b=bK1jukr1+MusmhdRrXSsPlO48GiOBtVWxLh2QsKugYUCXybmxbrI6ApeZNz3qRPo3F
         +gfkkZKP92wJtzVwCCR8pW5OicOXyedJ6Iu0Ep+/oZjyfW7MAQt9LqgHKzdNjBC1sZor
         MHlqbeIH0FKbyQwLuSalf5sdVWU6oxOyTbCq/9kt8VYdI7b73wrR4CWZJde1lDbd1ah/
         vm/yZlVib7xL7HHjLQSWOAglBadKngX3I6D8arg0YHxzdEH9vT84DaqHcF88b5GZoiEI
         LJCBNuJtT3ZuhYc617vddkf9amirw2/8/rNnUcDbDJ7IDR8iCBOAeqZXWD0i6GkjNTzd
         M3Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g9ItWJvuw8gRUB1rJe3KyukTXGtR2DFnpKkYpk2JtII=;
        b=VDZS0DJl138aLu55qdyozu2rN48JZryil+Ovq8HV8xT5d7N9ok8r4WxGFdMWZKsb8P
         jM3pVET+BwzkOPRHkuKys/AIszvN08pNbQO9zi3w0lafOtYgp13f38OJf0R7Rq4ncBMS
         c84Gny7gTboVnATDTbPU1K8PGEs2cKN+ZLAHERf7TQsZWmM3RejhjWddPxYcEcSTdTgQ
         OKdq7eZ3TCMXjuTLhpkoJLppGg2o8IdV4c18QxVgTxJW/AbKde/YAZZdKDwtPnq0zJXf
         Yo5Wip4PUcRh2tZh8OB+MCwwtkQmGtxCsKXaqSs8pbEw2Sig6xdUTp+/f0X4ovTmN6YF
         naQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vpqpT4qUzu0Yptv5QRRpYIVpOCN+QBZjcH4azXRqeZH7twxtv
	/huYsZyPgRNUhntjW4OLQhE=
X-Google-Smtp-Source: ABdhPJxwoL/L1sKpESH5pMXVuCSK/zowxXBAjeNHY3aeeiCOG0I2AgIsOXsAFX9amB04C+z/htTi9w==
X-Received: by 2002:a25:d691:: with SMTP id n139mr34304956ybg.27.1628075648220;
        Wed, 04 Aug 2021 04:14:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:790b:: with SMTP id u11ls247879ybc.3.gmail; Wed, 04 Aug
 2021 04:14:07 -0700 (PDT)
X-Received: by 2002:a25:da4f:: with SMTP id n76mr34804990ybf.121.1628075647754;
        Wed, 04 Aug 2021 04:14:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628075647; cv=none;
        d=google.com; s=arc-20160816;
        b=StxXDp2TJQtrEL0FpGItvhFWhqVfubQuR5RBp7TUEUKNQKvVXOOjqujUV2xEPjJyPa
         6rSppa3ITwpOorQ3pTtw8mohJyoddplxTyea4I645Sh66dMXrt9adrZDB705bwNP3IPo
         sU6zNWULvLqeRAjDhg036lZQ+7/y69WTth8yX1AbYHUUfQXafv9sl9Hb1wb7KLpV7TMf
         1Hcc+fvvl9+3lM44PizeHus1lK7cJUNQxnJ0AXp8E1sVnPKvbpaV1Yab9Eg6ayRXP/k1
         Lr0tBWFXPMExo7Qm7M7RwyxglXyxOPQGdN3+TjIC0LHri7Xl+yIJs9AOgmxoshZxMueY
         0dYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=XxKNPFN1haWQ4ktn56VeOzhBewonljimmOlql60okmY=;
        b=eOWICylytwHARZjORyJxvlv7Shl6MHSPXjqMuibh445uIeigd63KilDr+R5MjLFibP
         DHkxjB1MEme4D3OK1/OdmzX1p3lC0VvPXVXDS/QMdMO77SCXsZ5IcOAqzy8VTF9NiPiC
         mCEMczOKSJWYyPy8hGt5UjL0jc1DJfY8WfzaSrq1H+lYSWBbxANNEl/PQ+quUnjmuum3
         +uHpHsbMe0jQBG6KwfM1UzUlTL4Upvqraj3/HnJKhh7++T/z7xPIMmeGeHnmlSwXUtOG
         QEskNo4BwYKeIrTOf75iaDZRcOx/0fGu56UgGlaTzv6lNF3CaSuKB8H3ONZDKLPtvbm7
         XwDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n10si103218ybj.2.2021.08.04.04.14.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 04:14:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 224EA60FC4;
	Wed,  4 Aug 2021 11:14:04 +0000 (UTC)
Date: Wed, 4 Aug 2021 12:14:02 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH v2 1/3] vmalloc: Choose a better start address in
 vm_area_register_early()
Message-ID: <20210804111402.GB4857@arm.com>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-2-wangkefeng.wang@huawei.com>
 <20210801152311.GB28489@arm.com>
 <0de87be6-7041-c58b-a01f-3d6e3333c6f0@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <0de87be6-7041-c58b-a01f-3d6e3333c6f0@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Aug 02, 2021 at 10:39:04AM +0800, Kefeng Wang wrote:
> On 2021/8/1 23:23, Catalin Marinas wrote:
> > On Tue, Jul 20, 2021 at 10:51:03AM +0800, Kefeng Wang wrote:
> > > There are some fixed locations in the vmalloc area be reserved
> > > in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
> > > pcpu_page_first_chunk(), it calls vm_area_register_early() and
> > > choose VMALLOC_START as the start address of vmap area which
> > > could be conflicted with above address, then could trigger a
> > > BUG_ON in vm_area_add_early().
> > >=20
> > > Let's choose the end of existing address range in vmlist as the
> > > start address instead of VMALLOC_START to avoid the BUG_ON.
> > >=20
> > > Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> > > ---
> > >   mm/vmalloc.c | 8 +++++---
> > >   1 file changed, 5 insertions(+), 3 deletions(-)
> > >=20
> > > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > > index d5cd52805149..a98cf97f032f 100644
> > > --- a/mm/vmalloc.c
> > > +++ b/mm/vmalloc.c
> > > @@ -2238,12 +2238,14 @@ void __init vm_area_add_early(struct vm_struc=
t *vm)
> > >    */
> > >   void __init vm_area_register_early(struct vm_struct *vm, size_t ali=
gn)
> > >   {
> > > -	static size_t vm_init_off __initdata;
> > > +	unsigned long vm_start =3D VMALLOC_START;
> > > +	struct vm_struct *tmp;
> > >   	unsigned long addr;
> > > -	addr =3D ALIGN(VMALLOC_START + vm_init_off, align);
> > > -	vm_init_off =3D PFN_ALIGN(addr + vm->size) - VMALLOC_START;
> > > +	for (tmp =3D vmlist; tmp; tmp =3D tmp->next)
> > > +		vm_start =3D (unsigned long)tmp->addr + tmp->size;
> > > +	addr =3D ALIGN(vm_start, align);
> > >   	vm->addr =3D (void *)addr;
> > >   	vm_area_add_early(vm);
> > Is there a risk of breaking other architectures? It doesn't look like t=
o
> > me but I thought I'd ask.
>=20
> Before this patch, vm_init_off is to record the offset from VMALLOC_START=
,
>=20
> but it use VMALLOC_START as start address on the function
> vm_area_register_early()
>=20
> called firstly,=C2=A0 this will cause the BUG_ON.
>=20
> With this patch, the most important change is that we choose the start
> address via
>=20
> dynamic calculate the 'start' address by traversing the list.
>=20
> [wkf@localhost linux-next]$ git grep vm_area_register_early
> arch/alpha/mm/init.c: vm_area_register_early(&console_remap_vm, PAGE_SIZE=
);
> arch/x86/xen/p2m.c:=C2=A0=C2=A0=C2=A0=C2=A0 vm_area_register_early(&vm, P=
MD_SIZE *
> PMDS_PER_MID_PAGE);
> mm/percpu.c:=C2=A0=C2=A0=C2=A0 vm_area_register_early(&vm, PAGE_SIZE);
> [wkf@localhost linux-next]$ git grep vm_area_add_early
> arch/arm/mm/ioremap.c:=C2=A0 vm_area_add_early(vm);
> arch/arm64/mm/mmu.c:=C2=A0=C2=A0=C2=A0 vm_area_add_early(vma);
>=20
> x86/alpha won't call vm_area_add_early(), only arm64 could call both vm_a=
rea_add_early()
> and  vm_area_register_early() when this patchset is merged. so it won't b=
reak other architectures.

Thanks for checking.

> > Also, instead of always picking the end, could we search for a range
> > that fits?
>=20
> We only need a space in vmalloc range,=C2=A0 using end or a range in the =
middle
> is not different.

I was thinking of making it more future-proof in case one registers a
vm area towards the end of the range. It's fairly easy to pick a range
in the middle now that you are adding a list traversal.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210804111402.GB4857%40arm.com.
