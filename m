Return-Path: <kasan-dev+bncBAABBHMWZSAQMGQEEKEAO2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 892DA320F34
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 02:38:38 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id t18sf6735649qva.6
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 17:38:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613957917; cv=pass;
        d=google.com; s=arc-20160816;
        b=p0sSqxBFRQa1zeltlAtyZRt9WpbCJEqF6OW5f6WD44ZyJNJHcjo1XPB+gysF+spW6H
         p8ajtOFG3zQNsljgMjakcFHIc1FHkp3kWYx/8yKsunukJGzoa29+77OTDPjPfqU0eLUR
         AZ4lqUipm2KhdUSb+j/fBJkEZXEudpLHvTHc2lQaFcZfxvU3hM1NclJY4R59RlsN1mml
         hJQFj0DiC0WtMgI6XjTDrj20HPV/nSKvj3XvH+akaJj4Zcl7e+gm22Td656+HhTPVd2L
         5+tgP5KgO/fvjJ0ZO0Gxn3ofzYoOU1ATmgLzjY6K8t/WEyVqydLBACcHCZ1z/4I7M01c
         N1sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=xPhJKrG1NGmkga7kofKVi9RVQNyjnOBuczJaOeWGXbQ=;
        b=DQ/swYK7teda53/9YFACAnPkfRXjC4p6n2xVY6VXiZH2d6VtlOUu7iMAjSvOJsRXj1
         yMgWqwtixe/6T0OdjmslYBFdWwjuRalIqO+kabaPwDu6txMjeaLn131iwdd2lRH9yhUW
         T2gHGmQIz+fABTMOehdoQNYEN8EmsLCK5VJWHsmYTMO/3Q1IG5Jyz97EVITnzojYr4SQ
         AD3e9n22sr68DON1qQvEWrnnzw94a08iEwf7qAtHa2ZSyqYqT8vCgDyLwr5wiyVYRrS+
         4/B7gags5gryZrZSY5u/AiAUA8UHX2aftun0VLWU4ItIOEcqo+FI5dg+HvdFHxH181ot
         cGDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPhJKrG1NGmkga7kofKVi9RVQNyjnOBuczJaOeWGXbQ=;
        b=k+/qffH1evwUQob2RSUzpgrlOMnope5HhmNh25ky+Xsd4rpyOYbx5zGjZnx29A1sOR
         +jgq7EdzY3nFITUJ0wHbco4pbZHG7A3fTiukZpoEYdVBXGJcJcNzCVTMP2Uyo9tv8ViB
         yUjSN8/M0+uX3lALwMSBxtLrxhWOSJcpwM3jU9Dd98uBHWAyP2qsVTtnIPS8Aj7eIcMT
         UTk42AhSGTJqyLQ/9KtbYWXthwVDinhOF/C2YmIw72KpTUjZQIPKjFlTgYjhmjpHOU35
         w9gj67PioS5QRVRz93wQvD5aGrPZhi9eP/KQOMSCKlOtVRvUc8s7O2D51g+9AjkV703A
         qeJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPhJKrG1NGmkga7kofKVi9RVQNyjnOBuczJaOeWGXbQ=;
        b=rOStaP0xTxa5suwuGg56Mfw3soU5vPjWoQGiNGlNc+PIPk+mTRMiD/SVzBS98pwZCt
         SwqTZJHfwZ5QlimxEbQ45BljPJpuWRR7/ouv7DaA8N7B9UqFXAWIAv5BSw0ybWz1T+m3
         R25dANq/GWt+VfhYSufL1jo++UsVDPofSEhzTtXJivHzjC+tMuRfPx1S/FYlI8WvQ2y8
         Fdr+b1VUfDam5dLOIdrZqfAEE8Ztm3dpXAu+ifQXA2eUGICjKGKd2pYY77McyIT9GPI2
         0wJFGasMk2gb7AgNKkV1SE6KChiliJDdp1LOEGuUucMfCO2f1GmT2BMOLCvKMRZlw8hZ
         VHBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532j3jmpuzoSPxuZZfCWThmR7sO5uhG/u+JCyqsO1WCbJcSbZoXt
	MAGMR2cU8QouG0M0abe1xKQ=
X-Google-Smtp-Source: ABdhPJzZcptsh9fQHRsrfy7J7zm24/jPs74zlaps0h7kvtExbrGtmDlbzQQXYUk3eZJ6PrYBQqlUhQ==
X-Received: by 2002:aed:210e:: with SMTP id 14mr18929445qtc.118.1613957917311;
        Sun, 21 Feb 2021 17:38:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a04:: with SMTP id n4ls5834302qta.5.gmail; Sun, 21 Feb
 2021 17:38:36 -0800 (PST)
X-Received: by 2002:ac8:6888:: with SMTP id m8mr18000685qtq.71.1613957916812;
        Sun, 21 Feb 2021 17:38:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613957916; cv=none;
        d=google.com; s=arc-20160816;
        b=mJ3V3zfX/UHYBsDvqePYDpjUKivkRvpYOUSki4G5chkCjorw4gxlPSwRV+lrdSzQxr
         p4mw1e3VS2HY7WWP8UxQIOiccSWcwsZrA4k2UZxrchfbg1dD6k09m4T8K54MpkdOFdGh
         sNt/3H6tSBNq7ByablpGaS3Z+Ja5tdOeO53eEdzmiWaD/dn2DWP6pVQAUVBgLFegQM01
         ImOmZrfLr1EBHCL1bnTdJDyo19gs10DspwTi2TtoOE41ovhkdT7RKfTJmumPpPxfpRrF
         WkwA16UazQrXraBlldkmKqzdx4G3d0vfMfzOq4D4Qy+Tc7khQJV6ZSuFI2rjck/dfmEW
         9fIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=Npq6+HX95g84tqBZAPdx78Tdzud5uX5Gbt9x6e+QKk8=;
        b=uvIan9fFXHYVGFy8iBhs+aJ+De1B+n6rd0oqsDeAFVLdFXXqPOGD+Uck7srzrzBI6W
         v+oXa44u0T8NTD7uR/LnWLgUPVssRL0XptyzsL1JUALNSHJEr5qGrOcWXsd+BTBmCN42
         H+H57l1/SkE1uQM18NhYmyUROEn7FZ0JQU0T0HypNEuD/ot6dj2AHANpsic3A/Hn8wWW
         XV/9ZtdAfGxcxtJS2LQ7frTzx6RTPsqQM4y4MYw8zBCuYP7e6lmKZJnTmeAD2QgeOrVS
         INfyRfH7So7xs1GRpoILL44OnEux0/MHSdecpA/Ksms5E3HtqiKWQPi7e2znc/YwtIGD
         CJXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (atcsqr.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id d12si795566qkn.0.2021.02.21.17.38.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Feb 2021 17:38:36 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 11M1WPsm063709;
	Mon, 22 Feb 2021 09:32:25 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Mon, 22 Feb 2021
 09:37:55 +0800
Date: Mon, 22 Feb 2021 09:37:55 +0800
From: Nylon Chen <nylon7@andestech.com>
To: Alex Ghiti <alex@ghiti.fr>
CC: Palmer Dabbelt <palmer@dabbelt.com>,
        "aou@eecs.berkeley.edu"
	<aou@eecs.berkeley.edu>,
        Nick Chun-Ming =?utf-8?B?SHUo6IOh5bO76YqYKQ==?=
	<nickhu@andestech.com>,
        Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?=
	<alankao@andestech.com>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        "nylon7717@gmail.com" <nylon7717@gmail.com>,
        "glider@google.com" <glider@google.com>,
        Paul Walmsley
	<paul.walmsley@sifive.com>,
        "aryabinin@virtuozzo.com"
	<aryabinin@virtuozzo.com>,
        "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>,
        "dvyukov@google.com" <dvyukov@google.com>
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
Message-ID: <20210222013754.GA7626@andestech.com>
References: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
 <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
 <4fa97788-157c-4059-ae3f-28ab074c5836@ghiti.fr>
 <e15fbf55-25db-7f91-6feb-fb081ab60cdb@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <e15fbf55-25db-7f91-6feb-fb081ab60cdb@ghiti.fr>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 11M1WPsm063709
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

Hi Alex, Palmer

Sorry I missed this message.
On Sun, Feb 21, 2021 at 09:38:04PM +0800, Alex Ghiti wrote:
> Le 2/13/21 =C3=A0 5:52 AM, Alex Ghiti a =C3=A9crit=C2=A0:
> > Hi Nylon, Palmer,
> >=20
> > Le 2/8/21 =C3=A0 1:28 AM, Alex Ghiti a =C3=A9crit=C2=A0:
> >> Hi Nylon,
> >>
> >> Le 1/22/21 =C3=A0 10:56 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> >>> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
> >>>> It references to x86/s390 architecture.
> >>>> >> So, it doesn't map the early shadow page to cover VMALLOC space.
> >>>>
> >>>> Prepopulate top level page table for the range that would otherwise =
be
> >>>> empty.
> >>>>
> >>>> lower levels are filled dynamically upon memory allocation while
> >>>> booting.
> >>
> >> I think we can improve the changelog a bit here with something like th=
at:
> >>
> >> "KASAN vmalloc space used to be mapped using kasan early shadow page.=
=20
> >> KASAN_VMALLOC requires the top-level of the kernel page table to be=20
> >> properly populated, lower levels being filled dynamically upon memory=
=20
> >> allocation at runtime."
> >>
> >>>>
> >>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
> >>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
> >>>> ---
> >>>> =C2=A0arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 1 +
> >>>> =C2=A0arch/riscv/mm/kasan_init.c | 57 ++++++++++++++++++++++++++++++=
+++++++-
> >>>> =C2=A02 files changed, 57 insertions(+), 1 deletion(-)
> >>>>
> >>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> >>>> index 81b76d44725d..15a2c8088bbe 100644
> >>>> --- a/arch/riscv/Kconfig
> >>>> +++ b/arch/riscv/Kconfig
> >>>> @@ -57,6 +57,7 @@ config RISCV
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64BIT
> >>>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
> >>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> >>>> index 12ddd1f6bf70..4b9149f963d3 100644
> >>>> --- a/arch/riscv/mm/kasan_init.c
> >>>> +++ b/arch/riscv/mm/kasan_init.c
> >>>> @@ -9,6 +9,19 @@
> >>>> =C2=A0#include <linux/pgtable.h>
> >>>> =C2=A0#include <asm/tlbflush.h>
> >>>> =C2=A0#include <asm/fixmap.h>
> >>>> +#include <asm/pgalloc.h>
> >>>> +
> >>>> +static __init void *early_alloc(size_t size, int node)
> >>>> +{
> >>>> +=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size,
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), M=
EMBLOCK_ALLOC_ACCESSIBLE, node);
> >>>> +
> >>>> +=C2=A0=C2=A0=C2=A0 if (!ptr)
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to al=
locate %zu bytes align=3D%zx nid=3D%d=20
> >>>> from=3D%llx\n",
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
__func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
> >>>> +
> >>>> +=C2=A0=C2=A0=C2=A0 return ptr;
> >>>> +}
> >>>>
> >>>> =C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
> >>>> =C2=A0asmlinkage void __init kasan_early_init(void)
> >>>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void *en=
d)
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
> >>>> =C2=A0}
> >>>>
> >>>> +void __init kasan_shallow_populate(void *start, void *end)
> >>>> +{
> >>>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & P=
AGE_MASK;
> >>>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long=
)end);
> >>>> +=C2=A0=C2=A0=C2=A0 unsigned long pfn;
> >>>> +=C2=A0=C2=A0=C2=A0 int index;
> >>>> +=C2=A0=C2=A0=C2=A0 void *p;
> >>>> +=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
> >>>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
> >>>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
> >>>> +
> >>>> +=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vadd=
r);
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SAT=
P) & SATP_PPN;
> >>
> >> At this point in the boot process, we know that we use swapper_pg_dir=
=20
> >> so no need to read SATP.
> >>
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pfn=
_to_virt(pfn) + index;
> >>
> >> Here, this pgd_dir assignment is overwritten 2 lines below, so no need=
=20
> >> for it.
> >>
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd + =
index;
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_k=
(vaddr);
> >>
> >> pgd_offset_k(vaddr) =3D init_mm.pgd + pgd_index(vaddr) so pgd_k =3D=3D=
 pgd_dir.
> >>
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k)=
;
> >>>> +
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(p=
gd_dir, vaddr);
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_offs=
et(pgd_k, vaddr);
> >>>> +
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_S=
IZE) & PUD_MASK;
> >>
> >> Why do you increase vaddr *before* populating the first one ? And=20
> >> pud_addr_end does that properly: it returns the next pud address if it=
=20
> >> does not go beyond end address to map.
> >>
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(p=
4d_dir, vaddr);
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4d=
_k, vaddr);
> >>>> +
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_dir=
)) {
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
pud_populate(&init_mm, pud_dir, p);
> >>
> >> init_mm is not needed here.
> >>
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
> >>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;
> >>
> >> Why do you need to add PAGE_SIZE ? vaddr already points to the next pu=
d.
> >>
> >> It seems like this patch tries to populate userspace page table=20
> >> whereas at this point in the boot process, only swapper_pg_dir is used=
=20
> >> or am I missing something ?
> >>
> >> Thanks,
> >>
> >> Alex
> >=20
> > I implemented this morning a version that fixes all the comments I made=
=20
> > earlier. I was able to insert test_kasan_module on both sv39 and sv48=
=20
> > without any modification: set_pgd "goes through" all the unused page=20
> > table levels, whereas p*d_populate are noop for unused levels.
> >=20
> > If you have any comment, do not hesitate.
> >=20
> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > index adbf94b7e68a..d643b222167c 100644
> > --- a/arch/riscv/mm/kasan_init.c
> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -195,6 +195,31 @@ static void __init kasan_populate(void *start, voi=
d=20
> > *end)
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_SHADOW_=
INIT, end - start);
> >  =C2=A0}
> >=20
> >=20
> > +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned=
=20
> > long end)
> > +{
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long next;
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *p;
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(vad=
dr);
> > +
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 do {
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr, end);
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned=20
> > long)lm_alias(kasan_early_shadow_pgd_next)) {
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =3D membl=
ock_alloc(PAGE_SIZE, PAGE_SIZE);
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd=
_k, pfn_pgd(PFN_DOWN(__pa(p)),=20
> > PAGE_TABLE));
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 }
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next,=
 vaddr !=3D end);
> > +}
> > +
>=20
> This way of going through the page table seems to be largely used across=
=20
> the kernel (cf KASAN population functions of arm64/x86) so I do think=20
> this patch brings value to Nylon and Nick's patch.
>=20
> I can propose a real patch if you agree and I'll add a co-developed by=20
> Nylon/Nick since this only 'improves' theirs.
>=20
> Thanks,
>=20
> Alex
>
I agree with your proposal, but when I try your patch that it dosen't work
because `kasan_early_shadow_pgd_next` function wasn't define.

Do you have complete patch? or just I missed some content?
> > +void __init kasan_shallow_populate(void *start, void *end)
> > +{
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned=
 long)start & PAGE_MASK;
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN=
((unsigned long)end);
> > +
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pgd(vaddr,=
 vend);
> > +
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
> > +}
> > +
> >  =C2=A0void __init kasan_init(void)
> >  =C2=A0{
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
> > @@ -206,7 +231,15 @@ void __init kasan_init(void)
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow=
((void *)KASAN_SHADOW_START,
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)=
kasan_mem_to_shadow((void *)
> > - VMALLOC_END));
> > + VMEMMAP_END));
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMALL=
OC))
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_shallow_populate(
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_START),
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_END));
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_populate_early_shadow(
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_START),
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_END));
> >=20
> >=20
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Populate the linear mapp=
ing */
> >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_sta=
rt, &_end) {

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210222013754.GA7626%40andestech.com.
