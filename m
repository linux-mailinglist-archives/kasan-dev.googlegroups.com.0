Return-Path: <kasan-dev+bncBAABBSUT6LXQKGQETFR5XCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DD2A312775D
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2019 09:43:54 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id j23sf2655688lji.23
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2019 00:43:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576831434; cv=pass;
        d=google.com; s=arc-20160816;
        b=uiPuuYX5/P/pRPB9vgcCkpHBalHtyUUolXVHV3j96aKJlvUjp8rI0D0cZVfbxHVhzY
         iYT9MkdqJlAztqhuMBNdfMJNiZgb2GaBoD/TDU4+1C3H67O4LeHbmVB5cqbE14ftAu9F
         +Kmgx6rh38VFOjTDQyPCCe/VSB46BIa6PmdkT+9clqfXIpb2kMtFd2Ov9ycn1Cc+yIe8
         cKV8uBcZy16iogi7cVvlhilZOM52aYQDAWGBfLehjVmLTr3tXDB1hcjAznzQGVkXoX70
         JHzAcLawLzQi2L7Uw/VQe8n1s58teKl8BFvPSsX5rKlepS1ydB36nItVu31GZAZTcop+
         1+zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=qJlQvrdBvXzt1XtPTsxhw8nTLWMGJtlpIjQjNK2OyoQ=;
        b=Cx+UL9e1muhYKUQZHejMs8BvBC9FGbd6siUZPPLS8fZ0OrSbIzKWwZBnOZfk82yg+b
         QT52aX5BjnP9yYwI3bb5TXFmjQG8uyOI4QpxR3H/+AqKHeCy9NwQZl+t4ooEXX8U9zS1
         dpRlVQ4JxYiLQ0qoooywTQDyfCgneAvIPdkR2X2QoO7C7nIH0WtXXA9pW0s8g/KTpc6q
         u107OYUvVi8aX5nptEbap7nGqlh0/KsFnuweMPebpRP06ywaHKc+w+PN5THuMkMS32pN
         UsHgcSiG6oiAB6u3hJ+ZUme/oq8nMBsKm9cwWNF64nCm7yKMUVfe+cfo9s84DKHnzUnF
         N/Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJlQvrdBvXzt1XtPTsxhw8nTLWMGJtlpIjQjNK2OyoQ=;
        b=VYpCCOVaP5bVCUYswo6vpoIH+br5XyRrUrPiRbKoZsBBuSDaBk5Gs8j05mIsSkFmaM
         MByZ2oEAZ3LwiOzqcFS6famPg5mvHUk8Wyfb3j7ebRQmwaCuAFbYx2mTF/dGCHh+ohd8
         IfQSjJH17F02gxMDtq7MMuVfzHCIT7uuQ6lhwt9m8+O99O7pcLUNOz7T8Y1TnuJwtqTL
         q5blLyxbBPXUYKMVsbznUtuQ+wL9ekbHRIuOcqHZ8TRTBdlVzpquSmdB0LWNMmxqmQ1b
         6jfnvgTNjOsTH7G/p9v38escYTFF7u1NO4nB0bpQoWBkhAUm7Ya4S8yteXyGrAWqTim1
         oEYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJlQvrdBvXzt1XtPTsxhw8nTLWMGJtlpIjQjNK2OyoQ=;
        b=RqN40en9yn15iD9MnT6vsrGzTsxh7uZRJfGW+RM7mipZCqBJAnC10fYWCY52ePhI2N
         yC6cVYVuxmAZ4zWj6/NvXdgYd+u3CHs6bJx5LlwvIa+3e+fS/fuuzCvSD0z3FSQQLjTA
         FU+LSZQnJyrpn9p45jhU6u5mFoGLAeCA5KEdWKVjPIpgCqxoTswVu73TCVSl+/GBM4hP
         AQaGStERtRLRkcSgSz+OBsb8bMblI05xgEpdqfkWtXJAvfOjU9sVe94ZH/wsbx4hpBBN
         64ceojkF09O0PSjoS66TDYf9f1g/s7RsIBzRODv7f22sqSfizAcz69hcrMyaaZI0dqxj
         NEXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVDvM35V/3dv1GzLrt7iMm8mfAqnsricJFZcAbUTiy4DT2n45BU
	SQPlad0w8GRBSc5plGap+Ek=
X-Google-Smtp-Source: APXvYqz1cZYlLMA85KJQLgs7FglzJhvvSmvC6S48+XfoJXGAvteWeUB5dq4JL+VwawVk04kvG6bg1w==
X-Received: by 2002:a2e:884d:: with SMTP id z13mr9093866ljj.116.1576831434383;
        Fri, 20 Dec 2019 00:43:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4e7:: with SMTP id s7ls1195440ljm.10.gmail; Fri, 20 Dec
 2019 00:43:53 -0800 (PST)
X-Received: by 2002:a05:651c:153:: with SMTP id c19mr9121301ljd.237.1576831433758;
        Fri, 20 Dec 2019 00:43:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576831433; cv=none;
        d=google.com; s=arc-20160816;
        b=qK2T4suqvvh064DpqL7YHf8ALMtZkV8G8C6LNiYytzR6IemDOmvH8G4e1Ng493pV4R
         H6FwsxW9taqf5c6euS2kaJcD6w8/n4mqqaEE5jhAXiWKEusv787ShTcZQOwFknjnGp9/
         Fqr9YgjSnKOhM91UhwNoYuPqf71n2Z9iTndEu5PwhKbE8dxiOuZ4/EICQt2diW8EV/Ai
         cOX6bYvyW7irHpKLGA8ljO3SW7yziNRkC3v7jWtPKyyFy+rNolr0ksIcdv5D+9ykm2QC
         5qgfwLAe4+YM7Kw7qMEYynnwmeU8Ke2r1ZgD3eFHTmj5/Me97vFEzKuJn5tGaJ5wqujK
         hY6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=qt9mgfR2rmmvs1gMjcvkd2T+EuKVGNlQggjK0UrAnMA=;
        b=kzVb/N3flZ0MI+CABMfk1kRwPGs34enVSpCcoCaY3HPn7YiZhHKzLv1epZmIhJMa/i
         7JayrJYArw0z1syWoaasxgJ0ejCIRQwi1JPHnSFxRxcqtDDPyxkEwtnWxlID6tOo6LK2
         Vyv0seWdS2HIAXRbeAc5F3Y5t4Uo7oITCZkIiQaqPewdq79r/Je2avGiWsHSFrUX8KQi
         5f0VSDorgCLWf2lyq6k4E+ab1tdiC02uTrRBmAFLNM+9Vp0NjhAGahdUYOKoz7d4NAuc
         FVDHQyomI4pH7JZJlZ8JNCiWgx8X9gZhBPUkZLXV0JTPYjTw2govhfIf415yuJ6PwoOG
         AIbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id e3si335945ljg.2.2019.12.20.00.43.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Dec 2019 00:43:53 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 89C7AAE35;
	Fri, 20 Dec 2019 08:43:52 +0000 (UTC)
Subject: Re: [RFC PATCH 1/3] x86/xen: add basic KASAN support for PV kernel
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Boris Ostrovsky <boris.ostrovsky@oracle.com>,
 Stefano Stabellini <sstabellini@kernel.org>,
 George Dunlap <george.dunlap@citrix.com>,
 Ross Lagerwall <ross.lagerwall@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
 <20191217140804.27364-2-sergey.dyasli@citrix.com>
 <934a2950-9079-138d-5476-5eabd84dfec5@suse.com>
 <0844c8f9-3dd3-2313-5c23-bd967b218af2@citrix.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <43f35219-ec39-810b-ebfd-16c14e7b6150@suse.com>
Date: Fri, 20 Dec 2019 09:43:44 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.1
MIME-Version: 1.0
In-Reply-To: <0844c8f9-3dd3-2313-5c23-bd967b218af2@citrix.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=jgross@suse.com
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

On 19.12.19 17:42, Sergey Dyasli wrote:
> On 18/12/2019 09:24, J=C3=BCrgen Gro=C3=9F wrote:
>> On 17.12.19 15:08, Sergey Dyasli wrote:
>>> This enables to use Outline instrumentation for Xen PV kernels.
>>>
>>> KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
>>> and hence disabled.
>>>
>>> Rough edges in the patch are marked with XXX.
>>>
>>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>>> ---
>>>    arch/x86/mm/init.c          | 14 ++++++++++++++
>>>    arch/x86/mm/kasan_init_64.c | 28 ++++++++++++++++++++++++++++
>>>    arch/x86/xen/Makefile       |  7 +++++++
>>>    arch/x86/xen/enlighten_pv.c |  3 +++
>>>    arch/x86/xen/mmu_pv.c       | 13 +++++++++++--
>>>    arch/x86/xen/multicalls.c   | 10 ++++++++++
>>>    drivers/xen/Makefile        |  2 ++
>>>    kernel/Makefile             |  2 ++
>>>    lib/Kconfig.kasan           |  3 ++-
>>>    9 files changed, 79 insertions(+), 3 deletions(-)
>>>
>>> diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
>>> index e7bb483557c9..0c98a45eec6c 100644
>>> --- a/arch/x86/mm/init.c
>>> +++ b/arch/x86/mm/init.c
>>> @@ -8,6 +8,8 @@
>>>    #include <linux/kmemleak.h>
>>>    #include <linux/sched/task.h>
>>>    +#include <xen/xen.h>
>>> +
>>>    #include <asm/set_memory.h>
>>>    #include <asm/e820/api.h>
>>>    #include <asm/init.h>
>>> @@ -835,6 +837,18 @@ void free_kernel_image_pages(const char *what, voi=
d *begin, void *end)
>>>        unsigned long end_ul =3D (unsigned long)end;
>>>        unsigned long len_pages =3D (end_ul - begin_ul) >> PAGE_SHIFT;
>>>    +    /*
>>> +     * XXX: skip this for now. Otherwise it leads to:
>>> +     *
>>> +     * (XEN) mm.c:2713:d157v0 Bad type (saw 8c00000000000001 !=3D exp =
e000000000000000) for mfn 36f40 (pfn 02f40)
>>> +     * (XEN) mm.c:1043:d157v0 Could not get page type PGT_writable_pag=
e
>>> +     * (XEN) mm.c:1096:d157v0 Error getting mfn 36f40 (pfn 02f40) from=
 L1 entry 8010000036f40067 for l1e_owner d157, pg_owner d157
>>> +     *
>>> +     * and further #PF error: [PROT] [WRITE] in the kernel.
>>> +     */
>>> +    if (xen_pv_domain() && IS_ENABLED(CONFIG_KASAN))
>>> +        return;
>>> +
>>
>> I guess this is related to freeing some kasan page tables without
>> unpinning them?
>=20
> Your guess was correct. Turned out that early_top_pgt which I pinned and =
made RO
> is located in .init section and that was causing issues. Unpinning it and=
 making
> RW again right after kasan_init() switches to use init_top_pgt seem to fi=
x this
> issue.
>=20
>>
>>>        free_init_pages(what, begin_ul, end_ul);
>>>          /*
>>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>>> index cf5bc37c90ac..caee2022f8b0 100644
>>> --- a/arch/x86/mm/kasan_init_64.c
>>> +++ b/arch/x86/mm/kasan_init_64.c
>>> @@ -13,6 +13,8 @@
>>>    #include <linux/sched/task.h>
>>>    #include <linux/vmalloc.h>
>>>    +#include <xen/xen.h>
>>> +
>>>    #include <asm/e820/types.h>
>>>    #include <asm/pgalloc.h>
>>>    #include <asm/tlbflush.h>
>>> @@ -20,6 +22,9 @@
>>>    #include <asm/pgtable.h>
>>>    #include <asm/cpu_entry_area.h>
>>>    +#include <xen/interface/xen.h>
>>> +#include <asm/xen/hypervisor.h>
>>> +
>>>    extern struct range pfn_mapped[E820_MAX_ENTRIES];
>>>      static p4d_t tmp_p4d_table[MAX_PTRS_PER_P4D] __initdata __aligned(=
PAGE_SIZE);
>>> @@ -305,6 +310,12 @@ static struct notifier_block kasan_die_notifier =
=3D {
>>>    };
>>>    #endif
>>>    +#ifdef CONFIG_XEN
>>> +/* XXX: this should go to some header */
>>> +void __init set_page_prot(void *addr, pgprot_t prot);
>>> +void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn);
>>> +#endif
>>> +
>>
>> Instead of exporting those, why don't you ...
>>
>>>    void __init kasan_early_init(void)
>>>    {
>>>        int i;
>>> @@ -332,6 +343,16 @@ void __init kasan_early_init(void)
>>>        for (i =3D 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>>>            kasan_early_shadow_p4d[i] =3D __p4d(p4d_val);
>>>    +    if (xen_pv_domain()) {
>>> +        /* PV page tables must have PAGE_KERNEL_RO */
>>> +        set_page_prot(kasan_early_shadow_pud, PAGE_KERNEL_RO);
>>> +        set_page_prot(kasan_early_shadow_pmd, PAGE_KERNEL_RO);
>>> +        set_page_prot(kasan_early_shadow_pte, PAGE_KERNEL_RO);
>>
>> add a function doing that to mmu_pv.c (e.g. xen_pv_kasan_early_init())?
>=20
> Sounds like a good suggestion, but new functions still need some header f=
or
> declarations (xen/xen.h?). And kasan_map_early_shadow() will need exporti=
ng

xen/xen-ops.h

> through kasan.h as well, but that's probably not an issue.

You could let the new function return (pgd_t *)xen_start_info->pt_base
and use that here, e.g.:

if (xen_pv_domain()) {
     pgd_t *pgd;

     pgd =3D xen_kasan_early_init();
     kasan_map_early_shadow(pgd);
}

>=20
>>
>>> +
>>> +        /* Add mappings to the initial PV page tables */
>>> +        kasan_map_early_shadow((pgd_t *)xen_start_info->pt_base);
>>> +    }
>>> +
>>>        kasan_map_early_shadow(early_top_pgt);
>>>        kasan_map_early_shadow(init_top_pgt);
>>>    }
>>> @@ -369,6 +390,13 @@ void __init kasan_init(void)
>>>                    __pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
>>>        }
>>>    +    if (xen_pv_domain()) {
>>> +        /* PV page tables must be pinned */
>>> +        set_page_prot(early_top_pgt, PAGE_KERNEL_RO);
>>> +        pin_pagetable_pfn(MMUEXT_PIN_L4_TABLE,
>>> +                  PFN_DOWN(__pa_symbol(early_top_pgt)));
>>
>> and another one like xen_pv_kasan_init() here.
>=20
> Now there needs to be a 3rd function to unpin early_top_pgt.

Not if you do the load_cr3 in the xen pv case in the new function:

if (xen_pv_domain())
     xen_kasan_load_cr3(early_top_pgt);
else
     load_cr3(early_top_pgt);

>=20
>>
>>> +    }
>>> +
>>>        load_cr3(early_top_pgt);
>>>        __flush_tlb_all();
>>>    diff --git a/arch/x86/xen/Makefile b/arch/x86/xen/Makefile
>>> index 084de77a109e..102fad0b0bca 100644
>>> --- a/arch/x86/xen/Makefile
>>> +++ b/arch/x86/xen/Makefile
>>> @@ -1,3 +1,10 @@
>>> +KASAN_SANITIZE_enlighten_pv.o :=3D n
>>> +KASAN_SANITIZE_enlighten.o :=3D n
>>> +KASAN_SANITIZE_irq.o :=3D n
>>> +KASAN_SANITIZE_mmu_pv.o :=3D n
>>> +KASAN_SANITIZE_p2m.o :=3D n
>>> +KASAN_SANITIZE_multicalls.o :=3D n
>>> +
>>>    # SPDX-License-Identifier: GPL-2.0
>>>    OBJECT_FILES_NON_STANDARD_xen-asm_$(BITS).o :=3D y
>>>    diff --git a/arch/x86/xen/enlighten_pv.c b/arch/x86/xen/enlighten_pv=
.c
>>> index ae4a41ca19f6..27de55699f24 100644
>>> --- a/arch/x86/xen/enlighten_pv.c
>>> +++ b/arch/x86/xen/enlighten_pv.c
>>> @@ -72,6 +72,7 @@
>>>    #include <asm/mwait.h>
>>>    #include <asm/pci_x86.h>
>>>    #include <asm/cpu.h>
>>> +#include <asm/kasan.h>
>>>      #ifdef CONFIG_ACPI
>>>    #include <linux/acpi.h>
>>> @@ -1231,6 +1232,8 @@ asmlinkage __visible void __init xen_start_kernel=
(void)
>>>        /* Get mfn list */
>>>        xen_build_dynamic_phys_to_machine();
>>>    +    kasan_early_init();
>>> +
>>>        /*
>>>         * Set up kernel GDT and segment registers, mainly so that
>>>         * -fstack-protector code can be executed.
>>> diff --git a/arch/x86/xen/mmu_pv.c b/arch/x86/xen/mmu_pv.c
>>> index c8dbee62ec2a..eaf63f1f26af 100644
>>> --- a/arch/x86/xen/mmu_pv.c
>>> +++ b/arch/x86/xen/mmu_pv.c
>>> @@ -1079,7 +1079,7 @@ static void xen_exit_mmap(struct mm_struct *mm)
>>>      static void xen_post_allocator_init(void);
>>>    -static void __init pin_pagetable_pfn(unsigned cmd, unsigned long pf=
n)
>>> +void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
>>>    {
>>>        struct mmuext_op op;
>>>    @@ -1767,7 +1767,7 @@ static void __init set_page_prot_flags(void *a=
ddr, pgprot_t prot,
>>>        if (HYPERVISOR_update_va_mapping((unsigned long)addr, pte, flags=
))
>>>            BUG();
>>>    }
>>> -static void __init set_page_prot(void *addr, pgprot_t prot)
>>> +void __init set_page_prot(void *addr, pgprot_t prot)
>>>    {
>>>        return set_page_prot_flags(addr, prot, UVMF_NONE);
>>>    }
>>> @@ -1943,6 +1943,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pg=
d, unsigned long max_pfn)
>>>        if (i && i < pgd_index(__START_KERNEL_map))
>>>            init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
>>>    +#ifdef CONFIG_KASAN
>>> +    /*
>>> +     * Copy KASAN mappings
>>> +     * ffffec0000000000 - fffffbffffffffff (=3D44 bits) kasan shadow m=
emory (16TB)
>>> +     */
>>> +    for (i =3D 0xec0 >> 3; i < 0xfc0 >> 3; i++)
>>> +        init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
>>> +#endif
>>> +
>>>        /* Make pagetable pieces RO */
>>>        set_page_prot(init_top_pgt, PAGE_KERNEL_RO);
>>>        set_page_prot(level3_ident_pgt, PAGE_KERNEL_RO);
>>> diff --git a/arch/x86/xen/multicalls.c b/arch/x86/xen/multicalls.c
>>> index 07054572297f..5e4729efbbe2 100644
>>> --- a/arch/x86/xen/multicalls.c
>>> +++ b/arch/x86/xen/multicalls.c
>>> @@ -99,6 +99,15 @@ void xen_mc_flush(void)
>>>                    ret++;
>>>        }
>>>    +    /*
>>> +     * XXX: Kasan produces quite a lot (~2000) of warnings in a form o=
f:
>>> +     *
>>> +     *     (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
>>> +     *
>>> +     * during kasan_init(). They are benign, but silence them for now.
>>> +     * Otherwise, booting takes too long due to printk() spam.
>>> +     */
>>> +#ifndef CONFIG_KASAN
>>
>> It might be interesting to identify the problematic page tables.
>>
>> I guess this would require some hacking to avoid the multicalls in order
>> to identify which page table should not be pinned again.
>=20
> I tracked this down to xen_alloc_ptpage() in mmu_pv.c:
>=20
> 			if (level =3D=3D PT_PTE && USE_SPLIT_PTE_PTLOCKS)
> 				__pin_pagetable_pfn(MMUEXT_PIN_L1_TABLE, pfn);
>=20
> kasan_populate_early_shadow() is doing lots pmd_populate_kernel() with
> kasan_early_shadow_pte (mfn of which is reported by Xen). Currently I'm n=
ot
> sure how to fix that. Is it possible to check that pfn has already been p=
inned
> from Linux kernel? xen_page_pinned() seems to be an incorrect way to chec=
k that.

Right, xen_page_pinned() is not yet working at this stage of booting.

But using pmd_populate_kernel() with the same page table multiple times
is just wrong. Doing so the first time is fine, all the other cases
should just use set_pmd().


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/43f35219-ec39-810b-ebfd-16c14e7b6150%40suse.com.
