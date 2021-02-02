Return-Path: <kasan-dev+bncBC447XVYUEMRB2VE4SAAMGQEG4SPMZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8144F30BA4C
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 09:50:50 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id h17sf7375856wrv.15
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 00:50:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612255850; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pc0qRpbdWoWnKL2NUXIye5VgnL30TZIoJ31+z0aFvxVj+sBbLsK6clOrHP9k6TlxQa
         iu2BsQEXV1JvRzKSCI8Em5rR8va/6KZI74fLcsuXV6X59FZ4rDxM5gk8vmrMXilkWiAj
         ccyRd3F0S5LSfO2DaYjNDh5B61dk0bSFrs914TnqXThYkA1fdOasfCKIq+lHPNWWriPD
         G6rUMPTrYvWEpowLrI/3I1nFc+I0i2u4mUXedy593kyf5QFA977buk2Gw2A63T3fjjwt
         bW3rdG/wDGVOCyhRwdoNBFWK6S6tQaufiIZCzaEYkhQYVLPEAGO1A3wPw7c7BR6UVEX2
         Mrww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=nCJOoeJWSP37pN6Qu1dm5DWJWLMWerctRPOUYSDdJPU=;
        b=WxptX36UFAuEeBw7StqOB+KwEcbY266Y2yTLfuEi3PxqrMfhi4PYf87pEqiQcCSj6L
         7gWyq2y6iqWTaGVd4Sv9OXUnPRQ4tC1z/kho8EA0Zcrb7juWAv4Yy2Idc1jGyECJ3y4t
         VyAb9Jp84aQuFKBsnHfUxpWxamD4MokgWjvsS2o589oWV0iV1Pm3oWGPoVRapZeM/yCA
         +T8V7HGEmMS9bCqx/E7OAEU3hgMdcM3GR1xiSicdcOJ5pnrpW7lSu2ImYl6e1dv4BcMp
         3zyY6PIwycfFedSanYNGQnQhU4secgby91NerXOcu800xp6bDrzaC3Vw36Ay1mpXGdCR
         0SVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nCJOoeJWSP37pN6Qu1dm5DWJWLMWerctRPOUYSDdJPU=;
        b=Ot2vjrYPo2p5pU2vslTybvHo8JOlapJaMHzIY+A64MPciVxAUbYdcsbGYiTc91Zxks
         IMJBEbG5D8qj+3cuJRU7vYIss36ff0H5kIcUmNFUBltddgz0ZttUaun57Elt6ZwzH/Vo
         55ePy3MZvOf8Em7GBWF3kG4popJmitOcVn6VuztHn9b7xCWrkHYYcHrBMHFdfLkDtjsJ
         jsHWGyz85H2IRpvL1BUaxp5g6d+x9Tt85SmjyBuv6V1xnaxmsV4xDBhuHTNoVMk3Tm6b
         6NWzbGxabA3mYLCOXzvzABp8upRK5NDRnioBFDLtTusjDTWl9ioX5x4hpDzfNdctKmpl
         qfVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nCJOoeJWSP37pN6Qu1dm5DWJWLMWerctRPOUYSDdJPU=;
        b=PvbS6rirmso987RClpE3XXgBxqZbuko1VwehExhdySYAPWNPO9vv7yJzeELheHn4hT
         J9tzsRVThwraglmNxjxgHgFnIEdvLik0fAJn0RYXlQN4AKf3Vx01SFUoqAKXKG49qDAN
         3D/IoPVAU7ER85ABOy6r9Os8iRayOpIvzIxwCX+pnNI7ITHKq7U1PAGolVgfsVFBmAYT
         VCUVyCGRH692ZGvW1weiI+i6bqs7iTLgFNsdD6cqejQSeBd8MJERD3ICVnprS8L34sRK
         yAKHImrJTvSxDThhsHtIF6CzgaHy+/eJ96Pn6Tlzu/IRconfFH+SDsqzGb68xA4ftWoY
         C91g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HTGZKsBj9S4oEpOy2vi0XF7ijNMjxCOWwWiAjtMgH1JiLmdoO
	2H9vgMcLmzqe+AgQMtzhkLw=
X-Google-Smtp-Source: ABdhPJzXW+SF/xuwJSKRBFAuFHMvd+g5mqOC/R7cCACS8G7ZUKrqw6hT1Ssqhww25H61JcGlY9PXpA==
X-Received: by 2002:a5d:4492:: with SMTP id j18mr1070960wrq.403.1612255850219;
        Tue, 02 Feb 2021 00:50:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2ecd:: with SMTP id u196ls706662wmu.1.gmail; Tue, 02 Feb
 2021 00:50:49 -0800 (PST)
X-Received: by 2002:a1c:f417:: with SMTP id z23mr2513546wma.29.1612255849423;
        Tue, 02 Feb 2021 00:50:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612255849; cv=none;
        d=google.com; s=arc-20160816;
        b=t8DvYDdDt/fffV4uFVUzSYeeGICIbiMaqLfkc5tkCT7GIrE/m99CSgVU3CTv/AmkyI
         qtg9VJivG2mL8i+PYtL1vRt1cRogEuIuPUJCBMxV+6M9KQBp0nrl+h33NQJOIEj/YKpk
         P68HUY/9JUL43O2lJGspNVCP8lqJvIj4wjA4LbJCvMJG4ZmagiME/A9egxDQpjY+UiMO
         pJyebz9WKNc0z8EEf8ky4p3VewNnLw9tec9/OYupPjErv8nlxjRycA3JBB0RyqmSscSh
         GRpqavmkDhDhN+aswNBQ8HDgJPVuUW6AZIwlZXQmEL49/SABvSdWGyaMs7VbEIzd1YmR
         8uYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=WRInydb0MJWM8HWj0ruRDDxp+GfQN8Tt1SvUet6stxo=;
        b=UOhHr8TQbWcYBJle3cM/cQckA7ObhvUTw1Ra94qJw8U9C1TABq7oAehzGhv90m9qgR
         XKF8Ws6cbhhkBJb9EhjfjPzHDtuLzJHAUpPVRmn8M5trRZuFpnz7dNvBTW67G8k4ATay
         P1jduFLKEmqLAulG3y1mTwp8HErTK4UFgw6LOJeP1kia4mEdmgOnuBGiPuQWEb/aChDe
         NxxkHmnWCoL6yPmjN98MausBaM5mnBsJUptxpZdgY6KjrD33aHp6iP5rlAXO1jX4rgBs
         2xUwpS7JJNSpIzBKolIZthUn3LUON6l5GTH0N2i7LCZy37fJmq+mbcnxiPtz4nGoHHNv
         Lvng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id t16si152665wmi.3.2021.02.02.00.50.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 02 Feb 2021 00:50:49 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 82.65.183.113
Received: from [172.16.5.113] (82-65-183-113.subs.proxad.net [82.65.183.113])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 70341240011;
	Tue,  2 Feb 2021 08:50:45 +0000 (UTC)
Subject: Re: [PATCH] riscv: Improve kasan population by using hugepages when
 possible
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org
References: <20210201080024.844-1-alex@ghiti.fr>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <74fef5c9-0632-3e12-e11b-81dd115a4be5@ghiti.fr>
Date: Tue, 2 Feb 2021 03:50:45 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <20210201080024.844-1-alex@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi,

Le 2/1/21 =C3=A0 3:00 AM, Alexandre Ghiti a =C3=A9crit=C2=A0:
> Kasan function that populates the shadow regions used to allocate them
> page by page and did not take advantage of hugepages, so fix this by
> trying to allocate hugepages of 1GB and fallback to 2MB hugepages or 4K
> pages in case it fails.
>=20
> This reduces the page table memory consumption and improves TLB usage,
> as shown below:
>=20
> Before this patch:
>=20
> ---[ Kasan shadow start ]---
> 0xffffffc000000000-0xffffffc400000000    0x00000000818ef000        16G PT=
E     . A . . . . R V
> 0xffffffc400000000-0xffffffc447fc0000    0x00000002b7f4f000   1179392K PT=
E     D A . . . W R V
> 0xffffffc480000000-0xffffffc800000000    0x00000000818ef000        14G PT=
E     . A . . . . R V
> ---[ Kasan shadow end ]---
>=20
> After this patch:
>=20
> ---[ Kasan shadow start ]---
> 0xffffffc000000000-0xffffffc400000000    0x00000000818ef000        16G PT=
E     . A . . . . R V
> 0xffffffc400000000-0xffffffc440000000    0x0000000240000000         1G PG=
D     D A . . . W R V
> 0xffffffc440000000-0xffffffc447e00000    0x00000002b7e00000       126M PM=
D     D A . . . W R V
> 0xffffffc447e00000-0xffffffc447fc0000    0x00000002b818f000      1792K PT=
E     D A . . . W R V
> 0xffffffc480000000-0xffffffc800000000    0x00000000818ef000        14G PT=
E     . A . . . . R V
> ---[ Kasan shadow end ]---
>=20
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> ---
>   arch/riscv/mm/kasan_init.c | 101 +++++++++++++++++++++++++++----------
>   1 file changed, 73 insertions(+), 28 deletions(-)
>=20
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index a8a2ffd9114a..8f11b73018b1 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -47,37 +47,82 @@ asmlinkage void __init kasan_early_init(void)
>   	local_flush_tlb_all();
>   }
>  =20
> -static void __init populate(void *start, void *end)
> +static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned=
 long end)
> +{
> +	phys_addr_t phys_addr;
> +	pte_t *ptep =3D memblock_alloc(PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE)=
;
> +
> +	do {
> +		phys_addr =3D memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
> +		set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
> +	} while (ptep++, vaddr +=3D PAGE_SIZE, vaddr !=3D end);
> +
> +	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(ptep)), PAGE_TABLE));
> +}
> +
> +static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned=
 long end)
> +{
> +	phys_addr_t phys_addr;
> +	pmd_t *pmdp =3D memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE)=
;
> +	unsigned long next;
> +
> +	do {
> +		next =3D pmd_addr_end(vaddr, end);
> +
> +		if (IS_ALIGNED(vaddr, PMD_SIZE) && (next - vaddr) >=3D PMD_SIZE) {
> +			phys_addr =3D memblock_phys_alloc(PMD_SIZE, PMD_SIZE);
> +			if (phys_addr) {
> +				set_pmd(pmdp, pfn_pmd(PFN_DOWN(phys_addr), PAGE_KERNEL));
> +				continue;
> +			}
> +		}
> +
> +		kasan_populate_pte(pmdp, vaddr, end);
> +	} while (pmdp++, vaddr =3D next, vaddr !=3D end);
> +
> +	/*
> +	 * Wait for the whole PGD to be populated before setting the PGD in
> +	 * the page table, otherwise, if we did set the PGD before populating
> +	 * it entirely, memblock could allocate a page at a physical address
> +	 * where KASAN is not populated yet and then we'd get a page fault.
> +	 */
> +	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(pmdp)), PAGE_TABLE));

In case the PMD was filled entirely, PFN_DOWN(__pa(pmdp)) will point to=20
the next physical page, which is wrong. The same problem happens on the=20
other levels too.

I'll fix that in a v2 later today.

Alex

> +}
> +
> +static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
> +{
> +	phys_addr_t phys_addr;
> +	pgd_t *pgdp =3D pgd_offset_k(vaddr);
> +	unsigned long next;
> +
> +	do {
> +		next =3D pgd_addr_end(vaddr, end);
> +
> +		if (IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >=3D PGDIR_SIZE) {
> +			phys_addr =3D memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
> +			if (phys_addr) {
> +				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
> +				continue;
> +			}
> +		}
> +
> +		kasan_populate_pmd(pgdp, vaddr, end);
> +	} while (pgdp++, vaddr =3D next, vaddr !=3D end);
> +}
> +
> +/*
> + * This function populates KASAN shadow region focusing on hugepages in
> + * order to minimize the page table cost and TLB usage too.
> + * Note that start must be PGDIR_SIZE-aligned in SV39 which amounts to b=
e
> + * 1G aligned (that represents a 8G alignment constraint on virtual addr=
ess
> + * ranges because of KASAN_SHADOW_SCALE_SHIFT).
> + */
> +static void __init kasan_populate(void *start, void *end)
>   {
> -	unsigned long i, offset;
>   	unsigned long vaddr =3D (unsigned long)start & PAGE_MASK;
>   	unsigned long vend =3D PAGE_ALIGN((unsigned long)end);
> -	unsigned long n_pages =3D (vend - vaddr) / PAGE_SIZE;
> -	unsigned long n_ptes =3D
> -	    ((n_pages + PTRS_PER_PTE) & -PTRS_PER_PTE) / PTRS_PER_PTE;
> -	unsigned long n_pmds =3D
> -	    ((n_ptes + PTRS_PER_PMD) & -PTRS_PER_PMD) / PTRS_PER_PMD;
> -
> -	pte_t *pte =3D
> -	    memblock_alloc(n_ptes * PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
> -	pmd_t *pmd =3D
> -	    memblock_alloc(n_pmds * PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
> -	pgd_t *pgd =3D pgd_offset_k(vaddr);
> -
> -	for (i =3D 0; i < n_pages; i++) {
> -		phys_addr_t phys =3D memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
> -		set_pte(&pte[i], pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
> -	}
> -
> -	for (i =3D 0, offset =3D 0; i < n_ptes; i++, offset +=3D PTRS_PER_PTE)
> -		set_pmd(&pmd[i],
> -			pfn_pmd(PFN_DOWN(__pa(&pte[offset])),
> -				__pgprot(_PAGE_TABLE)));
>  =20
> -	for (i =3D 0, offset =3D 0; i < n_pmds; i++, offset +=3D PTRS_PER_PMD)
> -		set_pgd(&pgd[i],
> -			pfn_pgd(PFN_DOWN(__pa(&pmd[offset])),
> -				__pgprot(_PAGE_TABLE)));
> +	kasan_populate_pgd(vaddr, vend);
>  =20
>   	local_flush_tlb_all();
>   	memset(start, 0, end - start);
> @@ -99,7 +144,7 @@ void __init kasan_init(void)
>   		if (start >=3D end)
>   			break;
>  =20
> -		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
> +		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
>   	};
>  =20
>   	for (i =3D 0; i < PTRS_PER_PTE; i++)
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/74fef5c9-0632-3e12-e11b-81dd115a4be5%40ghiti.fr.
