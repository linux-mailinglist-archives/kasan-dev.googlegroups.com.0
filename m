Return-Path: <kasan-dev+bncBC447XVYUEMRBHNKQ2AQMGQEJHZMLIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id CF1F1313F6A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 20:46:37 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id u138sf72768wmu.8
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 11:46:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612813597; cv=pass;
        d=google.com; s=arc-20160816;
        b=fnfA8bGWxJOI32paK0SHXmOD49AYD3ckMMina9vlsKT6q2cd1xjDn+XoVv4r6tzqnv
         8Hft74DpzMqpVtSglxWJOY5QgHdfmoFhga89PyPldf5ijlo+OLpBKqbz4kDzFZKJYW3+
         cPG/HbLSvZdVQ+xUpiJCPYoaSWv9yR40VoD9B1LWCjTLZbAcmUv2LPvLk0ngjJIapPku
         GjidJLfOVrdlBWZB7RRU8F6lP7EYWsZBfZz2dG4os3v7esE9JWoH2gBBas3gQroaR95d
         OcdRdbS3tAsTf2IvQBLhVf5Re6RTBmyXbFZdchCtzqgOFElfvF6XchuU4q57C+1tQ6zC
         vOlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:to:from:subject:sender:dkim-signature;
        bh=CMPCrewmdZE7PkhmVGzGtRPnzetNo3m4H+szbagSOcE=;
        b=T/+7jQi+h8LuxCdqjgFKBA5FIaw6Dd/MQTgdc8jUKM70H0MrluG6+JvqzHftChEFtf
         Ke/l4BpuHo6DQ3H8P03n8iaLNMjK/5cjoC4lX7cti1gEw/1xzHIEsJUvof1OjW7VS5Ah
         MH+fKL9xLgO1tJhq5fp3fetMpVRManPK4vLb5415mmlgktVFWdZ+xd4OWDFhOlD6kBU4
         WTTqOo+27QQ1p/4FkQwC4GDJAocM5EttEygILYrWNu/0x2lEMmwnXxM9xXgehHGyG4+S
         stMlrNJ7eVQmK2O0Mck+MUTos4tNdrcwduV2As/F5mFB5dDCHRT7E5AKY+os31gEfJQv
         TDCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CMPCrewmdZE7PkhmVGzGtRPnzetNo3m4H+szbagSOcE=;
        b=NnPfm2ThlbtbIPZZrEeeiB4VXSyvepT/imH0+BYeMw5t16cuK2nIrD9gRS5mGj2xrC
         H4Pmom8nctTY3imkegOPqemQomHXBDIVIKhTAY6x1agjgHzTlLppCCxtb7WA1qlIRxld
         H2NaPJFeT+wmMELUbCPhAGs61uKLteG98SJb7oqNYNoz2/gEA0tOHzt3Jjx7jPT2pbLi
         NfcFFuFbAARSahFv4YErf1lQVyNDxYdz9rsEqzfcjOkJ2Mex8wbyAlEnfp1ol5kocqie
         h2HTnkQ4tQ376OgaN1MZhmljD7xULUU8piggTVHNKtS3IVaTTms8xpgh7EV/djqKaZ6s
         zHPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CMPCrewmdZE7PkhmVGzGtRPnzetNo3m4H+szbagSOcE=;
        b=kVo8+1OVrwLj1NnlvPHlywy/nSr1fyAOCorUeCgGnRVif1uJLGyD4hzY7BnRIcSZDJ
         Yk4rnJJ8OuLFBPYTkcZ9c2n0HYVrh6tWufVZ4GyFl8w4WcNM5Ck/k44geED7kQiExF7r
         hA/5cziYPGjoJU8lJ16bcLqqQkldzSCUnS+UqEcmM/mJ+MK+yg+HRZfR9X1ZwURapLWu
         Gp5uQLshQ3bHHumcXgmcu9z8SlD+VY0CxcMOJvoWC+pXEwn3Kdt7xx0YD7Z+gXaVO9Y4
         W7nfDPERHeaq8GQSnPiNu8TvPN1z8ArtWicY3zoAMVE8PJK2ze6Pp6KrkyZQaaLlD95Y
         6B1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xDEcCA26zHexGWXr7XZVddcL4Ufl0nh1ZySGfMgHRudeq+ycp
	mrrkzBDZh/+9INofHXQjuh8=
X-Google-Smtp-Source: ABdhPJxEIqxJEHaeULBpLq482a5CAplgUvs7CTV2FWAs8ldxyZ04TEh1ICGKtgqqPENDmr2IToRZxw==
X-Received: by 2002:adf:c6c1:: with SMTP id c1mr21674224wrh.326.1612813597537;
        Mon, 08 Feb 2021 11:46:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4d02:: with SMTP id z2ls5233539wrt.3.gmail; Mon, 08 Feb
 2021 11:46:36 -0800 (PST)
X-Received: by 2002:adf:decb:: with SMTP id i11mr21234480wrn.78.1612813596807;
        Mon, 08 Feb 2021 11:46:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612813596; cv=none;
        d=google.com; s=arc-20160816;
        b=EN6S5HSj1DIKMopm1dHcIAjTXkrGPjgEl5BRcnBjanx4F5q1Ej6x7EIF1HsSUGlWxt
         eGxQe5afnSDrSfSxZa0Oawn3prtYAOFLdB/rGef5UbiifYWrP6o7MNKwTH8mEyuYtiqX
         YijGylRY9ea0dFUwvi17IErc/hR4GUG0fB+REY1ryRiUq5Y3P2hntDRxBsdq/XrHzwjb
         Okc5PNQFPoYW2JEIZZH+3rFO6wdcU0s5aPCl4Odt29Z/GRZ8C+fxMcpNC2mnmvkbd6gS
         ZDyq0vcfG80DAa9U9VlZq+ZtDftxT5+xJHRlHnWLZQP+pqNuaJB5ezPEA+/s8Zd2jCEC
         XfzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:to:from:subject;
        bh=ZHeo9H0zdlQZ9wscrjtsEC74kzByyMRL4tV25L4vqIY=;
        b=TtwVN5OMui56wfhopeXQznzlU6ddJ+5eK8PMqzl68vmmUTKe4aiR2lW1C67KJWq2LW
         vupNmAM86gDo5547W2pdnk9j4hNwr93XqHxnqx+j1XavvejtDnVB8lmw8GOcx2yTr8zP
         tuCqZc5Ea7w08o2UDvCOoJGgc2NT70D7q6p1bNb6/3pYZbEyM1KNHobkbcV4b9ChFPWh
         tdjcEmEMNd8HZl3krWF5d9oWAHNVhZaWyyT7UTAcG8rdlA9mXE2WLqvQbo3k1AceC8Yo
         XqMl1xDpivhHVTZEEiWCjnYvpXnRYBvEJ+54aAxryiKi+86nsJ3uQXAJgVrxQG7uCuhR
         Hs7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay12.mail.gandi.net (relay12.mail.gandi.net. [217.70.178.232])
        by gmr-mx.google.com with ESMTPS id b5si722905wrd.4.2021.02.08.11.46.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Feb 2021 11:46:36 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.232;
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay12.mail.gandi.net (Postfix) with ESMTPSA id 815F5200002;
	Mon,  8 Feb 2021 19:46:34 +0000 (UTC)
Subject: Re: [PATCH] riscv: Improve kasan population by using hugepages when
 possible
From: Alex Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org
References: <20210201080024.844-1-alex@ghiti.fr>
 <74fef5c9-0632-3e12-e11b-81dd115a4be5@ghiti.fr>
Message-ID: <249567fd-d436-7e06-081c-65b1f9930b07@ghiti.fr>
Date: Mon, 8 Feb 2021 14:46:34 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <74fef5c9-0632-3e12-e11b-81dd115a4be5@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.232 is neither permitted nor denied by best guess
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

Le 2/2/21 =C3=A0 3:50 AM, Alex Ghiti a =C3=A9crit=C2=A0:
> Hi,
>=20
> Le 2/1/21 =C3=A0 3:00 AM, Alexandre Ghiti a =C3=A9crit=C2=A0:
>> Kasan function that populates the shadow regions used to allocate them
>> page by page and did not take advantage of hugepages, so fix this by
>> trying to allocate hugepages of 1GB and fallback to 2MB hugepages or 4K
>> pages in case it fails.
>>
>> This reduces the page table memory consumption and improves TLB usage,
>> as shown below:
>>
>> Before this patch:
>>
>> ---[ Kasan shadow start ]---
>> 0xffffffc000000000-0xffffffc400000000=C2=A0=C2=A0=C2=A0 0x00000000818ef0=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 16G=20
>> PTE=C2=A0=C2=A0=C2=A0=C2=A0 . A . . . . R V
>> 0xffffffc400000000-0xffffffc447fc0000=C2=A0=C2=A0=C2=A0 0x00000002b7f4f0=
00=C2=A0=C2=A0 1179392K=20
>> PTE=C2=A0=C2=A0=C2=A0=C2=A0 D A . . . W R V
>> 0xffffffc480000000-0xffffffc800000000=C2=A0=C2=A0=C2=A0 0x00000000818ef0=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 14G=20
>> PTE=C2=A0=C2=A0=C2=A0=C2=A0 . A . . . . R V
>> ---[ Kasan shadow end ]---
>>
>> After this patch:
>>
>> ---[ Kasan shadow start ]---
>> 0xffffffc000000000-0xffffffc400000000=C2=A0=C2=A0=C2=A0 0x00000000818ef0=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 16G=20
>> PTE=C2=A0=C2=A0=C2=A0=C2=A0 . A . . . . R V
>> 0xffffffc400000000-0xffffffc440000000=C2=A0=C2=A0=C2=A0 0x00000002400000=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1G=20
>> PGD=C2=A0=C2=A0=C2=A0=C2=A0 D A . . . W R V
>> 0xffffffc440000000-0xffffffc447e00000=C2=A0=C2=A0=C2=A0 0x00000002b7e000=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 126M=20
>> PMD=C2=A0=C2=A0=C2=A0=C2=A0 D A . . . W R V
>> 0xffffffc447e00000-0xffffffc447fc0000=C2=A0=C2=A0=C2=A0 0x00000002b818f0=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1792K=20
>> PTE=C2=A0=C2=A0=C2=A0=C2=A0 D A . . . W R V
>> 0xffffffc480000000-0xffffffc800000000=C2=A0=C2=A0=C2=A0 0x00000000818ef0=
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 14G=20
>> PTE=C2=A0=C2=A0=C2=A0=C2=A0 . A . . . . R V
>> ---[ Kasan shadow end ]---
>>
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>> ---
>> =C2=A0 arch/riscv/mm/kasan_init.c | 101 +++++++++++++++++++++++++++-----=
-----
>> =C2=A0 1 file changed, 73 insertions(+), 28 deletions(-)
>>
>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> index a8a2ffd9114a..8f11b73018b1 100644
>> --- a/arch/riscv/mm/kasan_init.c
>> +++ b/arch/riscv/mm/kasan_init.c
>> @@ -47,37 +47,82 @@ asmlinkage void __init kasan_early_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>> =C2=A0 }
>> -static void __init populate(void *start, void *end)
>> +static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr,=20
>> unsigned long end)
>> +{
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t phys_addr;
>> +=C2=A0=C2=A0=C2=A0 pte_t *ptep =3D memblock_alloc(PTRS_PER_PTE * sizeof=
(pte_t),=20
>> PAGE_SIZE);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr =3D memblock_phys_=
alloc(PAGE_SIZE, PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(ptep, pfn_pte(PFN_DO=
WN(phys_addr), PAGE_KERNEL));
>> +=C2=A0=C2=A0=C2=A0 } while (ptep++, vaddr +=3D PAGE_SIZE, vaddr !=3D en=
d);
>> +
>> +=C2=A0=C2=A0=C2=A0 set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(ptep)), PAGE_TABL=
E));
>> +}
>> +
>> +static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr,=20
>> unsigned long end)
>> +{
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t phys_addr;
>> +=C2=A0=C2=A0=C2=A0 pmd_t *pmdp =3D memblock_alloc(PTRS_PER_PMD * sizeof=
(pmd_t),=20
>> PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pmd_addr_end(vaddr,=
 end);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ALIGNED(vaddr, PMD_SI=
ZE) && (next - vaddr) >=3D PMD_SIZE) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys=
_addr =3D memblock_phys_alloc(PMD_SIZE, PMD_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (=
phys_addr) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 set_pmd(pmdp, pfn_pmd(PFN_DOWN(phys_addr),=20
>> PAGE_KERNEL));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 continue;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_pte(pmdp, vad=
dr, end);
>> +=C2=A0=C2=A0=C2=A0 } while (pmdp++, vaddr =3D next, vaddr !=3D end);
>> +
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Wait for the whole PGD to be populated befor=
e setting the PGD in
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * the page table, otherwise, if we did set the=
 PGD before=20
>> populating
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * it entirely, memblock could allocate a page =
at a physical address
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * where KASAN is not populated yet and then we=
'd get a page fault.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(pmdp)), PAGE_TABL=
E));
>=20
> In case the PMD was filled entirely, PFN_DOWN(__pa(pmdp)) will point to=
=20
> the next physical page, which is wrong. The same problem happens on the=
=20
> other levels too.
>=20
> I'll fix that in a v2 later today.
>=20
> Alex
>=20
>> +}
>> +
>> +static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
>> +{
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t phys_addr;
>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgdp =3D pgd_offset_k(vaddr);
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr,=
 end);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ALIGNED(vaddr, PGDIR_=
SIZE) && (next - vaddr) >=3D=20
>> PGDIR_SIZE) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys=
_addr =3D memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (=
phys_addr) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr),=20
>> PAGE_KERNEL));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 continue;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_pmd(pgdp, vad=
dr, end);
>> +=C2=A0=C2=A0=C2=A0 } while (pgdp++, vaddr =3D next, vaddr !=3D end);
>> +}
>> +
>> +/*
>> + * This function populates KASAN shadow region focusing on hugepages in
>> + * order to minimize the page table cost and TLB usage too.
>> + * Note that start must be PGDIR_SIZE-aligned in SV39 which amounts=20
>> to be
>> + * 1G aligned (that represents a 8G alignment constraint on virtual=20
>> address
>> + * ranges because of KASAN_SHADOW_SCALE_SHIFT).
>> + */
>> +static void __init kasan_populate(void *start, void *end)
>> =C2=A0 {
>> -=C2=A0=C2=A0=C2=A0 unsigned long i, offset;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)st=
art & PAGE_MASK;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsign=
ed long)end);
>> -=C2=A0=C2=A0=C2=A0 unsigned long n_pages =3D (vend - vaddr) / PAGE_SIZE=
;
>> -=C2=A0=C2=A0=C2=A0 unsigned long n_ptes =3D
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((n_pages + PTRS_PER_PTE) & =
-PTRS_PER_PTE) / PTRS_PER_PTE;
>> -=C2=A0=C2=A0=C2=A0 unsigned long n_pmds =3D
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((n_ptes + PTRS_PER_PMD) & -=
PTRS_PER_PMD) / PTRS_PER_PMD;
>> -
>> -=C2=A0=C2=A0=C2=A0 pte_t *pte =3D
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_alloc(n_ptes * PTRS=
_PER_PTE * sizeof(pte_t),=20
>> PAGE_SIZE);
>> -=C2=A0=C2=A0=C2=A0 pmd_t *pmd =3D
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_alloc(n_pmds * PTRS=
_PER_PMD * sizeof(pmd_t),=20
>> PAGE_SIZE);
>> -=C2=A0=C2=A0=C2=A0 pgd_t *pgd =3D pgd_offset_k(vaddr);
>> -
>> -=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < n_pages; i++) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t phys =3D membloc=
k_phys_alloc(PAGE_SIZE, PAGE_SIZE);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(&pte[i], pfn_pte(PHY=
S_PFN(phys), PAGE_KERNEL));
>> -=C2=A0=C2=A0=C2=A0 }
>> -
>> -=C2=A0=C2=A0=C2=A0 for (i =3D 0, offset =3D 0; i < n_ptes; i++, offset =
+=3D PTRS_PER_PTE)
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pmd(&pmd[i],
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn_=
pmd(PFN_DOWN(__pa(&pte[offset])),
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __pgprot(_PAGE_TABLE)));
>> -=C2=A0=C2=A0=C2=A0 for (i =3D 0, offset =3D 0; i < n_pmds; i++, offset =
+=3D PTRS_PER_PMD)
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(&pgd[i],
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn_=
pgd(PFN_DOWN(__pa(&pmd[offset])),
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __pgprot(_PAGE_TABLE)));
>> +=C2=A0=C2=A0=C2=A0 kasan_populate_pgd(vaddr, vend);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
>> @@ -99,7 +144,7 @@ void __init kasan_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D en=
d)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 break;
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 populate(kasan_mem_to_shadow=
(start), kasan_mem_to_shadow(end));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_mem_to_=
shadow(start),=20
>> kasan_mem_to_shadow(end));
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 };
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < PTRS_PER_PTE; i++)
>>

Palmer, you can drop this one as I split it and fixed it in my "Kasan=20
improvements and fixes" series.

Thanks,

Alex

>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/249567fd-d436-7e06-081c-65b1f9930b07%40ghiti.fr.
