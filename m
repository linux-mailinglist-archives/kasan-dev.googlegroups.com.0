Return-Path: <kasan-dev+bncBC447XVYUEMRBRGEZGAQMGQE5BGLJZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id AD485320A99
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 14:38:12 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id y6sf4777427wrl.9
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 05:38:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613914692; cv=pass;
        d=google.com; s=arc-20160816;
        b=pzXd29I/RWKkeN2YrLKrjb/jUcTxaDXsQ2JMcAy7uOI0+mn8TTi4fq5jjnat2AhWT2
         T0CZsdTA/SHv0jE0Ps+D+JjhumCAyXixk318vBqxL0xwDDLYlhTFarNt0Ey/yeroFJxS
         Yc0Nc2En7b/RnW+DEhCQT5mYS/hn6V+QfcumtHj0zObF6bhKD3bLnHFHJgMz8HRNUkjD
         Wn7Ydwk0qTp6YIuPbpW4IvPJI/XxUa5kRFBwC0u7xqAstC8iBxOovXBRDf5tLW9mwI/f
         zi/neiycAB1igVKZ9ux73pbwECWQuioNxeSvjhBf4ON8VZfzh20haNMQVuiqV4h7WGNa
         vshA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=F2HAGN//T1E/vnn8HQ0ZViOVB0F4tPYkDdo8ldZ11vg=;
        b=NVMfCorhe0hwISgJP5eVJcCXQwY+yIRAiAPXf+7G+CP2/XjM6janumIrGjyTcrTzmP
         5vI8UueSVgBWnRf5GbmYWdzkEmVEXXgDvHTYDKA4ml1+vi8R6Gna7YSsjVggZbS76ZVO
         LxpR6z7rmujNAqsmLcMaO3kRaikwQxqa7bdCfMtLmF5dTZmzufRrPLcE2hyqzRXSK8zU
         +GCWvxOEmSH0BiG5MKjdY6o0l859YDsykjei8z8Hoek+2alnkbpH1Ue4XQg7muZ/a7Lk
         GW8GB/22hPCFYxmiSpqEO3i4KrQIsoLUNcZz+oLpBxcYZ3Gi2Z29kSV60Tc5QiUgW7SP
         sGNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F2HAGN//T1E/vnn8HQ0ZViOVB0F4tPYkDdo8ldZ11vg=;
        b=XyP/2Vy9mZ9VuO/e0Mk/XI4gQgmiSsbHKFXd6pOD/qODRSB4mykteZhLzBZc1ztIfA
         aB5RTg5uvoUFcn3ZSHOOT4bcocrcoUkxJNyzta5v0L/WPbiix4vVXXWY+rq5lq84b02v
         bn5z/2YsJngqIf4Hm4CRx2TqogvTLudSidRQEGA5kVwBtgHNU9BbWU6m3WbrB10QBqYA
         Xk87xhy8jRuEte3gbshjjiNB/TCP7dub6RbtM5ELZGNp7xLYoM+iWdplj9JOfr2imOWN
         CVnjcoUuEaSilRqJn0J1PzEC/WsGnmVDm80KGH9HHrMd4KBCca2RR0XTi9yCfL0Nla+p
         CYVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F2HAGN//T1E/vnn8HQ0ZViOVB0F4tPYkDdo8ldZ11vg=;
        b=kgsn2t6c8IbiIo/crs8rqyqoVoaH/s1Sb4Ctv0ymoEWMfllfkfV1pcDqsLx1DD+K+b
         7m929Ft2CZ2wvvUM61BUTN9S6Nii03L0SvybLS4g/+nwYuZVy3rVcvGhw2fME/v9c7Kx
         Y3Qe+i9hvjFmCKhlqzLIW2b5jAVJs2sOIjtI1VcKVMq+VwlSgmm0jd006VRQXNjk4vE8
         qKcy95IPrbtR20seTNATT1XOqYALWq+KVlwqbeID9k4NRnFpQprScav3HEOd9gN2149N
         gDK2I/dcfZ//eUlA07oXF9QfsGgW5oX0WuS6IzXKvHAEYd69D03WfO2l1muWGz7JR5cb
         IQ4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ykLYAEnpOiag1WTKsIl96TtyoFcm7r63iOquFRvaiQVZRVHKj
	Zp8nP0eA8lSKuTcCEntzRCI=
X-Google-Smtp-Source: ABdhPJyjG22cK28GkwOyDRgooKK8EyjtEvsGUjrtJKlw84XbxTod+jXOfVRdNu8QH5tk5i1bm5DWuw==
X-Received: by 2002:a05:6000:192:: with SMTP id p18mr17298815wrx.403.1613914692454;
        Sun, 21 Feb 2021 05:38:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c047:: with SMTP id u7ls644773wmc.1.gmail; Sun, 21 Feb
 2021 05:38:11 -0800 (PST)
X-Received: by 2002:a05:600c:190f:: with SMTP id j15mr16287730wmq.174.1613914691624;
        Sun, 21 Feb 2021 05:38:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613914691; cv=none;
        d=google.com; s=arc-20160816;
        b=F/nIh8PPGCEvmGs56JCIHUoQiX91QCvgyQdzSzzBAFz5Jt8hKlY+Cf5RzLkkZ0WsMv
         lcE+B75O9SQ1gNDZ3s1gNj9hy8z4HFcYizwjpjeFueVjjtqaPau9pDOw/vu2oHJ9bcUY
         i/IXhe4vvVJPnXRXu2rxKQyIVfEi28SMMQLO7TbBvWJKK+NUzNu8IErx6MRkWpQHM8nU
         HDbz6LswSEUJO8NZ4f2zJVNykjstS1Q4tqowjNnqmvKmp0Qcm9eWKyWMaeoFUy/8HkIw
         rJJJlB2rWOJEuhFA/nLBvejvZmrcQrLHbnTdTRxi+i74CGG9rOsDuFYQ2WTqSCQe3fiI
         a2zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=x3P6+qdkna6OOUiq74t3k6545t/YaAbmb2+obLVNgbA=;
        b=MTEyKGBltHPf1IhM+Xtg3TLfeDXLLPrFoYYNt9aR/vta8VWi3ByrMNynhv3VBftjOK
         EHIBSchGh1t24Og7grPdVEA5/ZQiby6fKBaTrWGIZ2B2y6LuMETidBtoyDfVvNJ1EEYV
         AQLdQBEekLTEURCCqM2RGhwM6dAnpY+D041a4jb/1SPR6OlGeRbTM9oe9uVogpVGsKBz
         xzyT91aFlL42YW7MMrDpCIbm20FWyE8YiIsxJKJ7lbHjfN5z8+zW4HoCO8zwcm0MvnIk
         gRgKWLsF7h6ZCTYP2O6v0TsES0dJAxyFrprvbgXTfOiDnNkvrmESkpQA2Iq1XcoUUIZK
         jz0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id m3si925046wme.0.2021.02.21.05.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 21 Feb 2021 05:38:11 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id DC02E20005;
	Sun, 21 Feb 2021 13:38:04 +0000 (UTC)
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
From: Alex Ghiti <alex@ghiti.fr>
To: Palmer Dabbelt <palmer@dabbelt.com>, nylon7@andestech.com
Cc: aou@eecs.berkeley.edu, nickhu@andestech.com, alankao@andestech.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 nylon7717@gmail.com, glider@google.com,
 Paul Walmsley <paul.walmsley@sifive.com>, aryabinin@virtuozzo.com,
 linux-riscv@lists.infradead.org, dvyukov@google.com
References: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
 <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
 <4fa97788-157c-4059-ae3f-28ab074c5836@ghiti.fr>
Message-ID: <e15fbf55-25db-7f91-6feb-fb081ab60cdb@ghiti.fr>
Date: Sun, 21 Feb 2021 08:38:04 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <4fa97788-157c-4059-ae3f-28ab074c5836@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
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

Le 2/13/21 =C3=A0 5:52 AM, Alex Ghiti a =C3=A9crit=C2=A0:
> Hi Nylon, Palmer,
>=20
> Le 2/8/21 =C3=A0 1:28 AM, Alex Ghiti a =C3=A9crit=C2=A0:
>> Hi Nylon,
>>
>> Le 1/22/21 =C3=A0 10:56 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>>> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
>>>> It references to x86/s390 architecture.
>>>> >> So, it doesn't map the early shadow page to cover VMALLOC space.
>>>>
>>>> Prepopulate top level page table for the range that would otherwise be
>>>> empty.
>>>>
>>>> lower levels are filled dynamically upon memory allocation while
>>>> booting.
>>
>> I think we can improve the changelog a bit here with something like that=
:
>>
>> "KASAN vmalloc space used to be mapped using kasan early shadow page.=20
>> KASAN_VMALLOC requires the top-level of the kernel page table to be=20
>> properly populated, lower levels being filled dynamically upon memory=20
>> allocation at runtime."
>>
>>>>
>>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>>>> ---
>>>> =C2=A0arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 1 +
>>>> =C2=A0arch/riscv/mm/kasan_init.c | 57 ++++++++++++++++++++++++++++++++=
+++++-
>>>> =C2=A02 files changed, 57 insertions(+), 1 deletion(-)
>>>>
>>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>>> index 81b76d44725d..15a2c8088bbe 100644
>>>> --- a/arch/riscv/Kconfig
>>>> +++ b/arch/riscv/Kconfig
>>>> @@ -57,6 +57,7 @@ config RISCV
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64BIT
>>>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
>>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>>> index 12ddd1f6bf70..4b9149f963d3 100644
>>>> --- a/arch/riscv/mm/kasan_init.c
>>>> +++ b/arch/riscv/mm/kasan_init.c
>>>> @@ -9,6 +9,19 @@
>>>> =C2=A0#include <linux/pgtable.h>
>>>> =C2=A0#include <asm/tlbflush.h>
>>>> =C2=A0#include <asm/fixmap.h>
>>>> +#include <asm/pgalloc.h>
>>>> +
>>>> +static __init void *early_alloc(size_t size, int node)
>>>> +{
>>>> +=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size,
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), MEM=
BLOCK_ALLOC_ACCESSIBLE, node);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 if (!ptr)
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to allo=
cate %zu bytes align=3D%zx nid=3D%d=20
>>>> from=3D%llx\n",
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __=
func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 return ptr;
>>>> +}
>>>>
>>>> =C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
>>>> =C2=A0asmlinkage void __init kasan_early_init(void)
>>>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void *end)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
>>>> =C2=A0}
>>>>
>>>> +void __init kasan_shallow_populate(void *start, void *end)
>>>> +{
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & PAG=
E_MASK;
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long)e=
nd);
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>>> +=C2=A0=C2=A0=C2=A0 int index;
>>>> +=C2=A0=C2=A0=C2=A0 void *p;
>>>> +=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
>>>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
>>>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vaddr)=
;
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SATP)=
 & SATP_PPN;
>>
>> At this point in the boot process, we know that we use swapper_pg_dir=20
>> so no need to read SATP.
>>
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pfn_t=
o_virt(pfn) + index;
>>
>> Here, this pgd_dir assignment is overwritten 2 lines below, so no need=
=20
>> for it.
>>
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd + in=
dex;
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_k(v=
addr);
>>
>> pgd_offset_k(vaddr) =3D init_mm.pgd + pgd_index(vaddr) so pgd_k =3D=3D p=
gd_dir.
>>
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(pgd=
_dir, vaddr);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_offset=
(pgd_k, vaddr);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_SIZ=
E) & PUD_MASK;
>>
>> Why do you increase vaddr *before* populating the first one ? And=20
>> pud_addr_end does that properly: it returns the next pud address if it=
=20
>> does not go beyond end address to map.
>>
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(p4d=
_dir, vaddr);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4d_k=
, vaddr);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_dir))=
 {
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pu=
d_populate(&init_mm, pud_dir, p);
>>
>> init_mm is not needed here.
>>
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;
>>
>> Why do you need to add PAGE_SIZE ? vaddr already points to the next pud.
>>
>> It seems like this patch tries to populate userspace page table=20
>> whereas at this point in the boot process, only swapper_pg_dir is used=
=20
>> or am I missing something ?
>>
>> Thanks,
>>
>> Alex
>=20
> I implemented this morning a version that fixes all the comments I made=
=20
> earlier. I was able to insert test_kasan_module on both sv39 and sv48=20
> without any modification: set_pgd "goes through" all the unused page=20
> table levels, whereas p*d_populate are noop for unused levels.
>=20
> If you have any comment, do not hesitate.
>=20
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index adbf94b7e68a..d643b222167c 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -195,6 +195,31 @@ static void __init kasan_populate(void *start, void=
=20
> *end)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_SHADOW_IN=
IT, end - start);
>  =C2=A0}
>=20
>=20
> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned=20
> long end)
> +{
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long next;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *p;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(vaddr=
);
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 do {
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr, end);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned=20
> long)lm_alias(kasan_early_shadow_pgd_next)) {
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =3D memblock=
_alloc(PAGE_SIZE, PAGE_SIZE);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_k,=
 pfn_pgd(PFN_DOWN(__pa(p)),=20
> PAGE_TABLE));
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 }
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next, v=
addr !=3D end);
> +}
> +

This way of going through the page table seems to be largely used across=20
the kernel (cf KASAN population functions of arm64/x86) so I do think=20
this patch brings value to Nylon and Nick's patch.

I can propose a real patch if you agree and I'll add a co-developed by=20
Nylon/Nick since this only 'improves' theirs.

Thanks,

Alex

> +void __init kasan_shallow_populate(void *start, void *end)
> +{
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned l=
ong)start & PAGE_MASK;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((=
unsigned long)end);
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pgd(vaddr, v=
end);
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
> +}
> +
>  =C2=A0void __init kasan_init(void)
>  =C2=A0{
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
> @@ -206,7 +231,15 @@ void __init kasan_init(void)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow((=
void *)KASAN_SHADOW_START,
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)
> - VMALLOC_END));
> + VMEMMAP_END));
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMALLOC=
))
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 kasan_shallow_populate(
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_=
mem_to_shadow((void *)VMALLOC_START),
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_=
mem_to_shadow((void *)VMALLOC_END));
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 kasan_populate_early_shadow(
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_=
mem_to_shadow((void *)VMALLOC_START),
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_=
mem_to_shadow((void *)VMALLOC_END));
>=20
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Populate the linear mappin=
g */
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start=
, &_end) {

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e15fbf55-25db-7f91-6feb-fb081ab60cdb%40ghiti.fr.
