Return-Path: <kasan-dev+bncBC447XVYUEMRBUOJ3KAQMGQE3ZSPZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id AA54832446C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 20:11:14 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id d3sf1123704lfc.18
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 11:11:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614193874; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9klkuz+AAmBE/cC+mkFGd+sANGaLyxYQXDB5vGj2ys9br3uLJ/5tzhQLy1vcS4din
         HEbxbfA6yf+J3QBuSMy4D051xRglqFxo/4neXOEweScwWV9V/5or9easYKKBPUqvj+EG
         DXJ/zgiaLntlh1gyRtfEV9jTsUvLPD8gPlPsrr+NdFOt6YtlpRav/a71zGNKtJC8PtI2
         1kWXpBUlFLCKrf7Bixe5O2r1nKU0li6hL7AVPfIOe9AGjLzHbsp9xL92DjEKX9THJLbP
         ZqQfXgrrex2G4zmFDcZ2Ixtv69ApDPxnp7ZkwnJOZdpW34EnBgmWLeoLhD1/UbvcP3/X
         LX4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=JnBqXbzTvyxWylJYArk9NTlr1+sFRppBnmvQE64irOI=;
        b=k6eZBUXd0WRkuC7+5an0sDnJD6t0ewUG3NyYzIirBwhszUKGsXAW8hyHuCrRVwu/af
         nf2N9yTRfhMps9+3ttUl8r++w/4+daiVyVGMNn7e8j5aI304txkCRzJ8ykqce9P+E3Ct
         dPyrGSWybK2Wj/96Fu1GcAPZzzlhFmNLE0C/c9NUhGRtqNNWkigHBlDdfHAoN7BiMEvu
         Uy/euSpmOqAUcyUI/dVFYpUEd0xPGNBkVa5wOjlloesSD8qNolhKixnp6kQmrcsuSAUG
         QpFDprS7zxpOMy8ZQNexte91le9j3SYompdtsaM1sS0PYH8ShtHVXm2/RI46lzDQGylH
         sBdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JnBqXbzTvyxWylJYArk9NTlr1+sFRppBnmvQE64irOI=;
        b=IXo/Dgofoc35mfjE/RRsL8OlM/KjEAKXdQWnAric2U8GUiSBK1qUfatALGUGpqDdns
         /QwmYog1IEgpHL35CLT7Yec7v+KQCypGY/mUxiE4Y8lV616PhhCGWHB2lNACmoEi8NZj
         hu15cmtFrXqfjNxcLerR0ylGCfHw4qErJZ6RQUvFMf9r+9PVzW5wC0HB6bXMWZRsfz8X
         Avle0hlYqAExfab5DIFZ+SASTyMLxg4sz+FR95C+A9Du6t/6upKnFgzlQr+vZjtDpoHV
         Vf12NPg4GMDyt3jtyIAg2cFljEJwIa+AWnoLv/gCquipNfc4xxF+QpCy4z+XT9z1UnxO
         khew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JnBqXbzTvyxWylJYArk9NTlr1+sFRppBnmvQE64irOI=;
        b=STMPYnayaGBGohiCpB9+JGkFChP+1mAMyvAkJ2wuwjEStlrBqiYA5IUEjrCY5PgbEi
         J2gG/Fl///5yl5P6oaHgZpuilSEnadTC4k7RrcYeFzj5rUOeeXwYKKrYSEUo+EoRevLa
         AE3+k8jcXwPeKS24+DnLDT0PrTokZ6JHxYVUlrK8aDOc0V3WwSOjwyxfiMLZ5uktHTWB
         A4hY0OX/4foxA0a9K7NvczoDnY79W4d05FdlRyRPmCuXS23E1xZN5TG/eIhx+JJUgDel
         enWcCg18qjfsCOLXrm36BFNrNBNnXWxXQ5h/f65p8OvGoDvsYTjS22aAwNV+UM/c/tkY
         tU5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zCceDw0POeusXIIXjhRETUT3h6L7h1VRxLaIagwaqSgNIpI1o
	d07fdOMZtiQGtegbqpymo5U=
X-Google-Smtp-Source: ABdhPJy85LtRbSiVXA9WWwlGGjTXn891oqZu70cD2MP3BNIZ1XCIexE6yxWW4Xd30y1r1OQDHxJb+A==
X-Received: by 2002:a05:6512:31cc:: with SMTP id j12mr19135009lfe.408.1614193874167;
        Wed, 24 Feb 2021 11:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls2424217lff.1.gmail; Wed, 24
 Feb 2021 11:11:13 -0800 (PST)
X-Received: by 2002:ac2:530a:: with SMTP id c10mr7526305lfh.604.1614193873087;
        Wed, 24 Feb 2021 11:11:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614193873; cv=none;
        d=google.com; s=arc-20160816;
        b=zvUN+8qw/PLYZ/J3CkF6YC41z9wBuiLY56N13g9dDxqWYiHBO23+JNRJEO5wWHa0QJ
         WY3yDWEAHT3AejT/f3FEl3+weclgOX2ulJoC5Khq334yG7GkovWq828i2X3RHxHcKId+
         wcEdFT0EYhSxGHGirm379Ue7CdEmIeNfQQjkyLFaILBMdESjdxwO2n11dyOnkJv8VdCr
         7d29nDRXK+ZTkpZ0Q1k4PLZI9FJ6jby14vtohA5W7cp6dw4RcPOjj/jO5kuORuid9Wn7
         kuETAMUCpYNBMnZFoU//k3BCMDjJpd3YnmgPdT4lLFXY6/g5rg+xDLUC5W0S+CWsonGu
         zfAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=vjxIbLAkjCsk9ddLTmBc549ybEA12+qhvYB7VOEIPic=;
        b=vV67GOZf644Q7AOCvDGwxHuYZN4AmxB+1irOpvNHTcc3AGJyT2ne3oFKRR97k8hWKj
         hRlZokm3l07RKAzkCg+wcVgSAGpD9GDfWg3QZ7gYjl3LSinaRkoUHpvB1rR0Wref4/xf
         lbZ07t5YI0oBThm7TAXxkqopfpZRnGAMan/P08IqMS1VPZ7HIbRF9TZbhtIIK9vSZpAg
         bkGWgezUCmYJjhL+TZxil1n1bkbyqlWuKo05GcKT1e8i5GUtDtMJfzE35EJP8yADCxjf
         w8KbcE0OgbUll1sFUbpZ5eNl2+RwImWRy4V1vkNHE589WR6wo4ZXR5RUfMUWA3aZqfbR
         6B/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id j2si94800lfe.5.2021.02.24.11.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 24 Feb 2021 11:11:12 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id D190220004;
	Wed, 24 Feb 2021 19:11:07 +0000 (UTC)
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
From: Alex Ghiti <alex@ghiti.fr>
To: Nylon Chen <nylon7@andestech.com>
Cc: "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
 =?UTF-8?B?TmljayBDaHVuLU1pbmcgSHUo6IOh5bO76YqYKQ==?= <nickhu@andestech.com>,
 =?UTF-8?B?QWxhbiBRdWV5LUxpYW5nIEthbyjpq5jprYHoia8p?=
 <alankao@andestech.com>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "nylon7717@gmail.com" <nylon7717@gmail.com>,
 "aryabinin@virtuozzo.com" <aryabinin@virtuozzo.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Paul Walmsley
 <paul.walmsley@sifive.com>, "glider@google.com" <glider@google.com>,
 "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
 "dvyukov@google.com" <dvyukov@google.com>
References: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
 <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
 <4fa97788-157c-4059-ae3f-28ab074c5836@ghiti.fr>
 <e15fbf55-25db-7f91-6feb-fb081ab60cdb@ghiti.fr>
 <20210222013754.GA7626@andestech.com>
 <af58ed3d-36e4-1278-dc42-7df2d875abbc@ghiti.fr>
Message-ID: <42483a2b-efb9-88a8-02b2-9f44eed3d418@ghiti.fr>
Date: Wed, 24 Feb 2021 14:11:07 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <af58ed3d-36e4-1278-dc42-7df2d875abbc@ghiti.fr>
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

Hi Nylon,

Le 2/22/21 =C3=A0 12:13 PM, Alex Ghiti a =C3=A9crit=C2=A0:
> Le 2/21/21 =C3=A0 8:37 PM, Nylon Chen a =C3=A9crit=C2=A0:
>> Hi Alex, Palmer
>>
>> Sorry I missed this message.
>> On Sun, Feb 21, 2021 at 09:38:04PM +0800, Alex Ghiti wrote:
>>> Le 2/13/21 =C3=A0 5:52 AM, Alex Ghiti a =C3=A9crit=C2=A0:
>>>> Hi Nylon, Palmer,
>>>>
>>>> Le 2/8/21 =C3=A0 1:28 AM, Alex Ghiti a =C3=A9crit=C2=A0:
>>>>> Hi Nylon,
>>>>>
>>>>> Le 1/22/21 =C3=A0 10:56 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>>>>>> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote=
:
>>>>>>> It references to x86/s390 architecture.
>>>>>>>>> So, it doesn't map the early shadow page to cover VMALLOC space.
>>>>>>>
>>>>>>> Prepopulate top level page table for the range that would=20
>>>>>>> otherwise be
>>>>>>> empty.
>>>>>>>
>>>>>>> lower levels are filled dynamically upon memory allocation while
>>>>>>> booting.
>>>>>
>>>>> I think we can improve the changelog a bit here with something like=
=20
>>>>> that:
>>>>>
>>>>> "KASAN vmalloc space used to be mapped using kasan early shadow page.
>>>>> KASAN_VMALLOC requires the top-level of the kernel page table to be
>>>>> properly populated, lower levels being filled dynamically upon memory
>>>>> allocation at runtime."
>>>>>
>>>>>>>
>>>>>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>>>>>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>>>>>>> ---
>>>>>>> =C2=A0=C2=A0arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 1 +
>>>>>>> =C2=A0=C2=A0arch/riscv/mm/kasan_init.c | 57=20
>>>>>>> +++++++++++++++++++++++++++++++++++++-
>>>>>>> =C2=A0=C2=A02 files changed, 57 insertions(+), 1 deletion(-)
>>>>>>>
>>>>>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>>>>>> index 81b76d44725d..15a2c8088bbe 100644
>>>>>>> --- a/arch/riscv/Kconfig
>>>>>>> +++ b/arch/riscv/Kconfig
>>>>>>> @@ -57,6 +57,7 @@ config RISCV
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64B=
IT
>>>>>>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MM=
U
>>>>>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.=
c
>>>>>>> index 12ddd1f6bf70..4b9149f963d3 100644
>>>>>>> --- a/arch/riscv/mm/kasan_init.c
>>>>>>> +++ b/arch/riscv/mm/kasan_init.c
>>>>>>> @@ -9,6 +9,19 @@
>>>>>>> =C2=A0=C2=A0#include <linux/pgtable.h>
>>>>>>> =C2=A0=C2=A0#include <asm/tlbflush.h>
>>>>>>> =C2=A0=C2=A0#include <asm/fixmap.h>
>>>>>>> +#include <asm/pgalloc.h>
>>>>>>> +
>>>>>>> +static __init void *early_alloc(size_t size, int node)
>>>>>>> +{
>>>>>>> +=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size=
,
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), =
MEMBLOCK_ALLOC_ACCESSIBLE, node);
>>>>>>> +
>>>>>>> +=C2=A0=C2=A0=C2=A0 if (!ptr)
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to a=
llocate %zu bytes align=3D%zx nid=3D%d
>>>>>>> from=3D%llx\n",
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 __func__, size, size, node,=20
>>>>>>> (u64)__pa(MAX_DMA_ADDRESS));
>>>>>>> +
>>>>>>> +=C2=A0=C2=A0=C2=A0 return ptr;
>>>>>>> +}
>>>>>>>
>>>>>>> =C2=A0=C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
>>>>>>> =C2=A0=C2=A0asmlinkage void __init kasan_early_init(void)
>>>>>>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void=20
>>>>>>> *end)
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
>>>>>>> =C2=A0=C2=A0}
>>>>>>>
>>>>>>> +void __init kasan_shallow_populate(void *start, void *end)
>>>>>>> +{
>>>>>>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & =
PAGE_MASK;
>>>>>>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned lon=
g)end);
>>>>>>> +=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>>>>>> +=C2=A0=C2=A0=C2=A0 int index;
>>>>>>> +=C2=A0=C2=A0=C2=A0 void *p;
>>>>>>> +=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
>>>>>>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
>>>>>>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
>>>>>>> +
>>>>>>> +=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vad=
dr);
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SA=
TP) & SATP_PPN;
>>>>>
>>>>> At this point in the boot process, we know that we use swapper_pg_dir
>>>>> so no need to read SATP.
>>>>>
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pf=
n_to_virt(pfn) + index;
>>>>>
>>>>> Here, this pgd_dir assignment is overwritten 2 lines below, so no nee=
d
>>>>> for it.
>>>>>
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd +=
 index;
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_=
k(vaddr);
>>>>>
>>>>> pgd_offset_k(vaddr) =3D init_mm.pgd + pgd_index(vaddr) so pgd_k =3D=
=3D=20
>>>>> pgd_dir.
>>>>>
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k=
);
>>>>>>> +
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(=
pgd_dir, vaddr);
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_off=
set(pgd_k, vaddr);
>>>>>>> +
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_=
SIZE) & PUD_MASK;
>>>>>
>>>>> Why do you increase vaddr *before* populating the first one ? And
>>>>> pud_addr_end does that properly: it returns the next pud address if i=
t
>>>>> does not go beyond end address to map.
>>>>>
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(=
p4d_dir, vaddr);
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4=
d_k, vaddr);
>>>>>>> +
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_di=
r)) {
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 pud_populate(&init_mm, pud_dir, p);
>>>>>
>>>>> init_mm is not needed here.
>>>>>
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;
>>>>>
>>>>> Why do you need to add PAGE_SIZE ? vaddr already points to the next=
=20
>>>>> pud.
>>>>>
>>>>> It seems like this patch tries to populate userspace page table
>>>>> whereas at this point in the boot process, only swapper_pg_dir is use=
d
>>>>> or am I missing something ?
>>>>>
>>>>> Thanks,
>>>>>
>>>>> Alex
>>>>
>>>> I implemented this morning a version that fixes all the comments I mad=
e
>>>> earlier. I was able to insert test_kasan_module on both sv39 and sv48
>>>> without any modification: set_pgd "goes through" all the unused page
>>>> table levels, whereas p*d_populate are noop for unused levels.
>>>>
>>>> If you have any comment, do not hesitate.
>>>>
>>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>>> index adbf94b7e68a..d643b222167c 100644
>>>> --- a/arch/riscv/mm/kasan_init.c
>>>> +++ b/arch/riscv/mm/kasan_init.c
>>>> @@ -195,6 +195,31 @@ static void __init kasan_populate(void *start,=20
>>>> void
>>>> *end)
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_=
SHADOW_INIT, end - start);
>>>> =C2=A0 =C2=A0}
>>>>
>>>>
>>>> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned
>>>> long end)
>>>> +{
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long next;
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *p;
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(va=
ddr);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 do {
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr, end);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned
>>>> long)lm_alias(kasan_early_shadow_pgd_next)) {
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =3D membl=
ock_alloc(PAGE_SIZE, PAGE_SIZE);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd=
_k, pfn_pgd(PFN_DOWN(__pa(p)),
>>>> PAGE_TABLE));
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 }
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next=
, vaddr !=3D end);
>>>> +}
>>>> +
>>>
>>> This way of going through the page table seems to be largely used acros=
s
>>> the kernel (cf KASAN population functions of arm64/x86) so I do think
>>> this patch brings value to Nylon and Nick's patch.
>>>
>>> I can propose a real patch if you agree and I'll add a co-developed by
>>> Nylon/Nick since this only 'improves' theirs.
>>>
>>> Thanks,
>>>
>>> Alex
>>>
>> I agree with your proposal, but when I try your patch that it dosen't=20
>> work
>> because `kasan_early_shadow_pgd_next` function wasn't define.
>=20
> Oops, I messed up my rebase, please replace=20
> 'kasan_early_shadow_pgd_next' with 'kasan_early_shadow_pmd'.
>=20
> Thank you for your feeback,
>=20
> Alex
>=20

Did you have time to test the above fix ? It would be nice to replace=20
your current patch with the above solution before it gets merged for=20
5.12, I will propose something tomorrow, feel free to review and test :)

Thanks again,

Alex

>>
>> Do you have complete patch? or just I missed some content?
>>>> +void __init kasan_shallow_populate(void *start, void *end)
>>>> +{
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigne=
d long)start & PAGE_MASK;
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIG=
N((unsigned long)end);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pgd(vaddr=
, vend);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>>>> +}
>>>> +
>>>> =C2=A0 =C2=A0void __init kasan_init(void)
>>>> =C2=A0 =C2=A0{
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, =
_end;
>>>> @@ -206,7 +231,15 @@ void __init kasan_init(void)
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early=
_shadow((void *)KASAN_SHADOW_START,
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (v=
oid=20
>>>> *)kasan_mem_to_shadow((void *)
>>>> - VMALLOC_END));
>>>> + VMEMMAP_END));
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMAL=
LOC))
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_shallow_populate(
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void=20
>>>> *)VMALLOC_START),
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void=20
>>>> *)VMALLOC_END));
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_populate_early_shadow(
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void=20
>>>> *)VMALLOC_START),
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void=20
>>>> *)VMALLOC_END));
>>>>
>>>>
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Populate the line=
ar mapping */
>>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i=
, &_start, &_end) {
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/42483a2b-efb9-88a8-02b2-9f44eed3d418%40ghiti.fr.
