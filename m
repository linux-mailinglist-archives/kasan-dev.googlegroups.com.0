Return-Path: <kasan-dev+bncBC447XVYUEMRBJ6MZ6AQMGQEIYGKN4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64220321DC4
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 18:13:12 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id rh17sf1120234ejb.19
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 09:13:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614013992; cv=pass;
        d=google.com; s=arc-20160816;
        b=hbx/dP/VoGx1txN+z87RUF0TY4L8Nm4ziyjErGeamqx7j8kBrriP0n0GgKC//eR6im
         96QRRg2S+NvhVTkbW8ex0nu92ECu/CFQ2VGfyTn4G4JiFI6Fiw0y6zWc0ygwnRS+Ybws
         gWAxba6rlQo9M+6h6VS/88D8c6Bt7oeNNz+z907gaT8YQqKbEF9iyIoEp5tWKyJ28Q+s
         krSWbrUcLj3P8xaoJRvZF8Il13z4bIW+wvlkR5kOsFPfT2F4MPSCOPGKHRcJdmpDrwMb
         tbpDDUxouR7Qcf4sRb64+YierNS1nEOube9pMcO7kYu4yyHVcJpGAkRuauWF8yKrQDPA
         z2Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Hitt2dMlWGrn8S846OvBSs0jnL36fOJb0pJa6Bv+yWE=;
        b=vO0AqFiOV+Tfkt7DcsBKB84VBtPIV26nctzC+ob6cJFwpFvDOksWyiBWNa0Svwj62/
         Rpa0oucZgnxf20uvympsnY572pvtiH8pB1p272WNq7QwG5PjcDY9Fs+0ZFZDHWLu1t3C
         ba6zI6oO9VxP0gdpyJQL5+kk4cQTecbL1OzJpotmJ0ul27Ra753bHRCZi9rz/KvV/VQz
         5lS2NAQc19Xzhys71Ta8PTxtdRBe/BKnQjfg3/YekFCD9/ZCkmJsvMcdBS2eoWSbn9Xs
         0/palWZqFgnUaK0j+J40180xbbWnaXFB6wwJgQKM/eOt40KVTHk5rUNWsFtamm1X3PYv
         Gq5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hitt2dMlWGrn8S846OvBSs0jnL36fOJb0pJa6Bv+yWE=;
        b=d05vShiIpwlADrdzNZBtgVfza2Wv7300EzWq10w/LC6/7WfNSku0HqII2mayGYBgRv
         +uYC0Iaj+8dfjwEikBv/WAjSr1SOr+/gK9BeUVdRhf1IoaFP1CezcvKF4K0deAJrREck
         NDWrYu8c8RyTeHUmy0i81guT0vA1g1f7G++7Iq7i48mOyEwX3q423zwSRGbcvQRfaAbU
         IXoQsd37sIZo6LrBdNB/lyOtR5fj6KMpdBKh8D12Ha33A80Dx/3UP6xw1M6uN5aCHvAJ
         regfT1njrgpUpCYmpG6gzO5PmqlRrt3oVyCPmB52MtrjBxjCPfLvtpccXwdiaU5i1Py7
         gmDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hitt2dMlWGrn8S846OvBSs0jnL36fOJb0pJa6Bv+yWE=;
        b=J+TOmylns4+mijAPSWsingUdAMBNgssD3zmqF3+uMARL7AEjwbgefzmWAbC5oglsSE
         CYAL/QVc0JPDSKQaaA9TCi2yLXpwjUaiqXKpv1n0SuU1c6onx2+xFEjatuhImvvF5MDF
         KwdWgAhB2MYlYNJpXNsS1cLnFs/dTV425qEedfEJazu/uz2t5sViISbB8Zdc6u+vCKw1
         5biLGGiL0EdWJq56LEniqQYOWgnvit7FB8eni5j+6psuHc9ll5pG2VioS2j34Sn8pmRG
         TqV5pSR/ajNVHXa7dre/N2/PLUiPkIOC5QAoT+6CpiFnQ5SEpbKm2ZIkS/I3qnh7KAOC
         vozA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531c0Mz3TOcozioRkZIHvIe72LLZ9lA/7QkDQbBnycC9Scp1H++f
	5HhK8KrhagxP0HKxLtU+WI0=
X-Google-Smtp-Source: ABdhPJwrDr1RHbwBVL7hBV2PatrNwO33/dFSHKCZcsjcoeiO6AojPJWMQQ2HFzEWhg1JImAcLAYusQ==
X-Received: by 2002:a17:906:4d99:: with SMTP id s25mr15369551eju.351.1614013992138;
        Mon, 22 Feb 2021 09:13:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:b24:: with SMTP id bo4ls7610371edb.1.gmail; Mon, 22
 Feb 2021 09:13:11 -0800 (PST)
X-Received: by 2002:a05:6402:151:: with SMTP id s17mr22650470edu.107.1614013991392;
        Mon, 22 Feb 2021 09:13:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614013991; cv=none;
        d=google.com; s=arc-20160816;
        b=npTQ7aFomRhLr5jkwIVD/aQ+Sqe2O99orgb9f7hHo6VefNZB0r/QcjD6fAYP4mWIfh
         bYJRZvc4jLIxPAeK6CZ/WKIN6Jj4zHSVbCX9MLd2tRuanB9AmP8N8EFMj910PZcoyODK
         xvSugymkChLpZgqdp2myS4O6IjvC9XY8JalW+bic9yHOzfrGa8zaVqLvNk2zxkAtC1Iw
         sqUAGa0jrtgBTLTmNkuEB1ET2xfluCsKRg8yNNP96veFOnfkf3sFsvqKtqTl2f7XnGye
         53s4fEP2dYbkcZAXezMHKpGDYItGFNbhXQ2MqGEeZ+mpfo2TWqmjVOnUwc7XMvPkp+LE
         oRQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=5eMxdFIdZRflKKam03lDvMrLbC4ZfqP3UZ+zwVBonc8=;
        b=0VHEzl/U2QNtQSlNGEIPwhaNDiYWDo3V6Naf4U+8445fWJsjCTUv75EhrtN9dRvZqP
         yYrqlUwOdbbJdhdNG7MCS6WBqKu25XiIFRurQbzjEeZ/PZMz3DPsR6I9QgIMxWkKNdQT
         MO8aYxJy2bUjjvvRAZAo4uE66w4HEVsCB0BAXYP1n+6v1gxGSlXhY/E7UkvEpwjuXrXh
         6fM1jN9QfskIKpDxnPBcS8UjXSnUnytw6t/ZqDgkZztThAKMIEm6nIdaAf8tMNJ6JgqD
         FhW2Td+asjrMRTNCPsLs22ESZRqtlxoDSYBEuimJdJC8nXDSEO5T2bVmuFNOfdFS15kb
         Te4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay10.mail.gandi.net (relay10.mail.gandi.net. [217.70.178.230])
        by gmr-mx.google.com with ESMTPS id k3si140570eds.1.2021.02.22.09.13.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 22 Feb 2021 09:13:11 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.230;
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay10.mail.gandi.net (Postfix) with ESMTPSA id B8C0324000A;
	Mon, 22 Feb 2021 17:13:05 +0000 (UTC)
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
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
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <af58ed3d-36e4-1278-dc42-7df2d875abbc@ghiti.fr>
Date: Mon, 22 Feb 2021 12:13:05 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <20210222013754.GA7626@andestech.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.230 is neither permitted nor denied by best guess
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

Le 2/21/21 =C3=A0 8:37 PM, Nylon Chen a =C3=A9crit=C2=A0:
> Hi Alex, Palmer
>=20
> Sorry I missed this message.
> On Sun, Feb 21, 2021 at 09:38:04PM +0800, Alex Ghiti wrote:
>> Le 2/13/21 =C3=A0 5:52 AM, Alex Ghiti a =C3=A9crit=C2=A0:
>>> Hi Nylon, Palmer,
>>>
>>> Le 2/8/21 =C3=A0 1:28 AM, Alex Ghiti a =C3=A9crit=C2=A0:
>>>> Hi Nylon,
>>>>
>>>> Le 1/22/21 =C3=A0 10:56 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>>>>> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
>>>>>> It references to x86/s390 architecture.
>>>>>>>> So, it doesn't map the early shadow page to cover VMALLOC space.
>>>>>>
>>>>>> Prepopulate top level page table for the range that would otherwise =
be
>>>>>> empty.
>>>>>>
>>>>>> lower levels are filled dynamically upon memory allocation while
>>>>>> booting.
>>>>
>>>> I think we can improve the changelog a bit here with something like th=
at:
>>>>
>>>> "KASAN vmalloc space used to be mapped using kasan early shadow page.
>>>> KASAN_VMALLOC requires the top-level of the kernel page table to be
>>>> properly populated, lower levels being filled dynamically upon memory
>>>> allocation at runtime."
>>>>
>>>>>>
>>>>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>>>>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>>>>>> ---
>>>>>>  =C2=A0arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 1 +
>>>>>>  =C2=A0arch/riscv/mm/kasan_init.c | 57 +++++++++++++++++++++++++++++=
++++++++-
>>>>>>  =C2=A02 files changed, 57 insertions(+), 1 deletion(-)
>>>>>>
>>>>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>>>>> index 81b76d44725d..15a2c8088bbe 100644
>>>>>> --- a/arch/riscv/Kconfig
>>>>>> +++ b/arch/riscv/Kconfig
>>>>>> @@ -57,6 +57,7 @@ config RISCV
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64BIT
>>>>>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
>>>>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>>>>> index 12ddd1f6bf70..4b9149f963d3 100644
>>>>>> --- a/arch/riscv/mm/kasan_init.c
>>>>>> +++ b/arch/riscv/mm/kasan_init.c
>>>>>> @@ -9,6 +9,19 @@
>>>>>>  =C2=A0#include <linux/pgtable.h>
>>>>>>  =C2=A0#include <asm/tlbflush.h>
>>>>>>  =C2=A0#include <asm/fixmap.h>
>>>>>> +#include <asm/pgalloc.h>
>>>>>> +
>>>>>> +static __init void *early_alloc(size_t size, int node)
>>>>>> +{
>>>>>> +=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size,
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), M=
EMBLOCK_ALLOC_ACCESSIBLE, node);
>>>>>> +
>>>>>> +=C2=A0=C2=A0=C2=A0 if (!ptr)
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to al=
locate %zu bytes align=3D%zx nid=3D%d
>>>>>> from=3D%llx\n",
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
__func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
>>>>>> +
>>>>>> +=C2=A0=C2=A0=C2=A0 return ptr;
>>>>>> +}
>>>>>>
>>>>>>  =C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
>>>>>>  =C2=A0asmlinkage void __init kasan_early_init(void)
>>>>>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void *en=
d)
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
>>>>>>  =C2=A0}
>>>>>>
>>>>>> +void __init kasan_shallow_populate(void *start, void *end)
>>>>>> +{
>>>>>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & P=
AGE_MASK;
>>>>>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long=
)end);
>>>>>> +=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>>>>> +=C2=A0=C2=A0=C2=A0 int index;
>>>>>> +=C2=A0=C2=A0=C2=A0 void *p;
>>>>>> +=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
>>>>>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
>>>>>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
>>>>>> +
>>>>>> +=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vadd=
r);
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SAT=
P) & SATP_PPN;
>>>>
>>>> At this point in the boot process, we know that we use swapper_pg_dir
>>>> so no need to read SATP.
>>>>
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pfn=
_to_virt(pfn) + index;
>>>>
>>>> Here, this pgd_dir assignment is overwritten 2 lines below, so no need
>>>> for it.
>>>>
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd + =
index;
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_k=
(vaddr);
>>>>
>>>> pgd_offset_k(vaddr) =3D init_mm.pgd + pgd_index(vaddr) so pgd_k =3D=3D=
 pgd_dir.
>>>>
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k)=
;
>>>>>> +
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(p=
gd_dir, vaddr);
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_offs=
et(pgd_k, vaddr);
>>>>>> +
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_S=
IZE) & PUD_MASK;
>>>>
>>>> Why do you increase vaddr *before* populating the first one ? And
>>>> pud_addr_end does that properly: it returns the next pud address if it
>>>> does not go beyond end address to map.
>>>>
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(p=
4d_dir, vaddr);
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4d=
_k, vaddr);
>>>>>> +
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_dir=
)) {
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
pud_populate(&init_mm, pud_dir, p);
>>>>
>>>> init_mm is not needed here.
>>>>
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;
>>>>
>>>> Why do you need to add PAGE_SIZE ? vaddr already points to the next pu=
d.
>>>>
>>>> It seems like this patch tries to populate userspace page table
>>>> whereas at this point in the boot process, only swapper_pg_dir is used
>>>> or am I missing something ?
>>>>
>>>> Thanks,
>>>>
>>>> Alex
>>>
>>> I implemented this morning a version that fixes all the comments I made
>>> earlier. I was able to insert test_kasan_module on both sv39 and sv48
>>> without any modification: set_pgd "goes through" all the unused page
>>> table levels, whereas p*d_populate are noop for unused levels.
>>>
>>> If you have any comment, do not hesitate.
>>>
>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>> index adbf94b7e68a..d643b222167c 100644
>>> --- a/arch/riscv/mm/kasan_init.c
>>> +++ b/arch/riscv/mm/kasan_init.c
>>> @@ -195,6 +195,31 @@ static void __init kasan_populate(void *start, voi=
d
>>> *end)
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_SHADOW=
_INIT, end - start);
>>>   =C2=A0}
>>>
>>>
>>> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned
>>> long end)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long next;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *p;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(vad=
dr);
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 do {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr, end);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned
>>> long)lm_alias(kasan_early_shadow_pgd_next)) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =3D membl=
ock_alloc(PAGE_SIZE, PAGE_SIZE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd=
_k, pfn_pgd(PFN_DOWN(__pa(p)),
>>> PAGE_TABLE));
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 }
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next,=
 vaddr !=3D end);
>>> +}
>>> +
>>
>> This way of going through the page table seems to be largely used across
>> the kernel (cf KASAN population functions of arm64/x86) so I do think
>> this patch brings value to Nylon and Nick's patch.
>>
>> I can propose a real patch if you agree and I'll add a co-developed by
>> Nylon/Nick since this only 'improves' theirs.
>>
>> Thanks,
>>
>> Alex
>>
> I agree with your proposal, but when I try your patch that it dosen't wor=
k
> because `kasan_early_shadow_pgd_next` function wasn't define.

Oops, I messed up my rebase, please replace=20
'kasan_early_shadow_pgd_next' with 'kasan_early_shadow_pmd'.

Thank you for your feeback,

Alex

>=20
> Do you have complete patch? or just I missed some content?
>>> +void __init kasan_shallow_populate(void *start, void *end)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned=
 long)start & PAGE_MASK;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN=
((unsigned long)end);
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pgd(vaddr,=
 vend);
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>>> +}
>>> +
>>>   =C2=A0void __init kasan_init(void)
>>>   =C2=A0{
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
>>> @@ -206,7 +231,15 @@ void __init kasan_init(void)
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shado=
w((void *)KASAN_SHADOW_START,
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)=
kasan_mem_to_shadow((void *)
>>> - VMALLOC_END));
>>> + VMEMMAP_END));
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMALL=
OC))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_shallow_populate(
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_START),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_END));
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_populate_early_shadow(
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_START),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kas=
an_mem_to_shadow((void *)VMALLOC_END));
>>>
>>>
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Populate the linear map=
ping */
>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_st=
art, &_end) {
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/af58ed3d-36e4-1278-dc42-7df2d875abbc%40ghiti.fr.
