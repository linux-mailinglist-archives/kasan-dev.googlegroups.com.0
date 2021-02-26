Return-Path: <kasan-dev+bncBC447XVYUEMRBU5D4KAQMGQESJVQ6TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id AB095325D72
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 07:14:44 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id l8sf3033297ljc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 22:14:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614320084; cv=pass;
        d=google.com; s=arc-20160816;
        b=cYkZHZYS9ISWEIvze1kx6ZnkYd5PU4Dce6kiXzRUBkv8lTGMB2jKwEOs2nP3WdDuC6
         CSGCFtFmfGJjYumdLitXtRQNgvtZmXHVJgKWjK//B2NIeEWcp7ToIvLEUoGCt3wLIQVg
         l2yPVQepmC1pMyfMn5X/ZXD/k1Bp7cfyaPeCdKEIQGrthygcPA/9h90hlfeVSQFAmdkB
         E3/yBJyDfuy/SJ59rFnvWwfSW4whX4ksw/YUQei9iUwnyU2FoTWH9I057hsuia8yg8fL
         jXUmqUIR1phvZYlD8Y+OYkx3E+Dexb1F6bA0BYxD6H+xqj77nQlorDeT4KrcO91fxSHH
         lBFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=3VDvh/ZzF3TRkL5anMsE4xUlv4KAZ0NaX7mg+rPaFs4=;
        b=Rv9eUwNtUO7o8MbjBjf20uumUHX/udxf+v94uvr96Q887UjrnXXISxefY2ijFcoOdJ
         oJUQQkpj50X/77E6BwWOS7BB2AV9+GMpxTqhOp5jhp2w/IJZuHd8z1I2PUnIan+Krr3Y
         IY6JbwegH+LT+uOQxrhdw6SNvxhtXxl+Sp7bMbViKYIlE8aO5BtYI7FswQTsAeafvnZN
         MIXFpPfbF2E28LWMoW8Xa1ILIUXkCefo06Jnz7El+tTydMCfycMzFSUyNLcDlZhu8rtq
         LKpJ3OR1NUCauW1X6pW6ksJMv7XBKfDKWsVocjqTUICJC383iUOVJlsusAkdYuR4mt/T
         cVbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3VDvh/ZzF3TRkL5anMsE4xUlv4KAZ0NaX7mg+rPaFs4=;
        b=VA7cw1O/tbGEFHrfaz/360+9ydFHWLqJmfK4uNOZdrHc09sdzWnxUaSdtg4TKjRirh
         ANQ2IKYxXU++beUBRANkWuXpnoXOb3lk44FSnhT8YecIXFrTjQzu8DnmoR1kImKtowsB
         FHctvd8A+FOO7RuBwxFBajdqSccc7vhdKVDvAHaP81POUh7U/OvbQmSnNsSK36GRForO
         yt6aRWDeDsXWSQ/380yzrdV5JNZTjByx8kzcSRmwLbJXe+rd24oaev2yBWR3dsHQJQDA
         h1gorsPn25ZTKmhBLKDQePDS9THhFU3wcirumYmIeRHhAz6kKMOiomdU/2aIsKKZm3Pe
         UbOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3VDvh/ZzF3TRkL5anMsE4xUlv4KAZ0NaX7mg+rPaFs4=;
        b=h2KJ/l3cr2BSzr+tz47OCfAcIAfZA6NvisZ7+RtW33Z7YzMT0xyHoOmkfWPeAxVb87
         MiFzbyzqnYjmHzTKEWFPEfXFv1CBbdrxmhn9T7KjteQCaYihdf3xKexOHjePbEdgOIIY
         FzZOVjFeXWhhGZ3Wo+cR3nJZMGpmTCOLnkMLcTnAJhYm0BIVlGJVfD2gTZmF9HA2ZPoi
         O4Fv96kCPplOyYc46EEGJY+nNmDsfkUurj/HwuvtAFYwXFpTlNSSb/Ih0Ye8/vsXnCCa
         dkiVudVEaglhbH37u6TACymxab+l6YDqOJS0HXkxP6mbjSL6/z1bUxz7L+Mb4if2+DeU
         ZglA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531r946b0NW9fTaFRoMGLxqAtKFVUMD6YIYhsOUZ2i0BKCHHG/7W
	cdivWXO4VV99nI7QmURzZMs=
X-Google-Smtp-Source: ABdhPJxM1hoaoHiMO4tddocoH1fFXNawlM22R9HyM8JPGGvC+e7JrxnuHoLzuP0W1qxeU3KVkgHtEA==
X-Received: by 2002:ac2:47f4:: with SMTP id b20mr877999lfp.524.1614320084254;
        Thu, 25 Feb 2021 22:14:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:910f:: with SMTP id m15ls1439725ljg.6.gmail; Thu, 25 Feb
 2021 22:14:43 -0800 (PST)
X-Received: by 2002:a2e:b178:: with SMTP id a24mr765426ljm.484.1614320083117;
        Thu, 25 Feb 2021 22:14:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614320083; cv=none;
        d=google.com; s=arc-20160816;
        b=HePUBm5TZKpX/PJKzHoOwdlBsf0TxLDUEyKzNddJZYhr6f2UTXnkji2NxsvxQ/e3ob
         utAreI5L0Ce0gc9g/jGbEK7znPVZI+AuDDTGl/yUUi77fkcy8Bla8YR5WiGxrRZWMMgM
         F6o6lZSbiFnUQjGSn9VfE/6fq0+Il4BDmMwkM0kq6poVvESzrszkhNQzJ1XNqoZJW3N2
         SkJATce/noc6D2/56eowr2q3PDgsHkCMUDRPgIpSN1q66730Q4q+bsiQIUylLs1VXZWj
         /mfLYsSAWzXShT6oKoSkDoYyLZZNIk/Uv6pidx2vWR6Uub9aPaes+Rsmv9dO0srZfqmD
         dcFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GwxiVagG+5Ouiam1CSPg/AzFcZtOHIwFg+8/NlFG5j4=;
        b=DmBtB+0pKh4/SSjnRc9WAt7GBiuywyPi8u4CVl5dzXpvc9zwE7FFjJ3dKUI8sucpCt
         VbPz1oeFiz7kpOj0zCdNUKJJM2CDBrpVhwoRSX66BjXZfUofcGd76GC0v9fZ7XNbIDHy
         sNIu1JzpXYv2RzaSsilbgK8yGvzFJZMqbTNLLitX9tABhpZ8mZnueqGfNIfaVmhl4NUN
         atl+2vrqZgaYgHehMFWWaFta+1HjawB+6KVpq0cK4yc2gKA8WO16nxBA1jl45WPE5Jr2
         GyxpB9+VhC8RjBDivkOCQW+HLrGKsm8/tC9cDgRpy6KRYm6ZS5MWybKNkJEcJXw25ZQE
         Et1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id c8si391658lfk.1.2021.02.25.22.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 25 Feb 2021 22:14:42 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 90ECF20003;
	Fri, 26 Feb 2021 06:14:37 +0000 (UTC)
Subject: Re: [PATCH] riscv: Add KASAN_VMALLOC support
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: aou@eecs.berkeley.edu, nickhu@andestech.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 nylon7@andestech.com, glider@google.com,
 Paul Walmsley <paul.walmsley@sifive.com>, aryabinin@virtuozzo.com,
 linux-riscv@lists.infradead.org, dvyukov@google.com
References: <mhng-ea9a6037-0f18-41d5-8c01-6c16b14b6a63@palmerdabbelt-glaptop>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <e3754d1e-f61f-f7d7-b159-52af2817428d@ghiti.fr>
Date: Fri, 26 Feb 2021 01:14:36 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <mhng-ea9a6037-0f18-41d5-8c01-6c16b14b6a63@palmerdabbelt-glaptop>
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

Hi Palmer,

Le 2/26/21 =C3=A0 12:32 AM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Wed, 24 Feb 2021 23:48:13 PST (-0800), alex@ghiti.fr wrote:
>> Le 2/25/21 =C3=A0 2:42 AM, Alexandre Ghiti a =C3=A9crit=C2=A0:
>>> Populate the top-level of the kernel page table to implement=20
>>> KASAN_VMALLOC,
>>> lower levels are filled dynamically upon memory allocation at runtime.
>>>
>>> Co-developed-by: Nylon Chen <nylon7@andestech.com>
>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>>> Co-developed-by: Nick Hu <nickhu@andestech.com>
>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>> ---
>>> =C2=A0 arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 1 +
>>> =C2=A0 arch/riscv/mm/kasan_init.c | 35 ++++++++++++++++++++++++++++++++=
++-
>>> =C2=A0 2 files changed, 35 insertions(+), 1 deletion(-)
>>>
>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>> index 8eadd1cbd524..3832a537c5d6 100644
>>> --- a/arch/riscv/Kconfig
>>> +++ b/arch/riscv/Kconfig
>>> @@ -57,6 +57,7 @@ config RISCV
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64BIT
>>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>> index 719b6e4d6075..171569df4334 100644
>>> --- a/arch/riscv/mm/kasan_init.c
>>> +++ b/arch/riscv/mm/kasan_init.c
>>> @@ -142,6 +142,31 @@ static void __init kasan_populate(void *start,=20
>>> void *end)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_SHADOW_INIT, end - s=
tart);
>>> =C2=A0 }
>>>
>>> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned=
=20
>>> long end)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>>> +=C2=A0=C2=A0=C2=A0 void *p;
>>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(vaddr);
>>> +
>>> +=C2=A0=C2=A0=C2=A0 do {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr=
, end);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =
=3D=3D (unsigned=20
>>> long)lm_alias(kasan_early_shadow_pmd)) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set=
_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> +=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next, vaddr !=3D end);
>>> +}
>>> +
>>> +void __init kasan_shallow_populate(void *start, void *end)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & PAGE=
_MASK;
>>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long)en=
d);
>>> +
>>> +=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pgd(vaddr, vend);
>>> +
>>> +=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>>> +}
>>> +
>>> =C2=A0 void __init kasan_init(void)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
>>> @@ -149,7 +174,15 @@ void __init kasan_init(void)
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow((void *)KASA=
N_SHADOW_START,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_mem=
_to_shadow((void *)
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMALLOC_END));
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMEMMAP_END));
>>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate(
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_START),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>> +=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow=
(
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_START),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start, &_end) {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D =
(void *)_start;
>>>
>>
>> Palmer, this commit should replace (if everyone agrees) Nylon and Nick's
>> Commit e178d670f251 ("riscv/kasan: add KASAN_VMALLOC support") that is
>> already in for-next.
>=20
> Sorry, but it's way too late to be rebasing things.=C2=A0 I can get tryin=
g to=20
> have
> the history clean, but in this case we're better off having this as an=20
> explicit
> fix patch -- changing hashes this late in the process messes with all the
> testing.
>=20
> I'm not sure what the issue actually is, so it'd be great if you could=20
> send the
> fix patch.=C2=A0 If not then LMK and I'll try to figure out what's going =
on. =20
> Either
> way, having the fix will make sure this gets tested properly as whatever'=
s
> going on isn't failing for me.
>=20

Nylon's patch is functional as is, but as I mentioned here=20
https://patchwork.kernel.org/project/linux-riscv/patch/20210116055836.22366=
-2-nylon7@andestech.com/,=20
it does unnecessary things (like trying to walk a user page table that=20
does not exist at this point in the boot process).

Anyway, I will send another patch rebased on top of Nylon's.

Thanks,

Alex


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
kasan-dev/e3754d1e-f61f-f7d7-b159-52af2817428d%40ghiti.fr.
