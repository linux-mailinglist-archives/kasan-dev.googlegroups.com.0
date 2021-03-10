Return-Path: <kasan-dev+bncBC447XVYUEMRBIVXUSBAMGQESOWP6DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A8C73347CA
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 20:18:59 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id e29sf7514875ljp.10
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:18:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615403939; cv=pass;
        d=google.com; s=arc-20160816;
        b=WCM3UE5U/H6K61mxFqkRzPbFWyFZdKJ0hnrwgyfoS6yNUVISSoF2Lg4BxNVTFUqOHN
         xfG8l/VZ0QD7DujeV96FT/lBwMG/vlAqIHLdq6iAHydoKT3roa4viyNcRCnCS932hg+C
         42NG+6Ibr+GFK39L+28Y5Iu7SlsGKzG6VaqCuoSng5D6krPmGAFynLLqz1/V6q39QH6T
         QpYV+ZVRuL0x+RCGR8qVuMmZtyJ1Guf4bYdS3FF8XAZQ/JDgfXTjF4l5x1+GXoV8GL3+
         sXeu0UsrdWL9chTMA2ZGb2+QTke96Zuu2PSk2xpbJ3893r66osRP3skDKrZo8RB+4gT8
         Mmzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=qhIpOwOqoxivkmHuhgy38UsH09Bl5XNPfSfQu5Wmxs0=;
        b=jHDJjk0an2G+P3f9AsezcP9iX7rQHDIr9TpVLKaqzVoER0pVjQcQHg3Ouig5UADao8
         X+XVeNr4s5guLdJsWvCkg/ExMSF9kr5XsWyWThZJDEvrO/8qPdj9CEA+yIaTCYuenKu0
         J/fP5fufRd0I4VSo3RJ9+qlF/c5kpH7oA147AX7qEn840YbKy3IN5K4W7AzuaoohMwkv
         f7wVYUCQxM187kpSV7KX/jB1PpKLleljuUFOdeSW0Px8kYaLAffIaGktgxhFPmJkc7XL
         eNIP/5eZ5wGnE9q8s0eoA5LjC7Uz7ROJHqFicmkZ5jZgn30kx933P75wAq5sXyEgSQBF
         vxZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.199 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qhIpOwOqoxivkmHuhgy38UsH09Bl5XNPfSfQu5Wmxs0=;
        b=ccavjwMX7EUJ53UmwiZ8LX85VuUM6kd6lDGHwSVNolL4aZozLS1ZqLiPX1YA6PW9J2
         HfIFDRX3gwbRTZOotHNgZ5StrhSEQPvDzOrs2WOTCu8PSD2mNlgZO9BIfbL+FeOXTsIX
         zGEpHyfI/eytVAU/lnD/8dKMok6lJUnu5iTkoIcmvyT4i1eXxVxZZA/2I/11plK7VXb3
         ueerlzZTfdcrgWKkYU7tCO8H7cdhTdmvvcfXvSWR8UVjCNBbepDkqZDpOR43RI00TCqY
         dw6eX1RHfK7Lxl3Y4LEYWpI3AzI1znWo+otofZd2JtQFz9KTrJHzP5NbsjOaMp7csRv6
         LnPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qhIpOwOqoxivkmHuhgy38UsH09Bl5XNPfSfQu5Wmxs0=;
        b=tHEBpwu8U9zC9ffgLIgHILcmDPLDi7MnaB0UXHZDg/Q1/edE/5eKhrH8L/fRR45Tcx
         zD5qaELx143ioJpJuQfUDag/ez3VRGt6MKm0tPlWAbWVywmcKCeAbgVnR5wedIfEtPgR
         oj/sA5v1tSPXubdfvfsfCXXhdRdRAJ2nfFH+YmQ8iXTsR+M5A45cm0QizKm4VG4NSYP8
         xNFyjxrTUvndHs8sHP2/hRwoNi0zd0nQVvZUXWBFXki68FK3r0vMT9VzBAej+CQd6fgU
         0+oCPDOT5a1YeGSS7IVAEsafmgdySgYaliY3913ka+H7P8KweGdn7awZDhLds6lmvOta
         Tyiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ILPwqA9jF9bOAFbpq9gkwN59r/HOwJMlOTBzTznU9MEzFr82g
	Fu7ax6ykg/xsVPx7HLk7zn0=
X-Google-Smtp-Source: ABdhPJzeJstRnnoXk+sH+pFqfJdzsH7A4UXuLPJ8nRlpKOcn2FCt8SwUGiB3luE/UPauh1Dxs/YerA==
X-Received: by 2002:a2e:9ec6:: with SMTP id h6mr2681849ljk.12.1615403938921;
        Wed, 10 Mar 2021 11:18:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a409:: with SMTP id p9ls743907ljn.0.gmail; Wed, 10 Mar
 2021 11:18:57 -0800 (PST)
X-Received: by 2002:a2e:8e91:: with SMTP id z17mr2634997ljk.384.1615403937764;
        Wed, 10 Mar 2021 11:18:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615403937; cv=none;
        d=google.com; s=arc-20160816;
        b=j6YuPzoFFuToprt2BL2wo8Ex9yUlmVaMjHZL0KJlCNTPh3Cb4MvW1PIcbR4mWeUHjt
         GWE/goyLpOo4e61Z2pgBKSPM4Kuw1YORg8ywQxHUiADcxHdIt8g82bEvgWGHzR39+F96
         JlADE+4mi3Zd3CIxkgj7oApeLbVm/Y1HCIjPp/qUCbrjjot93KTSEvw5SptfBgSuMD0E
         GlswsZYtwjlxymELU905YkNlBAKaBiNuZ8TyYXlvKwgoLwwDKISQSurEsqVkOeIj6gnG
         rPfxD3NfEc1Un8L2AFSm2pTSj6uEc6yVKZ/FOgmMosKB+5pPXQsgyU1T0IIReW406zjC
         to0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=2zJZtf3XxCMW6/wv+zOkifQk+mjjcuWkEEA+oNPNdNM=;
        b=jxqOHKYNIvI9wqFjwQTkBfzDsys4pGWMOSNbsqy7rD9IOTdf4Z/iGjmNOBi01BDeaV
         2INLFCxwDhw2ARogtKd46lXhbTNU4UVKIBkFOjzd1aMqV/v4tEbtCcMbU/42Adch7Axp
         EOaD4wk12vZQkFJkgKwATwI29pEueSjtuX+AgOUPty0RzGTQOCdLmOy+ooqMC8tmSntZ
         r93aadcBkKOtRw1UZjsB7aP3In2omwzm5i21KBSJekl8CI26kjyZhfMgLYXkahFHhqXm
         DJAyamoOGZiPJM+A8QuNYqLhO2nxTgoS7vOpcpvhhUuoiw0EeP5thWz31bF7HxAMt/3O
         g7ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.199 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay9-d.mail.gandi.net (relay9-d.mail.gandi.net. [217.70.183.199])
        by gmr-mx.google.com with ESMTPS id a66si12543lfd.7.2021.03.10.11.18.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 10 Mar 2021 11:18:57 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.199 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.199;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay9-d.mail.gandi.net (Postfix) with ESMTPSA id 6273DFF803;
	Wed, 10 Mar 2021 19:18:52 +0000 (UTC)
Subject: Re: [PATCH v2] riscv: Improve KASAN_VMALLOC support
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
 nylon7@andestech.com, nickhu@andestech.com, aryabinin@virtuozzo.com,
 glider@google.com, dvyukov@google.com, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <mhng-a1ab9e7a-d992-4432-badc-02cc788b1ace@penguin>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <7db28eaf-f556-8ca5-e6b9-b932d4e786e2@ghiti.fr>
Date: Wed, 10 Mar 2021 14:18:53 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <mhng-a1ab9e7a-d992-4432-badc-02cc788b1ace@penguin>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.199 is neither permitted nor denied by best guess
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

Le 3/9/21 =C3=A0 9:37 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Fri, 26 Feb 2021 10:01:54 PST (-0800), alex@ghiti.fr wrote:
>> When KASAN vmalloc region is populated, there is no userspace process an=
d
>> the page table in use is swapper_pg_dir, so there is no need to read
>> SATP. Then we can use the same scheme used by kasan_populate_p*d
>> functions to go through the page table, which harmonizes the code.
>>
>> In addition, make use of set_pgd that goes through all unused page table
>> levels, contrary to p*d_populate functions, which makes this function=20
>> work
>> whatever the number of page table levels.
>>
>> And finally, make sure the writes to swapper_pg_dir are visible using
>> an sfence.vma.
>=20
> So I think this is actually a bug: without the fence we could get a=20
> kasan-related fault at any point (as the mappings might not be visible=20
> yet), and if we get one when inside do_page_fault() (or while holding a=
=20
> lock it wants) we'll end up deadlocking against ourselves.=C2=A0 That'll=
=20
> probably never happen in practice, but it'd still be good to get the=20
> fence onto fixes. The rest are cleanups, they're for for-next (and=20
> should probably be part of your sv48 series, if you need to re-spin it=20
> -- I'll look at that next).

I only talked about sv48 support in the changelog as it explains why I=20
replaced p*d_populate functions for set_p*d, this is not directly linked=20
to the sv48 patchset, this is just a bonus that it works for both :)

>=20
> LMK if you want to split this up, or if you want me to do it.=C2=A0 Eithe=
r way,

I'll split it up: one patch for the cleanup and one patch for the fix.

>=20
> Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>

Thanks,

Alex

>=20
> Thanks!
>=20
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>> ---
>>
>> Changes in v2:
>> - Quiet kernel test robot warnings about missing prototypes by declaring
>> =C2=A0 the introduced functions as static.
>>
>> =C2=A0arch/riscv/mm/kasan_init.c | 61 +++++++++++++---------------------=
----
>> =C2=A01 file changed, 20 insertions(+), 41 deletions(-)
>>
>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> index e3d91f334b57..aaa3bdc0ffc0 100644
>> --- a/arch/riscv/mm/kasan_init.c
>> +++ b/arch/riscv/mm/kasan_init.c
>> @@ -11,18 +11,6 @@
>> =C2=A0#include <asm/fixmap.h>
>> =C2=A0#include <asm/pgalloc.h>
>>
>> -static __init void *early_alloc(size_t size, int node)
>> -{
>> -=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), MEMBL=
OCK_ALLOC_ACCESSIBLE, node);
>> -
>> -=C2=A0=C2=A0=C2=A0 if (!ptr)
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to alloca=
te %zu bytes align=3D%zx nid=3D%d=20
>> from=3D%llx\n",
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __fu=
nc__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
>> -
>> -=C2=A0=C2=A0=C2=A0 return ptr;
>> -}
>> -
>> =C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
>> =C2=A0asmlinkage void __init kasan_early_init(void)
>> =C2=A0{
>> @@ -155,38 +143,29 @@ static void __init kasan_populate(void *start,=20
>> void *end)
>> =C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_SHADOW_INIT, end - start);
>> =C2=A0}
>>
>> -void __init kasan_shallow_populate(void *start, void *end)
>> +static void __init kasan_shallow_populate_pgd(unsigned long vaddr,=20
>> unsigned long end)
>> =C2=A0{
>> -=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & PAGE_=
MASK;
>> -=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long)end=
);
>> -=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>> -=C2=A0=C2=A0=C2=A0 int index;
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> =C2=A0=C2=A0=C2=A0=C2=A0 void *p;
>> -=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
>> -=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
>> -=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
>> -
>> -=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vaddr);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SATP) &=
 SATP_PPN;
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pfn_to_=
virt(pfn) + index;
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd + inde=
x;
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_k(vad=
dr);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k);
>> -
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(pgd_d=
ir, vaddr);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_offset(p=
gd_k, vaddr);
>> -
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_SIZE)=
 & PUD_MASK;
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(p4d_d=
ir, vaddr);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4d_k, =
vaddr);
>> -
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_dir)) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_=
populate(&init_mm, pud_dir, p);
>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(vaddr);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pgd_addr_end(vaddr,=
 end);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =
=3D=3D (unsigned=20
>> long)lm_alias(kasan_early_shadow_pmd)) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_=
pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;
>> -=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next, vaddr !=3D end);
>> +}
>> +
>> +static void __init kasan_shallow_populate(void *start, void *end)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & PAGE_=
MASK;
>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long)end=
);
>> +
>> +=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pgd(vaddr, vend);
>> +
>> +=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>> =C2=A0}
>>
>> =C2=A0void __init kasan_init(void)
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
kasan-dev/7db28eaf-f556-8ca5-e6b9-b932d4e786e2%40ghiti.fr.
