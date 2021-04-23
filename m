Return-Path: <kasan-dev+bncBC447XVYUEMRBAENRKCAMGQENMQUU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 04482368EE0
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 10:34:09 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id y12-20020a2e7d0c0000b02900c014139dd1sf1905330ljc.4
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 01:34:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619166848; cv=pass;
        d=google.com; s=arc-20160816;
        b=g/rD0+DHv4XfLr6lGioi7YJ153F9Ja/M5YzhHoD2SLz6cBwrfN1oaiB937gLIrvzb5
         Rxtf4lbWKZ7ZdLpfk6YYe+4muanUQm3RCW/xIqL8a/p2nDpXnzXsN8RUOcWMtC1Q36Cv
         YYRl9+n8JIZZnN9wircHg+3tntF/0YV7BgsBiFRAS7Qv6Dgm/sYPhrX5caSddRl4R8cf
         CvH+pJnNI9rD/3ZHDQojxYI0ar9yTxzY8tX0BTogqXmxYkg/G2mJ+2yjWV8dpieZ8w++
         D7MgBagE4Lyva7ViQhZnZgyBIEipiWIdaGfmXIemaX7aCuG/zGWbFcOi29zEo0/R6/wo
         7nQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=SV8O/88XKr/IOirpkKbS8e+18f6UyQQx9oVZkmeWsRI=;
        b=iUrbrxX9ejrb1FvONEKEpKvMzDa+Fax2kddxCTpXYFW2YiPfg1HKok/JqIbUPJR6FN
         kHLYXA1xcbUvV/Bu5R9vM9pmlMre9hwP0alDxNN3Isq29/22H5RETYVW+UsTOPQihR3N
         u0jP4RjblkHIpgUWCP8I+WlbuaqegzBJfRW+l4cvecIouLVWNGWBKFjtoK6P3/nmmMQm
         6cgkzAkdCw4yFZIwZT/k2nXdqWHz3nlvx5yjDWqmqLxYrbhYkKzLiRDVT7fpjtdB2luH
         r9HT0zISy6Hq4M8DqvVbiuSFE8H98Ysu8uGj1++PYGNfPbdVUgyp6BrOLonWxwoAfEf3
         nZew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SV8O/88XKr/IOirpkKbS8e+18f6UyQQx9oVZkmeWsRI=;
        b=EJHflimxCTwkldNFMOZIAODwFZWzd5WNp/hXJukZFTD4oca2DVZ86/u1A55tw+awSs
         xP9REwrrC0Oe9VU0eGMr71K12ZRS2l5/C5srU05zeIhhHGmpAiudPZ3fFtGDeVVx9YXi
         5CTzWsf7S42yp+H++RwN/jquejIdCN+0Ei5bdT0stGxjBioKeaZFGkwKv/acZg7/eeCe
         G9WVRH9X62ar8i786bW9DnnjK3iTkSGeXHr/TUBNlaLyQqOtlADBzdACSyw/LjK5vnvh
         RYX4LfnZonTxbhAmJZIG+SD5OSpCpqqEsnLmrYrJtkKEExcSu+yyEW1z+ntN8YbwwjYG
         ixzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SV8O/88XKr/IOirpkKbS8e+18f6UyQQx9oVZkmeWsRI=;
        b=MEZEf6eyRtObCS8sYCagvDpRT59GORBRbXOAZRj3aNy6P5Pf6P+C9FQF99L7sLDf6j
         0JwGw0BD39RmjFN94CFs9I9Gp0mTUWFdS4bBHnsZmXTUV11gO6kL7cgmtAtNBWt6NXKF
         t1bN2OxCsC47MavkD8hjP8JaOg5TFLKzSscNbkExXBLtNJx1KQtLraTlnAUZ4DIcblIe
         qM2y5/IPPQZdEvFbCOpDD07WjSfMUY6HJbFKneoZnjEbGWYguko4nJgrZYJMRY+JF8PB
         Z52cKjNXKXG69zMHFpYI88axjjRSAKoR784eUddlqWKWsI1Cx1ywboNbM5hfRJZLKkR/
         wNqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XELFL8t3AUYjGeHFr7t7Y9TsHrYuwSApWZFVPHyj4Z0ptHpUG
	Z1Z95k3PNe81uVQwIApi3vg=
X-Google-Smtp-Source: ABdhPJy5+Z49ANoRNVoWExTha373x9KANasi8jjPBJ/E0OtB0U3RnsZaGR6Ikoi+3BANPsna/MpIKQ==
X-Received: by 2002:a2e:720f:: with SMTP id n15mr2013419ljc.400.1619166848348;
        Fri, 23 Apr 2021 01:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c92:: with SMTP id 140ls245678lfm.2.gmail; Fri, 23 Apr
 2021 01:34:07 -0700 (PDT)
X-Received: by 2002:a05:6512:358b:: with SMTP id m11mr1989217lfr.179.1619166847232;
        Fri, 23 Apr 2021 01:34:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619166847; cv=none;
        d=google.com; s=arc-20160816;
        b=YawBjAXEPjVl2XZUFvk62T9lozpLw9A38WzKnSYh0tm9mrIamLkk3xyw77b8RTrRtV
         ir/a+R5wpW6qcVV5cxgNTETzG9qPf9rHXLPyg52wdnTzue/hZkySd7UzmE1l/h+MUPiH
         z5J/9+K1HxAYisrN4Cd7NXhCmtNa38WS7jpkRD2I9mxZlej+WmpEVwscKqYUwmK8p7on
         eoOeLmqHW3hw7J39defkfTll3+mGs/zZZC2bH50Sqy9yHv6djlVbwGtYT5QFGtixdGxI
         PaqkXrhvj4S2AW6sJ+522mulgLEWsDfeRKFamGpRwukzxeW0z2HAvfZA/hhg9Mxs8vRi
         Qg8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=kk4Yf0r0GhZLTEFLCr0o+DDD5D/QxTNMw6tTugkWxTc=;
        b=C2XeUUBx43IoOiaQPU2fAWa1He9xk/fSVAKNomL8+NhZZYxnQ++oBNAnGJ+naBqq5Y
         c3A0YYKRclwkTGN7MgTN0jkCy2hsTz62VBH5epFI41rjiI29YsrXGCEs3KaWbojczSgo
         TXKy8arqxYc2J9gXLyaLoXIXaGCFE4qT0pHra7mBoD/hkH8aM06Kh+YlhN2NfbFxXd5H
         f+wK1a3vubBvo/qpTG+TXHlNp78O4hf/AprEnMckLMcCtsk7/WV7rVQvLR8k6/87eTQ2
         dclxpMaOV0UAN2w/FRbdGEbMIW160sB122ftnE9yx1I8v6QwF+j8qTMKO9FNVVLc8QfZ
         OJ7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id p18si504495lji.8.2021.04.23.01.34.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 23 Apr 2021 01:34:07 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 178B620003;
	Fri, 23 Apr 2021 08:34:02 +0000 (UTC)
Subject: Re: [PATCH] riscv: Fix 32b kernel caused by 64b kernel mapping moving
 outside linear mapping
To: Anup Patel <anup@brainfault.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 Albert Ou <aou@eecs.berkeley.edu>, Arnd Bergmann <arnd@arndb.de>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-doc@vger.kernel.org, linux-riscv <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com, linux-arch <linux-arch@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>
References: <20210417172159.32085-1-alex@ghiti.fr>
 <CAAhSdy23jRTp3VoBpnH8B79eSSmuw8qMEYrXyh-02ccWT3O5QQ@mail.gmail.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <66e9a8e0-5764-2eea-4070-bad3fb7ee48e@ghiti.fr>
Date: Fri, 23 Apr 2021 04:34:02 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.0
MIME-Version: 1.0
In-Reply-To: <CAAhSdy23jRTp3VoBpnH8B79eSSmuw8qMEYrXyh-02ccWT3O5QQ@mail.gmail.com>
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

Le 4/20/21 =C3=A0 12:18 AM, Anup Patel a =C3=A9crit=C2=A0:
> On Sat, Apr 17, 2021 at 10:52 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>
>> Fix multiple leftovers when moving the kernel mapping outside the linear
>> mapping for 64b kernel that left the 32b kernel unusable.
>>
>> Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear mappi=
ng")
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>=20
> Quite a few #ifdef but I don't see any better way at the moment. Maybe we=
 can
> clean this later. Otherwise looks good to me.
>=20
> Reviewed-by: Anup Patel <anup@brainfault.org>

Thanks Anup!

@Palmer: This is not on for-next yet and then rv32 is broken. This does=20
not apply immediately on top of for-next though, so if you need a new=20
version, I can do that. But this squashes nicely with the patch it fixes=20
if you prefer.

Let me know, I can do that very quickly.

Alex

>=20
> Regards,
> Anup
>=20
>> ---
>>   arch/riscv/include/asm/page.h    |  9 +++++++++
>>   arch/riscv/include/asm/pgtable.h | 16 ++++++++++++----
>>   arch/riscv/mm/init.c             | 25 ++++++++++++++++++++++++-
>>   3 files changed, 45 insertions(+), 5 deletions(-)
>>
>> diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page=
.h
>> index 22cfb2be60dc..f64b61296c0c 100644
>> --- a/arch/riscv/include/asm/page.h
>> +++ b/arch/riscv/include/asm/page.h
>> @@ -90,15 +90,20 @@ typedef struct page *pgtable_t;
>>
>>   #ifdef CONFIG_MMU
>>   extern unsigned long va_pa_offset;
>> +#ifdef CONFIG_64BIT
>>   extern unsigned long va_kernel_pa_offset;
>> +#endif
>>   extern unsigned long pfn_base;
>>   #define ARCH_PFN_OFFSET                (pfn_base)
>>   #else
>>   #define va_pa_offset           0
>> +#ifdef CONFIG_64BIT
>>   #define va_kernel_pa_offset    0
>> +#endif
>>   #define ARCH_PFN_OFFSET                (PAGE_OFFSET >> PAGE_SHIFT)
>>   #endif /* CONFIG_MMU */
>>
>> +#ifdef CONFIG_64BIT
>>   extern unsigned long kernel_virt_addr;
>>
>>   #define linear_mapping_pa_to_va(x)     ((void *)((unsigned long)(x) + =
va_pa_offset))
>> @@ -112,6 +117,10 @@ extern unsigned long kernel_virt_addr;
>>          (_x < kernel_virt_addr) ?                                      =
         \
>>                  linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(_=
x);      \
>>          })
>> +#else
>> +#define __pa_to_va_nodebug(x)  ((void *)((unsigned long) (x) + va_pa_of=
fset))
>> +#define __va_to_pa_nodebug(x)  ((unsigned long)(x) - va_pa_offset)
>> +#endif
>>
>>   #ifdef CONFIG_DEBUG_VIRTUAL
>>   extern phys_addr_t __virt_to_phys(unsigned long x);
>> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/p=
gtable.h
>> index 80e63a93e903..5afda75cc2c3 100644
>> --- a/arch/riscv/include/asm/pgtable.h
>> +++ b/arch/riscv/include/asm/pgtable.h
>> @@ -16,19 +16,27 @@
>>   #else
>>
>>   #define ADDRESS_SPACE_END      (UL(-1))
>> -/*
>> - * Leave 2GB for kernel and BPF at the end of the address space
>> - */
>> +
>> +#ifdef CONFIG_64BIT
>> +/* Leave 2GB for kernel and BPF at the end of the address space */
>>   #define KERNEL_LINK_ADDR       (ADDRESS_SPACE_END - SZ_2G + 1)
>> +#else
>> +#define KERNEL_LINK_ADDR       PAGE_OFFSET
>> +#endif
>>
>>   #define VMALLOC_SIZE     (KERN_VIRT_SIZE >> 1)
>>   #define VMALLOC_END      (PAGE_OFFSET - 1)
>>   #define VMALLOC_START    (PAGE_OFFSET - VMALLOC_SIZE)
>>
>> -/* KASLR should leave at least 128MB for BPF after the kernel */
>>   #define BPF_JIT_REGION_SIZE    (SZ_128M)
>> +#ifdef CONFIG_64BIT
>> +/* KASLR should leave at least 128MB for BPF after the kernel */
>>   #define BPF_JIT_REGION_START   PFN_ALIGN((unsigned long)&_end)
>>   #define BPF_JIT_REGION_END     (BPF_JIT_REGION_START + BPF_JIT_REGION_=
SIZE)
>> +#else
>> +#define BPF_JIT_REGION_START   (PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>> +#define BPF_JIT_REGION_END     (VMALLOC_END)
>> +#endif
>>
>>   /* Modules always live before the kernel */
>>   #ifdef CONFIG_64BIT
>> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
>> index 093f3a96ecfc..dc9b988e0778 100644
>> --- a/arch/riscv/mm/init.c
>> +++ b/arch/riscv/mm/init.c
>> @@ -91,8 +91,10 @@ static void print_vm_layout(void)
>>                    (unsigned long)VMALLOC_END);
>>          print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
>>                    (unsigned long)high_memory);
>> +#ifdef CONFIG_64BIT
>>          print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
>>                    (unsigned long)ADDRESS_SPACE_END);
>> +#endif
>>   }
>>   #else
>>   static void print_vm_layout(void) { }
>> @@ -165,9 +167,11 @@ static struct pt_alloc_ops pt_ops;
>>   /* Offset between linear mapping virtual address and kernel load addre=
ss */
>>   unsigned long va_pa_offset;
>>   EXPORT_SYMBOL(va_pa_offset);
>> +#ifdef CONFIG_64BIT
>>   /* Offset between kernel mapping virtual address and kernel load addre=
ss */
>>   unsigned long va_kernel_pa_offset;
>>   EXPORT_SYMBOL(va_kernel_pa_offset);
>> +#endif
>>   unsigned long pfn_base;
>>   EXPORT_SYMBOL(pfn_base);
>>
>> @@ -410,7 +414,9 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>          load_sz =3D (uintptr_t)(&_end) - load_pa;
>>
>>          va_pa_offset =3D PAGE_OFFSET - load_pa;
>> +#ifdef CONFIG_64BIT
>>          va_kernel_pa_offset =3D kernel_virt_addr - load_pa;
>> +#endif
>>
>>          pfn_base =3D PFN_DOWN(load_pa);
>>
>> @@ -469,12 +475,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>                             pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>>          dtb_early_va =3D (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZ=
E - 1));
>>   #else /* CONFIG_BUILTIN_DTB */
>> +#ifdef CONFIG_64BIT
>>          /*
>>           * __va can't be used since it would return a linear mapping ad=
dress
>>           * whereas dtb_early_va will be used before setup_vm_final inst=
alls
>>           * the linear mapping.
>>           */
>>          dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>> +#else
>> +       dtb_early_va =3D __va(dtb_pa);
>> +#endif /* CONFIG_64BIT */
>>   #endif /* CONFIG_BUILTIN_DTB */
>>   #else
>>   #ifndef CONFIG_BUILTIN_DTB
>> @@ -486,7 +496,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>                             pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>>          dtb_early_va =3D (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PGDIR_S=
IZE - 1));
>>   #else /* CONFIG_BUILTIN_DTB */
>> +#ifdef CONFIG_64BIT
>>          dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>> +#else
>> +       dtb_early_va =3D __va(dtb_pa);
>> +#endif /* CONFIG_64BIT */
>>   #endif /* CONFIG_BUILTIN_DTB */
>>   #endif
>>          dtb_early_pa =3D dtb_pa;
>> @@ -571,12 +585,21 @@ static void __init setup_vm_final(void)
>>                  for (pa =3D start; pa < end; pa +=3D map_size) {
>>                          va =3D (uintptr_t)__va(pa);
>>                          create_pgd_mapping(swapper_pg_dir, va, pa,
>> -                                          map_size, PAGE_KERNEL);
>> +                                          map_size,
>> +#ifdef CONFIG_64BIT
>> +                                          PAGE_KERNEL
>> +#else
>> +                                          PAGE_KERNEL_EXEC
>> +#endif
>> +                                       );
>> +
>>                  }
>>          }
>>
>> +#ifdef CONFIG_64BIT
>>          /* Map the kernel */
>>          create_kernel_page_table(swapper_pg_dir, PMD_SIZE);
>> +#endif
>>
>>          /* Clear fixmap PTE and PMD mappings */
>>          clear_fixmap(FIX_PTE);
>> --
>> 2.20.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/66e9a8e0-5764-2eea-4070-bad3fb7ee48e%40ghiti.fr.
