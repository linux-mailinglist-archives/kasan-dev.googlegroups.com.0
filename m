Return-Path: <kasan-dev+bncBCRKNY4WZECBBYPYROCAMGQEH3CLJOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 135A636977B
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 18:57:07 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id e4-20020a37b5040000b02902df9a0070efsf15033300qkf.18
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 09:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619197026; cv=pass;
        d=google.com; s=arc-20160816;
        b=MK6VM1KG4WOr3dn9l6R6lj6vCDQIPhvitl8YWviTbtcjY9Xp0UmYm0andV9nVJ5nfw
         Q+Brbw+ylGNQyqz9RzXWcLvqvmiFYjebW37z55ifLx/Y1ZZTu4qgSUF6RPyYvWaguSHh
         cfC5fZVMJvtcZ1Ei+3OZ+GfT44Dq9xFMiL+dpJgqj8Jvnfx6IhswHRU8dvr2mdoK8+11
         Rx1Q0FExDbttrmdK2jrkWDbhq2EgsiOB1DxAigqvHdBk8fwoTz8rVmna4/AAbHndh8fe
         Il6w5BLlJqmrCu4k1+ea8GeHUEbvSgm1RN+VpkOqztEviakSKWPRaBrIWvAbPTBZ7bUM
         LDAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=Tq+QxE5x6dAs+j4kb9ZwbAOOLuOb1DxR+yuDozktaP0=;
        b=PcaoiwIj1mEUyype+flR4e0zZvMU5stYpDjB8iCuN0vKREt1kfpWu54MWhpukwvy8S
         swH89G8Y/KrabO+V2i/W9oRc5CmOUVdcxI0dUrXZxMdMuTBwB+HpUt92a8tVNbvi+1+R
         4MSpQq3vGzGTCl4thO6vugMDDmIdN3eFfYa8Tr+P+cAiZWCBzJPwTQ2EmrsniDDOs+Cg
         RXidHDukXNvlVZO2f2qKw1e2qJ0HZ3lUNsxOXKStzSU8b43AQgu/Qtjcp1TNjYyZclWr
         80J/FlVou5bvgUF4c/V0s5Y4Gib65NaN1XVB/MJaG2QCCaOhakCLB1AxRi1JPE116N2y
         8Rdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=NATfmSnL;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tq+QxE5x6dAs+j4kb9ZwbAOOLuOb1DxR+yuDozktaP0=;
        b=tCuQiA8FqwOD1Q4ByASlFnDTi/3MbRm9Mi5plAwvpeOOObkxkdTsH77rhFuTgBl2Ee
         NDhogF6aZW+up/pzu3PUAbtjaQYH9vpV7SYEmS+5USkIWaeVn4clUfK2JCOXJfgmYPH/
         /SmJxjkA6Tv7VBnB5K/lyXWNKmTHyiD6cT7yKXSXhcwb/VONQFSJ8q5nDY1fhPW5U2+x
         dfJg3646IbuRtUlRyLZTezQ/ohnmOPlCAKGMX5UKgByhbGINKT5u3C1wkz0t2MqEulKA
         YFnxe077Baz3b/UQI8/NBK/15rk6CuxfsOUMbjbktu2495stP4sXNf47fLl+DM1tl9fX
         /x4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tq+QxE5x6dAs+j4kb9ZwbAOOLuOb1DxR+yuDozktaP0=;
        b=PZklfE6B5i6h+nucqq9p5Zh4QCrUMFGqpQU13ZL+E01S0Z69PBfYEW3TprE2MKTHIo
         3xM72RAHYFduX7K6v4w8DZCuU5JPAgaMQlWTFySmWd8JCBN/1sulqKRXEZbM5vk/Hy2F
         1MfO7cW2hf83Pboc9EW9MeQQEZDYafYBABN8AZQ4t3eeWxOPAfAuTuIOZpwF7K6z+OlB
         ykFHyuN4y5eX2s+YOsqseGFFdgWoatC4vfVUDIcIahKPc8uMo3nGFvB+J5Qsn3HGpifl
         7pLURQKmP+Taq4sC6PFkFP1ThMAtHjvMSeNvVzRyoUfUO+Vfvz+dvVF/qiAi0dsTiqi3
         3pEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533v+VEwlYjgrX+KJ6xwVYd1LS1Uqpn1I0HWXVbdOQ4cIjg/ercL
	mC3ycP8NcX70ttxiH4kBoZU=
X-Google-Smtp-Source: ABdhPJyZEp27OsulHQ6YW90OK3k1OytCjOy3IL6T0pxLyV/DaB54h3KjbezUOMriD+MubHyThOUfvw==
X-Received: by 2002:a0c:eacb:: with SMTP id y11mr5174932qvp.57.1619197025968;
        Fri, 23 Apr 2021 09:57:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2209:: with SMTP id m9ls5340859qkh.5.gmail; Fri, 23
 Apr 2021 09:57:05 -0700 (PDT)
X-Received: by 2002:a37:649:: with SMTP id 70mr5120270qkg.318.1619197025536;
        Fri, 23 Apr 2021 09:57:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619197025; cv=none;
        d=google.com; s=arc-20160816;
        b=VlTX/q4av6wp9xZQjLRu1QnBfFguYe9qfeOy4Yw/Pnctkv/cVOK1OtKE6yC1bfrotz
         iqZYCr8QUQwJcmhy+G7wAHTNv1yyLD0fgua7SYkecoF/bnBM1AaaAlFbpmcH4Skj0Wus
         t7xAyWlK7raxwD2LvoE8YFHZJxkGEsEKxruGuXG6OqCiKHv+L/Ntp17qmL6WkwNItRe2
         UvrOBJCHCuzWEdkZ/wRSob6dNC5J2fwOgP5fJLfD0F0doxn4/24dAQ76QY2GrGSoUVQ4
         rc9lYvupcMYxU/uu2lgZsDNrHpmoYe6oJF4dPRf6zaMUOXEENDqYvCqB4ony83/hU+Y6
         vOUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=s4J0wdi9ub8j1oFLJOVRAwtlpmptPrFHS6TmHCwX3xA=;
        b=tP0tQXTQrNXro5FqYauMWlFB3AwO7n+GO26rlo7uQgUa5y15VpSSZDpCtfQFpnzruv
         wNivbERfDsLy258cyCDx5YrvKAZYdl9PmM0616KGW3s9864yMotVm3mhYEYz2Wb1ACOL
         6T47I0fG3RV+7EIj+UVSMb3TRP2HUJNqA0wiRTjwZVkuvoPmY2nh0bKNkeNUY54TjFJG
         safsJ6evvNEtpv/WG9kPY1B2cq+y5QEfRsx1pb6/Mi54yepCDFKg7XuBkrZPl4q9cRxm
         NSp38fyk63vAclxBBIGZahrpa8Sz6s12TsHAorEIqT6bWoUNAOBzAEXpbTsNqJIjiuOE
         fjsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=NATfmSnL;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id r26si831268qtf.3.2021.04.23.09.57.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Apr 2021 09:57:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id f2-20020a17090a4a82b02900c67bf8dc69so1527475pjh.1
        for <kasan-dev@googlegroups.com>; Fri, 23 Apr 2021 09:57:05 -0700 (PDT)
X-Received: by 2002:a17:902:e8d1:b029:ec:824a:404e with SMTP id v17-20020a170902e8d1b02900ec824a404emr5085166plg.61.1619197024421;
        Fri, 23 Apr 2021 09:57:04 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id a20sm5299988pfk.46.2021.04.23.09.57.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Apr 2021 09:57:03 -0700 (PDT)
Date: Fri, 23 Apr 2021 09:57:03 -0700 (PDT)
Subject: Re: [PATCH] riscv: Fix 32b kernel caused by 64b kernel mapping moving outside linear mapping
In-Reply-To: <66e9a8e0-5764-2eea-4070-bad3fb7ee48e@ghiti.fr>
CC: anup@brainfault.org, corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-5579c61f-d95b-4f9b-9f12-4df6bb24df0c@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=NATfmSnL;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 23 Apr 2021 01:34:02 PDT (-0700), alex@ghiti.fr wrote:
> Le 4/20/21 =C3=A0 12:18 AM, Anup Patel a =C3=A9crit=C2=A0:
>> On Sat, Apr 17, 2021 at 10:52 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>
>>> Fix multiple leftovers when moving the kernel mapping outside the linea=
r
>>> mapping for 64b kernel that left the 32b kernel unusable.
>>>
>>> Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear mapp=
ing")
>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>
>> Quite a few #ifdef but I don't see any better way at the moment. Maybe w=
e can
>> clean this later. Otherwise looks good to me.

Agreed.  I'd recently sent out a patch set that got NACK'd because we're=20
supposed to be relying on the compiler to optimize away references that=20
can be staticly determined to not be exercised, which is probably the=20
way forward to getting rid of a lot of of preprocessor stuff.  That all=20
seems very fragile and is a bigger problem than this, though, so it's=20
probably best to do it as its own thing.

>> Reviewed-by: Anup Patel <anup@brainfault.org>
>
> Thanks Anup!
>
> @Palmer: This is not on for-next yet and then rv32 is broken. This does
> not apply immediately on top of for-next though, so if you need a new
> version, I can do that. But this squashes nicely with the patch it fixes
> if you prefer.

Thanks.  I just hadn't gotten to this one yet, but as you pointed out=20
it's probably best to just squash it.  It's in the version on for-next=20
now, it caused few conflicts but I think I got everything sorted out.

Now that everything is in I'm going to stop rewriting this stuff, as it=20
touches pretty much the whole tree.  I don't have much of a patch back=20
log as of right now, and as the new stuff will be on top of it that=20
will make everyone's lives easier.

>
> Let me know, I can do that very quickly.
>
> Alex
>
>>
>> Regards,
>> Anup
>>
>>> ---
>>>   arch/riscv/include/asm/page.h    |  9 +++++++++
>>>   arch/riscv/include/asm/pgtable.h | 16 ++++++++++++----
>>>   arch/riscv/mm/init.c             | 25 ++++++++++++++++++++++++-
>>>   3 files changed, 45 insertions(+), 5 deletions(-)
>>>
>>> diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/pag=
e.h
>>> index 22cfb2be60dc..f64b61296c0c 100644
>>> --- a/arch/riscv/include/asm/page.h
>>> +++ b/arch/riscv/include/asm/page.h
>>> @@ -90,15 +90,20 @@ typedef struct page *pgtable_t;
>>>
>>>   #ifdef CONFIG_MMU
>>>   extern unsigned long va_pa_offset;
>>> +#ifdef CONFIG_64BIT
>>>   extern unsigned long va_kernel_pa_offset;
>>> +#endif
>>>   extern unsigned long pfn_base;
>>>   #define ARCH_PFN_OFFSET                (pfn_base)
>>>   #else
>>>   #define va_pa_offset           0
>>> +#ifdef CONFIG_64BIT
>>>   #define va_kernel_pa_offset    0
>>> +#endif
>>>   #define ARCH_PFN_OFFSET                (PAGE_OFFSET >> PAGE_SHIFT)
>>>   #endif /* CONFIG_MMU */
>>>
>>> +#ifdef CONFIG_64BIT
>>>   extern unsigned long kernel_virt_addr;
>>>
>>>   #define linear_mapping_pa_to_va(x)     ((void *)((unsigned long)(x) +=
 va_pa_offset))
>>> @@ -112,6 +117,10 @@ extern unsigned long kernel_virt_addr;
>>>          (_x < kernel_virt_addr) ?                                     =
          \
>>>                  linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(=
_x);      \
>>>          })
>>> +#else
>>> +#define __pa_to_va_nodebug(x)  ((void *)((unsigned long) (x) + va_pa_o=
ffset))
>>> +#define __va_to_pa_nodebug(x)  ((unsigned long)(x) - va_pa_offset)
>>> +#endif
>>>
>>>   #ifdef CONFIG_DEBUG_VIRTUAL
>>>   extern phys_addr_t __virt_to_phys(unsigned long x);
>>> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/=
pgtable.h
>>> index 80e63a93e903..5afda75cc2c3 100644
>>> --- a/arch/riscv/include/asm/pgtable.h
>>> +++ b/arch/riscv/include/asm/pgtable.h
>>> @@ -16,19 +16,27 @@
>>>   #else
>>>
>>>   #define ADDRESS_SPACE_END      (UL(-1))
>>> -/*
>>> - * Leave 2GB for kernel and BPF at the end of the address space
>>> - */
>>> +
>>> +#ifdef CONFIG_64BIT
>>> +/* Leave 2GB for kernel and BPF at the end of the address space */
>>>   #define KERNEL_LINK_ADDR       (ADDRESS_SPACE_END - SZ_2G + 1)
>>> +#else
>>> +#define KERNEL_LINK_ADDR       PAGE_OFFSET
>>> +#endif
>>>
>>>   #define VMALLOC_SIZE     (KERN_VIRT_SIZE >> 1)
>>>   #define VMALLOC_END      (PAGE_OFFSET - 1)
>>>   #define VMALLOC_START    (PAGE_OFFSET - VMALLOC_SIZE)
>>>
>>> -/* KASLR should leave at least 128MB for BPF after the kernel */
>>>   #define BPF_JIT_REGION_SIZE    (SZ_128M)
>>> +#ifdef CONFIG_64BIT
>>> +/* KASLR should leave at least 128MB for BPF after the kernel */
>>>   #define BPF_JIT_REGION_START   PFN_ALIGN((unsigned long)&_end)
>>>   #define BPF_JIT_REGION_END     (BPF_JIT_REGION_START + BPF_JIT_REGION=
_SIZE)
>>> +#else
>>> +#define BPF_JIT_REGION_START   (PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>>> +#define BPF_JIT_REGION_END     (VMALLOC_END)
>>> +#endif
>>>
>>>   /* Modules always live before the kernel */
>>>   #ifdef CONFIG_64BIT
>>> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
>>> index 093f3a96ecfc..dc9b988e0778 100644
>>> --- a/arch/riscv/mm/init.c
>>> +++ b/arch/riscv/mm/init.c
>>> @@ -91,8 +91,10 @@ static void print_vm_layout(void)
>>>                    (unsigned long)VMALLOC_END);
>>>          print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
>>>                    (unsigned long)high_memory);
>>> +#ifdef CONFIG_64BIT
>>>          print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
>>>                    (unsigned long)ADDRESS_SPACE_END);
>>> +#endif
>>>   }
>>>   #else
>>>   static void print_vm_layout(void) { }
>>> @@ -165,9 +167,11 @@ static struct pt_alloc_ops pt_ops;
>>>   /* Offset between linear mapping virtual address and kernel load addr=
ess */
>>>   unsigned long va_pa_offset;
>>>   EXPORT_SYMBOL(va_pa_offset);
>>> +#ifdef CONFIG_64BIT
>>>   /* Offset between kernel mapping virtual address and kernel load addr=
ess */
>>>   unsigned long va_kernel_pa_offset;
>>>   EXPORT_SYMBOL(va_kernel_pa_offset);
>>> +#endif
>>>   unsigned long pfn_base;
>>>   EXPORT_SYMBOL(pfn_base);
>>>
>>> @@ -410,7 +414,9 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>          load_sz =3D (uintptr_t)(&_end) - load_pa;
>>>
>>>          va_pa_offset =3D PAGE_OFFSET - load_pa;
>>> +#ifdef CONFIG_64BIT
>>>          va_kernel_pa_offset =3D kernel_virt_addr - load_pa;
>>> +#endif
>>>
>>>          pfn_base =3D PFN_DOWN(load_pa);
>>>
>>> @@ -469,12 +475,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>                             pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>>>          dtb_early_va =3D (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SI=
ZE - 1));
>>>   #else /* CONFIG_BUILTIN_DTB */
>>> +#ifdef CONFIG_64BIT
>>>          /*
>>>           * __va can't be used since it would return a linear mapping a=
ddress
>>>           * whereas dtb_early_va will be used before setup_vm_final ins=
talls
>>>           * the linear mapping.
>>>           */
>>>          dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>>> +#else
>>> +       dtb_early_va =3D __va(dtb_pa);
>>> +#endif /* CONFIG_64BIT */
>>>   #endif /* CONFIG_BUILTIN_DTB */
>>>   #else
>>>   #ifndef CONFIG_BUILTIN_DTB
>>> @@ -486,7 +496,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>                             pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>>>          dtb_early_va =3D (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PGDIR_=
SIZE - 1));
>>>   #else /* CONFIG_BUILTIN_DTB */
>>> +#ifdef CONFIG_64BIT
>>>          dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>>> +#else
>>> +       dtb_early_va =3D __va(dtb_pa);
>>> +#endif /* CONFIG_64BIT */
>>>   #endif /* CONFIG_BUILTIN_DTB */
>>>   #endif
>>>          dtb_early_pa =3D dtb_pa;
>>> @@ -571,12 +585,21 @@ static void __init setup_vm_final(void)
>>>                  for (pa =3D start; pa < end; pa +=3D map_size) {
>>>                          va =3D (uintptr_t)__va(pa);
>>>                          create_pgd_mapping(swapper_pg_dir, va, pa,
>>> -                                          map_size, PAGE_KERNEL);
>>> +                                          map_size,
>>> +#ifdef CONFIG_64BIT
>>> +                                          PAGE_KERNEL
>>> +#else
>>> +                                          PAGE_KERNEL_EXEC
>>> +#endif
>>> +                                       );
>>> +
>>>                  }
>>>          }
>>>
>>> +#ifdef CONFIG_64BIT
>>>          /* Map the kernel */
>>>          create_kernel_page_table(swapper_pg_dir, PMD_SIZE);
>>> +#endif
>>>
>>>          /* Clear fixmap PTE and PMD mappings */
>>>          clear_fixmap(FIX_PTE);
>>> --
>>> 2.20.1
>>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-5579c61f-d95b-4f9b-9f12-4df6bb24df0c%40palmerdabbelt-glaptop=
.
