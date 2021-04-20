Return-Path: <kasan-dev+bncBDFJHU6GRMBBBHVM7GBQMGQEFNKYZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 864D436513C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Apr 2021 06:18:39 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id s4-20020a2eb8c40000b02900bbf0cb2373sf6941256ljp.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 21:18:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618892319; cv=pass;
        d=google.com; s=arc-20160816;
        b=lnFnrhFbP9nUgOpG6+VE4IT+01Tp6jZeB+foBwSKNC93AZ78fcLG5gdQecgRT2fflY
         gHZI6K5wy78zkqDWk4dEOtSUzU6lPJ4cN4Gt2726mDJY6kZcHz2FRnEy/aM6UxCn1PPc
         bYEknfSnJzMHOzgcW58OX1SQBOge0nC8sc7ILerpkTGZsvjUijFNQCMLXwU6wEnAu/+C
         F5Cp+uOvl9NGTncopQTuqBbiDmlLjd1SsVQtxWPhSDiJYFxrR45g3Nc3OZmq/+nA5cJN
         KT8Oj412lwCHFS5tGOi7kEmup2ztmwbRuK/f5wlxRe3NBHrW0LucBrmNy+GRa2f7hi1r
         LvAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=rR8pgXi1XfsXDO1qBc/XUS5niCxeYfVVHtocjtvy9wU=;
        b=YZoszk5I9ECCb0YPnXC90CdELlUnoJqwcHRg7VT4pv8xazIUX/6R8o1bE/cwVCaiTC
         EbUAQiROcft6GG0Lu5e6xIU+AnxqIuHH7df+n5gEkjfSLFHWk5U9otLmMidjew1VKtSy
         +rRTDd0meyBuxMpqnt0Ar/rCJ7WyIP2dSFhWf5dLO+eZGdIHS+UikLgdzCpr1qD+VkAA
         Tgsy/DBWXbKgURgHQH269t+RRv+KmU2W/4tN3WuiXjImGDto8ssvgUKqPB1mjQ6e+Yb2
         9S/2L8dXRRC0hAwfDzzhkzQMtadutjoltuFzKbyVE0onlg+egsKfEpBPxlQ+iQ9cDgaj
         TXQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=zqRNucjD;
       spf=neutral (google.com: 2a00:1450:4864:20::429 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rR8pgXi1XfsXDO1qBc/XUS5niCxeYfVVHtocjtvy9wU=;
        b=msemJOx4iVqt+kuUGsEZW/I+ok62VfTsdYxjA30D1kC91eR/cNzdC3+UBBeq5/U4iy
         MpeZLPoWE/UOyaQKlKtyxzFFNCpskBe3zwIfJsHnthwFkoFpdjti0pDM+KGuylPPLJO8
         2OtPoR7IiEuGMz+757BDa63yXp6LeGvXH2hJ576ehjDXSMNLpvOz44u7uFJD6Q7WeHHl
         DwfTELmlMktD9xUcIrI/gyCWB2FWhvOpMnx/KaUsapCnLf88tNmFlia4/THKG1ymLKyL
         aB7awJch19suDiysh4OJGZ3miNEH90HJhBI4ayyuY32rbuw5Z95TnAN164trj3nwH2zg
         5lSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rR8pgXi1XfsXDO1qBc/XUS5niCxeYfVVHtocjtvy9wU=;
        b=p4J5C6jEkGYPY/gJhfqnZwpMPLmV/AiWUKcrv25G0qAYzLazaaLTrIDH6YRfhLoESK
         JpiAfq0EAfWRUPVayL34UcKXq3Af3AaKetYAs+lo7mxLsH+SLHlIz9cCVkt1suk02ufv
         ymmlz/tymPGVEseDjiGfocpO13oIE2l7ni4Nxzp5ioDnQfuL99Hwbglss2JQERRV4jW4
         iUlpD4GLkc+y/moKYNhHMdiAjCxE6MiPcZjrZN6NZeIw4LPMxXcwUtEC2Xa+JrbzFaxY
         24uNV8BwX8zQHsWbMCL12/mkJIqjbOG/J52G9Ap6cHOoUC5yV/e/8CAhg9fTdY5Sw19Z
         9lHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zPuAdWNdrKPFwnwflQd1/J2lnJm80ytzAxd8EoymBKvmVFI7v
	ulFWNdIlQG7pDoM8O2GL1jc=
X-Google-Smtp-Source: ABdhPJxzWyELIndrMkjrJuDAJiKZ6ft3W4YrnRd78q/st39+BrF8Q/YUgKpJxneJ5x6jU5tOB1onYw==
X-Received: by 2002:a05:6512:48b:: with SMTP id v11mr14016202lfq.48.1618892319118;
        Mon, 19 Apr 2021 21:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2129:: with SMTP id a41ls2585689ljq.5.gmail; Mon,
 19 Apr 2021 21:18:37 -0700 (PDT)
X-Received: by 2002:a2e:b6d4:: with SMTP id m20mr13541412ljo.448.1618892317839;
        Mon, 19 Apr 2021 21:18:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618892317; cv=none;
        d=google.com; s=arc-20160816;
        b=1FCuvltLdmbMFlwTs5F7ukw1dD5FmTq8e+PtHOZh5aFLvNKn+ctmvLWk+3kzjesFeC
         wnaVjFMstbwXUQ/YAt1BuodbziJNsYIw2GI4vPmEPqEcJGVSPk1jsbwjuqATG6pBvFe8
         5k9FMdeS2cblrziOVrPWeN1YlghgAHw6OHXFVEE2hCDZwc892VXCUDzMY/O0Zchgi/0z
         sLRJJkqoiOJ+21+9zycviuzbBSaQQYE26ENCCDVMuC+RZvpKGHVrrBNnAuEommThY3Tv
         C0Vd/ErXjuVNKiXktrL1K2W95IBgnSkyhtxygnKadCaH7mpuhlotGLVafsA43LAjMKDD
         OGHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SjWEZ1zxdmBRj9KcJNahO8i2TB9ZNFWY/gcI2Oi4MqQ=;
        b=JNiGvHtuNyODN5TTTnMId27yq/K5G6R5zVDJIjRuuOSH32p3GiCGSKIP78qqvh/g77
         Uf+FOqIZMzmiF/XdRTrT01KMPt+FDU4KIpN1dA3CwXyvNxBlxbSopkmE3jJyuGqgCZd2
         m6uBQiJRsHfJMAMvHqgi/8bGLt/tqWJ+xdABiWpN1ylNI7NE9uGXAxKouwc0q/oHfhy1
         rvaNUzoSw4NIOdP0l/L8mRGQcndn7fYulPIsjrNisiIRzsakDzMcLPa/d5FNHACCc5RP
         F37thgHICAa2xETWskCkq6i1y+bWM7IPKO7O/WXP1GCJLG3YJ/Rms3Fl0hn6bkd1mS3a
         n3qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=zqRNucjD;
       spf=neutral (google.com: 2a00:1450:4864:20::429 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id u2si904643lfo.2.2021.04.19.21.18.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 21:18:37 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::429 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id c15so27163637wro.13
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 21:18:37 -0700 (PDT)
X-Received: by 2002:adf:ce12:: with SMTP id p18mr18078880wrn.144.1618892317302;
 Mon, 19 Apr 2021 21:18:37 -0700 (PDT)
MIME-Version: 1.0
References: <20210417172159.32085-1-alex@ghiti.fr>
In-Reply-To: <20210417172159.32085-1-alex@ghiti.fr>
From: Anup Patel <anup@brainfault.org>
Date: Tue, 20 Apr 2021 09:48:26 +0530
Message-ID: <CAAhSdy23jRTp3VoBpnH8B79eSSmuw8qMEYrXyh-02ccWT3O5QQ@mail.gmail.com>
Subject: Re: [PATCH] riscv: Fix 32b kernel caused by 64b kernel mapping moving
 outside linear mapping
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-doc@vger.kernel.org, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=zqRNucjD;       spf=neutral (google.com: 2a00:1450:4864:20::429 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sat, Apr 17, 2021 at 10:52 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>
> Fix multiple leftovers when moving the kernel mapping outside the linear
> mapping for 64b kernel that left the 32b kernel unusable.
>
> Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear mapping")
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>

Quite a few #ifdef but I don't see any better way at the moment. Maybe we can
clean this later. Otherwise looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/include/asm/page.h    |  9 +++++++++
>  arch/riscv/include/asm/pgtable.h | 16 ++++++++++++----
>  arch/riscv/mm/init.c             | 25 ++++++++++++++++++++++++-
>  3 files changed, 45 insertions(+), 5 deletions(-)
>
> diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
> index 22cfb2be60dc..f64b61296c0c 100644
> --- a/arch/riscv/include/asm/page.h
> +++ b/arch/riscv/include/asm/page.h
> @@ -90,15 +90,20 @@ typedef struct page *pgtable_t;
>
>  #ifdef CONFIG_MMU
>  extern unsigned long va_pa_offset;
> +#ifdef CONFIG_64BIT
>  extern unsigned long va_kernel_pa_offset;
> +#endif
>  extern unsigned long pfn_base;
>  #define ARCH_PFN_OFFSET                (pfn_base)
>  #else
>  #define va_pa_offset           0
> +#ifdef CONFIG_64BIT
>  #define va_kernel_pa_offset    0
> +#endif
>  #define ARCH_PFN_OFFSET                (PAGE_OFFSET >> PAGE_SHIFT)
>  #endif /* CONFIG_MMU */
>
> +#ifdef CONFIG_64BIT
>  extern unsigned long kernel_virt_addr;
>
>  #define linear_mapping_pa_to_va(x)     ((void *)((unsigned long)(x) + va_pa_offset))
> @@ -112,6 +117,10 @@ extern unsigned long kernel_virt_addr;
>         (_x < kernel_virt_addr) ?                                               \
>                 linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(_x);      \
>         })
> +#else
> +#define __pa_to_va_nodebug(x)  ((void *)((unsigned long) (x) + va_pa_offset))
> +#define __va_to_pa_nodebug(x)  ((unsigned long)(x) - va_pa_offset)
> +#endif
>
>  #ifdef CONFIG_DEBUG_VIRTUAL
>  extern phys_addr_t __virt_to_phys(unsigned long x);
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 80e63a93e903..5afda75cc2c3 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -16,19 +16,27 @@
>  #else
>
>  #define ADDRESS_SPACE_END      (UL(-1))
> -/*
> - * Leave 2GB for kernel and BPF at the end of the address space
> - */
> +
> +#ifdef CONFIG_64BIT
> +/* Leave 2GB for kernel and BPF at the end of the address space */
>  #define KERNEL_LINK_ADDR       (ADDRESS_SPACE_END - SZ_2G + 1)
> +#else
> +#define KERNEL_LINK_ADDR       PAGE_OFFSET
> +#endif
>
>  #define VMALLOC_SIZE     (KERN_VIRT_SIZE >> 1)
>  #define VMALLOC_END      (PAGE_OFFSET - 1)
>  #define VMALLOC_START    (PAGE_OFFSET - VMALLOC_SIZE)
>
> -/* KASLR should leave at least 128MB for BPF after the kernel */
>  #define BPF_JIT_REGION_SIZE    (SZ_128M)
> +#ifdef CONFIG_64BIT
> +/* KASLR should leave at least 128MB for BPF after the kernel */
>  #define BPF_JIT_REGION_START   PFN_ALIGN((unsigned long)&_end)
>  #define BPF_JIT_REGION_END     (BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
> +#else
> +#define BPF_JIT_REGION_START   (PAGE_OFFSET - BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_END     (VMALLOC_END)
> +#endif
>
>  /* Modules always live before the kernel */
>  #ifdef CONFIG_64BIT
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 093f3a96ecfc..dc9b988e0778 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -91,8 +91,10 @@ static void print_vm_layout(void)
>                   (unsigned long)VMALLOC_END);
>         print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
>                   (unsigned long)high_memory);
> +#ifdef CONFIG_64BIT
>         print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
>                   (unsigned long)ADDRESS_SPACE_END);
> +#endif
>  }
>  #else
>  static void print_vm_layout(void) { }
> @@ -165,9 +167,11 @@ static struct pt_alloc_ops pt_ops;
>  /* Offset between linear mapping virtual address and kernel load address */
>  unsigned long va_pa_offset;
>  EXPORT_SYMBOL(va_pa_offset);
> +#ifdef CONFIG_64BIT
>  /* Offset between kernel mapping virtual address and kernel load address */
>  unsigned long va_kernel_pa_offset;
>  EXPORT_SYMBOL(va_kernel_pa_offset);
> +#endif
>  unsigned long pfn_base;
>  EXPORT_SYMBOL(pfn_base);
>
> @@ -410,7 +414,9 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>         load_sz = (uintptr_t)(&_end) - load_pa;
>
>         va_pa_offset = PAGE_OFFSET - load_pa;
> +#ifdef CONFIG_64BIT
>         va_kernel_pa_offset = kernel_virt_addr - load_pa;
> +#endif
>
>         pfn_base = PFN_DOWN(load_pa);
>
> @@ -469,12 +475,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>                            pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>         dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZE - 1));
>  #else /* CONFIG_BUILTIN_DTB */
> +#ifdef CONFIG_64BIT
>         /*
>          * __va can't be used since it would return a linear mapping address
>          * whereas dtb_early_va will be used before setup_vm_final installs
>          * the linear mapping.
>          */
>         dtb_early_va = kernel_mapping_pa_to_va(dtb_pa);
> +#else
> +       dtb_early_va = __va(dtb_pa);
> +#endif /* CONFIG_64BIT */
>  #endif /* CONFIG_BUILTIN_DTB */
>  #else
>  #ifndef CONFIG_BUILTIN_DTB
> @@ -486,7 +496,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>                            pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>         dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PGDIR_SIZE - 1));
>  #else /* CONFIG_BUILTIN_DTB */
> +#ifdef CONFIG_64BIT
>         dtb_early_va = kernel_mapping_pa_to_va(dtb_pa);
> +#else
> +       dtb_early_va = __va(dtb_pa);
> +#endif /* CONFIG_64BIT */
>  #endif /* CONFIG_BUILTIN_DTB */
>  #endif
>         dtb_early_pa = dtb_pa;
> @@ -571,12 +585,21 @@ static void __init setup_vm_final(void)
>                 for (pa = start; pa < end; pa += map_size) {
>                         va = (uintptr_t)__va(pa);
>                         create_pgd_mapping(swapper_pg_dir, va, pa,
> -                                          map_size, PAGE_KERNEL);
> +                                          map_size,
> +#ifdef CONFIG_64BIT
> +                                          PAGE_KERNEL
> +#else
> +                                          PAGE_KERNEL_EXEC
> +#endif
> +                                       );
> +
>                 }
>         }
>
> +#ifdef CONFIG_64BIT
>         /* Map the kernel */
>         create_kernel_page_table(swapper_pg_dir, PMD_SIZE);
> +#endif
>
>         /* Clear fixmap PTE and PMD mappings */
>         clear_fixmap(FIX_PTE);
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy23jRTp3VoBpnH8B79eSSmuw8qMEYrXyh-02ccWT3O5QQ%40mail.gmail.com.
