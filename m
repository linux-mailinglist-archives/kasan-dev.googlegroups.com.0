Return-Path: <kasan-dev+bncBDW2JDUY5AORBKVEROJQMGQEQSBDH5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E185450BC8D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 18:04:59 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id x63-20020a4a4142000000b003369bebf175sf4162709ooa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 09:04:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650643498; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJPjqe+GZop2jwMX2f5oVj6CH1mhY3x+5UZxWjVO6RO27Q/W0y9YFB1tAYV62wNhX7
         KngfMFa3vvaRoyfozHQjhB/RBMV66fWPwg58lw5w73xGSbYmHKHv9C1RW9aoRU9Pa6ZV
         /fJdz4+h2JHFns/POuTb04zxHfwwBRUe0zHj4+vJdKU4kwwyCMwr68X4JN3oIKt4YDgz
         dSAkR5cXqFmGlO1ahGWp5YAnwzVi+LBj0sdtGga0lZlT1Jj3Ly6MBZJeGy7Mx3KUridg
         DDrjEwkrQt3djQv0SPlsyRZc+tgNmsKNBPHwg+iKNYghVabhCTYdoadQ25wAH7x6tdkv
         2+Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=KGCC7tyfZUTzDdsbfCIsHdZNIk7TBydPDXrnd7+Py3M=;
        b=hVyUFtAObnbhn9PpGJ4yxR+/m3xJSx1+w7mvtSNzpzRIrnEmSYEVaNGMLuSiAEy1Tg
         2dQpX4eejCoV9prsylMdodr0IT2aMPfvcGsLDhkwXNAsusP65wyXe2OCnjwvK7Yv/Mmi
         gHLEftTifXTqmEPKNnMUmrdDrJ8GS7+lu+EFA5VhrLo5BdfD1AamdnQjTz5/I2i1sAMz
         hDaXOtWoECbyOkFZXhNpNJzsRixmRzZ6shaXtDJ/oDs8TpBH06JCkovzfp0ZnwTOL8Cq
         bV8nFnwlCdfIC/HH/TRb5utgTxK44SNHa8qYVbiOs/JjtQu5oodfepcN4VV9v1eByOyZ
         XKsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GYlVR9EM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KGCC7tyfZUTzDdsbfCIsHdZNIk7TBydPDXrnd7+Py3M=;
        b=XQMS+StIFa6yMoaDn5BHCqDXBwY9IzCKDAS+AF4UyPngWXIfnfAMxljwak7Ncr3iXD
         wegGp83jIjsAQ/0jUokUMCm9+RPLXhVlDW0MFJ3T1LdF4GJAIzgL3wNv09wpm798FbVL
         ZF8pUPnFAXSUB7m3obPnV6U+0JjNvkGXHNYkYofX1oqGGnTKIfE7afk+tTA8UzvKH1kO
         74imhnPzErK9mayrnF/xVBAxU6CfmZcmfbpBe3hK7XyAUga9NxIZwuf2WjwQJNMmfkCv
         vEM9LUf4yFTW0ayt/XX6UDXwiipVaIUM8Z5yRvgQSXJVbJUoM0A4Vgz9FhiLWYrhcOIk
         NT7A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KGCC7tyfZUTzDdsbfCIsHdZNIk7TBydPDXrnd7+Py3M=;
        b=LlJmOYJDJKX4tzlnwleHxWul1PlPEzQ4s3ZXbbwMAI+hCMJ1112lRgs1/UF/w4igeH
         rTEmMQujKFP+xudbzQzyxdP8b0nwOA9eOuL9gXGa2p91XDYLJDwwvmuToygau0J24Oug
         qbbl+CK6vAYNsNHMqdrBCTJXKsBLWngpsFNNyigCVMHNpT0Qw9K+cDRcUNFrj/dqHaiR
         +cEWq9SxFzuxAvOpgv90z9BkD3j6gfLipWDP5+n95H4kRnT4/VHG2mszs1lVMfEzYC6F
         2MkTnU0Y0Ap2sJvlNPZ1VTr2DzW9xyjxQeV4IXVz/7jrgWlO/vNFwVPE4bMt3kTYYHPD
         ZM3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KGCC7tyfZUTzDdsbfCIsHdZNIk7TBydPDXrnd7+Py3M=;
        b=l41Nw85aIAOmndwdNzYOdzXOGcjnJkaXay/5XJslzdLBk7DAJTRGTpjTnAVVcfkyrV
         QUIlkRUAAa4Nn3+4D/4lw6t1lE5nFYu5HswiaImZopt5R81NehJCmwPzjOZnvDoaKH4m
         pAusOZbmScO/XLK25gIIXiBmSNefKlqFKksP0gbNb8bZEfX48b14rcKMhyXFWMD1eEKw
         htO1Mk9Pr5aXbj4Aod2WKk/3Kkb435mYRHG/7PWC/7sk72ZUS3ql8V75R2HdVuxm62zo
         UaYnsZkOBoOy77WAoHHbXm+6MNItSAsZE85zVRmlInayA1Bt5fvxA8dkwiM8RI7AKdz6
         XWkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nlIb90LzaPi92FjoRjBW2/Mgp2BBBkH2N7bu5uZVEXrtGgW2S
	DG8cK6w1vvL0KIyG0KAVwc4=
X-Google-Smtp-Source: ABdhPJxXbcb+cqY6q0EUMX6ZDZtbONDKrR+ZNGPusgPVtmSQIl6ZX03yyy9vfAfm20gC2GZYm9vvTA==
X-Received: by 2002:a05:6808:ec8:b0:2f9:6119:d6ed with SMTP id q8-20020a0568080ec800b002f96119d6edmr6926844oiv.215.1650643498628;
        Fri, 22 Apr 2022 09:04:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f693:b0:e2:1a68:2965 with SMTP id
 el19-20020a056870f69300b000e21a682965ls215122oab.2.gmail; Fri, 22 Apr 2022
 09:04:58 -0700 (PDT)
X-Received: by 2002:a05:6870:b616:b0:e2:f8bb:5eb with SMTP id cm22-20020a056870b61600b000e2f8bb05ebmr6346254oab.218.1650643498198;
        Fri, 22 Apr 2022 09:04:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650643498; cv=none;
        d=google.com; s=arc-20160816;
        b=QK8FgUzX+/evNlV2GJ4GDkLZ+NUxtStU/84we3FX3pG7BUW0U2y3nQL4/bIFePvfaM
         csHzKo3c+VgZSFvf/V6SVUUTXy8++YfPduBJjmBoi6h9bKE4yW9BYCv6FFWVMICQk0YN
         zFOygiwVDYmh8ZZE5msDJg4AeURxjntKQf+9tsAXDdKFSxWN7PuLqO5xo+6Q0n5yOJ6D
         K8cTS57nXFR95Kqhb0w44GgxY4thKbyqcWsL1nt+3Vv4BRr/tzLm+vnOQWUDxQLt/7zG
         FZ9rdSFxx+EoBnpzaoXdlVOZumdvFJvj+PmpYmNiVBzAfBHrz5irJ5AaxdR1fMyk9f4C
         dm1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KfvcnPXDciGbM0GgFvcrkL5rJogs+wxiu9DmRRZRSNc=;
        b=dLUydAtIrpVqKHsQo4v0FAUiPfUKIswU7aaJxUnfvKmBpSdCaXy8uuUhBRCJi+lNln
         aLa5Ly/tJtqyQo1tRrC8nkKbFu8V9cGyGB5owvUa6+06VOkkW5MpilBWXLDLMbdre+Cl
         PU37jHwh53D7uhzq2zc4q61O7xogDs8gVGZJSsV99xZDhRbVpgKQR2A3WnvMmAHYxuIu
         y3pVxJzADftOckCueFvzFuOD67LI5EPFmxCbBERIEWFtFpT7srkg/0+BzQQtMzJQcDBf
         IOoU5WrqZdfnX5+mQPnqrrNQ4/c9fR7Q7K8nDq2zHrRFVJkvFHA6qKWvhCNRnlFXs61t
         m2ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GYlVR9EM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id i26-20020a4a6f5a000000b0033a52ed3b6asi849263oof.0.2022.04.22.09.04.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 09:04:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id r17so5320468iln.9
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 09:04:58 -0700 (PDT)
X-Received: by 2002:a92:c561:0:b0:2cb:d912:bc83 with SMTP id
 b1-20020a92c561000000b002cbd912bc83mr2215506ilj.81.1650643497795; Fri, 22 Apr
 2022 09:04:57 -0700 (PDT)
MIME-Version: 1.0
References: <20220421211549.3884453-1-pcc@google.com>
In-Reply-To: <20220421211549.3884453-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 22 Apr 2022 18:04:47 +0200
Message-ID: <CA+fCnZdouu-v1MKndMbeOw96pknGN=77=8B=_K4kedRROrL9pw@mail.gmail.com>
Subject: Re: [PATCH v2] mm: make minimum slab alignment a runtime property
To: Peter Collingbourne <pcc@google.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Pekka Enberg <penberg@kernel.org>, roman.gushchin@linux.dev, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GYlVR9EM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Apr 21, 2022 at 11:16 PM Peter Collingbourne <pcc@google.com> wrote:
>
> When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> slab alignment to 16. This happens even if MTE is not supported in
> hardware or disabled via kasan=off, which creates an unnecessary
> memory overhead in those cases. Eliminate this overhead by making
> the minimum slab alignment a runtime property and only aligning to
> 16 if KASAN is enabled at runtime.
>
> On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> boot I see the following Slab measurements in /proc/meminfo (median
> of 3 reboots):
>
> Before: 169020 kB
> After:  167304 kB

Thanks for the improvement, Peter!

Overall, the patch looks good to me:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

While looking at the code, I noticed a couple of issues in the already
existing comments. Not sure if they are worth fixing, but I'll point
them out just in case.

> Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> ---
> v2:
> - use max instead of max_t in flat_stack_align()
>
>  arch/arc/include/asm/cache.h        |  4 ++--
>  arch/arm/include/asm/cache.h        |  2 +-
>  arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
>  arch/microblaze/include/asm/page.h  |  2 +-
>  arch/riscv/include/asm/cache.h      |  2 +-
>  arch/sparc/include/asm/cache.h      |  2 +-
>  arch/xtensa/include/asm/processor.h |  2 +-
>  fs/binfmt_flat.c                    |  9 ++++++---
>  include/crypto/hash.h               |  2 +-
>  include/linux/slab.h                | 22 +++++++++++++++++-----
>  mm/slab.c                           |  7 +++----
>  mm/slab_common.c                    |  3 +--
>  mm/slob.c                           |  6 +++---
>  13 files changed, 51 insertions(+), 31 deletions(-)
>
> diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
> index f0f1fc5d62b6..b6a7763fd5d6 100644
> --- a/arch/arc/include/asm/cache.h
> +++ b/arch/arc/include/asm/cache.h
> @@ -55,11 +55,11 @@
>   * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
>   * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
>   * alignment for any atomic64_t embedded in buffer.
> - * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
> + * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
>   * value of 4 (and not 8) in ARC ABI.
>   */
>  #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
> -#define ARCH_SLAB_MINALIGN     8
> +#define ARCH_SLAB_MIN_MINALIGN 8
>  #endif
>
>  extern int ioc_enable;
> diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
> index e3ea34558ada..3e1018bb9805 100644
> --- a/arch/arm/include/asm/cache.h
> +++ b/arch/arm/include/asm/cache.h
> @@ -21,7 +21,7 @@
>   * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
>   */
>  #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
> -#define ARCH_SLAB_MINALIGN 8
> +#define ARCH_SLAB_MIN_MINALIGN 8
>  #endif
>
>  #define __read_mostly __section(".data..read_mostly")
> diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> index a074459f8f2f..38f171591c3f 100644
> --- a/arch/arm64/include/asm/cache.h
> +++ b/arch/arm64/include/asm/cache.h
> @@ -6,6 +6,7 @@
>  #define __ASM_CACHE_H
>
>  #include <asm/cputype.h>
> +#include <asm/mte-def.h>
>
>  #define CTR_L1IP_SHIFT         14
>  #define CTR_L1IP_MASK          3
> @@ -49,15 +50,21 @@
>   */
>  #define ARCH_DMA_MINALIGN      (128)
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> -#define ARCH_SLAB_MINALIGN     (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> -#elif defined(CONFIG_KASAN_HW_TAGS)
> -#define ARCH_SLAB_MINALIGN     MTE_GRANULE_SIZE
> -#endif
> -
>  #ifndef __ASSEMBLY__
>
>  #include <linux/bitops.h>
> +#include <linux/kasan-enabled.h>
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define ARCH_SLAB_MIN_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> +#elif defined(CONFIG_KASAN_HW_TAGS)
> +static inline size_t arch_slab_minalign(void)
> +{
> +       return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> +                                        __alignof__(unsigned long long);
> +}
> +#define arch_slab_minalign() arch_slab_minalign()
> +#endif
>
>  #define ICACHEF_ALIASING       0
>  #define ICACHEF_VPIPT          1
> diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
> index 4b8b2fa78fc5..ccdbc1da3c3e 100644
> --- a/arch/microblaze/include/asm/page.h
> +++ b/arch/microblaze/include/asm/page.h
> @@ -33,7 +33,7 @@
>  /* MS be sure that SLAB allocates aligned objects */
>  #define ARCH_DMA_MINALIGN      L1_CACHE_BYTES
>
> -#define ARCH_SLAB_MINALIGN     L1_CACHE_BYTES
> +#define ARCH_SLAB_MIN_MINALIGN L1_CACHE_BYTES
>
>  /*
>   * PAGE_OFFSET -- the first address of the first page of memory. With MMU
> diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
> index 9b58b104559e..7beb3b5d27c7 100644
> --- a/arch/riscv/include/asm/cache.h
> +++ b/arch/riscv/include/asm/cache.h
> @@ -16,7 +16,7 @@
>   * the flat loader aligns it accordingly.
>   */
>  #ifndef CONFIG_MMU
> -#define ARCH_SLAB_MINALIGN     16
> +#define ARCH_SLAB_MIN_MINALIGN 16
>  #endif
>
>  #endif /* _ASM_RISCV_CACHE_H */
> diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
> index e62fd0e72606..9d8cb4687b7e 100644
> --- a/arch/sparc/include/asm/cache.h
> +++ b/arch/sparc/include/asm/cache.h
> @@ -8,7 +8,7 @@
>  #ifndef _SPARC_CACHE_H
>  #define _SPARC_CACHE_H
>
> -#define ARCH_SLAB_MINALIGN     __alignof__(unsigned long long)
> +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
>
>  #define L1_CACHE_SHIFT 5
>  #define L1_CACHE_BYTES 32
> diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
> index 4489a27d527a..e3ea278e3fcf 100644
> --- a/arch/xtensa/include/asm/processor.h
> +++ b/arch/xtensa/include/asm/processor.h
> @@ -18,7 +18,7 @@
>  #include <asm/types.h>
>  #include <asm/regs.h>
>
> -#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
> +#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
>
>  /*
>   * User space process size: 1 GB.
> diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
> index 626898150011..23ce3439eafa 100644
> --- a/fs/binfmt_flat.c
> +++ b/fs/binfmt_flat.c
> @@ -64,7 +64,10 @@
>   * Here we can be a bit looser than the data sections since this
>   * needs to only meet arch ABI requirements.
>   */
> -#define FLAT_STACK_ALIGN       max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
> +static size_t flat_stack_align(void)
> +{
> +       return max(sizeof(void *), arch_slab_minalign());
> +}
>
>  #define RELOC_FAILED 0xff00ff01                /* Relocation incorrect somewhere */
>  #define UNLOADED_LIB 0x7ff000ff                /* Placeholder for unused library */
> @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
>                 sp -= 2; /* argvp + envp */
>         sp -= 1;  /* &argc */
>
> -       current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
> +       current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
>         sp = (unsigned long __user *)current->mm->start_stack;
>
>         if (put_user(bprm->argc, sp++))
> @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
>  #endif
>         stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
>         stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
> -       stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
> +       stack_len = ALIGN(stack_len, flat_stack_align());
>
>         res = load_flat_file(bprm, &libinfo, 0, &stack_len);
>         if (res < 0)
> diff --git a/include/crypto/hash.h b/include/crypto/hash.h
> index f140e4643949..442c290f458c 100644
> --- a/include/crypto/hash.h
> +++ b/include/crypto/hash.h
> @@ -149,7 +149,7 @@ struct ahash_alg {
>
>  struct shash_desc {
>         struct crypto_shash *tfm;
> -       void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
> +       void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
>  };
>
>  #define HASH_MAX_DIGESTSIZE     64
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 373b3ef99f4e..80e517593372 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
>  #endif
>
>  /*
> - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
>   * Intended for arches that get misalignment faults even for 64 bit integer
>   * aligned buffers.
>   */
> -#ifndef ARCH_SLAB_MINALIGN
> -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> +#ifndef ARCH_SLAB_MIN_MINALIGN
> +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> +#endif
> +
> +/*
> + * Arches can define this function if they want to decide the minimum slab
> + * alignment at runtime. The value returned by the function must be
> + * >= ARCH_SLAB_MIN_MINALIGN.
> + */
> +#ifndef arch_slab_minalign
> +static inline size_t arch_slab_minalign(void)
> +{
> +       return ARCH_SLAB_MIN_MINALIGN;
> +}
>  #endif
>
>  /*
>   * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
> - * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
> + * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
>   * aligned pointers.

This comment is not precise: kmalloc relies on kmem_cache_alloc, so
kmalloc technically returns pointers aligned to
max(ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MIN_MINALIGN). See
create_kmalloc_cache()->create_boot_cache()->calculate_alignment() for
SLAB and SLUB and __do_kmalloc_node() for SLOB. This alignment is
stronger than the one is specified for __assume_kmalloc_alignment
below, so the code should be fine. However, the comment is confusing.

Also, the comment next to the ARCH_KMALLOC_MINALIGN definition says
"Setting ARCH_KMALLOC_MINALIGN in arch headers" while it should say
"Setting ARCH_DMA_MINALIGN in arch headers".

>   */
>  #define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
> -#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)
> +#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MIN_MINALIGN)
>  #define __assume_page_alignment __assume_aligned(PAGE_SIZE)
>
>  /*
> diff --git a/mm/slab.c b/mm/slab.c
> index 0edb474edef1..97b756976c8b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3009,10 +3009,9 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
>         objp += obj_offset(cachep);
>         if (cachep->ctor && cachep->flags & SLAB_POISON)
>                 cachep->ctor(objp);
> -       if (ARCH_SLAB_MINALIGN &&
> -           ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
> -               pr_err("0x%px: not aligned to ARCH_SLAB_MINALIGN=%d\n",
> -                      objp, (int)ARCH_SLAB_MINALIGN);
> +       if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
> +               pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
> +                      (int)arch_slab_minalign());
>         }
>         return objp;
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 2b3206a2c3b5..33cc49810a54 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -154,8 +154,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
>                 align = max(align, ralign);
>         }
>
> -       if (align < ARCH_SLAB_MINALIGN)
> -               align = ARCH_SLAB_MINALIGN;
> +       align = max_t(size_t, align, arch_slab_minalign());
>
>         return ALIGN(align, sizeof(void *));
>  }
> diff --git a/mm/slob.c b/mm/slob.c
> index 40ea6e2d4ccd..3bd2669bd690 100644
> --- a/mm/slob.c
> +++ b/mm/slob.c
> @@ -478,7 +478,7 @@ static __always_inline void *
>  __do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
>  {
>         unsigned int *m;
> -       int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
> +       int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
>         void *ret;
>
>         gfp &= gfp_allowed_mask;
> @@ -555,7 +555,7 @@ void kfree(const void *block)
>
>         sp = virt_to_folio(block);
>         if (folio_test_slab(sp)) {
> -               int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
> +               int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
>                 unsigned int *m = (unsigned int *)(block - align);
>                 slob_free(m, *m + align);
>         } else {
> @@ -584,7 +584,7 @@ size_t __ksize(const void *block)
>         if (unlikely(!folio_test_slab(folio)))
>                 return folio_size(folio);
>
> -       align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
> +       align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
>         m = (unsigned int *)(block - align);
>         return SLOB_UNITS(*m) * SLOB_UNIT;
>  }
> --
> 2.36.0.rc2.479.g8af0fa9b8e-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdouu-v1MKndMbeOw96pknGN%3D77%3D8B%3D_K4kedRROrL9pw%40mail.gmail.com.
