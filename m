Return-Path: <kasan-dev+bncBD63HSEZTUIBBXMLYL6AKGQEGFOWXNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FFC12952A4
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 21:02:55 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id e82sf1455353oia.15
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 12:02:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603306974; cv=pass;
        d=google.com; s=arc-20160816;
        b=KxbJkm0JG9WTp1bolR2SkdU0TJ1mVKiuhF1i89V+puW8/PSWukITB17CzsRPsCqCXs
         AJfjcMYdn80kW2My5qbsj8DIcALo2JXARDEMycwb3yXScWe6wFdgcfDNYoTulItR6//+
         KFjzYIbdoHGgOx03HeAivUKOHo7gBuksuI2HTA3XHGlhzxrsXOhTHuAgf8AtosZb3BmB
         9331lZ3eE68SpROD75125x9NIK/bPhFnsZ4T28rmwgFGLNpGWyY6pzpdVJDOiADAccz8
         qimN4aIM5alZg6uMJEjdimHRTOp7GkonDJhsUsP+Ei/rKgy62PkFkc91UUTe3ad8mwPo
         JPIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=CnzMeL0e3Rc/5taSryiEGpraD1Dz68gQOiKC/Rte3a4=;
        b=eJNpgxcbgMRptDdvi+v/V+0StPaWsz5DTWtINWFFTaXQYEm0k8dMjyL0yYVX4PKIDo
         QAQfunryR+vEQdmjD/MGhOXd1pefAwvV0AZSgcCaQRrm1VKG6AG2IG73XWL6/cbB7jab
         eoXN9KvtC6JFYFiNPrK5gg6Y348HY8jv4k21ai7GdBJJuFgTOM9u1RUyj//+Lhvb8sWR
         k28PKLd1dqqqL75LkTxD8ba0jSt0R7QWodxiITRKD+c+55Od8jtpnpBkFvB/puYfHh6S
         dGZKQU+UB2zjpfZRxbGL/LIPDhCvVWFXVkWKoHCN308LGGltCldr7Ae1X51R8hlEBvP2
         4Cgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RHFbNLBR;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CnzMeL0e3Rc/5taSryiEGpraD1Dz68gQOiKC/Rte3a4=;
        b=QXI4J+MxmbpT/DtPsm34ocRQgnksMIh07JTn4k1KMSmA98bNfKZp6+TN+SgjchjUdV
         zR5isf863tt4t5qLRWmqCD/CFYyq85gZqdzgcYpPLFWj07/lTnlh/eH25whC3yK0gNXm
         Ptk7AD90u1XbKs+D0NHoqKc0FI+A6Gcq27PRbZ+6ETgvp66CJkOSWZUDvhBOWBO1lI+P
         1Iv0p68YRDYjQz7N4RPzThkoRMm3c+e3Md5ho0cY4OdAigZjigphXuFOZXJySZ78Cswa
         a7DMAKeNcnJlh5C+9k1oKTLzhOKcD+skS6RBBfaMKOb4ELBNYB2JY8q8mF11NQP/q91p
         qMng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CnzMeL0e3Rc/5taSryiEGpraD1Dz68gQOiKC/Rte3a4=;
        b=p+Zyi8lnQUDm/ef6qAN8RHnP0h0+/ria9Xm8WLAxO1wUxlnL1m91qLrf1Rhb7zQVxc
         QID48yecs1WK5UIrYgMcBcf3RzolSF/OFHx1GRW8mzIDRqA652C+nDNWcRbEXXH7koth
         3sJQoQwmi8/yc/XMNSEaT6asHs9ag8WfiY8tsD9YyMN4x/gs2r76NTkiIfenI8HeD7ns
         iNjfOrbhCgJaGS13qp0VOdNLRjBbnZbsfY+asTbBl7U0XCtsgfYTsALotpIXaL7XmgB3
         VsK0bsMiCYaGHXGDrY+gJU6V67BS2/16yJ8gBL/nFfD15hAOAN3eYDS3//8X63zH+KN4
         mpUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xDxG4+09DHhoEVFGomi6MEM4yx1wuLo2C2GlOXCKmoycCN2Tg
	pT6OT6xkjpskgCI7G3IjelY=
X-Google-Smtp-Source: ABdhPJwQx7gXUosU+W30NP2q57Zl5s6hVNtOdkt8wMEuoh2gPffhTI04WjzbMsOoHJ/BR4nLVAUH0A==
X-Received: by 2002:a9d:7458:: with SMTP id p24mr3860282otk.22.1603306974037;
        Wed, 21 Oct 2020 12:02:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c649:: with SMTP id w70ls166790oif.3.gmail; Wed, 21 Oct
 2020 12:02:53 -0700 (PDT)
X-Received: by 2002:aca:4e05:: with SMTP id c5mr3434405oib.99.1603306973408;
        Wed, 21 Oct 2020 12:02:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603306973; cv=none;
        d=google.com; s=arc-20160816;
        b=x5EQzUq7c9OtUZdwBLoyBagPmFcoS03ynanyyh91JX8lII0TH/f3HXCwtKJ82hCO/C
         kse7H5zYnA3ZSUTZ9IM5LBrfOuYSth+v3ebStTt6Z7IrVxrh2GJj/HG/+j2SzBWM5Q7n
         pvi7FG8B2xM0H9AGTZ8FjI5yyxzpY82lb0BrJNDyqzcbx7kkbUsVO5ciQfZSN5nEIZhO
         FM2tT9S7HwkXi1zbqL6ajcWumQTMKRU3G8LkQOVjAC1z68pXDpTZ7BFTIxGwKN2P6RfA
         XjQBYGI2xR5jL5nJybP0ed8ylTrVx/SY3XjxHzniuGYRecyDVokQtCtaAlQzef7rSbcW
         t1dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qcPbGlFOsUqV4ZwfO2j85jZ5KoUVBEu5I+mcqG3qfj4=;
        b=hRSAfyI8+wBIB4Ea2wJAOOIfI3B90k9f+TVEd00Ee7aVG6PwgV9sGzcKDTWnkItjQR
         aECssQNdPekXVSsfbAI4G/iDPUm6dOOGXhRCnN3Wgespv0NSTdlQqSroqNCBlSsaIpjs
         a/lx84Mz0NTdyX1++JQsltuGBDk6pLkSJ1J3fLG6mT4mE5BM6GB5uCdgWXx1q1feVub0
         Z9xD5wGcQbjQu/NG6ehMReTsIxO+Qe3RcpswswJpYzUSw2kJPdiqn2/ZRsm6VULzd4ih
         1OD6AdQuwebPUm29nW5vTewdWXleyv8DubftgbNkCG7Ov7RQPb/L9FFU6ZQ2nXiF2n9N
         ifHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RHFbNLBR;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si288749oov.2.2020.10.21.12.02.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Oct 2020 12:02:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f47.google.com (mail-ot1-f47.google.com [209.85.210.47])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2A39B2417E
	for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 19:02:52 +0000 (UTC)
Received: by mail-ot1-f47.google.com with SMTP id f37so2812310otf.12
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 12:02:52 -0700 (PDT)
X-Received: by 2002:a9d:6a85:: with SMTP id l5mr3828841otq.77.1603306970159;
 Wed, 21 Oct 2020 12:02:50 -0700 (PDT)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
In-Reply-To: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Wed, 21 Oct 2020 21:02:39 +0200
X-Gmail-Original-Message-ID: <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com>
Message-ID: <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, X86 ML <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=RHFbNLBR;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, 21 Oct 2020 at 20:58, Joe Perches <joe@perches.com> wrote:
>
> Like the __section macro, the __alias macro uses
> macro # stringification to create quotes around
> the section name used in the __attribute__.
>
> Remove the stringification and add quotes or a
> stringification to the uses instead.
>

Why?

> Signed-off-by: Joe Perches <joe@perches.com>
> ---
>
> There is a script that might eventually be applied
> to convert the __section macro definition and uses
> to remove stringification
>
> https://lore.kernel.org/lkml/46f69161e60b802488ba8c8f3f8bbf922aa3b49b.camel@perches.com/
> https://lore.kernel.org/lkml/75393e5ddc272dc7403de74d645e6c6e0f4e70eb.camel@perches.com/
>
> This patch is intended to create commonality
> between the uses of __section and __alias.
>
>  arch/x86/boot/compressed/string.c       |  6 +++---
>  arch/x86/include/asm/syscall_wrapper.h  |  2 +-
>  drivers/firmware/efi/runtime-wrappers.c |  2 +-
>  include/linux/compiler_attributes.h     |  2 +-
>  kernel/kcsan/core.c                     | 10 +++++-----
>  lib/crc32.c                             |  4 ++--
>  lib/crypto/aes.c                        |  4 ++--
>  mm/kasan/generic.c                      |  8 ++++----
>  8 files changed, 19 insertions(+), 19 deletions(-)
>
> diff --git a/arch/x86/boot/compressed/string.c b/arch/x86/boot/compressed/string.c
> index 81fc1eaa3229..d38b122f51ef 100644
> --- a/arch/x86/boot/compressed/string.c
> +++ b/arch/x86/boot/compressed/string.c
> @@ -75,7 +75,7 @@ void *memcpy(void *dest, const void *src, size_t n)
>  }
>
>  #ifdef CONFIG_KASAN
> -extern void *__memset(void *s, int c, size_t n) __alias(memset);
> -extern void *__memmove(void *dest, const void *src, size_t n) __alias(memmove);
> -extern void *__memcpy(void *dest, const void *src, size_t n) __alias(memcpy);
> +extern void *__memset(void *s, int c, size_t n) __alias("memset");
> +extern void *__memmove(void *dest, const void *src, size_t n) __alias("memmove");
> +extern void *__memcpy(void *dest, const void *src, size_t n) __alias("memcpy");
>  #endif
> diff --git a/arch/x86/include/asm/syscall_wrapper.h b/arch/x86/include/asm/syscall_wrapper.h
> index a84333adeef2..f19d1bbbff3d 100644
> --- a/arch/x86/include/asm/syscall_wrapper.h
> +++ b/arch/x86/include/asm/syscall_wrapper.h
> @@ -69,7 +69,7 @@ extern long __ia32_sys_ni_syscall(const struct pt_regs *regs);
>         long __##abi##_##name(const struct pt_regs *regs);              \
>         ALLOW_ERROR_INJECTION(__##abi##_##name, ERRNO);                 \
>         long __##abi##_##name(const struct pt_regs *regs)               \
> -               __alias(__do_##name);
> +               __alias("__do_" #name);
>
>  #define __SYS_STUBx(abi, name, ...)                                    \
>         long __##abi##_##name(const struct pt_regs *regs);              \
> diff --git a/drivers/firmware/efi/runtime-wrappers.c b/drivers/firmware/efi/runtime-wrappers.c
> index 1410beaef5c3..14e380ac65d4 100644
> --- a/drivers/firmware/efi/runtime-wrappers.c
> +++ b/drivers/firmware/efi/runtime-wrappers.c
> @@ -162,7 +162,7 @@ static DEFINE_SEMAPHORE(efi_runtime_lock);
>   * Expose the EFI runtime lock to the UV platform
>   */
>  #ifdef CONFIG_X86_UV
> -extern struct semaphore __efi_uv_runtime_lock __alias(efi_runtime_lock);
> +extern struct semaphore __efi_uv_runtime_lock __alias("efi_runtime_lock");
>  #endif
>
>  /*
> diff --git a/include/linux/compiler_attributes.h b/include/linux/compiler_attributes.h
> index ea7b756b1c8f..4819512c9abd 100644
> --- a/include/linux/compiler_attributes.h
> +++ b/include/linux/compiler_attributes.h
> @@ -42,7 +42,7 @@
>  /*
>   *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-alias-function-attribute
>   */
> -#define __alias(symbol)                 __attribute__((__alias__(#symbol)))
> +#define __alias(symbol)                 __attribute__((__alias__(symbol)))
>
>  /*
>   *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-aligned-function-attribute
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 3994a217bde7..465f6cfc317c 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -814,7 +814,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
>         }                                                                      \
>         EXPORT_SYMBOL(__tsan_read##size);                                      \
>         void __tsan_unaligned_read##size(void *ptr)                            \
> -               __alias(__tsan_read##size);                                    \
> +               __alias("__tsan_read" #size);                                  \
>         EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
>         void __tsan_write##size(void *ptr);                                    \
>         void __tsan_write##size(void *ptr)                                     \
> @@ -823,7 +823,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
>         }                                                                      \
>         EXPORT_SYMBOL(__tsan_write##size);                                     \
>         void __tsan_unaligned_write##size(void *ptr)                           \
> -               __alias(__tsan_write##size);                                   \
> +               __alias("__tsan_write" #size);                                 \
>         EXPORT_SYMBOL(__tsan_unaligned_write##size);                           \
>         void __tsan_read_write##size(void *ptr);                               \
>         void __tsan_read_write##size(void *ptr)                                \
> @@ -833,7 +833,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
>         }                                                                      \
>         EXPORT_SYMBOL(__tsan_read_write##size);                                \
>         void __tsan_unaligned_read_write##size(void *ptr)                      \
> -               __alias(__tsan_read_write##size);                              \
> +               __alias("__tsan_read_write" #size);                            \
>         EXPORT_SYMBOL(__tsan_unaligned_read_write##size)
>
>  DEFINE_TSAN_READ_WRITE(1);
> @@ -877,7 +877,7 @@ EXPORT_SYMBOL(__tsan_write_range);
>         }                                                                      \
>         EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
>         void __tsan_unaligned_volatile_read##size(void *ptr)                   \
> -               __alias(__tsan_volatile_read##size);                           \
> +               __alias("__tsan_volatile_read" #size);                         \
>         EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
>         void __tsan_volatile_write##size(void *ptr);                           \
>         void __tsan_volatile_write##size(void *ptr)                            \
> @@ -892,7 +892,7 @@ EXPORT_SYMBOL(__tsan_write_range);
>         }                                                                      \
>         EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
>         void __tsan_unaligned_volatile_write##size(void *ptr)                  \
> -               __alias(__tsan_volatile_write##size);                          \
> +               __alias("__tsan_volatile_write" #size);                        \
>         EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
>
>  DEFINE_TSAN_VOLATILE_READ_WRITE(1);
> diff --git a/lib/crc32.c b/lib/crc32.c
> index 2a68dfd3b96c..373a17aaa432 100644
> --- a/lib/crc32.c
> +++ b/lib/crc32.c
> @@ -206,8 +206,8 @@ u32 __pure __weak __crc32c_le(u32 crc, unsigned char const *p, size_t len)
>  EXPORT_SYMBOL(crc32_le);
>  EXPORT_SYMBOL(__crc32c_le);
>
> -u32 __pure crc32_le_base(u32, unsigned char const *, size_t) __alias(crc32_le);
> -u32 __pure __crc32c_le_base(u32, unsigned char const *, size_t) __alias(__crc32c_le);
> +u32 __pure crc32_le_base(u32, unsigned char const *, size_t) __alias("crc32_le");
> +u32 __pure __crc32c_le_base(u32, unsigned char const *, size_t) __alias("__crc32c_le");
>
>  /*
>   * This multiplies the polynomials x and y modulo the given modulus.
> diff --git a/lib/crypto/aes.c b/lib/crypto/aes.c
> index 827fe89922ff..5b80514595c2 100644
> --- a/lib/crypto/aes.c
> +++ b/lib/crypto/aes.c
> @@ -82,8 +82,8 @@ static volatile const u8 __cacheline_aligned aes_inv_sbox[] = {
>         0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
>  };
>
> -extern const u8 crypto_aes_sbox[256] __alias(aes_sbox);
> -extern const u8 crypto_aes_inv_sbox[256] __alias(aes_inv_sbox);
> +extern const u8 crypto_aes_sbox[256] __alias("aes_sbox");
> +extern const u8 crypto_aes_inv_sbox[256] __alias("aes_inv_sbox");
>
>  EXPORT_SYMBOL(crypto_aes_sbox);
>  EXPORT_SYMBOL(crypto_aes_inv_sbox);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 248264b9cb76..4496f897e4f5 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -234,7 +234,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
>                 check_memory_region_inline(addr, size, false, _RET_IP_);\
>         }                                                               \
>         EXPORT_SYMBOL(__asan_load##size);                               \
> -       __alias(__asan_load##size)                                      \
> +       __alias("__asan_load" #size)                                    \
>         void __asan_load##size##_noabort(unsigned long);                \
>         EXPORT_SYMBOL(__asan_load##size##_noabort);                     \
>         void __asan_store##size(unsigned long addr)                     \
> @@ -242,7 +242,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
>                 check_memory_region_inline(addr, size, true, _RET_IP_); \
>         }                                                               \
>         EXPORT_SYMBOL(__asan_store##size);                              \
> -       __alias(__asan_store##size)                                     \
> +       __alias("__asan_store" #size)                                   \
>         void __asan_store##size##_noabort(unsigned long);               \
>         EXPORT_SYMBOL(__asan_store##size##_noabort)
>
> @@ -258,7 +258,7 @@ void __asan_loadN(unsigned long addr, size_t size)
>  }
>  EXPORT_SYMBOL(__asan_loadN);
>
> -__alias(__asan_loadN)
> +__alias("__asan_loadN")
>  void __asan_loadN_noabort(unsigned long, size_t);
>  EXPORT_SYMBOL(__asan_loadN_noabort);
>
> @@ -268,7 +268,7 @@ void __asan_storeN(unsigned long addr, size_t size)
>  }
>  EXPORT_SYMBOL(__asan_storeN);
>
> -__alias(__asan_storeN)
> +__alias("__asan_storeN")
>  void __asan_storeN_noabort(unsigned long, size_t);
>  EXPORT_SYMBOL(__asan_storeN_noabort);
>
>
>
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ%2B1R7tsnA66ZzsiBgw%40mail.gmail.com.
