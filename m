Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF4UYL6AKGQEWUTR4FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 849102952D7
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 21:20:57 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id e16sf1402970pgm.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 12:20:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603308056; cv=pass;
        d=google.com; s=arc-20160816;
        b=pLqiEeJtRVUZXJz8LvJ5KSOnBeYR4XZIBjs4J9L5s8HCiRHEKRaMi4EanBdfJQh8OX
         LglZRzzJqcZ0bX9UEo2fw9P/P+xCzTAV31DGi2c8ZtUVhsaYrvhqcy8UEqLrjCZb3cJg
         mP66+7zCGA32E/7AvuQprsUQ8toA2p/S3fh4nFsHuOlvMFZiCm/Vc9AdIFJ8MSMmXdRf
         0UOuHvKhQUWsRbs+GUi2yOxgX5NNpiSb2qt46ppcX3KG/aUUqfZb0smj8+0IOl3YgpCc
         cTrcd1XanysaoQ5fhZJEzvYxeI5k95uwTLFL51nFk5LWw8TPUewkXZicYBG0XVDBdWke
         KUig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=azUVKntc+zLW9ipM+GRNqWj/iWkBXyGm8RaChwVkZdo=;
        b=jPDT09TVAq/VYGaYzuWMb+ds6Q3T9Cq+pYlIkqVjQM1zgKi+giQ7T0EpcmBqaJ0jBf
         v7FgldhQrvd8rJUPFnE14ySN3zQaB18gLjUsXmGwAmMi3TjUkt9uQE/7jTAGfq5H3FNJ
         UciDwk5jtuS8Vl2hzKVrFJ2Jsx3QgVlBIxGr2c7f3kgqt0elsSfEQ181iV787j11y3pR
         LdQQvxzhZ6yc5U4RCirwq4AcChr/kfpr4HyIJLw3/+ZjcGn0vTRkqboWxda6Rvl3sso9
         8TG05P8FsRPMfxFXQK2eXem2yiQz08zY7rTYz4RL50lrXUCoAk2GWQ3aKd0frhRxH6he
         E0Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VCKexwNU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=azUVKntc+zLW9ipM+GRNqWj/iWkBXyGm8RaChwVkZdo=;
        b=i3qw8NDC87rw3hH1QjPJjdX7s89QHsaZZV0zA3eEmbdcvQYCYCtzu2LkiARjpwvVvi
         MfM9qo4RERUsiL88AdXSW+O0KD0AqO+zHFVGPc5EdUBtpMhurOO1564u1cJA/FS2ghfJ
         XRBW1poBHTgeV0C4ITsFmldbw95aOsjVA1aRHD8XGaKe9bo/nQgpgF4R38RdpuaTmvCz
         uHSGkjTLshmhOwNoXJ1t75j2ZEhX1b4gcu4C+szZcMhS38x6dUyhXzbqBALWuwSsoqzb
         0n5quU5iajsov9WodKtnOSnrkB02pYFKeeFtpKwTXfGZp7llUPgixWRkUi4nvN+cO1Dk
         5zgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=azUVKntc+zLW9ipM+GRNqWj/iWkBXyGm8RaChwVkZdo=;
        b=ERSPcelwJnkc4PdCv6MKTfYtYuKdxcUMYY0iGSQWB4Dz4CCRyZTLFWFBfeOB9Xmmat
         X2/Ao8o1n7munD6x0MmZegGIEWU0X+E35kn2t8FRqPMfzNeE8V9P5Xfl7A5ShKqBFSmj
         G9j24JAjAGXwiicVMA2PVpBfqFYtjNDwagKSwE/nL6PDwGOVEph2Gt+5KiUZ7ivb2Ayw
         vPk+DsUyPtw7HWUjN3qw74dyrGF4Uy0cqhgWoUMaltTqE4rJlelxDlleAij1yqBEGIRT
         NSPZNnNGGpFlTWRPqsufF1xd3krLyddbe7B8FBRwEq51FgXCzWfgGsFeID2fxVZ7v926
         epmQ==
X-Gm-Message-State: AOAM531NY6PwJxAyBMrJIijLSKtYvu2j/0OBrDBEN025R80lbCaLZ+h5
	+AiUfRuFtwhc4M3o5Cdq40E=
X-Google-Smtp-Source: ABdhPJzhD8WkaSVuHerlmf/3KNxyvvcnut63YDOeViy8WrzVuCdFR6XsGkJ6nIStpqO8OPGo8Nx+vg==
X-Received: by 2002:a17:90a:6984:: with SMTP id s4mr5031357pjj.206.1603308056080;
        Wed, 21 Oct 2020 12:20:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:39c8:: with SMTP id k8ls240370pjf.0.gmail; Wed, 21
 Oct 2020 12:20:55 -0700 (PDT)
X-Received: by 2002:a17:90a:7788:: with SMTP id v8mr4866371pjk.8.1603308055504;
        Wed, 21 Oct 2020 12:20:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603308055; cv=none;
        d=google.com; s=arc-20160816;
        b=NsqI5w2dykZkbpXLVCGed5TxqO/8VXNEOmuOfF3w7McSnCA3qcGOyVKWg00/MQtulK
         dpjdlz6eUMYggfmVrIJ1J626nFwNJtPrrfslxia/cyinul80/madUGaGVEgxvD/hamv1
         gqfncryqcwmNRQ/h9zxGTusxhFrABArgqoy8p7Y9eOgrmke6JgB9lCu3iVIomEVvkZ9Y
         7ItVa5+XEbyysgteOChJbIelEJ9+ibDDQY8z5VQGCJbS5YOArk6GKQcKi/joOPVrBU1n
         8oyyP30YOlxpmOYCLU3GM5I4xWZRqOaB0q94H9vlCoVk4nNL73tUKiuvOL6MbjvUdLfg
         mA9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=akqU1MhDkrT7oithdF82for+lErNOGYxs0P90JR1g3w=;
        b=xGUYHKaLwRLUdGj7ghyLh1/0T9OLEVkmfVovVTELKnxXcxR4Sqks9HLNs2J0sTh+Rz
         BYuoluxnfxukELF6gQ1AfnCkS2QJfcp9BZDnD3qXXSahgyrkeBhq43/ClQ9yFs9Bw6BP
         /6EzLzJhC0tgHMyh6QA4xQuM9GDuhEveGkcU1kLN9gfutcCXkLtymN/AwY5s+8VrFRdG
         jockYKbTQ5R6H4EiNDluJWz+C5MkGZJuNDLhoCSB0OEfRPeJYGs/InXuTg1OZAP9eMEK
         nDVQR0XBNxCXS9GqCxino/WScdmKigz5DeAQUaz24SIoKnDcOsofM5OagPUXyyVS/cdC
         aryw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VCKexwNU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id q2si206804pfc.0.2020.10.21.12.20.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 12:20:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id x1so807452ooo.12
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 12:20:55 -0700 (PDT)
X-Received: by 2002:a4a:751a:: with SMTP id j26mr3679810ooc.14.1603308054842;
 Wed, 21 Oct 2020 12:20:54 -0700 (PDT)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
In-Reply-To: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Oct 2020 21:20:43 +0200
Message-ID: <CANpmjNP0aKOabKvhY4wcrAPdX6ypp81uMfe5_qhNV0NVnvjAEw@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-efi@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VCKexwNU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Reviewed-by: Marco Elver <elver@google.com>

for KCSAN and KASAN.

Thank you!

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP0aKOabKvhY4wcrAPdX6ypp81uMfe5_qhNV0NVnvjAEw%40mail.gmail.com.
