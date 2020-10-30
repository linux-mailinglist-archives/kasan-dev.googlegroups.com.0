Return-Path: <kasan-dev+bncBD4NDKWHQYDRB64G576AKGQECZB5NIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A568429FE8C
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:40:44 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id l188sf4197747pfl.23
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 00:40:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604043643; cv=pass;
        d=google.com; s=arc-20160816;
        b=zJOqmiwChrcNe9Dx7D93M89cG9ZRRxLuhumgwWqevnvK/TNi447S7jZZ5eZjRcd54B
         5XyclSbWwHenGzceN0xFIVq4INhGatrdo14KO0jTxV0TmxxQ164WHgKfPv9JCtb+mTOB
         ZKkxBBYEXhbMnGKLejdeMomIgu0UdFeCPipGNhDNJTJLDg/rEe8ifH3Med7Xq7CHEu3j
         Wqe8cDNDdQHsFr4EhnyFc3D8K4nucsZTeUXEIX8DpfdOALPIrTnXx3glH0byK/txevZz
         wlQ+9l9//6PwzsnIpTtLaeabJqbWVHwvH6rotAYgO3FLH7ejg8ky2v/i6V16GxExRvun
         6fTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=lBiO14ywyZptfkylEHuUN2B21wCPBoZyMdDdi4sbZ44=;
        b=JWR69EoJ9wvVa7/HDJD1maeJpf2658xUFdxPSMyC932bG/eNuLPG5c3sqDVUzBMEmz
         dfepn8iqHfWvYbLaqff1uLUz/Ilf9wmoCSDfHar5YfIU7V8wzbd4ZcUN9yP0M1O6vFms
         za6wOBdHGpODD82NGtGNH9Z81W0ExAlvkwAiw7sx7HRGmT+F5kdWv1US7/XDHLcHcpWi
         K2/8KZiPGn99I7bSK0rjlXbWBQbh1VTRovfmm3XBuNX/KSXfJc3YH3UUS6ta/DwqIGmC
         feNu0AwPfb2DraBJtSsUwHtx3w1t+LmVGmNwrQAXhydRdrpsXXyuLdIAqrQLPay/ztJ4
         uNvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vRO2afTP;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lBiO14ywyZptfkylEHuUN2B21wCPBoZyMdDdi4sbZ44=;
        b=nIWEeBSxe+WqxBN4qzWKb7KK9Zb++w4eY6Pjt59W4R9MORACQ+s1MLjLhyc3wz6JrR
         Ex0HuwBAFfMlanSBmSvcTrkdslO3tVoiCVLc5gXMTs2NR5dlcHOARf/+h/FfVucljeZw
         aRYCgwoekd33BbK5VkFCM1Nh1CnLOjQ5GZiBMvpoLIHVp6jaMVeoPToupo3/bVrhtf63
         cN8r9w/4mLewQOaZfHGl4ywUOqoh5ILA+qWIe5WKwWqVT5A0e/EMg77P7Pdb3xRK3JH6
         pP/BlK/B+LnNEzaZop61FmRjJ7FNhH+Mpz411FXYpR68J2+OUZRIjsiM8TO/AgyzN6Ag
         VtCw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lBiO14ywyZptfkylEHuUN2B21wCPBoZyMdDdi4sbZ44=;
        b=cv26gw+PJwrpWKwTp0juiufrBmqa3KSz5v/1X/Y4soPUhT4lreU46JtBVVsH8nEVau
         NaUUYzdYTu+fK3wTvKGov0g9dtWLrarXVS7/kHfKc7we4RZQsl8yikcOXMTTFGKm9eF8
         ToShNPYKppuGxLOIIgIWMwRNIbQMab5yzYzI7kGBay72K5OOo+12L5Wh6rBke60CwKgf
         iRtnbZWNY2GZAhQeKTSP55nenFQ7Orc7EWrxm9ONBvR5y1ZX8Ey+UZrQ7gVz7INrvSYe
         Xwqtb9pRODMxJA5Z2Ww+cef0NVs8vXDtcGyV9yV7P8vAe6aITkhbpSsTx8BJ0sQxNV0R
         tBCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lBiO14ywyZptfkylEHuUN2B21wCPBoZyMdDdi4sbZ44=;
        b=Tkr2CZQERU/8QImqBdZ+9PpiTbhKBhgx4mjGQBJByGIi+Y8IqYpBQssxP+Fvxccwpb
         8bsTBW5x6W6YxT6ZTHHJ2weH4V4Pf2WVgFhtKDPENJbcjk6HfLgSEpBoBV3WzaYWkRIj
         nDJqvuGpm0TVf1JIBmZzAbOoeyJvDcpoR6Xx6nxyCT0SO4a+RsbdCiXl0cNmMLa+8Dq3
         JMa5olK/D9UjdIe0WfIHkKHvGnXhNpzAVF9b4lrq42f/yCWXDJj8HUYAnytILyUwOLYE
         ZYqtq8FlU+7uG/cFL5ajfEu3hnc1fd5Ef3pNmBn2yWGg+HKtgrcm/0LFemYUmVR0uDMr
         yaRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/WFDlLY5+V/Bn4se+KknFjSP+FOi4UlHka1SmkWgu7Vz+CJKv
	87j5NoPMHvjEJNkEYSSX1XQ=
X-Google-Smtp-Source: ABdhPJyO4U3EUEbngX8x4Z4jbP58Vfe5sRaB2Q2wIoLE1pX8QAVqQHbrVqmFzAi3YVxZDuZdv5ezxQ==
X-Received: by 2002:a63:1604:: with SMTP id w4mr1093153pgl.148.1604043643151;
        Fri, 30 Oct 2020 00:40:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f13:: with SMTP id a19ls2022152pfd.9.gmail; Fri, 30 Oct
 2020 00:40:42 -0700 (PDT)
X-Received: by 2002:a62:16ce:0:b029:160:5faa:23d5 with SMTP id 197-20020a6216ce0000b02901605faa23d5mr8112878pfw.26.1604043642599;
        Fri, 30 Oct 2020 00:40:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604043642; cv=none;
        d=google.com; s=arc-20160816;
        b=AYr7GF010PkByXQEpvkz2Uy33uydU16yFlQCxG88fb74MuhvpAUYYxyZSpRFfqpe9S
         o4s6Z0fqgkMxkTLwj6M2FMC5UL/XCUxiVbEgxMRZFclGd56uYih+/kdPuKKqalZ/y0WZ
         b4O/uaJqYBmy+anqsokVoq5qV2UXqXikgDp8q509dmE6HcbKhre62z94aApPDTaiBQPj
         +QaLRCQvrTG0o2rcXSb+ppXRm8JPnq1C98TIIlrcegjnW0PYt2btPtCCYtdTzMvt5lnr
         clNsf6PDMROgzb3Lwl8Bv5cax6EjkV+cciDfqZ5RtqKbh4PZx6SrVqjHkBKMQ5NW7Vhn
         qu1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4ZZqckq9iBzbPT7QTQmdrh5Ofh971dIkKFYUcVvnOi0=;
        b=D7e3oAe1jCxZkjzhpT4Yf2VKCtbVLjaQ8ThAqWBYfUUSaggYnpLpi6AsPK2PIRisyR
         gogOR5NVg/YU2wY9Yu6C0FroCfSzOvJ+7GGOl46dQxnuXL5/na3XJ+dANIqIoDuSzS0e
         6EsAzvAOlSi/5OPXwXCvok1ykUF/szu3iUFcsN/CP5kCMqMKHBo1zZ6K2A9jjmorLgyv
         QAyv/jQWAl0PXzIn5MNnA4WIMBlAqGQmnxi+bMahDcpfR6tFjod26GgaSCE8/EWU/VYt
         I0m6hnaimqC8aTXZnhn52mkeLrliLvbHV2qhxxDiBZN0vaQ4VLQquOqjoqB3p2N2kZcc
         0T2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vRO2afTP;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x142.google.com (mail-il1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id mv6si137276pjb.0.2020.10.30.00.40.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 00:40:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-il1-x142.google.com with SMTP id a20so5664081ilk.13;
        Fri, 30 Oct 2020 00:40:42 -0700 (PDT)
X-Received: by 2002:a92:da92:: with SMTP id u18mr975106iln.266.1604043641932;
        Fri, 30 Oct 2020 00:40:41 -0700 (PDT)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id r3sm4188815iog.55.2020.10.30.00.40.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Oct 2020 00:40:41 -0700 (PDT)
Date: Fri, 30 Oct 2020 00:40:38 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Joe Perches <joe@perches.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-mm@kvack.org, clang-built-linux@googlegroups.com
Subject: Re: [PATCH] treewide: Remove stringification from __alias macro
 definition
Message-ID: <20201030074038.GA1747580@ubuntu-m3-large-x86>
References: <8451df41359b52f048780d19e07b6fa4445b6392.1604026698.git.joe@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8451df41359b52f048780d19e07b6fa4445b6392.1604026698.git.joe@perches.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=vRO2afTP;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Oct 29, 2020 at 08:07:31PM -0700, Joe Perches wrote:
> Like the old __section macro, the __alias macro uses macro # stringification
> to create quotes around the symbol name used in the __attribute__.
> 
> This can cause differences between gcc and clang when the stringification
> itself contains a quote character.  So avoid these differences by always
> using quotes to define the aliased symbol.
> 
> Remove the stringification and add quotes and when necessary a stringification
> when existing uses have a ## concatenation.
> 
> Signed-off-by: Joe Perches <joe@perches.com>

Reviewed-by: Nathan Chancellor <natechancellor@gmail.com>

> ---
> 
> Unlike the __section macro conversion in commit 33def8498fdd
> ("treewide: Convert macro and uses of __section(foo) to __section("foo")")
> this one was done by hand.
> 
> No other use of __alias exists in the kernel.
> 
> This patch does _not_ convert any uses of __attribute__((alias("<foo>")))
> so it should not cause any compilation issues.
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
>  	long __##abi##_##name(const struct pt_regs *regs);		\
>  	ALLOW_ERROR_INJECTION(__##abi##_##name, ERRNO);			\
>  	long __##abi##_##name(const struct pt_regs *regs)		\
> -		__alias(__do_##name);
> +		__alias("__do_" #name);
>  
>  #define __SYS_STUBx(abi, name, ...)					\
>  	long __##abi##_##name(const struct pt_regs *regs);		\
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
>  	}                                                                      \
>  	EXPORT_SYMBOL(__tsan_read##size);                                      \
>  	void __tsan_unaligned_read##size(void *ptr)                            \
> -		__alias(__tsan_read##size);                                    \
> +		__alias("__tsan_read" #size);                                  \
>  	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
>  	void __tsan_write##size(void *ptr);                                    \
>  	void __tsan_write##size(void *ptr)                                     \
> @@ -823,7 +823,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
>  	}                                                                      \
>  	EXPORT_SYMBOL(__tsan_write##size);                                     \
>  	void __tsan_unaligned_write##size(void *ptr)                           \
> -		__alias(__tsan_write##size);                                   \
> +		__alias("__tsan_write" #size);                                 \
>  	EXPORT_SYMBOL(__tsan_unaligned_write##size);                           \
>  	void __tsan_read_write##size(void *ptr);                               \
>  	void __tsan_read_write##size(void *ptr)                                \
> @@ -833,7 +833,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
>  	}                                                                      \
>  	EXPORT_SYMBOL(__tsan_read_write##size);                                \
>  	void __tsan_unaligned_read_write##size(void *ptr)                      \
> -		__alias(__tsan_read_write##size);                              \
> +		__alias("__tsan_read_write" #size);                            \
>  	EXPORT_SYMBOL(__tsan_unaligned_read_write##size)
>  
>  DEFINE_TSAN_READ_WRITE(1);
> @@ -877,7 +877,7 @@ EXPORT_SYMBOL(__tsan_write_range);
>  	}                                                                      \
>  	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
>  	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
> -		__alias(__tsan_volatile_read##size);                           \
> +		__alias("__tsan_volatile_read" #size);                         \
>  	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
>  	void __tsan_volatile_write##size(void *ptr);                           \
>  	void __tsan_volatile_write##size(void *ptr)                            \
> @@ -892,7 +892,7 @@ EXPORT_SYMBOL(__tsan_write_range);
>  	}                                                                      \
>  	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
>  	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
> -		__alias(__tsan_volatile_write##size);                          \
> +		__alias("__tsan_volatile_write" #size);                        \
>  	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
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
>  	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
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
>  		check_memory_region_inline(addr, size, false, _RET_IP_);\
>  	}								\
>  	EXPORT_SYMBOL(__asan_load##size);				\
> -	__alias(__asan_load##size)					\
> +	__alias("__asan_load" #size)					\
>  	void __asan_load##size##_noabort(unsigned long);		\
>  	EXPORT_SYMBOL(__asan_load##size##_noabort);			\
>  	void __asan_store##size(unsigned long addr)			\
> @@ -242,7 +242,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
>  		check_memory_region_inline(addr, size, true, _RET_IP_);	\
>  	}								\
>  	EXPORT_SYMBOL(__asan_store##size);				\
> -	__alias(__asan_store##size)					\
> +	__alias("__asan_store" #size)					\
>  	void __asan_store##size##_noabort(unsigned long);		\
>  	EXPORT_SYMBOL(__asan_store##size##_noabort)
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
> -- 
> 2.26.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201030074038.GA1747580%40ubuntu-m3-large-x86.
