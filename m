Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSNDW6FQMGQEU5FUHHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id F2E9743280D
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 21:58:01 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id w201-20020a25dfd2000000b005be4c3971cdsf3604628ybg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 12:58:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634587081; cv=pass;
        d=google.com; s=arc-20160816;
        b=SriXTEFnmp0jBUCIoHUQUhUTRpbs2HKeAOtSfZlzsSiYkXIYHkhsNd2vXlGvQlk5dz
         HXbRcYatnafoYcgbIfWLubIZ0Z6KwWis5jopVWVQh+6GH2OAA6PswaeguVEsRVlhvyz3
         8AvH8TmCqUTzkx8MBMWrTv4l0YHvBMql0lNNvfkjz6NY1MD04ascgedKYlQy8sSEUI50
         3f1tOaVlczfmBTcM1q8l3Bm1sJ6kjv81It8W8xA0Odt6fsl6O0kCggvuVknFH0tbSCYE
         Acd1M/ruaeQD8uCv8AbEsEip6nTQQn5uUPhEueCZ1IyF6W/lpZrCPWByegQpgsnANwiz
         6U/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BVL3+TXpnO8M4h/FxzHm2ye6pEhAT88Db588SZJGqew=;
        b=cjJbt2Sk11vh7BbMQBwCHA5zZUmVqtTkUIQTZ7aitwYt0c/ojRCK2vfEfDC68sh5/y
         Ygv2H/akwfK/MFSeGKso6du7P4Gr+F2fyRCof7kqoIuj1EK8Ev4R79Bp2H4WuHWsb630
         TKuP7or0Bcvx9xRUACGQM40lq4y+CZIgirWEgD+bSxVpfhY4aX1di7gUpIsG93ZPJvtC
         xfqEtslJFewiZ3DnHm90tg8sIHPjNJpkcssS29Snjv/YhWVjAHikftZTTtLZdw/vEgOb
         lwbK5BQWMO2af4Zq8yEOKTXhXwdl3uaThigI8SrkoS5zB7zqFCPWN4e6b1d0LJV2EhwO
         7GKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Qe/4DEOb";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BVL3+TXpnO8M4h/FxzHm2ye6pEhAT88Db588SZJGqew=;
        b=gNh1CA4DqOZQ0zEt9+DnqQVqmNcNjG8gU8z6GcDMfvghh/VjHuobaoj8I9+ziCWjOS
         V9/xcO2CODiuPyDJUlbCjAQsOi99QLhwlN+yBpI61xHf6A+Ex6eDobWRUPy/jHDLVPiG
         T30VtdxZ+jeH/SL5mwhbe9+AfXoNplWDc54Q2xgzGhW6Ko3oXXXN4wjhZ1mFHK2InHdO
         AjFmWvWytdYeQQSlJE3057453WVY6VbrK6Y344i7ZLHIdW0VUkdQS0eSzS7N/oqgC7CI
         l4FC+3bVWZqxdbInDU7ZpL4RO1NVWaNfT1Llz+RH4LCDJoffaGeF7mEL08TA7wXTojVP
         X7Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BVL3+TXpnO8M4h/FxzHm2ye6pEhAT88Db588SZJGqew=;
        b=nBjpS2tASMDZGFxxwgoPM+atKR6KDkbk+YKKTRq1JFNwwrw4NHgf9/gGxhcbrAhwvA
         ZBfqGDDUv1exSV78M/A7Rau6FzkWaORvSp9/UGlbUyuzMniIKZlMOhGaFrHIUY1hnSDo
         j1pdd4JFzvbxhvkIZp3OcauMPd0a4CqDLFzClEuBYBOtOmSZjBIHFXLvIbmNe0X0lkOZ
         DqPZPOm3qTKprrIe/epnZknMqbJkC9xSTaKHDpNjatG6Rs2SGzMPd/qGcOV6/8Exu1iy
         XqsS2dsE20imRHIiemfemG6Q64NbKpH/ZpaUMHfEzruJEUJyd/amUw3K33VJBE5eK8Jq
         hzWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316EMbBBuKpO06yY3L2Py3B2AkcUHHVBFb7rr+PDa8RK7CbW5xq
	yDNqWJUgvRrtSMHhDkiC1Bk=
X-Google-Smtp-Source: ABdhPJzVvWvXbuT6nMTlJnybTTquhW21OhIvLaNOOZYEky84Xnqdr923Axh72WkQ/yzmJLPxgF0Wlg==
X-Received: by 2002:a25:aa8e:: with SMTP id t14mr32242670ybi.532.1634587081100;
        Mon, 18 Oct 2021 12:58:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cb8f:: with SMTP id b137ls5380543ybg.0.gmail; Mon, 18
 Oct 2021 12:58:00 -0700 (PDT)
X-Received: by 2002:a25:d7d3:: with SMTP id o202mr32583426ybg.485.1634587080706;
        Mon, 18 Oct 2021 12:58:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634587080; cv=none;
        d=google.com; s=arc-20160816;
        b=ZEak86SFPjVzPrurrRSyCYv6qyDAUPxQhrbF+e+89MxjrIMXZXeA5lpZBX1EYJbYEf
         OBO7eYqZsP0dSYPrAyXZ+2gkCd5yU36tbUkxL86NZ6mG227U01qa8IapgoWkvnY5uTSr
         /1OhxxtFp+6N13wL/OLGN9rnoeCjTKBsPsj6RLWwsIP7DBaTlyphTSfnNmdNfioKEf8U
         bvdw/3xwrwv57jgNMb3fhIeNzNg6jKcvEezQJHE26hXcVqS9aK8GD8b+Dr+joGU0Njyf
         RY4zgpnLnodf7/vko6GnJcWqdjFWoAR+prgKjZqxXJR8hdVBTCRUY2rew5IAuAt6I3hR
         q3lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=br6xKN+ewFquRu4Vdte2iE68fWUT3Vzo8bAwzpphWYM=;
        b=abBEQvGwvKXNi1FpBwiVTUlcj/6d6LKTVL9j4lkmgZ1tVTZQXDbGFHJAv7Ttvv9jgl
         +1mwYuL+TEMAFNnheg40pgCsw7ubsAFRrXN+AcltDsdpiDIauo0rZIJ06+DKMkKOdX00
         wD+xXkBWaCXwVyYZd5h0Si7hVJmOTLOSJZsEcsiP6/PrqIvNLOR23Ih2+oAwsoQJdfKI
         z3sekU35hRdEyMxJL8Uln6Qt7KaUXaxHnm8w9RHysEAT8vukbz1KDYEHsBKsuc6QeXqN
         avkE6M0ETe0RtcQPJrEaZy6HKQ84MG6vhb1/djIBykGuU0cKURkvjqDp6nFln/y6VoE6
         hryA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Qe/4DEOb";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id k1si1208155ybp.1.2021.10.18.12.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Oct 2021 12:58:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d9so8393172pfl.6
        for <kasan-dev@googlegroups.com>; Mon, 18 Oct 2021 12:58:00 -0700 (PDT)
X-Received: by 2002:a63:5714:: with SMTP id l20mr25127176pgb.121.1634587079898;
        Mon, 18 Oct 2021 12:57:59 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id bt5sm265293pjb.9.2021.10.18.12.57.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Oct 2021 12:57:59 -0700 (PDT)
Date: Mon, 18 Oct 2021 12:57:58 -0700
From: Kees Cook <keescook@chromium.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: linux-hardening@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Arnd Bergmann <arnd@arndb.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Marco Elver <elver@google.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH 2/2] kasan: use fortified strings for hwaddress sanitizer
Message-ID: <202110181247.8F53380@keescook>
References: <20211013150025.2875883-1-arnd@kernel.org>
 <20211013150025.2875883-2-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211013150025.2875883-2-arnd@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="Qe/4DEOb";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Oct 13, 2021 at 05:00:06PM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> GCC has separate macros for -fsanitize=kernel-address and
> -fsanitize=kernel-hwaddress, and the check in the arm64 string.h
> gets this wrong, which leads to string functions not getting
> fortified with gcc. The newly added tests find this:
> 
> warning: unsafe memchr() usage lacked '__read_overflow' warning in /git/arm-soc/lib/test_fortify/read_overflow-memchr.c
> warning: unsafe memchr_inv() usage lacked '__read_overflow' symbol in /git/arm-soc/lib/test_fortify/read_overflow-memchr_inv.c
> warning: unsafe memcmp() usage lacked '__read_overflow' warning in /git/arm-soc/lib/test_fortify/read_overflow-memcmp.c
> warning: unsafe memscan() usage lacked '__read_overflow' symbol in /git/arm-soc/lib/test_fortify/read_overflow-memscan.c
> warning: unsafe memcmp() usage lacked '__read_overflow2' warning in /git/arm-soc/lib/test_fortify/read_overflow2-memcmp.c
> warning: unsafe memcpy() usage lacked '__read_overflow2' symbol in /git/arm-soc/lib/test_fortify/read_overflow2-memcpy.c
> warning: unsafe memmove() usage lacked '__read_overflow2' symbol in /git/arm-soc/lib/test_fortify/read_overflow2-memmove.c
> warning: unsafe memcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memcpy.c
> warning: unsafe memmove() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memmove.c
> warning: unsafe memset() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memset.c
> warning: unsafe strcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strcpy-lit.c
> warning: unsafe strcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strcpy.c
> warning: unsafe strlcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strlcpy-src.c
> warning: unsafe strlcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strlcpy.c
> warning: unsafe strncpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strncpy-src.c
> warning: unsafe strncpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strncpy.c
> warning: unsafe strscpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strscpy.c
> 

What is the build config that trips these warnings?

In trying to understand this, I see in arch/arm64/include/asm/string.h:

#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
        !defined(__SANITIZE_ADDRESS__)

other architectures (like arm32) do:

#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)

so it's okay because it's not getting touched by the hwaddress sanitizer?
e.g. I see:

config CC_HAS_KASAN_GENERIC
        def_bool $(cc-option, -fsanitize=kernel-address)

config CC_HAS_KASAN_SW_TAGS
        def_bool $(cc-option, -fsanitize=kernel-hwaddress)

> Add a workaround to include/linux/compiler_types.h so we always
> define __SANITIZE_ADDRESS__ for either mode, as we already do
> for clang.

Where is the clang work-around? (Or is this a statement that clang,
under -fsanitize=kernel-hwaddress, already sets __SANITIZE_ADDRESS__ by
default?

> 
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  include/linux/compiler_types.h | 7 +++++++
>  1 file changed, 7 insertions(+)
> 
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index aad6f6408bfa..2f2776fffefe 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -178,6 +178,13 @@ struct ftrace_likely_data {
>   */
>  #define noinline_for_stack noinline
>  
> +/*
> + * Treat __SANITIZE_HWADDRESS__ the same as __SANITIZE_ADDRESS__ in the kernel
> + */
> +#ifdef __SANITIZE_HWADDRESS__
> +#define __SANITIZE_ADDRESS__
> +#endif

Should this go into compiler-gcc.h instead?

> +
>  /*
>   * Sanitizer helper attributes: Because using __always_inline and
>   * __no_sanitize_* conflict, provide helper attributes that will either expand
> -- 
> 2.29.2
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202110181247.8F53380%40keescook.
