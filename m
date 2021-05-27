Return-Path: <kasan-dev+bncBD4NDKWHQYDRBF7SX6CQMGQEIV5U5CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 298DB3936B7
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 21:55:05 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id x8-20020a6bda080000b029048654ffbae7sf1128219iob.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 12:55:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622145304; cv=pass;
        d=google.com; s=arc-20160816;
        b=SImumD3aa1qMjMUB3qkO6GCiwuStOBQWIe6wWGBYXoCl8sQfBffbYhAvao4Dlplqee
         n041L6DGlmHzG9qfBCg5bPh+LqIWm7jgVcPfP0sjqDMBXDk1Zaxkyi3VHKvhYjFQgi4x
         kcEX/bKYB3euirvjvKYBl0FLn1PVMOg83D7oHrH0NmXZSwYzT+yd8pgaKuRJTJUfluGM
         MTAZ/jYmx8IxNTx8vyEd18gcpxSKKpOLbSBekm18KhRK3TQdZmWAP+GrLmUCCVVdamSF
         WYjYlI2NJWQ4iuJq/ev6VUdiznWDZVAAJENu1tnjpUGmxjRVVqNca7TABQZJwAFIbOkK
         dzyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NRNteOyn0HxMMDLZVTSk/gVZyW/2+uPG78loRLaPfoU=;
        b=DHzhommoMMoohrESafIU8X0JaFTxLqoSAOHEUqDGaHO8h5OuG8qHAL5tQ27EsGtVTQ
         buT9RLodogw9gyqokO5yfs/fB8EVOj03GYdE6W+942GPTGERHsKBp2GYASHy8UQurf1L
         ocnA+FyuvtApfE0InQoGUVjijMldrnoSMM/JAvlL7l6Y/2e2OkyEGBXIT8vyU46TAngn
         WeChnIE8+luVK1ToYodsld3GbvRuz8uWL9VgDNjfaINwNeWMHzH6oZPQOfFtIhx/lFS4
         TC2MVnPtC9zrOaozHxD4eRJgDbDqmK9TYeZMRqIg1BfPjnFwYrcHsp3ipLIiGNju+ZE1
         lXxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ai3g7nGL;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NRNteOyn0HxMMDLZVTSk/gVZyW/2+uPG78loRLaPfoU=;
        b=eXhBdEOafA71NE4yIB3b9qcCnEQwCuLgfC/TZidH0jefewppBdJLyb43LCjk5/Ehc3
         e1lnsAaoAfMWH+mBPjzbNeNUPONMl9QJjifrC90GjjuaUoW8iLFnU40WEO3mPKHD1Jcz
         If7D8qC7A+eZ60MOc0kzSFmujRv2ZbkYH4mtbzZcirqeFKlVil6AJrLvg9o+eab4CujC
         gpIvHhG0BULonWK5X5FORUTEGbXjJaP3xF6FgXLADmimQqe+CNJPP/PNQh6lDIGyt1HR
         VcAYSRK5ABkSNs5N5P6BEgl8dkhnnb6cO1tv457GH/vwcjAtjqElrbMOdQwutMnVcViw
         AuGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NRNteOyn0HxMMDLZVTSk/gVZyW/2+uPG78loRLaPfoU=;
        b=MXp4xPFIL+5rsZoJOJefrwI7+d0jRk4zw7YlJBlhlnBwIWBagnN8BIf65rXwd1LgKx
         siuvOqQ1V5l5faOkcpdWUwdQnT2BLdOkzCzeQlfo249yb0EstrgBfNaST4vSr/yNcDtn
         k6ZzlmUOu6C18rUi0pAjIekXqsE1q/NxOIJZIqFzTMGBeK9ZvJyFHguziH0bEKDyZR5g
         QGRa1sCavfFaAhcBbE4+b+nTISPwIALjmtCFUXKrS45t+kTIMGv+CNnF02CrmjjtAJk2
         UzkDj4pePDpnyNYe8uHI1NwfmIqztLWWibS6kXw9toXt6l//CkhUdlERDcyPqzYmqnE3
         lb0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FN32QSvBrEczkB1nF31U6rGc26gz04GMgsA1bXkLdHKcP/z27
	dlGSh6ukdGSiSzYzcNayl2Q=
X-Google-Smtp-Source: ABdhPJymPZ6sFozj81RqV87XbT2/GYxJ5PL7B2+A8d31owLE7ORljLS9iKsswEoO6GHUja1ot2MVeA==
X-Received: by 2002:a92:c794:: with SMTP id c20mr4238335ilk.288.1622145303754;
        Thu, 27 May 2021 12:55:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:dc8:: with SMTP id m8ls622638jaj.3.gmail; Thu, 27
 May 2021 12:55:03 -0700 (PDT)
X-Received: by 2002:a02:a409:: with SMTP id c9mr4986041jal.43.1622145303352;
        Thu, 27 May 2021 12:55:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622145303; cv=none;
        d=google.com; s=arc-20160816;
        b=etfU5uxm3DYPJwQZ8MaedSsEV2ALKY8AVx8b7ZJVx2xKz+IUDH+pC2JMvjao7yfDXx
         3LwH3npUjOov23mx3XrsP2SQEjLa/mpL7t4xtNOtMYLC2cLoaZ1X/ILnKjkie4WoEtMA
         Flr+xfYzPhSxE0zdCqXFrTRk1CQJdNyqHNTzU/hOf11Og+0RW31z+GYw8iqzJP2As7aJ
         veZasF339gl1DUVB2zk7YrUgcIy+yScW0/GepuT8zNaunY+T78WSdcj95NmFf44+ln6C
         DjBH9d5cvC2KNEbulbR91L5PIEEWerfTzPVSGp9fiVpzHa/kcIpPoImYODEGGObOQpuw
         EN0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=SIGMVnTBIspCPVoYI6kntLfi6ga7bBpq4sXkRqi5sY4=;
        b=ND2AciakNBBsn+XGZ5wEvktITXNn5l3kLHudY8Uyiv8ZdV8tSO1FEOSX9Gzzk1BpSD
         MISNUNRnB06aJO66+cvVnSo7RPjHBx9mcZ4UrElwnGZkYw4MausRiLL+hBwCGBBuNUS2
         ksBQhk6dtFRYM1tYXM/31YX87PjEkYKCY92ORj3YuIf+qlE81n/DTAcRjvbP5We8yGJ9
         QdZI87NUafKWnyz7GSbt6048eHFBvj5k5s2uD2C/RGFiVYKUW4fhyTyxGv/DLuWZZuq5
         AE7S7hZvYWpNBN1ssR5vmtPVmETemctlUaFYM7KgN27eUkkQuvOM7ikhXMuhZMdw7Iqm
         yH7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ai3g7nGL;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x13si347007ilg.2.2021.05.27.12.55.03
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 May 2021 12:55:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 29C6D613BF;
	Thu, 27 May 2021 19:55:01 +0000 (UTC)
Subject: Re: [PATCH v3] kcov: add __no_sanitize_coverage to fix noinstr for
 all architectures
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, ndesaulniers@google.com, ojeda@kernel.org,
 keescook@chromium.org, peterz@infradead.org, will@kernel.org,
 nivedita@alum.mit.edu, luc.vanoostenryck@gmail.com, masahiroy@kernel.org,
 samitolvanen@google.com, arnd@arndb.de, clang-built-linux@googlegroups.com,
 Dmitry Vyukov <dvyukov@google.com>, Mark Rutland <mark.rutland@arm.com>,
 kasan-dev@googlegroups.com
References: <20210527194448.3470080-1-elver@google.com>
From: Nathan Chancellor <nathan@kernel.org>
Message-ID: <be3971b1-cf26-36c7-0f9c-d79c656ec855@kernel.org>
Date: Thu, 27 May 2021 12:55:00 -0700
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.2
MIME-Version: 1.0
In-Reply-To: <20210527194448.3470080-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ai3g7nGL;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On 5/27/2021 12:44 PM, Marco Elver wrote:
> Until now no compiler supported an attribute to disable coverage
> instrumentation as used by KCOV.
> 
> To work around this limitation on x86, noinstr functions have their
> coverage instrumentation turned into nops by objtool. However, this
> solution doesn't scale automatically to other architectures, such as
> arm64, which are migrating to use the generic entry code.
> 
> Clang [1] and GCC [2] have added support for the attribute recently.
> [1] https://github.com/llvm/llvm-project/commit/280333021e9550d80f5c1152a34e33e81df1e178
> [2] https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
> The changes will appear in Clang 13 and GCC 12.
> 
> Add __no_sanitize_coverage for both compilers, and add it to noinstr.
> 
> Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
> if the feature is enabled, and therefore we do not require an additional
> defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is
> always true) to avoid adding redundant attributes to functions if KCOV
> is off. That being said, compilers that support the attribute will not
> generate errors/warnings if the attribute is redundantly used; however,
> where possible let's avoid it as it reduces preprocessed code size and
> associated compile-time overheads.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Miguel Ojeda <ojeda@kernel.org>

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

> ---
> v3:
> * Add comment explaining __has_feature() in Clang.
> * Add Miguel's Reviewed-by.
> 
> v2:
> * Implement __has_feature(coverage_sanitizer) in Clang
>    (https://reviews.llvm.org/D103159) and use instead of version check.
> * Add Peter's Ack.
> ---
>   include/linux/compiler-clang.h | 17 +++++++++++++++++
>   include/linux/compiler-gcc.h   |  6 ++++++
>   include/linux/compiler_types.h |  2 +-
>   3 files changed, 24 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> index adbe76b203e2..49b0ac8b6fd3 100644
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -13,6 +13,12 @@
>   /* all clang versions usable with the kernel support KASAN ABI version 5 */
>   #define KASAN_ABI_VERSION 5
>   
> +/*
> + * Note: Checking __has_feature(*_sanitizer) is only true if the feature is
> + * enabled. Therefore it is not required to additionally check defined(CONFIG_*)
> + * to avoid adding redundant attributes in other configurations.
> + */
> +
>   #if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
>   /* Emulate GCC's __SANITIZE_ADDRESS__ flag */
>   #define __SANITIZE_ADDRESS__
> @@ -45,6 +51,17 @@
>   #define __no_sanitize_undefined
>   #endif
>   
> +/*
> + * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
> + * with no_sanitize("coverage"). Prior versions of Clang support coverage
> + * instrumentation, but cannot be queried for support by the preprocessor.
> + */
> +#if __has_feature(coverage_sanitizer)
> +#define __no_sanitize_coverage __attribute__((no_sanitize("coverage")))
> +#else
> +#define __no_sanitize_coverage
> +#endif
> +
>   /*
>    * Not all versions of clang implement the type-generic versions
>    * of the builtin overflow checkers. Fortunately, clang implements
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index 5d97ef738a57..cb9217fc60af 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -122,6 +122,12 @@
>   #define __no_sanitize_undefined
>   #endif
>   
> +#if defined(CONFIG_KCOV) && __has_attribute(__no_sanitize_coverage__)
> +#define __no_sanitize_coverage __attribute__((no_sanitize_coverage))
> +#else
> +#define __no_sanitize_coverage
> +#endif
> +
>   #if GCC_VERSION >= 50100
>   #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
>   #endif
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index d29bda7f6ebd..cc2bee7f0977 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -210,7 +210,7 @@ struct ftrace_likely_data {
>   /* Section for code which can't be instrumented at all */
>   #define noinstr								\
>   	noinline notrace __attribute((__section__(".noinstr.text")))	\
> -	__no_kcsan __no_sanitize_address
> +	__no_kcsan __no_sanitize_address __no_sanitize_coverage
>   
>   #endif /* __KERNEL__ */
>   
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be3971b1-cf26-36c7-0f9c-d79c656ec855%40kernel.org.
