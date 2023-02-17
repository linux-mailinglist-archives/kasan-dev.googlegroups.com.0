Return-Path: <kasan-dev+bncBDW2JDUY5AORB5F7XWPQMGQETBZFJ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E1FA69A9BC
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 12:07:34 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id x127-20020a633185000000b004fac0fa0f9esf289495pgx.19
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 03:07:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676632052; cv=pass;
        d=google.com; s=arc-20160816;
        b=YCff1gAu/KU/WGX/Fp1/qphLEIs5rFz2/j47M1c4mFpvikABXq9lVNkJelTOVRtLWF
         0Rr7qQch6aUxYECzN+N7RyyTRvU/gKavixi6jmqx0b6YHJi1GT47PqmKQEE17Q3uC8Hb
         y7RIEqYTsIYAS8f1oagTEmu4x6FP0dGiChEbMa21+oRB2wD/fbx2XhMg0AibGOBv0++b
         O2PZELb7XprHIhc8kjuAvJ+i2cvojQ38TFqpezX4bJLgf+2S0CBq0rQxZITQ/RMbzRvt
         DfFhPJfVPixk2VUUnGKE9yg4DdYgMpTuo7FcJ61JNE5oYuhhAGjG/dUPiMKrmWpTjC+g
         GJJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/C1/qgoAa38AtbFKqf4OnVDSmtoekvgtTm+shHfxs7g=;
        b=LST+1QjnKZEm1JHINDj8TEli28HYcVrrat7bVoyrOLoXHBVUxidP5Hwq2eEDfJkvp6
         id12xHmbRMg1gqqdtCJWoIZyNDNZZtsCUSkkHdWeqLzwh9ef3Kg4FAQ/gk8xWDBkjf2R
         Kdq4QvtFVfkcs27jq+1nYCI7Ah6k5Z2nSZ+vSVvNRfL1jAcE8g9wiJm8uyKzm0sr8Ppb
         6116swwgxxwqkM+BR+nUMwLfGuUFvLSKjcMKcyqS+zQ+kasec9f0L3KcyEZGze3ID/YQ
         R7jfY2XTWeeSi0s67e2DOzZdcIjS5D4R+hrFj2i8Tv/W39Ohv+a4+p9D9BA1mHLAc/1C
         2pVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EnMJ6h80;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/C1/qgoAa38AtbFKqf4OnVDSmtoekvgtTm+shHfxs7g=;
        b=nenu3z1EAP1RWGV1eFYseqDI6jKXcVZW3l8HgZJTnRzMxzu8dzGhCk4w+6PzjECMk3
         mUKddBe9VyFD2BAuOf8m0ssWQWOvnn5/96BH5ISpkNFM3l7qaC8jaMs4xkBuygv6jhY2
         YConhhLpzcAzumZSlplUlzrcfHitk+LSlfUTlfx1Q1KTd3EsB+p4riA+3ZcqHEpMYhxh
         oHmXw+YuqbP2QGAOjO1BG54egAmtR2z4UUlV1kAO3vw5ssdtrOe04pbq7hK+XVsCpuXQ
         7r+A63JBb7egDEDm2PL96VkcYHiXQIfGFPEoX9ozCV8Sdp4UZog0ftNpkKWA/SJ6766q
         tB3A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=/C1/qgoAa38AtbFKqf4OnVDSmtoekvgtTm+shHfxs7g=;
        b=LOM+1DdcpeT+3nfR8u1mEAWnw6Ix4sqb8HRPOprab9Jy2DjCzD13f1Bgmxi47YMce5
         vNGQPItAnqlV0UokI07YhyrNo5zl7Ayzn8PvXMlUP8JTw4nhboHgW1b0dyvBjGdWZ0or
         3+AUYVssklYHnYlQA3+5IRAAS3cZFKSc68m/p0tXFfjC11cE9jr/psOKzpDMWZMbvO8s
         gFMqoGpdDWGpcSEiSUw6+wjs1Vz6sngpFAFAj7oOE4NnHvpUeNNimW6bEM96ycWIKddo
         mEGUembKtprhzBi/ODXP1Se4OyIfBc1Ppn+biACM1Xd3yLoY1BfV78WBDUsSvPw6i4Zf
         Wqzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/C1/qgoAa38AtbFKqf4OnVDSmtoekvgtTm+shHfxs7g=;
        b=x00Q6zFk2irDoEJTYQOFd38fcnxTp2t/hIRgZUg0LhB0hU8gVYS8ocz+d8W2MfkWmx
         1fqaJ/+W+El3atHyiCiA8E6cEZeuJKi5MwiRpJa6kWRxOZFElYFT3Hxd6XCXPQ0ulLmH
         M7GYtVMwnbFv8xSyYx0a60pSR/CFD3XmugBigGY3tm6rqyfQCphQ6XgWVJNXwsGla3WV
         6aUdj+Eyn6KG/beKfcJWXh2ASeuTNQU0nnyVzrQN3K7kfdFnDPC/a5jWbBzwr+554Hu+
         uOQBzw6vwT3CQ8nRvjf8mHzB2/W5HrKJkRWpzXoSJnNOjbnO6Wus5b/P2dNUw4BzTyrs
         cOEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVm8zVHLQx4oXa7vtbt/fmNN3Zv93/DtZOVBOf+neNQjgKm1G78
	aA5agYsCcK04vpAPvt1CeTg=
X-Google-Smtp-Source: AK7set8At449ke9ZwxylUl8xaeuzblQTUmrnkijCdhkKwC5nOqFcFm3re9LKqPB81CCkIn7SXw9OZw==
X-Received: by 2002:a17:90b:4c46:b0:235:b712:4181 with SMTP id np6-20020a17090b4c4600b00235b7124181mr591868pjb.10.1676632052695;
        Fri, 17 Feb 2023 03:07:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d311:b0:234:bff4:2e74 with SMTP id
 p17-20020a17090ad31100b00234bff42e74ls1087373pju.1.-pod-preprod-gmail; Fri,
 17 Feb 2023 03:07:32 -0800 (PST)
X-Received: by 2002:a05:6a21:9986:b0:c7:5d84:d6e0 with SMTP id ve6-20020a056a21998600b000c75d84d6e0mr3723494pzb.31.1676632051926;
        Fri, 17 Feb 2023 03:07:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676632051; cv=none;
        d=google.com; s=arc-20160816;
        b=Fuz49rn2Mp2LsZwPGLIMbfCQycslUGe1kVfGoUDoqsX0DuWg+OP1h56oGyQ5I+eb9T
         6UFXyWLhnsG10f0Wurvqo7DkRuTOf99GbXWMbjmS0w3RLyeOnwwu1lgY8oRXuDjvbzcu
         qlQkzeOQR7pV6lMkBCDMn8fT/QdkfL9d6qEVQhnSf7EAHBiMW+oZoRez/BxEO5Yc+/XZ
         7gm9bHc3H7PgaYyXb2DdBlN7wtsnnEg9fCe89pHhFGCux0I/eBIvQN19mByESUcc/8+P
         EBn1m/ZSUVDos89xiUWK78hCsbsG7vYFO8wlRH/k1OPvZAsQFZmRHnyC7naLW8lHPMoN
         vYuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/jA5JR6jmFA0atOq1lU4NeFnNlRF/LnXa1fUxjSCz8E=;
        b=gqFVptTf1YaQ6KKuX1SniSiQLTG0JGOJ3gNCKzl4axiI5Wo733myRzhrMzqb2Pusbi
         r9n90+a5GHVasgGBYOzZySPSRDDU6IMwO6Cw3vMGT6rtm+xwq4hrZAZWCpMelwcvu/Rq
         Tf5saGR52mdNNCynf6Qx567WRjl118KZaXKHQPS7zCfIGrh3HiDYABcYSQw/UmN2Fnm0
         HEe5MyTtDeqFddYGBbg5Dn6XpaP0tbsKhLNZPRXfbNEXobibKFRJv/9CW9izCKP+LsTm
         cIM2zvcmoRcaxvoHnJsVuxrf0RCPhUUJYtYspe5elO36Mg+OE0xE1xAPJh0x/S6ePRP+
         l2DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EnMJ6h80;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id p16-20020a056a000b5000b005a9c5460f25si154720pfo.4.2023.02.17.03.07.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 03:07:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id ev7-20020a17090aeac700b002341621377cso773975pjb.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 03:07:31 -0800 (PST)
X-Received: by 2002:a17:90b:1f8f:b0:233:3c5a:b41b with SMTP id
 so15-20020a17090b1f8f00b002333c5ab41bmr1428932pjb.133.1676632051210; Fri, 17
 Feb 2023 03:07:31 -0800 (PST)
MIME-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com> <20230216234522.3757369-2-elver@google.com>
In-Reply-To: <20230216234522.3757369-2-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 12:07:20 +0100
Message-ID: <CA+fCnZehvF1o4rQJah=SXaS-AXWs--h2CDaUca-hJK=ZTD8kTg@mail.gmail.com>
Subject: Re: [PATCH -tip v4 2/3] kasan: Treat meminstrinsic as builtins in
 uninstrumented files
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=EnMJ6h80;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a
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

On Fri, Feb 17, 2023 at 12:45 AM Marco Elver <elver@google.com> wrote:
>
> Where the compiler instruments meminstrinsics by generating calls to
> __asan/__hwasan_ prefixed functions, let the compiler consider
> memintrinsics as builtin again.
>
> To do so, never override memset/memmove/memcpy if the compiler does the
> correct instrumentation - even on !GENERIC_ENTRY architectures.
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v4:
> * New patch.
> ---
>  lib/Kconfig.kasan      | 9 +++++++++
>  mm/kasan/shadow.c      | 5 ++++-
>  scripts/Makefile.kasan | 9 +++++++++
>  3 files changed, 22 insertions(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index be6ee6020290..fdca89c05745 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -49,6 +49,15 @@ menuconfig KASAN
>
>  if KASAN
>
> +config CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> +       def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=kernel-address -mllvm -asan-kernel-mem-intrinsic-prefix=1)) || \
> +                (CC_IS_GCC && $(cc-option,-fsanitize=kernel-address --param asan-kernel-mem-intrinsic-prefix=1))
> +       # Don't define it if we don't need it: compilation of the test uses
> +       # this variable to decide how the compiler should treat builtins.
> +       depends on !KASAN_HW_TAGS
> +       help
> +         The compiler is able to prefix memintrinsics with __asan or __hwasan.
> +
>  choice
>         prompt "KASAN mode"
>         default KASAN_GENERIC
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index f8a47cb299cb..43b6a59c8b54 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -38,11 +38,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
>  }
>  EXPORT_SYMBOL(__kasan_check_write);
>
> -#ifndef CONFIG_GENERIC_ENTRY
> +#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && !defined(CONFIG_GENERIC_ENTRY)
>  /*
>   * CONFIG_GENERIC_ENTRY relies on compiler emitted mem*() calls to not be
>   * instrumented. KASAN enabled toolchains should emit __asan_mem*() functions
>   * for the sites they want to instrument.
> + *
> + * If we have a compiler that can instrument meminstrinsics, never override
> + * these, so that non-instrumented files can safely consider them as builtins.
>   */
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index fa9f836f8039..c186110ffa20 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -1,5 +1,14 @@
>  # SPDX-License-Identifier: GPL-2.0
> +
> +ifdef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> +# Safe for compiler to generate meminstrinsic calls in uninstrumented files.
> +CFLAGS_KASAN_NOSANITIZE :=
> +else
> +# Don't let compiler generate memintrinsic calls in uninstrumented files
> +# because they are instrumented.
>  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> +endif
> +
>  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
>
>  cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
> --
> 2.39.2.637.g21b0678d19-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Is it also safe to remove custom mem* definitions from
arch/x86/include/asm/string_64.h now?

https://elixir.bootlin.com/linux/v6.2-rc8/source/arch/x86/include/asm/string_64.h#L88

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZehvF1o4rQJah%3DSXaS-AXWs--h2CDaUca-hJK%3DZTD8kTg%40mail.gmail.com.
