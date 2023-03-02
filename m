Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7MJQKQAMGQEHWGBWXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 73B1A6A80E2
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 12:14:07 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id l7-20020a0566022dc700b0074cc9aba965sf9880294iow.11
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 03:14:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677755646; cv=pass;
        d=google.com; s=arc-20160816;
        b=RLQFYeMj5O4s+9myA9lC//tYUUQdkGZ+aDSYnTXSq4fhvJz78pBnOQ5UY9K17YOfDJ
         4bh9PvWktq/R/W1N7mQ+w8s1MFQQ0SicUHlvgVco6RA8gMMEJUbq2Q/JVVZBTRMCuOez
         sk9qsWoocWrLLrMRwtXOCD+OiB9yYAIa2YEBzemnHRHUFTrOBirtEQksYW94a7VxbDqt
         BzCraB8UExafnDSRN5cx4jBv9tyFUDj5XgtzqfYektjQrffIcL1ZRezVg0gM/Pa5XBqq
         xGG0F+bXT/ycjEIHpfd/QEdURHkX5Z4UjrUPhnc+eQVolflsJcXjKLm8k1CNU9IDm1sh
         OI4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Yl8mrbDJIoLyTqlMZH8nAouk4GvVJnSbtuVtiCUZep8=;
        b=g8o7iSPXXnhXz+VZGYi9XN1FlLqEl0+Se/2YqW2NLnnzgy4qgeG6qb68rMM4Ki3SB4
         4KHSHChvQZfEpz/Uvt2PhKccExHyfw2CPx0Fjy7McGOH1QDCRXpGrh9oiThkHzae5bsT
         ZQRSszvPbk+FvpgX2/tzsyodI/qFCNYyCzaVXziS9Q9llDS2F9Di4+zqH1fpk9ZvHFgF
         ifhHCZEHhfK44IjAuUT5+6dKvrvQVPyGV+/CzraQuw464cLLevEu6K3aSPo9NMxj71St
         9xCyaA+ZLS66kxL3RS7FqH3gMg94LL053og2YWO0B3LKdD6JpoqywiUDgalBbSz5nGO9
         9VRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BGi2q0M3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yl8mrbDJIoLyTqlMZH8nAouk4GvVJnSbtuVtiCUZep8=;
        b=MzJ/sKUdDxGSW9eL63MxnSGcvWTU4WMmJlbEPFv/FBGUOl/6fS+IQYclfOTjd90H9V
         sBYrMeORGDcf2Vx60CP8/FmJpaDGTIo6GlRrdohJSWXQzuGVYO0y0M8zHa6zmWIh5oj3
         xwX78BafQ8IwURlF/9MziOvLLRnsJ6Ia5wZ5ioUOuIo68LmSAxybrWwytwDSwjU/SKPw
         6QcUg4pEWdYImWXHG7Aeq0nc40HT2ZmwskePaQshDihNtSRP8QK3MFlXSzX3WkiPQdTg
         /xtzHEPAtP0RWXKeW3q+HctdIJT7sJVK5Zf6QtOPbKvhdzNQ9PA54ycz0BhMC1OEhm/8
         QLRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Yl8mrbDJIoLyTqlMZH8nAouk4GvVJnSbtuVtiCUZep8=;
        b=7cSiS5roQdAdOy9xegUvN4FMtAZaJVfQjw2xomxEfTdxFWwcRIaxZQcBmGoG0b8S5V
         YwsG0dZykRxQSXoZBtnBctaaHLa9dDjJcUOGkbr75OnsTb0G1GxTJSipn/G8Mx1aGnfO
         AaiuKYPsHE+BeSrljoCSZ4nNi22AnzC4Xb+gY9/taxX0O0S6FFuWEt/D2t6DpuA15m91
         5ycv1Zh4omb75n31pIGrf3REkkMCm24XazIC74yLWIyhMTiAeGBxJa2ND2aGGo9NuigK
         /HXLIz38t1I90+KP+7vy4EwLrsgCZuQbBlPH0WsfIsgMz+l3QugGh2w4P0UIp53+K0Zt
         BIeg==
X-Gm-Message-State: AO0yUKX1PVks1KdTndW6ff5bqcSt+GkVmNWEwwZt585egeI/Q2HfxJrU
	ENUJ79flDy0Yjt/pRyV0jVg=
X-Google-Smtp-Source: AK7set9yd5kWLsMoHxorUJEMgD8febOPLx5LNzqUwAFCV1QY93gPqCjTdSe6tfG9JftA6ohHMwOhbQ==
X-Received: by 2002:a5d:840d:0:b0:745:a41c:7c97 with SMTP id i13-20020a5d840d000000b00745a41c7c97mr4258590ion.3.1677755646035;
        Thu, 02 Mar 2023 03:14:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b492:0:b0:74d:364:dfd7 with SMTP id d140-20020a6bb492000000b0074d0364dfd7ls2319212iof.10.-pod-prod-gmail;
 Thu, 02 Mar 2023 03:14:05 -0800 (PST)
X-Received: by 2002:a6b:db14:0:b0:74c:aa8f:1f4c with SMTP id t20-20020a6bdb14000000b0074caa8f1f4cmr1262447ioc.8.1677755645465;
        Thu, 02 Mar 2023 03:14:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677755645; cv=none;
        d=google.com; s=arc-20160816;
        b=KkLYERYVm/pUgeHScPDxvUkwxanOfvG2NZgEleax/L0OpI7dyi9nc4i/w4WpVXZb6+
         kmJ1/iVhAkoASvPmPw6qmPWrZ+qwWsrc3UXuJEz/UZ/dag95ySuNuyiElYMnwhXqBCoN
         se+DQU2ZYhLD3DY8KeI3HYVgPNg3Z5t1T+RXHUtIMFWDdATEMpYy/pwmnY2b5IfrGDmn
         8qXjOw1MWSsUNBLvrjmIOqf1MZnXGswukldFKzLY6T3dnQtUxPEhSZWWmPcy5AmSY04+
         CiGgDbQmhB5XGBHM9gczCXcFTVUVv5sS9SYbGSqdwC0my6oWi1nZdLoqiB0xT8/51nBq
         q67A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zAvzWwN+/2QX88rMyJtxLyzDNIZ57vJV9SRYMAd7t2o=;
        b=X28LuE9NpeLf+GolUfH1qe2aN6/HR9vgfOj6ovD5w/1ZODKiO5xOjVmM9s2T8nfGx1
         S0qFfP5GaTiGuA8j7+y7V6jBgkg2kz4DQ3/6RwUIGLGUSSiUAbhNmrNW5xx76kTyAVYW
         nGCMWtpSoRiBGn/QevigFnEO+joXYQ9UXNjJvkylYkL2L7ooOLAfgQRxNRS4XlnbM6pW
         nt561/vqFv7V85EONz6HokF9alk1q/Rny/9q6wY72L9TMpPIBRgAi9PyPtZut50iTELq
         w9urAkEYiHWrliT5FBS0Ed50aeG5pBNkv/zfSaplsg2UbFX4VjOIgwFf9kSWacvXu4kp
         LTDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BGi2q0M3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe36.google.com (mail-vs1-xe36.google.com. [2607:f8b0:4864:20::e36])
        by gmr-mx.google.com with ESMTPS id k9-20020a056e0205a900b003179767c2b2si249186ils.0.2023.03.02.03.14.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 03:14:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) client-ip=2607:f8b0:4864:20::e36;
Received: by mail-vs1-xe36.google.com with SMTP id d7so22106375vsj.2
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 03:14:05 -0800 (PST)
X-Received: by 2002:a67:f311:0:b0:402:9b84:1be2 with SMTP id
 p17-20020a67f311000000b004029b841be2mr6391648vsf.4.1677755644783; Thu, 02 Mar
 2023 03:14:04 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com>
In-Reply-To: <20230301143933.2374658-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 12:13:28 +0100
Message-ID: <CANpmjNMR5ExTdo+EiLs=_b0M=SpN_gKAZTbSZmyfWFpBh4kN-w@mail.gmail.com>
Subject: Re: [PATCH 1/4] x86: kmsan: Don't rename memintrinsics in
 uninstrumented files
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BGi2q0M3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as
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

On Wed, 1 Mar 2023 at 15:39, Alexander Potapenko <glider@google.com> wrote:
>
> KMSAN should be overriding calls to memset/memcpy/memmove and their

You mean that the compiler will override calls?
All supported compilers that have fsanitize=kernel-memory replace
memintrinsics with __msan_mem*() calls, right?

> __builtin_ versions in instrumented files, so there is no need to
> override them. In non-instrumented versions we are now required to
> leave memset() and friends intact, so we cannot replace them with
> __msan_XXX() functions.
>
> Cc: Kees Cook <keescook@chromium.org>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Other than that,

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  arch/x86/include/asm/string_64.h | 17 -----------------
>  1 file changed, 17 deletions(-)
>
> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
> index 888731ccf1f67..9be401d971a99 100644
> --- a/arch/x86/include/asm/string_64.h
> +++ b/arch/x86/include/asm/string_64.h
> @@ -15,22 +15,11 @@
>  #endif
>
>  #define __HAVE_ARCH_MEMCPY 1
> -#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> -#undef memcpy
> -#define memcpy __msan_memcpy
> -#else
>  extern void *memcpy(void *to, const void *from, size_t len);
> -#endif
>  extern void *__memcpy(void *to, const void *from, size_t len);
>
>  #define __HAVE_ARCH_MEMSET
> -#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> -extern void *__msan_memset(void *s, int c, size_t n);
> -#undef memset
> -#define memset __msan_memset
> -#else
>  void *memset(void *s, int c, size_t n);
> -#endif
>  void *__memset(void *s, int c, size_t n);
>
>  #define __HAVE_ARCH_MEMSET16
> @@ -70,13 +59,7 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
>  }
>
>  #define __HAVE_ARCH_MEMMOVE
> -#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> -#undef memmove
> -void *__msan_memmove(void *dest, const void *src, size_t len);
> -#define memmove __msan_memmove
> -#else
>  void *memmove(void *dest, const void *src, size_t count);
> -#endif
>  void *__memmove(void *dest, const void *src, size_t count);
>
>  int memcmp(const void *cs, const void *ct, size_t count);
> --
> 2.39.2.722.g9855ee24e9-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMR5ExTdo%2BEiLs%3D_b0M%3DSpN_gKAZTbSZmyfWFpBh4kN-w%40mail.gmail.com.
