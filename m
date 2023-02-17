Return-Path: <kasan-dev+bncBDW2JDUY5AORBUHZXWPQMGQELIEMA7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 330CB69AC2D
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 14:10:42 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id h4-20020ac81384000000b003bd01832685sf620797qtj.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 05:10:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676639441; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y0m9JzjW5wjF821ZosUhdarrn6zs+D4JpqUFFdoyayCRFd+Q5R3zYQp6aZX6oal+11
         vWVhhXnKA8ccUH9gPfkYvpDlyBpp8z5vGct2KLzWA3we1YJS74xUHiM1LBSBk9QHZpWC
         qf9/Hn2xsdKUZbq8hkFr4Yeza3ntLneZO58MS6fusQ112JVbXVJFGuJI4rfKaFmpRkQ+
         Vo6zfNmQL2j8gPq3UIlEUIjE05YYIiLh8FxGe8rmxPcZCTKrhp/mQDE648Ry1FId20Dz
         RcAV9LkT+O8AiMkfoJkjNNM9YSHkYxQS3N4hu/al4vwMT6yD8TatXhU6lgMP7tJQSJmw
         JHcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=pKHIKJ+ArPi7+mgUoW+WWRjTjnEplDSz7Pnr7KNfOzg=;
        b=ELrXtaVciBoiSVbARgV0mgipIUNkDlo5DEN7P5hmTbHlZUAq+EAwuIPv8iih5zKue5
         98stAfxqKCHjbt6Bgi0HVNw2+yUn/zJNQv478dH8tom9gHsH0p0mwG/3uN7y5UWi8Gv3
         49xg1xZAl/6+KwsFeg+KBO61OC3Lx4ZXwSH5DfmxOIVkCE2OsKKLhFNnFI1opbHQGnoc
         GsxV48tbuE9FhuB64KjXDz+TtrLIgDqQ663FSgxl3SUAod1JMA6VUwmCw7x3N4BMcD8H
         h/AqOe5QJCtNr2nC8yeoRk99FgDZJR78VwnF3x8QRffRiZ8C2g7KTK7ckHO7H4qkkctu
         C4jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dC0eKp2B;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pKHIKJ+ArPi7+mgUoW+WWRjTjnEplDSz7Pnr7KNfOzg=;
        b=ho41JI33fdDTWj7uFDCALB11tcdu69GoLxOVj6ffWhVCe/ga4YfxvULkQll3iZ7Rjj
         7FN7AIOtFFMsFtdPubBGKCwl70GmhV7Psh5ecDFUxHxEgDcXRlSlYMMODhGjSr1tGjxu
         SUPRrrvEpHyyF4mcgVGhowpl8lxFKLYeXKYGLVLaYdXnmZPV9qTTYaUtw28EQBaQmDfP
         FyesK7fpE5QUYOi1uwe5ZV/JksiIQBxyM36IszypWMaGp8t9lpUUnT+X6XKTR2K+N9q1
         yjkHKlNiWgnmFfWHjoxTFbisqrd6GCjAc+m8KkqS5GIQLWtycSZsBIRNrMzvipUvqfom
         tUWg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=pKHIKJ+ArPi7+mgUoW+WWRjTjnEplDSz7Pnr7KNfOzg=;
        b=AO0zO6AN0D1CRKt1ZHTZ9Thbf4dojoww/nrXCVD9cJUHwf4WYLCXObbRaqnKKGXdUv
         FBSREAMGMPHb5ylFqo0PE79DZruOr2dRe2+9a23UQLEcIExJ6fLUCybfJKw5ck95w8Eu
         2vgfyGxN9MC/unOt1mXjvCUpoLK7v6sDG5xcKWZUVxHUT0jom3XqL4Ex73615sQ7PvNM
         fpTdj85U8OvrOMtzVnsvY54B2vM2WWC56CXQE52/TEMB7aZ/pK8ihc0aMSF0FEaz0EP4
         YzEy9OyphOX6pkpq46GvGqlRj+SXXJZIY33ljq4ktTkNX/yBMEdd0W9sl4vBWjC3bPTH
         9Sng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pKHIKJ+ArPi7+mgUoW+WWRjTjnEplDSz7Pnr7KNfOzg=;
        b=DOuBRCfLgXjXjHw/rGWKTf6FPbPvfSmyC+gKXSoqSS9KOirbmhNx6Ehk0s6+zy+de9
         2T8sY0x/mOV3sSDusF1ok5uc9GZWWruGp8G3JJUb3tAtXZSMuWwmuFwKYANw7yaPRaXC
         F60gr2E0XuFnLnPiS+3ANPEA09MyKdwWbjvv+j+oPk4hsmMgzBE5NI0kh31TtW+bObbR
         1hAOJeT4z4h5Jm2Bv4IbHx3uxpkHNPY1Uj2FSBo8fdBs7Own0/0hloboYtA/FqKduJp3
         +gS410zLD2i1+crTpWhbw51gi6fCK9c1V8rcLDZ5bxvfnJiGRYsGExN/hifefrXs5BFi
         JsPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXdOzlrJmOnoGkW4FgJPgMIguYQ8Eb6G+rVCqtKWmUOSNtv/R/J
	mwAxRK1bn08q3Qpeikm5+k0=
X-Google-Smtp-Source: AK7set8hBHjrArErHp/D32cP0ipViHv7bUJ0VSTB/nRURpFIQHc8eytbT4izoWrYxQBu8D/LJpRBSA==
X-Received: by 2002:a0c:8c4b:0:b0:554:de5b:b953 with SMTP id o11-20020a0c8c4b000000b00554de5bb953mr186248qvb.82.1676639441073;
        Fri, 17 Feb 2023 05:10:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:44b8:0:b0:3b9:a441:37ec with SMTP id a24-20020ac844b8000000b003b9a44137ecls977920qto.2.-pod-prod-gmail;
 Fri, 17 Feb 2023 05:10:40 -0800 (PST)
X-Received: by 2002:ac8:7d04:0:b0:3b9:bc8c:c209 with SMTP id g4-20020ac87d04000000b003b9bc8cc209mr10108344qtb.20.1676639440563;
        Fri, 17 Feb 2023 05:10:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676639440; cv=none;
        d=google.com; s=arc-20160816;
        b=i2ssqcRY3YnxDSpNJ+3F3vk7AKP5OYcHmfCTnvEZvOq28s7QuGJHyaA072S3fODFA9
         QaqBwDIct5XfnFss5f0xdjT72C+kYY3nREQf8TrsZHheszyF6Y34uC9+oSTRUgf+fb8V
         6ZB3ex0idMtpe0eRUJy64irj299DXYulHa/3Y1IhAnk+iaFGnKvfaIDB/oyh0eT7vXdC
         8nKvFA/F4X1NatvlUHWY3D9yA0n9us0Loq4rjUjw9XEfDRqtbpf2ZYhOptpWrqwt/Hzh
         mmFPYUlKMB+szOVp7t0QRM+p1ROoZr53Sxn43Or5YkHfGjFHoUXBlONDOtqWl8WGv6Xw
         JlJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sIFlAqUfSEj1u08jK3w+qv2YAspHGSL2922Yed+agrA=;
        b=ezYVGj/unBFisGR4sgJSNbBU1ZY3GuBl7BhAQmHohVf+Qs5W4ebJnC/j49pUSvNcvs
         3Ua75WBE8q6KwQ5WZMwhcKwnXSjQV/v8yufr1yOsXvpyqtUHqGN1pgatkM6EqlPHoC+C
         W/HJy3fVqs/lZ0QZc6Sz6R52hLT4We/JT/QeBkZf6qEZuuE4Y+uO768W7rjK54y9XQiq
         WGKIHXhWmGKdv62xt7tY4bvw7U0FLs4ThOC0r4vJ9ofuxv6U+Urk+3NREgZoj3PS0446
         +5i0IPlDYpYpkP94rtgo1R2fTftflnyzqPV3vKhtCzNiYz6NyqrJxs75SvMAknRE+w2d
         Aipg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dC0eKp2B;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id cd12-20020a05622a418c00b003bb820fca79si332244qtb.1.2023.02.17.05.10.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 05:10:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id o97-20020a17090a0a6a00b0023058bbd7b2so1193823pjo.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 05:10:40 -0800 (PST)
X-Received: by 2002:a17:90b:1f8f:b0:233:3c5a:b41b with SMTP id
 so15-20020a17090b1f8f00b002333c5ab41bmr1514654pjb.133.1676639439623; Fri, 17
 Feb 2023 05:10:39 -0800 (PST)
MIME-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com> <Y+94tm7xoeTGqPgs@elver.google.com>
In-Reply-To: <Y+94tm7xoeTGqPgs@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 14:10:28 +0100
Message-ID: <CA+fCnZd+BQo=+YzhJ4DXz6EK_M9UnGVRi8X1h3tV8cXXYS=T8A@mail.gmail.com>
Subject: Re: [PATCH -tip v4 4/4] kasan, x86: Don't rename memintrinsics in
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
 header.i=@gmail.com header.s=20210112 header.b=dC0eKp2B;       spf=pass
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

On Fri, Feb 17, 2023 at 1:53 PM Marco Elver <elver@google.com> wrote:
>
> Now that memcpy/memset/memmove are no longer overridden by KASAN, we can
> just use the normal symbol names in uninstrumented files.
>
> Drop the preprocessor redefinitions.
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v4:
> * New patch.
> ---
>  arch/x86/include/asm/string_64.h | 19 -------------------
>  1 file changed, 19 deletions(-)
>
> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
> index 888731ccf1f6..c1e14cee0722 100644
> --- a/arch/x86/include/asm/string_64.h
> +++ b/arch/x86/include/asm/string_64.h
> @@ -85,25 +85,6 @@ char *strcpy(char *dest, const char *src);
>  char *strcat(char *dest, const char *src);
>  int strcmp(const char *cs, const char *ct);
>
> -#if (defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__))
> -/*
> - * For files that not instrumented (e.g. mm/slub.c) we
> - * should use not instrumented version of mem* functions.
> - */
> -
> -#undef memcpy
> -#define memcpy(dst, src, len) __memcpy(dst, src, len)
> -#undef memmove
> -#define memmove(dst, src, len) __memmove(dst, src, len)
> -#undef memset
> -#define memset(s, c, n) __memset(s, c, n)
> -
> -#ifndef __NO_FORTIFY
> -#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> -#endif
> -
> -#endif
> -
>  #ifdef CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE
>  #define __HAVE_ARCH_MEMCPY_FLUSHCACHE 1
>  void __memcpy_flushcache(void *dst, const void *src, size_t cnt);
> --
> 2.39.2.637.g21b0678d19-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd%2BBQo%3D%2BYzhJ4DXz6EK_M9UnGVRi8X1h3tV8cXXYS%3DT8A%40mail.gmail.com.
