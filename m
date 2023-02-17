Return-Path: <kasan-dev+bncBDW2JDUY5AORB357XWPQMGQEV3FMZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id E10C369A9BA
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 12:07:28 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id p25-20020a0561020e5900b003eb2e441471sf1502699vst.13
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 03:07:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676632047; cv=pass;
        d=google.com; s=arc-20160816;
        b=grRT37hNh7Ns7yQPlKrhPVPxaxA0cOt+EQAyto3O1BkkeqmhJpqLpsWD99Mt+CGPb4
         YrmZ2l2cHJPffWE+oT7LnJMtSdqIOo/pYotZ1cTWUUmdbGKU0r1WUz/2cnMMzY79LhQD
         tk/X7MDl7B7scQDb3ORKMaJWzwvZgyAlrUEZrPtmMInX8QSXIJHnrJswHugOox3kisYs
         bpjJFj8l9Ib2nd3iNbBYIlJWBecZxxFcwnV8fEmT0akiqUIWOH55ock1sN7/r11PGUFW
         vKwAXXak4afpR2fjdlAKBNDHDch15RgZwAXGhTIZbya52XSVSuU2QCSEFqEHAnZrK0c4
         5FFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=K08Duj41S0gQV1ZXTC2D2C4r4ktXRSncra762B4tACk=;
        b=gwel7UPHIXpk9TzmX1joatVNgsR8y1kdp46ztoP+elTB9KuoJUUjbTnms5VW17Z89+
         wWpwWYkGwIJprm94OAUzS+Z2c/cwkgCiGFvvwtyE4zbUUgnbCzOFUq9L/8g8Tajy1SZk
         3j7p+Gaf3iMe/c17MbxknyMKbb6Ps60X6vNpw0zmde8KvBRlyi1EK68PeGxeK9tpBptZ
         7aKr337+y5XCBN7QnxZpChbsdet0zJlPuk67FixZfk2XjI7aXoRez25Mb+Me7ACIQzke
         Dh51VjYoxjc7WpweZ+XuhVjka/nGAs1OAxDHHzoBay2+HkwpNNfKvMW7YmdWmQxsO+ly
         7tYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qZoB6rRn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676632047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K08Duj41S0gQV1ZXTC2D2C4r4ktXRSncra762B4tACk=;
        b=GMtJhyrP80ZaGAB3CT9Ma1cGwBnrpKd1s1ili1CmTJ690lMbRq+xbNObgy2enBcdY7
         GClAYmXFHp0Kt/hiernKhlJsoelKMXpe4EztaQAQZ/lsD2iDdowagPBjfr2ziGw7xB39
         AQb9ybwoXV6SQrYHxTQzL/PLCcix3Z0nLaXOEPSspRd8q1NJa4231DpXsSFzITl5RV3l
         OPCbBl5ei5QpPGvhhWbqCmxlZfOFafjlCqreu3MxyA/yaQfHj5pfBoD41/oXmpCmdFnA
         9Jh4LPGCiX8Ijd2mO2Gl61qO1eHcJMPan2XBXb6wAtlpoclGrZ6dZjKHeTnLXRsmW8kB
         m4VQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1676632047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=K08Duj41S0gQV1ZXTC2D2C4r4ktXRSncra762B4tACk=;
        b=ndYFxrgEFj3jbe5afraoE00n61mSHrTJHRqwOHqnkf/1TAtXpjXrIkOYUcAj+Supur
         1b1rP4B4QHSrCWMmPntbU/y2g4Q3Ze4ErZW8iCD6r5LeoHwLgNqevoG3yI4wtOJwAw/Z
         Lvm7HI6tFsP8/yH1LzVUYLQx9t5k4b+GhvBNxO7U+fL7AtM+QnmlYqaPOywgYfI6NBwR
         KrRRXE0M06dC2dpAo6kAt8sifs9V4SSQk0aB+GutVyfny7ngcWapQ87VqwpKovyC0G+4
         ptruahgvg/UzIkjk3EnWbl0tlQ2yJwtPCowg4IOKdgJ5uhahVymc5ar1L+5XX38IxAmS
         EUrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676632047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K08Duj41S0gQV1ZXTC2D2C4r4ktXRSncra762B4tACk=;
        b=EBELh+Ho1B/J4sxCBEDBOAb7wVayQ32ImHrlioCptbfDnANAJJUxSkdS3fvBGUVFcB
         jDfyhWmDWRcaeM9GMRQUS9dKxlnSZz8QCes/raYp9AJhQJOuOeSkgGuqkwijSCI7lM8C
         iyleT/HbS+9pslGUmmcTBk+oN+vz3tPctDDAhf5CQO3tNd9cUcOJe/2BROspMw88NSlN
         wTvFGSJwmBb+etj6YNBzdM49CVT98jfYHzKWlZQdrOTxsj70Zq7snNV95fp7I32Zg3S3
         s2WQtPEUTlLeWHiOGJdmM/cFumQuJv4IQk8xLn1rUftxeDReLq5S6Ob7zDr83PTMw4wp
         B/Qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUlQ4J6mJUQZKxxk0Mx5giQng7NUVOmS+AbwI8ZzIXQg6ktBB3q
	nJ1h9GLcg1g1m/uYOBTngVw=
X-Google-Smtp-Source: AK7set8ugSTWPcK6ltYp8b2gQUiPuj1oBfFJ8lZJDwG0MvcQf/FjgsjhHhbAxb/jWGc+C3ytmUCdNQ==
X-Received: by 2002:a1f:2104:0:b0:3ea:4764:c895 with SMTP id h4-20020a1f2104000000b003ea4764c895mr60882vkh.25.1676632047632;
        Fri, 17 Feb 2023 03:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c7b5:0:b0:3fd:2bb5:712c with SMTP id d21-20020ac5c7b5000000b003fd2bb5712cls190805vkn.11.-pod-prod-gmail;
 Fri, 17 Feb 2023 03:07:27 -0800 (PST)
X-Received: by 2002:a1f:1883:0:b0:400:abee:332c with SMTP id 125-20020a1f1883000000b00400abee332cmr451017vky.15.1676632047003;
        Fri, 17 Feb 2023 03:07:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676632046; cv=none;
        d=google.com; s=arc-20160816;
        b=B1lLH4kjTCJ+qCkBVTRYoVQMuXiPy+SQjzHI0cvj9VkP2rEXU4ORRRnFsf9YWiBjXE
         EhGTdLii6sF5hT5ywUP32q2ULXJTktH3PMqIj/28HOI8wiT59n3kWLZEP4oqCxIMcCtD
         Z+a7VykoTjUxyxghpVChOPxpVv5n0c9tysyFKO6h5c0pX20mHdZ6GKku72WJHmMoGYFi
         jqe9NfMW9u/2qrhjNXkCC5SCPWNIM/hHEGX9keXaAvdCADfxzabXbr4+HZMBkbSq3EIl
         K2oiCChtSdA5mFqvsjpG1bExVTmZ56tBAUZprMdn2aWcQ0sKFH1Gohd1tCSIlqgbdE2O
         fUzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QZTCpwoqSxAuHWQ6Ualf+NSmhnZey5ULzRU2vpqw9C0=;
        b=b3nZSU27D+/rQZ45ehiYHQvGCKzZkRcyPrZE1sMC2zIVdUPiw/xJHcRplo2KP+JPw/
         JbjizFKHwlScvnwOU127DkYwztNihEtchYCTpX8Drjh1GHEbppbEjhJDaXtBAXSeDqSm
         oVzBgIt73OQUk7UjKMum3Af1JSx48CJ5Ri0dkiHQdwzRZc5okS0wGWQKmuaGeRZUWWJZ
         UZZJHbT6MSfUaA4nGTdQ8bQ9gmSOXHTkLeKuO3Jtzq54Z3LICXMfDGkaXi3GTDDy2PM4
         Jf2X4dqh7ph+aPrdoxenKyOtfa4cc6AjW2/jPreAZMgJAsiqgF/YqBbhR0W/9pbE5Xgc
         89SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qZoB6rRn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id b26-20020ab05f9a000000b0068b87220585si281897uaj.1.2023.02.17.03.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 03:07:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id mj16so984440pjb.3
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 03:07:26 -0800 (PST)
X-Received: by 2002:a17:90b:1f8f:b0:233:3c5a:b41b with SMTP id
 so15-20020a17090b1f8f00b002333c5ab41bmr1428877pjb.133.1676632046068; Fri, 17
 Feb 2023 03:07:26 -0800 (PST)
MIME-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com>
In-Reply-To: <20230216234522.3757369-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 12:07:15 +0100
Message-ID: <CA+fCnZdrHz12Rs9WYPwdL4DgBu+7ufsZ0iMAUaWNXxvrszHGMg@mail.gmail.com>
Subject: Re: [PATCH -tip v4 1/3] kasan: Emit different calls for
 instrumentable memintrinsics
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
 header.i=@gmail.com header.s=20210112 header.b=qZoB6rRn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f
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
> Clang 15 provides an option to prefix memcpy/memset/memmove calls with
> __asan_/__hwasan_ in instrumented functions: https://reviews.llvm.org/D122724
>
> GCC will add support in future:
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777
>
> Use it to regain KASAN instrumentation of memcpy/memset/memmove on
> architectures that require noinstr to be really free from instrumented
> mem*() functions (all GENERIC_ENTRY architectures).
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
> v4:
> * Also enable it for KASAN_SW_TAGS (__hwasan_mem*).
>
> v3:
> * No change.
>
> v2:
> * Use asan-kernel-mem-intrinsic-prefix=1, so that once GCC supports the
>   param, it also works there (it needs the =1).
>
> The Fixes tag is just there to show the dependency, and that people
> shouldn't apply this patch without 69d4c0d32186.
> ---
>  mm/kasan/kasan.h       |  4 ++++
>  mm/kasan/shadow.c      | 11 +++++++++++
>  scripts/Makefile.kasan |  8 ++++++++
>  3 files changed, 23 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 71c15438afcf..172713b87556 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -637,4 +637,8 @@ void __hwasan_storeN_noabort(unsigned long addr, size_t size);
>
>  void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
>
> +void *__hwasan_memset(void *addr, int c, size_t len);
> +void *__hwasan_memmove(void *dest, const void *src, size_t len);
> +void *__hwasan_memcpy(void *dest, const void *src, size_t len);
> +
>  #endif /* __MM_KASAN_KASAN_H */
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 98269936a5e4..f8a47cb299cb 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -107,6 +107,17 @@ void *__asan_memcpy(void *dest, const void *src, size_t len)
>  }
>  EXPORT_SYMBOL(__asan_memcpy);
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +void *__hwasan_memset(void *addr, int c, size_t len) __alias(__asan_memset);
> +EXPORT_SYMBOL(__hwasan_memset);
> +#ifdef __HAVE_ARCH_MEMMOVE
> +void *__hwasan_memmove(void *dest, const void *src, size_t len) __alias(__asan_memmove);
> +EXPORT_SYMBOL(__hwasan_memmove);
> +#endif
> +void *__hwasan_memcpy(void *dest, const void *src, size_t len) __alias(__asan_memcpy);
> +EXPORT_SYMBOL(__hwasan_memcpy);
> +#endif
> +
>  void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>         void *shadow_start, *shadow_end;
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index b9e94c5e7097..fa9f836f8039 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -38,6 +38,11 @@ endif
>
>  CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
>
> +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> +# instead. With compilers that don't support this option, compiler-inserted
> +# memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
> +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
> +
>  endif # CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_SW_TAGS
> @@ -54,6 +59,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>                 $(call cc-param,hwasan-inline-all-checks=0) \
>                 $(instrumentation_flags)
>
> +# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> +
>  endif # CONFIG_KASAN_SW_TAGS
>
>  export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
> --
> 2.39.2.637.g21b0678d19-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdrHz12Rs9WYPwdL4DgBu%2B7ufsZ0iMAUaWNXxvrszHGMg%40mail.gmail.com.
