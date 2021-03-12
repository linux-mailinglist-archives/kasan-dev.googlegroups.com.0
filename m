Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD4IV2BAMGQEC35XYWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37A823390CC
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:09:04 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id z26sf5471609wml.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:09:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561744; cv=pass;
        d=google.com; s=arc-20160816;
        b=HT3+BRJe/CBO85Ve/3kuP8m3TR3Dpdc6puVbfKnnXdJpDG9Jt2JW9lbERtCwX+TEtk
         xs0+6GwdD9Fhvg/VWjdHsSzQ+vDMiF23ONrIyJ5n58t7TIyuGSoB5vE5Eb4ZpW4dcp0+
         YA2Udi43CH9+YvPBM38rMZ8aMaL0TTFUxvdkxIofz8zgCtySl5bWS0SL/OwHN2AyUbaq
         w9Vw+pDACRL3ELULHh65V0nxhbyeP+3gsL1C4ebyh/2Wg+rsxDm7z04Z4HambarlJvB9
         NsbwhTI4lMOkqClg+RppVfJHgXadkHf5nM5WJ5ZavL/7LDQPrMvJXWFUDDAer3B8qXqv
         eZCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=iOMGvC2fjsaM44lhsPoB8upHFPyatbj8pEn8PUGIRlE=;
        b=Hkrbs92h7c5xY4HkwrxIzXKZ+8ja42Dj3+uY+x2udD00liBET52MF8KOS5wQrqNiRM
         q883VKk/VuUFmVcRVQFlYLZoyGAepUEIvJvlmZroy+3FDG1QGZoOCj1iERi3YgWDZjPs
         RIkltY45SZrTDNfX5B0x4VUnPefh++z8w2Z0M2aJmFvu6drZH+mzDpz50XHunXBBjazn
         TzmIDqUTQUJ89ptxeFY42XGsLGa+z8l82aibiFi/3kAISifHPXApXqPNYWriBNO5EIrj
         OL/NSIFnbwX2vtijpSOOK4eGqER9JN6fZysr6jz5mOIrJF5uFkNsEVrvNtjPQwPJUlt1
         PCWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YXc7cfUG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=iOMGvC2fjsaM44lhsPoB8upHFPyatbj8pEn8PUGIRlE=;
        b=Ji+lEd5AenVczc0BgtAv4WbkgN75+As0vOF4oqUpq9u5PlUJJdk/9rwX2awBCpUwB7
         U/+K7aCm8OfZAM6YlViUE2F4CQU+exq8+tCoiD1lEMgDMoaCpS8shAVGw4Hj1cQFQA2i
         qXuenin8yamMu+ie0QqcaBhNZ6DYohbGfL5jp5qtrC+MfO+u/CyeK+8sxeNoqBDx0+0g
         3q9rRAO369KVKBMYb06B6g9kLdHYDu6RQm8q9UpE9QE97LAr3X3a/NBHI3IM3PZveBvu
         83KdRNljRDjrVUHaJeNIleYgxb+q3R0dIUfjvZar0U1iY/McaT+om/XVrXVG6dRDZA1+
         WO+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iOMGvC2fjsaM44lhsPoB8upHFPyatbj8pEn8PUGIRlE=;
        b=dtgbLAPiH1tML9y33Ux8iTxV/SzxcanOSfGpHudVpnGowstl87a3+yekmXIp58o5Ir
         0cO4mEaSkjAiyxXQitdtJ2rDt0RjvS3QKb0Ofl0ZbYygGBaauEwJv+XAENQVpG1Z8tVL
         lKuCYIkxe8VSjuqX6Aer6AmL4CHqv4McndMOJzEKHdiXLTftA7QRP+QahG9In7OEP+VW
         Gdh7P5g5qPwBj7+0bBwdw1MXmoR5t7DjvQggAcAkBZOL79AuLJaWGHmOUO2LEPRjOlCi
         aiUPDKTI+BVdScIHqdl0Fvya+K1cVLQd6uZ1B0Cme4ckrrNXtU7udhKXY2WbifIesNS/
         sNag==
X-Gm-Message-State: AOAM530h0n/uugmWEgmx35G7rOX1Dnljub3W9pPI5EWVjhK7CQAJhHfW
	jw7z3ZoON5xCFT2epczhyZc=
X-Google-Smtp-Source: ABdhPJziuqzEahWWxQgZbu6XE6Hjb51fBtKl0ft9P9y3xlmYwPjBMF+hOON4oWGpjJ3Q3QWUljISYQ==
X-Received: by 2002:adf:f948:: with SMTP id q8mr14668128wrr.296.1615561744043;
        Fri, 12 Mar 2021 07:09:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls117848wrd.0.gmail; Fri, 12 Mar
 2021 07:09:03 -0800 (PST)
X-Received: by 2002:adf:8b58:: with SMTP id v24mr14220289wra.160.1615561743054;
        Fri, 12 Mar 2021 07:09:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561743; cv=none;
        d=google.com; s=arc-20160816;
        b=JRL61pqbEVy+2cnwFrCgNAQRr1Y+2OJlcHnMC1LyLbA8yeZpzaApBrNBlUeuRnOqQB
         SX6iPAgo4D0Dnw3TkUZFdwqYY5M0fy5wwv06Ag630rqf3KEhBrtWy9+adrdvXkmzdavJ
         MbZ5zQhJ7BkyKOilixwFM97dmiSxXK5NwCIMnhjFHz3cQqtIUmvW7obBYXk1aPq+ByfE
         3CyjSQnftl4kEoNFJi2P00TezUHQ5JLzx/ak4Wg4HWsBzm+U0vYyQb4nPoY9gl27SMdd
         Jkw676W5BsynaNSOGSBCN8ZpLEYFihhXRZANm/VZ9FRUGAa3zp5HI+0CG5/fqsUyHKkf
         wJQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8MLa7BfE7dVLn4tTMKZ+HSLGOdEizmmjEqt3urdruHo=;
        b=shifBOpCycbSNPiX0JwwxqIsvyU0DakTd4mqhf56o6PzaqjUjei7+AJOnFQhNRD3ZN
         7r5DWydnmE9c/LSEn0Pv+UoAbYv3y/lpIHNTt5uSnNXwNUpPV27OCWZjO11cDYJVbXT6
         c3GPp+ApWzRE2QupGB7UUVQZqA7mn/9dzL5lClyUHyRykFm8aQODKch7vPOrMcXEeu8w
         ZIHKcPaq3gXrlnESc+4L9y7co5N1BSwPX+6PA7nHaIrh1xcLVyBMrrcK8/kN1SsqFmzv
         Zh8LXGbn8KT7pZC6zD6aWAHl6irP+P9AnPX+E5+hB+gz9GNHmpb+OINsAumrRoyT4hdo
         YjQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YXc7cfUG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id i22si290872wml.2.2021.03.12.07.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:09:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id f22-20020a7bc8d60000b029010c024a1407so16016830wml.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:09:03 -0800 (PST)
X-Received: by 2002:a05:600c:2053:: with SMTP id p19mr13577526wmg.87.1615561741593;
        Fri, 12 Mar 2021 07:09:01 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id w131sm2402679wmb.8.2021.03.12.07.09.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:09:00 -0800 (PST)
Date: Fri, 12 Mar 2021 16:08:55 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 06/11] kasan: docs: update GENERIC implementation
 details section
Message-ID: <YEuEB3IhoXdixgiP@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <f2f35fdab701f8c709f63d328f98aec2982c8acc.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f2f35fdab701f8c709f63d328f98aec2982c8acc.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YXc7cfUG;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update the "Implementation details" section for generic KASAN:
> 
> - Don't mention kmemcheck, it's not present in the kernel anymore.
> - Don't mention GCC as the only supported compiler.
> - Update kasan_mem_to_shadow() definition to match actual code.
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 27 +++++++++++++--------------
>  1 file changed, 13 insertions(+), 14 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 1189be9b4cb5..986410bf269f 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -200,12 +200,11 @@ Implementation details
>  Generic KASAN
>  ~~~~~~~~~~~~~
>  
> -From a high level perspective, KASAN's approach to memory error detection is
> -similar to that of kmemcheck: use shadow memory to record whether each byte of
> -memory is safe to access, and use compile-time instrumentation to insert checks
> -of shadow memory on each memory access.
> +Software KASAN modes use shadow memory to record whether each byte of memory is
> +safe to access and use compile-time instrumentation to insert shadow memory
> +checks before each memory access.
>  
> -Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (e.g. 16TB
> +Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (16TB
>  to cover 128TB on x86_64) and uses direct mapping with a scale and offset to
>  translate a memory address to its corresponding shadow address.
>  
> @@ -214,23 +213,23 @@ address::
>  
>      static inline void *kasan_mem_to_shadow(const void *addr)
>      {
> -	return ((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> +	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>  		+ KASAN_SHADOW_OFFSET;
>      }
>  
>  where ``KASAN_SHADOW_SCALE_SHIFT = 3``.
>  
>  Compile-time instrumentation is used to insert memory access checks. Compiler
> -inserts function calls (__asan_load*(addr), __asan_store*(addr)) before each
> -memory access of size 1, 2, 4, 8 or 16. These functions check whether memory
> -access is valid or not by checking corresponding shadow memory.
> +inserts function calls (``__asan_load*(addr)``, ``__asan_store*(addr)``) before
> +each memory access of size 1, 2, 4, 8, or 16. These functions check whether
> +memory accesses are valid or not by checking corresponding shadow memory.
>  
> -GCC 5.0 has possibility to perform inline instrumentation. Instead of making
> -function calls GCC directly inserts the code to check the shadow memory.
> -This option significantly enlarges kernel but it gives x1.1-x2 performance
> -boost over outline instrumented kernel.
> +With inline instrumentation, instead of making function calls, the compiler
> +directly inserts the code to check shadow memory. This option significantly
> +enlarges the kernel, but it gives an x1.1-x2 performance boost over the
> +outline-instrumented kernel.
>  
> -Generic KASAN is the only mode that delays the reuse of freed object via
> +Generic KASAN is the only mode that delays the reuse of freed objects via
>  quarantine (see mm/kasan/quarantine.c for implementation).
>  
>  Software tag-based KASAN
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuEB3IhoXdixgiP%40elver.google.com.
