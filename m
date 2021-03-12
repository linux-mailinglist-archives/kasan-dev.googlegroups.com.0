Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUIV2BAMGQEJ3PUR6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E42F3390CD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:09:23 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id e29sf9892495ljp.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:09:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561763; cv=pass;
        d=google.com; s=arc-20160816;
        b=AddtuaiONiCh6VYi4yBKBxDt0EWYxx4sDfJn6BrIpWga6YWhQs5TWC9wJl+6ewy6lB
         WIaEzHZ6S9QJ91wvNwfrj12JZvWlghD8fqRHOwqo4ZB29Ksv00gI5XQ9bobXY8FYK90A
         /T9nxsPGgerhHfb5ChOANkM4XHve3XN4nGSic6NbJhEHpl+kjgpQeTAyELlSVd5weNBJ
         2Hy8LzXWBI8dp0h0vjP/vx5lCyqKOzoHN3zQk7Hj1+d2dqeJgZdCqJp1Yv8X3rKS0IEe
         qKhYc+/Lgvvcc8eRjKrwPWoxq5xCNniQr8aRDFqsQU5K2yPvYoOyuLX1hy6KfaMBz74f
         e2XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pmnqKCUGyDTpkixTuWbLqlhY8ypyaL66dHOXe0pBXSI=;
        b=Fih9xoTgEx+2caes7X8w42FE0eeAoEHGPmm0pxbVOLu/RNQXWgpMVSFNf4BuoIJF7B
         hix0UGj6nLdHESf8q+wBDpI6aBHS166vBiuc/xzXa3pR6L521AWDbbw9XR7VOYc/MBSW
         tqqK4vUmG5AjCeDO+8D/8d4XgGiVYysS+8fsJYl4aKZVKFegx7lWM/zilcvN9gHBmzE2
         SsG9mdNnTRkbdQUK5MY4Qz7XHUXie8Idb/mPDzGDyUCh4tPC3x9nM4tUQsTun/+VjvK8
         VCT0faUCdd5+J0SzkY3YGrIRUuI4h34rLrnaZQRNZFo5sgDf6SDpPVBaVJiUKAOasnme
         VrEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R1RmWkGT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pmnqKCUGyDTpkixTuWbLqlhY8ypyaL66dHOXe0pBXSI=;
        b=JuT9n3kGfnGVTleN6ZWEiUOE6YKgbrvuYm/vSpIRfRHqBrCxI+WvfKMZNsTIWBfFc0
         ygs+kTzhITIy5OhKLVuV2pvYTcw3ReAT57ma1MYTLoP8qa1mnfyC7QVQTBVL+QMft28O
         umzjdAfyl8KSdEw23Lup6tKn2oZ3SjWEzGYxZUCJ8xiNJiQaRL8fYX6usGwVUtkfY7sD
         AOvAoLl+uurb1REalx7iWk+WGlImYxxjW9268NTy8OIB6lmPgCEtHHXH/90La+T4UZ8l
         Or2+hINkEROe4jBacg+OWs5ZQtN/vLHIUMJakkNfzh6N/s4rWrb4qXbfg1HPRBRoulGG
         d6dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pmnqKCUGyDTpkixTuWbLqlhY8ypyaL66dHOXe0pBXSI=;
        b=FBGNW4QNflHXjS+uTpToszDsX5rr3TdEqQyOIDUJFj5eNEkDvkccDOOb1VNQw7o+6y
         ePUjvE8bjz7sWD1bEod0u+bmmTGEG1PTha+QOKaai78ND3CNx6FddXIrdzF6IoxQ1+CN
         j+OYIlr8ru0XH3s8mfZC8JhIqGKNt9w4QAaPQgTKbxwNGgPysG3nj49koIwVr6uIVeYN
         I6cUbJsQ+BUeMJyBXIGB3HGoYj/lqSB/ZmRYs6uIiXOapNfKv884oXdk9FbLk/QJWrm/
         1ZYjz2U2SoLmZfbtfhRY8DG7j5q5r7Yt+rIbuuWixRgG7b+NDoB819zc2FX+rf8mswFd
         AXsQ==
X-Gm-Message-State: AOAM532VjeQ9Qjfz7hOVJlH+Kz+bM6/3XzS0gpP39usr1F7HYX3idN04
	KUqiMEu1N5+uyvax/yJ/xa8=
X-Google-Smtp-Source: ABdhPJwRRKOXbbzSYSlEpLCgqSPiSwSpp+jl9RmdBhBwiv05ICQFljsp5s00cyO2YX2sumQmQOsjtg==
X-Received: by 2002:a19:7010:: with SMTP id h16mr5430732lfc.173.1615561763118;
        Fri, 12 Mar 2021 07:09:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls3654881lfu.3.gmail; Fri,
 12 Mar 2021 07:09:22 -0800 (PST)
X-Received: by 2002:a19:e08:: with SMTP id 8mr5394677lfo.199.1615561761931;
        Fri, 12 Mar 2021 07:09:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561761; cv=none;
        d=google.com; s=arc-20160816;
        b=IHu/3/Ga4o+W6ycyD0G2PyQ7E3LT5vHKu+XztZPnpIcCjLNty0JDpEo+73h+kII2Le
         f0KZUpSamB2QwD1EUoogV1mQjUmYlkJQBWQqK2fG14NkXUQoQeyHygqT5W1cj5pHROVT
         iauOq1thO+sajGyew+rrK9Dla+fv8QOeT5gUu98Ud1lqL+2unWtTD0GUJbEmA+uOaMG4
         GJOGegQeWO6SHtvEKyCz5PZYJQPMAPF1oXspVWlSwvczjxogaSAoVhNadNCIaa/ALfDL
         0Gljst5xo3/1eu5Yu5PbRjI52Inc673TGoAajkH3bkIlNmBi8F+x7bGWClybMMBXuEtm
         Hb7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=gtvZkycLjntznV5+6tLS7tFxXM/9IJvZKgaaSBlNSTQ=;
        b=SMTDjKui7xZ5CGWF5MKTsdPSV/+y0kwiKAls/mi0rVC6VvInwA7qpdfs4Z+kUfUBKS
         crJPkbBcnibqMuMDEtKpdk/BPRsNh+3HFIh6KrSIued065647dOfdyQq0JCOOCuge8+k
         NInbC92RVoYlcUFtnxZosF+C3NfJiOZQhD+Z3BuUbhvgc2xp/0rz8WUk7LINlQy2thmH
         J3befIgK0VAgkygCo7AQ7cJlGAZQqq3r9do9F4moPgGMDH71yNj/C5Y+3MdxI1shftr4
         PTPiZj54us7vP114m30VB97WMMchl+tKkGb9c/Jo03Uk4kuCu4ur2SfsbPgkbVcg3g1Z
         Lz7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R1RmWkGT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id d19si230734ljo.1.2021.03.12.07.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:09:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id w203-20020a1c49d40000b029010c706d0642so4726921wma.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:09:21 -0800 (PST)
X-Received: by 2002:a1c:4986:: with SMTP id w128mr13516548wma.37.1615561761555;
        Fri, 12 Mar 2021 07:09:21 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id m3sm2303932wmc.48.2021.03.12.07.09.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:09:20 -0800 (PST)
Date: Fri, 12 Mar 2021 16:09:15 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 07/11] kasan: docs: update SW_TAGS implementation
 details section
Message-ID: <YEuEG+K4/V4zn9l4@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <69b9b2e49d8cf789358fa24558be3fc0ce4ee32c.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <69b9b2e49d8cf789358fa24558be3fc0ce4ee32c.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=R1RmWkGT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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
> Update the "Implementation details" section for SW_TAGS KASAN:
> 
> - Clarify the introduction sentence.
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 39 +++++++++++++++----------------
>  1 file changed, 19 insertions(+), 20 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 986410bf269f..5873d80cc1fd 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -235,38 +235,37 @@ quarantine (see mm/kasan/quarantine.c for implementation).
>  Software tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>  
> -Software tag-based KASAN requires software memory tagging support in the form
> -of HWASan-like compiler instrumentation (see HWASan documentation for details).
> -
> -Software tag-based KASAN is currently only implemented for arm64 architecture.
> +Software tag-based KASAN uses a software memory tagging approach to checking
> +access validity. It is currently only implemented for the arm64 architecture.
>  
>  Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
> -to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
> -it uses shadow memory to store memory tags associated with each 16-byte memory
> -cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
> +to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
> +to store memory tags associated with each 16-byte memory cell (therefore, it
> +dedicates 1/16th of the kernel memory for shadow memory).
>  
> -On each memory allocation software tag-based KASAN generates a random tag, tags
> -the allocated memory with this tag, and embeds this tag into the returned
> +On each memory allocation, software tag-based KASAN generates a random tag, tags
> +the allocated memory with this tag, and embeds the same tag into the returned
>  pointer.
>  
>  Software tag-based KASAN uses compile-time instrumentation to insert checks
> -before each memory access. These checks make sure that tag of the memory that
> -is being accessed is equal to tag of the pointer that is used to access this
> -memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
> +before each memory access. These checks make sure that the tag of the memory
> +that is being accessed is equal to the tag of the pointer that is used to access
> +this memory. In case of a tag mismatch, software tag-based KASAN prints a bug
> +report.
>  
> -Software tag-based KASAN also has two instrumentation modes (outline, that
> -emits callbacks to check memory accesses; and inline, that performs the shadow
> +Software tag-based KASAN also has two instrumentation modes (outline, which
> +emits callbacks to check memory accesses; and inline, which performs the shadow
>  memory checks inline). With outline instrumentation mode, a bug report is
> -simply printed from the function that performs the access check. With inline
> -instrumentation a brk instruction is emitted by the compiler, and a dedicated
> -brk handler is used to print bug reports.
> +printed from the function that performs the access check. With inline
> +instrumentation, a ``brk`` instruction is emitted by the compiler, and a
> +dedicated ``brk`` handler is used to print bug reports.
>  
>  Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
> -pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
> +pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
>  reserved to tag freed memory regions.
>  
> -Software tag-based KASAN currently only supports tagging of
> -kmem_cache_alloc/kmalloc and page_alloc memory.
> +Software tag-based KASAN currently only supports tagging of slab and page_alloc
> +memory.
>  
>  Hardware tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuEG%2BK4/V4zn9l4%40elver.google.com.
