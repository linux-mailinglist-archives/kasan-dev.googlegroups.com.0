Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTEIV2BAMGQEQDXYAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 928CE3390D4
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:10:04 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id l8sf9963577ljc.14
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:10:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561804; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0os7Crvnldj1KaKSxuj/LSU4RB59ms7cIGEnYCVG6YyXwHhaF3IP+Wg8SpYFNjJjs
         W0Of8p7pl1vQkI5RLmiQ7AOhRRxTIJwlUG4m2muFs8m86+Wxp/vXI18VKry7Uh87bmV7
         t3Y2zhpvijbd/pqSqWuS4Wthq281UA3+G1Z1QApeYOejjLbxfGAZcXzIZiOmVwFs1iu1
         uSo06rzDowj1Cwk7sAiZdrqTad7VqhOqR5zJm+T2lBLAncQJrzHjDMmOQWFvcqrXoEe2
         p7nkSP/OZTurxesnRS03FbpNnejaOpUwdcmv4JpsKoxBTv73wA1y+LBuCQRCS/AGP5ec
         I4EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TgZuuTd/uc+yNqLohFsp0DQY/cwv4adDCMUX1NJ+boc=;
        b=exufVD48RL0Us9BDxhBD+DGCUKXO19fUNdRpxSrq2YPrBBlnoh5eBolyQxsKZWMf4u
         UL+fjGW7pii5TrFKmzAj2jt7Uo5jlKuYoCCT9P6ZRv9KInFPQzoXTRckjLDfF6cjL4bz
         GgUnECh9wHFEsBbINcwrPBCfK8OrYpl5jy329c7MyiQRel05ovSnJmPVURtMpDUPFjtG
         UOdBniDxe2z8OjHd097zzFIWel9eU93c1ae0bxoVj7yMmfshGOqDGi7Qd52cVDga0ojU
         TMsMgvW5JwUWFKg+GBqKbWfQBkaQIQ4mypeCHfDB3JdfiVzgBAvhQYhDSbVk2FGf7W3g
         +xCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TQB5C6l4;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TgZuuTd/uc+yNqLohFsp0DQY/cwv4adDCMUX1NJ+boc=;
        b=VONQNlV8Uec3ayoRDj9twMfJNwQqes0gwpMIlYJEh7P5gqFtBbjRSnLbpu4nWEiC+s
         +NF+5mzkg2y/aYD97nFVel2sgAvzmsvTAGrUlj/7+TZDW1pwPHpfS7ghxF/cxQCzhusp
         TAW1P9PnjIfqV9lEMAgTC++FrANJQGo+5BkZFTKp7e2Df3diDDkYDF/Poz3Y5WFlZrCv
         8CuDb4Y6l96Z5j0USm5yP4DkKYSfoSK4oQuvXDMmEMosNDlUWnJN2q0tRHhdrB3kEE4I
         UymWuxFL1id891mn91hhmjufLqKxUBEdAy3n9ouz1zAcpJS/gDOvL7eVuFPzHspfIxHa
         HGYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TgZuuTd/uc+yNqLohFsp0DQY/cwv4adDCMUX1NJ+boc=;
        b=rfsdVIX4Q2W063/OzvYxzNlwE0KhC3HkLteJIW8T6a0UJuya4OzFocqxsctQEZMFCK
         Jc9Z5hVA7pUQVTd5E0VU0TMDUEMrAICTijXipDG7mRnk2ziIGAPsRY83AjAQDoUe6wKR
         zPPbaPH8S4XSx0a39d1jR8n7yJulme1K+bAc8Sd/bz03bciuHezvE8GueYtpnQ9NtTVW
         a3EdObyd4aKx60MJPezUYHTMHwFXDddLRVBLjRTEi+EcK+ii5ju3QAUDQaYgZKvT0kC0
         zyy7+MjLvj2CDRDjNQyA4S4/A25zgW3Vx3XUjlX0Ko9o/iaaPQVlpH02PohcYiNLMOug
         Tl2w==
X-Gm-Message-State: AOAM530uPL4N7qSm61IMUMTaCYRx7gxsK4yF/6FOpF3G8Z7dhvI71Hng
	Nt9J9NRqi+7pASAIXJuTLGM=
X-Google-Smtp-Source: ABdhPJzTI8iwCRs4phBpDlci6oRdUnEDEEdDkve/vcqn2e5WgRQA5THaRcIJbtQO7L/rAa8ucPJTHg==
X-Received: by 2002:a2e:7c14:: with SMTP id x20mr2723254ljc.146.1615561804213;
        Fri, 12 Mar 2021 07:10:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8915:: with SMTP id d21ls2023223lji.1.gmail; Fri, 12 Mar
 2021 07:10:03 -0800 (PST)
X-Received: by 2002:a2e:8591:: with SMTP id b17mr2618230lji.230.1615561803078;
        Fri, 12 Mar 2021 07:10:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561803; cv=none;
        d=google.com; s=arc-20160816;
        b=p5tmxmbFZ4iLkzHcKx4+ewAjDK2QBQGEKT5zRhM85BXXfiBIm49vc5sm5yMp6MiKS4
         j2/zIEqPaj6TftnQWwWzrC7ijmlqxGpHU6vTcJmgodJ/CGl08sR6xigLjUojcDfArOdl
         UQjbCbjoY0tHvLS6ytjT6md+zHY6Mw2GC7rBGcpDshnspK9BgNJgCpgM0mq0J+GFqIST
         7PYX6kOtQ/Tln/1dL88MMvsxbmzcR16l8lIyDPSStValCmyE/hKi1QJL/W51kSU/RJ9T
         99PaTOhILxipneN99BEb11xvX4bnFV46cCDKYrKyV8xxZ1SipLEESGWEwJ5nj4YmQuAy
         4vdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=q9bPQXFsE5NHB3Ewyjn3BKLWEisEUyEGFLv0VSHg4OQ=;
        b=tK5mUCLclXRgNMbEvJkpR7qHc1I8aUeBhxdRlGA4YtkInf0Uf695V9UG/zQqHiitED
         TLp0/rfsk5ooKXLEfnq1QJVjy8H2clHm7BI/dDfwxoTh5bMg5CC8iVHzVxuHBk4XBaKk
         7a1edI5DgTBDdan7jZd0FYf1FCQin3/usf8tT5hrW68VEqUtXm5rVM5EDLIPMOibts2w
         boquciQ8fLdHKmzUbfE+d5AOZCph9bzBjkbB8ZCPMXFYZzPvn/NMz9TiHaPb01U/Trbh
         rPe0OK1xlYsK3ovKnQhbdk8JdtUWgTzgjCbAvSp+yzmqa0Nu+csRIvR3a1ey7nj/UV28
         RIrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TQB5C6l4;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id d19si230878ljo.1.2021.03.12.07.10.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:10:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id r10-20020a05600c35cab029010c946c95easo15376015wmq.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:10:03 -0800 (PST)
X-Received: by 2002:a1c:c20a:: with SMTP id s10mr13423275wmf.144.1615561802386;
        Fri, 12 Mar 2021 07:10:02 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id q4sm2523647wma.20.2021.03.12.07.10.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:10:01 -0800 (PST)
Date: Fri, 12 Mar 2021 16:09:55 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 09/11] kasan: docs: update shadow memory section
Message-ID: <YEuEQ79AE0+BoV87@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <00f8c38b0fd5290a3f4dced04eaba41383e67e14.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <00f8c38b0fd5290a3f4dced04eaba41383e67e14.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TQB5C6l4;       spf=pass
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
> Update the "Shadow memory" section in KASAN documentation:
> 
> - Rearrange the introduction paragraph do it doesn't give a
>   "KASAN has an issue" impression.
> - Update the list of architectures with vmalloc support.
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 31 ++++++++++++++-----------------
>  1 file changed, 14 insertions(+), 17 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 2744ae6347c6..d0c1796122df 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -304,14 +304,11 @@ checking gets disabled.
>  Shadow memory
>  -------------
>  
> -The kernel maps memory in a number of different parts of the address
> -space. This poses something of a problem for KASAN, which requires
> -that all addresses accessed by instrumented code have a valid shadow
> -region.
> -
> -The range of kernel virtual addresses is large: there is not enough
> -real memory to support a real shadow region for every address that
> -could be accessed by the kernel.
> +The kernel maps memory in several different parts of the address space.
> +The range of kernel virtual addresses is large: there is not enough real
> +memory to support a real shadow region for every address that could be
> +accessed by the kernel. Therefore, KASAN only maps real shadow for certain
> +parts of the address space.
>  
>  Default behaviour
>  ~~~~~~~~~~~~~~~~~
> @@ -323,10 +320,9 @@ page is mapped over the shadow area. This read-only shadow page
>  declares all memory accesses as permitted.
>  
>  This presents a problem for modules: they do not live in the linear
> -mapping, but in a dedicated module space. By hooking in to the module
> -allocator, KASAN can temporarily map real shadow memory to cover
> -them. This allows detection of invalid accesses to module globals, for
> -example.
> +mapping but in a dedicated module space. By hooking into the module
> +allocator, KASAN temporarily maps real shadow memory to cover them.
> +This allows detection of invalid accesses to module globals, for example.
>  
>  This also creates an incompatibility with ``VMAP_STACK``: if the stack
>  lives in vmalloc space, it will be shadowed by the read-only page, and
> @@ -337,9 +333,10 @@ CONFIG_KASAN_VMALLOC
>  ~~~~~~~~~~~~~~~~~~~~
>  
>  With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
> -cost of greater memory usage. Currently this is only supported on x86.
> +cost of greater memory usage. Currently, this is supported on x86,
> +riscv, s390, and powerpc.
>  
> -This works by hooking into vmalloc and vmap, and dynamically
> +This works by hooking into vmalloc and vmap and dynamically
>  allocating real shadow memory to back the mappings.
>  
>  Most mappings in vmalloc space are small, requiring less than a full
> @@ -358,10 +355,10 @@ memory.
>  
>  To avoid the difficulties around swapping mappings around, KASAN expects
>  that the part of the shadow region that covers the vmalloc space will
> -not be covered by the early shadow page, but will be left
> -unmapped. This will require changes in arch-specific code.
> +not be covered by the early shadow page but will be left unmapped.
> +This will require changes in arch-specific code.
>  
> -This allows ``VMAP_STACK`` support on x86, and can simplify support of
> +This allows ``VMAP_STACK`` support on x86 and can simplify support of
>  architectures that do not have a fixed module region.
>  
>  For developers
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuEQ79AE0%2BBoV87%40elver.google.com.
