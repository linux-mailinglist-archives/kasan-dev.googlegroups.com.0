Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ6JRGBAMGQEPPJSBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E922332F09B
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 18:04:40 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id 42sf1761533plb.10
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 09:04:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614963879; cv=pass;
        d=google.com; s=arc-20160816;
        b=FRb7jkGQilj9RvGGfT5sAjMN4X9epPi8+hBl5FHUUkcQoTeB2QyKTqdShmRZMCK/k4
         8UNEfobumo0+vyRqQwYLsgXBf0jz+TbGkDLHzhSNM0TzB5DKfmFvTn1hyNKQot3FlhjZ
         viS/aPpGfw3hq6OzGliGD1RxAXn6UWNQT54BnhEVuL8TZJ0Ab0YiGfhPE1E7Elle7cUJ
         B7fziZbyl+BFSuOnsw+GBLh1zXqtkrqNVbZFYjkt5GAV6Haq+XMSdhvAVkMo7PKN+s3p
         v42ZCeryP7oHteiFoUtkF8Eerk8GagL9ecSGSFStwo/Y2VwaGJ+o4cCeMEEBFNc0xjcJ
         lpDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DiK4uOrKX4W4AnSrcdePm+M5ZSHAzCaFBTm91612uWQ=;
        b=MOwb18BaXMyKadJaHWaHQV3D3TV6Hh4naG4UDHOAjlcyHFyj6tikq1Itfx1zBwZDHH
         NnXZIfUkFMMbz9vaDDv5KE653MkKiaDBC7I/LHh0LuLVIeWhzeDEqmDbt3vHnNY1o4an
         dhGPUQEuxJXIXMJHda4SlvRx2hpCFi3D8FiDoOnFlUrkk6GlQ7X1aPrrpRSul+4Dzja5
         SnJtif/ABdqn0SjJIhhuKfOw0q0/xCjkecwiah7Cq86ldHiwcHC5QhN5Gwlap9067D52
         fJoR6LflQNYqaPZDO8odLSoYXTD0hid2rUBx96wLsYVQkQ8N2WA/7+ETh7crpp6MYnOy
         bGww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dXaqm+Vx;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DiK4uOrKX4W4AnSrcdePm+M5ZSHAzCaFBTm91612uWQ=;
        b=g4EjqoMW+dT872oealxgIB/t1dIG/nc4ixIEip8jyD76rXwD9FNLt0ibGqbcrDJQcg
         83cpYoopqHsg5FO85DGJuuYv6j9ZHtzyGlvTmoW+5TXd1BUM/L/LOBl7HOnNR4wii2K9
         31hzdJSMvPrE0HckmGI81re/y0WIac8m/0DYIgji9112hiXeJaUAP1eOfvR3F1TypdfI
         hM4MDxBwJbZE5EzNNlZwOcFjva4O/FtnriIoNOJ2cqLsyZ2JxumaaRteeND4OEulkPB2
         enOPupRsJsSnIMRVw9u0g7c5noBIcSJxrqhWWPKL9Xu/a6S/nxul3+3s8az+CsgBP2hE
         B8Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DiK4uOrKX4W4AnSrcdePm+M5ZSHAzCaFBTm91612uWQ=;
        b=oMULKr9jM5fsO8j40aQz1amyJ1hyIZhYaVTskK9jdQ2zyw4YbxH8e/5Pct3lMclX5V
         UTxkwgx0n/8EYqoubT/5ZzxAoPcgFE9fs/3HNzk9MzP3VGL7tUGQ9ggNWBkPm6Wn5Nut
         1TrrgatJyE5MwbizVrl3nt43KQnrjYpLPjj7qgEgN2K0g4bEMx9GSQukburZIJlfp1Rv
         fAwPKrInk9D4i5FD8LuUrxPqmWdl0IrfRSVf87rFRKopKJGHs6AbJ3VXuIa+Nyj2YLnm
         lL0NNmPpxvzdxpGyqHp+qpkrqr9YuzsjXKpiobWdPDeV5eR6i9vvFW2QE9iShDubmSRa
         uQGQ==
X-Gm-Message-State: AOAM530/vrXoMPYtVL7/SybuyxVhxv34TJPUMbZuFtiJ2d4FVX9dRKQ9
	1n18fy53vkhuxrjfPPXJCMY=
X-Google-Smtp-Source: ABdhPJyNlOrRGTFaZg4ukWWQIm0zP6W4rJjb9Kg2MCp0FB4tmvYbHo+swHRBj6m2zcPUWQnv06OtTw==
X-Received: by 2002:a65:4203:: with SMTP id c3mr9486246pgq.65.1614963879438;
        Fri, 05 Mar 2021 09:04:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e788:: with SMTP id cp8ls4901841plb.4.gmail; Fri, 05
 Mar 2021 09:04:38 -0800 (PST)
X-Received: by 2002:a17:90a:77c8:: with SMTP id e8mr10958523pjs.48.1614963878877;
        Fri, 05 Mar 2021 09:04:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614963878; cv=none;
        d=google.com; s=arc-20160816;
        b=UCesGyVDwFFgOO+4k9Lg/J0JEP4QcTvDw70cAAzw2QGqAzTpTHn911GdCzC3nkRMgA
         nm0zd0ZBs7lq6WV/4DLghEEJKyT4U0Ir3Oe4ffHNLYgXczu9KEB6fI7TQgFbDTx+M2y6
         ogm/iy8SIV74UM7kXB6e88mw9czRf1z2ii8tc2eNb8IY2QzNwSbElADONe4HFWBksYZr
         SgY0Q+23Jq8HjRN83/r+/zZDm/Ya+dETHPwAcZjm0bBLo2FOmJw35C+TofvUzsr5SF5h
         dRR3AFkOJHcpoRp0zAKGGIdw3B6BdanMvirBh3/D20APILRwcqm7FQQ2tHUgTdRjpQKn
         /KcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VCvImFx+wjxWiBbU2aABnmv0wEUTxntHCJc3sPTuzt0=;
        b=A0ykPiKqfxV4+WV6EA3bc/gVk3fBm/zES+L7fBgfPolwYvsknsFmk5NU4eUCPo6/gV
         34gCvJbioOK4MyAEaDx0JMzrMJSOQZzuTorGgsZ8/ZPN1Z3dUY65ipHVFlkzHZ/fd52E
         KUx3JoAgphTGgNMSBWXGNRSzBjtwOG3PrR1I7//yRbQ41Va5qVtIsP0Ti/ZvwCW8QXt5
         k23LhfuQODYqjvxbkBzaLvtX3fSP5Cf9weKMmSI46ZyioB03VmqrnTpNVFz9uKchtPLb
         K07lG4hPwYHxwYczBYDrqIgHNgdmD8pPaA5jy+aY04+0+B7XqqRXVtldQPdJqVqX4VTG
         cuqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dXaqm+Vx;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id r7si1464611pjp.3.2021.03.05.09.04.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 09:04:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id o10so1797878pgg.4
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 09:04:38 -0800 (PST)
X-Received: by 2002:a62:38c8:0:b029:1ef:21ba:aba3 with SMTP id
 f191-20020a6238c80000b02901ef21baaba3mr8126629pfa.24.1614963878391; Fri, 05
 Mar 2021 09:04:38 -0800 (PST)
MIME-Version: 1.0
References: <1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl@google.com>
In-Reply-To: <1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 18:04:27 +0100
Message-ID: <CAAeHK+wyh=vpw=Gbi+NqZ0A1z-0a8pQS8q0OkOfLc9o=zhMEUA@mail.gmail.com>
Subject: Re: [PATCH] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dXaqm+Vx;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Feb 26, 2021 at 2:25 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> after debug_pagealloc_unmap_pages(). This causes a crash when
> debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> unmapped page.
>
> This patch puts kasan_free_nondeferred_pages() before
> debug_pagealloc_unmap_pages().
>
> Besides fixing the crash, this also makes the annotation order consistent
> with debug_pagealloc_map_pages() preceding kasan_alloc_pages().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/page_alloc.c | 8 ++++++--
>  1 file changed, 6 insertions(+), 2 deletions(-)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index c89e7b107514..54bc237fd319 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1311,10 +1311,14 @@ static __always_inline bool free_pages_prepare(struct page *page,
>          */
>         arch_free_page(page, order);
>
> -       debug_pagealloc_unmap_pages(page, 1 << order);
> -
> +       /*
> +        * With hardware tag-based KASAN, memory tags must be set
> +        * before unmapping the page with debug_pagealloc.
> +        */
>         kasan_free_nondeferred_pages(page, order, fpi_flags);

Looking at this again, I think we need to move kasan_() callback above
arch_free_page(), as that can also make the page unavailable. I'll
send v2.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwyh%3Dvpw%3DGbi%2BNqZ0A1z-0a8pQS8q0OkOfLc9o%3DzhMEUA%40mail.gmail.com.
