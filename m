Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NAVCGQMGQERVCBXLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1983F467792
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 13:41:26 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id m17-20020aa7d351000000b003e7c0bc8523sf2494440edr.1
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 04:41:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638535285; cv=pass;
        d=google.com; s=arc-20160816;
        b=TfKCVpUyX/2LyGuTcEeIjX1b937FTRM3q+XzZBFFirLCa+PfKT2enkGBTHlDkuEnP1
         LXO+FLIVZhm4YFD3sPRn08QqpSptNqbCRw38BB7vXhIKaS70/eoRCg4F/kngAyRHvIHo
         jlrNB3uZtvlBPAUd0m3zsYbZequkvGXAIRZkF6NJAXZ7gs7YyWPTC9+hc1ve/doTQunO
         3Mk65bs4vqmpfZB0atwkpSFTZoA9szTvyJ5FzoWTTBbfsKRHBrZMf4bdb1BYQ8hjzFmV
         gYgs7r/VwZYiDgmj0q582JZqt75Ln8b5WSBRr5kALmTTrf7ZoaE8MZ6LV3Jsl08+JLKQ
         a8gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tCm63hhieZhMLEZBZak8dBzQVIrxUSINquIFGQRD8AU=;
        b=aLK3QDw5hMdUxYZT6N+MUjzCBRP1zREGImRZHHch7QTH9sZNSHWqhjfgo1bWSpMY+/
         S9EAEzqBplHfvijFEYWgNx6C6MntlPVCYuHV+ebwCQhGF3nTV8Lnd8RDCTZYRCSkWyh1
         Cc5beGUPy9uYDwbLv+7T7pTCfgH7xIAxwqrDwjErwfZi1ZehlUOhtALBtBuRFBbwrari
         FJRbZnfNtEjyMxZzeby9OfnRlH1R7kIlkRbwUwemHZbYxenKy1UJBmIbOIzfKqyGoj8J
         EuGhINC0SmAE6rpDR3NjRYdvKT6K6qm4SLjCbOfgjA7KdVf34kH1ZGPjB1IriArg80BJ
         4CrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EGQ3aws5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tCm63hhieZhMLEZBZak8dBzQVIrxUSINquIFGQRD8AU=;
        b=ANIWfmug2OmavYojI3ScGUFHCjk4Fb8L6AWdVPXpO/eBfMeC8NxN+Sj4Z63z+x4cUe
         tEgARQpgvuliuzqrFaj9O/hp/8nH7sjnRTIXLxpvPMpcuF2TW9xKvsVwNCRktfFeO2W8
         u3I2M7PCeOgkhbLqMzpA37obO5pCgAS8o28qDVZy6fqaRJWFraXSXTgxJzyFQyiZ5AYV
         agHH8sPYIVzndkCuTZiYXa5Kalx0UqrDaeXl4zrre6Th+3otKaNu9/b5GocLiF3CHn6l
         MbG9hz1jRyB8Z9DFQ+/A7tDJMTB4K2byIjXCmwyVNLLy3Fua+MyWFf9m/nPNid2Xiyyd
         cHOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tCm63hhieZhMLEZBZak8dBzQVIrxUSINquIFGQRD8AU=;
        b=QeEAgvGe++zCE5UBYKE05aA9fT44q01Yaf9AqjNBYR1IZbStZHs3wbDjU6Tl9AQSVB
         XN2zVFxIxlHoL4iL/J3s2RFwgI7f9ghFbbS4RYgMureLuDz9kxNug8qUKW0WLwBlMh3M
         b8Z0Y6+YlTNsXUup2rolh+8Q/JPcx+TeB9H+un1GbZJRfBPuKdOZxrJpvLzReUX6JLSK
         Fm1bbZDaZu9uF18l7exhK9t1/vv5FwEp7HR6Cp2OPXs6OI8PPx9J6Z94Ko+XCX1wHu82
         iTWIZFtUQcJ6bqxufbea0UBaHanpGchlz46pmieRIIK8DBM8vmVAV8GcBfsp0Q8QnZlL
         czTw==
X-Gm-Message-State: AOAM53325eNzG3eENH11F9/T+onVfL6V0I6N47EwfFGI3+BWX6XTbDNb
	3rDLr6v9wuaFgPpBhQoOIvs=
X-Google-Smtp-Source: ABdhPJyEDWTHfIfkTQTa0/KFBFxNwBwdBaea8TJxcLrsqz6skDZNbbvKUwfJLoJgqbDExW60OuSB7Q==
X-Received: by 2002:a50:9eca:: with SMTP id a68mr26828581edf.127.1638535285856;
        Fri, 03 Dec 2021 04:41:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c98f:: with SMTP id c15ls275848edt.0.gmail; Fri, 03 Dec
 2021 04:41:24 -0800 (PST)
X-Received: by 2002:a05:6402:438a:: with SMTP id o10mr27045657edc.353.1638535284827;
        Fri, 03 Dec 2021 04:41:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638535284; cv=none;
        d=google.com; s=arc-20160816;
        b=BfJm5LmspVueeoeUXSxnB8msvyDb0z2LTNDr/njlMALJ+dFOOOPPVcuk8xqVxJLjwQ
         1Mks/6y1pmUt25OvrexQ5Ohhkbb2MvQJO8EAN2MJer65NPM7qq4XhEddWH3X0X9nvkep
         2eR/dKsnt/5jjhlbZ/aCeN50IV+zq09iV3xqmhHLd+cRo9Ua9ydoDZ/EhZvU9YYADzmS
         n0mo0ca4uUN8ZCx2Eus05Q3xwx9Dz0snRnSoX4G6bo8uu0VGM/nNKSDPXYYBSj5ty7VE
         ZMf+fqA04PkbDBmoO/MupK1+Vjg/YGdtuLtu5Zcel+yINKt10ZqkEOUbu30xY4p/5i+q
         D+nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2DlaYyrMnNAfarN4p4bn7fLOENYHGsS+8GIcDJI44kI=;
        b=dT8UFV7PCQ5PdtaQD4xCE6KfhuYSP5RrRxIqZHv5bnKEfCLmJqDCoYQg3uOrZeNc3f
         0H/w2Q2I7oHdXVwCVCT2/i+uOt+YANKKys8v3aAcRWP1FMGZOwUwhgp+oM+QFdx1Ro1c
         JqQAJHHObBAK5b6NvlLevXIyIHD+E7J0pAo8TlP0OoA3L7s5UL2rYw5ZmG38mdtK1C+f
         qeOGHo7t1MHhy5Ifx2ttIWbGkXtSUuZQM8aCP9mih816zS4oKSKPtgwVinq/ygRNgGs6
         vUMReYxuxcgk9IZJ6NW4+TsMiGhXuwkoYFBE/W7CX6rCf2eyayNFpVv+CcvRqaT2/n1P
         D4jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EGQ3aws5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id i23si169963edr.1.2021.12.03.04.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 04:41:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id a9so5423984wrr.8
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 04:41:24 -0800 (PST)
X-Received: by 2002:a5d:4889:: with SMTP id g9mr21784593wrq.455.1638535284334;
        Fri, 03 Dec 2021 04:41:24 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:cb5f:d3e:205e:c7c4])
        by smtp.gmail.com with ESMTPSA id z6sm2427482wrm.93.2021.12.03.04.41.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Dec 2021 04:41:23 -0800 (PST)
Date: Fri, 3 Dec 2021 13:41:18 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 27/31] kasan, vmalloc: add vmalloc support to HW_TAGS
Message-ID: <YaoQbt/7FoEnBx4K@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <aa90926d11b5977402af4ce6dccea89932006d36.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aa90926d11b5977402af4ce6dccea89932006d36.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EGQ3aws5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as
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

On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> This patch adds vmalloc tagging support to HW_TAGS KASAN.
> 
> The key difference between HW_TAGS and the other two KASAN modes
> when it comes to vmalloc: HW_TAGS KASAN can only assign tags to
> physical memory. The other two modes have shadow memory covering
> every mapped virtual memory region.
> 
> This patch makes __kasan_unpoison_vmalloc() for HW_TAGS KASAN:
> 
> - Skip non-VM_ALLOC mappings as HW_TAGS KASAN can only tag a single
>   mapping of normal physical memory; see the comment in the function.
> - Generate a random tag, tag the returned pointer and the allocation.
> - Propagate the tag into the page stucts to allow accesses through
>   page_address(vmalloc_to_page()).
> 
> The rest of vmalloc-related KASAN hooks are not needed:
> 
> - The shadow-related ones are fully skipped.
> - __kasan_poison_vmalloc() is kept as a no-op with a comment.
> 
> Poisoning of physical pages that are backing vmalloc() allocations
> is skipped via __GFP_SKIP_KASAN_UNPOISON: __kasan_unpoison_vmalloc()
> poisons them instead.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

This is missing a Signed-off-by from Vincenzo.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaoQbt/7FoEnBx4K%40elver.google.com.
