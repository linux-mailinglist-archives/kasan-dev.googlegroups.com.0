Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBI453HVQKGQEMUDMIHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AC45AD9B0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2019 15:07:48 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id n3sf2533452wmf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2019 06:07:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568034467; cv=pass;
        d=google.com; s=arc-20160816;
        b=gP3c2JkDWA7nkp6lClrHQQKS13hY8pVfdWFxRGw4omjvvFzzLwjdnAifWVX1Hhcro2
         ZtDz7X0zsQzMh+6dyIdYHyfSOWlzTbYPkumz8xUz9cYySnH9Wc9KMMWad9PjvwEh7mvb
         aL3iDYCmLNxJVFFJROHH4oaQFHz1Yrh1u4fiW511b63vk7OVa0QzzXlP61EHzhe3Ckm+
         sM1sdHgb1NZGYyCZbXFpxWtR7SnJgW15KvJogAlGXR5NEvvFv6Lah2SNiWtTKEhmfmaR
         fIjdyBKhXghqSfN5/XuombS+a+ippdNvMZJ4M+7zn1NdD1y353ZZzrnKndfCcvSbVh11
         h9hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=yK10CLGa4Pg7gcyLUfRRMYuOsGPzddxoBm8JbPou5D8=;
        b=lZWVhGOsTzVVFLd1BxmJeZ+ZPamW3NTRbaLpLH51PO72xxyrKZP0FJb7YfAtK9eqyw
         gWBKQBBbCeJSVfKLgUd0Y4j8iH8UK0zJhXUusYEa2MQ+tW0sb9QMGChHn/UvZbW/zQXf
         d1YU0ZjqihtF8AgbA9nGzgHqt19FjXIhjdGmZ4/+WT5+/4pVWkXfgNF6iILCUtCof3O8
         HpokWVf8Vl74415RJejYdDKETbZIgO1kAKu2XSoJSK/T0S/MKdt+3BVDFINXQB5Q1gqy
         dFb3lFtMTfoGO3hADZycoY3O9+zA0aHsPTnfFSJlzXCTa89NcWw07FE+5MS06fzf5fB7
         grDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yK10CLGa4Pg7gcyLUfRRMYuOsGPzddxoBm8JbPou5D8=;
        b=N55Gsjyp93Zg5B59o4ZNoRm/9YfCdRHzr7hl0voE3libvfGve/aL7PkPK2LauO6G57
         OToZX2dv5HfHwyPfcV3iBHB4bly7pH63H+Dg8/nQQ+Owozzkhe0Xniq0Q+T8DCC1mSS5
         WmJu9Mfsh3NBA7zDgRsHPjnLIPseml3DF4t7yWHmAva3+ryhxdaKSDFrs/3eCKOBMwu4
         meZs86sV7b0Z/jsWD3m058GAlFpBA0fDE49YKJM/wf8o6UU6rmt/wPI0YcceUQznuyF+
         tRXFpz+S8E17XPcEZERuLPY2+plKB5q+963jDg73+5klRn7b1VDDC1w5GlUhr3Fmznb/
         d0yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yK10CLGa4Pg7gcyLUfRRMYuOsGPzddxoBm8JbPou5D8=;
        b=JdQyYG/vZL4QshSKgdcKfmKNpBfpYsOvVS5PqmmZVdl9StzWLmGlXa+NAE42t9vpbn
         f/NZntXtplOljNBQdaPDb0FTBc/u9voU1NY4rcEAktjmnykjqM92oQsAbNhBK0tMguaZ
         z/vbZ+swkB1fNFDtzxA2B//UZwRcRXy4kijx3pKXfnqXJJKZLTNfvgjDo17FRBRr/CHF
         xu1ZP2kCErD6RrMsv6+x7y2WKtcKUmZciB/tZPqE1PlFWJXqDWfN3c4dWvleAvNiFs9g
         E1+JchvQFGe4BazoR+lLvGTSkcHds7TOYxEiyLFOA6RsmBsoT4UL6wUoI/23i79pAYj9
         +cPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVubuDhz2I09xiNvhFdrfnfPodwCfpBnlompTstqaoyI6k5ANzL
	KxSTEyl5v4lst5RvVk11bn8=
X-Google-Smtp-Source: APXvYqxla07Mu97OrA6J5jomSyiK5mP8IuLob7N/ISdHSJnJUuNmOzBpYmU8j/Vf7UfWBQ906reJQQ==
X-Received: by 2002:adf:df8e:: with SMTP id z14mr19969536wrl.81.1568034467856;
        Mon, 09 Sep 2019 06:07:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c44a:: with SMTP id l10ls5342950wmi.0.gmail; Mon, 09 Sep
 2019 06:07:47 -0700 (PDT)
X-Received: by 2002:a7b:c08d:: with SMTP id r13mr12552196wmh.142.1568034467120;
        Mon, 09 Sep 2019 06:07:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568034467; cv=none;
        d=google.com; s=arc-20160816;
        b=dbHfyy7J01uu30N9fUbo4yNODMpEaY0AeMQPx5qzH6IuqsnKrJuj7JeTInK7Ol4xKC
         e7VtlWgyeWpqlFHeNVvstNSG5Jq4ZNUj3GvdcSjRwbFzkwZj7y3ocDDKwDVycerFPCr4
         uQW56LIpFycSnkX028JPSuvc4e16IqUtDt2L0sFJYVaTN772iwnBke2XVvqMsm7PRHwI
         BSUCIcZ2ddcjIotdZF1luxNiljU5POrF5KRhPuqPCWpsn30Bo5UZowlzeYiePYyaVjS2
         SmjF09wz+VKNLN8gebSGi4jWtIytlFG6W22jCdnsoRmiM4Q8dTiXe+2iP152sT2kKCyX
         5ZBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=vwMMzMvxkQmYU+cgMn7bmQcXsQg2xN/Q4Qk7+zmeX+I=;
        b=B8l3lyUxCzu6oXKZCXvsowEeiLIkfwtcoedCNKg11id8P2waOflgJ8mlsCI0cPHmUg
         xvR5kIyufqdjhZ5f0chsWdtGvK0ndUFVMYKEbswWFP8D/dWN2lntBbmJDE6zxGP4w3kX
         fQZ2RXV0L5IJA2gZl717F9VqT5vxKAXdrm/FtH1kMLwzo5oltK8+CLT4XH16/rr4FkLQ
         2dtCtGvUcoUAdld+Dzucl1fEzn2IBPaZM7HUqg99y29OA784OO5UGczsl1VLw2rCUHf3
         8YyyRqXmVWeIqHjOKIaALAlYtgHEsUrbz+enOMKA3KEyYpS5lhB2WpLV5yTYfNd0yjL/
         hs1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id m18si820519wmi.1.2019.09.09.06.07.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Sep 2019 06:07:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 737C5ADDD;
	Mon,  9 Sep 2019 13:07:46 +0000 (UTC)
Subject: Re: [PATCH v2 0/2] mm/kasan: dump alloc/free stack for page allocator
To: walter-zh.wu@mediatek.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Thomas Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>,
 Qian Cai <cai@lca.pw>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <d53d88df-d9a4-c126-32a8-4baeb0645a2c@suse.cz>
Date: Mon, 9 Sep 2019 15:07:45 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/9/19 10:24 AM, walter-zh.wu@mediatek.com wrote:
> From: Walter Wu <walter-zh.wu@mediatek.com>
> 
> This patch is KASAN report adds the alloc/free stacks for page allocator
> in order to help programmer to see memory corruption caused by page.
> 
> By default, KASAN doesn't record alloc and free stack for page allocator.
> It is difficult to fix up page use-after-free or dobule-free issue.
> 
> Our patchsets will record the last stack of pages.
> It is very helpful for solving the page use-after-free or double-free.
> 
> KASAN report will show the last stack of page, it may be:
> a) If page is in-use state, then it prints alloc stack.
>     It is useful to fix up page out-of-bound issue.

I still disagree with duplicating most of page_owner functionality for 
the sake of using a single stack handle for both alloc and free (while 
page_owner + debug_pagealloc with patches in mmotm uses two handles). It 
reduces the amount of potentially important debugging information, and I 
really doubt the u32-per-page savings are significant, given the rest of 
KASAN overhead.

> BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x90
> Write of size 1 at addr ffffffc0d64ea00a by task cat/115
> ...
> Allocation stack of page:
>   set_page_stack.constprop.1+0x30/0xc8
>   kasan_alloc_pages+0x18/0x38
>   prep_new_page+0x5c/0x150
>   get_page_from_freelist+0xb8c/0x17c8
>   __alloc_pages_nodemask+0x1a0/0x11b0
>   kmalloc_order+0x28/0x58
>   kmalloc_order_trace+0x28/0xe0
>   kmalloc_pagealloc_oob_right+0x2c/0x68
> 
> b) If page is freed state, then it prints free stack.
>     It is useful to fix up page use-after-free or double-free issue.
> 
> BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
> Write of size 1 at addr ffffffc0d651c000 by task cat/115
> ...
> Free stack of page:
>   kasan_free_pages+0x68/0x70
>   __free_pages_ok+0x3c0/0x1328
>   __free_pages+0x50/0x78
>   kfree+0x1c4/0x250
>   kmalloc_pagealloc_uaf+0x38/0x80
> 
> This has been discussed, please refer below link.
> https://bugzilla.kernel.org/show_bug.cgi?id=203967

That's not a discussion, but a single comment from Dmitry, which btw 
contains "provide alloc *and* free stacks for it" ("it" refers to page, 
emphasis mine). It would be nice if he or other KASAN guys could clarify.

> Changes since v1:
> - slim page_owner and move it into kasan
> - enable the feature by default
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
>   include/linux/kasan.h |  1 +
>   lib/Kconfig.kasan     |  2 ++
>   mm/kasan/common.c     | 32 ++++++++++++++++++++++++++++++++
>   mm/kasan/kasan.h      |  5 +++++
>   mm/kasan/report.c     | 27 +++++++++++++++++++++++++++
>   5 files changed, 67 insertions(+)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d53d88df-d9a4-c126-32a8-4baeb0645a2c%40suse.cz.
