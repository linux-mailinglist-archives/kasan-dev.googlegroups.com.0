Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBL62VOKQMGQER2ZKH2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FD4D54DD1C
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 10:43:28 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 2-20020a1c0202000000b0039c94528746sf801342wmc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 01:43:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655369008; cv=pass;
        d=google.com; s=arc-20160816;
        b=O5I0OtihCjdhS/40Pt8WVIzRK+ncF7XgiyrNSHkxvA3hWHH3DP+okz360aPE0FBOo1
         sp+uonWBWBUvTBnS42N/KUq1xo3VZi6Uc3jTt/wHC58/uhwJ6pgvhH1ltjzj0xypSw5t
         iZJYSX51ECY05zXNZ0J1cw4Sk3xthhUz8nbdvnux1jWLz8oIBGJkfUrBuWGnCm7IjOFI
         +w63MKKwrtey59ygCzCv1pqDbRoPPiNHkTv1qw3DrioOKd8PVbZQ2rPWF0x5DL6wcL9c
         2g9w73Chi/b55rsnM3npGbnD4BkF9tRCfFEP5Z5J//1nKGDDYVXvRr2TJ6uPUVGzbYcc
         EfVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Dud4FXq8iZO4TcLURPk8N2KaRpiy7EE1/fRyBL9Xx2g=;
        b=Ir2mOqSkkNy1SksB0sQBKq5Af9wwZtWoR/dZuVfXUYzQ5Qu8etmdFwgt9Jz9Qz3VbM
         hoUultpmHoervrrwd1XJCFd7ATazT28xJl/cGuLkV6766XffOsypWER7tfsTkJvxf+U+
         zP2ddOo6CvE23XCttfx8Cdvd2+7z6bleCqJD0nTJA1J7vT+O25IbY0l5X1PxlZDBDpls
         7UTTayYt8CS4ZWCV6PRRTu7HnQCop/JJYrTSoiZ8rc+1ARM6WpuSAOalC+yg0a4FQ22J
         zyPBL8IR5K1GzHrm8ZundhSYaQU3XIeN8n/nzhjl5ne2lnIOSuDQ5RvPVvhRSZt192Rp
         E8rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dud4FXq8iZO4TcLURPk8N2KaRpiy7EE1/fRyBL9Xx2g=;
        b=pGkh9CUKO9D/77YzvmWWuL4BLx/1uNX5kJQpRHZKTG7OLNrs+3MHBi/hxIhuDIcrM7
         3l03EDEfBfGXdPnOR+lkReBObZNADGrbR1L0p1JHRWiY9dsia2Hkl9QZ+739ujdaF9z8
         lZt4h3sMeyBKjCFIt1SlvO/S10gqdXB5W0NhVU88NSqs64eY8Inzotw6nhDkuPKT/kPL
         ZyDyW8P5n3/jFwmUlg5w0CCb683xCMFy1x/AN4+Pmch9C5C66h79MJkc4oncdUtODPX8
         b5bMlFgd6ptsYdkwB8zJpEvqTbLTXwCXpZqgam8sDiCFfST3r8BW4fsOxBTXiYowG80E
         lHPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Dud4FXq8iZO4TcLURPk8N2KaRpiy7EE1/fRyBL9Xx2g=;
        b=VQgnmzQnpnr6OhfUbU68cglMxgJVsTiIc5qEbrYGhvZJ0nk75ygiV30oE4Qv3nVOJ3
         /+yqqzfFED0IBXaS30D6tXk3sxa6sLPG/RG+yTjVyU9BbsJZba5vkI7h8GiYP+r7N8TK
         apcBxoRpo8yd4X8osecn0t8dqF/ZaoHA82a7Npi0qpUtZmsvk/MDhW8XP9llWBvt2u+h
         C34alWBh5AFldDidJ0dCbSASdopu23b8YlVr1gPiurLa4iuW+JzQ27WA7SNsu2qC4KAm
         wc7yXIiV4DB0OYITp2++F7HIOvduPMpF5X53IAvkktxjPSmLQMA49qOB7fE5/T7Ba3Bg
         TDKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8/L0i3yrLNgNslG36EvszN3P6Dm6iuxE/W2MyIFvSmSTj39YYf
	ZuvrxCSeEHdp35ThsdUyf54=
X-Google-Smtp-Source: AGRyM1ufXGgiYfgagR6imOH9x/kVQIk4dS1lnuXOCreJMwHtwOGHTd8GhiSrtv240encEA1NFGXnOQ==
X-Received: by 2002:a7b:c856:0:b0:39c:3b44:7ab0 with SMTP id c22-20020a7bc856000000b0039c3b447ab0mr3789130wml.117.1655369008033;
        Thu, 16 Jun 2022 01:43:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d20:b0:39c:4b30:51b4 with SMTP id
 l32-20020a05600c1d2000b0039c4b3051b4ls637313wms.3.canary-gmail; Thu, 16 Jun
 2022 01:43:27 -0700 (PDT)
X-Received: by 2002:a7b:c003:0:b0:39c:5642:e415 with SMTP id c3-20020a7bc003000000b0039c5642e415mr14328906wmb.111.1655369006998;
        Thu, 16 Jun 2022 01:43:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655369006; cv=none;
        d=google.com; s=arc-20160816;
        b=kvShUPXqYgB0lqmHOe7oFH2Jxu+Q+IaMeTC8pjX+rid490eX0ahclujawgYZIJdsJj
         RMjk89TFzOfh1NSEGIrm4TelBBg8q1D9rbuQ5/KvV5lTDZT3SIqXolOkRhBd97ot1rrh
         LzsMjHusJjcdrt7rtbolj2BPB4a5MM84CC2ht5lPRzOMCZJQY6I13xGN18xa1wwfV3E6
         zJZIYrzVyHHPllLkD8w5v5H3orEbmwwP/RS9NM1WODJIEutVfKN5Z9m+Y5vdrf+pU97v
         7ogR8kbJSw5WVEghOKClt5R5W1D+K97FEdT9prqTTez0A7mJIfyRTBqplMqBom36zh+p
         8RSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=j8pxUgTGnrr2bMHaOyK806sYPY/0uqx4pIpmlPYEC6g=;
        b=gW1ggIT1WYi9ZCqu9ltfVYRJ4zeW3WPt2KSWA9A8pKc4PR2VXAq388cebizStfQrD7
         vQSZQROP6CuPbosd5lWuv9NoxsgguF9VGSxXpRHeBWkRar5pEf0T7DpfQ5FiTrgRp7ui
         Bn8WNUV4eMw5Bl3Z0lo/zu5UxjZho06q1lqtuMaLr9U2v+CGlSaCb2+lD1ioOrNMllW+
         41PYwD404/of00DcDvax8+ZqWowXa+vTfXAUQkk1/NPx0ghPeCbt11SZfywtA0Noi4Z2
         guRBMqlyNVYMkGBgH81DmVJn9mucYa4RhcL5bdyLhgwJe2Y/rtiNlqb4FEObcPvRb9Au
         7duw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t15-20020a5d49cf000000b0021a07a20517si44584wrs.7.2022.06.16.01.43.26
        for <kasan-dev@googlegroups.com>;
        Thu, 16 Jun 2022 01:43:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7397C12FC;
	Thu, 16 Jun 2022 01:43:26 -0700 (PDT)
Received: from [10.57.69.164] (unknown [10.57.69.164])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7F0ED3F7F5;
	Thu, 16 Jun 2022 01:43:24 -0700 (PDT)
Message-ID: <72dd2ba6-3650-2d71-3027-0a17c46978a5@arm.com>
Date: Thu, 16 Jun 2022 09:43:22 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
Subject: Re: [PATCH v2 3/4] mm: kasan: Skip page unpoisoning only if
 __GFP_SKIP_KASAN_UNPOISON
Content-Language: en-US
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>, Peter Collingbourne <pcc@google.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arm-kernel@lists.infradead.org
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-4-catalin.marinas@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <20220610152141.2148929-4-catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 6/10/22 16:21, Catalin Marinas wrote:
> Currently post_alloc_hook() skips the kasan unpoisoning if the tags will
> be zeroed (__GFP_ZEROTAGS) or __GFP_SKIP_KASAN_UNPOISON is passed. Since
> __GFP_ZEROTAGS is now accompanied by __GFP_SKIP_KASAN_UNPOISON, remove
> the extra check.
> 
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  mm/page_alloc.c | 12 +++++-------
>  1 file changed, 5 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index f6ed240870bc..bf45a6aa407a 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2361,7 +2361,7 @@ static inline bool check_new_pcp(struct page *page, unsigned int order)
>  }
>  #endif /* CONFIG_DEBUG_VM */
>  
> -static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
> +static inline bool should_skip_kasan_unpoison(gfp_t flags)
>  {
>  	/* Don't skip if a software KASAN mode is enabled. */
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> @@ -2373,12 +2373,10 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
>  		return true;
>  
>  	/*
> -	 * With hardware tag-based KASAN enabled, skip if either:
> -	 *
> -	 * 1. Memory tags have already been cleared via tag_clear_highpage().
> -	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
> +	 * With hardware tag-based KASAN enabled, skip if this has been
> +	 * requested via __GFP_SKIP_KASAN_UNPOISON.
>  	 */
> -	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
> +	return flags & __GFP_SKIP_KASAN_UNPOISON;
>  }
>  
>  static inline bool should_skip_init(gfp_t flags)
> @@ -2430,7 +2428,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  		/* Note that memory is already initialized by the loop above. */
>  		init = false;
>  	}
> -	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
> +	if (!should_skip_kasan_unpoison(gfp_flags)) {
>  		/* Unpoison shadow memory or set memory tags. */
>  		kasan_unpoison_pages(page, order, init);
>  

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72dd2ba6-3650-2d71-3027-0a17c46978a5%40arm.com.
