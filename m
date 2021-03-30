Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBO4TRWBQMGQEGNLTW7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id E3AF834ECF3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 17:54:35 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id w16sf10443668edc.22
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 08:54:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617119675; cv=pass;
        d=google.com; s=arc-20160816;
        b=umeU0fNc7VbFGUtfD4yi9u/n7HdcFq5QU+VDYPFN7kiNJPvXochCe4mw5fY2/VlIv7
         jVTUEqKjJm/eMcUK9zZeLoqGv6siffy65P9KNxovHWeFq2Q64EPsxqtTalcvF+K9eIry
         zCneekNPSzvvQEm3QFQkWtoo4Tv9nIGqLN0nF79ZvJnpiLkr97hUTKYOuw+TD5rHscNA
         YIbo+P4OOUAvzYRz1H73UFiqDwvWBsYPA5TRartn9/94ZqdVMNabxGwzcLWqrkdCc2xu
         dJi9pJWp7PAr3xc0ObBauWIkvbPLtkMi0KgYYeapV/TiuAp8cKjmOpMDQjzvgxf/UGU8
         O9pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=55PjYYXI8tyhnpccaNGdFrOxD0kDI24gzhuLKZY3Q0g=;
        b=FBF2PBMzSAJ1qwhJKreRJT9jz6lwYwv7KQiC4oyt82wpVAya16OW6m9dOmy8fDs4vV
         2P7dShHiw6Pi0VgOjjXnLye2TwHtg8SKagM8rpnjhMaZhpU629MwTcWm2Ro2Oh8fVfJJ
         LJeCEXms2L6dSC4Nx1Zqp+7dqMnqIcmmpdU7ffC8U68WInArj31YBIrVHa+GVwSD8ER3
         3/ACPNs6kjKVL/I3GM5BNybVT6mujbMh5flP4fsjU+dMNEyMeT6O153sr2HxNElG/mdM
         60MA+g+YXWw/64HpPryg+wk6FJRFnWuhtr6ehrD0UbRsMQtfTuEJrwZvDWiLYITx3RCe
         cHpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=55PjYYXI8tyhnpccaNGdFrOxD0kDI24gzhuLKZY3Q0g=;
        b=G3luc2EFdi7UoDlZeAizNVLn/UD8xJCtRg1b77EilBXx+Hw2UHy/LsradrCjm2CjNY
         +YPkpOfrKog+BqR03CnLJzScjRfPX40BRzTTMcLbC8hAJI9Q5B4fjGLwTxhADXSJNoci
         4WuSm8K/q4EQKzoa3E19w2/vuL6uoS3NAPkxlgYBjmU/eiNHOtJC5Y2FoHzJvJVMtUdC
         +NPClzem4DQjlP6hRY/sGmXUkxbjBqK43qqyrPecrB/Ox4pfDeC7xy8bxT6NCnp6L3rV
         izQBDEwxBvpyTwiIB/qpwnOoBQswRpTeCu4fC+sL5NQnqY8zcSIMuJQ1FIGXcNqXxzNi
         Qr/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=55PjYYXI8tyhnpccaNGdFrOxD0kDI24gzhuLKZY3Q0g=;
        b=j/c1z3+LKMMA8SsmDjDVq0piALz+i44Lm9qEl/svJ2IA7ONYizc3G5lqbqP1YHoA6C
         gJjiNLKzAC9IXIy5VEZ313n1glmjPKU3ptmRuaZ03wN/eG0/0CsjL9IoYP8WHVUXBWno
         NmAFbX+oFCwQojgDCi06rbI2UE3EJykWRmOtii1UX9NhU8d6CPLdkGlG16xFFyzxcoZ9
         8HNNZiF2BAtmJeCe5NqswxCVMGYLyk7fp+6jpgOLr5A2405AvMAtxsrC5AzD5DD2OpNz
         jwP1YPseXadkH88CL2rjNeqDpvI00AvH6cTNb2dAQ1qYhzpPv30OCGp38I3OG8Nn0ooU
         SXyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qXupbpbqLZaju2DJVzcYpu4TAlSc1/KOpLgTlJOERTUDJO88E
	336qcG1T1Opxpofk8DpWlTM=
X-Google-Smtp-Source: ABdhPJyUncwWCZKyrxq7MyrvrzhSkh5UNA/V7tG+UVf2LYFjCLTDUD0HcDrVZmxHEi6VzNs2ULQXFg==
X-Received: by 2002:a17:906:1986:: with SMTP id g6mr33664871ejd.533.1617119675745;
        Tue, 30 Mar 2021 08:54:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:41a:: with SMTP id d26ls10380638eja.3.gmail; Tue, 30
 Mar 2021 08:54:34 -0700 (PDT)
X-Received: by 2002:a17:907:98f5:: with SMTP id ke21mr34222786ejc.552.1617119674779;
        Tue, 30 Mar 2021 08:54:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617119674; cv=none;
        d=google.com; s=arc-20160816;
        b=HdOoESkV/vXbc+YOJwUqJB5dOssGKBKWHPagswg2W3sdD+g7lQd9la1LzEyZPKk655
         j/jS5GKBXzaqMcySQxGBdbX0iLHKPRYuDNGhm1qnuWWTXYNwtRcRFpbTmKyl1/z5li7P
         Z4YP58/knrfHeEux7gpwU3a74KVmyfylysltvhE9KMnpPX+dRADez0tBXbSWfW/kq4HF
         yeRkIyCwN3JrOoE98Yd7ORRsFOjq9asLAPSUuN2KPZq1W3ok3LdKh4nb4/XK7MhTaNZZ
         iSvLQp8dS+YoCd9DQmgnx54QLdPFrjsFQnAnJu53xsXSBURrlWk186CrbIjPowczbZGK
         gcmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=64b3fdMPlVJUNEUsxnzXgqJK3VMxYzeiBjitNt1Dkog=;
        b=wIzj9zBGIe5FluwcTIlfy2RldjVsiihPL1y5kUWmL0DSF4+DUtFtqT3i6age6Vni8P
         kDxEsoykAG05i3hyJp3BRm2/Nmwc3xLOO6m6Fnf+hSiBUh+rQxRUrFornV04GPu85KBN
         8E6kZtagmLZpX+BSaP7n4XzSKp99w06D9oUOTuXvXLQRsSeOFPBW8Bz74ZZUqovfZ7wX
         AZHtSLOyH1r3fo20MDAQTIEoUlJySH5YMWhqYwSeexNhsTIozjOnqDO6NxVl7N+NpVZg
         oHKmLgi2vIwhBDrUZA5d+QBKH0y1uNK4vsuMBiad4SOHiNJn5Kn+Q/xlBBcUOq5XydPP
         A2xQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id ck26si547223edb.1.2021.03.30.08.54.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Mar 2021 08:54:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 44DADAF10;
	Tue, 30 Mar 2021 15:54:34 +0000 (UTC)
Subject: Re: [PATCH mm] mm, kasan: fix for "integrate page_alloc init with
 HW_TAGS"
To: Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Sergei Trofimovich <slyfox@gentoo.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
References: <2e5e80481533e73876d5d187d1f278f9656df73a.1617118134.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <115c3cd4-a5ec-ea4c-fdc8-a17a0990bd30@suse.cz>
Date: Tue, 30 Mar 2021 17:54:33 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <2e5e80481533e73876d5d187d1f278f9656df73a.1617118134.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
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

On 3/30/21 5:31 PM, Andrey Konovalov wrote:
> My commit "integrate page_alloc init with HW_TAGS" changed the order of
> kernel_unpoison_pages() and kernel_init_free_pages() calls. This leads
> to __GFP_ZERO allocations being incorrectly poisoned when page poisoning
> is enabled.

Correction: This leads to check_poison_mem() complain about memory corruption
because the poison pattern has already been overwritten by zeroes.

> Fix by restoring the initial order. Also add a warning comment.
> 
> Reported-by: Vlastimil Babka <vbabka@suse.cz>
> Reported-by: Sergei Trofimovich <slyfox@gentoo.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

I expect this will be folded to your patch in mmotm anyway, so the changelog is
not as important...

> ---
>  mm/page_alloc.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 033bd92e8398..1fc5061f8ca1 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2328,6 +2328,12 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	arch_alloc_page(page, order);
>  	debug_pagealloc_map_pages(page, 1 << order);
>  
> +	/*
> +	 * Page unpoisoning must happen before memory initialization.
> +	 * Otherwise, a __GFP_ZERO allocation will not be initialized.

... but the comment should be corrected too:
"Otherwise, a __GFP_ZERO allocation will trigger a memory corruption report
during unpoisoning."

Thanks.

> +	 */
> +	kernel_unpoison_pages(page, 1 << order);
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_alloc_pages and kernel_init_free_pages must be
> @@ -2338,7 +2344,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	if (init && !kasan_has_integrated_init())
>  		kernel_init_free_pages(page, 1 << order);
>  
> -	kernel_unpoison_pages(page, 1 << order);
>  	set_page_owner(page, order, gfp_flags);
>  }
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/115c3cd4-a5ec-ea4c-fdc8-a17a0990bd30%40suse.cz.
