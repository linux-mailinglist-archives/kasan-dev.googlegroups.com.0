Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB4NM5TWAKGQE75KSNMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id E01FCCDF83
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 12:41:54 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id b67sf14603559qkc.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 03:41:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570444913; cv=pass;
        d=google.com; s=arc-20160816;
        b=agtFiPdSQg6Di7wM54f8HI8q48vJH7ven7HQWEflDzjeOjuhwthkKQnXkBrGP9FyYr
         d+j09BdgGPJjiXSvq9/kYFQbxxL0L41EIyBbcCze/GMLZG7d+FR6w1yPlbL4upjiGd2a
         WBvd5/adbL1Gyw4Iw/nkMLiKhT2FpUoE9uW/v5HZI/ehmOdMF9czzLw0Y1B0Y0lS3pvN
         iqkpRfrESfR2aJY1v6LTrYTeMXIhqDP600+smYByCxjGo0ztfLLky2wPgQnLnrgPa13r
         n4QVSNOZw1+yQDakj4gIJWk9X3vvEE/PqpG2YBiZgZUdpV6SakD/xz6EM8Yhx+zsYg9Q
         kxtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=YqHaIzKLY08H/BFjBmkxY1vPHvHy2zhBvDMCvgWp8iQ=;
        b=W32pxV2+g8/ivnx/kYI9/Juk5YJLO3PzXZBTMCurU2/RwcQUeZOubUUcqrOXLB0pk9
         K2aajALHifet9bbdns3C75sGzJgWuis88RaFNf5qbBP58rWEpZUGzqOFZIPubMtDhe+k
         slRX4BA+fw6E8t+/emGOZfSS4uZIfOaTi3nyl6WtEzUXlXIiI1iygicnpTWT8UCBBC/K
         XvoMLliAZgGPuws/TmKVGdQD3WfSyrgPWtFW+gBLP3wdplCIvEffOXFAsUlXz3fcDHO6
         J2CSSA4j5VXAjIuPFgtXNGLF2CD37J1RWnywhxt5qdvJc7giHR17n71dB++gTCFqsTCx
         c59w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=LPp1jYpI;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YqHaIzKLY08H/BFjBmkxY1vPHvHy2zhBvDMCvgWp8iQ=;
        b=r5pXjUutN50+B9cKHCEZHeVh1LgcVYMaTQ4hbbbKXiRhjSVyoLqTlXQ8ZeWQI1c3Ad
         jGu6WXg5BROfSTXsv8cowZiTG80YlaLwFlBpUuqy6eAM6kKra4dJIm/UZLFrml+Z7g5P
         j1mgTQMgir2M73g2AWZZuWP+s3A7CSDZ/gAug9pqbogRTL0E4SWOekQS9XaqwAE264I4
         k211sM/WMoWviTszZvtrjiyRLIV+7ABMn2Yh9D8D47PQJGajUrUJx+eDaxKUURihCAQl
         yfiki25PLvC4gzgoInfx0iDMFaLt/sm2jgmLKJNK6e0bC8bTrRfihsG0y8dBPGLP/iT5
         Yr+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YqHaIzKLY08H/BFjBmkxY1vPHvHy2zhBvDMCvgWp8iQ=;
        b=FgbeVYqsJ4kLyIMWas9Y4vEzn/bQXQSQfC56oZMRs6GV34rIx0erwYiwv4nf8mUXTL
         TMHmo3+DKJcPofj3NDdmPlsLj7HDs7Nx3cZQsndJ0/xp2x3suVoes5461ULiSIOb4E9X
         CgdF0/PVbUDuNAkMlBKGe8153p5gM+WyWzNCYKrBjIfTnZsQyjIduNPSLlSssXnvSHuv
         1PcFcdCAIqNvC1cjg5HF0qrqs7PZZYg8qMeg8NRp7wwEGxEc0NL+z3l6zPMObrNFnBlG
         DolmZq4T43hOzPhToiw4UIS+DiAKKOOtlfmsxegYFlYPY6DGhoZrCgk0VwSV5u7hRiMR
         tXsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX2cyg5HJ2KR/G+KusZqet+8mucutyUUQE2Xj/H4YwM74FG11ik
	t+9+aJj344nEP+0a8dA8nNA=
X-Google-Smtp-Source: APXvYqyPwGCYjBIjszx8fsQK9zP0Vdfv5NhxLZZnxU8os6K1NZg23ACqRvWrP29LsJMSIYRHSWiNwA==
X-Received: by 2002:a0c:8828:: with SMTP id 37mr26942273qvl.44.1570444913712;
        Mon, 07 Oct 2019 03:41:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ef0f:: with SMTP id d15ls4813493qkg.8.gmail; Mon, 07 Oct
 2019 03:41:53 -0700 (PDT)
X-Received: by 2002:ae9:ef53:: with SMTP id d80mr23078481qkg.33.1570444913409;
        Mon, 07 Oct 2019 03:41:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570444913; cv=none;
        d=google.com; s=arc-20160816;
        b=yUpZGIsPy+k/Kc/4ebgAmyS9APbHkKODuWDFC+891bqAeHW4QA1E0hdsCfET/vD0qC
         9xDI0BChtY1usbqjZPAL2fyBZa7gz148nUK6Iby+xIkuMrSkV0lOSLMhyWqNjOWeZBEs
         9aX4o/TYCsvbgWaBQMwwOQt885voNv6mKFtoQrn0rpdkpaPyA7dpZNZHPVIrQYPZvwZ7
         k2V1P4fNKeKRCn2DTTHbf5p+mch9q/3lXRdOG2+91bYcS/wvrq8/TBihTSS8hDSJsIg/
         mKwlVP0x5nzv2YDaVPzwNMLhhMNMuQ8Q+RVGPjsruhcxtwjvkYZJZbQerou8SR+X4LAF
         0jBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=8ycSeDCC1GZiryzM3NK5XnFiikWmWhbkO4qYr8NwHI4=;
        b=LeUMHEC26aBk7Gu9Si3sFnMXH1UsoGmiMx+HRxGeSGJdFkwVLYhgxQJHYndaDys85J
         c7j+dNIv3hUyHV8MMeoGYMrfsHUlAQhGDoXEN78BxF+YWSlIm0s56WC9IlYnVYc4ii9J
         z/oTvAy1Kcoa60soLpzVLf+4AQOrohsbOMHgbAzkOWikdPzGKdLJtlCzPfQ+IkHtDmGF
         nvP7y6V9k4i7jUFYGq5qRlZgTjdBAVyHtFHYl7aTi6MqpJyLRL+6GwZgvSDEJAvMLPdu
         nymWCWn3PUkW/syHXS27j/gAngb1G51Sq9tmaxihlASqo/EDao3nZbfyAaTOWoT+IsSB
         LlXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=LPp1jYpI;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id u44si1365655qtb.5.2019.10.07.03.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 03:41:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id u22so12032044qkk.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 03:41:53 -0700 (PDT)
X-Received: by 2002:a37:bdc6:: with SMTP id n189mr20769736qkf.263.1570444912890;
        Mon, 07 Oct 2019 03:41:52 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id d133sm7699145qkg.31.2019.10.07.03.41.52
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 03:41:52 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v3 2/3] mm, page_owner: decouple freeing stack trace from debug_pagealloc
Date: Mon, 7 Oct 2019 06:41:51 -0400
Message-Id: <4DDB4C10-0EED-4B1A-A09D-656B2305B51A@lca.pw>
References: <20191007091808.7096-3-vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
In-Reply-To: <20191007091808.7096-3-vbabka@suse.cz>
To: Vlastimil Babka <vbabka@suse.cz>
X-Mailer: iPhone Mail (17A860)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=LPp1jYpI;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Oct 7, 2019, at 5:18 AM, Vlastimil Babka <vbabka@suse.cz> wrote:
> 
> The commit 8974558f49a6 ("mm, page_owner, debug_pagealloc: save and dump
> freeing stack trace") enhanced page_owner to also store freeing stack trace,
> when debug_pagealloc is also enabled. KASAN would also like to do this [1] to
> improve error reports to debug e.g. UAF issues. Kirill has suggested that the
> freeing stack trace saving should be also possible to be enabled separately
> from KASAN or debug_pagealloc, i.e. with an extra boot option. Qian argued that
> we have enough options already, and avoiding the extra overhead is not worth
> the complications in the case of a debugging option. Kirill noted that the
> extra stack handle in struct page_owner requires 0.1% of memory.
> 
> This patch therefore enables free stack saving whenever page_owner is enabled,
> regardless of whether debug_pagealloc or KASAN is also enabled. KASAN kernels
> booted with page_owner=on will thus benefit from the improved error reports.
> 
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=203967
> 
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Suggested-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> Suggested-by: Qian Cai <cai@lca.pw>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
> Documentation/dev-tools/kasan.rst |  3 +++
> mm/page_owner.c                   | 28 +++++++---------------------
> 2 files changed, 10 insertions(+), 21 deletions(-)

The diffstat looks nice!

Reviewed-by: Qian Cai <cai@lca.pw>

> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index b72d07d70239..525296121d89 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -41,6 +41,9 @@ smaller binary while the latter is 1.1 - 2 times faster.
> Both KASAN modes work with both SLUB and SLAB memory allocators.
> For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
> 
> +To augment reports with last allocation and freeing stack of the physical page,
> +it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
> +
> To disable instrumentation for specific files or directories, add a line
> similar to the following to the respective kernel Makefile:
> 
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index d3cf5d336ccf..de1916ac3e24 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -24,12 +24,10 @@ struct page_owner {
>    short last_migrate_reason;
>    gfp_t gfp_mask;
>    depot_stack_handle_t handle;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
>    depot_stack_handle_t free_handle;
> -#endif
> };
> 
> -static bool page_owner_disabled = true;
> +static bool page_owner_enabled = false;
> DEFINE_STATIC_KEY_FALSE(page_owner_inited);
> 
> static depot_stack_handle_t dummy_handle;
> @@ -44,7 +42,7 @@ static int __init early_page_owner_param(char *buf)
>        return -EINVAL;
> 
>    if (strcmp(buf, "on") == 0)
> -        page_owner_disabled = false;
> +        page_owner_enabled = true;
> 
>    return 0;
> }
> @@ -52,10 +50,7 @@ early_param("page_owner", early_page_owner_param);
> 
> static bool need_page_owner(void)
> {
> -    if (page_owner_disabled)
> -        return false;
> -
> -    return true;
> +    return page_owner_enabled;
> }
> 
> static __always_inline depot_stack_handle_t create_dummy_stack(void)
> @@ -84,7 +79,7 @@ static noinline void register_early_stack(void)
> 
> static void init_page_owner(void)
> {
> -    if (page_owner_disabled)
> +    if (!page_owner_enabled)
>        return;
> 
>    register_dummy_stack();
> @@ -148,25 +143,18 @@ void __reset_page_owner(struct page *page, unsigned int order)
> {
>    int i;
>    struct page_ext *page_ext;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
>    depot_stack_handle_t handle = 0;
>    struct page_owner *page_owner;
> 
> -    if (debug_pagealloc_enabled())
> -        handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
> -#endif
> +    handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
> 
>    page_ext = lookup_page_ext(page);
>    if (unlikely(!page_ext))
>        return;
>    for (i = 0; i < (1 << order); i++) {
>        __clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> -        if (debug_pagealloc_enabled()) {
> -            page_owner = get_page_owner(page_ext);
> -            page_owner->free_handle = handle;
> -        }
> -#endif
> +        page_owner = get_page_owner(page_ext);
> +        page_owner->free_handle = handle;
>        page_ext = page_ext_next(page_ext);
>    }
> }
> @@ -450,7 +438,6 @@ void __dump_page_owner(struct page *page)
>        stack_trace_print(entries, nr_entries, 0);
>    }
> 
> -#ifdef CONFIG_DEBUG_PAGEALLOC
>    handle = READ_ONCE(page_owner->free_handle);
>    if (!handle) {
>        pr_alert("page_owner free stack trace missing\n");
> @@ -459,7 +446,6 @@ void __dump_page_owner(struct page *page)
>        pr_alert("page last free stack trace:\n");
>        stack_trace_print(entries, nr_entries, 0);
>    }
> -#endif
> 
>    if (page_owner->last_migrate_reason != -1)
>        pr_alert("page has been migrated, last migrate reason: %s\n",
> -- 
> 2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4DDB4C10-0EED-4B1A-A09D-656B2305B51A%40lca.pw.
