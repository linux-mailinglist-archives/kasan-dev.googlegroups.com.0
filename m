Return-Path: <kasan-dev+bncBDVIHK4E4ILBBUUDWLWAKGQEQJBACVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id F0502BEE38
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 11:16:02 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id j2sf677138wre.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 02:16:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569489362; cv=pass;
        d=google.com; s=arc-20160816;
        b=u07GH/XNfN5J9clAVgateRqiqd7d5kTe722O4x2yap+7RbREdreeWCF0sZUoDCI181
         tEzOo38EnazPtn8xKe+4PbkkRxSnkmiuKcdXY0YN/8WT7xVsJWjtJrbzhjLIWFZ8ZImP
         uf1ns/GTE5uJZez8JfjfiEWZ4tCp9XVo2q/Lc8lKTVI7gSAblmwwyTSqtVn97x1osBI5
         QnRlTEkIzcbXxlL8bGmJHD/deqw0poUZsX0ceqiVZHgQ/SIwA8q2A/HI5e26SQJYTptz
         RXkl/n6nvqBzMA4ydYEW0CH4T+ndVkw/3m81EakfGVlgPy36nKL/kWuwKBzE4THeFqsa
         nGPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=vpRFlqLs/P8a04dH/qk0J09A4DevIg7gtyOcc6cULto=;
        b=r2ynyAU/ptz1ivFNEVqwcI67O92D2wUbBapiGWsVMIzEDSVbKmBKP/4P1GLyp0JKst
         450UdcKy7hQ8wFW86LUIGSEFq3NNJH760uP5q1yG1nU0rkaqXyv93O3UCXPgBLwE0lmW
         Jb5RKzK2fbJRjh+s1Dl3OH1rty/jOgSbI427Rmy+szCv3wk3CoKxLyF3eGYNxFWfQmQy
         NjEGgoi0MjMtp89GoBIYEKHMeosC00Vd72q0O8rCM/5Rw6vDdd+9sgr3WuLMlFBTr3I1
         sUKm1svEZvz21HFlsLbmaGhuk1dDpJCbD7K8u/jWQYNkNPditifvnkvOzdXJEJS6TbWw
         w1ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b="mSJPHGU/";
       spf=neutral (google.com: 2a00:1450:4864:20::541 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vpRFlqLs/P8a04dH/qk0J09A4DevIg7gtyOcc6cULto=;
        b=Qi3Eg5tEwO6rH/9b1LEZgnJFMSWZgtP73BBwFj6TnTGHHMUNNspskak/wnOLzeqlfW
         yPViSyJovFKA2nOZ8C99pTyhLDjU41atkPagvFzlAox+4nBlWNQF/OMbr1X7X0fVmWMs
         XfhiNcGkhmOuArR332gmm7KHJo2LlKBEXR5dqTlG/ssTiw4yzCCo/uBWTsjGp0y6bS6W
         +LzcbEr7BCCgS56Cn/dmtNFYJznvoaWdNBs4cJdn1KZRPXXl7y3K+astYAIZYia47jln
         LZ8ehr0huhNLg+VLG6yc3azYlcQC6my3oZgNgW9pCPTnhvuztUQCKT5XiA1i1OVwC6pO
         cIdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vpRFlqLs/P8a04dH/qk0J09A4DevIg7gtyOcc6cULto=;
        b=qh0m2HUCJgh30VWjUjYlWCPnzRMUSaFd7qtQcQ8y6ZX5nyr39Xoh+2Jwn+nip5CIQY
         +lBQTKm1J51EEM0s5wDrcYQeGSEHXRUs6etIU0cixfXpWO9uhjAhZYzOtIA3ZnqrI2f9
         J699MA54e5BiBkMyFnr6z8lZFGEjT7mu9HuIxNBzcKotITGT2QQkf8KtHcoiP9/uvP/1
         iGPDIIyTN1crMEDj3DrpiIT6G11mtOEk7ZMQcOePwqyfkyXorfMF92TchlxLtsMasYCE
         8/CdOiRYnxECzPGJMfA5oOWjpPgfCZno9Op6wmobl0F7Oh3lWSrto74lO5wwNb57uxnr
         NR3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXKJDplxpRp2HJmOk/ALNyoOtBKJMIOfOQ3GskPvnPRMRAL28B7
	8BBXtUfEnVp1PYQwcv7sAHk=
X-Google-Smtp-Source: APXvYqz2zWr/2EX0r9ffaOIp5OXNGHCnDjvVg6I09tdQm/IRe+LOgW1QPTIaUrZQ2WDmVEi5DrkeqA==
X-Received: by 2002:adf:e28e:: with SMTP id v14mr2088517wri.184.1569489362650;
        Thu, 26 Sep 2019 02:16:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e304:: with SMTP id b4ls433608wrj.14.gmail; Thu, 26 Sep
 2019 02:16:02 -0700 (PDT)
X-Received: by 2002:a5d:614c:: with SMTP id y12mr2166379wrt.392.1569489362176;
        Thu, 26 Sep 2019 02:16:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569489362; cv=none;
        d=google.com; s=arc-20160816;
        b=0qvKYS62524dw28xw7NtqJUX19KNwjnEVr8IoAA88mkj9Melbw7t8gpyBdUF06vJZi
         rmCPj9Z8muqIf0zFxFJBx1aL+Ou3MZT/+eXKVtHF6FlL4J2cvmx12Etzl1wYPRNAE4+2
         rciALtUEpvQA0Dv+HXaIcBuyU7VaqLSheRey6nghYa2opSo3G+Qn7C4bbgEMu/Than6d
         xJcT/qwkllw51t1CfcEamgVyzue5mVarBQpUjDun1VO6lPjVezo0ZdSP6Mpzvdrmmkmx
         PPBKny2LXq+7o5LLypCxJUt0xEnsHcgY8vPrBdblrpFFh9Y+q053UGR60cYzHiN+6GkU
         XUsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=C50uCIRZXB+UBz8ksrHz9YHG9QxeChHhVCa2axN7YVA=;
        b=dXBa0jN+eXHZ9Q+i2MRY+ZRt7h6ULtircKoUyYTxnS5ZChFE6793M63sVdLwfG7iSV
         F040+xiME430HobgXhh/vh7XtjZT4942IPH9QeJQaEOuS/VVuZXpaEqU6QQK6BOOKhJg
         slbKegiFWVYQsUB+SkOiO8RD49hKTul5JVV7dbzNPU5Rxl8vjneP8ysj5D4C++RVWUEA
         0GuppRBg6pZ9jm5+ge5KYHICSEio+Srn9N3cYX+zjeSMjASJf059iJZSrGYeBXuPzPxB
         8gFwBC1XfSVZs3+cEFMi2qB5XSzvJiALrqk5MI9fquI2bzHa8hvzn1Ym1t86lQfmTP1h
         /v5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b="mSJPHGU/";
       spf=neutral (google.com: 2a00:1450:4864:20::541 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x541.google.com (mail-ed1-x541.google.com. [2a00:1450:4864:20::541])
        by gmr-mx.google.com with ESMTPS id 5si483295wmf.1.2019.09.26.02.16.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:16:02 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::541 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::541;
Received: by mail-ed1-x541.google.com with SMTP id v38so1289029edm.7
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 02:16:02 -0700 (PDT)
X-Received: by 2002:a50:ac03:: with SMTP id v3mr2407789edc.113.1569489361850;
        Thu, 26 Sep 2019 02:16:01 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id o31sm352089edd.17.2019.09.26.02.16.01
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:16:01 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id 105B1102322; Thu, 26 Sep 2019 12:16:04 +0300 (+03)
Date: Thu, 26 Sep 2019 12:16:04 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH 2/3] mm, debug, kasan: save and dump freeing stack trace
 for kasan
Message-ID: <20190926091604.axt7uqmds6sd3bnu@box>
References: <20190925143056.25853-1-vbabka@suse.cz>
 <20190925143056.25853-3-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190925143056.25853-3-vbabka@suse.cz>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b="mSJPHGU/";       spf=neutral (google.com: 2a00:1450:4864:20::541 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Wed, Sep 25, 2019 at 04:30:51PM +0200, Vlastimil Babka wrote:
> The commit 8974558f49a6 ("mm, page_owner, debug_pagealloc: save and dump
> freeing stack trace") enhanced page_owner to also store freeing stack trace,
> when debug_pagealloc is also enabled. KASAN would also like to do this [1] to
> improve error reports to debug e.g. UAF issues. This patch therefore introduces
> a helper config option PAGE_OWNER_FREE_STACK, which is enabled when PAGE_OWNER
> and either of DEBUG_PAGEALLOC or KASAN is enabled. Boot-time, the free stack
> saving is enabled when booting a KASAN kernel with page_owner=on, or non-KASAN
> kernel with debug_pagealloc=on and page_owner=on.

I would like to have an option to enable free stack for any PAGE_OWNER
user at boot-time.

Maybe drop CONFIG_PAGE_OWNER_FREE_STACK completely and add
page_owner_free=on cmdline option as yet another way to trigger
'static_branch_enable(&page_owner_free_stack)'?

> [1] https://bugzilla.kernel.org/show_bug.cgi?id=203967
> 
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> ---
>  Documentation/dev-tools/kasan.rst |  4 ++++
>  mm/Kconfig.debug                  |  4 ++++
>  mm/page_owner.c                   | 31 ++++++++++++++++++-------------
>  3 files changed, 26 insertions(+), 13 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index b72d07d70239..434e605030e9 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -41,6 +41,10 @@ smaller binary while the latter is 1.1 - 2 times faster.
>  Both KASAN modes work with both SLUB and SLAB memory allocators.
>  For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
>  
> +To augment reports with last allocation and freeing stack of the physical
> +page, it is recommended to configure kernel also with CONFIG_PAGE_OWNER = y

Nit: remove spaces around '=' or write "with CONFIG_PAGE_OWNER enabled".

> +and boot with page_owner=on.
> +
>  To disable instrumentation for specific files or directories, add a line
>  similar to the following to the respective kernel Makefile:
>  
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index 327b3ebf23bf..1ea247da3322 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -62,6 +62,10 @@ config PAGE_OWNER
>  
>  	  If unsure, say N.
>  
> +config PAGE_OWNER_FREE_STACK
> +	def_bool KASAN || DEBUG_PAGEALLOC
> +	depends on PAGE_OWNER
> +
>  config PAGE_POISONING
>  	bool "Poison pages after freeing"
>  	select PAGE_POISONING_NO_SANITY if HIBERNATION
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index d3cf5d336ccf..f3aeec78822f 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -24,13 +24,14 @@ struct page_owner {
>  	short last_migrate_reason;
>  	gfp_t gfp_mask;
>  	depot_stack_handle_t handle;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
>  	depot_stack_handle_t free_handle;
>  #endif
>  };
>  
>  static bool page_owner_disabled = true;
>  DEFINE_STATIC_KEY_FALSE(page_owner_inited);
> +static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
>  
>  static depot_stack_handle_t dummy_handle;
>  static depot_stack_handle_t failure_handle;
> @@ -91,6 +92,8 @@ static void init_page_owner(void)
>  	register_failure_stack();
>  	register_early_stack();
>  	static_branch_enable(&page_owner_inited);
> +	if (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())
> +		static_branch_enable(&page_owner_free_stack);
>  	init_early_allocated_pages();
>  }
>  
> @@ -148,11 +151,11 @@ void __reset_page_owner(struct page *page, unsigned int order)
>  {
>  	int i;
>  	struct page_ext *page_ext;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
>  	depot_stack_handle_t handle = 0;
>  	struct page_owner *page_owner;
>  
> -	if (debug_pagealloc_enabled())
> +	if (static_branch_unlikely(&page_owner_free_stack))
>  		handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
>  #endif
>  
> @@ -161,8 +164,8 @@ void __reset_page_owner(struct page *page, unsigned int order)
>  		return;
>  	for (i = 0; i < (1 << order); i++) {
>  		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> -		if (debug_pagealloc_enabled()) {
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
> +		if (static_branch_unlikely(&page_owner_free_stack)) {
>  			page_owner = get_page_owner(page_ext);
>  			page_owner->free_handle = handle;
>  		}
> @@ -450,14 +453,16 @@ void __dump_page_owner(struct page *page)
>  		stack_trace_print(entries, nr_entries, 0);
>  	}
>  
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> -	handle = READ_ONCE(page_owner->free_handle);
> -	if (!handle) {
> -		pr_alert("page_owner free stack trace missing\n");
> -	} else {
> -		nr_entries = stack_depot_fetch(handle, &entries);
> -		pr_alert("page last free stack trace:\n");
> -		stack_trace_print(entries, nr_entries, 0);
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
> +	if (static_branch_unlikely(&page_owner_free_stack)) {
> +		handle = READ_ONCE(page_owner->free_handle);
> +		if (!handle) {
> +			pr_alert("page_owner free stack trace missing\n");
> +		} else {
> +			nr_entries = stack_depot_fetch(handle, &entries);
> +			pr_alert("page last free stack trace:\n");
> +			stack_trace_print(entries, nr_entries, 0);
> +		}
>  	}
>  #endif
>  
> -- 
> 2.23.0
> 
> 

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190926091604.axt7uqmds6sd3bnu%40box.
