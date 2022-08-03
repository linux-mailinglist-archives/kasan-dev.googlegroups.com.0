Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAVMVOLQMGQEJEWJ2FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 715105892FA
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 22:09:39 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id v24-20020a7bcb58000000b003a37681b861sf457011wmj.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 13:09:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659557379; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ao8L10LTpyqo5Aoiy+LOVPv0myjDS+c+W0+IcidnNRr6taO6EvKrQZ9LvxszDDA23A
         MACaxJnIMLPQwkrsYMaA39U6WZYjl/qnLFGWe498gcEpz7BK+nC59hNcAP1l5QNEBX1U
         gQMj501UlSfltDHoUKDMzg/3Ajt81TjT7EqswTd3AlZXF0aLviZ+HkwG1KvzhcYCrAI2
         OrY8kFXPWZqvKqKASxmYVqANF3Y9rLeEbAICNlXHFdLWsVslCq+7OLzQIveMY1YAcGlt
         zV7EwJToPMpRcR/VdZEu5mVy7jKtJ02eZ1fyAyyyW5dilYv5nfIBQnyGGc2bfZHU0/Xa
         wRDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qW0ww9wJWmWxd8sGnafiDBxRmQjtUb+bNPsDollheZY=;
        b=tDdqOCS6jViq71zMfQUP0yhsGRDhpmfzC//dG/FcPcmSDMD5nSST3s56qc3gfx/59w
         3OGV5Cwpj7gZShGA7LNJP96ZjuAR/ZpV+bPD0U4ZHvYPNd7cEwF4ROcc3qlG2fFk4xVA
         8vV/R+XA6VnCvoBTrFQV2en+jN6PcBY29wU4dvcNUAgFNjHdjPuNvpFgybvGiAzUDl74
         2nq++pWPb1PWvNnjSsgzslsCaaiI8mTyafHS/iKnp4a1pBwuna7spTsPauMp6LicfwEu
         W60jThXmT6JY70keWrR0df2GHt+wnvOMGCQ+DVZYyUYqSJa85nWFOL+iw21Upzlwqcvb
         huZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mHTRC+oF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qW0ww9wJWmWxd8sGnafiDBxRmQjtUb+bNPsDollheZY=;
        b=kv9A8SY5NK7RVgnsTPMMAOUT3oSjTXL4CD6m1JbSSlOohZWXHKutlXcX21fQR2ZZwp
         6oTjvYioXF6nwhBTSKgsvVQkn2sGBrQgII+2YEy8QvuaOMPztS22B05ODztT2tV71llp
         U0ozk2FDDtS6vBcIQL2g/xmhosneqBeln9Q6/+uFD7uKWUpnvijJHTEFRirMBIDdH8dI
         mXwD0uvapW1ScWtRVnxAvstJAWhAzskSkJtKid2PFKF/hLEyWqWtQCU3iKnezDoSgC9t
         gM/3wgd1DwkKtfBn31ULUX8CMyTgzTdH8noy2EA55vmiVKoVgPUrVY498q5b53cAq2AO
         4k1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qW0ww9wJWmWxd8sGnafiDBxRmQjtUb+bNPsDollheZY=;
        b=WP9SnKRM0hijga432UpDso3VFW5tW8EXgQVsa/7zDs65zq3GlMONL35sHZ/UVwvp6C
         X88ycXNW5MgPWlTkHvoW/uSZCj8uicTzlz37fdrA7S69maoEDRJNsDUzhIAyitSOlu0a
         I7mCES5PQX/G7nXc32AdNlaIJaR1alXT+HrM0ugfzh19j7ursPPbcWl+IKCIfT4dQ+Qi
         HN7OJI3T0vRskBBcMRdUAAY9lK+9a9GQt86Fq9f7AncUmLU22NVhKrQCXtOkJjXEFTSz
         PJ4RnWxEHpIaq+eiSI5D0qNorxrx7hdM0bVVn5HD2qHjacFj11anIc9WJqmIPiXa83+K
         DUpA==
X-Gm-Message-State: ACgBeo3HS7q7JQrDb4vnEAn+VHId2r91PWPo9zAdX8MUbS96r9SRd9oU
	aDHWmgZEUqPkLa/WvcJss2k=
X-Google-Smtp-Source: AA6agR6HZDMGalxu7/XTH7TF4VpMuVZsrTptrU1AkPbz/fG4/ZKZ3SBo/rUrxNTlFPz4WcAeZqXsfQ==
X-Received: by 2002:a05:600c:5120:b0:3a3:2ae4:fb20 with SMTP id o32-20020a05600c512000b003a32ae4fb20mr3775579wms.81.1659557378982;
        Wed, 03 Aug 2022 13:09:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c04:b0:3a3:13cc:215 with SMTP id
 j4-20020a05600c1c0400b003a313cc0215ls891825wms.3.-pod-canary-gmail; Wed, 03
 Aug 2022 13:09:37 -0700 (PDT)
X-Received: by 2002:a05:600c:3551:b0:3a3:1d4f:69ed with SMTP id i17-20020a05600c355100b003a31d4f69edmr3927717wmq.188.1659557377497;
        Wed, 03 Aug 2022 13:09:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659557377; cv=none;
        d=google.com; s=arc-20160816;
        b=qZHcga5uciRNt/cydnxgXVCiuMOdAWNAa5BNUcvARC3q+ufRaMr9fE1FZ+Fo7ypejv
         wDKzauOlQLnMDgRlgOvHFFpbVmh4/uHXDqQSN0ffsT5jl7qMzkwMxpjlsBo4Eka6Ih/B
         kXTbnePXK3Avbem41za7obORjZ6RXAbD31isLuqHmh/+5eqnKm/mMA7dU/r1iheJC0Hz
         B/+5QCqeICfIbC3IeXOuhyyI/MmIxh6bKB8upw+213+L0fFMp8Jc4BdvS1NG8IVZ7caf
         EbCCSun+AtsrNb53DjpXXAXD0Y7wlJDGF8sQl0Xaabx992GH2cGj0ipVeaaStu71Q3Tp
         IbvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+vbIHQxok3iBrj2ygZ5X4w7Hfhhf7olzopwK/xIfKBc=;
        b=tolIqBcDF4wioP5z7YBJ/UuVjibEyxWDZlwlf4NSef1EpmxRS3sKZHKbVlYPosdSmk
         NYAnnvB60ho7KbmrxyVUaRBz1laFAL0s/0xLDEglhDAIIuYC8P+7G2je0QC0axU/kCY/
         h/XOR8jK7Y/M++egmlfvXWUnVg6qsP//vfYYfP9r+9z+3yydi4QjQFpTmNCLPsEA/IyX
         0pwu9tEmP29537T8di4OI7HfC3Sb/+7A7RH6iRlauDk8xmV0Tv8JspPd//WXNSmQoYBW
         BYSnfc38kZR/PwsVZ7WvcNOchbtoH5zgPiTjys3t4Y5PJQI24/Ovc25Lvbwk7Z7UWWqI
         Mh+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mHTRC+oF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id a8-20020a1cf008000000b003a32bc7d078si113766wmb.0.2022.08.03.13.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 13:09:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id h13so3531469wrf.6
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 13:09:37 -0700 (PDT)
X-Received: by 2002:a5d:590f:0:b0:21f:c78:4693 with SMTP id v15-20020a5d590f000000b0021f0c784693mr16993089wrd.544.1659557377015;
        Wed, 03 Aug 2022 13:09:37 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3b95:8ad2:f0d4:6c46])
        by smtp.gmail.com with ESMTPSA id g9-20020adff3c9000000b0021eed2414c9sm18642635wrp.40.2022.08.03.13.09.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Aug 2022 13:09:36 -0700 (PDT)
Date: Wed, 3 Aug 2022 22:09:29 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v2 32/33] kasan: dynamically allocate stack ring
 entries
Message-ID: <YurV+SDkF2dQCQLn@elver.google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
 <4db564768f1cb900b9687849a062156b470eb902.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4db564768f1cb900b9687849a062156b470eb902.1658189199.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.4 (2022-04-30)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mHTRC+oF;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Tue, Jul 19, 2022 at 02:10AM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Instead of using a large static array, allocate the stack ring dynamically
> via memblock_alloc().
> 
> The size of the stack ring is controlled by a new kasan.stack_ring_size
> command-line parameter. When kasan.stack_ring_size is not provided, the
> default value of 32 << 10 is used.
> 
> When the stack trace collection is disabled via kasan.stacktrace=off,
> the stack ring is not allocated.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> Changes v1->v2:
> - This is a new patch.
> ---
>  mm/kasan/kasan.h       |  5 +++--
>  mm/kasan/report_tags.c |  4 ++--
>  mm/kasan/tags.c        | 22 +++++++++++++++++++++-
>  3 files changed, 26 insertions(+), 5 deletions(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 447baf1a7a2e..4afe4db751da 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -252,12 +252,13 @@ struct kasan_stack_ring_entry {
>  	bool is_free;
>  };
>  
> -#define KASAN_STACK_RING_SIZE (32 << 10)
> +#define KASAN_STACK_RING_SIZE_DEFAULT (32 << 10)
>  

This could be moved to tags.c, as there are no other users elsewhere.

>  struct kasan_stack_ring {
>  	rwlock_t lock;
> +	size_t size;
>  	atomic64_t pos;
> -	struct kasan_stack_ring_entry entries[KASAN_STACK_RING_SIZE];
> +	struct kasan_stack_ring_entry *entries;
>  };
>  
>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index a996489e6dac..7e267e69ce19 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -56,11 +56,11 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>  	 * entries relevant to the buggy object can be overwritten.
>  	 */
>  
> -	for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
> +	for (u64 i = pos - 1; i != pos - 1 - stack_ring.size; i--) {
>  		if (alloc_found && free_found)
>  			break;
>  
> -		entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
> +		entry = &stack_ring.entries[i % stack_ring.size];
>  
>  		/* Paired with smp_store_release() in save_stack_info(). */
>  		ptr = (void *)smp_load_acquire(&entry->ptr);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 0eb6cf6717db..fd8c5f919156 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -10,6 +10,7 @@
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> +#include <linux/memblock.h>
>  #include <linux/memory.h>
>  #include <linux/mm.h>
>  #include <linux/static_key.h>
> @@ -52,6 +53,16 @@ static int __init early_kasan_flag_stacktrace(char *arg)
>  }
>  early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
>  
> +/* kasan.stack_ring_size=32768 */

What does that comment say? Is it "kasan.stack_ring_size=<entries>"?

Is it already in the documentation?

> +static int __init early_kasan_flag_stack_ring_size(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	return kstrtoul(arg, 0, &stack_ring.size);
> +}
> +early_param("kasan.stack_ring_size", early_kasan_flag_stack_ring_size);
> +
>  void __init kasan_init_tags(void)
>  {
>  	switch (kasan_arg_stacktrace) {
> @@ -65,6 +76,15 @@ void __init kasan_init_tags(void)
>  		static_branch_enable(&kasan_flag_stacktrace);
>  		break;
>  	}
> +
> +	if (kasan_stack_collection_enabled()) {
> +		if (!stack_ring.size)
> +			stack_ring.size = KASAN_STACK_RING_SIZE_DEFAULT;
> +		stack_ring.entries = memblock_alloc(
> +					sizeof(stack_ring.entries[0]) *
> +						stack_ring.size,
> +					SMP_CACHE_BYTES);

memblock_alloc() can fail. Because unlikely, stack collection should
probably just be disabled.

(minor: excessive line breaks makes the above unreadable.)

> +	}
>  }
>  
>  static void save_stack_info(struct kmem_cache *cache, void *object,
> @@ -86,7 +106,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>  
>  next:
>  	pos = atomic64_fetch_add(1, &stack_ring.pos);
> -	entry = &stack_ring.entries[pos % KASAN_STACK_RING_SIZE];
> +	entry = &stack_ring.entries[pos % stack_ring.size];
>  
>  	/* Detect stack ring entry slots that are being written to. */
>  	old_ptr = READ_ONCE(entry->ptr);
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YurV%2BSDkF2dQCQLn%40elver.google.com.
