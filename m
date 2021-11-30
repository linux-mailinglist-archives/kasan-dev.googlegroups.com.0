Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBY5UTCGQMGQENFKG25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15CC7463461
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:34:44 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id s12-20020a50ab0c000000b003efdf5a226fsf10631979edc.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 04:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638275683; cv=pass;
        d=google.com; s=arc-20160816;
        b=QbCn8Ea/ZVMNA2fS/Jqqx07Alauumvb1ToOEsTKq8BzjNdpfz0vHTQk/JwPsVe36TX
         44bf5hL/zUjDkJBjekIJsWxsj/prZpqZ/VRjDPbvlRFX0M5znI4KeDfPg7wuEfz6ztOF
         C6C+UwF5B3MGaSizu9w134bZSFlyObX5Q1klktmv08Qk7J+aTj5Y8kDT1XHD4qidOTqO
         buohRmJR0r3VwVg1g2uls4udJ63Cz/Ud3F/Zd2UwjGrYPlfgIMmPo5zOs1hHaWwbG9aC
         AZFaZ9YarNhhEdcET637n5f8hl3UkofbMdk17bCHOL89LTAarzh5DK7u7lk7fzqdiYCq
         jMjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=AjNwCWcU42xwF0DudphSTjVxua4dIAkAKn5RDMRtuYE=;
        b=tz0qXMsPiKLAaT69EF5Qht41vVyJNZ+ij0xRpL3Q2wWJ6uikDmIzp0Atkt8EG+ZaZ8
         ljX5uWcT8Z3T+DPHYCEb5t6+5iBxqMC2w0pcMU49LWAqZ3+wRcBwaVtfCj4ezEF5AVAG
         Rv9KsFnsUpDshGUChR0drUrwt4mA/8SSiBBP5a73cKTedoBcpg/wA3chD6PzlVwvh6nL
         +0EES5HDrIrePOghdzwpfn4OCEAt+3qIk0OUiTKnMFDUhSIiNawe0uHaVSjFTW5+Pwmy
         arjU8RIaYrxtbNhJy7TN5qHjZ5P0rRDTK+8gZFK/z/8extYeQ1vfq+fjyzF6l5swxN3X
         nx9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DpHiyHM2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AjNwCWcU42xwF0DudphSTjVxua4dIAkAKn5RDMRtuYE=;
        b=q9mbM1mi0kJrxYtGdhUnX1ZFdHj/nTkFdoieKjha3ROSEaZV9Bi4kYVI06edrJ0012
         WWf0Cdu8Au4dfVdnfFj7Vibuwrple5EG4Lf0+voxvzivb018rFq8vxrzUQagNQc9wRHS
         5DUuQdmgSmscoxKwlOLk03M1fVVeDAedOpFMcyGio+2M6UCmQvlZ2bTgeQMtm8zNzaPF
         oFWJnEvrOQa6ywOjIJAUurpcFYw0NeMpE8ub8bkpt7IiRJ+hAF68k3wP5WRrQ/kjSZwu
         xBjL0saf4g5IMMAChQtgLu01zN0ZfWvQMZz8B7c+Ag0VTsk+VMf8Ei/TxBMW+7H2fTpm
         +i6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AjNwCWcU42xwF0DudphSTjVxua4dIAkAKn5RDMRtuYE=;
        b=z+MpScsbjN01QOnly5FgwR32mHfpnUB0+S5Z4QFGN/8Q/DbkuFcWbQiy82W69gbjzK
         dm2FaLDQlzKKpusvhcUsQHgfCqMvsaMbwK+umry61yfZAbz9zzWD5jCCbqApihMGpcPF
         oFvLVDEdAz7jvWRoRPIe2isQ7y5OYSS4Rk8SFIStD6mwNxRpfzDZ1eXickVKO/xtaP40
         dQ39bEnjc/G0yxQcMsxTXcb4q7i1lHrRoV66VbySlsBKZYLSm95SJN3diZPUejbi1hRd
         8xN134/t6y+TLbKwodS4ojJaGQDiqW//FavRdnKPr/WcBz2Bo95HzRoztIArBv9gHmo9
         GTHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Q+moOGraByc/laPWm/G/4evbm5/DKTu+a5O6Sp5h3rzmd4LdZ
	MtTePPfIm8hiVvAuZsNLvx8=
X-Google-Smtp-Source: ABdhPJwtJXuIX8VejJABimLx7cas/UOY4sq0SmOIsrqXTGJhWeJK29kVQll4/8VUac94cZqCj8qIvA==
X-Received: by 2002:a05:6402:50cf:: with SMTP id h15mr82790998edb.90.1638275683872;
        Tue, 30 Nov 2021 04:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d10:: with SMTP id gn16ls2977861ejc.5.gmail; Tue, 30
 Nov 2021 04:34:42 -0800 (PST)
X-Received: by 2002:a17:906:c155:: with SMTP id dp21mr67070429ejc.450.1638275682793;
        Tue, 30 Nov 2021 04:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638275682; cv=none;
        d=google.com; s=arc-20160816;
        b=TdsmoVx9nhSlWJ5NTcKZJ0bG1h+SFsO1xWnqr3eLuwtrNM931kkY+RC/NTVjghmO0X
         +XaJWUTV12dXzEwt9grVGxto+AQePs8WsP5j9IQmrqpBL2koIeZb8kdBjYn6Pldfbexp
         GfIBJcGpuX96cO3HEJZzT95qQjUIgRyNYH3Wa6bQCl9OhZEHHFM3B45Cu7mvG5HY1Izw
         sD+rhH5hMnxX/guK/fNT0LfVWqAMmQlWp2c1ca0QiEONEbN5apiIiqTp1CDG2jPYJw1E
         RuQuLsV2m/t0SpnE0zCegwogHha4WWMS/rqBPk/2J5u6PPDOcnkm88fD2Co2mJMxb+ak
         yBNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=fpzJzpUtUcBoti6u4Vx5MyjLRfI5xfFsHhW6Dr3Lcnw=;
        b=mLCZwj1Q8r4QUVXPc496X97cfqIpF7WvjOhAzZVwsgD8fsaqjL3J50AiH/8TeTyA3k
         cyYyLm4xZAN1FNcxSX4QIbqlC3rtuTGku4neSZ649dlDGgkOQvXkPrzLYnf0WgaOk1P+
         FgKf8RB2X3w1RGHRdwBFSgAjsng8m9qeG+5guflJ6wGsVmJtBwEGxq+BXwXn3jprjYhI
         lm7qo6rhtwCmchbb0H0Q8CtsGbiWEzOWYw6UNDxNw5QLJi3w5kLyF6kv+/SEMuWkAI3Y
         o75CUVWDLcbJW0sZmAsysV9BpQioUDTGFON/dikaCl1w8WfZhljU87Oh7By0snk+mkv1
         R/Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DpHiyHM2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id i23si993677edr.1.2021.11.30.04.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Nov 2021 04:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5E19F1FD59;
	Tue, 30 Nov 2021 12:34:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1C1D613D04;
	Tue, 30 Nov 2021 12:34:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6qowBmIapmGXeQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 30 Nov 2021 12:34:42 +0000
Message-ID: <37053057-1aa0-6ed3-7c84-c3eeb26cbcf1@suse.cz>
Date: Tue, 30 Nov 2021 13:34:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH] lib/stackdepot: always do filter_irq_stacks() in
 stack_depot_save()
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vijayanand Jitta <vjitta@codeaurora.org>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 Imran Khan <imran.f.khan@oracle.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 Chris Wilson <chris@chris-wilson.co.uk>, Jani Nikula
 <jani.nikula@intel.com>, Mika Kuoppala <mika.kuoppala@linux.intel.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org
References: <20211130095727.2378739-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211130095727.2378739-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DpHiyHM2;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
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

On 11/30/21 10:57, Marco Elver wrote:
> The non-interrupt portion of interrupt stack traces before interrupt
> entry is usually arbitrary. Therefore, saving stack traces of interrupts
> (that include entries before interrupt entry) to stack depot leads to
> unbounded stackdepot growth.
> 
> As such, use of filter_irq_stacks() is a requirement to ensure
> stackdepot can efficiently deduplicate interrupt stacks.
> 
> Looking through all current users of stack_depot_save(), none (except
> KASAN) pass the stack trace through filter_irq_stacks() before passing
> it on to stack_depot_save().
> 
> Rather than adding filter_irq_stacks() to all current users of
> stack_depot_save(), it became clear that stack_depot_save() should
> simply do filter_irq_stacks().

Agree.

> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks.

> ---
>  lib/stackdepot.c  | 13 +++++++++++++
>  mm/kasan/common.c |  1 -
>  2 files changed, 13 insertions(+), 1 deletion(-)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index b437ae79aca1..519c7898c7f2 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -305,6 +305,9 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
>   * any allocations and will fail if no space is left to store the stack trace.
>   *
> + * If the stack trace in @entries is from an interrupt, only the portion up to
> + * interrupt entry is saved.
> + *
>   * Context: Any context, but setting @can_alloc to %false is required if
>   *          alloc_pages() cannot be used from the current context. Currently
>   *          this is the case from contexts where neither %GFP_ATOMIC nor
> @@ -323,6 +326,16 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	unsigned long flags;
>  	u32 hash;
>  
> +	/*
> +	 * If this stack trace is from an interrupt, including anything before
> +	 * interrupt entry usually leads to unbounded stackdepot growth.
> +	 *
> +	 * Because use of filter_irq_stacks() is a requirement to ensure
> +	 * stackdepot can efficiently deduplicate interrupt stacks, always
> +	 * filter_irq_stacks() to simplify all callers' use of stackdepot.
> +	 */
> +	nr_entries = filter_irq_stacks(entries, nr_entries);
> +
>  	if (unlikely(nr_entries == 0) || stack_depot_disable)
>  		goto fast_exit;
>  
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8428da2aaf17..efaa836e5132 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,6 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>  	unsigned int nr_entries;
>  
>  	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -	nr_entries = filter_irq_stacks(entries, nr_entries);
>  	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
>  }
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37053057-1aa0-6ed3-7c84-c3eeb26cbcf1%40suse.cz.
