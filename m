Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHFC73DQMGQEURUJ6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id EDA9FC0EFBE
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 16:34:54 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-47106a388cfsf27920065e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 08:34:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761579294; cv=pass;
        d=google.com; s=arc-20240605;
        b=bVrJ44SOC8kW+zuERiFO7GPGYrkQSVkoVDlqCtFzcWZGPqUxnHCwWV35uIkkisrzQb
         5mKEdYxSPjZHvkVntbruH+jjRTnnG7RP7KweXgwHk30+rrOo/4BursETYk6W1xr+d9tq
         1QN4+P9UzGqxS3C9e9Nj6vD/JktIAa+1z9+wVvTvoKvq+GvEmr3DLbn0rkUA5LuG7e4c
         LFC2JBJH/NzTP6EG5xGqox0eMb7w+A4qoqzZTXtsHUABHFF7r/AD+uJuNyNZIrHTRY4y
         wRyYaUbBZKf+YjoyM0SN9p+b1USYOcjHCqDsFnlVxo21p6wsj+jL+5A7cjUcnoSvbhfw
         b9fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=0dea24WFZse2ykkC8EgczdG5qqSCFuFypB90LcJ6mmA=;
        fh=8Pu8Cw/2QyAbAjoRUoqmvuq7bYEdVHDCAEYfsjnKuNk=;
        b=WcxK+MSq8M4rDcTxof1fGu8ESLKnFlLUtw9hLeAFiga9Ml+/MqyWNDYl6Q+YPRhkSZ
         HlDTRA/YvZF1X7s1p8TA2E44lKmQsJuvL42iW2axCmXxFg5eeGxi0d6m68a/EceZCs6K
         L+ZoIkxo6y+2gkx8rzXW93LYxkU/KJb53gcExAg/KgcbEh8xlZmFK5YERMCfnwFTG/tf
         OAg/wh/er2TtIyJzUwCkDXzp8EodVfcQbrEX2o3Lsw/N8bIBIE4KldpBYn5AvHUFlYWK
         ZMb1Rx0lwjJ+B1vaJ+EVhh6og/dHWKWv0OjkL5AmcPjQTbHHPD1j6wq/Ww5Uy3zJ8dkG
         dvQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XpUhomsW;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XpUhomsW;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761579294; x=1762184094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0dea24WFZse2ykkC8EgczdG5qqSCFuFypB90LcJ6mmA=;
        b=xK8+P6+41qDvw5TBx+/3RzsFLQqREnQV7btbZEuJRtJBZ8e5TesEjmHFdd9IS9J9zf
         kqYqsfCK+3Djm1eDDAMjHqfuo0arYSXEo+j5Mfz0BasHLWbfVLg60u9/fDQ+dL5im2R8
         acFwFz9fFIopNDMi2rhDy4aZcG2t7Y5+HCFUjDMwniXL8JqY9IFcld9EsTz+dhdq9o70
         7U/1CFGpaZju2gbgw91mWSZK/NafWKkgCD7ekC3p3QTtrCnmxFyikPVPGrpSRPQ39C8A
         Kuv00MJ//HEWlSeVjl8As+kLxnvm3aGTkOki8VZ8XZSIek2Qp9TNSnj8erZqmPatEjWV
         f41w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761579294; x=1762184094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0dea24WFZse2ykkC8EgczdG5qqSCFuFypB90LcJ6mmA=;
        b=AHqHMeN6EImSAm1AwC3fEYTCaGlFSNaqJhPz6BkjDJZVL3o55Tuu4LoPlquDvfBqup
         /Tb/ZTtjleG4XAE1eTkf0kw7CMZk4lyBfRSbwV2frnldEYGwAhstpxxvB45dXMOmtQYE
         nmT30vaxvduEjlUxWRKBeuuuBsJwXyvG3iRa9zkceNGlSpT/hhpolHXP0WqGJbTaojsG
         /+GFrCOGJkENgk5+XPd7kSaFlQxYKb1og4z5DoKQIhVOIfCZ3E9p4BwXaD//kVbW7zIb
         SDKdLkzv79xzG4BpQER3dJ5eSOQ1sqxggU7i/VsOnNYJ3lHomfQOYh8781oTfVTQzeyX
         I99Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0G+OlT6lwiprQEqebqRhVHrCVwk1q+pro4w6961VVUWsEwzaxy6/hWOT3eQdPEbyeEr9cdg==@lfdr.de
X-Gm-Message-State: AOJu0YzSeuvhe9h2ax5VPyNe3XpkdBeRtOFMlI3oi4zjy6EpyOMyuymF
	M4a0aKiv1y7vKbIGGHzNqTaBIj1DDLAf1dP+zQ0NwrHAM06H2rjpXR/o
X-Google-Smtp-Source: AGHT+IHVETt3eTVJuVNzOb2UTaizRuwWOo+JMy1RXE7z+vlib5VZxddGbFfJT1lbvPNUndTjcvOKuw==
X-Received: by 2002:a05:600c:83c4:b0:471:c72:c807 with SMTP id 5b1f17b1804b1-47717e414c6mr462235e9.22.1761579294034;
        Mon, 27 Oct 2025 08:34:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bLDLxqOvKCezpbHgCF1WHDTPGF3ZAKUXBYUQDn1KFZyg=="
Received: by 2002:a05:600c:6d46:b0:471:e4b:ff10 with SMTP id
 5b1f17b1804b1-475caa8f9e0ls21138735e9.2.-pod-prod-06-eu; Mon, 27 Oct 2025
 08:34:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6sKC06GunpWlra7N9aR54AyiUGdsspO8j9Wvx/sWriKhlurIhqp1Qsys2AQP5hVPaQ7zsB7T0Yak=@googlegroups.com
X-Received: by 2002:a05:6000:1846:b0:429:978f:16ef with SMTP id ffacd0b85a97d-429a7e7c09cmr109706f8f.30.1761579290849;
        Mon, 27 Oct 2025 08:34:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761579290; cv=none;
        d=google.com; s=arc-20240605;
        b=akz69dViBz9xXKLUW3O5iVsWfVXxtFGKXnZli2ein21M6GOCGWDDuspOr5p7GtgaLR
         vsKNddwUSbsIPbpOfHnBhZLVRV9EgHPjVkP1Y8Ss9A5NPkmfvLEEAD1p+LbU0oy88JBQ
         vogY90UhonEYPUj6ipqRDLTrqam1B5LLsdEToh9YZPQ+jCe9KuocP50UyF3glNXyt6M1
         qmlvQu+BktHoZdXoP+Y6CFBVOcCgX4M+8HPTuGkeOpUKBXk4hTThfnSGYO6aCN9ATWBK
         3lVOVBtrx6x47h+/OzCDGWtKAM725H8ycYLJRfsmuT9zdNQrWGElcfCPJ8rr6Gar1nEm
         lGuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=fkCzjDITEmu3iQxYf6mZpY8gvpmTVbipkrkmE98m6bo=;
        fh=M1RT4ashImlNAMrfP6qlwdJZSrKzZsYGGkg+loRltoc=;
        b=LUWgQez6cvRDMIamM17bOj0lPRJDnBYf5WBSNykFwWmun+iPVAvTC1HxuegbWyrSH2
         LDn7DIgSfUbipoM2Kwgc0fZLphqC8K/eWKrYx/K+dkgq5mQZV3MozgFMNJc/xSWB9Mf9
         8MOYb6JFp4XBFDtM073Oe3ZSo+fUEoYc9gyGz97A2VufpXa/QWc8gQbhtog1moJpa91b
         RlyVMmRbkhsv9bR9WsQZ/nXYxaZcbns2LCvS5FNCRpyVCpRs7G4wnvhC+TmfDocBmbaY
         6TSClEb0nnXWYEqLzxzYTc9zW8fBSrzN8Gylz0SGXdLSWtyr/5kPSHb4dm92xO2Sz10o
         I+7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XpUhomsW;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=XpUhomsW;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995ff903dsi147389f8f.6.2025.10.27.08.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Oct 2025 08:34:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 57BF0216E5;
	Mon, 27 Oct 2025 15:34:50 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 31771136CF;
	Mon, 27 Oct 2025 15:34:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id FTU0CxqR/2ifUgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 27 Oct 2025 15:34:50 +0000
Message-ID: <fc6434a8-21fe-4924-95fc-5a1fd1f3d197@suse.cz>
Date: Mon, 27 Oct 2025 16:34:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 01/17] slab: Reimplement page_slab()
Content-Language: en-US
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 linux-mm@kvack.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20251024204434.2461319-1-willy@infradead.org>
 <20251024204434.2461319-2-willy@infradead.org>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20251024204434.2461319-2-willy@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_SEVEN(0.00)[11];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,imap1.dmz-prg2.suse.org:helo,infradead.org:email]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=XpUhomsW;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=XpUhomsW;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/24/25 22:44, Matthew Wilcox (Oracle) wrote:
> In order to separate slabs from folios, we need to convert from any page
> in a slab to the slab directly without going through a page to folio
> conversion first.  page_slab() is a little different from other memdesc
> converters we have in that it will return NULL if the page is not part
> of a slab.  This will be the normal style for memdesc converters in
> the future.
> 
> kfence was the only user of page_slab(), so adjust it to the new way
> of working.  It will need to be touched again when we separate slab
> from page.

+Cc KFENCE folks.

> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>

Otherwise LGTM.

> ---
>  include/linux/page-flags.h | 14 +-------------
>  mm/kfence/core.c           | 12 ++++++++----
>  mm/slab.h                  | 28 ++++++++++++++++------------
>  3 files changed, 25 insertions(+), 29 deletions(-)
> 
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index 0091ad1986bf..6d5e44968eab 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -1048,19 +1048,7 @@ PAGE_TYPE_OPS(Table, table, pgtable)
>   */
>  PAGE_TYPE_OPS(Guard, guard, guard)
>  
> -FOLIO_TYPE_OPS(slab, slab)
> -
> -/**
> - * PageSlab - Determine if the page belongs to the slab allocator
> - * @page: The page to test.
> - *
> - * Context: Any context.
> - * Return: True for slab pages, false for any other kind of page.
> - */
> -static inline bool PageSlab(const struct page *page)
> -{
> -	return folio_test_slab(page_folio(page));
> -}
> +PAGE_TYPE_OPS(Slab, slab, slab)
>  
>  #ifdef CONFIG_HUGETLB_PAGE
>  FOLIO_TYPE_OPS(hugetlb, hugetlb)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 727c20c94ac5..b16e73fd5b68 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -612,13 +612,15 @@ static unsigned long kfence_init_pool(void)
>  	 * enters __slab_free() slow-path.
>  	 */
>  	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +		struct page *page;
>  		struct slab *slab;
>  
>  		if (!i || (i % 2))
>  			continue;
>  
> -		slab = page_slab(pfn_to_page(start_pfn + i));
> -		__folio_set_slab(slab_folio(slab));
> +		page = pfn_to_page(start_pfn + i);
> +		__SetPageSlab(page);
> +		slab = page_slab(page);
>  #ifdef CONFIG_MEMCG
>  		slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
>  				 MEMCG_DATA_OBJEXTS;
> @@ -665,16 +667,18 @@ static unsigned long kfence_init_pool(void)
>  
>  reset_slab:
>  	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +		struct page *page;
>  		struct slab *slab;
>  
>  		if (!i || (i % 2))
>  			continue;
>  
> -		slab = page_slab(pfn_to_page(start_pfn + i));
> +		page = pfn_to_page(start_pfn + i);
> +		slab = page_slab(page);
>  #ifdef CONFIG_MEMCG
>  		slab->obj_exts = 0;
>  #endif
> -		__folio_clear_slab(slab_folio(slab));
> +		__ClearPageSlab(page);
>  	}
>  
>  	return addr;
> diff --git a/mm/slab.h b/mm/slab.h
> index 078daecc7cf5..a64b9b2c8731 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -146,20 +146,24 @@ static_assert(IS_ALIGNED(offsetof(struct slab, freelist), sizeof(freelist_aba_t)
>  	struct slab *:		(struct folio *)s))
>  
>  /**
> - * page_slab - Converts from first struct page to slab.
> - * @p: The first (either head of compound or single) page of slab.
> + * page_slab - Converts from struct page to its slab.
> + * @page: A page which may or may not belong to a slab.
>   *
> - * A temporary wrapper to convert struct page to struct slab in situations where
> - * we know the page is the compound head, or single order-0 page.
> - *
> - * Long-term ideally everything would work with struct slab directly or go
> - * through folio to struct slab.
> - *
> - * Return: The slab which contains this page
> + * Return: The slab which contains this page or NULL if the page does
> + * not belong to a slab.  This includes pages returned from large kmalloc.
>   */
> -#define page_slab(p)		(_Generic((p),				\
> -	const struct page *:	(const struct slab *)(p),		\
> -	struct page *:		(struct slab *)(p)))
> +static inline struct slab *page_slab(const struct page *page)
> +{
> +	unsigned long head;
> +
> +	head = READ_ONCE(page->compound_head);
> +	if (head & 1)
> +		page = (struct page *)(head - 1);
> +	if (data_race(page->page_type >> 24) != PGTY_slab)
> +		page = NULL;
> +
> +	return (struct slab *)page;
> +}
>  
>  /**
>   * slab_page - The first struct page allocated for a slab

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fc6434a8-21fe-4924-95fc-5a1fd1f3d197%40suse.cz.
