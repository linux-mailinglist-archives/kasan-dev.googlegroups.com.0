Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6HY73DQMGQEQCGU7FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id EEFDAC0FF3C
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 19:39:53 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-4270a273b6esf3642417f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 11:39:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761590393; cv=pass;
        d=google.com; s=arc-20240605;
        b=BJKdMYnHEyjQ3uRsTTih6PWYO7jq9CywNLwIT8cz7u0wFrQXgF2lUSGKeOA25gcT/u
         8YHKimZG/TMv56Bw5xHUHI9Fo9KiRv5xL6c2yrjuz2OfiRMWaXtHOVe4waPXElG/GxU0
         mzGKHglJlSjjWp2wJL/QTpjTc/ER7qU+NyTJeja/ZCa8YT0YJdY1WV4/UjrnDgb4YK0k
         zbNJPH5DLNriC1FcLLU5izTrDBcWGe0pRNl9gbXYjAMXFJAuNjPXu5ouaowNTvqx+cZl
         kyulUlXLwfAT6SnFDQLDT96/vCQOrmMhNRP8x+L27Ixrm0O6jfgbBi6A3f4tJWHBX7Dn
         x8BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=gzgW6MOlNqF0WMR/YoXtfc/uF0OS+krQQegVwcK8TAs=;
        fh=gzkV102ORRgwDVmJaHiRtc2cp00+Kku3EQd9bga8b20=;
        b=FZecm3xblIqxiLDIYT4CFWR8wMBf/yCbJokt5+XLpgu92hazK8Z8fkMuIx8sufZASt
         qxvS9bzafpt/VK15BwwGgmevbXY39K7OYE55f7/maOLL+xy+8BgiN/X2PO98OVUMF76x
         9jXPPbYxtGg6dRCTTC9/cIsphWVdHeTTlOqS5Va9tudqZe1qFhJQGTATNsDnF3rK9sW5
         M1hF/kLfLNa7JyWe85BNrZi/zpp1aI/DX+0pYZ2jlRmKTkvAtdWuzt7merJZIxWcqG7y
         jljYZwYULkPnA9iQqz60TLlrsjefpvstKuVsRIMIdzPXbRgzk6tVUOL0nOIlE5VPC6Ls
         dftQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RteJ7yg9;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RteJ7yg9;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761590393; x=1762195193; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gzgW6MOlNqF0WMR/YoXtfc/uF0OS+krQQegVwcK8TAs=;
        b=r8z159/bL86gUqrlBB1CkMKesle9d7UzpHbWja5o2zJNNOBuM/e9rErqqxHd0JfBRp
         G1rMlQ3ZW9o3pA7p7n/stBLvY5x2VitRZSbDOWsDhQ/z73X7TE25MpIW5/5hNgiWjEwg
         MJ6WdRpsJc8ftBFhPJhQQePoBMCOnHZveL/5N08w8ndhEgULV9/Xz+2EsqmR4ZRr2l3I
         YoitvXSu3qQOebprIIVc+bmtwoZoconw/n2UAsHeFprsHB0MeXlIlk40YF3bmzowBG6r
         7oOFLRthAq+FuUBOWzEXwnXvZNXJDARokXYSdfKV+Bgbr8sreyR/Vw2bYzOoniWMg4G/
         bQgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761590393; x=1762195193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gzgW6MOlNqF0WMR/YoXtfc/uF0OS+krQQegVwcK8TAs=;
        b=Zz5zoJARDrEEgNdWPeJv6gB6XWZz7Yde+pSEGxTQYd1XwbWUIwkKtMnoeNg75o29Yj
         yfH6gOWswO1VNtEtUxJSXXDyMqajO8p7FS+zFrT3dZAgzb4JroMRZhtjl07k/lGDekXi
         b46g8vFfLlVz4gXtZcqqWtFseQilFyV3J9OK3jguZzp4CnpH+mB/4TQkcT9j7lP4UBtv
         J0h23h+A2tzvI0aImPs2WasPlZ1o3w1Xo7YnWKqjtNqnQjAiyPkPTN1wRCTRDFCmb2ao
         Hlvc6pjlHoiYHMS3rsUiRpqzXIM7eAHr01uylKTfDQfRxSP0mVsFSWG5XcrdQSSMLLT3
         x/mQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3OSCPBSvy8uUerMM8RoCKapLZM3rQ7F5hN1u2FKPLDC7oNxZnCQAxOk6klBnxkV2LFgzy/w==@lfdr.de
X-Gm-Message-State: AOJu0YzuxdU7S1uycZ9HsUpA/55DLx9JpBJk6RUrAVI8Rk70+sG8WSVi
	jfiYYOUnVdwweA169+onJXCQTmxljvt4J5zg8VqNRkiYJDkKGTSPPJ1W
X-Google-Smtp-Source: AGHT+IEjDUDUknpok2jzz5uprRmTkwI5uGS3Ex3k2RC+47YRxSWbFis9dCMCGWV84vpykWPoxeu5sA==
X-Received: by 2002:a05:6000:491a:b0:429:8d6b:16f7 with SMTP id ffacd0b85a97d-429a7e5190emr649853f8f.25.1761590393023;
        Mon, 27 Oct 2025 11:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YeRwBtdO5jADPl/vaPiHxwOs7nQ2R6YDimwnm8cSk0Ew=="
Received: by 2002:a05:6000:2889:b0:3fd:4c4f:96d2 with SMTP id
 ffacd0b85a97d-42989daaed3ls2989339f8f.1.-pod-prod-03-eu; Mon, 27 Oct 2025
 11:39:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+5hG41ofAOxXdXDGDmc4kEWVrDi38gJ0BshF4B23L4waeQ70abvkJ0g5RIoj8jIoeCCxsE+E4IbA=@googlegroups.com
X-Received: by 2002:a5d:5f95:0:b0:429:66bd:3caa with SMTP id ffacd0b85a97d-429a7e7db93mr737408f8f.49.1761590390304;
        Mon, 27 Oct 2025 11:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761590390; cv=none;
        d=google.com; s=arc-20240605;
        b=F6r51jUKSITRjPe+R6248/hkD8Z6fM9iMHoNRt0u6h/7VhZWvovxcMoBayRiAiYb/A
         7Q1m8+b7LwXBilfGZS6ct+UO8xDsWldunenbf6vbbZ2+095Ti7ZYaMJJ6s6FY577ZjnR
         54fStIThNMrEzfSYYm+slWDe3Ta5EzKztHVUvhu/DYx6Mk3ii//eBaQ+xuUufzijhaR5
         FcOCplFeU1sVPhXKmUHU+yMsrVhkZNiLJsZL1PoGyJKidu7OUfU3OhMZ0YNjIeU4Gb2B
         UH1JM8KQe752UH3DKSBOMpu0m5dL8bTfMDRlqZiPm5tVuapp8ycSpqmbOqFmjTzbcXDx
         PpRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=5UdNcCz5jl1QRTKAi0eT8hEWfVN0MVORcJZftQx/sno=;
        fh=GQ1CknIHC3I18LPv3khWiJhfxklV7xH29WYqZXaafH4=;
        b=I4Y4+/MgRsWGITP67s5jLHHnOcDu970gK5Na5M1LBlZzOpr3y9jd1fIDl/vuTVwDDx
         RnO6WnqOl1qkOyb7YTreX8FSC+HCxpKjvJ/I6g1Bh8rdmID2J1mnQeXbbC2iAfH1gClj
         yI8Xp8J4XX6N5CmjQU93oul9khtBgj5R3bkmLbyBYynK9ST8RImuYSlBkr1elAh48jbF
         opcnh8OqlgnSxLKUfVueF0mGGN6xL+bKbK3Wz3fndR+G4Oc2bDMxu1qgGR21YPwUWmMx
         SPIPC7oUqFOyslKT2+QGbnVedqSJxcC+0nBcCmwdYlSHaExAhVvYapfSGgAfTv1M/dkE
         hOWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RteJ7yg9;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RteJ7yg9;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995ff8f70si222375f8f.5.2025.10.27.11.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Oct 2025 11:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9AA0021A63;
	Mon, 27 Oct 2025 18:39:49 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7E5EB13693;
	Mon, 27 Oct 2025 18:39:49 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jCZMHnW8/2j4EgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 27 Oct 2025 18:39:49 +0000
Message-ID: <d9468a23-d39f-4005-8ff3-3abb429d7dc5@suse.cz>
Date: Mon, 27 Oct 2025 19:39:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 16/17] kasan: Remove references to folio in
 __kasan_mempool_poison_object()
Content-Language: en-US
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 linux-mm@kvack.org, David Hildenbrand <david@redhat.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20251024204434.2461319-1-willy@infradead.org>
 <20251024204434.2461319-17-willy@infradead.org>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20251024204434.2461319-17-willy@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 9AA0021A63
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	URIBL_BLOCKED(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,infradead.org:email,suse.cz:dkim,suse.cz:mid];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_TO(0.00)[infradead.org,linux-foundation.org,gmail.com];
	MIME_TRACE(0.00)[0:+];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[gentwo.org,google.com,linux.dev,oracle.com,kvack.org,redhat.com,gmail.com,arm.com,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	TO_DN_SOME(0.00)[]
X-Spam-Score: -3.01
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RteJ7yg9;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=RteJ7yg9;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> In preparation for splitting struct slab from struct page and struct
> folio, remove mentions of struct folio from this function.  We can
> discard the comment as using PageLargeKmalloc() rather than
> !folio_test_slab() makes it obvious.
> 
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Acked-by: David Hildenbrand <david@redhat.com>

+Cc KASAN folks

This too could check page_slab() first, but it's not that important. Note
that it should be fine even with not marking all tail pages as
PageLargeKmalloc(), as ptr should be pointer to the head page here.

> ---
>  mm/kasan/common.c | 12 ++++--------
>  1 file changed, 4 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 22e5d67ff064..1d27f1bd260b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -517,24 +517,20 @@ void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
>  
>  bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>  {
> -	struct folio *folio = virt_to_folio(ptr);
> +	struct page *page = virt_to_page(ptr);
>  	struct slab *slab;
>  
> -	/*
> -	 * This function can be called for large kmalloc allocation that get
> -	 * their memory from page_alloc. Thus, the folio might not be a slab.
> -	 */
> -	if (unlikely(!folio_test_slab(folio))) {
> +	if (unlikely(PageLargeKmalloc(page))) {
>  		if (check_page_allocation(ptr, ip))
>  			return false;
> -		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
> +		kasan_poison(ptr, page_size(page), KASAN_PAGE_FREE, false);
>  		return true;
>  	}
>  
>  	if (is_kfence_address(ptr))
>  		return true;
>  
> -	slab = folio_slab(folio);
> +	slab = page_slab(page);
>  
>  	if (check_slab_allocation(slab->slab_cache, ptr, ip))
>  		return false;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d9468a23-d39f-4005-8ff3-3abb429d7dc5%40suse.cz.
