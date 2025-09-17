Return-Path: <kasan-dev+bncBC32535MUICBBVPPVLDAMGQEVOT5W4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E5B9B7F4AB
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 15:29:59 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7e870614b86sf1506359585a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 06:29:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758115798; cv=pass;
        d=google.com; s=arc-20240605;
        b=XBPaBU7x4Qso1O1OTdQ6P9+hcz3i3w5ZBo575+sf09DsX3ve+hxG98k2H7Ol+wmEr/
         HkuxmNV021i3AtRl+w0ugDQxHRSaeUmeUgoKS7Me7JAWRq+kKY9yXiBm7zLZv5vz1cla
         s8TQx/JSGFGMdtJEtN+TgQKnWhyoDwI/EJv1ph6NxHwv/gddECuLLOwTc4PpBOdZjXBa
         ZObEhOVwPjqLiJJXQhgpUyewienwaqL3RX7z/yEXS6TNhVmR4eG8cizSxnYEJFEC58G2
         ufiPp+yeYLNmlo4lpSq7dFKM477Opo2EL4F2ux/tYU36u3ou6SEuuKaZtK1GbLcLP8Ex
         nnkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=XaQVU39m9pbRdfsVCp0HJRM1FlxD1DmnEm9jlUUgWjU=;
        fh=r/bXA4C2o6U91vzgFt5ISG9YWvPwubsMoIsqSRS/6/w=;
        b=Z8pRaLyeUCc7f8yKn/Qibiy1iqwE8ZUyiXL0pR3BeEO37b+IQWFaKROoTBwoMorF4D
         OFcjVGwqvdeYFztiGUCVE3haA7bTJ61dBKzzhE0l1Z0cjuI1vDRgh0dwlSYVpDHGWVGL
         0xdd+Jm8qvYrhtRrHzrHGuDTi6dQhPLYAuamys1QAISuoKNgYjubBDmALF8bTzTHvTrT
         J3f65SS+oMyuGkbJMfkjFYdKNInw4Q1HTJxnnlf79bgyaqwwUhow46neLYA0v9s2FJT5
         iOCNNItk2wy/4XCSdT7Et530tK5vyRcwKPOrecN4y1KyDLAR5HlWO3EU9JEu9p64+fCu
         5mwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UtHN411b;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758115798; x=1758720598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=XaQVU39m9pbRdfsVCp0HJRM1FlxD1DmnEm9jlUUgWjU=;
        b=HvS4FWKDK/CaOMuqr8wtfYefaq+tBIp/i99y0uqXJR4hYxBJrhu4iKHcgWgDkIFETO
         hUhzPY/qv+KDSF1fqZ8mvEDZAQG5Dmm/czqVt+eaG+ohFsDtbx+NDmJe7YZ5t1yvE155
         rE5VgO/ZtO7TEqTHaGQzXlksIgf9IXB8WLLQn54YWseLEUk65pEdgeotDUin4YwsOcJz
         udpaxSe/FsQmgXLwVovOMU6FbQGyUwcLLuvHJTlARDv+T/Xh9bovVXw37OpbuqUNVH6p
         0IQxkaHuDbXmk10z5/PvT5RVJdTqvLc7olKfVOsb2QLVSbkLzQcWQljOQLHn1ub0/xdU
         +Fyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758115798; x=1758720598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XaQVU39m9pbRdfsVCp0HJRM1FlxD1DmnEm9jlUUgWjU=;
        b=DRFQm18wEiuChf9hyFGWJMbyQ8JdRpLqzYoqIPFVszpX/3u8zZ1lozPolb+bQBzMFx
         4xQQ4Xo7JfFFbz5usXPv6WTvI3VdMSrDMFuBKK1AZs5oBNsunS9H1t1BXI5Ss0hTgmOt
         i0DcVy6WvNkoWQEVgkkq0dycyrmn9+5uhlmst0GHLTD6pZ9z9msASwvvQ/THrjVRBFfj
         JzPeQjuQRRVPQwoQb1NkTfmGmqIcPEEn1ILfVbFwW1QaEb16IgqiVtrUxOviwDKRlQNs
         5KEZb/f0mv0bxsbVft1EZlxK8PcmFTxPmKkTsM5CMxBp2Zue6Cxxax3TOvbP90BJYJx3
         05fA==
X-Forwarded-Encrypted: i=2; AJvYcCXYaAAihEPYhJHxQSg78Tpn9CiAWPcW6pv5N4/qPxIRONVn8vWGjIBEnom7ziJqRZ9X5ZkrbA==@lfdr.de
X-Gm-Message-State: AOJu0YwxTcJDhb4k8IZojivE/gxPSIgTmaWGFOqIp77Faj6wjm4p4Iq6
	z7fehIWdfRZvOq7eEz4bYjBi3vr9pTlcUazprwmEH40oHpIN7+Mpw8l0
X-Google-Smtp-Source: AGHT+IG7aOGdaO6rGBFJSKyvpwQVnaikZG825WCOshRVoE3085LttPy/s5v03apWvH7KkPKyIFTQpA==
X-Received: by 2002:a05:620a:4443:b0:826:f242:e524 with SMTP id af79cd13be357-83112d88876mr179313285a.82.1758115797842;
        Wed, 17 Sep 2025 06:29:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7rUA1eGxyAJE8H82EUiRotiyGdFbyFBA6w2by1S01ppw==
Received: by 2002:a05:6214:2528:b0:72c:74b2:94c9 with SMTP id
 6a1803df08f44-78da2c452edls27514856d6.2.-pod-prod-04-us; Wed, 17 Sep 2025
 06:29:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJZHHXztQAS1io9iBlETwsIlH1ekhga95BRSiRb97sfRhz4BFyAa6o8elOjnrgwFZuFDq5jYIAl+0=@googlegroups.com
X-Received: by 2002:a05:6122:21a4:b0:53c:6d68:1cd7 with SMTP id 71dfb90a1353d-54a60de3eb5mr816335e0c.13.1758115796796;
        Wed, 17 Sep 2025 06:29:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758115796; cv=none;
        d=google.com; s=arc-20240605;
        b=FvmpUx4qwLoninAVlY/k4zRwfjIlQ4QYmn+Cm15iOXrz2GbaCC7yVPgIGbix4qs8SU
         J2brHEqWkQAMLpUauZGmQ+q4WN3tGcDm55TZN8JBvxo2dTmmdIoK5UlEPmqKbzBFpXqB
         dDrGkMMjWBkdXI7ZoNIvMGy/qL6xyYmTOrCGmsnrEPCIcuWzVLGazL4zwSNOxbQywEje
         6wZEhu8TJeYuz+rzRGJ/HbU13lXRsd33PwidsRqbC3b1F9u10LBCjLfb42pEWdfVBr5E
         2uX186xLPst6ZuI2vOshn7DQLU7hGp7S3CevWKXmRGHddTk+WdQs5Zf2yz/y85KZMXuu
         2OZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ORcJ/40pST81yvYCAWc/eP0hnGAXGVPHAP2CtAwPNcM=;
        fh=MmwI2lMy4VTvCyaN1UAimGfvSOEo8wGIULazMeRa4MY=;
        b=Vt/jeKq/qEgmmr+piT9h6bDpA/e0pGZlIQp51RJFERMCtYYNaPT5pAyR6Y/ip9lPmA
         0YTnVtQDJzR2gJdeiSwSb6WWdlVNil0MHd2Gak9BRZ9nZMZcs65oeIJvAssVlEByskCL
         m6S20EHn++lfWuUow8wgYBU4l4GC/j0ADXgomeBevy0pnT5FzGqKMupXu3gY/Hn6Fbr+
         k7/YgwijOtv8uot2mjz3bhEwv5MlD1qlc8He7ShRw6T32aiA4eaTvmumiPAMNq/Mum18
         efn44JrUeX5VMNfAR+v62Vt4YIpu+3qBuF0fTy/fObzCyDraRFA14COB6zgDKtZOp/Ei
         6aow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UtHN411b;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8d769757209si437444241.2.2025.09.17.06.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 06:29:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-453-USR_dvzdPXKVLkAXPn6tOQ-1; Wed, 17 Sep 2025 09:29:54 -0400
X-MC-Unique: USR_dvzdPXKVLkAXPn6tOQ-1
X-Mimecast-MFC-AGG-ID: USR_dvzdPXKVLkAXPn6tOQ_1758115793
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45f2f1a650dso22942345e9.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Sep 2025 06:29:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWlnT6xV8sADxtGPikchB8RJPzCBe+kQtGimsgWjaNno0YKfGQJ/UkvWAkh9+lPJykleBNTMEyPGHs=@googlegroups.com
X-Gm-Gg: ASbGnctemTG/3YB3sLLYZ4EHFTlzej+hLW1YrPxRRYB27I9oEBDIXHuxlgKrQYKo1BD
	KkLfH8Ee694TIY52gdDPwihGTau5qfoh1Bwxm568jQwsgm6h5QjtYFqUp1uobcJvLQiTOydUGx3
	dWsDXkYvcW5WidRtoCjptDlLQyPHeJklqotLMl4DaSoFuZRIkXK675feaXO/5JxK7bVYLlhHFEf
	AWNghM+uRoCv1dgK83cxOUpgs04BdInx6yYXB6BF1quIfYyB/W6srb1JqW76QJuPOakPxDAjj1t
	COrPUGIQPla+pgCDFuSRWywbGqiyArRPWHEBTb90ktVOabCxb5ICy4iPnBM2Hn5hNaO7JhawPoq
	/BTThYUv1dWQAL9UI6jk50paHGxLZqShVjsyX0401qS89dolImBcvWYAmhtabgUUx
X-Received: by 2002:a05:600c:1f0e:b0:45b:8adf:cf2c with SMTP id 5b1f17b1804b1-4620683f83amr19217985e9.26.1758115793372;
        Wed, 17 Sep 2025 06:29:53 -0700 (PDT)
X-Received: by 2002:a05:600c:1f0e:b0:45b:8adf:cf2c with SMTP id 5b1f17b1804b1-4620683f83amr19217705e9.26.1758115792898;
        Wed, 17 Sep 2025 06:29:52 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f27:6d00:7b96:afc9:83d0:5bd? (p200300d82f276d007b96afc983d005bd.dip0.t-ipconnect.de. [2003:d8:2f27:6d00:7b96:afc9:83d0:5bd])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4613eb27f25sm38795825e9.23.2025.09.17.06.29.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Sep 2025 06:29:52 -0700 (PDT)
Message-ID: <aba22290-3577-44fa-97b3-71abd3429de7@redhat.com>
Date: Wed, 17 Sep 2025 15:29:51 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1] mm/memblock: Correct totalram_pages accounting with
 KMSAN
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, vbabka@suse.cz, rppt@kernel.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com,
 dvyukov@google.com, kasan-dev@googlegroups.com,
 Aleksandr Nogikh <nogikh@google.com>
References: <20250917123250.3597556-1-glider@google.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250917123250.3597556-1-glider@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: BKG9dCvKKwbK0nT-UDuJ-WmVg6EVTJ3nf-wD8S7leGA_1758115793
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UtHN411b;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 17.09.25 14:32, Alexander Potapenko wrote:
> When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
> for metadata instead of returning them to the early allocator. The callers,
> however, would unconditionally increment `totalram_pages`, assuming the
> pages were always freed. This resulted in an incorrect calculation of the
> total available RAM, causing the kernel to believe it had more memory than
> it actually did.
> 
> This patch refactors `memblock_free_pages()` to return the number of pages
> it successfully frees. If KMSAN stashes the pages, the function now
> returns 0; otherwise, it returns the number of pages in the block.
> 
> The callers in `memblock.c` have been updated to use this return value,
> ensuring that `totalram_pages` is incremented only by the number of pages
> actually returned to the allocator. This corrects the total RAM accounting
> when KMSAN is active.
> 
> Cc: Aleksandr Nogikh <nogikh@google.com>
> Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>   mm/internal.h |  4 ++--
>   mm/memblock.c | 18 +++++++++---------
>   mm/mm_init.c  |  9 +++++----
>   3 files changed, 16 insertions(+), 15 deletions(-)
> 
> diff --git a/mm/internal.h b/mm/internal.h
> index 45b725c3dc030..ae1ee6e02eff9 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -742,8 +742,8 @@ static inline void clear_zone_contiguous(struct zone *zone)
>   extern int __isolate_free_page(struct page *page, unsigned int order);
>   extern void __putback_isolated_page(struct page *page, unsigned int order,
>   				    int mt);
> -extern void memblock_free_pages(struct page *page, unsigned long pfn,
> -					unsigned int order);
> +extern unsigned long memblock_free_pages(struct page *page, unsigned long pfn,
> +					 unsigned int order);
>   extern void __free_pages_core(struct page *page, unsigned int order,
>   		enum meminit_context context);
>   
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 117d963e677c9..de7ff644d8f4f 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1834,10 +1834,9 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
>   	cursor = PFN_UP(base);
>   	end = PFN_DOWN(base + size);
>   
> -	for (; cursor < end; cursor++) {
> -		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
> -		totalram_pages_inc();
> -	}
> +	for (; cursor < end; cursor++)
> +		totalram_pages_add(
> +			memblock_free_pages(pfn_to_page(cursor), cursor, 0));
>   }

That part is clear. But for readability we should probably just do

if (memblock_free_pages(pfn_to_page(cursor), cursor, 0))
	totalram_pages_inc();

Or use a temp variable as an alternative.


LGTM

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aba22290-3577-44fa-97b3-71abd3429de7%40redhat.com.
