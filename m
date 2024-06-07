Return-Path: <kasan-dev+bncBC32535MUICBBPFIRWZQMGQEMOXKMFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id BA115900BF6
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2024 20:41:01 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-44045bc46eesf48391cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2024 11:41:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717785660; cv=pass;
        d=google.com; s=arc-20160816;
        b=eLuVMiPT48/65IGqaIdUZCtcEEKcW4jRYQ3MP89+OF1CnNqp2ziAxWlGF2B1uqnslT
         XX19qvLwpuoZLMVrW2LPhc/uN/EUUyeBUKz/sOE5lkQHq6E1tgporDCIftKyzWv8zM8V
         8dClP8csY5TEgM1U01wbEKceKSVJMuJBA2T2vX7JPNNA+OD3NGfgJbgGS9zfa61+4uGZ
         3hRm06E/wBdrTjNYiw0/XOPsRjfgDQSD3MrKao72hmgyFwnqSry9Mh5SqzkC9L2FgJpG
         sjMd4AbaCqaEFKFWlwV8aKd3nNLj8a1qv1AuPSfMuAoCM1KP1FqbtGduJqWZKXuy+kUl
         Wasg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=JaiT4xJnbPwsmI7msJ8v2k+3YrqqIiv2+QKxNVl6wU8=;
        fh=OkOQ4oa7zZZbgQIBDqpMeZzSCVHoDtn5pe15aNBU3Cw=;
        b=C2ufAeKYBnljb3xfv0OGFBoMy2AnI3kwCoGQFFI6s1L7kOfrmnJBqIys/SqPEQKG/a
         OTNE9JnJElvNMfOktEEYdX+ITKzRuBLmnsJy3syIjrbabBfVSH/4Oljkv3IietT4trL6
         EysXHe/y6kVFe3HMz193YFCHP2X2Y8zkL0fm7HmmcnxzyZ4FTOMVUwr3QCG1OeamJoDV
         njQGh2my7JBKEFsF0zwgjtdhH1rVJH03+cQvXpYdQB1UnoTOcOfBtN/tafriraB/BDmP
         +kpDo7ABsGHZEq7kRHVVT+S3mykitwHf57kvr2FTYEXJEXswGn2AzTFOM863ERrDNqlN
         V1Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OFXzYyMx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717785660; x=1718390460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JaiT4xJnbPwsmI7msJ8v2k+3YrqqIiv2+QKxNVl6wU8=;
        b=B2f8RfeHgyzvgOd1I8y0aSaCgPBZ0+/LeFCBv4Ye/IDON5Kg+PfD89AItvZbMsNtrP
         9V2VDvLO/qFegql5j5PRgZu+Q0n0M6P4ot7EfMY56zgiGJlIqATOCXJ9R0pLUYErm/li
         uvqoHGiG36pIdrSd4U0ox6ztMdROBfosK3+XW9YYh0Zt88/664624lPflvoNK3Fiy7hn
         1IbedO+oLa0rVJKdIN5CuRnVIx7E6FM/2LlL03OAXSYXnzbxG2PaaHgau7EqqyEs3CP2
         VpWdfOIc6YdESBqX7ApyvfYEw0kNMQiH41RdD9NzcqqIykUwL++UdRAmggnGGjhqXHI6
         FlOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717785660; x=1718390460;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JaiT4xJnbPwsmI7msJ8v2k+3YrqqIiv2+QKxNVl6wU8=;
        b=ZGcYV0kZP7Q0gbQgPZFEf/dWLOt62yPeg3aYx7otroCxZ04nbbMKG8yHaSDguI4xAa
         lWtO7VHUw2HzZ5AkA2Wr7GYgDaOTxcBbrLKB8iIJa+Yr8ILCFO11Vw/KEPIJVAIpUywz
         1GVBILv1/ELXJKU6SKMbQRJUoqPJ+g49icEM96Sata3wDkLDGyX78VhPkItb5t1dQiam
         BetcgmK9R+e6/9z158teA+BqkmNW0rRoY+cyXr2KkSWWUsx31xaLspDWDfrAXMe1QfBw
         skYm1rjp9DJnuoAalZ4hxCDSVkUY+HKWx3gElc6cdSWPb2T/veDjTI0iT/MOMSFdsDoM
         pbPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXu3acn4+INZuHH9lRdy7Ez1F7qrGh3N0BApCuQDtVl7ZEG6fIAuDs/8+RCyIVdpDNAq4JaC1+M6ky0d+EOgE8ZzUwVbGN5Zw==
X-Gm-Message-State: AOJu0YyyreWPtzqLdSWSSfcuoJt/esE5Pl++FOYh6p4uUVx1cs1vCK76
	HIgmCdy9RiDTkKfd4pvwrZZyAnWIfn7FmjeRENnxEwPO8TZvAALc
X-Google-Smtp-Source: AGHT+IGuo0sQ4EdmBsz7D8tf7YtKHtlTgfIHbUodGbVmoyuT57Fh2lYaRxL9/4wD/FQ7JJ6jiQdwEw==
X-Received: by 2002:ac8:4f46:0:b0:440:200e:88c with SMTP id d75a77b69052e-440567d2d10mr110391cf.27.1717785660349;
        Fri, 07 Jun 2024 11:41:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1390:b0:440:c13:e7e8 with SMTP id
 d75a77b69052e-440406711d6ls20061771cf.0.-pod-prod-03-us; Fri, 07 Jun 2024
 11:40:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRAPByEXwxFDZXVXQ0bfJkTBME/NWgRrTn3fDBqJJTuRoSO777w3DkY/Zv7GstBUxQvt5lh9oyJj5zS0644JcGugiW0Noj0Z3d5Q==
X-Received: by 2002:a05:620a:8521:b0:795:387e:cd57 with SMTP id af79cd13be357-7953c652bd9mr276389685a.44.1717785659340;
        Fri, 07 Jun 2024 11:40:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717785659; cv=none;
        d=google.com; s=arc-20160816;
        b=aYEJJLEMMfL3EPvmzeLbH/wBdZO7nmXy00cyIbQl4cGqjTItZkMAW3AVbfQaNnBTOq
         F8aXhJi1ZSe/Zu3UCM1e5hyWn6K9b2RkTHlnElEFpNrhi7rbL+vy4p7BFXzdM5DB+wHC
         x23fuGB6wIZ+/hBC2OBX+IFu4+6jmbXr3+5HUk6Mq5FGMPRTJr7WPZ7RDgGuzNYNKsFB
         c/94cYQ9KDB6WU/QlnoYHR1bGlgJtxVPU+XSTg47nLtm+guAQci7q5+5ODzx2BC7SKlX
         zbnNeGMIyJgBRukkHieD/KH14Kq+phCVamcSvEUnwObUVcc40M98Kp9klyP5L46xpNr6
         cnCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=J1hUmjCQX6fG/8RrOn/s4Zg+H1krUQrxIX7N8cOfAjs=;
        fh=ya15RDm/0cXT1NKkaaP41oLBcByZuDrLbOMnFVsmx9s=;
        b=CTpa5vvYpRxmfZEL0i3yDuh06gfsGnbZAD//4PsNKwDJ+qS1vj3v4juxQj6EhyV3/H
         23iD2k0B4QgrQpXySo3XAw98uIFZItU3RMuI9odcyk1UgzPqx0GHl20YUB4xH0g4Nz2t
         QZevIcp74YSGIov52UnKAl3J1k1roe/tYWoRlJPRerU+YK0gT6mmWe9WYee6fGtDlJKh
         ERzU1IxAGk9MaBAz8oiDqLwEjA1l+79dKqhU2kXf55IluF7IVE4vodSGCHmgdmPTN1TU
         /AWVPTwCLfCnWAzKp8B83s8/+sllSRcaeVFwOTrxyB9al19mKJoGfRZowoz1xRAFxUdW
         7PXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OFXzYyMx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79531c7faa1si17524085a.0.2024.06.07.11.40.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Jun 2024 11:40:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-30-ipwJE0wVPYiI2qVDzV9rlQ-1; Fri, 07 Jun 2024 14:40:56 -0400
X-MC-Unique: ipwJE0wVPYiI2qVDzV9rlQ-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-42159c69a28so17489695e9.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Jun 2024 11:40:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWC63lO5B6FAeSel6tlVqfNOVGQQcUWc3UyBTsew1UkV8fgYPPEz/KJy8jp0eU7I/P9xStEVg2VbzrOhrgQFYrpvS5ulYBcrnyYdg==
X-Received: by 2002:a05:600c:3b22:b0:421:1f68:f80c with SMTP id 5b1f17b1804b1-42164a3274cmr33023965e9.25.1717785654949;
        Fri, 07 Jun 2024 11:40:54 -0700 (PDT)
X-Received: by 2002:a05:600c:3b22:b0:421:1f68:f80c with SMTP id 5b1f17b1804b1-42164a3274cmr33023775e9.25.1717785654411;
        Fri, 07 Jun 2024 11:40:54 -0700 (PDT)
Received: from ?IPV6:2003:cb:c71a:2200:31c4:4d18:1bdd:fb7a? (p200300cbc71a220031c44d181bddfb7a.dip0.t-ipconnect.de. [2003:cb:c71a:2200:31c4:4d18:1bdd:fb7a])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42158148f43sm93769755e9.33.2024.06.07.11.40.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Jun 2024 11:40:54 -0700 (PDT)
Message-ID: <b72e6efd-fb0a-459c-b1a0-88a98e5b19e2@redhat.com>
Date: Fri, 7 Jun 2024 20:40:52 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
To: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org, linux-hyperv@vger.kernel.org,
 virtualization@lists.linux.dev, xen-devel@lists.xenproject.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Mike Rapoport <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240607090939.89524-2-david@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=OFXzYyMx;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 07.06.24 11:09, David Hildenbrand wrote:
> In preparation for further changes, let's teach __free_pages_core()
> about the differences of memory hotplug handling.
> 
> Move the memory hotplug specific handling from generic_online_page() to
> __free_pages_core(), use adjust_managed_page_count() on the memory
> hotplug path, and spell out why memory freed via memblock
> cannot currently use adjust_managed_page_count().
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>   mm/internal.h       |  3 ++-
>   mm/kmsan/init.c     |  2 +-
>   mm/memory_hotplug.c |  9 +--------
>   mm/mm_init.c        |  4 ++--
>   mm/page_alloc.c     | 17 +++++++++++++++--
>   5 files changed, 21 insertions(+), 14 deletions(-)
> 
> diff --git a/mm/internal.h b/mm/internal.h
> index 12e95fdf61e90..3fdee779205ab 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -604,7 +604,8 @@ extern void __putback_isolated_page(struct page *page, unsigned int order,
>   				    int mt);
>   extern void memblock_free_pages(struct page *page, unsigned long pfn,
>   					unsigned int order);
> -extern void __free_pages_core(struct page *page, unsigned int order);
> +extern void __free_pages_core(struct page *page, unsigned int order,
> +		enum meminit_context);
>   
>   /*
>    * This will have no effect, other than possibly generating a warning, if the
> diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
> index 3ac3b8921d36f..ca79636f858e5 100644
> --- a/mm/kmsan/init.c
> +++ b/mm/kmsan/init.c
> @@ -172,7 +172,7 @@ static void do_collection(void)
>   		shadow = smallstack_pop(&collect);
>   		origin = smallstack_pop(&collect);
>   		kmsan_setup_meta(page, shadow, origin, collect.order);
> -		__free_pages_core(page, collect.order);
> +		__free_pages_core(page, collect.order, MEMINIT_EARLY);
>   	}
>   }
>   
> diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
> index 171ad975c7cfd..27e3be75edcf7 100644
> --- a/mm/memory_hotplug.c
> +++ b/mm/memory_hotplug.c
> @@ -630,14 +630,7 @@ EXPORT_SYMBOL_GPL(restore_online_page_callback);
>   
>   void generic_online_page(struct page *page, unsigned int order)
>   {
> -	/*
> -	 * Freeing the page with debug_pagealloc enabled will try to unmap it,
> -	 * so we should map it first. This is better than introducing a special
> -	 * case in page freeing fast path.
> -	 */
> -	debug_pagealloc_map_pages(page, 1 << order);
> -	__free_pages_core(page, order);
> -	totalram_pages_add(1UL << order);
> +	__free_pages_core(page, order, MEMINIT_HOTPLUG);
>   }
>   EXPORT_SYMBOL_GPL(generic_online_page);
>   
> diff --git a/mm/mm_init.c b/mm/mm_init.c
> index 019193b0d8703..feb5b6e8c8875 100644
> --- a/mm/mm_init.c
> +++ b/mm/mm_init.c
> @@ -1938,7 +1938,7 @@ static void __init deferred_free_range(unsigned long pfn,
>   	for (i = 0; i < nr_pages; i++, page++, pfn++) {
>   		if (pageblock_aligned(pfn))
>   			set_pageblock_migratetype(page, MIGRATE_MOVABLE);
> -		__free_pages_core(page, 0);
> +		__free_pages_core(page, 0, MEMINIT_EARLY);
>   	}
>   }

The build bot just reminded me that I missed another case in this function:
(CONFIG_DEFERRED_STRUCT_PAGE_INIT)

diff --git a/mm/mm_init.c b/mm/mm_init.c
index feb5b6e8c8875..5a0752261a795 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1928,7 +1928,7 @@ static void __init deferred_free_range(unsigned long pfn,
         if (nr_pages == MAX_ORDER_NR_PAGES && IS_MAX_ORDER_ALIGNED(pfn)) {
                 for (i = 0; i < nr_pages; i += pageblock_nr_pages)
                         set_pageblock_migratetype(page + i, MIGRATE_MOVABLE);
-               __free_pages_core(page, MAX_PAGE_ORDER);
+               __free_pages_core(page, MAX_PAGE_ORDER, MEMINIT_EARLY);
                 return;
         }
  

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b72e6efd-fb0a-459c-b1a0-88a98e5b19e2%40redhat.com.
