Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB3OZ7T7QKGQE3H5LG7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A38A2F510E
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 18:25:02 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id f20sf1108066ljj.15
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 09:25:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610558702; cv=pass;
        d=google.com; s=arc-20160816;
        b=LMAfIxYCNIRrVhuXCqyDRjkBxiAZFCPN5uoSS78vgxVuMmwyXaOBcis/SRoIj3zoYO
         m/cRFl/S9aRlhClSYEC03w4aJvDyrLW5FS4iGEbKsaZRNMDfg9we3YAkwQ+2Et9IhjJv
         /1wnnEe8XrxOCz6u+3PbskHGm7zyjfaK3z+hbLtvAb9RzyvN3L1zmLZkv3Cqc+RcFYmu
         4SYcIwMC8NIhl+QdYhrMFyJcQyOTI8YZFz/g/T8HQWBCRQKBWyN48knds69WuTorTi0N
         MHbFXqf9LRTkdCyWb6V+IYw3MVBGdN/Bu9fy4Kb1/EaYtfgquwa/MsH1xmS/I6omtrUm
         vK+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=94LaGLStDD50DDSwMX3ZGalGuwjGKcNc8KIS94cbFLc=;
        b=p4BxpJOdS6j+UHpPDoAI49kTjkwDxH/VGQjd2OdQhqFj6Sh1t1beKrR9tHBrrGoj7l
         ISVbdMf7H+3e7LVmSCm9L0DiPTocyUs40+HWqVQ8ePxqdI/vw5Y9I8p1wyZwh00j3yu3
         NnovBYYdimRrNLSjZzXO4QWWus7K89pCk9NReqDUPSUtr3BCsXl4kGxbfuSW75AWemeo
         9aqwMewb5M8myrzajM9e+hwlC64cxRrVqyBJqYRGh2ojNr/+SxbbAmTcJcxMpOxXAybi
         9Fz2z77aMF+QuXqFlUZQti1T4OHfWJ/IpV6BnO1l1023qaL23WHZbWgFT/NGUe9fS0gf
         MJuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=94LaGLStDD50DDSwMX3ZGalGuwjGKcNc8KIS94cbFLc=;
        b=fUBVd/9Dk6scHnac2jLNKKQsz7gG0K/0EkEEe0EalvI9q5H/6qXcf+PUn5H1pNC4p6
         mJeFciqSLB50Nyqv5NH6VyKMb6uWrrDCAKIb+bg7sYMCHWFSSRmO9A7rLv2yKn25RlbU
         OWhrJc4Mxr/0oKlJXMK7SUR83UZ6HRyzeNEhdcelvOsXFXisW3osfxDLVcjVx007JcMi
         uJFebRIB/d/EC/kdNoflhysN1824lVQ7amqKsmJq1KugqAr6QR8zdJgiNs3mJZ9wDYiL
         rux/TRxdsOdjDr0GhGklZyfkM4nMZvHcQF9x0KooDV73Xz2+kcCBWoyVUx5ImqwxgRsx
         e/DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=94LaGLStDD50DDSwMX3ZGalGuwjGKcNc8KIS94cbFLc=;
        b=WBv+f0bR81AuMIPSxOqdaUjPDQNPhP6dp7xOZZ685B/xXLYEO0gWmX/tg62EYuquWa
         E2bCjkq5g4Y2lgyS2aA2wNKlYuvsrui0Px6V15QKSwLuzKZdhUGp83bkJwyEdzzhmj+f
         OlGtSwdNmUVXMdpIb6BxsuDXIx9cx4d8KzwSsSPeqnae2TcURl311mYXiiOBGJGwhTXJ
         tsIibwQXVP9kvLCRJocMvoYBY9qpSEuRHcx53INycvkcmP6W27lS393oO77rvp7CQX0P
         YfXBy392du5WhY1ZI1S3Dhm/2q+0ZxGBR6EpAh5uKORAiTT9YBP9NUsLY0nKUivFYAWu
         5pZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IUEQIyXJ0pCA6cePGNVkrBlJl669kiLIVRtGtnDxncLgx64CV
	aJFW8J5q+xpwA1ZUQvR6BlI=
X-Google-Smtp-Source: ABdhPJwg0nV9CugLPQ80cn0FYaDlsTF3SgXh6nruNk3Nkt/bYBMRPApJTxU88Twu0/KT14yBvDRD1A==
X-Received: by 2002:a2e:870d:: with SMTP id m13mr1326714lji.136.1610558701986;
        Wed, 13 Jan 2021 09:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7806:: with SMTP id t6ls484320ljc.8.gmail; Wed, 13 Jan
 2021 09:25:00 -0800 (PST)
X-Received: by 2002:a2e:b0d3:: with SMTP id g19mr1392382ljl.279.1610558700837;
        Wed, 13 Jan 2021 09:25:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610558700; cv=none;
        d=google.com; s=arc-20160816;
        b=ikpGKjBHHpjY67eqWBK2NNVnhmVVsUqt8ei5j8xNvIENXaK3qYr03KVf9AIhGXUMMy
         EQqFVWJ9Ulmkidn7MUexLKeAISuJNnI4RPXBvhClIPh2Si5wBj62blwpE6VHzg6z89KU
         SaRvSlDv9nx0OOnixHdd5qw8Tcityi92dbpe2GsX+ux9M44xU5s0yBdcr113Va0TRhxd
         2WdYVBVoV7zcBpajOh9UBaA3jMdRpSrl6u1UIqrx3pX+OTGHcLmEUNms9kfzmTNpxubx
         ccUshm4Q9OTmb9Mof0uiVxErsT0dSQR1Vr0Q5H6gYnaUVQz2ULw0hUzhtdg02J5xE/Pl
         iWGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=D1vwl0f2mresUg2Scd/Va0+q+JfPdFFKQF2Jvx8WJCA=;
        b=hVlX20EHchv7YLHgWOLznvvdQhsxVfZoc4pHQOoFj4M0RHI3A9IOCkuIoFG2aQYyAp
         Gd3ocnFa3rwpZsmnlFRF652vzYT2ftMW1IcCPXlJde2wXhYBZ95YDuMpg0sIiiMuxYQi
         CIOdo+H8VsX29Yy/qsfC1VYHjumx9rhIv7Z1e/th8ulvqE3ZCIsuI0/6f18+hQtI8Won
         H2Bh9YkVm9addLOlUsLXGHezHwKUJwgvsquV3GQp21+qatAm6Czt60xepZoG2X3Pon+2
         IECiUcywPryzwoA8b/8sAQJQdBI6apOOXTGeWqFI3sXMMXbPx+HupXWm6RycBEAYnDXR
         ZNrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id u25si116970lfd.11.2021.01.13.09.25.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Jan 2021 09:25:00 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 023E0ACF5;
	Wed, 13 Jan 2021 17:24:59 +0000 (UTC)
Subject: Re: [PATCH 1/2] kasan, mm: fix conflicts with init_on_alloc/free
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will.deacon@arm.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1610553773.git.andreyknvl@google.com>
 <7fbac00e4d155cf529517a165a48351dcf3c3156.1610553774.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <25aa25d6-080c-ccfa-9367-fc60f46ff10f@suse.cz>
Date: Wed, 13 Jan 2021 18:24:58 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.0
MIME-Version: 1.0
In-Reply-To: <7fbac00e4d155cf529517a165a48351dcf3c3156.1610553774.git.andreyknvl@google.com>
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

On 1/13/21 5:03 PM, Andrey Konovalov wrote:
> A few places where SLUB accesses object's data or metadata were missed in
> a previous patch. This leads to false positives with hardware tag-based
> KASAN when bulk allocations are used with init_on_alloc/free.
> 
> Fix the false-positives by resetting pointer tags during these accesses.
> 
> Link: https://linux-review.googlesource.com/id/I50dd32838a666e173fe06c3c5c766f2c36aae901
> Fixes: aa1ef4d7b3f67 ("kasan, mm: reset tags when accessing metadata")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slub.c | 7 ++++---
>  1 file changed, 4 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index dc5b42e700b8..75fb097d990d 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2791,7 +2791,8 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
>  						   void *obj)
>  {
>  	if (unlikely(slab_want_init_on_free(s)) && obj)
> -		memset((void *)((char *)obj + s->offset), 0, sizeof(void *));
> +		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
> +			0, sizeof(void *));
>  }
>  
>  /*
> @@ -2883,7 +2884,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
>  		stat(s, ALLOC_FASTPATH);
>  	}
>  
> -	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
> +	maybe_wipe_obj_freeptr(s, object);

And in that case the reset was unnecessary, right. (commit log only mentions
adding missing resets).

>  	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
>  		memset(kasan_reset_tag(object), 0, s->object_size);
> @@ -3329,7 +3330,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  		int j;
>  
>  		for (j = 0; j < i; j++)
> -			memset(p[j], 0, s->object_size);
> +			memset(kasan_reset_tag(p[j]), 0, s->object_size);
>  	}
>  
>  	/* memcg and kmem_cache debug support */
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/25aa25d6-080c-ccfa-9367-fc60f46ff10f%40suse.cz.
