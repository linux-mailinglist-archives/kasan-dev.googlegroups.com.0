Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEUDW2SQMGQEAV3N2DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id BE8E174F504
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 18:21:40 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-682a4f1253asf9018152b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 09:21:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689092499; cv=pass;
        d=google.com; s=arc-20160816;
        b=fZhyLnGHqLyoSupbGJy9DtNAscjQObVFUIqmRTOjJCj8xfYpRRs6UGZbnRHphinVBy
         kxua6m+whezezCmRWk/ZgjJpERnblWpqwNXDi8wwoWYMMKVbGvQcSnkQoB26zoXH08uY
         /eMgN/9Z/EBprjtrlQO/0hb7G/XWq0Cg3iGXl/ooBXI9AyyJ7HOMou1VHpMsQxDzFAwP
         Derkkp0NR+4EsM0TB5Wb6NUizUDF2ZjxbDGM1/HW4Ph7lNsJshgDtmDFmoCFq59wCSkL
         yv1t2BDMZPLNxDXvxH9TCG+I8rtrSAqA4/FKJjNpuvgEhqKXXE8pvD3WLS8GR9oCB5MG
         KWNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+MKB77X0P57N7ApXCCFFe6K9I3+k3oDEgXlS+QhuFIw=;
        fh=uVhf7W460rgBYDoMEVmAaCiCt78MDctxX7/FHURrW1A=;
        b=m59gVHXjvjzUWzu1x0aX7c6IfAzdIqXRXYEn/CyODj7al6JSbbpHRfRDpncntYtbm9
         MONeqfFRlGW/g8abwQJ9qA2wjetNrSgLnYI1Bdr+t7m5FqWIIhDgFkU7yr/vsYtXGixC
         eVQ+olLw/zEAOsEfkFfcuPNXhHYEnvAJybKs1c6XrznGmZDWcoGbaS6XmtrTs65K9qi1
         Z2CAyiHbFIjfxIS75iVGPYTg6rlA0wOEqItRUV4KrRhHfzyw6tyBNM7zlnYJKR9pWEx+
         rrFhcblvvV/OYd5xswvthjdhNpvY4NEQYogsj4z1jPvTLnfaYqL4uHexFFsw7ZY2wUX/
         b9bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=gpWbxLEJ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689092499; x=1691684499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+MKB77X0P57N7ApXCCFFe6K9I3+k3oDEgXlS+QhuFIw=;
        b=dpjKjCm6soUiIADS/bGtYXQzg8OqX411smeSPYLzrPsOjpAkgXhKytcZOrkIFGby0+
         o8QJTNFcPXyVyhZQnT5RUSS/bYObTUFkk6bkIkPQMXQXXSqSlkmVQ5N6HsImH+nUDi1S
         MDZ219uZ88oyT5RIrdTnbm4GqYmNfByQ6ABAyYYdffpbrEn6bRTUv9Iuw2DcuDxYFrjR
         ZL72LVB49/C5LvDsjc73/4vUSyq0cQoIgxJAEolxbEOoRX9DDBkNNU+4Jao8KxYG/m7y
         BQxpEBHaW6oT+YaKnEPD5Q4L/vl1wwAWH+Y3OcboxN9uysOXQUP4evzudFjA1e5zfSnn
         a7rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689092499; x=1691684499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+MKB77X0P57N7ApXCCFFe6K9I3+k3oDEgXlS+QhuFIw=;
        b=lUyvCIh41pWl9Wyu7rLubaFnw8NapBfDqNP2jiLyf7dq+rREnX8v7EzyD1l4E1WOA+
         WNJQwl6UGWljz7Zs2EHbQPZsTEbZFVjqnz2Fv6T/72n/hFwpunWOVRtLe1Kn342l7ZfM
         Iex2fSrRs4+NKRfqsKu4CDuwV8Mc/EGsN1U/4Fi+uBmQQd9+Mq6O0jPG0mj/mRcHRqgd
         ZqpqDGSnup9bsBiu/Ht8Y+OTGSOjBaNgH+IuyMMLW2muWssYQXerzrRzgbQB6th2Jx0p
         lYDM5RqTAJYM09hWBm9BE8uw4Zmn2y6j+UVaVFSvqhR5wQIsJq7QKuagxUJEzM6azZ2j
         wTUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYvfHURf8KDX9hCp+OitaLWsJGT7v4M5smALi8rxHudlNnYy6zw
	D0IXnO+vPELCI5StiKWE1JE=
X-Google-Smtp-Source: APBJJlHhATDYFmNCdNXOmzHAw/S1MWAdDcTuofQgTlqA5BrcAOGPnk7MZBuQwo6znvFvndhDYy4qTw==
X-Received: by 2002:a05:6a20:3951:b0:12f:acc9:286 with SMTP id r17-20020a056a20395100b0012facc90286mr24428720pzg.17.1689092498675;
        Tue, 11 Jul 2023 09:21:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96e7:0:b0:669:ebf8:2ce4 with SMTP id i7-20020aa796e7000000b00669ebf82ce4ls5105368pfq.2.-pod-prod-00-us;
 Tue, 11 Jul 2023 09:21:37 -0700 (PDT)
X-Received: by 2002:a05:6a20:3ca7:b0:12c:8aa2:8b59 with SMTP id b39-20020a056a203ca700b0012c8aa28b59mr21215472pzj.28.1689092497629;
        Tue, 11 Jul 2023 09:21:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689092497; cv=none;
        d=google.com; s=arc-20160816;
        b=u6cEJvUQDNRQ70U1pN0J/8VtJIHlINZ2zCKDcv6GKcI3DoM0EXcJpPYZtnFav1ybRZ
         jIWe7pgyziZVhxiFYbAnNy9b705iCwGs0Uy1UiOxnkgXx67QCIudsSZ+OBTPv4N53Wk0
         wDuHXBmDnvCUn5NdYrdVKq/Sib6t9fbODdJJ4DKLEGEbE3JiEb3tf5sUKbu8Wh9cyreT
         RTArH5j8rosCxIFPLbP4/kMCmYJIjxAHoM1UC90zJO1+bMgB96T6yPR3gMO6+CBmuTxY
         vWTcBUW4lYU5ZwWw3yYytm/IHta9V0G5MBpDVFffm4gkMbGrKyyo2XBG9XFz1ZicnHEA
         5H5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FRd6MSnrDwuyQ7znWMqv6yCTnL1/DCJOC7bU8PD4YHA=;
        fh=uVhf7W460rgBYDoMEVmAaCiCt78MDctxX7/FHURrW1A=;
        b=kZS1Y1l602XdlLlZpJbdR/sxkR9xlB9EQlNo2CSa//kWrA9Gh8Vlb3U9Nz815slfh5
         V+KVPIDyw8nhpsyPRrdVLAsenRr0E0BOFEJb4deQJYDvT/fHN/QjD4mfxo7PSkiaEKxl
         g4qOa16PMOMm9qi/WPStwtL7DmC2fhtR7VHaFOn/OZ2K2wbqqQEj4/+d6pPkC6Mz+3Mu
         Bo28thjgmdFAyFJYgyNnsmy3X1lmCTX9ZV6Adx8QjzP7TV8Hk0CDpplv63r7UuDoB/Sl
         yhEGWfOjErs9zsdnWF8bTCjc37PvTLHZc2IrUwfrCLbiqpxQrrZD3eayscgFZtgD7wte
         wD9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=gpWbxLEJ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id fh5-20020a056a00390500b00681f56016b9si221144pfb.4.2023.07.11.09.21.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jul 2023 09:21:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6726d5d92afso4485577b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Jul 2023 09:21:37 -0700 (PDT)
X-Received: by 2002:a17:90b:1d02:b0:263:114c:52fc with SMTP id on2-20020a17090b1d0200b00263114c52fcmr23830843pjb.12.1689092497290;
        Tue, 11 Jul 2023 09:21:37 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id dw16-20020a17090b095000b00260cce91d20sm2026175pjb.33.2023.07.11.09.21.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jul 2023 09:21:36 -0700 (PDT)
Date: Tue, 11 Jul 2023 09:21:36 -0700
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	patches@lists.linux.dev, linux-kernel@vger.kernel.org,
	Matteo Rizzo <matteorizzo@google.com>, Jann Horn <jannh@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH 2/2] mm/slub: remove freelist_dereference()
Message-ID: <202307110917.DEED145F0@keescook>
References: <20230711134623.12695-3-vbabka@suse.cz>
 <20230711134623.12695-4-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230711134623.12695-4-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=gpWbxLEJ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Jul 11, 2023 at 03:46:25PM +0200, Vlastimil Babka wrote:
> freelist_dereference() is a one-liner only used from get_freepointer().
> Remove it and make get_freepointer() call freelist_ptr_decode()
> directly to make the code easier to follow.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 16 ++++++----------
>  1 file changed, 6 insertions(+), 10 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 07edad305512..c4556a5dab4b 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -397,18 +397,14 @@ static inline void *freelist_ptr_decode(const struct kmem_cache *s,
>  	return decoded;
>  }
>  
> -/* Returns the freelist pointer recorded at location ptr_addr. */
> -static inline void *freelist_dereference(const struct kmem_cache *s,
> -					 void *ptr_addr)
> -{
> -	return freelist_ptr_decode(s, *(freeptr_t *)(ptr_addr),
> -			    (unsigned long)ptr_addr);
> -}
> -
>  static inline void *get_freepointer(struct kmem_cache *s, void *object)
>  {
> -	object = kasan_reset_tag(object);
> -	return freelist_dereference(s, (freeptr_t *)(object + s->offset));
> +	unsigned long ptr_addr;
> +	freeptr_t p;
> +
> +	ptr_addr = ((unsigned long)kasan_reset_tag(object)) + s->offset;
> +	p = *(freeptr_t *)(ptr_addr);
> +	return freelist_ptr_decode(s, p, ptr_addr);
>  }
>  
>  #ifndef CONFIG_SLUB_TINY
> -- 
> 2.41.0
> 

I like reducing the complexity here, but I find dropping the "object"
reassignment makes this a bit harder to read. What about:

	object = kasan_reset_tag(object);
	unsigned long ptr_addr = (unsigned long)object + s->offset;
	freeptr_t p = *(freeptr_t *)(ptr_addr);

	return freelist_ptr_decode(s, p, ptr_addr);

?

They're the same result, so either way:

Acked-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202307110917.DEED145F0%40keescook.
