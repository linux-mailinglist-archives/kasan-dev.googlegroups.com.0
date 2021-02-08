Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKVVQSAQMGQEBLVX2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B2ACE313003
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 12:04:10 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id s18sf12655892wrf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 03:04:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612782250; cv=pass;
        d=google.com; s=arc-20160816;
        b=z4NfOSpRjM1k+0FsAEX2kBBjaES2Y7HRWrNcytLbDT3Qv9xK98VBqM4aYYW5kVJUqe
         iAVtuPZ0cs9n7ciNEihumyVlcbuG4tzIZbwouIOrwXKAobyG+YxK7zdEaK/Uv9Fi/9FR
         BYA4DCJ8gTHVWzj219+qHANKYcYBXcHl2MYLl/GZ3bzSoK2uLQeIthtae7+nSjS/3uj8
         4Z17PZxuOJL+BeBAjheJAhJEW131f0GABorcZ3VvkpGEWPc+ykbPgZtHmVnXQdi7yZ23
         Y2JHF3H1czEAfoD13N2oFjvVgjSSCrBQWC91cp2i4ai5Hm8JvhJQ0RX2zHZF9dTg+WsM
         KJog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RKS5wForVf3hW2hA3WdzoBUlv6ufi3W/dnf+aGRFqy8=;
        b=INnBHuLQMLLJrHNDWxlUn/OBjQFVvIjkowb843Db0nhlp5nu+VHgwvIOb1jmVw3wVY
         d1FUBcZp7W1vXAF08A4e2TbVMpHetDoZUuEB0ZeZYQAckvZaWe86p+jHytVtFLS1/suc
         vRaHE2VZy0FbVxoYGP03fb+HktLZ3Ld8/23NItbVWiQ/DWLx+S6tHGEBYqeHhr6XFBm1
         7Oj2a1AJGYfrgdFoLkPyjoco4skcjYM2WY89viXkSNgMm2dc0DjejUTYxKY6VQXoxpgK
         4oPaVqu6nZg+TFjQxQTchtSGM3RGQdiKjys3FRswh6QAjP94pRoBciqw1ZLJh0LCyxwr
         sUXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iniQAbHQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RKS5wForVf3hW2hA3WdzoBUlv6ufi3W/dnf+aGRFqy8=;
        b=ppx1aPz1/ptKXSCR6NMBm4bRTbmEHd9z2XI5fdpO0iA42hSvA47smJbfQMFqaRjsut
         xMIYKImXqmxM2XK5pbu8+YFytYA0XzBoI9AIrOXDzp3gP/2PMjwLOgCsWzQdI7+/P7ED
         UCIEbHKHkhR/ns745mAAOx43i4qY0JwFZ0ANq8W4dgYHMQxxivpxKNif+4UScvlFB7LM
         dr15b2mW05hPrx51M9Akcbxf+qnecLm0sWuYbXSsxxuAwmJOLNeY1gll5x2lVeelpDbc
         ozEWWuHsT2UKvWRtru8C3F1Q0YOdIlT6qnVujBXcGaeJX+CYyuAFZghSSw5eQnkv1Vdb
         Wxwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RKS5wForVf3hW2hA3WdzoBUlv6ufi3W/dnf+aGRFqy8=;
        b=cxLCFzejdCBAZ1Ppk7TQTdgFHvX1fJhMfK1bgkepPUz27TvyX8kkIfi3FabpAuld9F
         6pnN8E4dLeDHsFS/u7aXOq5OSKIjdusZ5OiWbw5jZMCe42F999AZsTvHKT2IrkPvLtNt
         l060R9sJ8qS8MS4/WzAvwriviNqtTY7rT2VH1EfgfLj5i5Y2y/FQVsOmO5te4plqqM/B
         j0IBFSlbN04clBJkUUJULlP9b4JvjzE307kelK50y735CGbxHIZJ3AmJVk2wI9T0SPX3
         RLdQDIevYTgU6f93l0GZ/AgIAkM0nRWpgjMQnKxz0oxkC6qZhYHR//hwGLk7rmkYah7L
         7p+w==
X-Gm-Message-State: AOAM5316BOEANDvHdgHXwJ4ZDpHSmd2dQ4mmy6rWgozT/o9TU6EYXmXG
	Ixny7IVP2kuyow89fpYvZos=
X-Google-Smtp-Source: ABdhPJyuF3xPDAryDQvn5Ux7kkiOMhlnsiOAts/3jq8Ds8LOTzKEpfRXVg+crZYwfNdZ/XiHKs8m5A==
X-Received: by 2002:a5d:6684:: with SMTP id l4mr19751235wru.111.1612782250479;
        Mon, 08 Feb 2021 03:04:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2ecd:: with SMTP id u196ls7130872wmu.1.gmail; Mon, 08
 Feb 2021 03:04:09 -0800 (PST)
X-Received: by 2002:a7b:c95a:: with SMTP id i26mr14197522wml.164.1612782249663;
        Mon, 08 Feb 2021 03:04:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612782249; cv=none;
        d=google.com; s=arc-20160816;
        b=NSIl+cY+lLTHMkJTVaEnbBncuJR0UmCn+sXFfRU9Gbh6NglFqb750D0NrIa9czTVr4
         g4zI0n8UgZqQK7KXAdGM8X294KNzQ5whRb6i5fq9LWiAg0Xqu5uE5ds8VVVZsdoSx9Ka
         50nyzQmEEC2ZmzYcR07dmt/WYfHDIw65j75Z0fn06kwSf3av0W1ib+U3ZGiGcQb09dU8
         Xq9tkT6v81gCIl1pBgDy1v5fCQ9sRaZiBemn4S+hoo05e+8zWFNuGUm7aReKXaE/bNbz
         IJt8D1IAHLdYfrDvyXKNFbKiLu7HmdlAt1MvAkGE7s9w2Ecu4+90Xvp5j4cXt8PsU2k8
         R22w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pufLM1lgk30Z0xNUrr/sKibBHabmfyHL7QD1WY1Y8VI=;
        b=sGbTZIr1mra0OO6QJwbyJcYqrk1ysglFhEvvfuikw3yXbOC4OSWwM9nU4olg8/fj7i
         nXfnv3IbFdItG4jitbBekIXkefnLvYHUgeNHXC7gtb4ygWK7FmIEqhitQGw9/dgKDxP2
         cfeP6o5P5pqn+hoZQKXYm8euHPTuKr46elAzalu1AqWMZXaEPIKq+s6Y7ljePtxycvO7
         BrgkAZbEIdNM1uJPrPkJFggvUbgQ7M31/Op7KXKBGZHornKCExFwT7AYGzMQBZDZ+r57
         3C6TD3fuSgTMxHk9/s1d4bV6FmxXSuiAzAk2oo6HH8lq+RGaBflQde81qrsrp8VXjz85
         dipw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iniQAbHQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id n13si114302wro.2.2021.02.08.03.04.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 03:04:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id g6so3550300wrs.11
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 03:04:09 -0800 (PST)
X-Received: by 2002:a05:6000:192:: with SMTP id p18mr19149327wrx.69.1612782249203;
        Mon, 08 Feb 2021 03:04:09 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:497f:76ef:2e62:d028])
        by smtp.gmail.com with ESMTPSA id x82sm14752706wmg.31.2021.02.08.03.04.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Feb 2021 03:04:08 -0800 (PST)
Date: Mon, 8 Feb 2021 12:04:02 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 mm 11/13] kasan: inline HW_TAGS helper functions
Message-ID: <YCEaohDsfF8MCl0N@elver.google.com>
References: <cover.1612546384.git.andreyknvl@google.com>
 <2c94a2af0657f2b95b9337232339ff5ffa643ab5.1612546384.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2c94a2af0657f2b95b9337232339ff5ffa643ab5.1612546384.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iniQAbHQ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as
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

On Fri, Feb 05, 2021 at 06:34PM +0100, Andrey Konovalov wrote:
> Mark all static functions in common.c and kasan.h that are used for
> hardware tag-based KASAN as inline to avoid unnecessary function calls.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c | 13 +++++++------
>  1 file changed, 7 insertions(+), 6 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7ffb1e6de2ef..7b53291dafa1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -279,7 +279,8 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>   *    based on objects indexes, so that objects that are next to each other
>   *    get different tags.
>   */
> -static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
> +static inline u8 assign_tag(struct kmem_cache *cache,
> +					const void *object, bool init)
>  {
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>  		return 0xff;
> @@ -321,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> -static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> -			      unsigned long ip, bool quarantine)
> +static inline bool ____kasan_slab_free(struct kmem_cache *cache,
> +				void *object, unsigned long ip, bool quarantine)
>  {
>  	u8 tag;
>  	void *tagged_object;
> @@ -366,7 +367,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  	return ____kasan_slab_free(cache, object, ip, true);
>  }
>  
> -static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
> +static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>  	if (ptr != page_address(virt_to_head_page(ptr))) {
>  		kasan_report_invalid_free(ptr, ip);
> @@ -461,8 +462,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>  	return tagged_object;
>  }
>  
> -static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> -					size_t size, gfp_t flags)
> +static inline void *____kasan_kmalloc(struct kmem_cache *cache,
> +				const void *object, size_t size, gfp_t flags)
>  {
>  	unsigned long redzone_start;
>  	unsigned long redzone_end;
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YCEaohDsfF8MCl0N%40elver.google.com.
