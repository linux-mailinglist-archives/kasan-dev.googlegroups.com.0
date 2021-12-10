Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB3UEZ2GQMGQEVGKO3IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4610D4705E4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 17:38:07 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id p7-20020ac84087000000b002b60be80b27sf14533634qtl.18
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 08:38:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639154286; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIOvZmBAqHhCphSEMaiYuSSnTJyY5eh8ByDCr0nVr0W1XdjUVvLAcgl6LKlSX0cZoF
         kN/D89QgkHC8K/A8p5cOR1dVKSb4m2Uxd3dU6Bobit39Fl2fqa6m3T7pGf4a0z1pKiIh
         64JftPtvgM6QJY6bm9HpRIVn07LhTGVOR1L3pzv81VXszQv3+E26L6GEjRDJ5IUhWVYL
         Plq+mzE3eDm+7ifM4avSij0hlEaUSQG7CWq9GSfmPeWj+MJLPLv9RjgxccGYf+JhJ/hg
         Ma0UNzzPshOZM4/EH1IltCQxoF5G/RBRb9iObEInYux4agbS5H1z8tpq12eXECMYns/t
         ayNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=9kdM+EhXp8Uxc/9LLBfFXJqHHhq/7eUUOvkvXVtOrOk=;
        b=tjGGdRLvlNtSXf7dPUvQL9Dv8r/uqwMko8i9lXXoFs5hOV4qQ0oE1+rlm9FWSr4AGM
         aq1dJRkRQVgy64m1ix4GHu6/LJLHrzLkUx8qrgw1m5RC7JGSLHBihKXaAYRZEBO0pli9
         i4WXO1nk8eESH865DhrB/+zQAhQQ/BjBKj+ODB+8hdgis6VihCTbEiHa1MyqNUk5/qa3
         sqbBkOqp4/HHwzHQmXwAN0TiiOdcnMX0ufolPfd70dAjKy/22ahbNBCM0kuvb77VxMVC
         ScTtOQRORP1XrAKRUIhEMu5WZC2vrlTEAoGROV2KuY1/Lcfpct0XWhp1ds52TO6tVdfW
         tieA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dZIXcowv;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9kdM+EhXp8Uxc/9LLBfFXJqHHhq/7eUUOvkvXVtOrOk=;
        b=F7BtWzZuGT9QgOz6Vct0fxjXhzhycCL24zHqDLY3ALXHVK8UkqROuaX4eRpGLAU2ER
         r3qTicNGTEKcBhkSYkfFg+fSnyfXQC/qffLr0fXLhhHqYlqv6CfPDtG1I1ajMsGyX1uL
         shwngm4+jvJBQLvcIfIha5ZqIYgB5anGNXihGG7nbfDjOur+8vbHrGxoZcco0mI6FoHy
         bVYOhJVtGSawi5y+FxVVndvzsXVlxFAZgD6yhpFd0NNTsww4mgmzPc4oxHeOugc7F6mh
         +KI3JTtAE3Ja5L3VjJwf8/cAQUF0A4DzgoMyOSZJZrRVIKm9ZosLZe1OMhyUVHp+4KX2
         9Ybw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9kdM+EhXp8Uxc/9LLBfFXJqHHhq/7eUUOvkvXVtOrOk=;
        b=Mtc7M5g1vxmXFSWdT88gdQx5NTVT11RHckZG09DsHiA99DI5pxrIEmulmz0XvLQUy0
         jexsiEpdikn5xzmlPyOBz6A6TotXKFKRQfE5fgCDcjkwll4MKMSYhSoZQctAHYHxzdHK
         UiSKAcVkzZjy8iQ/tTueVJpgkszpUUMOGKdS9z0Tde+hCjcf/kQaH+DiuVtuYTpoA+f+
         7+gDCZ6ntBm/ClR7SZQeYeTx2P/6tUbuWd6OEbD/G0ZniVhgFzdaIPKZvnGjrcEomQJK
         Q/lKBcIGebuFRUyCmYyrQt02kIWPq3kZ+DX3y47eZD0rjxXipX8aq5G7dcwNF6R4doh6
         U0xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9kdM+EhXp8Uxc/9LLBfFXJqHHhq/7eUUOvkvXVtOrOk=;
        b=cpdTHo7GWMs0ZObHX+SsAhe3jy6c9cWD/7EJVn6v9o4f8FvTs3yE4gf+FcWoXCjS9c
         CfL7mFHgK+IlKOO3GgcyTLyenUeMeKLcrypwRBbt/JY2vq88zthgguXX0hmU6do/UN4T
         hJnxMWW02Yah+D/6LkY35v4+Qd+qo8ugABQxtqRPcVVM+x1U+x7Rr7HHMXxXUQgaErV5
         Tu5PkDTYbEs9a8jpbrM3W2EGCAg/5IlkLBnBKBXcpx7uZ0LNJgpvbi976iG/yBTzJ64/
         BquuV6VH3mphbtCb0MKxGSeYOOf7NZRbd109tZIE8UiNGwISs18qLsugomF4BfZUS8yg
         pAlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y98lGv4+ZqJry+4qtUV9Q5vPk8TiijNBp38N+LumEkGpNFx9x
	kXDG1v+9JUxUYijvDx5v/J8=
X-Google-Smtp-Source: ABdhPJwUGdNhJpf4gW+g/upTKvwNlYDka/ZWMPEpUhHj6pMjByXpXeOGmRJY3UZwNI5h09D+5CNv0Q==
X-Received: by 2002:a05:622a:1450:: with SMTP id v16mr28059753qtx.367.1639154286130;
        Fri, 10 Dec 2021 08:38:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:40cc:: with SMTP id g12ls6265301qko.4.gmail; Fri,
 10 Dec 2021 08:38:05 -0800 (PST)
X-Received: by 2002:ae9:e88e:: with SMTP id a136mr20874647qkg.76.1639154285650;
        Fri, 10 Dec 2021 08:38:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639154285; cv=none;
        d=google.com; s=arc-20160816;
        b=vq8Vgc1PuSGXmtGsO/QNwUoMrPJM4WjSprNXHVJecv5vvrL1aVLthVr6NLC9LWyRmB
         Ds4qduNppPN1yG++n6UafTMwqHa7xeIPZvbZy+3Acj7eTjqYUTh2gk31dWrfaDXUktg5
         k0Ic2k/8mOFtgRpcoVfVYNVmQ+XET4Ssv91Wd4CWHE38oCMhQo1E1etInhUqzw6ScIvG
         RK/BZY9M13aDzosPcgcnBzzNpqP6xcyZbTl3qcxl2le97Q63L6OIR6E+0JJu7Z9+UruF
         iggpb7VHLbSbzTX4K3SMug0nX1AfUE/5xpeh8t1F8N08W8zb3Ds7JaSD8wSyqRvOdPi1
         wY5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FOdVuXmZVxHQka5/xLY4uUXT8XTZfcWZO4u7CsQGj5o=;
        b=FCbKo03Qw9V8RURpxzSqbdB2/Bbi8wccMge76Vv7wjVOVSZZuxacqJM2j1cOLiSN+/
         jrD5q3pQY75bNDbFfAYmJaHLtAOVqENUl/uD/E1rVRFRJ2iTZh3f4jnRQBHmTN7U+dj+
         6fJ7bKbzbu3zLtO6NANuC7jlfUX+jqYgheN3L6u2ExoAvdksekM1JyDirGzplUu5I22s
         wxyse6c+zs/SMd2n0e6Hy3qvhgIVaueF0cgHfWzMNBncfePF6xVvp/HBpGVN4ANUltly
         Dq58p0ADe+6j7BrRNNvG48tA/dHU5EjgIbHg290TIvhEiKxF/hyBhGehPEb5PkniPJFk
         xhsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dZIXcowv;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id u2si246454qkp.6.2021.12.10.08.38.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Dec 2021 08:38:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id o4so8882065pfp.13
        for <kasan-dev@googlegroups.com>; Fri, 10 Dec 2021 08:38:05 -0800 (PST)
X-Received: by 2002:a63:5c0a:: with SMTP id q10mr39625623pgb.213.1639154284892;
        Fri, 10 Dec 2021 08:38:04 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id f4sm3709333pfg.34.2021.12.10.08.38.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Dec 2021 08:38:04 -0800 (PST)
Date: Fri, 10 Dec 2021 16:37:57 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
Message-ID: <20211210163757.GA717823@odroid>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211201181510.18784-32-vbabka@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dZIXcowv;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Dec 01, 2021 at 07:15:08PM +0100, Vlastimil Babka wrote:
> With a struct slab definition separate from struct page, we can go further and
> define only fields that the chosen sl*b implementation uses. This means
> everything between __page_flags and __page_refcount placeholders now depends on
> the chosen CONFIG_SL*B.

When I read this patch series first, I thought struct slab is allocated
separately from struct page.

But after reading it again, It uses same allocated space of struct page.

So, the code should care about fields that page allocator cares when
freeing page. (->mapping, ->refcount, ->flags, ...)

And, we can change offset of fields between page->flags and page->refcount,
If we care about the value of page->mapping before freeing it.

Did I get it right?

> Some fields exist in all implementations (slab_list)
> but can be part of a union in some, so it's simpler to repeat them than
> complicate the definition with ifdefs even more.

Before this patch I always ran preprocessor in my brain.
now it's MUCH easier to understand than before!

> 
> The patch doesn't change physical offsets of the fields, although it could be
> done later - for example it's now clear that tighter packing in SLOB could be
> possible.
>

Is there a benefit if we pack SLOB's struct slab tighter?

...

>  #ifdef CONFIG_MEMCG
>  	unsigned long memcg_data;
> @@ -47,7 +69,9 @@ struct slab {
>  	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
>  SLAB_MATCH(flags, __page_flags);
>  SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
> +#ifndef CONFIG_SLOB
>  SLAB_MATCH(rcu_head, rcu_head);

Because SLUB and SLAB sets slab->slab_cache = NULL (to set page->mapping = NULL),
What about adding this?:

SLAB_MATCH(mapping, slab_cache);

there was SLAB_MATCH(slab_cache, slab_cache) but removed.

> +#endif
>  SLAB_MATCH(_refcount, __page_refcount);
>  #ifdef CONFIG_MEMCG
>  SLAB_MATCH(memcg_data, memcg_data);

I couldn't find any functional problem on this patch.
but it seems there's some style issues.

Below is what checkpatch.pl complains.
it's better to fix them!

WARNING: Possible unwrapped commit description (prefer a maximum 75 chars per line)
#7: 
With a struct slab definition separate from struct page, we can go further and

WARNING: Possible repeated word: 'and'
#19: 
implementation. Before this patch virt_to_cache() and and cache_from_obj() was

WARNING: space prohibited between function name and open parenthesis '('
#49: FILE: mm/kfence/core.c:432:
+#elif defined (CONFIG_SLAB)

ERROR: "foo * bar" should be "foo *bar"
#73: FILE: mm/slab.h:20:
+void * s_mem;/* first object */

ERROR: "foo * bar" should be "foo *bar"
#111: FILE: mm/slab.h:53:
+void * __unused_1;

ERROR: "foo * bar" should be "foo *bar"
#113: FILE: mm/slab.h:55:
+void * __unused_2;

---
Thanks,
Hyeonggon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211210163757.GA717823%40odroid.
