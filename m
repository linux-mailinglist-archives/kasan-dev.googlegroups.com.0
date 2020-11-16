Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5KZL6QKGQE2R6ES7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3581D2B4785
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:06:16 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id h29sf11124194wrb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:06:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605539176; cv=pass;
        d=google.com; s=arc-20160816;
        b=WMQdB0Mp4m2TXKWeywFLez/6/z6tkPK7DfXKT0QFdV7rOfyW3tV5vKbSSVoe3IG2+G
         QF5uZE8JVlhaePNhW7k2QJKOYN2HUuRqRb1mrfOXJTQOq/PF8aoaRtJe3N1M65BrivBa
         itONeDBOpkouLsHy+/Y4WogvULl+0jHo/Zi2rNAfNFYdBGp6bL8EeA6SpaSya/2NFpC4
         cbTT1r/wNjnSPMbxyMw/1ZJSLKcvWAcPPd4vep+xzlQfvsUO3eEfGsGEBZ3xMBWZvfMx
         V3+V6N83UwnVuheVP9vcb/MtBLOhv3GAJkNrDgyBICqhg4z8nDCr8IQwcH1OJDaPTenY
         FAIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4xNPxorVtbIY+JYrRR0gBDLT1Rdp8Rc33Y1mgsCObpM=;
        b=OafObjYztME8cH7YxpdGbkq+/t/BoVNIpPqcT7i2D/Je2agGa0asqIabxzedkV6EKv
         1RKWIHdqdgsRQtwg9DJ2B+dVuMUSjELca6CPOJ0SOxWy1p8CcFMyzCPxo2xV+l39LZtD
         ix9ZSpTswM83Bz/AbA1fCyl+BeHEFPYUFpLg2gOEnxeSSs0CJjESU5Xm+z8e8WMF9scx
         SM7fHhWUk8vO9KJDqEpGHPSih+I18zPFzLgvlx6zPD3dYaAXT42OHJv0qpCqlDiM8flo
         Oh0sqw6JJF5zw/Ol28GiUPgpTAHxbycRYZEVmXJQ+0kVdETDiAoV/7Q+Zsv1rGGrILlL
         1VLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="u/ixGDcp";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=4xNPxorVtbIY+JYrRR0gBDLT1Rdp8Rc33Y1mgsCObpM=;
        b=Ufa5HVUJuSRmGmt/NnzfNUDW8UEMBsnX0vsRJ5HYuwqXJA0LQAMYNriPEwEBUiHC1u
         PBXk/2UvbnVux2TB05cI6iqePZ1MHwsrjV77Nah+LXZ3MIIHs+ycEWw0rMGxHGMxnkx7
         +qC4TYvzdP6ZLwucWYBdJAjGyDdpBAyMPUN+QfJlq0mrzilbz+RizTDg99zxlPEMWU5K
         qMOwVaq0MfBQnUdkOkRr9/bJd56eR+ZmHgEhYUbkt37dslZKMy260VueaDf4v48AoPGc
         OpRXaWD+gq8UyPo+9s1h215uW5Kn/caG3RFwtSTfm7hAjnYb/ZF7JCScAsVIDRXFUWMT
         j5Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4xNPxorVtbIY+JYrRR0gBDLT1Rdp8Rc33Y1mgsCObpM=;
        b=qCGV6zxCnaBR6l0R/rNWe5Xb/0KM/yHaQMdetmrAqmKVXnPxNNSo+UG68Ys15gK+Is
         IgHpRqB3zRIK3tJwgCbIUVLPu8wLcTPw347OJ5IZrtvV2ABbawWGbVgllk6UsCg5cgyM
         gYdN0aWHQujAGA7FfOwrYbQ1KXf9xNvAkdWddlXcDSpFQaqiApeYTTdWMjDTvT+6xI/Z
         N/hsMWiRbiCJhRNxUqUjxot/cUe46oZhmw3Y2HEeiIpueVuM9kwPRFlhqtYK8zdSUVYm
         lmREe/KTXqbBEesPK/5OkbJglldd7l3323/1pv+5gNXlaCAFO9s8EsjJc/vaVxIk8NX8
         kOyw==
X-Gm-Message-State: AOAM5309c2jdAfFlil8SqwzBGOeVfdV3IJvKbkw/tL8gRMk1PnziRtil
	FGR+fq5/agd4Kurnoe50CX8=
X-Google-Smtp-Source: ABdhPJzT7CcPEoT/LzT27DmXsIngwsgnbssXFAPfRykIDM7Av+X7tlGzusmB34Hp94h/SZz9WDyT6g==
X-Received: by 2002:a7b:c3d2:: with SMTP id t18mr16487665wmj.112.1605539175943;
        Mon, 16 Nov 2020 07:06:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls15795776wrp.1.gmail; Mon, 16
 Nov 2020 07:06:14 -0800 (PST)
X-Received: by 2002:adf:c443:: with SMTP id a3mr21103165wrg.249.1605539174943;
        Mon, 16 Nov 2020 07:06:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605539174; cv=none;
        d=google.com; s=arc-20160816;
        b=VvyDP3nBhJAJ5GizDBNLHaDxRbZDTaozQRmz0wijN/RfrZ2KyD6HRUyplzNsg0vyjX
         U+qTHSq5FCity2aljqvncmZneO1nmVtqBfXuxTTgZZQq+tqp+Uax/Q9a3nQiJN9wmm0i
         uFkQdQg2sFMiGtX6UG//X9FgH7snjYcTB++SYh27FmJWPY9rSfcJJbLpvleSly01Gjlx
         XT5Gcl5+XXMWHS92SD1MEZ5khtUSHoSBeAVyLCS4z4tjDU4t/UVa8z1a0wmVjnDv1TOf
         /Q3EK0VeTPfmKpw16mPGGksWpNkYDXArsjEL21/SWXH86GNHr9iqE5Uvv5Kbyz1vuJo7
         qwlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=s4udoHyh9j5IqUv+HxIL+80tVyb07J8vLMt6/kF0Ir4=;
        b=1KOLYzGIovKLd7i8/M2btzcACPjhPQDLLChpfEVcU/PAPy/86UyE7R0wEGFc0WaWHY
         qSiAnRgIbN7w4L1v9/Xh57EwpOP43qvNJoq2Pl2vbtS/OC78ak67FlIXp4Njj5/+O2b8
         J0xLhtrL5ep97lUaTDO8kAZ998wUeuZ6OJvW6u66TMJX1unxKppl87pfYWsS4nzYQt29
         Olj8//mcCGIriS3FsJZAndUyvARr3OvkghK5+lK3pAD7DC7WWPPAgrK9cqYwFw9QYltS
         QsnoE4LhPOddiAMdl3RUFuZWmXFDDeFlhP7kOxJFGLK/ccbCaLKVY6DC2v9RkBcqHCHJ
         F8aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="u/ixGDcp";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id i3si530913wra.1.2020.11.16.07.06.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:06:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id 10so24024851wml.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:06:14 -0800 (PST)
X-Received: by 2002:a1c:9c53:: with SMTP id f80mr15486878wme.19.1605539174436;
        Mon, 16 Nov 2020 07:06:14 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id d128sm4597301wmc.7.2020.11.16.07.06.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:06:13 -0800 (PST)
Date: Mon, 16 Nov 2020 16:06:07 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v3 09/19] kasan: open-code kasan_unpoison_slab
Message-ID: <20201116150607.GA1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <4d64025c647190a8b7101d0b1da3deb922535a0d.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4d64025c647190a8b7101d0b1da3deb922535a0d.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="u/ixGDcp";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Fri, Nov 13, 2020 at 11:19PM +0100, Andrey Konovalov wrote:
> There's the external annotation kasan_unpoison_slab() that is currently
> defined as static inline and uses kasan_unpoison_range(). Open-code this
> function in mempool.c. Otherwise with an upcoming change this function
> will result in an unnecessary function call.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

I also think this change made the code more readable, as
kasan_unpoison_slab() made me think it's unpoisoning the *whole* slab,
which is clearly not the case.

> ---
>  include/linux/kasan.h | 6 ------
>  mm/mempool.c          | 2 +-
>  2 files changed, 1 insertion(+), 7 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 1594177f86bb..872bf145ddde 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -106,11 +106,6 @@ struct kasan_cache {
>  	int free_meta_offset;
>  };
>  
> -size_t __ksize(const void *);
> -static inline void kasan_unpoison_slab(const void *ptr)
> -{
> -	kasan_unpoison_range(ptr, __ksize(ptr));
> -}
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>  
>  bool kasan_save_enable_multi_shot(void);
> @@ -166,7 +161,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  	return false;
>  }
>  
> -static inline void kasan_unpoison_slab(const void *ptr) { }
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  
>  #endif /* CONFIG_KASAN */
> diff --git a/mm/mempool.c b/mm/mempool.c
> index f473cdddaff0..583a9865b181 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -112,7 +112,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  static void kasan_unpoison_element(mempool_t *pool, void *element)
>  {
>  	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
> -		kasan_unpoison_slab(element);
> +		kasan_unpoison_range(element, __ksize(element));
>  	else if (pool->alloc == mempool_alloc_pages)
>  		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
>  }
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116150607.GA1357314%40elver.google.com.
