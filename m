Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB2OUYCVQMGQEHS2US6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id CC83580690A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 09:01:46 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3b9ba7bff47sf3766796b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 00:01:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701849705; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y/rPhTuVjoj/vt8CDeNowD4EVQnpYLL4q9ZVi9w53lVSD+OSYvNBptwuMqTzHJ3IcQ
         EeOqBVVt+w4hdEbyG5FLYA61O9LkL7srnawyWc/1RMpWxvSwQLp94nduBu3DehxHIGO4
         MrQ+j6m7OYCEE1pF8dD57SepWDsiy3Rt7XsvBzRrDEHlb+9jxE9OyaBOBfb7yxZL5JRk
         QtNpNdLjys5Dsxsivkdyq1BfC4FcTpwkLUrzYEOU2JTct7cnjqW/H7Pgz5RbXvqVqoSE
         Y6ZPdrOvfKVQOqr18b1LktH4SUKJrqm/5wWRjB1Yi8euJAecnj3T0FmNrJKh6FZOmkQs
         7etg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Iw5/P1z5ffWtLwdpDxW3WUhrWaupzm0PCCgX5+PLmXw=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=Pvl0SltjxPQ6QuCxURgupq9xTRTDzAZAMxNJxNTEvegfibY84EsakpVFjWGFlCC6xw
         Pts2C9Fczuo0bGmp/1wFBDtBj20SfXPp8rgPQSZ5LaHKP2+bnCYmtBDGmX8PjlijWYJg
         nQtFDYhl1blNY7+EoyoC7Ueyg6mY39QKwHwfJo9p/dKyJ1+lwR2zt8QT+waugcqwCkmD
         YOQ+hz8H9fTsiDD0mlf4Re0xKySEB5OX1/bBiuVDEuHXyAMLb7RQJFxLcrPY/lDTXQHY
         2EcyIX8xH4QTzfJqz8qYN8yxMuxhaKPu5iU1Xh70lJQR23Iup/DLvWzRi5Pv0Xg4z5+C
         eGxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QEJ0aIom;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701849705; x=1702454505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iw5/P1z5ffWtLwdpDxW3WUhrWaupzm0PCCgX5+PLmXw=;
        b=ucmvv2iA6iBd+d4H7eEiBFZRe//A+RchBTILj/jzVAOVucAhUALKhtG76nKwMqyRQM
         5l0qsYWjIABRKLYGmKEUl345/R/QS13/LawwXsU853aZwP6Ml8UNznsiarhx2CZyQLXJ
         85sGisJu+9HbkmTTqGTkEMtyfFrK2zBebAEdsPrCrRl2K/TmzAUpOST7u4law1AavQFN
         N5utoNI3BTLF3ht5DEWNVWqORsiYhZUjmzTh7LsdSylr890tDpPMtNWxGLUtW2J1JAA4
         MWqPZ/neGXVCWvKoU058wOim/GZC1a29zfGkNZ3RKIXV7DjV3JhKwucg5gjTAbELc2DS
         Spvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701849705; x=1702454505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Iw5/P1z5ffWtLwdpDxW3WUhrWaupzm0PCCgX5+PLmXw=;
        b=ZzZLZ8bInQRGhJfhvlqVRA9i5tiTf5frBfHiIEPtPs9o4EWfnjt2Hssmw3SfujT2Wa
         j2DOkl06si7vfYDg4oyghMDXbnNtNVje4f++Zc1BwP8aD42PjK7Qyl0SmKZHPD0CueSW
         RueZKfyyJE0ipQMHbP09032aQKPIQf4k0hoUAgxHbYob6psV4lqsYa/x2bsqU8Lj16KU
         GC3IhmtqfoJrN/A2E0ZfznISldeK2AYS52rE2vouQ+fzRsgTMcUqAAsWN06vd+0CyAyV
         53MbDCukydQBJFkGG36cSuSjJYL2RWLoauGETvgTX8tyhu9HRLhmzbhw9KWpxSzmEsqK
         NaJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701849705; x=1702454505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iw5/P1z5ffWtLwdpDxW3WUhrWaupzm0PCCgX5+PLmXw=;
        b=ghlfr7atNgjAH1kFeKxUxMsFGseP2WV5K9LJiNtCHM+6aPXB6xJUKNgKJKpd7qSMh8
         pNioU0Axy8d85DCgROOvOO1TcGpKGU/Wx8sie8/BwGxuI4j7jOnnRj7myM0Bh2azOkpe
         EE/6rifQT6bzKwwUkcBoiXUyj+59BrcA7C1csYbPp1sooPGVLzNXyg6Qz6uYxnUSZHET
         lOgS78ftSs5th0OL6mEQuuHaktQOyWjrnMRhpH8IIRFL8IakjUMTOiYVjR0GblI858JD
         SjnHBctDX2v9Gx029TED6t+HML31IaE6MNQGGUKVabZ/Y+qm8CkgxdUCu9uEU+QDW3Rv
         E8rQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxwNoWD/2uC/1RNWF83GsMxzUF4JdM0H+YTaF5mfistN24APFkY
	ii6q7CjGKysPGo3eH+KL8CM=
X-Google-Smtp-Source: AGHT+IEK5ZvQQB9cv+3AoLjCQ0po2/YWe4TdHzk/uAUnnFHJGwHgksKNbln8LfM/M0gNPGKwzt8L3w==
X-Received: by 2002:a05:6808:e88:b0:3b8:b063:6bb3 with SMTP id k8-20020a0568080e8800b003b8b0636bb3mr590911oil.98.1701849705227;
        Wed, 06 Dec 2023 00:01:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8a0e:0:b0:6ce:710b:857e with SMTP id m14-20020aa78a0e000000b006ce710b857els258723pfa.0.-pod-prod-04-us;
 Wed, 06 Dec 2023 00:01:43 -0800 (PST)
X-Received: by 2002:a05:6a00:4c0c:b0:6ce:7b6d:b33c with SMTP id ea12-20020a056a004c0c00b006ce7b6db33cmr328778pfb.29.1701849703295;
        Wed, 06 Dec 2023 00:01:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701849703; cv=none;
        d=google.com; s=arc-20160816;
        b=Q2FK2ZaYG6mFM2UFkbw7mZZ/HFHvK8VVuWdBLvvyu5iQrqdqFZSPvFag8dR7wzeYE/
         sJ9sp9o8Np173NbDTSKcDqg3x4Tkkwe1CjgDgcHlS/ZG55wzgmxvoldhyNYgZasljCXc
         DdWgItm+ouGR0ly/4d2MeLXCuJLLcf7JOergBp1f/CmgRTw4WI1s+l0LOYh5Tkj0Vj4w
         c2lMhIJLxU0nBIh66KpQcWgZcBmNJszqJSXnhDjO3K0jer+Ix4OjKXnnGWB1DmekIjE3
         c1tdKrMwbCviLwoZBFfanFtjZ1SaxKRUKN240ceSow63R2HiF23yFWJJxt5BIQDycW2Q
         1NcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NsJi+rAf1/pjE2JHoHBlEmIyNC7axeV0xxI+MHCEAm4=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=z2qsZu0vXAoYSxA6AD/7hMDI4C24rGYQsvz20CKVg19HAKYzf3gHE6BQZwXVumkGM/
         Wjn51SreKc1cy85Dd6hC0ccH/GvxmmCwve3gRWPD5vHgKLfiQ4V16Y7sOiHehPw5Jusx
         5o42leC9HkMQETmTgbWXVBg0kiiPR7g1uMcUyuOEoFyszdZ70bCch8ejyTh0aJLGK2dq
         1+Wr87nrHxQH8MX5HlMYQcCsanK1H4zAdIPZZKZI+LYWv9g0PoGBt1lLmfG3huuzHG9G
         eq1kCf6PYjQyg5cbRar+AS7MJjZm/jiomQ8GZ0/nwaEhdUmllec/72PVzrltxIoqogZ/
         zqDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QEJ0aIom;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id x37-20020a634a25000000b005b7e6ff6c09si922960pga.3.2023.12.06.00.01.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 00:01:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1d0897e99e0so22717425ad.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 00:01:43 -0800 (PST)
X-Received: by 2002:a17:903:1208:b0:1d0:6ffd:ae04 with SMTP id l8-20020a170903120800b001d06ffdae04mr321640plh.107.1701849702755;
        Wed, 06 Dec 2023 00:01:42 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id x4-20020a170902ec8400b001d08bbcf78bsm5976368plg.74.2023.12.06.00.01.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 00:01:41 -0800 (PST)
Date: Wed, 6 Dec 2023 17:01:27 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 04/21] KFENCE: cleanup kfence_guarded_alloc() after
 CONFIG_SLAB removal
Message-ID: <ZXAqV8wCjw/KAiRp@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-4-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-4-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QEJ0aIom;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62d
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

On Mon, Nov 20, 2023 at 07:34:15PM +0100, Vlastimil Babka wrote:
> Some struct slab fields are initialized differently for SLAB and SLUB so
> we can simplify with SLUB being the only remaining allocator.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/kfence/core.c | 4 ----
>  1 file changed, 4 deletions(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 3872528d0963..8350f5c06f2e 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -463,11 +463,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  	/* Set required slab fields. */
>  	slab = virt_to_slab((void *)meta->addr);
>  	slab->slab_cache = cache;
> -#if defined(CONFIG_SLUB)
>  	slab->objects = 1;
> -#elif defined(CONFIG_SLAB)
> -	slab->s_mem = addr;
> -#endif
>  
>  	/* Memory initialization. */
>  	set_canary(meta);

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXAqV8wCjw/KAiRp%40localhost.localdomain.
