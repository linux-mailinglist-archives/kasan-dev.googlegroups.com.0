Return-Path: <kasan-dev+bncBAABBLWDXOVQMGQEMZEYHZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C3BA7804CB5
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 09:39:11 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6d811dc2a60sf5537697a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 00:39:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701765550; cv=pass;
        d=google.com; s=arc-20160816;
        b=o4Ox3mJb0DRQYxVt7QUBYSnMjgQ7Peq5Mra7n1oVNBnUOPJ0XIkX+jcRNhvQTVpOxA
         k8jVeKa9exglQU+4z6hyF9dnC0Vcva1uMPTHaBqoiXngMtIkJTH6HQTZjbtwCiICOTmM
         ZrVP9oeYYbgnqumd2X5cCWR8IlicFDfaelnNJBwaUcbxxQVmonmUogshtZ7Sz5TG0F8T
         c25ABnFJunl1AaVSDkFPe+q7JWc29eUD4ydzH4jNe/GaZ0OKBTxEqNt1AiJsQHkkLsu+
         wNjlYaeAyuIEH+G2eXDV86c0kS1uGjmqRw83KgXvTK7E1pp+TJsHVOXlgkyMm2wVuWjV
         t2+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=Atu1mgbTNDwNUBSPkpMGwrn1k+6pMKs0qIv+6r+HuV4=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=Dcakhdb1BW1grVDTZIyWlLo1+NeX8wOH2HAOFABYGPxgNrSpNw3sKzX7O1SDyJcaR1
         rQ65xYhzkrNCvK7Ws5ZMJGAyR7CMI0G1CIuMKmF96YAb7S8S6jPYhoCyME28IDW24WAm
         H6S56mkKcd/CoN0OLTjMxKBOmre0hPq8zKpNeo2dS2MaMOlVIiU6v/Z8YqIAGb/DiiIO
         wOQ3OtcKxHSsHp8bzd+6Svy19b67UU1q0XfkvD17YhA6uFhKOFwtzOn+oX3w0FPkEOtK
         S40XOxNUaT8eAwnB7sxoXt/6ORYnerQidG5cyN8bnqGRdElDgQZktJm9hp3vQEXv8me+
         mWwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JtHkQHye;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701765550; x=1702370350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Atu1mgbTNDwNUBSPkpMGwrn1k+6pMKs0qIv+6r+HuV4=;
        b=bzvA7yD6Od659JO4U05K6ZjfKaWovoyfUKYxlXWPl/2rPdPacpQLftoMuhqXg00Gu3
         zmMr0TFvruySIbs7JmLHv5wZNYkbaWCk7S6GRhL+6JsDuWK+HEJ2Gf0OxPDHb6b1gWBc
         AhgTxqI9lCz8Isapm+B9Qup/11MF/phm1T0jNjU4rK7lOECWN2RfwDBWs7WvgbTqZOxU
         slvfenDKQkPKsS8EobwWeCSsJEJGX0xil4rDqSJfBn+zTeCjL4RjV6HIriV6T5COCXgs
         WrbPU0eq+/Ah/Ot3UWzRYwKUCR7/NJiHGJRIs8h+9z7ciQTQ7IlmkxCKgDnh9l0FtDet
         FB1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701765550; x=1702370350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Atu1mgbTNDwNUBSPkpMGwrn1k+6pMKs0qIv+6r+HuV4=;
        b=ZRJJcubWV8vemB0de9B6YlzM16rSWz0IoanvJO/iPBeN/qQ5/NVUEdVOmvtw4deEcK
         kqJKAfJ6iKvMbo91c/89A3XF7gpdmFrz+HoNaR1X6tr5Jj/lbRICQ4fPe4n1kT9mIHxc
         OYGnck4ohhjrHrPJHF3Ka1xhoW2v/7LidudDGoreOrUXX+RsJ++W0AmJDdekrR60ffVP
         zEzrF03jZ2DQicCJthVH3rgbcboWTeIBZ+TnXbbH5STseRLCFOuwzFMhec+Tw4tnYMbk
         g7eDVNPj+ZJqkoONKLBORT13rumA5RxOV6XmZyfCDED2VHwC2Ujqa/F5u5KY3Zs/+LcB
         +I+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwqEyPcRbQV8v6yz6r3xAc6aiNNlykUh20ltnTx0x5LP4HkNzVH
	AD70tJ50HCpnIFR/8ZkS7fo=
X-Google-Smtp-Source: AGHT+IF3rEyVo6Zxwmvgb/T8WJIU81w/LsNtcpe9k0bUx4U5AJy1z9ptfrBh78MaPDmI6VsZDgiXSQ==
X-Received: by 2002:a05:6870:d1ca:b0:1fa:f19c:6803 with SMTP id b10-20020a056870d1ca00b001faf19c6803mr5510500oac.16.1701765550211;
        Tue, 05 Dec 2023 00:39:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5687:b0:1fb:4d90:ab90 with SMTP id
 p7-20020a056870568700b001fb4d90ab90ls470655oao.2.-pod-prod-00-us; Tue, 05 Dec
 2023 00:39:10 -0800 (PST)
X-Received: by 2002:a05:6871:7990:b0:1fa:edd5:cb79 with SMTP id pb16-20020a056871799000b001faedd5cb79mr1134169oac.4.1701765549920;
        Tue, 05 Dec 2023 00:39:09 -0800 (PST)
Received: by 2002:a05:620a:1789:b0:778:a9dc:3cb2 with SMTP id af79cd13be357-77f1b08c380ms85a;
        Tue, 5 Dec 2023 00:11:13 -0800 (PST)
X-Received: by 2002:a2e:9584:0:b0:2ca:db6:a13 with SMTP id w4-20020a2e9584000000b002ca0db60a13mr967468ljh.58.1701763871090;
        Tue, 05 Dec 2023 00:11:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701763871; cv=none;
        d=google.com; s=arc-20160816;
        b=FRH8CKtsal97OtUWFOxceDkHtYcNw/H3kJy8t3TX7UAx+BhHLOSLTyPvSRKkIaftSR
         Ke4uR/qZUZD3C/pmkkY9qjiECjejGrx7pKCLLpkVRUtAlh5DbMChwMUZovfmw+I/+eYf
         5hNUvSknp01mJxaD1PV8S/STY27epxGVVYRvPoIOO8dwfeiV3RsMOBqDZtd9kVbYjUor
         bne063CnN8pvNC2dhR62YjF+IYBSWBckke04W12yVBSpL321trmB7ffDnXhBu7JKDhjL
         MuOh5tyvxyLfkV4cIBNMgnnzb8cY2DabRQgn0pRDX4lO+0VoJ5OQQMLmveWPcHPff1nx
         cHfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=c7tcXxVB37+e74YIJ/SoIf8Zq3/8qsP6opp7sTACB/E=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=Rfa+zyoa9rk6AWjjkCXeFRZtwz0zddNYGyYSlzt/axT3sthOd+Il4xUxk0Rsm++F0S
         mCQvdinBE3RVnE1KmsNhn0+mhZR/heU2W/Fg08bX2D9vOq6YmDlZ1YToVQ2KDnOT4g34
         X1dZDvpg2FaVa33cWXOGPCaQ1eePJGvBAm347v42/xm6eBeXoL8Mh665sx+/NTlQb8kj
         Vzp2m9qUCHyXrO554OUiLyIQEI3/PQDe/WxDqNNOjOgNXoiD8fYSAjrCi8j619IDbXMt
         hdvRWRocWDCb9uNYc0YweTQVSZq13EJjOvtGb8uEfixtxhUBQ23GUESn60N8PWhaxHzY
         3LZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JtHkQHye;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [95.215.58.173])
        by gmr-mx.google.com with ESMTPS id h20-20020a05651c159400b002ca098f24basi197517ljq.2.2023.12.05.00.11.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 00:11:11 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.173 as permitted sender) client-ip=95.215.58.173;
Message-ID: <c9867365-3a44-4699-a2d3-717bae0d4853@linux.dev>
Date: Tue, 5 Dec 2023 16:11:03 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 1/4] mm/slub: fix bulk alloc and free stats
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-1-88b65f7cd9d5@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-1-88b65f7cd9d5@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JtHkQHye;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.173 as
 permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On 2023/12/5 03:34, Vlastimil Babka wrote:
> The SLUB sysfs stats enabled CONFIG_SLUB_STATS have two deficiencies
> identified wrt bulk alloc/free operations:
> 
> - Bulk allocations from cpu freelist are not counted. Add the
>   ALLOC_FASTPATH counter there.
> 
> - Bulk fastpath freeing will count a list of multiple objects with a
>   single FREE_FASTPATH inc. Add a stat_add() variant to count them all.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Looks good to me!

Reviewed-by: Chengming Zhou <zhouchengming@bytedance.com>

> ---
>  mm/slub.c | 11 ++++++++++-
>  1 file changed, 10 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 3f8b95757106..d7b0ca6012e0 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -396,6 +396,14 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
>  #endif
>  }
>  
> +static inline
> +void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
> +{
> +#ifdef CONFIG_SLUB_STATS
> +	raw_cpu_add(s->cpu_slab->stat[si], v);
> +#endif
> +}
> +
>  /*
>   * The slab lists for all objects.
>   */
> @@ -4268,7 +4276,7 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
>  
>  		local_unlock(&s->cpu_slab->lock);
>  	}
> -	stat(s, FREE_FASTPATH);
> +	stat_add(s, FREE_FASTPATH, cnt);
>  }
>  #else /* CONFIG_SLUB_TINY */
>  static void do_slab_free(struct kmem_cache *s,
> @@ -4545,6 +4553,7 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
>  		c->freelist = get_freepointer(s, object);
>  		p[i] = object;
>  		maybe_wipe_obj_freeptr(s, p[i]);
> +		stat(s, ALLOC_FASTPATH);
>  	}
>  	c->tid = next_tid(c->tid);
>  	local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c9867365-3a44-4699-a2d3-717bae0d4853%40linux.dev.
