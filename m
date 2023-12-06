Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB7PUYCVQMGQEPT5LODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 64BD7806A60
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:10:23 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d04d286b5csf55075675ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:10:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701853821; cv=pass;
        d=google.com; s=arc-20160816;
        b=DoIV0pWkBIB79Hwwbvdtz6Eps0FvjGjybt8rXPvu+9VBQKiD8E2Y+iNnuYqZ9pwNSi
         0MvqcN1ui7sPG1ElT1kXo34QS373h0oHhyABQ/2CmsoJeAKdbTNKSIznBs1xKSZWmasH
         aEJQH2wwO8QyyLNb07VHKqV8W3nEDgHtjnxjgoLGks/CJeK2A+8GCQeQ5Me58Onez4zE
         R3/mCmG9OLvICM1bjAd8Lfv2GsWW0v7nFFhL/gthg7OAigXaY6BHt1KKFdvWdRz00A0I
         E1Rtm3z/aGwaelepr7miqWs+HHHJVl1FCqwkdRDxdp/RSn1BVW5wDjvN8YRYeGrh4lob
         tkSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Mhi3knxlrvexjliV/noARKqwmj85LPfuBe2GEb/LPsk=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=vxwIg7S1NhFRBBJwuCApB8wbGUDcYlbdoteiWoMhg+6gtmCCe65sZATCM939Tpksmq
         0gEF/NyWohrleKPfwaQtnTTQpbFzALx+oYFdbXCPa0qtHh8vuRmagSajB68KzQ2rlhRO
         whWSxYqtg6npgqJb9NvY04zVuFDJz/w8wIUSDema2h4PfBhFrBJ+/AvjwzXBv5uFZOSb
         /LxbgjIxZlX1eiAC4H4OTLg1cjnu25p3LEnhhnK9YuzjSgdyu5QiuUx/nG9EPe/HO5Nt
         Aj2wZASVLzCju5RtfTCa+2w45AhkpTgieswrstmg7kx/sVqat19t4GzOVGT4+SdFgF3x
         kf2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QiI86Rl2;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701853821; x=1702458621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Mhi3knxlrvexjliV/noARKqwmj85LPfuBe2GEb/LPsk=;
        b=wHlY8+bUvDIXuvCHM+7pmfKRM6Gzv86u+jKi0iaMJNuBNwTeDxnEJDhL5DHmgVIbwD
         e0ncmYO0V9uAxulzdIAZaLXtYNgM6B+pncCclmIQfKPgnU9EchMRFNJr2HIcT4VW8GjK
         4PcweEVlI57cvyJHVwDY/31GKL8b8Wi7HtlVJo8KBP+FqEYIfm/npZvTz58VierWqvy2
         TI74Li4kn39mYvh/Mn0UIgf4aBMgXIUZAlw5eAMGkPh8Y3zJ4AgLn5DLFJmYvNMyJBKS
         HHU33EcKpWQbq9nngIgSctfAX5hYbCgN7DzJC8cINwd28gg7OywBOiQeRW6tAUnAuoTG
         8sPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701853821; x=1702458621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Mhi3knxlrvexjliV/noARKqwmj85LPfuBe2GEb/LPsk=;
        b=POWNxX9xi03tkCSXOEx4f9V28V5shCh23aDIlg8zNz1UbPNUhBwRbpm6XjN5vGBiki
         AFiFZS3acWxocHv2EvbYhMz7bD1dvCoHpIKq3usyigSokLA8kfH4ku84WXK088KhBXTM
         HohN78gJl0Zs99hj4mmdr+wS4xc23GrTCgdqZvYXS64oGfLEqGcLz1ahu8PvXE91/071
         9PziBs+PVR1amqh8gvLvk5WurvuPBYY4+4lMxK8zbGTbFVZB0ibNwDzAL9xvv0LBzxJO
         fvO5kzEBhSEpHb/zXW0mqJIqt9/0CLZ7k/eNsA3K0GOa5eT8xxHq/3ToGkJ5dCLVO7Wn
         gfBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701853821; x=1702458621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Mhi3knxlrvexjliV/noARKqwmj85LPfuBe2GEb/LPsk=;
        b=eg6L0ujjWhBoeC4OxPEJyJlYnZJkB9X2JxE1JrBuGyM9XRSNuM1ytag1G14cIom+yd
         FNhYEA8RcBHijBsYk/rChbg/l62DkqaR0+JgQ7B00lUBGM6oWbeAPbs0SZB5yyOIPfB3
         6Uz0ZzG9oboU6HIYq+hrfh3NQemMUL6rRMVQKBNjBZQ9gs6UHuydueWfyu/1R2X1DEYm
         c5xui/cdu3LDrTJMw9BT0KqGwTDnUqtGfK66lTO198sh1w0UZytOoGNU+kNm5YMv91D1
         Fn1qV06gza4yFZsgpJWsKg6xt+VZ4PN/zsfL7hImEMckc2krTLG6VIxkIEFRKazjs/cE
         0e4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwD70Ukwod3YQLsr1qFfxkFkwicKBOPZXVJJBUmS3Rqzeti9ygW
	LupFb2JeXbWhokfxs9yoQk0=
X-Google-Smtp-Source: AGHT+IHbOHvwK9vZY1fLquGmjq6JLOHp/FhQCWUgiQu3vgHuwM12QPGRxZkKt1Zn1g+dr3/ojcSFhg==
X-Received: by 2002:a17:902:ea95:b0:1cc:5e1b:98b5 with SMTP id x21-20020a170902ea9500b001cc5e1b98b5mr560816plb.66.1701853821466;
        Wed, 06 Dec 2023 01:10:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2788:b0:1cf:c385:c460 with SMTP id
 jw8-20020a170903278800b001cfc385c460ls4159193plb.0.-pod-prod-03-us; Wed, 06
 Dec 2023 01:10:20 -0800 (PST)
X-Received: by 2002:a17:90a:72c1:b0:286:6cc0:cad2 with SMTP id l1-20020a17090a72c100b002866cc0cad2mr542430pjk.73.1701853820263;
        Wed, 06 Dec 2023 01:10:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701853820; cv=none;
        d=google.com; s=arc-20160816;
        b=xLqmajeiwHeJwPfZY7XeuZMqnxTOsGC5SQ1si1KlumlMw4HCuk3jWFZFAHhfjG9PNS
         n+f9K2pXGiqyNANDaN4KphI8Jf4EzXtsFZqHoXuS5FBqqcLjd6y6dyF4Lm/4t3P4TMLs
         bSzxZJwSt14nffyf246YIFGup9j3V8C9S2uXCWfuqaOnw2MeZmX213eop+tzZQzw1F2J
         Fw0M8sHQV5dBSu8MBo6jUirP12+C2EsAmAhuHbeQGSiWDNDh6vRRSGlRcioyGuA3Smie
         j7xn6SEbs1BFcnlps7986EchlQyndriOEfjxfeFYEMHx870aq1nMvdr1Owtta6PIhdyH
         cYxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=D8vZXQBRikGU6sWc2QsfIXjdmr6JSGCqbWWomJu158I=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=CAcv80W+1iFj3Q0WbPdgIusSXknfdV1N2+XYG6KRUnxZphk986h4e24HAnBFFZfhHe
         0gmNx1NPvWYl3SnjDyoXMihoW/qltKo6Y42jxaICmvojAigmvXzNEJGt2tAxR7GNrECy
         G2NFGvoao7VyP5xEi6aZ5oJx6iNfU6Pu3GDU7ISoknCHy+a5oXtEfcjXU5ReJCPPGREP
         fY0cnVBWN2m03BPd26FU6mW74gv5qFRqAPHrJvbbDCc3ObpkHAHOMS6mbT8J3T1hoo7d
         k4Ua2MimCD+pCRecQWyJXxx+edwP9+fPTZoP9WkqVHHfUTPbw8tdkD8mO/CaRjBvvaje
         cAyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QiI86Rl2;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id jg21-20020a17090326d500b001b816e24eabsi389600plb.4.2023.12.06.01.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 01:10:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-5c690c3d113so2493580a12.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 01:10:20 -0800 (PST)
X-Received: by 2002:a05:6a21:3102:b0:188:f3d:ea35 with SMTP id yz2-20020a056a21310200b001880f3dea35mr877394pzb.50.1701853819776;
        Wed, 06 Dec 2023 01:10:19 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id u6-20020a170903124600b001d01c970119sm11497348plh.275.2023.12.06.01.10.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:10:18 -0800 (PST)
Date: Wed, 6 Dec 2023 18:10:11 +0900
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
Subject: Re: [PATCH v2 08/21] mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB
 ifdefs
Message-ID: <ZXA6cwJbnayb6KA/@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-8-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-8-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QiI86Rl2;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534
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

On Mon, Nov 20, 2023 at 07:34:19PM +0100, Vlastimil Babka wrote:
> CONFIG_DEBUG_SLAB is going away with CONFIG_SLAB, so remove dead ifdefs
> in mempool and dmapool code.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/dmapool.c | 2 +-
>  mm/mempool.c | 6 +++---
>  2 files changed, 4 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/dmapool.c b/mm/dmapool.c
> index a151a21e571b..f0bfc6c490f4 100644
> --- a/mm/dmapool.c
> +++ b/mm/dmapool.c
> @@ -36,7 +36,7 @@
>  #include <linux/types.h>
>  #include <linux/wait.h>
>  
> -#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
> +#ifdef CONFIG_SLUB_DEBUG_ON
>  #define DMAPOOL_DEBUG 1
>  #endif
>  
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 734bcf5afbb7..4759be0ff9de 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -20,7 +20,7 @@
>  #include <linux/writeback.h>
>  #include "slab.h"
>  
> -#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
> +#ifdef CONFIG_SLUB_DEBUG_ON
>  static void poison_error(mempool_t *pool, void *element, size_t size,
>  			 size_t byte)
>  {
> @@ -95,14 +95,14 @@ static void poison_element(mempool_t *pool, void *element)
>  		kunmap_atomic(addr);
>  	}
>  }
> -#else /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
> +#else /* CONFIG_SLUB_DEBUG_ON */
>  static inline void check_element(mempool_t *pool, void *element)
>  {
>  }
>  static inline void poison_element(mempool_t *pool, void *element)
>  {
>  }
> -#endif /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
> +#endif /* CONFIG_SLUB_DEBUG_ON */

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

>  
>  static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  {
> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXA6cwJbnayb6KA/%40localhost.localdomain.
