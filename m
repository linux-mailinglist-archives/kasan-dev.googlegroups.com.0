Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZHH32GAMGQED64FHDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D5E35457099
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:25:40 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf4132350wmj.7
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:25:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637331940; cv=pass;
        d=google.com; s=arc-20160816;
        b=c42sXIIbTNH5kx/OIUbds6Ycy8n9aEOESPfhcvnqdD100dptAT+hPQ72VDMdCaBa2T
         nFFZcbg3Qaa1FPfluG4orXKaqqaOZe8DHU+4DnSRzqnLK24xM9aQMzG1O9JkZNrwLuqF
         D/0294dhkN2s7hUUdtwe1877tDwLHBUvApfOl2HebRxqu4VVFqIL6DDsKjiVBN7XsJfX
         ERvTPMUJRB+ylvOlRGg73/1gN+ihRIeLJRngx/tY11eYYnWqHX3ZMyPELX3Cfl/XQhO3
         h7YrmHrLEp8JkJ2HEhKvreXSi+a+Od33aTtRQeUWSlIqvvQVbQbiMg6dF4bKi7CzEKvw
         gJtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ov7CeM5x9ttj22/Qplz0CPTqXpLITlqZal8ByI2JQ44=;
        b=YEAhoXOHX4aT92AQglObkdeYuNVAfADxDoSYFUvnfpXUvB6b3fXhuWO0TMQjOV3SvF
         RXHtv4ZpaQjycTBe2XrNc+RK+VEunvTqCvwGRxwtD5kVufRNEW/FI3IOYaEACsDOdZoL
         tN1+AF1/wheo1/6CqxMXExEVgOLVueyVHofnzilCxRtUoeSaOmynHXM3jDvHkZ+ABvW/
         aEWih6mukOtOBURzfOql908I18uETIWpzdfOA0LHfpNoDc6kqlmDeuuUSgaCXcR/uveQ
         NzFZWbf+QTgWd75QGS6Nc9qtJ9M8jI/0MgvZdvU3hRUvSneQ5S2ZPaGGxnWXonZXdawZ
         iKIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jR4fBVfa;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ov7CeM5x9ttj22/Qplz0CPTqXpLITlqZal8ByI2JQ44=;
        b=Zx4xFT6+iUKkxzU1uG6r8Qx4ysjfNn4KcnTk2AoroG+Q3/vPvdXZE2I8I8/ao4P0yG
         PmJ1oGB1z2kIRDB7CQ9qLlw2FK2ngPQdxnGLngBv/V6fNPwba97mj4ysCuOTMjXwyHc/
         gESdMvKImao1rZCnMXPFsFEcDc1eaN+qGnTDbAU3mobxbn1hymSWYvxWdv1SUfzo6IDh
         sQId51LZuReg7AJ1CbipqCP2upYiaNCtJOEoiRryiu6TcZRnUCboA12HzH7t05DATU1g
         MvtH0cnRKWSQt7N4Yc1d3KHGX6t8uHlx9/uI8ziQdqXTSg+L6kep+Gz24vR5m0Fps0bh
         XtKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ov7CeM5x9ttj22/Qplz0CPTqXpLITlqZal8ByI2JQ44=;
        b=O3kwyLo1ipRYaJyu+pIZU0IcTEn0v+3T14nnmaniPT6GKBbijbM1Gtay6AOfDHAdEF
         ArgDGXNvbSlgpeWiwCc6HzjKWAHZjXG0JVEqN0Itz5uUm80GJ/rW6Cy/FgSGzBvX7568
         KK+2Y3lZcJoINF0MrRspyNtrf0z22yUSQKUNxA2LP/gX1SHvIS8oV+0dH4Hl4/lISVyx
         h2pF+cmTL12zKDakXht3MWfuaeuNrLL1xOY1vbEAGV6BUeC5QEaMfj7+H09p7HIWlsq2
         pkBF+WOFR1TG0RMG3q9YFcR+U+5y6/Zxq4+l4svYAX+YGNYsNXpNaJPFGoHGGoKehWO5
         jrqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532y4j5c8T3Btr6K0mKyHEH4ycMxHLhdbO9ZViJrXHxrmXvcXVFj
	ueVLc6zXdbGV59HS6xr3AjU=
X-Google-Smtp-Source: ABdhPJwcPs25xFe0L6+480HBfra0rZoC65t76JIna8MbdrSW2yfeCq1ovWgp7ofDlXsjtG8Ru+rOgQ==
X-Received: by 2002:a5d:6da9:: with SMTP id u9mr8224368wrs.237.1637331940593;
        Fri, 19 Nov 2021 06:25:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls3405343wro.2.gmail; Fri, 19 Nov
 2021 06:25:39 -0800 (PST)
X-Received: by 2002:a5d:6e8d:: with SMTP id k13mr8124668wrz.295.1637331939553;
        Fri, 19 Nov 2021 06:25:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637331939; cv=none;
        d=google.com; s=arc-20160816;
        b=FOudzHOJZKlKFVHvB/irh7UnkFEYE+VCnIdiRV8eKkD2o4fEq+zf5RHySdxiyYu7/n
         os/L/G5076jEatxWz7HqNDtdDoBR8sJCfj/lpm/Djqlp4dqOc0HIVpEY/fbaHVwJeQ7Y
         cOcrNCX5MrEe1gR6/mtvjrByk4pyFf1PBszzzD9psZTPOFBrO3i8ihv95bjQ6YwPxun9
         SgtUp7E+rSXLZuiimLvGZqPl2gUqN/gCJXtPbEvEo1SbDRpULBz2LxT7bSQTiwSguWMW
         /EalVoY/Bzqq6mzWCBfwGj0Gym1KjGS+/otCSFe6SjqERge6bar5NSpHM1MXK9c5cUcd
         c3YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=Wm4Uvhu20tXaQ171tTZLKuWEI2LRkW51/Udm0dRJZLw=;
        b=s5kIGvN647UEGql2qpmBuKBbaFzA8LqynFVNOQa5ewUHNoVGIZG0Pe9HZXecuRy3u7
         8/Xi11eFpl9swzJnmbLAyWqrod6GKH0VRzc8CJ+1WcK5cLWwgKjiQl1V+wueSyISJBc7
         /P5OlN191pfhQktUJzPbZnY36bCt+rz3idoqAtpBNNj7Enr1/mVZFvnxpCe2+B4d5Qpt
         LCJYina7VvPD2z4Fxwnaz0IRqKteoJURE3kVt9q7jy/GO1c3DQo+eFuFFLeARflW1G6B
         w0SJx/3jzHMwvH/I+s7y1vVxjJw1QNJgASXylfgmDXhscIfwlQZ6qGAolgNdazQTMqUT
         OdTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jR4fBVfa;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e18si279wra.2.2021.11.19.06.25.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Nov 2021 06:25:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 3469C1FD3C;
	Fri, 19 Nov 2021 14:25:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id F07F013B32;
	Fri, 19 Nov 2021 14:25:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id jOxIOeKzl2GuAQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 19 Nov 2021 14:25:38 +0000
Message-ID: <48c8a614-5338-4381-8b1b-5c0962bed8b0@suse.cz>
Date: Fri, 19 Nov 2021 15:25:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.1
Subject: Re: [PATCH 1/2] kasan: add ability to detect
 double-kmem_cache_destroy()
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
References: <20211119142219.1519617-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211119142219.1519617-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jR4fBVfa;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/19/21 15:22, Marco Elver wrote:
> Because mm/slab_common.c is not instrumented with software KASAN modes,
> it is not possible to detect use-after-free of the kmem_cache passed
> into kmem_cache_destroy(). In particular, because of the s->refcount--
> and subsequent early return if non-zero, KASAN would never be able to
> see the double-free via kmem_cache_free(kmem_cache, s). To be able to
> detect a double-kmem_cache_destroy(), check accessibility of the
> kmem_cache, and in case of failure return early.
> 
> While KASAN_HW_TAGS is able to detect such bugs, by checking
> accessibility and returning early we fail more gracefully and also
> avoid corrupting reused objects (where tags mismatch).
> 
> A recent case of a double-kmem_cache_destroy() was detected by KFENCE:
> https://lkml.kernel.org/r/0000000000003f654905c168b09d@google.com
> , which was not detectable by software KASAN modes.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slab_common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index e5d080a93009..4bef4b6a2c76 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -491,7 +491,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  {
>  	int err;
>  
> -	if (unlikely(!s))
> +	if (unlikely(!s || !kasan_check_byte(s)))
>  		return;
>  
>  	cpus_read_lock();
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48c8a614-5338-4381-8b1b-5c0962bed8b0%40suse.cz.
