Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBYVE7GNQMGQERFCZR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E932D636675
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 18:03:31 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id z9-20020a2ebe09000000b002796f022c63sf1635694ljq.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 09:03:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669223011; cv=pass;
        d=google.com; s=arc-20160816;
        b=Slz2AEIx2nKB9RwkNo51HO0g7nDuA+vkv6kJsFMgL/o4fgqP0NukuVgLiUCor4XbeB
         4LwKykNF0WEPfKKBdXJS2Yq3aCLdtQ/Q8jvqBYTbmeqVyejyrCd7M8R6MtQiG+/cE/fR
         +4/wCg7sm41DD4d5r24oMYi1WSLpVm5t4zrU74GhrdkfQUDybVa2V33/W7j/wLpjTvxb
         wg8csBkRFs/qt0O2uKb3eMx5l7IAPbOmCH7To06kf3SVrF4n/XwgV6w9BRHu7tXVQZ31
         U4jyc3lF0w9EktONH+tsQjPZihMPifafuFQrF5RyhV7F9WoPEKE2k4//O4wzqy1q7lgd
         yEzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9ctNQm+xXbnMUTPnUPVeYIySZmFoAx33RmcK7Mcd8oE=;
        b=HeUi6r484P86TURXUwpGfh3wU9St+EdnyMZUoV76G/UcrR9t/cg7XzYjm2YUTrr3FA
         xqfYPxpB1o0CpSDXy5xOdp0dGWeTc00DPTADiAuLp71ncM/pKXMhjWBmhv00gqDZlFU3
         oKAjaxFGlqFkgZzcnDXwptZy2H0PAYX4zQHj39qA5kOiHCBJc4KOTje2iDtrZJDb6ie4
         DuNDSuJRqiQ+Qevgd+981sILA9dLpx4lhtAD72/1eCqsJgrE6SpagUUdFO+o3tCoP7rO
         ilCBZqUn8EMAOtyetNffFRw6wuoBk11IO4uO/w/aebqlo9WHAvzE+EHUwegdSXhthhS2
         qVmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P7YAkbJd;
       dkim=neutral (no key) header.i=@suse.cz header.b=ct7u2HKk;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9ctNQm+xXbnMUTPnUPVeYIySZmFoAx33RmcK7Mcd8oE=;
        b=inQvk04wlk+w8KJLKBCkSsXpU15Z7irAbrx5l5fgqAUqvVrIh7Ovujv6jc2D7ukiVE
         nZMFUiPL4qIqX5BJNop6anST6I8VeO84vn8WXjTNuy1rMP43V0oirZeBcMaHrGVwwR8C
         oLUJsQuU/ZiKp+mlO2VmyNks9DpgbLH5c8LoOxmUMrOPX9/K3W5LMFif+0gAZ7UIbI0n
         Il6bioSX7gz/A70W7ASRWr+lF1MeBoLSMTRGuY3rM02JfAV8sTmP7OS9My65XpKixuKZ
         FL6pV3tsWOaIwr/e5SppWAjw8XIt6f2/fjrCZSf1g5spH+4koflgZvIeirNH0+LgHBit
         T2Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9ctNQm+xXbnMUTPnUPVeYIySZmFoAx33RmcK7Mcd8oE=;
        b=hMlhoQcPv21SATqKyAJT10AkJtzRe8T545vtMuGe1OIq1xWAMn5LFTlHKMdOBb7bRn
         l2Uqz99vABca48HL7DwUjVbqPFPtzardwhIQwDb4wq6/gpyGmvyoo6JVReU1zKW1cWQl
         R5BIUyWgvlx+fmjhGk3vSWYYSbCrfXenWFc+nNhgPvMOdjdEwDG/EYzVAKktPJhoLEjz
         NXkpXRS8vfDk33MZHj+xnLv3wcwN8CY+bhElbEMEDrRw3PVuFg7KJ5MHhQyg+gsKsV+3
         pBGzREMZ3G1SoWiGgDIEgK0WZtMjNoqX7MubECuwPAwP3PYgP8azBYMgJEVGi4yblAGB
         cLCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plcRR+XERCBsZUoMxK59d03xf6cutJKDRI65easzcP16mh4L0JB
	2yaFLgTPrij/L6NXikKQBRc=
X-Google-Smtp-Source: AA0mqf6NKCYAWCpXTR33QFxqsVxW9C0x7kc2WwHBgZF7eYG7/j4E4Jb8uSb7F+LqUiWZNq/YCk8DLQ==
X-Received: by 2002:a2e:bd05:0:b0:277:6ad:b2fa with SMTP id n5-20020a2ebd05000000b0027706adb2famr4793320ljq.24.1669223010305;
        Wed, 23 Nov 2022 09:03:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3147:b0:48b:2227:7787 with SMTP id
 s7-20020a056512314700b0048b22277787ls1525609lfi.3.-pod-prod-gmail; Wed, 23
 Nov 2022 09:03:28 -0800 (PST)
X-Received: by 2002:a05:6512:3b06:b0:4aa:8cd:5495 with SMTP id f6-20020a0565123b0600b004aa08cd5495mr4193357lfv.254.1669223008407;
        Wed, 23 Nov 2022 09:03:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669223008; cv=none;
        d=google.com; s=arc-20160816;
        b=pPVZqEtKLNY1MlC7tymIo4ayvQ1P7cn+1ac7VSk4H6hAVXB2K4PBVRJjl9LFcGomL5
         OuEgl3UDSOX7OXJZHK4AFMcRJM+4OlQiHHPVTeOuJckKt7dNgryGoy+qUdkz7VTBD8fO
         55tt/nfd1F086mst1S0n9UbdW4/Z8pt5ar7cvda4ohuB1bfwApQinxe5ycHL0g8UAK+s
         /GuwX2nkSDDAAvT863HPolQu5iuJoyE8E6VQiEQshO+0lGHz+p2bz+xREqB+r2y6xQFU
         cDfLQv3MlKbVyUhbPsc8xgFTzO6a2lDKSyS2cys0BzZgtO9pB6mtbl1kI62Q7xi9BPON
         WMtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=QOTqESa3U7W1bqo4V15GNCzXDu459rGsEt2ugIrp2oo=;
        b=RXNdYh1YlNT5OZrPezkx2pt78eWAX2vNIithS4SAq7ymO53+si74ZALEUoaM3izQIx
         zEXNW2U9ebuHuOZlvALUo8sREGPGoRNJEP/f6mUqBpcR3yTfgk/kPtqovLFfIQ+OH9gN
         dCUdFn+2QTLv2vJGeQaXqcVUeH6LelvanoI5oKOc4DbGa22L/qYhALmGJCmueaHAWkl4
         jOVLoxU5VPg8Ripctqu0sAGoxmhVzDs042FXE8ZM/7C4HhmiQQ7a1+e95M6LlzO5KVKT
         VvfdSjZrok5qyEstHHGSBKkL9mTgBOegYNeH/gIzh5Frjuz4ajz9fyyn5+D1PcLIzMks
         1Rlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P7YAkbJd;
       dkim=neutral (no key) header.i=@suse.cz header.b=ct7u2HKk;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id s4-20020a056512202400b004b49cc7bf6asi659660lfs.9.2022.11.23.09.03.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Nov 2022 09:03:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id AD7E921A20;
	Wed, 23 Nov 2022 17:03:26 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6EDA213AE7;
	Wed, 23 Nov 2022 17:03:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id PkBhGl5SfmOscAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Nov 2022 17:03:26 +0000
Message-ID: <bdafa84a-e5db-471b-fdb2-34ecbf09c225@suse.cz>
Date: Wed, 23 Nov 2022 18:03:26 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: [PATCH v2 -next 1/2] mm/slb: add is_kmalloc_cache() helper
 function
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20221123123159.2325763-1-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221123123159.2325763-1-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=P7YAkbJd;       dkim=neutral
 (no key) header.i=@suse.cz header.b=ct7u2HKk;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Subject should say mm/slab

On 11/23/22 13:31, Feng Tang wrote:
> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
> kmalloc") introduces 'SLAB_KMALLOC' bit specifying whether a
> kmem_cache is a kmalloc cache for slab/slub (slob doesn't have
> dedicated kmalloc caches).
> 
> Add a helper inline function for other components like kasan to
> simplify code.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

Patch 2 seems to depend on patches in Andrew's tree so it's simpler if he
takes both of these too.

Thanks,
Vlastimil

> ---
> changlog:
>   
>   since v1:
>   * don't use macro for the helper (Andrew Morton)
>   * place the inline function in mm/slb.h to solve data structure
>     definition issue (Vlastimil Babka)
> 
>  mm/slab.h | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index e3b3231af742..0d72fd62751a 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -325,6 +325,14 @@ static inline slab_flags_t kmem_cache_flags(unsigned int object_size,
>  }
>  #endif
>  
> +static inline bool is_kmalloc_cache(struct kmem_cache *s)
> +{
> +#ifndef CONFIG_SLOB
> +	return (s->flags & SLAB_KMALLOC);
> +#else
> +	return false;
> +#endif
> +}
>  
>  /* Legal flag mask for kmem_cache_create(), for various configurations */
>  #define SLAB_CORE_FLAGS (SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA | \

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bdafa84a-e5db-471b-fdb2-34ecbf09c225%40suse.cz.
