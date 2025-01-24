Return-Path: <kasan-dev+bncBDXYDPH3S4OBBGV4Z26AMGQEKKDLCKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F6F6A1B789
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 15:05:16 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-43673af80a6sf15145405e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 06:05:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737727516; cv=pass;
        d=google.com; s=arc-20240605;
        b=HziXtUXnDf2deiEP5S/fr9rnk/00THcG81ZOAvmlKH2ubtEaYlfTFfhTyssko0nnX2
         p46MdmFGjhxSxSfLi4xZ0UwYQ2n0oSUqwhYIRtwcPz4sTOZ5rgcSh5A8V7TyiSAHS5aZ
         mYavopGcI5gtWF7At9qq1X7knx5Iu8OKcdnTNxMPDBt19YjXTqyHs5Jr/FXdurxlVDA0
         91Di5gmOjLn5/QhZoFjSbclCeDqPEZR00xoVNvh9WXCoE+coy8VeXV1Wauj0c/EfovbP
         ASfgi9nP6jBepk3ws55n5BowToX4LxU//C3uyYCmR+jswaRQpi9/aI24kU71atv6XdPC
         lbug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=CgXl72ydxiljXe29X7r6c7uFTMGKufDDtwd8FQlsX2w=;
        fh=ZrP9XIXZ3oWLawxap52NRQlGkltTijUsL32RwFCuXJU=;
        b=cPDu/lkp6TzU2CO7UENUmUk1Vo0+sD3C/3Zs+toEVIkND0R9+YL89HRRAN0MLtHEUY
         /f61kBjhriZZCZ9Wt8Lq0BCs0BWA29MPRzt5XbpOEjPyKTLWGGGwysmUQSraMkSYD7kQ
         0ylkgqD0eOnWv4fY9+P56UQSQWv7sJNorGlwue49L3OaAtBJ5Mj7flyCpVb0scTyevIQ
         mbcbzx5Ha1Ej4Q5Lf2PXJd9y2rNVvsVpWDeC38qJguxyj4aTZn0AgfKoA86ovZoKa+DN
         IguPfm4mjxJcMBGDXFeg+q8uaVRdCeif5/rKGlETwVjGUrAXtDic0chlAVjc0dZqeP7D
         kdOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zOuVyxCD;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jSNIYaBv;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737727516; x=1738332316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CgXl72ydxiljXe29X7r6c7uFTMGKufDDtwd8FQlsX2w=;
        b=IAjVpNnjvtieKGoTO4SB52+uAZWA30zp4IHUcevaJrTgGsl9Y9ZwKpxoZ3nKfdSr1y
         /f9ghNUVbBil984npYa6ezo+pPhOJxcIK68fsnlePg1OPePs8cMMfVbxlPLMbqgVnY8R
         f+ItMIVfNw/fRlCU5I/Ui/E4scqOFGNsnr7ohJfnbcqYfYrNVsdKGzPMZS/rNBC5tqik
         zBXqtg7sFKW78BqJlFNJE7KITad6Wwx0EpzfJZTQJfVOl4ngCktdSfNDhuwpRskiw/k6
         c9waIHcpX2De7iX+doKI4pdjFLsR3oVPIHk/taBVQQU7bdk21yKs/nTG4T+rZWdgUI87
         HIQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737727516; x=1738332316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CgXl72ydxiljXe29X7r6c7uFTMGKufDDtwd8FQlsX2w=;
        b=O9dY+IVqSPtgWPZX6cT5ATE6ifMa7/j/mLVIpSZPE6KUrve65xpgt4Q2njogz6R45q
         6oxwKWDeCGlQdsvg448hPw6yodjkqcAp7wRMX6mW7H2LTzdLP4kjRxLR/IMj+EdkLTWh
         Wm3Y+pfNkweQUEQXMGwCgHPmKcPakHjjXEU+FdjNPON6V58jrHSZwS9wPg2u8u2HIbzs
         2gUyaQzxj80o18xvN0h/bYRfuZGInjW88tAPeX2uEcqFLbihVis9Tm+trM9N6oNhqRpA
         oUa8aTOYAVlFZBGZiCVyojEy9NERdYv8OI6SWZk6dg9ElyvGO6QxGtjStmztjFN9O4BS
         mf4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmfy6KKXsRpwseKMR5/cF6x6fHDvu2qqlwCEfybdVaXF2KVDNILzxIXgNwm/XpIANCy1k45Q==@lfdr.de
X-Gm-Message-State: AOJu0Yyw6mXbNKY2hG+tj8aXIDUbqmddXaIADWZfRtjwQHtkESpIjMAz
	kzLK8Dzg1koMCzm49d6oE41TT6IpF49WnEUqbesZEkEmRwJCuHz8
X-Google-Smtp-Source: AGHT+IHyLuraXkrrNOf/NIj5lucFgggwpAP1k2GontjhQ2eAJzhErlmPW38EAghDPzcxEb5Fz6Xofg==
X-Received: by 2002:a05:600c:1c16:b0:435:32e:8270 with SMTP id 5b1f17b1804b1-438913de562mr294013885e9.14.1737727514807;
        Fri, 24 Jan 2025 06:05:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:21d0:b0:434:92f9:ac7 with SMTP id
 5b1f17b1804b1-438b879d988ls1145145e9.1.-pod-prod-07-eu; Fri, 24 Jan 2025
 06:05:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVd6rE3ZUdyDtBuTHsoQcgBOJNQsvdYoYBNWt4MYcdfVBqF1VNPOJODwbCEc73qPpC/rL7HzqaLPQw=@googlegroups.com
X-Received: by 2002:a05:600c:1f8f:b0:431:93d8:e1a1 with SMTP id 5b1f17b1804b1-43891430defmr237253435e9.27.1737727512535;
        Fri, 24 Jan 2025 06:05:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737727512; cv=none;
        d=google.com; s=arc-20240605;
        b=LFjsNNb8QFyEFn7EFER3plaf7n89acxn2xYQ0tBtIc4O9xmzqnHHAQo6U412SYDbtw
         d0mhA41bWWfeOG8LCQbG3Vn2DCK7FU0Bcvq6pfYStkoumgqNwwqKQAc6Cdj/wi+zS4IP
         wRwWsdvzyqDZuOT1j58RwXcqBqTsJRWAdxMjwNcAJkAscp7oaqWemyS8/yH9AmxiHj9v
         pIVmogHyotQk9fMXkvKRP4tVZ7o7ItoWKrzu8dIQX1q1kyIY6jagr6T2BUVBP3wBxCyB
         pA9f8pgTBVnNXnAJ+JgTk71/EAVgMP6JS+9STAz1brKv6hg4AZ6HlFG3UxdF2KzcXB/B
         tz3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=TEpqkUFrpFwJ9Q28sx9kwQ1bMc8a+hA5atrm7T8BjuM=;
        fh=ZasQ0mXavyX8VNd9VGnxE2Mae0DPRIWq2odfW+DUfSk=;
        b=HAkDFROrkcdNVucwAIO+3vMFZVu9Rqz3+k6YK3PzOaj0EKA+kzYd0scdYi43eWTwg6
         LSllaxdOfltb6B3zEzNwvgOf6i3Q3Uob/XngXsXZbJ5WRomCDczUGSeM3c1KasW11O10
         DIjlRYUfKELHgq22VWG+XIA3sLKIwwRSoCbNngfv54XqysS5i7ngTEU/dMNwl7ApDvEf
         rqdU7qjBtLwGYpKQxd2yvN8rcpuXD5mI23py3rmoAXC14SdPazmr47QDNb1Ej60GGHHh
         G/Lckr06v5zQeWp+L5Olp0XwgVAmnm+z/9ZH4/q4IQ4trAMhop7NT+apV1YlKUI6XNvv
         juPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zOuVyxCD;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jSNIYaBv;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-438bd4728c4si267385e9.0.2025.01.24.06.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Jan 2025 06:05:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E370F2117D;
	Fri, 24 Jan 2025 14:05:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CE6D2139CB;
	Fri, 24 Jan 2025 14:05:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8rUdMBaek2fZFgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 24 Jan 2025 14:05:10 +0000
Message-ID: <d4a7b91e-5048-496e-95e5-c83cd8252d8f@suse.cz>
Date: Fri, 24 Jan 2025 15:05:10 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kfence: skip __GFP_THISNODE allocations on NUMA systems
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 Christoph Lameter <cl@linux.com>
References: <20250124120145.410066-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20250124120145.410066-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	RCPT_COUNT_SEVEN(0.00)[8];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zOuVyxCD;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=jSNIYaBv;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/24/25 13:01, Marco Elver wrote:
> On NUMA systems, __GFP_THISNODE indicates that an allocation _must_ be
> on a particular node, and failure to allocate on the desired node will
> result in a failed allocation.
> 
> Skip __GFP_THISNODE allocations if we are running on a NUMA system,
> since KFENCE can't guarantee which node its pool pages are allocated on.
> 
> Reported-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Christoph Lameter <cl@linux.com>
> Fixes: 236e9f153852 ("kfence: skip all GFP_ZONEMASK allocations")
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks.

> ---
>  mm/kfence/core.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 67fc321db79b..102048821c22 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -21,6 +21,7 @@
>  #include <linux/log2.h>
>  #include <linux/memblock.h>
>  #include <linux/moduleparam.h>
> +#include <linux/nodemask.h>
>  #include <linux/notifier.h>
>  #include <linux/panic_notifier.h>
>  #include <linux/random.h>
> @@ -1084,6 +1085,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  	 * properties (e.g. reside in DMAable memory).
>  	 */
>  	if ((flags & GFP_ZONEMASK) ||
> +	    ((flags & __GFP_THISNODE) && num_online_nodes() > 1) ||
>  	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
>  		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
>  		return NULL;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d4a7b91e-5048-496e-95e5-c83cd8252d8f%40suse.cz.
