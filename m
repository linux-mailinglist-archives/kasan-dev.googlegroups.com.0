Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBJ5KV6SQMGQEAQMD5PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5877274D251
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 11:53:44 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-506b21104fasf2997508a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 02:53:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688982824; cv=pass;
        d=google.com; s=arc-20160816;
        b=uwqYrN5yGUxRthCJVaZAj66uUkap1mPi8ys2tRSqUdMHZJ0/YxGmulm53qDv9IC387
         TnMPcuviyCx1ifLhooxzr4kl/CZhBrOeFkIlqsJIS0I67rGfG90YJQ1JPFbYs2iUjRY4
         0wwRtwrAjUqMQEMY0lOUrqf9kjL4x9NzxlNuStnp0DZFQ+McpRpacQHJt1gAXeSfj8Pb
         Yn1UGc9975YMLMvEbcbEgDdRipVLX8DTjyThIN+xrx+PuFQMmqsyBu3JXtWUpVkQF1MK
         Z/r1+lj/ta1IPJpN0f/ptEgVeKKa46mYPfrnOGY/aE9p8nJFynDAYqCPI9D3Q//erzxt
         Kl2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ew7gyWFHmi5GsxxNNPLbHAcbShn72gHCSHSz4YG3Eck=;
        fh=IrI/n/gkqIRJEvv5dkVbr4RFMyZ5dUl3kTv7gxKjtGo=;
        b=szMK7timU51+MKS+Hzya1FLFLVYdr40dthGu7/EaDi5hq3mcGG1Co2M11oEu1fJ/37
         Mmrf4QgfmW1bad4s1qsSAgVUqVz8q3WaFNoEzff0grSHRCPMrQsKuchH1oy08rHnUshY
         XzKegnQDQGS+87LiMG7DutkZady3EzyUFb5u1uJr+l02uSAxAeLcEXByqKzSadcyamkq
         pnbG+SQfbNt8ND+2EoebkNBuVCCmJ0LWSJEWkhuJPf/zQrCKml24eweo/XshwQEvJIM6
         KDVlTfpY/MG+poFAD8yMuNKfuUatTtWgOm0F3JVLn0UfaRnzA9bQtxBFL9ACn3W9OdCM
         51yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xz6F2AKC;
       dkim=neutral (no key) header.i=@suse.cz header.b=KxXe2n8v;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688982824; x=1691574824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ew7gyWFHmi5GsxxNNPLbHAcbShn72gHCSHSz4YG3Eck=;
        b=lZFVOGq8vX2dnMCHhO3//CN5J19GGBhDhy+gNqt8Sn3p/D++5rgiangoerGVMEDjOl
         gfX3gQ6MEK+0cZhdaI4xHaucjkZxbyw5FSIdOEbrbEYDSVvVzOHq3UeBY4zTTNZ1ebZa
         xdYO4syVn05Qcl5ubdtvoYFgH2vBBysrIzrEfRRuYjmW4EOv1JvF0neGnYyZ1GFoRIhy
         GfW1qywj04ZCi3cXuvoqrVBX4q76dMOTdQi0XU0XFed5ALpvGx8kqmlyIYmkLhi0Ia5v
         MQcWnOCufsssnCZsoKIkojiTXfqY2Jy44tKZYgXsyXKfpVge/LwpB2o/YxargN9iHsk0
         HGAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688982824; x=1691574824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ew7gyWFHmi5GsxxNNPLbHAcbShn72gHCSHSz4YG3Eck=;
        b=Mfb9k2S7kEoAADqAbFWS5WSspR3DqQfqIzlXZItTPOJjW19yXXFO/Vh578BAVFsjLY
         PAgO0LMcepXO3Y8Fe+LazVaX9C9uG1B6EG0SEV9PlMXCvnic6vTuFyr5joTfr6BCn6ku
         YkATcRwlbMMrwu/K1gWtGw2EcBnPW/iz1ZB+jHgY9mwCTRZyn1lglX4Pdf2sHue+ODHa
         8ehnod/YB/LfNeZlw+oGFHMRzrx2s5Ses0J5ub/1XLt9iDKjRsgB5HoROYwCJ6wWUkkW
         3Lo1jm4UMkv3zMwnCRoZ1RGCFz+2a155MNdW05TOWjBPvTFjbOBpyl6ctek+HYsjBPRp
         T/JA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLau2wQdUQnETLENGRtfk6A8AfdermyiDJ/uvD9pSHNjlu7SxoEQ
	RXBCdHYxawLGj7CTK96M+Cg=
X-Google-Smtp-Source: APBJJlGnb5nLRxw6kGCJRKioMre6q/Hoxq07WX8HqImvtbXX3n0klVK7bfsIM75DuYXoPkbMaRU0jg==
X-Received: by 2002:a50:eb0b:0:b0:51d:e2c4:f94a with SMTP id y11-20020a50eb0b000000b0051de2c4f94amr8856839edp.20.1688982823315;
        Mon, 10 Jul 2023 02:53:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cd52:0:b0:513:f87a:ef6 with SMTP id v18-20020aa7cd52000000b00513f87a0ef6ls1523393edw.0.-pod-prod-06-eu;
 Mon, 10 Jul 2023 02:53:41 -0700 (PDT)
X-Received: by 2002:a05:6402:890:b0:51d:98d1:5337 with SMTP id e16-20020a056402089000b0051d98d15337mr11484845edy.37.1688982821525;
        Mon, 10 Jul 2023 02:53:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688982821; cv=none;
        d=google.com; s=arc-20160816;
        b=PqselGIQ3OXomK5x8qj94Uy0JEqOn4OmaMU+kHM2V81c5s83uc00x6uyCydGZC6LcW
         KjADUuZ2TBjTlk1oa7fZehZ68q5tAKM3NReRGgl/0emUoA4ukROa5vW43mmZUgykIQ27
         /aCuKi8tysUplkTuaFiAbC4tPzUrX0MeFclNj7C/1bMjfYQLflLy0WFNZtQ9UOJ/NNSU
         X9rE/cJMrnr1kibmIlWsGeiCW3QKR8fJgiTFrwvWjuNrOyxdVuIaAgCige2cJJacG4e7
         O+978YCNiDh4xcZBdUTn1C0Aau+4cS/phbqefWz1lwVdxbRBQrg92ggGQjZlbdZI08WD
         XjQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=JhQYnd3zFReOIgvPmbBH7euJHgaFU8/SGouVRAGqJOg=;
        fh=IrI/n/gkqIRJEvv5dkVbr4RFMyZ5dUl3kTv7gxKjtGo=;
        b=p1Zx+SJpwo+NAI1RVIyadmY7ah0+QMNvRh+BzJXI6f/fZJHbsEFNjKsQoKMLCZ/LYl
         n0iOEIOy6cYGBfY2D+013j8qtxi3CBI09wQEAW8CakfoNUNWUAXQBCwvwH88i/snR4gv
         Om+yY/yCUMMA47Lf5mO7xfar0UoFdFyPG+o3Ps7XwI5c8hahck9gbqWLjd6qli741Gci
         LtT00NV8LWbnB78HhujahIrlrk2aES7326W3eMMXllla/EtOMXvf4l8ywed4AbMm6esJ
         Gr+zWNhAO8YdVB26pftuF1Lr6MkZtpoEi0JAv1x/a9KBq9lpetLWdif/bc6pdm4LRe0U
         VuEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xz6F2AKC;
       dkim=neutral (no key) header.i=@suse.cz header.b=KxXe2n8v;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id i39-20020a0564020f2700b0051e55e30e45si232424eda.5.2023.07.10.02.53.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Jul 2023 02:53:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 31F6021EEF;
	Mon, 10 Jul 2023 09:53:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 5A11213A05;
	Mon, 10 Jul 2023 09:53:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id wcRGFSTVq2SsNAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 10 Jul 2023 09:53:40 +0000
Message-ID: <71313e6c-79d5-3ff7-981e-f7675aee0a5c@suse.cz>
Date: Mon, 10 Jul 2023 11:53:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.12.0
Subject: Re: [PATCH] kasan, slub: fix HW_TAGS zeroing with slub_debug
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 Catalin Marinas <catalin.marinas@arm.com>,
 Peter Collingbourne <pcc@google.com>, Feng Tang <feng.tang@intel.com>,
 stable@vger.kernel.org, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-kernel@vger.kernel.org,
 Andrey Konovalov <andreyknvl@google.com>
References: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=xz6F2AKC;       dkim=neutral
 (no key) header.i=@suse.cz header.b=KxXe2n8v;       spf=pass (google.com:
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

On 7/5/23 14:44, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
> kmalloc space than requested") added precise kmalloc redzone poisoning
> to the slub_debug functionality.
> 
> However, this commit didn't account for HW_TAGS KASAN fully initializing
> the object via its built-in memory initialization feature. Even though
> HW_TAGS KASAN memory initialization contains special memory initialization
> handling for when slub_debug is enabled, it does not account for in-object
> slub_debug redzones. As a result, HW_TAGS KASAN can overwrite these
> redzones and cause false-positive slub_debug reports.
> 
> To fix the issue, avoid HW_TAGS KASAN memory initialization when slub_debug
> is enabled altogether. Implement this by moving the __slub_debug_enabled
> check to slab_post_alloc_hook. Common slab code seems like a more
> appropriate place for a slub_debug check anyway.
> 
> Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated kmalloc space than requested")
> Cc: <stable@vger.kernel.org>
> Reported-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71313e6c-79d5-3ff7-981e-f7675aee0a5c%40suse.cz.
