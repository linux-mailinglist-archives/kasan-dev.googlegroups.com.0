Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBRPEXKJAMGQEPNAVV7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id D3B6E4F7BFB
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Apr 2022 11:43:33 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id l2-20020a056402028200b0041cd2975b87sf2633455edv.22
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Apr 2022 02:43:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649324613; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wa4a87C6aQDPbk8iRMsTxaFou3/0SHfckxkGvrrfDdvgeBRg/sJd9QoC4Rbx/Bu42n
         RbWVtYfczvrLEsO/vNCGgOT3guFSGuWYXLdgsWMXZc6h2EwZqbBmIg2QC2lH+XJW9EK0
         CQzywal9Sxa0vvgXKok3xnnhW8mdQyxYSPXmVsdYIO+DPUDIfARrm5bRnrNV49ZDw9cq
         1nWG3Jv5zzRSX1l6DBS1kXcS8aFZXYJJrKxzVTgtc4iQ/AKpukAB5wL0CYcMRyKJcN5b
         +fCKLwGmAl6iuYTXBt31ZK0/A2RTQ2clBpuFCHnXL9VQ/uifp5JhHDJc3IaME7nj1AQr
         t4dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=thxIK76YXmzIQdZVEesOdmh5t1YEP36mBg+/C1h9oTw=;
        b=JRFy2EKtcJbRGHuTRb6vFZot0ZDRrmWbEaJqGa1u9eGrgmTOEAMcJmxIvjzin3e2MY
         9T7LwvMu0orqCMIVbZopX36pimn82nCusWrZNYwrGJOVX/Avz+4QdisBMzy6frRxzcAq
         /BaUIxQMikxBjg3kYLLXPHBDaXjQ1STh1tpNs1IeP1bVkXAAKZNf+Puz8u42/KP3O10Z
         6wsAnb1w/2P1nxBOES/UOmSsrJ10N9Cp94UAqQ3pyeN4z+Wnwqr7um1oxAnTggcP47tC
         8kZIHeGXl0ycHNwbycWHx+bXFpqcpi7QMVkGxOcEJDPQi8e+UcZV5UokGKQ4JucxP7dz
         DbLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=n9ckxMvl;
       dkim=neutral (no key) header.i=@suse.cz header.b=7piVvb26;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=thxIK76YXmzIQdZVEesOdmh5t1YEP36mBg+/C1h9oTw=;
        b=dKys6AzY8IrUUsCHADvJaA/izmCLWOZwpZdkcjlo2qq80jAM/z3Ex9idH3JjqU8oax
         Khh2kpTowmf03ISnogPZWFbhmivanNT9FLVYjBJpRFKpmnUbe5YsK67x3BcFR5+FAmml
         bdoD7OoCiIGxZCueOFTFxPSgGm568Kh0LP2amxlbtjKTRTxWydrnms6vsHmLsnAAc709
         Bdr9JkeFvlO2uzS7LP9XsbBXaJ5f2LbBq++gkyi9nr+1yUbnqhTOWrmxAVPPEmkXSYOn
         23JcTCBN3AjlRxbVKmNJ6Xli97xuLzQXYWlDZdsYZ6UaatzwmlSUR+Tw7DIDdpN+iPy1
         kF1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=thxIK76YXmzIQdZVEesOdmh5t1YEP36mBg+/C1h9oTw=;
        b=USwcg8yYvnMc1paxDv4WjRZIaQ+oYml78PRpP9RrSYiba7ghPDBjRlY8FLoGHomVPC
         ucpEaeAqbfujMPjArFBZZc+P2h6y/DRvYsOX09DJw9KDO56JezOkWQ1SyugIoL4Z3cM5
         GjfLa4ZLs69MGPtpTwDkcKouPyVwhRAYWMZHTiz/x6cG6JmGz5EoUu+24JgXc6KoXh/T
         1O82cJMzjpo1RPqBYDLyPfy01PM7hh7pfh9bIBgQokVfHJIWIFgckgjbxEPhhqciDseG
         om/r2sDJeVq79AWaGcdNWbQXEQjWUlKwQcTyqj/CX4qme/J6PXsr+BKE1l3QMzMu18PS
         /3jQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ya/Igi/WnwSkDGVij3OL2DLWCYR0jOVDuoXui+FGkePGpDqjb
	R7bl3kk0PaXX/FoCCU9IuAw=
X-Google-Smtp-Source: ABdhPJy/72NypPV1SsLsy+01f6piI7ZYU7DlvHEpB4JqWZ9a2qXkeUVSV4PPlWMimydaz/kIwX15Cw==
X-Received: by 2002:a17:906:d54b:b0:6e7:f185:18d5 with SMTP id cr11-20020a170906d54b00b006e7f18518d5mr13101012ejc.155.1649324613452;
        Thu, 07 Apr 2022 02:43:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:274f:b0:6d6:e53e:993f with SMTP id
 a15-20020a170906274f00b006d6e53e993fls1259825ejd.2.gmail; Thu, 07 Apr 2022
 02:43:32 -0700 (PDT)
X-Received: by 2002:a17:906:5006:b0:6ce:3762:c72e with SMTP id s6-20020a170906500600b006ce3762c72emr12147192ejj.30.1649324612087;
        Thu, 07 Apr 2022 02:43:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649324612; cv=none;
        d=google.com; s=arc-20160816;
        b=o3sJgzEEHAY3fBLhLm2pxNgy8TS1fn84tge+N8v1cwX9EccN3wFrLKDKctLF1bOMck
         UujGRoc2DOxzHibQNe7gNWcfINHDYqLL4X9f9z+raTnx+AmVU+NUi/Jg2Z2w7Jh4gx4O
         mcM3uy9sbSbVrQD9OkoEVq7/KiCKOjzED57A670217z7SvZRy360tW0K5jQlVWDGHEcb
         UcCIaZUbLYHbIxmhqPpGGxq9aZlzZ+yQL522Dhh1kurn7MKT10D0vJoO1veUx0RnYN7y
         ZxfxT1JQTl9bHLS6Vn39sU6m9bZdJYGQIe3S6Z88GuEp8DbV3MC6f4hRY4ZdhZM3uoB0
         6MTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=vVYoOYaAx4Gi+k6jmKcQlAmR+lRXy3fsIaZR5iuwl9o=;
        b=aiDpE1YOBfCg4Hik2/DhAO3Mhc4UVXNf+22rpylqsg3rWzteDTPmqRd2HDHNBhARNN
         ClPfitbyWY9cEk5k7P3/a/edO8BwX781x4GQWrLfANINcAD++r28QYZ0uXPQZVugPIJH
         FlNlu+QjLkH6sI1WyKiaBQ33F505FYHtYkPespbfpQZ0dxkhto0fvvf5dWZlzEyQDMB8
         Lsq5hnklMeDityivvYdNDULiZL9dO5p4SNW3LqAAofKzgL2dHXXotKLW5+m1VX/LlZkF
         OyVufMnXwFsuH15FXe3ioCWwQuxtPquYSodenrAwPyz40rzeRH4TxV7m4+9+QDcNTMGq
         WUdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=n9ckxMvl;
       dkim=neutral (no key) header.i=@suse.cz header.b=7piVvb26;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id f5-20020a50bf05000000b00415e600c761si248771edk.2.2022.04.07.02.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Apr 2022 02:43:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A4F0721118;
	Thu,  7 Apr 2022 09:43:31 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6EB7A13A66;
	Thu,  7 Apr 2022 09:43:31 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id nVgvGkOyTmL5MwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 07 Apr 2022 09:43:31 +0000
Message-ID: <4b592848-ef06-ea8a-180a-3efc22b1bb0e@suse.cz>
Date: Thu, 7 Apr 2022 11:43:31 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH] mm, kfence: support kmem_dump_obj() for KFENCE objects
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kernel test robot <oliver.sang@intel.com>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
References: <20220406131558.3558585-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20220406131558.3558585-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=n9ckxMvl;       dkim=neutral
 (no key) header.i=@suse.cz header.b=7piVvb26;       spf=pass (google.com:
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

On 4/6/22 15:15, Marco Elver wrote:
> Calling kmem_obj_info() via kmem_dump_obj() on KFENCE objects has been
> producing garbage data due to the object not actually being maintained
> by SLAB or SLUB.
> 
> Fix this by implementing __kfence_obj_info() that copies relevant
> information to struct kmem_obj_info when the object was allocated by
> KFENCE; this is called by a common kmem_obj_info(), which also calls the
> slab/slub/slob specific variant now called __kmem_obj_info().
> 
> For completeness, kmem_dump_obj() now displays if the object was
> allocated by KFENCE.
> 
> Link: https://lore.kernel.org/all/20220323090520.GG16885@xsang-OptiPlex-9020/
> Fixes: b89fb5ef0ce6 ("mm, kfence: insert KFENCE hooks for SLUB")
> Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks.
Given the impact on slab, and my series exposing the bug, I will add this to
slab tree.

Vlastimil

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4b592848-ef06-ea8a-180a-3efc22b1bb0e%40suse.cz.
