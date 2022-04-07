Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBSHLXKJAMGQEIEHUK6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B107D4F7C3E
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Apr 2022 11:58:32 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id m3-20020a05600c3b0300b0038e74402cb6sf2728100wms.8
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Apr 2022 02:58:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649325512; cv=pass;
        d=google.com; s=arc-20160816;
        b=csAC4UUrIMUjuSayCU/eCaHCjX2/0THS3KkDXLPjYI8J8BleiNT1c5S6buZz/VMIdZ
         2Bd5AZS57nNvn4nLiBI3NpaXb/nNCDTgixG2g7kqhXF7y5p1sj/2XR8BGmeNwTooSyBH
         yzTDEBL8r9HtEmdj8AD7GgV3Zwi8OrRvglBMR6wHyzl66jAaOsmteGaKaxV2UIdANq3C
         oCLIOV1gIvnRVMztggvli6C7Ui3vsqLzbVbnDn4juRTFMayprcmUA1RBXRigCXP9fyxy
         zIh9umNyGuhfyf1+yACYONfS3XUsqRUloLVghsjrehdDHyyTaol+2JlL1k/W+5Fy6yZY
         D5hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=mYi6IMUw1Qq7vjgaez5DWC7c3U1xHayT2E1zA5co7Dw=;
        b=pZmIuqhlGQzhogE4HMog9ul9FnjhkW7DeZMnn8uu7vZgs6IDDtsOeh8bb4djXMfrip
         KbE/okF9ed7FeZ0ubz7Pe2FWrDvh6Minp8xjT9WKD7g85WU6PgsUpFe7guVKiPDg0Fke
         LD8oeZv3KxcmruGcdad54NCgGwJFnHHyLIPzw01Pff+rBsxLmp/3dklAFkdR1rVWCEGw
         Ymoxw38hRExaj7EQxWC1UKx5Q5nqZ2HVyOvLLug3SzjMv4PG9gOtV2tSAheIb0LeQ/Jm
         7NUaZokRlmw355SXthrsvfJ5V4vtVn5ERjSg+nxOlAWeGyF8NK3E8jxhmh4LvaLlm4rb
         TIWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=usFCJscT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9Q5u38Fp;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mYi6IMUw1Qq7vjgaez5DWC7c3U1xHayT2E1zA5co7Dw=;
        b=TehRrWf9o6GmcpMremsTer06QlG86xuJDSK/WS6ikJfnQNBQlNMuS/AyQl4M/lcyaF
         OC7IilYF/kkGRk9L+rD7ILsCsuFub/JmG3Q51zz1muEJM7GpveRsRJS29bMMkLEE1Wm+
         xrK+GrjFtrrDgb0j77/qEUSi6Jwa4rm/uUQcgOw3CB35UUXeViJadE+UtlC0xGCk6a14
         89pLYKqtZGm1zlf++1mTx3mwjEJvgAgIUPRTjHxBIaQ+mE7bUe4a12kbV1aezUmaSuHO
         CvaCeMtoj3KXOjezcR/a8Uq8bT1z7LWDqVhkhEJIxV40SK1svEZ0xLkMDt0t6R3g5VYq
         OurQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mYi6IMUw1Qq7vjgaez5DWC7c3U1xHayT2E1zA5co7Dw=;
        b=40PXDsH92UcrjpjcX14JITHwdp98O+q72f5LGteXFiZTR5+G7wM8FB10DuAIJwMMq+
         8EeldrN+TeZrP6qDHpqiKtcKjBzGGqr1OchcLhqf1PYyn81f86Atj63ec4aCPXKpCB+B
         l36AwZPQa64G/rr/55NccZkXEYB9209sCA10Wvs3DwaVq7X0UKItlMCSCX6qLU8hlVNL
         dp/VkvMTAnEbD1Cr3spEoOI76KSd2Qkpg5l+QFspD7oO1wOz3a+HHdYtGPyLWC+RFfVL
         IHVZYY8bCUYdNhjc+1PG+ZscfWz/uTsSSv68zduQ5PGv/DVVezOdhkrTRHdELQIQ2/8U
         sIaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BjJVORAuk+D2jG4YG9SXY+6lNLqYvkbiYsZbL18XXRhO0ceqG
	RqN3uXMZn63P1Q/zeHrj1q4=
X-Google-Smtp-Source: ABdhPJw0i8TnM4lGwDoD6JyAET8B7K1l7oR3c1/ej0VGkEd1rQyhbfQccB6sY2xI0utVhkzZ/78B6Q==
X-Received: by 2002:a7b:c8d5:0:b0:38e:8df5:c9e2 with SMTP id f21-20020a7bc8d5000000b0038e8df5c9e2mr2285071wml.154.1649325512307;
        Thu, 07 Apr 2022 02:58:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5306:0:b0:206:e61:ce02 with SMTP id e6-20020a5d5306000000b002060e61ce02ls1883983wrv.2.gmail;
 Thu, 07 Apr 2022 02:58:31 -0700 (PDT)
X-Received: by 2002:adf:fd08:0:b0:206:164c:4ac1 with SMTP id e8-20020adffd08000000b00206164c4ac1mr9994833wrr.680.1649325511044;
        Thu, 07 Apr 2022 02:58:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649325511; cv=none;
        d=google.com; s=arc-20160816;
        b=AeXJX7CvL/e6osR84Wb1zrGMIH9gjHOgC0ho4frOllWk9bCGVFXmVJLSObXaI2DX6k
         kWTUWWx+5+LTimuzfN8YKQkdgaxdAuyvGhC9lxdhuWY5n/hGmb46gEKT4i+TFALXQvck
         V/EdLcOOpyuqL2FBtBWflcnjd56aqovoPJ6v0ACK6TD81HyXExbxUsvcrzPdPHQvu1MM
         selfKqxVNniWFBYet57M6EH1lVEn5rtZHvgIk18e1VZwV2pzg+Pbo66NiYMWjdjgtcCB
         7kM+krVTrew5/Finh/8se0v5cYkOsatOhcr2DqY9nykQ1yaRRYlkzKn6J7bjNWvyUmbl
         goQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=QE+cv28KYN3xiXPbIjU3dnkz8QDJL3R+xVJOvX+X4/g=;
        b=Mt2u8Zh0AwtKjBIQpxuGdO1FtRvoxG34d1zUiIFLUV0/mXoWged/W9BKvwDfG32kse
         1fEJWmacuwAsjPtvn50sBKktB36cTX7HdohIXXj/5I2DY4gGSDNALf4JrvdvMT8a0MFj
         knCX06dZZCGW5dRMM+1073lLi8B0nTBIJZ8H1jSERrPuxwXPGKRVJKZ8fGmlh+cP62nU
         b19V9/Sf0JE+Z4sb3PdQy2shslYFk0AnVedCKKmHElwCG/L7g8gIFQJZJADQvqcwE/Wa
         HAOQpWAKS+Hii84XlDyNR8amATxG2k8HVrBOXWKsMdwTLR+z/I+l4uBkR4b2Nomghmys
         KNKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=usFCJscT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9Q5u38Fp;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id 11-20020a5d47ab000000b00205f806f142si1012135wrb.8.2022.04.07.02.58.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Apr 2022 02:58:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CE2EC21122;
	Thu,  7 Apr 2022 09:58:30 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 879AB13485;
	Thu,  7 Apr 2022 09:58:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id vzlqIMa1TmJYPAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 07 Apr 2022 09:58:30 +0000
Message-ID: <6bf9acf2-4e89-0767-63a5-2231291c30da@suse.cz>
Date: Thu, 7 Apr 2022 11:58:30 +0200
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
 header.i=@suse.cz header.s=susede2_rsa header.b=usFCJscT;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9Q5u38Fp;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

For the slab parts:
Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  include/linux/kfence.h | 24 +++++++++++++++++++++
>  mm/kfence/core.c       | 21 -------------------
>  mm/kfence/kfence.h     | 21 +++++++++++++++++++
>  mm/kfence/report.c     | 47 ++++++++++++++++++++++++++++++++++++++++++
>  mm/slab.c              |  2 +-
>  mm/slab.h              |  2 +-
>  mm/slab_common.c       |  9 ++++++++
>  mm/slob.c              |  2 +-
>  mm/slub.c              |  2 +-
>  9 files changed, 105 insertions(+), 25 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6bf9acf2-4e89-0767-63a5-2231291c30da%40suse.cz.
