Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBGHLXKJAMGQEJS5WJ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CA1744F7C38
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Apr 2022 11:57:44 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id e6-20020a50fb86000000b0041cbdc01b2fsf2677478edq.12
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Apr 2022 02:57:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649325464; cv=pass;
        d=google.com; s=arc-20160816;
        b=l9U52DwyzeyoIHYvH4CZEFDU58pb0artE0el8/NQ+PuPW7d3HGtHtkPKVafWrn91xi
         CXdMyZvG9Bmjt3rE1b/iIAQGN5GJ/fKLi+xr2XuKUKRYMUiGzF+UI+PX4amtPi35o+se
         WSVkKG6Dqy8ALvHyt73029cy5GLKDrSWHYoDGYt9+lZVdqxhVSrv/UwH0i9y8uSj99QH
         o1K2TWUNYItO7clRxHM3Z/TkFBcqnXDPjdFWAw5Plpb2kDnMpTCOX2lJRHmbc3P97cKE
         usWvV/NNlvK88LYDsf83ViT5B+isfbq3b4Jz5Dfdv8NRrz9e/kjUVGJX1Bgvz3TYDtbJ
         Tzfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=2AArUA9AGj4aU6YC0g2tP4chmK/drPvlfV4w2P34vyo=;
        b=Z3jmf1XQem1dgM+tuCMUD6CarXCe1Is6nedQ6C0mufm4f9I8nCfJIHGlm8FlLfwmqz
         T/NrX3mkfxHgUA/U6K5HmTKdtJuukAn4b1Dm7B1DJoUG26vn5k0SSioF4D5gBFjU9A2N
         MSeD1AhmlWtSnYh39pZ90d54tkkBqhFhcF9JVoJ8SAluVJd+zuxyl+8/cWqFr1C8N6je
         a50nkAMg1bBv/2BR4hUCVGDIrycwYnCiaN/cVGKwcN5sE8G/2Mc2fAVYiCXTmPjNTnp1
         NdgO4xklM6hP/paeLLXvZfZ/qM1SfDWNQYF/1YpbQq/YmEKFWAVXsSYIVaGOyyJn8Ppa
         hsxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CNJ7geQJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="/V2x1NPw";
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2AArUA9AGj4aU6YC0g2tP4chmK/drPvlfV4w2P34vyo=;
        b=knRT8Decuefw0JSBvJMrobybF/3ua4Tinm2n30HBBcgTh2yr1I0Wfdb3tkfzYp6vL5
         DpPUGD0AWo4OkDcC55++o8WyRm84sq9rHcE4DVLpFlCQeYJCgFU6AFXRYyjz6N9W7jYX
         RQen70zgWVBLyGiQ8bKU1SFzcrGmHDlC+bt8BsSvlb65FOCAyC3iXLFPuhg4u1uIeZ7z
         aRcciGuh2rm/vzhAikOpwIWKvRc8o3wYJHxWVs+Hzs9IiYo9D0556wUpEMiiWIYl0llb
         Pq0lQAj9MpwL+t2CDBpwRlIxMcjSAjwqvVXCta59cT/5zC6sQHcHvo9Pk/xLUEZ30hbW
         bllQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2AArUA9AGj4aU6YC0g2tP4chmK/drPvlfV4w2P34vyo=;
        b=JY4UPOQAMev9eijktrfdTw7KEGDtL6jGaF4q1sQLgUotq5cr6Z1boSu7U133GFE6xL
         SzRcJFsJ19ScRYNAfgWGF4LM0MwF1Yln42u9N2u6boJ43hEAPl45eBuk1UeoJecwA/be
         uq44Yg0QyV0jZ+NFSwmes5cs8dLaGdx97dmoYeNWibxYSny9y5uQKYzJBUZWkheZNIuS
         +Rd2Kp4EEXJqvKih944gfO8eSC7ZQdyHthdv72pNppCCAsjntNftgOWWAA6XEhYNigoU
         hr9oNbxAOEsWhi5XC2z5CeOGcTawyP4fihKlnwYynzxt2EYG7NbcJoKs9KrDwz19j3am
         p3+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G3fyYxJAVjsPSsN/KTlEvVMK14T0KrgXouRyOXeej4bCZtpPB
	jPYdJgUDJ05GcS4EKu/V7e0=
X-Google-Smtp-Source: ABdhPJyQ/XB+VFj9AFN65I4rVjxVADSUKjParQwYvMwn6KsHk2+kIbfBGPnkBO/tWbBEeOPIDMLGOw==
X-Received: by 2002:a17:907:1b10:b0:6e4:bac5:f080 with SMTP id mp16-20020a1709071b1000b006e4bac5f080mr12499183ejc.24.1649325464527;
        Thu, 07 Apr 2022 02:57:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7f05:b0:6e6:3c07:fbbb with SMTP id
 qf5-20020a1709077f0500b006e63c07fbbbls62599ejc.6.gmail; Thu, 07 Apr 2022
 02:57:43 -0700 (PDT)
X-Received: by 2002:a17:907:6095:b0:6e7:cc3f:c33d with SMTP id ht21-20020a170907609500b006e7cc3fc33dmr5848600ejc.570.1649325463175;
        Thu, 07 Apr 2022 02:57:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649325463; cv=none;
        d=google.com; s=arc-20160816;
        b=dCSNriHL4r8UEpFFMK6bgfejryUVElMyfzyPMURp73df2dAOYYkVqfJ0NG+8/3nNAq
         hDM3bMyWIDeE0YmO8ynTh0pJawrXR9Kw0cev4ylnBCJt4z1LPKP/UZg7hIh4WLNurg8v
         a3nUuzSKztDMkEoMSI2ESJCIrc2/bVoX2i1byLgl5fRJ2BzxA1SJpo6F0ZTNDu7FkNTs
         arbw3H8jGwSdYLPXOwg4K4vp27QL8tX3rm1E5AIOs42AvjmSnFnvnQdsZv02t54ScDDD
         cTctoSWIho1ueIjy9hro4p5QhJcgHcfstUVbbVY/eq5l9lVOGlSq+254ev5l/BN4KVqa
         lRJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=5nI9oyUvHFM5eGetZ+O4IuNGMmysnPBQecOrPZDio/k=;
        b=sxP8J1YQ7LsneMbURxq62UpWzX9a1hNUwIvLL4wJwGNUGD0J3krsALx0+Mv0tumTwu
         8jTqbVDYLpliyHbudNfdCV2+k4nxdJdCSx8/wmxjHdMQvyhyzb7sP6uL/JewzN+2exRa
         CGes4MUQt6t2euhtFQqwkFyry+UeKfF3YjwKrKlhU4lxKDMpcT8dsvrIICGjhciq0hy3
         HMljCr1KkMJWFi3DHpeoe7KODVtCHsFPIZGLCs/xLeHV8YyGVbGtRR/zEyONy9yXDI/7
         HsbIw+0MSL2DxUQeyVFdKwHJ53shjjzoGf/FH8AqKH6XA2hvmBSkjJEj3AUUtRTtwY3+
         RY8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CNJ7geQJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="/V2x1NPw";
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id q2-20020a50aa82000000b00418d53b44b8si1278127edc.0.2022.04.07.02.57.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Apr 2022 02:57:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C32D121118;
	Thu,  7 Apr 2022 09:57:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8EB3513485;
	Thu,  7 Apr 2022 09:57:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 0741Ipa1TmLtOwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 07 Apr 2022 09:57:42 +0000
Message-ID: <d179e539-1da6-c489-b2b4-ad97367bd73a@suse.cz>
Date: Thu, 7 Apr 2022 11:57:42 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH] mm, kfence: support kmem_dump_obj() for KFENCE objects
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kernel test robot <oliver.sang@intel.com>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
References: <20220406131558.3558585-1-elver@google.com>
 <4b592848-ef06-ea8a-180a-3efc22b1bb0e@suse.cz>
 <CANpmjNP-XtRB3zTOymH_PCKbDMHoJVYx6UQd_xoM-s33bXJk2w@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNP-XtRB3zTOymH_PCKbDMHoJVYx6UQd_xoM-s33bXJk2w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=CNJ7geQJ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="/V2x1NPw";
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

On 4/7/22 11:48, Marco Elver wrote:
> On Thu, 7 Apr 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> On 4/6/22 15:15, Marco Elver wrote:
>> > Calling kmem_obj_info() via kmem_dump_obj() on KFENCE objects has been
>> > producing garbage data due to the object not actually being maintained
>> > by SLAB or SLUB.
>> >
>> > Fix this by implementing __kfence_obj_info() that copies relevant
>> > information to struct kmem_obj_info when the object was allocated by
>> > KFENCE; this is called by a common kmem_obj_info(), which also calls the
>> > slab/slub/slob specific variant now called __kmem_obj_info().
>> >
>> > For completeness, kmem_dump_obj() now displays if the object was
>> > allocated by KFENCE.
>> >
>> > Link: https://lore.kernel.org/all/20220323090520.GG16885@xsang-OptiPlex-9020/
>> > Fixes: b89fb5ef0ce6 ("mm, kfence: insert KFENCE hooks for SLUB")
>> > Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
>> > Reported-by: kernel test robot <oliver.sang@intel.com>
>> > Signed-off-by: Marco Elver <elver@google.com>
>> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>>
>> Thanks.
>> Given the impact on slab, and my series exposing the bug, I will add this to
>> slab tree.
> 
> It's already in Andrew's tree:
> https://lore.kernel.org/all/20220406192351.2E115C385A5@smtp.kernel.org/T/#u

Ah, missed that.

> Does your series and this patch merge cleanly?

Yeah the dependency is not on the code level.

> If so, maybe leaving in
> -mm is fine. Of course I don't mind either way and it's up to you and
> Andrew.

Yeah should be fine as linux-next will be safe with both trees merged. Thanks.

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d179e539-1da6-c489-b2b4-ad97367bd73a%40suse.cz.
