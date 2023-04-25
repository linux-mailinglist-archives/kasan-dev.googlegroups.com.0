Return-Path: <kasan-dev+bncBAABBKU6TWRAMGQEVMLK2WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 47C286EDAD1
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 05:55:24 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-54f855ecb9csf71506837b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 20:55:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682394923; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+d2DxFBL6p50cBRIx39e9nVEgp0vzju8MaG0/Ddtoa1ydVe5ARkkf+vq4p98CGcVH
         YrpMtZZFeDWhIUkMlOUZhGq6ZzIaFOZxY6wB0esI40zFSlUpOCl3BBHKFNCAPCPl5DyZ
         cq+C7vx+FOp7KCoA1QWcp/ZzHQmJX42MMm3B169eGPXb7FeqZSrWqB/eFS+1Fp5cmWYm
         pn15JskwL4fgRcNP3jUWt+Z3XmXzmFM3cLOWrgAZHxJIf/M+IJcOM3TwmpQOWcyHD8wg
         QmrM3pqn8zTXh4TDQIVnGSxQsqZBYTdZ6gmNhqAOMNnWooDBjQ9vNfxgjbvufqraJNPY
         59IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=x58BTD/VkwBmx8YNXQ9uj5TlNcmmLr511UGxnjM+XLY=;
        b=jDPIkR6XJUtWErkyW5az8RWr00fLITKPGLHI4lTto0HtPbAtu5ruNKqJwn6H0g69RI
         cyRlt3a2bCIPl4Kh+tQl+nworz75DaFESSkf9KbJPAUNMEcB5VgZycmwFVwnNzF6wHJG
         cmRbkXDWMZvKVTNFA2EELb4S+CbgOKHwF9KT8idwOvKZc88PVARmmUYrO37CrhVc1A1G
         WwBxA52LyLsV0VAWo76Gm6LQcHXKSRQx9DTrO48Ri8I4GMTDIxouom5dF7xP1OYI6cFo
         iQ42lZ57eMASuXgQDHqv74LiQrtCWb9Hb2GjjCvoaEKIkygVA38LjeXUkHGu++jyU/PX
         ToOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682394923; x=1684986923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x58BTD/VkwBmx8YNXQ9uj5TlNcmmLr511UGxnjM+XLY=;
        b=DE/8uUsZEqxD4pr6p/yYWRA0ZO4sINY94fHanziZaE//gNCZlzr7Km9id3zi4DRl/Z
         gIFN7vUh1opg/M2wApXroZ437ulNE2STiX+D+lHOhkBHGvBxA6aZAAcmRUWhJOU+q9iz
         7T1ZykLkPQF3KSvHdf1Qn9qO/56D6WAPPjADlsbkcENsIwf77mTFM/PmfravPbfzgyF1
         glf4G3Q4lLFQ3JDA7QYLeeMGB/NIZsU8O0whscVkC0Gu6nRLfzbJAGrGAYTCVshEXxCD
         RxiYCuSuQeHk6h1Xu7RO/c8CCsrth0vr02hMrW/KRbxjc/YkGG9V+5mPt0/5PDxxb3nm
         ihjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682394923; x=1684986923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=x58BTD/VkwBmx8YNXQ9uj5TlNcmmLr511UGxnjM+XLY=;
        b=Z10HUs7DkKqMefz1GB34ndYlyiJ24EaFAzqylTCvmM1EDqp2QtIp+0GMd76t/j0kzZ
         CVkNuGGaYg4MNNE3Iw1Xg/yRYSVjSy4fW+jeHguaCofY7hEMijDcr9qbOTxxGxu6xdKc
         KajAlgylUl6uVH3yjQuaTMed9EIc6A/zhvnSaFQt9eys/br2O8TsSO10zuG250lcE3B4
         epET2M1088lG83Bxdmfr/5THERyb1qixvCkZKMMxQAyO6njAQwifReRe3C4/j8vemyc1
         Dp04JLG/Oc3lXi2H+8KyFFrWc4cKb3SrjLueaZUqPo4N2iBBZ/gcd0wpU/DRXCPXVLGL
         qW0g==
X-Gm-Message-State: AAQBX9dTw+QbhggccxP7HaGuOIxsmgfrku9HtOZjR7OJrt8shjU7SGL5
	ctjqx9SwFRcouhtPsp/4tkE=
X-Google-Smtp-Source: AKy350ZzQDdE+nt8J0fL8kP7uh2Ejvjp8xt+rNAbKkdM4gZtn1Kp33o5E8kb7ifPhcLzISvRAjzHGQ==
X-Received: by 2002:a81:b667:0:b0:534:d71f:14e6 with SMTP id h39-20020a81b667000000b00534d71f14e6mr6948913ywk.9.1682394922942;
        Mon, 24 Apr 2023 20:55:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:dc8:b0:54e:f746:51d with SMTP id
 db8-20020a05690c0dc800b0054ef746051dls6955497ywb.4.-pod-prod-gmail; Mon, 24
 Apr 2023 20:55:22 -0700 (PDT)
X-Received: by 2002:a81:914e:0:b0:545:acb:e5da with SMTP id i75-20020a81914e000000b005450acbe5damr8966577ywg.28.1682394922468;
        Mon, 24 Apr 2023 20:55:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682394922; cv=none;
        d=google.com; s=arc-20160816;
        b=aEXPKqScmOisvkopbw7vnfNuA/Dj9wBiyd8X29g6nnxFolbuJnNZI/UROpPPpBPLQS
         8VKRo0+FGPMBymr7RxjzoTCl9LO2HZRFPRMa6gU4XIIj9TL7WZQlBQlpjpTznLK7ULX6
         WUone+fB1azyZYhsp1J9FA5jzuDtVdFaM3r12rDdCSmf5XQQbvmaICU9tGBagmzeNMWO
         /LGD5tcy/BlMq8mbqmcoxY1Hxy0MmDzXR3kljfV98cnPGByGcGaqGQ3Nyee8Q+8y3mpV
         ljt8t825Ux5eHbrson3vztMb6hprc6N+J+1yR0OyqOfmOZIoD7iCvSJk7myY4oNRKoSe
         rvdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=CoEKKzOJt3kg3DSMXzb/BFd6QDKZKPpl6ThiVhhnRcc=;
        b=mNCOI/vGN20+igRmPuh54mzVq5vOk+6t3zh0rF41sHBMv7Ds71in1phcKwhVod8Y1I
         HE2dG4GQQbOScU1yIBcodKDdIVlpHNY8ZwomWEiqgBflld825WlTsTBdRrQxAOBUgcf4
         4R2qsKM+XeGu6xCwxHoBMcLiWgjXsuNbLUE99THyRXYyLGLpQun50rpDMkDVFpTw17Sw
         4VGTDhS07kMh0/22kvtPw+s2IjgH2+FOyIVAvjqmskF0hNujqNNYhjVFIVERAHc9m8rn
         GDg+UWtlGfRNcVRcrwauWlM7bCv+KVIKEo61Hyer5OfHKIMTTBOz0YbYNkGjI5ULFg13
         qg6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id eh16-20020a05690c299000b0054f8f5de2f1si738489ywb.4.2023.04.24.20.55.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Apr 2023 20:55:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.53])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4Q57RK54VWzKvMB;
	Tue, 25 Apr 2023 11:54:21 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Tue, 25 Apr
 2023 11:55:18 +0800
Message-ID: <0f3abe0f-216b-dda6-38c4-26ffa79d966f@huawei.com>
Date: Tue, 25 Apr 2023 11:55:18 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Alexander Lobakin <aleksander.lobakin@intel.com>
CC: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>,
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>, Kees Cook
	<keescook@chromium.org>, <linux-hardening@vger.kernel.org>, Paul Moore
	<paul@paul-moore.com>, <linux-security-module@vger.kernel.org>, James Morris
	<jmorris@namei.org>, Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng
	<xiujianfeng@huawei.com>
References: <20230315095459.186113-1-gongruiqi1@huawei.com>
 <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
 <36019eb3-4b71-26c4-21ad-b0e0eabd0ca5@intel.com>
 <f5b23bbc-6fb5-84d3-fcad-6253b346328a@huawei.com>
 <ce1c307e-b7ae-2590-7b2e-43cbe963bc4d@intel.com>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ce1c307e-b7ae-2590-7b2e-43cbe963bc4d@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Gong Ruiqi <gongruiqi1@huawei.com>
Reply-To: Gong Ruiqi <gongruiqi1@huawei.com>
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



On 2023/04/24 21:46, Alexander Lobakin wrote:
> From: Gong, Ruiqi <gongruiqi1@huawei.com>
> Date: Mon, 24 Apr 2023 10:54:33 +0800
> 
> ...
> 
>>
>>> It's fast enough according to Jason... `_RET_IP_ % nr` doesn't sound
>>> "secure" to me. It really is a compile-time constant, which can be
>>> calculated (or not?) manually. Even if it wasn't, `% nr` doesn't sound
>>> good, there should be at least hash_32().
>>
>> Yes, `_RET_IP_ % nr` is a bit naive. Currently the patch is more like a
>> PoC so I wrote this. Indeed a proper hash function should be used here.
>>
>> And yes _RET_IP_ could somehow be manually determined especially for
>> kernels without KASLR, and I think adding a per-boot random seed into
>> the selection could solve this.
> 
> I recall how it is done for kCFI/FineIBT in the x86 code -- it also uses
> per-boot random seed (although it gets patched into the code itself each
> time, when applying alternatives). So probably should be optimal enough.
> The only thing I'm wondering is where to store this per-boot seed :D
> It's generic code, so you can't patch it directly. OTOH storing it in
> .data/.bss can make it vulnerable to attacks... Can't it?

I think marking the seed with __ro_after_init is enough, since we don't
mind it could be read by the attacker.

Given that the code paths the attacker can utilize to spray the heap is
limited, our address-related randomness in most cases prevents
kmalloc()s on these paths from picking the same cache the vulnerable
subsystem/module would pick. Although _RET_IP_ of kmalloc()s could be
known, without tampering the source code and rebuilding the image, the
attacker can't do anything to make those caches collide if the cache
selection algorithm says they don't.

So in my perspective the per-boot random seed is more like an
enhancement: if one day, by analyzing the open source code, the attacker
does find a usable kmalloc that happens to pick the same cache with the
vulnerable subsystem/module, the seed could make his/her effort wasted ;)

> 
>>
>> I will implement these in v2. Thanks!
>>
>>>
>>> Thanks,
>>> Olek
>>>
> 
> Thanks,
> Olek

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0f3abe0f-216b-dda6-38c4-26ffa79d966f%40huawei.com.
