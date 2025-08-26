Return-Path: <kasan-dev+bncBAABBK76WTCQMGQEQ4QYC2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E456B352EE
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 06:59:25 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7e8704d540csf556741685a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 21:59:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756184364; cv=pass;
        d=google.com; s=arc-20240605;
        b=HkcuGvt8w7L1d8ljsZ4xUQ+uPYKgSD+wtkRPKP++rPh2B/nzd058+RelEEyCBOO2ep
         vrWLEdVWWf5QkGGwutijuFZU/8pINsf7MpgU7++qBhUTd5vWeXkrKAcumUXQUb/Qt92k
         DEVXUNFqvam45HvAEuUeXipv8C++B6EMuEUKJUL3bUE8iXPUJSh8J0010bpNuSRVmVtT
         uljcPjUWwHuRGg53RSCj8eE6YevObtW4mFb/lKf263QsODRCM9QXJ0y1G5Y9VYK/STTA
         2Rgw3s2jLgxig7pafzpmoZy77iB3ayFy1U9qSbOI49IJzEWs8z921PoSnk7EH4dTxOsk
         uXAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=lRRztcQvnHZ2C6YjjXd6wl1XdiF826uyumByrsvqL20=;
        fh=zEYkJW39qg1JVLNXjx6mNdPzcnbqN/9eo3w7z4tRRkQ=;
        b=G8arW37da2XTLWxzWlrYXOPVq7WLmHfGBi/i0EnSfOV+E+ulWvLb9ExL73mqDd1Id9
         w5Y9qQDL1GfNM9SdwP8Zb3hASUgWBJenJmqOEJ6jONOtcZoksN2GAaAJh83HVmLFbA0v
         ibbQtjFSbWGd6IUYO50VRr4emFB5nmM0+4ZcCT6P3Ey6brbd54An/RCVqo/JdvSDukjg
         e1L0gEVuoMXYKPLEVDfc59JquhzWayOMwH9CzOxFckJevcKRt3MhrHPtTA/jUz9En7wU
         auPjbaSdcf3mhlZho0B3JS02PksVwUhrFStVM0QFOMyXtfcUkiRQrv0TmKczvRJUDV1g
         ueLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756184364; x=1756789164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lRRztcQvnHZ2C6YjjXd6wl1XdiF826uyumByrsvqL20=;
        b=imHoM0ekq5U2XVP8KLQAksLJzghICaA+j9Srp4ukJmhwOOC6GWt4trr+Fq8AqHd5Wg
         TKKd6hMfn0jbdPwoTh48jCZMVru5uZdXMdzGYoCunGIYsBwjwyOA1pS/hdDntXssnTkI
         ooiBMgDCPk+JIB4e5GSfHRWmga8Yi5zWcnWZXICMnaWsag8tkA2KBDszuz1QcrptkKoG
         mDQPRf0pBBg4cswlTVF3c5bPRe2/HXqwsNPdugazVH9mWxFpfXLPiyZG/HdjPYQGU1i1
         3LvGzp9VVFheAmABrORs5LYULB7L71mn9dl3ucw/5t0/gxcfqcfO4GnDTT3f3AB0xGou
         fE5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756184364; x=1756789164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lRRztcQvnHZ2C6YjjXd6wl1XdiF826uyumByrsvqL20=;
        b=fNO2CzXsVrWv334ZIxoJr5B0BYvyO5m5zQcgm3LjAYMCJz8eLxCmRl2joDUKz6vaYv
         27xho1PpMpHlqL73DBpqsJtZupjZzgj4cVNN/SLGNgKqVro1ioo4RcZ2yMU3udNeMJ+X
         WItwHXn030+9pa81yrx9uEnvG5ryiBodhYKneqicGnsJ2pTlnl1PZRXvPNKMgelj9u6f
         czx7alTI0Dxrjh0ywXnWuKyBeds03U3T7dkEoB1pP/km1wbVKkNfhrcjx+j1HLfndhOT
         cZAEwlT8eQkAkeWihOPHm8yfi2VErsJM84K3x7IM1arwbLkZMpmVgzAqLnvo+mRIIYHc
         u6rQ==
X-Forwarded-Encrypted: i=2; AJvYcCW5k/cVZUu681Ipssqb/IvkH7xoGjz4UQMvvkJDyFiwFF3Fap7f+rLHtCcniQ3h2zwK3a7RLg==@lfdr.de
X-Gm-Message-State: AOJu0YykQLLpAC25upPaF28CaDqEqZlujhtPD0U/7iiJm+wJuSYolT9W
	5Q8NkqYolzwk0ruAa9/Rl5Bw0CULsJwzw3AhlpOJ3WHWUriVv/NnM2+l
X-Google-Smtp-Source: AGHT+IHZYHTJ1NutdUi9W0kPkDv6Ov/SkY/dnj3oH3iAFYJNHZwSFu3h7RPtnnZ78dkMPL8wVbd9hQ==
X-Received: by 2002:a05:620a:4509:b0:7f1:3d57:8899 with SMTP id af79cd13be357-7f13d578c44mr861994085a.73.1756184363916;
        Mon, 25 Aug 2025 21:59:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeS+mFOaDU6eTAYhOjhNAJBREeFJzPtwsk2ZFCJ8mP1OQ==
Received: by 2002:a0c:f097:0:10b0:707:71f2:6be6 with SMTP id
 6a1803df08f44-70d859ffc46ls43666736d6.0.-pod-prod-08-us; Mon, 25 Aug 2025
 21:59:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQgGXsyWBUWSevIto+rSHHecp5yYRgYIlWhx3/zH6Y1zts5/9xwUd4Cl4gQQ2loOnhUU5u+I2Fi08=@googlegroups.com
X-Received: by 2002:ad4:5cad:0:b0:70d:6df3:9a89 with SMTP id 6a1803df08f44-70d973f51c4mr159907336d6.57.1756184363368;
        Mon, 25 Aug 2025 21:59:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756184363; cv=none;
        d=google.com; s=arc-20240605;
        b=ZzErx+A/wSYKHCF1SNwlldrQkehusmC6YBl+jwYSetb9utt69vJ33j+eOLkqOlLiLM
         f2/Te2lVCMLG05vOjE0p0Qow98l2AW4dCBCBDT3SfF2b7blsv4BGXa/2E1T3A8KnsZ4W
         UG5rusO7QV4Tz8SowlISG9x8KL83Subc54eCA5bq4D9QqQQC/QyddWNNBjQsMjZhvEBP
         78AXK/jmW+masisbeuHT2FFWApw3facdo95BVKznFxF4Uujma1ogWkobuxvNkUSxped4
         bF2Nrh/kI27oSFcRlUP8+D+AJXCB0gNY0DfGw3U0ZxVbto8tqnC1fpAzx+pNIcHVJ9zo
         bASQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=HzNX3NeEzB8V23zaQ9TmqXXvMWOXvUwomNCGLR8uscM=;
        fh=uiVSDUgguTDAikDUF5ZB42yPyKHaL/67rtFFz0DtZ6Q=;
        b=jQ/2fg9YLz+2Aasjt4ASiVBlRTAwb2WdhNb4tXlEj83ej+BdDq7/KvpfMmb7uTa0+N
         dTD/T57M5IYGavK1n0I+WUsi99p9uk2bt54ogv5RbtakB2jz9iX5Ay9vTsJy4mIyl3vo
         MrqBb6ksZJK/yWRCwyMkONLjO+w71Qcfgj7ihCGebmQMRn0PFBd+c+yzg3ejoeh9h/Gq
         GwqTJkX5oqV0LCZnJqD9+OORxVZyRuLEqU0az+9EvAYW0FF6t2pt60KhebYHqrdEDPEm
         TsEVSHTZ4j9qxzumSgHmS1fKb+0fmnSdLFtRRXRcFcsRnH9bk4UMsgwsxSgNL4rBQMT0
         wIOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da7172a95si1721746d6.2.2025.08.25.21.59.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Aug 2025 21:59:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4c9wMs74THz13NLV;
	Tue, 26 Aug 2025 12:55:37 +0800 (CST)
Received: from kwepemk100018.china.huawei.com (unknown [7.202.194.66])
	by mail.maildlp.com (Postfix) with ESMTPS id B38881402CF;
	Tue, 26 Aug 2025 12:59:18 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by kwepemk100018.china.huawei.com
 (7.202.194.66) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.11; Tue, 26 Aug
 2025 12:59:17 +0800
Message-ID: <97dca868-dc8a-422a-aa47-ce2bb739e640@huawei.com>
Date: Tue, 26 Aug 2025 12:59:17 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: Marco Elver <elver@google.com>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>, "Gustavo A.
 R. Silva" <gustavoars@kernel.org>, "Liam R. Howlett"
	<Liam.Howlett@oracle.com>, Alexander Potapenko <glider@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>,
	David Hildenbrand <david@redhat.com>, David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Florent Revest <revest@google.com>, Harry
 Yoo <harry.yoo@oracle.com>, Jann Horn <jannh@google.com>, Kees Cook
	<kees@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Matteo Rizzo
	<matteorizzo@google.com>, Michal Hocko <mhocko@suse.com>, Mike Rapoport
	<rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Roman Gushchin
	<roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, Vlastimil
 Babka <vbabka@suse.cz>, <linux-hardening@vger.kernel.org>,
	<linux-mm@kvack.org>
References: <20250825154505.1558444-1-elver@google.com>
Content-Language: en-US
From: "'GONG Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250825154505.1558444-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: kwepems200002.china.huawei.com (7.221.188.68) To
 kwepemk100018.china.huawei.com (7.202.194.66)
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: GONG Ruiqi <gongruiqi1@huawei.com>
Reply-To: GONG Ruiqi <gongruiqi1@huawei.com>
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


On 8/25/2025 11:44 PM, Marco Elver wrote:
> ...
> 
> Introduce a new mode, TYPED_KMALLOC_CACHES, which leverages Clang's
> "allocation tokens" via __builtin_alloc_token_infer [1].
> 
> This mechanism allows the compiler to pass a token ID derived from the
> allocation's type to the allocator. The compiler performs best-effort
> type inference, and recognizes idioms such as kmalloc(sizeof(T), ...).
> Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a slab
> cache to an allocation of type T, regardless of allocation site.
> 
> Clang's default token ID calculation is described as [1]:
> 
>    TypeHashPointerSplit: This mode assigns a token ID based on the hash
>    of the allocated type's name, where the top half ID-space is reserved
>    for types that contain pointers and the bottom half for types that do
>    not contain pointers.
> 

Is a type's token id always the same across different builds? Or somehow
predictable? If so, the attacker could probably find out all types that
end up with the same id, and use some of them to exploit the buggy one.

-Ruiqi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/97dca868-dc8a-422a-aa47-ce2bb739e640%40huawei.com.
