Return-Path: <kasan-dev+bncBC5L5P75YUERB2VC5HVQKGQECBK77PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id C9C35B10B0
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 16:08:42 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id t185sf57712wmg.4
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 07:08:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568297322; cv=pass;
        d=google.com; s=arc-20160816;
        b=XHfeeTDS0pcpENb159CrScR/yz3Fk7ZrhxddVUFmBh3kFBTUWGl2HRrMLH6/aZMDY/
         hd7+VnmXT/kIjQdUdbFs6MndzXePRI85vZsnHt80JTJWaBXa7qPSeYqCbsV28W9HP0AR
         BM+RIqyuAku9pB8WO7FPDKHulX6RtYlzvrCNxSy/4sx3YLVXqzProlXIGrfu04PMWgFh
         xZ5RTI4z05pd8btcxOuUHxC39rd9pLgjE4TT52o1M01qWGlWaDBTfEz6jJyWK5V4xONd
         CF/sKKYa6NSggXZFCFe3BbfYGlnn4XrUJr4Zbx2g8+IKa/gSWQsglaGIokwiF58AnvN/
         YMfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=egqb0MwsV/S5mestHcwmC1VAcNItr1dCOBsHXM77GNQ=;
        b=YYfItVBIHmtjXoHpUTOSIz6ZjxQOTPTcqc/kk8s8kjNr7Tvj7HuIFgReZCA3XpJP68
         sUSArbz6kUB0nUTi8SzFeDgWRbozfYSDMpo3hyLEtlB3w97EnU91szOmg4O7JYiaIN75
         FMbhmVKt3onTLXish5WgZz5ixtLCZr6sC1G5MKwIBNecNrZj/urKRA/i5XCg+NGP5o5V
         clgOiXNkkHqnR1dzKCQXtBbXoaX7U3QYDFqQ+ic6qyNYZqKR+fDITUdAok1W6q94+CbU
         vf4ap5wD5nuUu7oqvz+T2S/jR2vSqm8gyNpKF18JSMJOUkhN9g7AGNajHWbgX04ljseg
         0JKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=egqb0MwsV/S5mestHcwmC1VAcNItr1dCOBsHXM77GNQ=;
        b=M2ZJnb1YfWh05uKBN6Y3aaV63TGYqG7PCqn4NGoQhJ6S0zD5X60YIuwE+QzomS8nsQ
         a9AVx9Lo0ZGrQV/udH6Ld8QxuyJGo8nzMDonnreod/WCAzOMzKf9JtsfWjoDe0HZ68Mb
         GG+rpAJ3yS2iZjzvaZcN8RLPS1Nq8tpNg2iXhNi9OtWYUfr3LDFL0XPDOC2sQAOI7s5g
         N5dJryJYTb0wj8UzGSvkhSrRp3BX1xJk3uHoANO/o1HrD7XTdfk62ck3worcKgBt5bwl
         e6rAel+Uo7UQ/8JU1YdZousYRFTASNakfX9ngTDDRLksp7hzT5BwCb24wkaLC2A2TvD2
         hP/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=egqb0MwsV/S5mestHcwmC1VAcNItr1dCOBsHXM77GNQ=;
        b=U0TBaXIp6ZxPyNI8baoEo04ZroGB6lKD00NE4pXQs2ev9UmVvxIxG0W1WNU73Z14WV
         CHReyYAvcLSODq6gdpk7q4tq8fsK1gqMpvPTLwDzfMp7b+FIhYl4kl0aPPxnkqpV4958
         i3IF9WVo9uiGu8Z0AwnSM7wQzhtnDmKm4A/IbB+YhsKtdm77Y0nIvI1ZTbKyO0DeH7jx
         I1bpWT3T3fWRpwrsNLDDKEt2LswVuAS5jbJAeu+6NhQ3xdVy737+mYS4ci4PgTPn1XV+
         2WuLx37feZwiHbmyB2bSIs026p6eVqGhfRkpvNuEAwM01v3pyScxNDfleLMtkWdWQRo7
         dJzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVkvDYJ/lbY589npwwQs5LWkF6KpwpDTVb5OT0KKrvLnxvRnmRU
	Qo+b2nHBbPN5gn4+v1ldhNk=
X-Google-Smtp-Source: APXvYqyy0Wo0kYHFOFOffp6GhVs9zLbEewWZp/j1akRyrW02Hk8lZZfydU+hULq16lEp10C2vioPMg==
X-Received: by 2002:a5d:568c:: with SMTP id f12mr35755906wrv.248.1568297322396;
        Thu, 12 Sep 2019 07:08:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c141:: with SMTP id z1ls49003wmi.5.gmail; Thu, 12 Sep
 2019 07:08:41 -0700 (PDT)
X-Received: by 2002:a1c:7c1a:: with SMTP id x26mr156743wmc.115.1568297321920;
        Thu, 12 Sep 2019 07:08:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568297321; cv=none;
        d=google.com; s=arc-20160816;
        b=nCb6UY3o61kiewks5gBHjh7RgK8QOJzMgp15FAv5W237RiwcwW6KRhmc8/ckvcoFBa
         shKo0idP6gFPlcwS/HJrDWw73xpcskmi2V61w1shRdM/2IjA7EaoY2i8W5lE07gFuWNB
         HYsM1FDuLoDi1nJvoj+IgszpcfKd6W+MDH/QjPLQc9BKZgPPJxHscc+hgY2/0Gk4KNYM
         ZmP6NP98VAu+BIG2KQfu1MObgjLoMiGFfEPBdRgVxETBuUHQmnj8i8KysveG8giSbcFv
         973HdSGOt41PafgfxOq2vY/9qItJNzapVZ2tvjvLH/UqM6Sj98QZ9tobp5zra18fLt7h
         Gizw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=zSC6VrtWvqGOkWuBv2AldD+/BDY2YAJUIjmOQn8Hwtc=;
        b=ovCE9M54YISDh460xcf7uY8xYatKWAe1bfgKfaVLvtgl+geOEzmZgx+OcAeRHggfAe
         OeoXMCvDhHCIrRsWpWv2zNsQNwwTXhq2ZjgdgGSFj/ibFFvTyeMiIpPYP2uEi2Mel4zk
         9dW8T1WD0M4bcTbGJr5+1lDPOivVYua1f+At5x1StpRu+LXRbMfLFFPZGXZVzmw2NHhM
         Tee17PwkRdXLs8fsQoVs7lTZHTIJKAP7xP9I1lZAosBD/94k/DV1RO6TqNa+UTBVzReo
         QawkYCQpt8pfRvWF1f8NpEcjPi9Bd5K8BcuONaXSY0UgF2H/oV7deZCZfY54Tc0v97oO
         1iJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id y3si10162wmj.0.2019.09.12.07.08.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Sep 2019 07:08:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i8Plm-0008P3-U4; Thu, 12 Sep 2019 17:08:23 +0300
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Vlastimil Babka <vbabka@suse.cz>, Qian Cai <cai@lca.pw>,
 Walter Wu <walter-zh.wu@mediatek.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <e4e23249-9f37-1d66-d411-7786b7aba36e@virtuozzo.com>
Date: Thu, 12 Sep 2019 17:08:21 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 9/12/19 4:53 PM, Vlastimil Babka wrote:
> On 9/11/19 5:19 PM, Qian Cai wrote:
>>
>> The new config looks redundant and confusing. It looks to me more of a document update
>> in Documentation/dev-tools/kasan.txt to educate developers to select PAGE_OWNER and
>> DEBUG_PAGEALLOC if needed.
>  
> Agreed. But if you want it fully automatic, how about something
> like this (on top of mmotm/next)? If you agree I'll add changelog
> and send properly.
> 
> ----8<----
> 
> From a528d14c71d7fdf5872ca8ab3bd1b5bad26670c9 Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Thu, 12 Sep 2019 15:51:23 +0200
> Subject: [PATCH] make KASAN enable page_owner with free stack capture
> 
> ---
>  include/linux/page_owner.h |  1 +
>  lib/Kconfig.kasan          |  4 ++++
>  mm/Kconfig.debug           |  5 +++++
>  mm/page_alloc.c            |  6 +++++-
>  mm/page_owner.c            | 37 ++++++++++++++++++++++++-------------
>  5 files changed, 39 insertions(+), 14 deletions(-)
> 

Looks ok to me. This certainly better than full dependency on the DEBUG_PAGEALLOC which we don't need.

 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e4e23249-9f37-1d66-d411-7786b7aba36e%40virtuozzo.com.
