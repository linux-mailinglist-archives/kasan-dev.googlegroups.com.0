Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBH4NX7VQKGQENOAZFUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C1BCA8568
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 16:13:52 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id w193sf4180332lff.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 07:13:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567606432; cv=pass;
        d=google.com; s=arc-20160816;
        b=UU1acTeCEhzPZCq29VB+TMCMUjvaJbT5Ylku3izCsL9nJoY68uxUcK+q2qOLEO/vaZ
         eX+uHRSLpPqMsh8h5VNFtLnWrVlQFB9syxq20DCNB4dcQtxFCBrR2TUd95g9SX9UCRbJ
         W3ShcDIw3Ma0eoH5dVaq2JxRMgIu51fWGQdGJuZS1+QUyUPwQfoxL0dNsMhl5JsUBOmq
         jZRJsEWXip3ysOv+pFMZjN9zXPkENyVtrmDpOAZ5Y6Z/LrL46aP1lF3KgFq9Kr83MpxM
         boBQgLZGBWesBG6vmmCkySH4hccVXEed+4qUDbIwWrFjLLDWhExREcXarshv5pyzOR7D
         BagA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=2btcvUjELufNpfS5vlvrD4gTHEzBVbCSbvgkCUTmE1Q=;
        b=FteL+7s4jjRlBpwHTbWgKpJc58Gggozf72phqdng5yGWcRB6m0zVzS0iTjIqZe7SCY
         1aZPOpHvhPCwBKyEVk6UALb38365bPdNvhgQfy3Oo7YsvY7ySJJuiDogCY+/Sve8otA5
         nRUoigyhSBwq36Ex0gkP06+kHnb31oP3iZ7ev2L2N4ymAfwGwN85ckASlNo+svS8T2um
         FDBKIuIGyHgg5H1Okorc32zPJL7uzckU5/Lzj0CGEdtKceNop1eWf+84tHPSftnuXuVs
         2YY8PTEQ5jyHTZWFe7vOe2V+dMrfuBny4labSr8RoneLSOqjnXAvVKLPYALsrfTzQbdt
         aidg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2btcvUjELufNpfS5vlvrD4gTHEzBVbCSbvgkCUTmE1Q=;
        b=ig4TrQGKAy/uHvWqdXYOLmXMSJcu4BqSRxZqNuN5RRKIYTCRevwA52HmgZ3iZLHdLn
         FFSpDr0znJK74rpQHxmBtQdOertLYH0zpghlrJ165Ax85UhEBzS8alklF8/XQRuF6UCo
         Epm3PNr+oThnKlBwMpt1xCsGEbTQiwEabk2PyufL+KB6S0qTvNHvKCZhNBSbWvIvdTFA
         /mf1lrtAk2bT2+urQAcSgQG47jhpOEffge1R3JHVYet8OiDMuQgFe/8xCbz7ilMVxQ/4
         RCC9kCeq/DdSle8cR7MpyPbVRMwQgdvxkm0S9QhSzqFNMeUlLc+jMNkOtFuNmsBXSW9/
         8qFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2btcvUjELufNpfS5vlvrD4gTHEzBVbCSbvgkCUTmE1Q=;
        b=qZ/0latBy4N01WvMkLslir1VYJD2/tbCTaPl19qZe2we7XaB7KvA2T2swJyf8TTola
         JK4U3TLNLaBD7a7a9MoHc6Icxz2o4QdEvl8LivBhZmJyxUFUF0jv6MnTZC4afQKbMS3N
         trS1C00FxiHvazQ5vho6VvMamGDUfQWVhRgJihODD5Y/QiWYk1kU4IwmIGDe0pCwPd2I
         Cit5i1Ec2V8XZKPbeE78WuWpvWMNTQ7ARmPcpkR2Emh1qdkP749xLP//0Y4a3qJw8RNW
         7oLynI12OnH6lm7fPpaieWTFeteYieDtyj2ue+F+YPp3b2UXiN7MJGDqpKodLxmXB1hW
         SkqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUvCsjNdQ3hcPznJs6xWIuM+92Lfd4IdG8Aw4P9R5IQY4xgfM9h
	9USPkaX3FpYfI0wC7y0e/G4=
X-Google-Smtp-Source: APXvYqw15XRFYgT2Uy9hi7URZSItPAeZ6l714fM2ofyIHidiWSfS8qZwM5KZYLtwSiIvnlBQmAvnJA==
X-Received: by 2002:ac2:5485:: with SMTP id t5mr21586763lfk.27.1567606431919;
        Wed, 04 Sep 2019 07:13:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1285:: with SMTP id 5ls1438159ljs.11.gmail; Wed, 04 Sep
 2019 07:13:51 -0700 (PDT)
X-Received: by 2002:a2e:8591:: with SMTP id b17mr22737872lji.200.1567606431308;
        Wed, 04 Sep 2019 07:13:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567606431; cv=none;
        d=google.com; s=arc-20160816;
        b=NFpjKSA50lkgyBM20VtehXs2os5PnSrg71Qi2czbY0i7caZCF58sTIkU6cc890qb4N
         PznNrd9hPhpXAgc6l3YidgsyWft9YoheZAohG+I8s+x6BPEydClAzED4xRpYP3eLARwP
         5rKSoaajXL5526PMlwSOnCdYC+JyHOX/dgnoMDazA2xnI+wu68JdCW0bbzW7UGx35jpr
         TLWWgmeg9a6vangwEB8LoIQcIXKWyNQOZABgfiQvN2fwbEBDm9nlkYlgpgR/e4IIyiCT
         bsttLB+lfNMNOnBTjou5Qc3NAjL9xxhd1B6pRT3aaiMBQIEKv8z+p/wGCYZKmMF2novI
         NcfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GoXykA/lVU4T5iNkVo59Bw1Rmk7YYxqAlGL+xi7EDrE=;
        b=IONh+b8CNrLeVpyq0EdecreMpb5K2KpiJfTgBsNFNhJdj46Jp8fbCOsUM1JGDvHVn/
         k1YJ8yNWw1JQyLUToPwBnDC/3uXcUiVdzJ/Cc/TI9TVX0HTkbX8/d3n+eGf56LccPQQV
         pjuskrfIFArI+YB2JNCmheJV7y6dF7KzRug3m95mZdzBzX9avH0w+tVmFRHJeye2ABjZ
         9QmhyW/HdFwj/JBF9w7/27MKrksYsQnd4soGcQ7oC91C52Dei5xWHicQK+gGqeXSdbB3
         GoGQFQS9UT8+gE22Um6+1s/Nc3clmBvzmNKYooL52jBWjYNJVOVcayouoWBID1tKMjvq
         Bfww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id h6si1104262lfc.3.2019.09.04.07.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Sep 2019 07:13:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 8F3D1B048;
	Wed,  4 Sep 2019 14:13:49 +0000 (UTC)
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
 <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
 <1567605965.32522.14.camel@mtksdccf07>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <7998e8f1-e5e2-da84-ea1f-33e696015dce@suse.cz>
Date: Wed, 4 Sep 2019 16:13:48 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1567605965.32522.14.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/4/19 4:06 PM, Walter Wu wrote:
> On Wed, 2019-09-04 at 14:49 +0200, Vlastimil Babka wrote:
>> On 9/4/19 8:51 AM, Walter Wu wrote:
>> > This patch is KASAN report adds the alloc/free stacks for page allocator
>> > in order to help programmer to see memory corruption caused by page.
>> > 
>> > By default, KASAN doesn't record alloc/free stack for page allocator.
>> > It is difficult to fix up page use-after-free issue.
>> > 
>> > This feature depends on page owner to record the last stack of pages.
>> > It is very helpful for solving the page use-after-free or out-of-bound.
>> > 
>> > KASAN report will show the last stack of page, it may be:
>> > a) If page is in-use state, then it prints alloc stack.
>> >    It is useful to fix up page out-of-bound issue.
>> 
>> I expect this will conflict both in syntax and semantics with my series [1] that
>> adds the freeing stack to page_owner when used together with debug_pagealloc,
>> and it's now in mmotm. Glad others see the need as well :) Perhaps you could
>> review the series, see if it fulfils your usecase (AFAICS the series should be a
>> superset, by storing both stacks at once), and perhaps either make KASAN enable
>> debug_pagealloc, or turn KASAN into an alternative enabler of the functionality
>> there?
>> 
>> Thanks, Vlastimil
>> 
>> [1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/t/#u
>> 
> Thanks your information.
> We focus on the smartphone, so it doesn't enable
> CONFIG_TRANSPARENT_HUGEPAGE, Is it invalid for our usecase?

The THP fix is not required for the rest of the series, it was even merged to
mainline separately.

> And It looks like something is different, because we only need last
> stack of page, so it can decrease memory overhead.

That would save you depot_stack_handle_t (which is u32) per page. I guess that's
nothing compared to KASAN overhead?

> I will try to enable debug_pagealloc(with your patch) and KASAN, then we
> see the result.

Thanks.

> Thanks.
> Walter 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7998e8f1-e5e2-da84-ea1f-33e696015dce%40suse.cz.
