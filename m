Return-Path: <kasan-dev+bncBDR5N7WPRQGRBS7BY6MAMGQEMU3JPJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D26B5AADF6
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 14:02:20 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id h5-20020a056e021d8500b002eb09a4f7e6sf1578618ila.14
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Sep 2022 05:02:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662120139; cv=pass;
        d=google.com; s=arc-20160816;
        b=p6wvB42kcgtJsbAsZR1dXJZWsdUFjBTksXxLcjfLQnziFu+pe9uZxvNOazP0iiXmox
         y95r/dbVkGP94wEqP5gj1bw9QswHlHVqSDsmC6/EO1+hofS2tytbo0d70lQuI6stwmN/
         4Zrb6vRRfWMteT9aTsfuyXyr79fXcUSDctQyE89jrgSsBPMW6DlqJCDJrTxxtitjml6X
         ihgzPePdDzo3U2+AE7F6AgVsxTd4NAf4IGWkpU9tEGXKvgFKGA+IID5LqWlGIETmSWvw
         Q8wm3+7qIpRiEgYdloJzIkJPA8W0cxPWiz8L3yfDJVUu11foJIZVgfuB99rSqDex6WDd
         AEWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=5snNGC/pVkdDCOn9fbl0IFbMdYKPEncQNQj079QxkEA=;
        b=K2+fPDFkCzi0aqD/EoiAcDWklAbGnb3vV5as449j03wrqaKmNbYXgpY+8r8EqFxp//
         m0G2uacqoUnQ47Xfu1lieWpmtxWpWayRjYsnR10prF+oJIi/n7cXnyB3D3wI5UZbxkve
         9m0PfJDFjsP0cGM24lfd6JaybWE73dJejITKxbNROrKBn1rkUFn6LYAxl55XGlAfipPp
         jrN0oG0g3hSzGUIIjdH6oAVWRlvQONuOheKWVS+2hoePP7x7pg9jOMHxzaSuXIwZRDW0
         HToUpma5YXSQZ1gHZ9F/5ni3J+FbWJJ1RLgoHXV82q1JDY1XkOpcRG671UQ/USl4p2z7
         Ugbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=KJAXAw3+;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=5snNGC/pVkdDCOn9fbl0IFbMdYKPEncQNQj079QxkEA=;
        b=UIuGCzy/86Nzu8diO/5w7681hLR4r7mWHd+sYdrfHAfIwzcXCqZu0G9MyRJw1R+gxj
         xgwqQw0dHGQON6S7YasZLwhOCpGOcv7eZ/85UDaMzrGA6XcFlKhGZTp43lVi7F1Xwc0Q
         Kz/X6Vg+cdKhCmSimbtbFKq4y3ONg76HkDfYKdlZhR2wr/hG4w/2hbCSJneRNPBgeOWl
         zdyu3VKNobpWzRqKI1Fc9ndtSMB1OFd3RWj4gkgkvaHtt/0d18dgkP8EC51qwyh/uJ/r
         fBv3L0TF7p7n5bR/BCadWEKALezWTfllFJsR54gisF817SvTe6875+XR+6Iq75ZcGc4O
         hs+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=5snNGC/pVkdDCOn9fbl0IFbMdYKPEncQNQj079QxkEA=;
        b=BiG1gihR8WsMdSW2gGdz1CmuSd5/oHVlOlsmjbUUkBtw/eFGkxAQY6m5QCh+9XutOM
         4vpMO/k0otaghxR5A3+jzy7wvjprjV/ve8ezMzUjCuaYxXF9N0yI6t6N+bEXxEJ+EFOt
         NGgnKynoS42TER9Kd4wywQgCUwxVbSMw+bOoDkGG0Q1nj06nMA5cZyOsdQWXGfiWpciX
         U/WDxfuVbtljJx8Zs8YIY8hktqEbmGjJjrtkqUNKt0TOY7FjGnQzqBEjxXwunIiac4wj
         TLGVNzJesuBWOs9mA1f+0j1WPc3gV/AxqsHedZWqrz9UnCMxGhOIGHo04aCp3Faisn7W
         PxXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2zJpVQ8dZ8w1UVZPqsZdsGShtPZnQ4v63gPfCCyICG83ag2n2I
	28CLraPLfomWMFnVaRPyfUo=
X-Google-Smtp-Source: AA6agR48sxJZrGEfnCO2JelTg+NEBjj9i5hdU5Vaxh9S7VOze2yUyPH2hNvpAPFhpKvFQ227h26Z4A==
X-Received: by 2002:a05:6e02:e08:b0:2eb:26ff:791c with SMTP id a8-20020a056e020e0800b002eb26ff791cmr10062022ilk.168.1662120139389;
        Fri, 02 Sep 2022 05:02:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1207:b0:2ea:c355:ada with SMTP id
 a7-20020a056e02120700b002eac3550adals1142099ilq.0.-pod-prod-gmail; Fri, 02
 Sep 2022 05:02:18 -0700 (PDT)
X-Received: by 2002:a92:b0c:0:b0:2ea:db40:77c7 with SMTP id b12-20020a920b0c000000b002eadb4077c7mr13377459ilf.188.1662120138751;
        Fri, 02 Sep 2022 05:02:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662120138; cv=none;
        d=google.com; s=arc-20160816;
        b=TOAkoYR+vd7TmF7G5fspoiRCnaY4rIj60wJb2JnZQiWGNXvOJcngRxisbwYECbgC1s
         JWCcx4jkFbzkQyN+JOf8ZVa75vuMrAovfNlTrijWJ+wgDiEPFCICX6aDDvphipkOiBJX
         OtLniKu/GppIKSGgcaH74ONT37nO4aMgo6/5I880/Fi/ggTtZGwpe3YYwIhCf7metzec
         rV2i5sBz95emOOmBB5W3NpoWX8z5yc1oYKvBvdXUDu8vY0gyffHu6Sq7zzUPeQaO+Q4X
         5LRv4pmFzT/UnJkYDzSSsC1wEtwuga1iahRzyYotXDqTiJj3tAtfujStjJrQ/QkVlJxa
         uM6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=W8RjYI+n37ofAo9LBQEiCCEo6ndS1LkvyfXGybqsT9Q=;
        b=hcsRQBMCmnG6bWGXWur7680TtiLacIIJbUCzCV22wsstUAbf9tU3DTbL1DJn95+/uv
         e2p4PSQU9bUguQwxRv2xays5cpur2YruJIyLAUsunwKiAQZCjbbKZenO5Ds79EKE2e4B
         j0OxfDABRqtVSxmHr2YySTKLs2o/V4+DA0tIpjZCzIixJ6XYbNScAVhTb3iX8c49zcfC
         AdP+yA6smOBd3ldZEua5LR/VOmB9gQ8qDQUcH0hsqDOMdoGZ5w2En17hNVNxXCWnMSpH
         9VVin/EjipVLObH/Q5iSztLbwxCzHmsI5OCheccHpd9L3sI7QMlTZl/atmmROkN6u4in
         J5aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=KJAXAw3+;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id u9-20020a056e021a4900b002eb7fbf5c8esi84237ilv.2.2022.09.02.05.02.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 05:02:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id l65so1662020pfl.8
        for <kasan-dev@googlegroups.com>; Fri, 02 Sep 2022 05:02:18 -0700 (PDT)
X-Received: by 2002:aa7:92d8:0:b0:537:acbf:5e85 with SMTP id k24-20020aa792d8000000b00537acbf5e85mr35570681pfa.61.1662120138036;
        Fri, 02 Sep 2022 05:02:18 -0700 (PDT)
Received: from [192.168.1.136] ([198.8.77.157])
        by smtp.gmail.com with ESMTPSA id v65-20020a622f44000000b00539aa7f0b53sm1557339pfv.104.2022.09.02.05.02.13
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 05:02:17 -0700 (PDT)
Message-ID: <3a41b9fc-05f1-3f56-ecd0-70b9a2912a31@kernel.dk>
Date: Fri, 2 Sep 2022 06:02:12 -0600
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.2
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Content-Language: en-US
To: Roman Gushchin <roman.gushchin@linux.dev>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Yosry Ahmed <yosryahmed@google.com>, Michal Hocko <mhocko@suse.com>,
 Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
 Suren Baghdasaryan <surenb@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>,
 Johannes Weiner <hannes@cmpxchg.org>, dave@stgolabs.net,
 Matthew Wilcox <willy@infradead.org>, liam.howlett@oracle.com,
 void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, Steven Rostedt <rostedt@goodmis.org>,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>,
 arnd@arndb.de, jbaron@akamai.com, David Rientjes <rientjes@google.com>,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 Linux-MM <linux-mm@kvack.org>, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
References: <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de> <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
 <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=KJAXAw3+;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 9/1/22 7:04 PM, Roman Gushchin wrote:
> On Thu, Sep 01, 2022 at 08:17:47PM -0400, Kent Overstreet wrote:
>> On Thu, Sep 01, 2022 at 03:53:57PM -0700, Roman Gushchin wrote:
>>> I'd suggest to run something like iperf on a fast hardware. And maybe some
>>> io_uring stuff too. These are two places which were historically most sensitive
>>> to the (kernel) memory accounting speed.
>>
>> I'm getting wildly inconsistent results with iperf.
>>
>> io_uring-echo-server and rust_echo_bench gets me:
>> Benchmarking: 127.0.0.1:12345
>> 50 clients, running 512 bytes, 60 sec.
>>
>> Without alloc tagging:	120547 request/sec
>> With:			116748 request/sec
>>
>> https://github.com/frevib/io_uring-echo-server
>> https://github.com/haraldh/rust_echo_bench
>>
>> How's that look to you? Close enough? :)
> 
> Yes, this looks good (a bit too good).
> 
> I'm not that familiar with io_uring, Jens and Pavel should have a better idea
> what and how to run (I know they've workarounded the kernel memory accounting
> because of the performance in the past, this is why I suspect it might be an
> issue here as well).

io_uring isn't alloc+free intensive on a per request basis anymore, it
would not be a good benchmark if the goal is to check for regressions in
that area.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a41b9fc-05f1-3f56-ecd0-70b9a2912a31%40kernel.dk.
