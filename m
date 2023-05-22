Return-Path: <kasan-dev+bncBCAP7WGUVIKBBMFGVWRQMGQE5FKUG6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 19B7D70BBEB
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 13:34:10 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-75b16092b0dsf77724485a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 04:34:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684755249; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCpUv/KDM3j/JaV+7uyY+072FeFy0BlKIQ/ZsvOU0XrVoKVaRiYfPAi9k7s5qH3wzo
         epUL0WFrD/ug2B6ErELG3ql/Dsm1Rat9c47+oTiEQA3le2IJolXKsNZkEZNXDXE0WIYo
         NdBhSX9mnc1zLMfi5GXRAK3NGTDrDDzHY3W49WJNCfRqH6xJr5XG41YzO6JjwEmIT6Np
         FMUVzIHaPV/3DBRcXgQ4feT3Wn0oQLl8F7QZuuTSHSZkHE1EKG8OBiEzeEb7u0fM/gQO
         dFaTRps8w53eMqO9D2P4wdZekKIhddrCXILDg+vnHYR9vgC9PA7zWwiikbtvhEDFmocd
         v5SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6b8gADOtBWzw5UBaLs8PLFaJJj+svFr5Y2mg1qb4dos=;
        b=iMRJoGWbvCfLN/i6QSNExFJVSsWAxSonChcPcuxRhio33mFSGY8dkoDY5/Cihz0PL3
         M08rJVVLRM+J6u4gcy3jz04/fY5eOosZNnxDlMXmtY9H1/eQkbSODnO3SSK0UAuJIAx1
         B5CSy1icMozc0mFMxo7UjNvrNOypo0PGbIfVB7X/Gu8MWgpqTseysliY60F+KO8+0vDX
         W2vNluXjchB5FxB/jKTEkoUcbRfF8JA37ejIy1e7IizaBPkgnO/dTnR7DGH8qf9FrVHl
         hiIno/qkaHbSPppAV1JCMPEcdSSE8xJXJNWLlq2VjH3i0JKbIYIJ8PUO1VcLc68KJ8qQ
         HQcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684755249; x=1687347249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6b8gADOtBWzw5UBaLs8PLFaJJj+svFr5Y2mg1qb4dos=;
        b=og1PSTeFvGYSZcfHjQeQcDYcFOu4HqRms8gdw7HuxCizz1WXSNt08aNXMmjqZr1mv5
         DfhEDoL/P56rcmIfj/QD3xoUSjhMVx5jTitj23+nm4MSdd7Zl9mvzrSGRBOTeQuqlD0a
         UOSpdT2HV1/fd5n8jzap/cJMjIb2wNxX3hRLsePd/JBvdcuOXjh4fnh9CgAc3Fr6P6NY
         XjZ7ow/4syOeH+h8CR4fQe6npa+b7+eJOUF3IQSBHsdnQiWQMOp4SKgcjTjKYzDQ0yV8
         v/9tRsvAq7hstH/6H4XWVRGV1JlTc9qKJN4YzXuZ9y+LuTHuIb4+IjflkpOCx2TCO+LB
         SLrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684755249; x=1687347249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6b8gADOtBWzw5UBaLs8PLFaJJj+svFr5Y2mg1qb4dos=;
        b=ORsv+TtlN+SZxU3dhBcfdg4HN3fxYxhk1iaIBbZCNwIJu2sZUfirQkB88q0JSW1ui1
         DLHD0HKl1YUSdO49dBcey0cpXGyED9gfXlh218udg9zrhGlyEKvvcgudqzQc3BUwyvgN
         LXM9fN1ggV32pX3KVjDa63vhEgD36ZZfs0VSqGChAWHLxrOJ2NeLI0HQkwg5yZ7zaATn
         Rakb73nM1YTmHxHOD3KdvE8v3WQ+i2QaXX57E7VbKE8OlXmdBJURAUGKI1ITuH2Le5Ow
         KdVcLd7QCp/JUEKAwOKyTaG4SdIxRIa4TfrFO19cJqISRs77vrSSssECR07hjGg9wv90
         zk6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw4rNeuJ4UCy3y/k4mPzPYVeCbH/cAAv74mbPZ4G41S5VmTQaXr
	7XjAkKtvRSWrXgYpRRwmkr4=
X-Google-Smtp-Source: ACHHUZ7J3tHXySPK3CvDxQND3XR62+ihXFCdccKUK2a4L5WCvJV4m+HGtFL3t998Zpf4eoZUtGcf9w==
X-Received: by 2002:a05:620a:4694:b0:74d:33a7:1049 with SMTP id bq20-20020a05620a469400b0074d33a71049mr3245301qkb.14.1684755248806;
        Mon, 22 May 2023 04:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:186d:b0:623:82b3:3d95 with SMTP id
 eh13-20020a056214186d00b0062382b33d95ls7160302qvb.1.-pod-prod-05-us; Mon, 22
 May 2023 04:34:07 -0700 (PDT)
X-Received: by 2002:a05:6214:c46:b0:5f1:606b:a9ca with SMTP id r6-20020a0562140c4600b005f1606ba9camr16542542qvj.37.1684755247765;
        Mon, 22 May 2023 04:34:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684755247; cv=none;
        d=google.com; s=arc-20160816;
        b=DXsomusYh51fFWiHs1k05IDwOVKk/4JVni6YJUZHbIRatvZh1KACoK4YZybg0VLjbD
         aSfHokHvvbegsShd+uGg1Znlh1jxsev4WLfyA0mPP4/r7toXfTjZ0lk+h/5Cccw2XeIt
         fFjPJXc/J0H4uHkZYIGD/C8XyAfu7dxUUXJPnTc9QUCW1Fe0ISnMkcCNC/4S3W5JhgE9
         KnoSaaJlLoy5TXyW8B0rbZCKTkEFmVvEsjXh7CfDxIzC+n1iD1WU3lvtScw/xLRWbE8z
         XOUockrRB7gbTzL0NEgbE9zw24rVFmdwaNkJrm+qd4qnIBBAdFiqb2Bp8CPHwwWYh1/P
         2DCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=AYDtoh5mxqYqc6EDdsPzMeP0JarrQHBBAVQsSfkeDKQ=;
        b=Em9P3EQOwpI8Q6JDR96Rrt3vJORmc8Idq5X720osdKcEe/8cVtsdNR0hM3GBiVj3Bv
         txvbsGY7BU24DqoJZTMMC/FGID7u0mIaR1l1+3kV2hXK0lpFwUUWMK75EF/9vAxhNJum
         D23WncQRzjbmiyTnI2FRZCuGm3R8URhgk1Er9PFzuqxzhWuPmp60EuXTI7058jTbM71r
         C2fgDsu0Nui5SLLJiIMP/xGjg+LYZKF+CyemBqTT5OjDI/9ovtP/NnjZCQEBXlhG41Qz
         ArMRwt0J5o+Te6SF/usw5glmaZ+r60v0bXO5zAN3jbAYLEJQN9VCggFaEhgNFrV5PMJb
         GcNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id n8-20020a0ce948000000b005fc5135c65csi442577qvo.4.2023.05.22.04.34.06
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 May 2023 04:34:07 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav315.sakura.ne.jp (fsav315.sakura.ne.jp [153.120.85.146])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34MBXpNp050520;
	Mon, 22 May 2023 20:33:51 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav315.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav315.sakura.ne.jp);
 Mon, 22 May 2023 20:33:51 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav315.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34MBXpQF050517
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Mon, 22 May 2023 20:33:51 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <b3a5b8be-8a45-a72c-334d-0462cdc582d5@I-love.SAKURA.ne.jp>
Date: Mon, 22 May 2023 20:33:49 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
Content-Language: en-US
To: "Huang, Ying" <ying.huang@intel.com>
Cc: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
        Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
 <9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
 <87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
 <87a5xx2hdk.fsf@yhuang6-desk2.ccr.corp.intel.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <87a5xx2hdk.fsf@yhuang6-desk2.ccr.corp.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/05/22 12:07, Huang, Ying wrote:
> Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp> writes:
> 
>> On 2023/05/22 11:13, Huang, Ying wrote:
>>>> Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
>>>> Where do we want to drop this bit (in the caller side, or in the callee side)?
>>>
>>> Yes.  I think we should fix the KASAN.  Maybe define a new GFP_XXX
>>> (instead of GFP_ATOMIC) for debug code?  The debug code may be called at
>>> almost arbitrary places, and wakeup_kswap() isn't safe to be called in
>>> some situations.
>>
>> What do you think about removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT?
>> Recent reports indicate that atomic allocations (GFP_ATOMIC and GFP_NOWAIT) are not safe
>> enough to think "atomic". They just don't do direct reclaim, but they do take spinlocks.
>> Removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT simplifies locking dependency and
>> reduces latency of atomic allocations (which is important when called from "atomic" context).
>> I consider that memory allocations which do not do direct reclaim should be geared towards
>> less locking dependency.
> 
> Except debug code, where do you find locking issues for waking up kswapd?

I'm not aware of lockdep reports except debug code.

But due to too many locking dependency, lockdep gives up tracking all dependency (e.g.

  https://syzkaller.appspot.com/bug?extid=8a249628ae32ea7de3a2
  https://syzkaller.appspot.com/bug?extid=a70a6358abd2c3f9550f
  https://syzkaller.appspot.com/bug?extid=9bbbacfbf1e04d5221f7
  https://syzkaller.appspot.com/bug?extid=b04c9ffbbd2f303d00d9

). I want to reduce locking patterns where possible. pgdat->{kswapd,kcompactd}_wait.lock
and zonelist_update_seq are candidates which need not to be held from interrupt context.

> 
>> In general, GFP_ATOMIC or GFP_NOWAIT users will not allocate many pages.
>> It is likely that somebody else tries to allocate memory using __GFP_DIRECT_RECLAIM
>> right after GFP_ATOMIC or GFP_NOWAIT allocations. We unlikely need to wake kswapd
>> upon GFP_ATOMIC or GFP_NOWAIT allocations.
>>
>> If some GFP_ATOMIC or GFP_NOWAIT users need to allocate many pages, they can add
>> __GFP_KSWAPD_RECLAIM explicitly; though allocating many pages using GFP_ATOMIC or
>> GFP_NOWAIT is not recommended from the beginning...
> 
>>From performance perspective, it's better to wake up kswapd as early as
> possible.  Because it can reduce the possibility of the direct
> reclaiming, which may case very long latency.

My expectation is that a __GFP_DIRECT_RECLAIM allocation request which happened
after a !__GFP_KSWAPD_RECLAIM allocation request wakes kswapd before future
__GFP_DIRECT_RECLAIM allocation requests have to perform the direct reclaiming.

> 
> Best Regards,
> Huang, Ying
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b3a5b8be-8a45-a72c-334d-0462cdc582d5%40I-love.SAKURA.ne.jp.
