Return-Path: <kasan-dev+bncBCRKFI7J2AJRB5FXRKFAMGQENAXFOFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA54A40D12A
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 03:20:53 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id c4-20020a170902848400b0013a24e27075sf2131155plo.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 18:20:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631755252; cv=pass;
        d=google.com; s=arc-20160816;
        b=HsJMoYpCaOPpqtHWQdq+nSjAHSpd/rGE5iMdMzmmUjrxR94ixTvwWB9rvrWVYZ+/CZ
         wXh9HTWDBhnCIU/BZb+s3Ww/H0KbcLQxuZBzMhYWK5BWpNwjLKdhUDAVH/Eq3O7HMKRy
         xKuoNIlO3pF58V/Cm+BgTir9eejMKvkK9fOOnhtDeIqTjd4sSHVsWD8otbT1mD59ZhmC
         etTRzK3fhzBcYwEUSqC08eDRjp4nexPWn1UcKMFxmfIZVICReqEm8K++HJ5m+EADM+Qy
         HyRfLtFmYlB7stvMgP2C6+/7f65uyPMqjoE0fXeLt0JK8d+wP0svy9lvgoNEvYPU42IA
         vy3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=Yeyr01f4qxPTwuGBsbcRUCYldWexfq3EDD9GKI1x8dY=;
        b=XSp8iVBkhx/9YieH2DNJBewIptxF/cl7n2I6c4ZLnXsjJjyg4Ai8fM9gApNE8DhTwr
         GUhT4MXNKA+zudWwN0modbKMy0vom4HadGNy2DRNTd0A9gpSwsvEdsgGl4ma/rSOOsc9
         LuL+Ik2e4NTAq4H65Zdk+qLy1yp4CubFvy3TD/Hr3t3nLnhBHFh5oEz76sVVeZxhQKv/
         OgiNL1qbBt8CmOe1GvPOJfgj+pcmv6KERdVCaxrDo3XttBVAidfBiFRfl2ZtVVb4EcYR
         rTuxPhAv5jZKkRajemnKae7y42eOu3uKpCflxnC8uxbB+EcVOdJWCi3FDxQ6bkZ7Ebty
         ymhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yeyr01f4qxPTwuGBsbcRUCYldWexfq3EDD9GKI1x8dY=;
        b=AgDifnyDQK/a/IfONI8a5XebROXcfQoMAXvRSB9bg8B1a+fPIQe4FVpzEw0HMhVE2S
         KBTbrq2CuADde0Yyvq/g8kPfFoUeAn7qBudf9emLJ/z6aHtosNxNG0xpXuH8BntRw4UX
         cWMFrkiMaPhQADDGNk2a4FtB3V+QG5xl42m3AXS3CZS3gVOimL3BZBkySKDww1SZNGbt
         eVH30F46AmzHJwqy+UU6B/CqGseX1F93z+QHXIdImmpNzHd8jgZFnSSFPbDIVxknhC1B
         8u52pFJn6kyZfVSd3FIzFttjW2X/BEIuOAt7U1uG8dwgu/E/caOI0lBpmPSEtdktX3hd
         Fk0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yeyr01f4qxPTwuGBsbcRUCYldWexfq3EDD9GKI1x8dY=;
        b=63OfsGFCA/Vp0XdD9G88Rrc3eoAo9Z22c/MlWKiNop77EuVUieGMidST5POEGRxHxM
         vgAZ5UyZOmuBHwyYnHMj/l2a0PTNjyGs3vc+uBU8KETjkIDRVwmcV+aKQ5rNiM1SyPX0
         uRLPFs2zQDUNhjt6FjQ1hA3/cXcAU3jUXI8sb3QnKXi5tevsGOL4spHGW+uNjBgltokJ
         TSZUAGUnSXhBmAUQqEsL/WN+T5eUH9GNPvRT/Z39enKZTO+If3nBj1F8ty9Spv9ocNVx
         CtmkvXva36QCJ3jYSf2R62KtoCFUXFggqfh0pfKlMsYR3nw/JJoKzvdKcI58GCbCeNR8
         XCTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531l0AO3IdnWbz0hggAqdgXOSzz3bZxppk66pfct+YxOe7OvuW64
	imeXHpscdhWansM+nE8GIzc=
X-Google-Smtp-Source: ABdhPJzrRjFdW6DmCV+ijiVdFuOyJ40HwKs3SKgtXKdSXcheLKnie1XC29q4mPvcacfXWVZr++N2tw==
X-Received: by 2002:a17:90a:7345:: with SMTP id j5mr11946911pjs.48.1631755252506;
        Wed, 15 Sep 2021 18:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4d2:: with SMTP id 201ls778661pge.9.gmail; Wed, 15 Sep
 2021 18:20:52 -0700 (PDT)
X-Received: by 2002:a62:178f:0:b029:3e0:35c4:f0f with SMTP id 137-20020a62178f0000b02903e035c40f0fmr2547451pfx.64.1631755251938;
        Wed, 15 Sep 2021 18:20:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631755251; cv=none;
        d=google.com; s=arc-20160816;
        b=v4nJrew3rafu+051bfjGQ3Lirxo/wv2v4GyhHMPbqFiAiYdVhgplBZ95+ak+UroNC3
         H8jxq+Q+OZ6SAbRB48kS8PmkrXCaXdKl96FlFHYD6Nk8IDDYQ6gRzIUG5Ogznds4UEML
         4qieZK/1r+O8TUYfe5JKRm79MIevCm/lXhe+u/7jwadJIFPY5dipvgvR9yZSg9IIxA+k
         ZEhP/KllHe8D9ASCeF8GykttslV2yr5ncv/xjyzRIaPuhCIN1VyIyEicak0C6bQZUSmN
         NSBCLupfAKd5OssPdCK4Z77u1si+DF0sGvUJRuP0OlNoUTYyUIzNJYIEqv9dyTKhf/S8
         URgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=Y3VvBlbUhu3YqvXbBjbA6d5CKuXewQIqX8FBJNqGnvg=;
        b=nAvTBltedY0RwrR9m+b891EBIUWYM/Cdw9PlIwNaepICz4zvGqmHNzE1eLXVCqdseH
         KhNezA11NEuBnifv+X124ZXA0VVbsBLW1KUDh5I3JBWw6BnkOHa+C/IbyEJyEp1Wan/H
         KpolFW3oSjiIMkYTRqIipFm9cySd9HVcmyzhfOuBKtzX0z9sStIZCyzAF6YoMEgHAyhU
         rxMxxxIIv0KQk3ZhH8k435L8bcbKA5kxLG4Et+k2Luo11R6NjUfiXDxst9rNFeXfNfKt
         pOvEiLpEOEvzzxWE3PNj7gAsJSA1nwqOueq5tEXl97iYl5UWyoZQnCom3kWsM7MXKIO1
         zruQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id r9si364834pls.4.2021.09.15.18.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 18:20:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4H8zgW1GwQz8yC3;
	Thu, 16 Sep 2021 09:16:23 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Thu, 16 Sep 2021 09:20:50 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Thu, 16 Sep 2021 09:20:49 +0800
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Marco Elver <elver@google.com>, <akpm@linux-foundation.org>
CC: <glider@google.com>, <dvyukov@google.com>, <jannh@google.com>,
	<mark.rutland@arm.com>, <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <hdanton@sina.com>
References: <20210421105132.3965998-1-elver@google.com>
 <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com>
Message-ID: <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
Date: Thu, 16 Sep 2021 09:20:49 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Hi Marco,

We found kfence_test will fails=C2=A0 on ARM64 with this patch with/without=
=C2=A0=20
CONFIG_DETECT_HUNG_TASK,

Any thought ?


On 2021/9/16 9:02, Kefeng Wang wrote:
>
> On 2021/4/21 18:51, Marco Elver wrote:
>> The allocation wait timeout was initially added because of warnings due
>> to CONFIG_DETECT_HUNG_TASK=3Dy [1]. While the 1 sec timeout is sufficien=
t
>> to resolve the warnings (given the hung task timeout must be 1 sec or
>> larger) it may cause unnecessary wake-ups if the system is idle.
>> [1]=20
>> https://lkml.kernel.org/r/CADYN=3D9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Q=
i5NAJiw@mail.gmail.com
>>
>> Fix it by computing the timeout duration in terms of the current
>> sysctl_hung_task_timeout_secs value.
>>
>> Signed-off-by: Marco Elver <elver@google.com>
>> ---
>> =C2=A0 mm/kfence/core.c | 12 +++++++++++-
>> =C2=A0 1 file changed, 11 insertions(+), 1 deletion(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 235d726f88bc..9742649f3f88 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -20,6 +20,7 @@
>> =C2=A0 #include <linux/moduleparam.h>
>> =C2=A0 #include <linux/random.h>
>> =C2=A0 #include <linux/rcupdate.h>
>> +#include <linux/sched/sysctl.h>
>> =C2=A0 #include <linux/seq_file.h>
>> =C2=A0 #include <linux/slab.h>
>> =C2=A0 #include <linux/spinlock.h>
>> @@ -621,7 +622,16 @@ static void toggle_allocation_gate(struct=20
>> work_struct *work)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Enable static key, and await allocatio=
n to happen. */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static_branch_enable(&kfence_allocation_k=
ey);
>> =C2=A0 -=C2=A0=C2=A0=C2=A0 wait_event_timeout(allocation_wait,=20
>> atomic_read(&kfence_allocation_gate), HZ);
>> +=C2=A0=C2=A0=C2=A0 if (sysctl_hung_task_timeout_secs) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * During low activity =
with no allocations we might wait a
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * while; let's avoid t=
he hung task warning.
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 wait_event_timeout(allocatio=
n_wait,=20
>> atomic_read(&kfence_allocation_gate),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 sysctl_hung_task_timeout_secs * HZ =
/ 2);
>> +=C2=A0=C2=A0=C2=A0 } else {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 wait_event(allocation_wait,=
=20
>> atomic_read(&kfence_allocation_gate));
>> +=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Disable static key and reset ti=
mer. */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static_branch_disable(&kfence_allocation_=
key);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/abd74d5a-1236-4f0e-c123-a41e56e22391%40huawei.com.
