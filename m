Return-Path: <kasan-dev+bncBD5NPEPNXUNRBY7EXKPAMGQEZUSCVKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 071DB678117
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 17:14:28 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id f11-20020a056402354b00b0049e18f0076dsf8803841edd.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 08:14:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674490467; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGyWzU6sOnPx5j0f+hhUVsrY3nfwRYBhs917JH87zctjP7zvV+wbKK5kV3fYfqE/+e
         yRRJ2E+0KGRDiWZOf2wdCAQwvALbBSqK2VpfRkSJJ5VFIqWegskzTrPLOYJmHmIMojfm
         nJN6HULH6kbn4OIf2tL1DjHBCyIEPjZX4v961ueRW4uYlWM+n/IbqALwFQRo2D8ieuUY
         nEnO/gVSGhEPoFPT4HHTeVGky+wg4TkPzQYlM7tY1xAZSzmROcwPnEDZTM/0XTnj2RSy
         hTc2bhWQggMbsIry4MMpfwEqEpeFxXxpKVbNTmpS2o6Ji9XnTYUPqjTZn3/qKlTSafXc
         Byrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:to:subject:cc:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=gkvbIBA+kWrxeBInV2hJTO0byEuO8HbYiBg+Q1moDQI=;
        b=Ei/Ru7q4njAqiMKXVwMnzqkFPB96oMDFUbEasRQfqFCGR2bXJ7v8cgYRebtUXjCH6I
         nIs/jNpC8D9JOK3yTA3fsuneSWucBDbfvpQeMinNn+JkbDugirEMo68nRMyicB43q4KR
         vnsptWO7SqvjM3h+/qIWagFidgct4ctoK8biwW+vfFBgGe/uuLOYHJVPffhipRM0pyQt
         K4u6HcritO5NQe8i9lsP6O1JOVkVLeDvZI5o85BttSs6zMP+QUiEZtwcyLR1H8Dfq5Mz
         tQ/4cBb/lURz9opg1qRqr8Dscvjgs7LNgQvEwp9f+oeYtx6jIZ9yHbNzPgn7fNvPmqAY
         Bbfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cCMi4MLW;
       spf=pass (google.com: domain of jbrouer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jbrouer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:to
         :subject:cc:user-agent:mime-version:date:message-id:from:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=gkvbIBA+kWrxeBInV2hJTO0byEuO8HbYiBg+Q1moDQI=;
        b=Yg5+BNMcTmbUKFxwrFrYDk9xi6zdEKBWrPaslfm1DlM1RXZnLw1SyRuYOe4t9GNX0e
         B4KKOMY396SLrb5DeqKE/FoaUaZBYeJv9il39kfl3bRXvSeEG62OHSKjAT400ohwWp1x
         6rFZLd5heZUSNgTWJz16Nm7Mf/nZp8eEVN8SFsAOMRFmh11o/+tvO+CFd+1AWQu2SPm/
         bxL0suE1kRguU49g0qmypsIpBv+rMYYmXCKCFm9uuMoBHuJpQ8PVEneAN4Tj4MioBeyE
         bkvK8pvrh+uLuKnKTpQSkd1yq8q2eEZI03tAqSWyYW2W7rxdQyBtJLqlCDg24xXAUY3e
         0QUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:to:subject:cc:user-agent
         :mime-version:date:message-id:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gkvbIBA+kWrxeBInV2hJTO0byEuO8HbYiBg+Q1moDQI=;
        b=CasFlDiGAEISkttMtlMHFd2A3Ry1im6SqxtzQdFv98nga8rbuGgNJhgiIgDR7mpKKl
         BcgYFO2RXa2R3+hh3hsnjh4hyibX1aO5E+Y6LCd6jeYxQ7jrS/5m8jRdZStIOLfWbJCu
         mWFxfaFlZLRhrh5/m5eiaQaHpQB4uSU+f4v9ATD+uB5SGejrMNPuaakxJ0j4HXUgXTMf
         B4Et99PuxS1ZsHIKNjdJ2NWSYottfMsv+TbMycJuWnvqXQNVX0U55bGgkRgUL4XUx6IC
         43jUO8BcW5w0P3uxM7zXUqmEd+B6svQ3osh5rztk1/J1pfbgyf3pXcUutEG1F4gjS7Sd
         /nQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krQfNOp2YsmohD1iQ6pHzRouEaHhurp4jZUf4cVtr8+he2Fw5c4
	2kumoFvfYwa4ZhpAS61kOb8=
X-Google-Smtp-Source: AMrXdXu+i1Pq3NrwBylUS+uUKDI1vLn/RESvUfzVDEhknxeiwQ/bHxQvzg0zAkNTFeYl/UN/WcVGqQ==
X-Received: by 2002:a17:906:1be1:b0:870:159f:c518 with SMTP id t1-20020a1709061be100b00870159fc518mr3235627ejg.95.1674490467542;
        Mon, 23 Jan 2023 08:14:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:430d:b0:43d:b3c4:cd21 with SMTP id
 m13-20020a056402430d00b0043db3c4cd21ls10867831edc.2.-pod-prod-gmail; Mon, 23
 Jan 2023 08:14:26 -0800 (PST)
X-Received: by 2002:aa7:c44d:0:b0:46c:b919:997f with SMTP id n13-20020aa7c44d000000b0046cb919997fmr17000580edr.17.1674490466518;
        Mon, 23 Jan 2023 08:14:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674490466; cv=none;
        d=google.com; s=arc-20160816;
        b=KPxL4qRrT9cSlm/jn0DEfRd6W6RJ9LAvAMkaxl8ooqm5sxbgZ6n5pd++Uv8lWQsmBW
         W0zjQcw6t6bJmth4uBpM48OvcSJ4B1b3io7FeWMy1cQ68zmiPpqjGJW6NYHVk2se4mrJ
         nz1INpfphrJ4KgJrfdRb7aHeXIs7Sgxk+X4RWE0DBXYiI9nwJiZTqb1frlTnWzY2xPyP
         bHkCPdr977yX8e2uvNcjm4uOZVcNYAtGr92WpfV/Dxhx6poy2ClUGYqyyMlnGHMHIXF7
         rsMpYpz0oVRF1DXGO+tUE9TeKGlT6kWNgHIpXIclE7ZQ0msyMrHntLVEMUCX9I/Yx1KJ
         rb8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :to:subject:cc:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=Hf49zbFN3KLWLBk8hS5GvALY3WWpLu7tA32Veqwn+JY=;
        b=s6pqBR4WRTcN5H0OT7A+sXjh1LtgR8cOHeKkSeEUk5Ldq27PyN3t5tMAmzXQJ63jk/
         K64V+32BfT+WwKhxvgGWg8Ad1egORbxQf8Dzt/JyWAzNIL2evX9h3tyE4zAzBldYi5dm
         8tnLjP6bPip+BBpb0/MNIm+TKDsbkYYjmiPff9pCbQ+qYV6DzkN8h0fZmstv+YghOOdw
         OLUhyt7xdiCOl1xMW54WrdF9U8Nqe8ormIuuJtEGy4rUKCvVF7WgjOdSFZrST51q8C8O
         ccWi8yw0bjXCzZb0/A0/2CemLDA1zGUAtN8RJUkIfre07DxlUM/F1wUXzWyMfTxo39zn
         yYrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cCMi4MLW;
       spf=pass (google.com: domain of jbrouer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jbrouer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id s1-20020aa7d781000000b0046c3ce626bdsi2001021edq.2.2023.01.23.08.14.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 08:14:26 -0800 (PST)
Received-SPF: pass (google.com: domain of jbrouer@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-ej1-f71.google.com (mail-ej1-f71.google.com
 [209.85.218.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-344-GFDoZ6tPPRaniD6iSArpZQ-1; Mon, 23 Jan 2023 11:14:24 -0500
X-MC-Unique: GFDoZ6tPPRaniD6iSArpZQ-1
Received: by mail-ej1-f71.google.com with SMTP id hc30-20020a170907169e00b0086d90ee8b17so8092893ejc.10
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 08:14:24 -0800 (PST)
X-Received: by 2002:a17:907:6a98:b0:855:2c8e:ad52 with SMTP id ri24-20020a1709076a9800b008552c8ead52mr17843927ejc.29.1674490463169;
        Mon, 23 Jan 2023 08:14:23 -0800 (PST)
X-Received: by 2002:a17:907:6a98:b0:855:2c8e:ad52 with SMTP id ri24-20020a1709076a9800b008552c8ead52mr17843911ejc.29.1674490462981;
        Mon, 23 Jan 2023 08:14:22 -0800 (PST)
Received: from [192.168.42.222] (nat-cgn9-185-107-15-52.static.kviknet.net. [185.107.15.52])
        by smtp.gmail.com with ESMTPSA id sa14-20020a170906edae00b008639ddec882sm16028604ejb.56.2023.01.23.08.14.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 08:14:22 -0800 (PST)
From: Jesper Dangaard Brouer <jbrouer@redhat.com>
Message-ID: <93665604-5420-be5d-2104-17850288b955@redhat.com>
Date: Mon, 23 Jan 2023 17:14:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Cc: brouer@redhat.com, Christoph Lameter <cl@linux.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Mel Gorman <mgorman@techsingularity.net>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, penberg@kernel.org,
 Jakub Kicinski <kuba@kernel.org>, "David S. Miller" <davem@davemloft.net>,
 edumazet@google.com, pabeni@redhat.com, David Rientjes
 <rientjes@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Matthew Wilcox <willy@infradead.org>
Subject: Re: [PATCH RFC] mm+net: allow to set kmem_cache create flag for
 SLAB_NEVER_MERGE
To: Vlastimil Babka <vbabka@suse.cz>, netdev@vger.kernel.org,
 linux-mm@kvack.org
References: <167396280045.539803.7540459812377220500.stgit@firesoul>
 <bfe4ff8f-0244-739d-3dfa-60101c8bf6b8@suse.cz>
In-Reply-To: <bfe4ff8f-0244-739d-3dfa-60101c8bf6b8@suse.cz>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: jbrouer@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cCMi4MLW;
       spf=pass (google.com: domain of jbrouer@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jbrouer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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



On 18/01/2023 08.36, Vlastimil Babka wrote:
> On 1/17/23 14:40, Jesper Dangaard Brouer wrote:
>> Allow API users of kmem_cache_create to specify that they don't want
>> any slab merge or aliasing (with similar sized objects). Use this in
>> network stack and kfence_test.
>>
>> The SKB (sk_buff) kmem_cache slab is critical for network performance.
>> Network stack uses kmem_cache_{alloc,free}_bulk APIs to gain
>> performance by amortising the alloc/free cost.
>>
>> For the bulk API to perform efficiently the slub fragmentation need to
>> be low. Especially for the SLUB allocator, the efficiency of bulk free
>> API depend on objects belonging to the same slab (page).
> 
> Incidentally, would you know if anyone still uses SLAB instead of SLUB
> because it would perform better for networking? IIRC in the past discussions
> networking was one of the reasons for SLAB to stay. We are looking again
> into the possibility of removing it, so it would be good to know if there
> are benchmarks where SLUB does worse so it can be looked into.
> 

I don't know of any users using SLAB for network performance reasons.
I've only been benchmarking with SLUB for a long time.
Anyone else on netdev?

Both SLUB and SLAB got the kmem_cache bulk API implemented.  This is
used today in network stack to squeeze extra performance for networking
for our SKB (sk_buff) metadata structure (that point to packet data).
Details: Networking cache upto 64 of these SKBs for RX-path NAPI-softirq
processing per CPU, which is repopulated with kmem_cache bulking API
(bulk alloc 16 and bulk free 32).

>> When running different network performance microbenchmarks, I started
>> to notice that performance was reduced (slightly) when machines had
>> longer uptimes. I believe the cause was 'skbuff_head_cache' got
>> aliased/merged into the general slub for 256 bytes sized objects (with
>> my kernel config, without CONFIG_HARDENED_USERCOPY).
> 
> So did things improve with SLAB_NEVER_MERGE?

Yes, but only the stability of the results.

The performance tests were microbenchmarks and as Christoph points out
there might be gains from more partial slabs when there are more
fragmentation.  The "overload" microbench will always do maximum
bulking, while more real workloads might be satisfied from the partial
slabs.  I would need to do a broader range of benchmarks before I can
conclude if this is always a win.

>> For SKB kmem_cache network stack have reasons for not merging, but it
>> varies depending on kernel config (e.g. CONFIG_HARDENED_USERCOPY).
>> We want to explicitly set SLAB_NEVER_MERGE for this kmem_cache.
>>

In most distro kernels configs SKB kmem_cache will already not get
merged / aliased.  I was just trying to make this consistent.

>> Signed-off-by: Jesper Dangaard Brouer <brouer@redhat.com>
>> ---
>>   include/linux/slab.h    |    2 ++
>>   mm/kfence/kfence_test.c |    7 +++----
>>   mm/slab.h               |    5 +++--
>>   mm/slab_common.c        |    8 ++++----
>>   net/core/skbuff.c       |   13 ++++++++++++-
>>   5 files changed, 24 insertions(+), 11 deletions(-)
>>
>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>> index 45af70315a94..83a89ba7c4be 100644
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -138,6 +138,8 @@
>>   #define SLAB_SKIP_KFENCE	0
>>   #endif
>>   
>> +#define SLAB_NEVER_MERGE	((slab_flags_t __force)0x40000000U)
> 
> I think there should be an explanation what this does and when to consider
> it. We should discourage blind use / cargo cult / copy paste from elsewhere
> resulting in excessive proliferation of the flag.

I agree.

> - very specialized internal things like kfence? ok
> - prevent a bad user of another cache corrupt my cache due to merging? no,
> use slub_debug to find and fix the root cause

Agree, and the comment could point to the slub_debug trick.

> - performance concerns? only after proper evaluation, not prematurely
>

Yes, and I would need to do more perf eval myself ;-)
I don't have time atm, thus I'll not pursue this RFC patch anytime soon.

--Jesper

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93665604-5420-be5d-2104-17850288b955%40redhat.com.
