Return-Path: <kasan-dev+bncBC32535MUICBBKN6XKPAMGQEUFX3D3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id DAB89677E6F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 15:52:26 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id k7-20020a056e02156700b0030f025aeca3sf8422212ilu.12
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 06:52:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674485545; cv=pass;
        d=google.com; s=arc-20160816;
        b=jnxZov7mSzFPuWwp5P7cef4xCFOdmLOOipzNFYRK2oK/kqJjlm7Y5dzrEkrgsFZimm
         n8PPGCy+6qjBwaYbver0UWpzcOL1rKBBod8Kh6+8GUEu5bKT8X0KObhkzGcld6Ql/R3k
         r530U8wyqyVW+99PvWk5g0GiSfjkOIpqIYRwTWPN84sPFmHdjNGQOBycLxvbvjEohoAK
         IDo9kh6n76v1cK65I8ScOz1KjsPGmWIk+nW3CwHnV7XvBWx/E3sL4WnmK28ApaaexpHW
         qGN9hisw39ryYV8QnS6hyJb9iE6mdwkfa1+nAWPdsSSIlKTui1uSEKlUEvdtccv1hX3p
         9SxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=ieJ1RR/c679uvwUmRzzOJtgl1sKur09cDFRJAdDMfws=;
        b=T4LrBFKaLiRqseD4DEld9fYe8OcMydeeArQEh1aROOSbG15/W+U2lMHtr4MeDhRNH+
         4TcH2s05ECgRrac71coNOMHbXEVmvFjWMTGsJmDGaZEPGeFD7KUxqpDNxQRAmQKvnC74
         TZREEViZ2SahyxpGMb48DoztTu6QPOmrDBwUROdoitbtb4SBjZfY4kAG9L/kaS5S6zBV
         yz5yNMwdQ3LPmFtsuke89LrNUrQ/eT7/ksk71EFwSOphl9qHzWRubYGrtL4y/UAv9LfV
         bKoM9DYpFqWQWpfQftq9gpmgAyILBxUJVQ2AWrXtczq1B658tIK0qx9Uv4hwIWXtLgST
         eLnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=B0h1Jd34;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ieJ1RR/c679uvwUmRzzOJtgl1sKur09cDFRJAdDMfws=;
        b=ZVe93cRJKM/Rst3sBidw9jA1HpBmA+EMODkzP0BWqQWIVrEE50KCAeOq+PUMLa0aCU
         DCSMuMl1FzR7m4ucm/448d8yKqSGKsqGVtCthx5h/noG+KVuM4OE8DmAjHY1BXZofHgP
         k0vduvSPcL7umsdsEwWkQMbSzEl+rYGTTxfTMDkjkqdKBHew/ZSk/Ttk8tQzWQDPTwdT
         18ud7Qa75FV59bjZqaRS38Rz180/qCqZbtqyY5JHQBGQc/g3Pr9mSvlcd4nWYKL56euE
         YMhavTebHEeb3e2ELZ9rpB3xmKLeVAlLVdN40Fo0wnGERRK4D1twDkPJrHqB1HIPKeW+
         iitg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ieJ1RR/c679uvwUmRzzOJtgl1sKur09cDFRJAdDMfws=;
        b=YvUsAjcK2RNPYygKlpIfB0qqznaPbc4gjiSxHgZOgo4RZyxAPhcmSJPAXNNhYbR08m
         1Is7T+c8E0qUf1kdZ3q0nFIaZGKA/KeyuwmkyPZWTba+FfdXXEucsC6z52j3X5YKIwhY
         PKL8kY4IzEypvPa8bc25go/EEmY4Kute/rct/HUk61tpivlgc60TkPicaWDol+uKH+4W
         ODn51nmTgTr+W2nKRVcBgXBZ5aCBpJCISAdE8Wk6UwHu7A5TLCC1SKVUN9RaLqiv/Rd/
         bt/rfeo1GpUKZgQAV1a9Nk0X2Aur5bZtlTUnbpaDAh0d6sAGzqP4/OTYjkDB27psmCQK
         kVPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpkFOkFxDuX5Cx40YRBIL9M7x7OGRleBiNiowvKCHNnhK2SA/2h
	7mxqOn31Cu6ahDvRWeFARzA=
X-Google-Smtp-Source: AMrXdXstCIaH7lhtLQIWOEdamUvJonE1TdvCUpf7eOYcNBZwMXNQbeiXyaklW4I9JHrsoubuWJ1/jw==
X-Received: by 2002:a05:6602:2593:b0:704:cdff:6366 with SMTP id p19-20020a056602259300b00704cdff6366mr1881849ioo.160.1674485545482;
        Mon, 23 Jan 2023 06:52:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c5b0:0:b0:30c:27a9:a355 with SMTP id r16-20020a92c5b0000000b0030c27a9a355ls4049380ilt.3.-pod-prod-gmail;
 Mon, 23 Jan 2023 06:52:25 -0800 (PST)
X-Received: by 2002:a05:6e02:cc2:b0:303:608d:b34d with SMTP id c2-20020a056e020cc200b00303608db34dmr16781153ilj.18.1674485545032;
        Mon, 23 Jan 2023 06:52:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674485545; cv=none;
        d=google.com; s=arc-20160816;
        b=z/jigTifrKX3sFXl/Q5MHbI4u1DarSuwIkv/+zPMmiIM7eztexWUfrjyBw6EzvYauI
         iu74QhHYu/+fs6quqEkSgUA5chUX5Gy0fLqNd/mk1xn086sri+Q7Psg9vz7FuRKf4FqV
         ZhuSCiowNI36O74IKDkdxvG2Pr0QBpeWFq2f0KVDVWU4Ed+NqS/YRdH5GWM9rgtwCsIf
         zJscIGrYeIG4fbL/Wx9tCMOScf5I9l0uBwOCO+83Auce6GlB6lifW5AU43V0aTEzw5Tc
         E6mPk8fm+qhv9BykmYedRg5+Ey80A1sFv4m3kwNF1zkPZQwlBC3ZNkb/PpSirqIBdcq8
         0bYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=T03uo0w38ySOqZDIO4krSGr7PfEci5UnYfFK1tg2gBM=;
        b=mP33q3vIrKPsSnWU0lq5MtUEBor7G+D8ydFO5XmPnsvLHqzpugvSBw34ZRr/ALIO7t
         XFUQnh5+Yh8HbLAdSjoCj9PWbrq/Us33Ccidw+ww0fsopLXf9iQS5HYwQtkqgMMxlWmA
         wBo4BLyYGm2CSZI996wGTwIpzcZhENv49Dmy2zrLHBh1qeG/eV1eaS2WFmdJoxGjAV9h
         ccTdDdnlz+PbtYVWKBGJlSEq3V9rxz9OOf5hVPo4O193FdOi8Ft/NiT0YTMcTjbn2qHI
         nFyW5t0G8QOWbuEl5GOEkIQ2jxabqefuQA8V7A5snsqInCZfzvMij5SeSRJm368VsPMQ
         ENzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=B0h1Jd34;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id o5-20020a027405000000b003752c8d2694si2423609jac.5.2023.01.23.06.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 06:52:25 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-561-cwznOBPsPJ2B4FWxzWdJUQ-1; Mon, 23 Jan 2023 09:52:23 -0500
X-MC-Unique: cwznOBPsPJ2B4FWxzWdJUQ-1
Received: by mail-wm1-f71.google.com with SMTP id l23-20020a7bc457000000b003db0cb8e543so2959700wmi.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 06:52:23 -0800 (PST)
X-Received: by 2002:a05:600c:181a:b0:3d2:2043:9cbf with SMTP id n26-20020a05600c181a00b003d220439cbfmr24302087wmp.10.1674485542173;
        Mon, 23 Jan 2023 06:52:22 -0800 (PST)
X-Received: by 2002:a05:600c:181a:b0:3d2:2043:9cbf with SMTP id n26-20020a05600c181a00b003d220439cbfmr24302069wmp.10.1674485541943;
        Mon, 23 Jan 2023 06:52:21 -0800 (PST)
Received: from [192.168.3.108] (p5b0c6374.dip0.t-ipconnect.de. [91.12.99.116])
        by smtp.gmail.com with ESMTPSA id m18-20020a05600c4f5200b003cffd3c3d6csm11679776wmq.12.2023.01.23.06.52.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 06:52:21 -0800 (PST)
Message-ID: <0b2660ee-ce1d-caf6-7f81-9c1fb64b67b4@redhat.com>
Date: Mon, 23 Jan 2023 15:52:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 08/10] mm: move debug checks from __vunmap to
 remove_vm_area
To: Christoph Hellwig <hch@lst.de>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-9-hch@lst.de>
 <02bc3d67-3457-ff17-0810-e75555609873@redhat.com>
 <20230123145016.GA31543@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230123145016.GA31543@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=B0h1Jd34;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 23.01.23 15:50, Christoph Hellwig wrote:
> On Mon, Jan 23, 2023 at 11:43:31AM +0100, David Hildenbrand wrote:
>>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>>> index 97156eab6fe581..5b432508319a4f 100644
>>> --- a/mm/vmalloc.c
>>> +++ b/mm/vmalloc.c
>>> @@ -2588,11 +2588,20 @@ struct vm_struct *remove_vm_area(const void *addr)
>>>      	might_sleep();
>>>    +	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
>>> +			addr))
>>> +		return NULL;
>>
>> While at it, might want to use WARN_ONCE() instead.
> 
> One thing at a time.  But yes, this makes sense and could be an
> incremental patch.

Sure, there are some more !ONCE WARN calls hiding in that file.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0b2660ee-ce1d-caf6-7f81-9c1fb64b67b4%40redhat.com.
