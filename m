Return-Path: <kasan-dev+bncBC32535MUICBBI6VUKZQMGQEJHTC4BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id EE960904530
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 21:51:00 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-df7a6530373sf380899276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 12:51:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718135459; cv=pass;
        d=google.com; s=arc-20160816;
        b=AiFj1ZUA55oqylZbxGMe03rVhcZEe3wTRQo7535Lsifl0/JwtAyCc+8wwZ7J8XwkKd
         5DRmx1WCiqL5d1ENbt5F/gm1yxXcJoUatOnplFB0Fp9MTq4jmsddwtnuMVPZUrhYVkag
         UiFaidP+6/DgDtvui3/eI+PT8Oa4r+3REWFl95NfpBaYYA5Br2q7LpTLlA5uL5QPhs5P
         ktOAjOJ5soNkrW2Rax7/9TfC/U1mxhW6y0icaCpAH61QUPvV+g6BUHbDfcXpW9zzvPOd
         mV/Remx04NUJY1DIel1aActlKlNnJZ41fsz650fqE2swRtsETodsh/G080X0xinP3Fxm
         NOgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=jV3uTRB5PwGjryApAtIRPlRqblueX9pWcVYMk9J0SwU=;
        fh=vbMLi9T/8KWZi5Pe2sYPqEuFLmLTuI9Swt//PciXWko=;
        b=so3KEkPXxIVH97v5n9IUQ4lKGulKF/0G4b8GUuMfi96G+F5EaZ3kg1upzjHgrGFf+3
         F39JEQM+gogj6fdx5kscL873GvzedW01ylr7Xb5FpRj1dm0tTSMcbgn1IRTTq0fStgwW
         GhSN1cYXLWoBUd1E43np8ayD2OwX2JzU9mmSaHRtlOQIsF7Zq9Uox4MgoB+N40okTpEI
         vxzZwYztuyiha+yREJxc2xvv7KUcPirVQsL3f0vvuwSipkPYKQcbeCRYw+A3KopXbNAc
         78sXkWqB3MTY7o3nYSenaQoFGWlqPgUq05ZFen3VRD8kIde/NJaS7I0omOweZ9UCq+wp
         LZ2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=D2u31ezr;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718135459; x=1718740259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jV3uTRB5PwGjryApAtIRPlRqblueX9pWcVYMk9J0SwU=;
        b=LbArqYlBsTb4UnS36QTozxzuOjxeacYx0tyAUD/XaK9+sIlSYj6jF7FPAMLi9OkEDe
         xg/NvuCOQjw2rBqUjjcQ5HZ38rSOoVX5D0UZC+ye7197kAAnkPPjNSBYa1rI00VPlL+s
         TS8r2JIpT6uHsDNcb4r31dtsL9K/X8CaOYJ1hEx2WNV/4y8q6x3xlClyd0zKeFtCc0p7
         AxNhVeQRmRAMLNTDJKYkE+RgUjiMecIjqJIjlTp3slZeh3EsVnSmI5gU9B/wxOEh8JR+
         h0g3cenU1Bkgm8JaM0inxvDSm4VV/+XDbLmv1XS7I4vFiNpNlcnbcOLM0qkA11vkuAej
         8JLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718135459; x=1718740259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jV3uTRB5PwGjryApAtIRPlRqblueX9pWcVYMk9J0SwU=;
        b=ZFZxCfURoD7eF9MMOPROR0axphomvcSUMD9YuCOgR6VgG+LuILrX8fVkS4MhMKM39f
         xVe/a6s7vBvVMJUaky54ZlkiAvL9gyk4qyN58Z6/U/cQK7ObNr8lilYeUr/VWSyt7xtR
         NduvN7ndMTXPn3dUBN42e2s4OEqM0SnropSDoDPXzftTRrxN2dIT6l+Q71GSbttYofse
         GSE4V2C7Ak8nlSSrkWCV2FvMegccgmDcai3pKvHfPQKXk8Rs+t197ySJ5Fh2g+yfPd0g
         87/TK4Occl5p1nULdNtS0AJtz4XfTSBO1DGdvKCInAjOF5HOwGLVlKCqyLp7S0veiQOd
         +zuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVfcg4njUz7cUikTRgPCvDaPk3Xol+2/0cKW/YrHAr9F9DHgsH+rUXqng/KGKNJ/O0EAcbCvTNM8JZvumym2Fp/J8tyaZSnw==
X-Gm-Message-State: AOJu0Yz+bpViBTLYJXartRlK0ceBsJi96BEcvQk+Dxyb3aNO6jnY1Ttd
	yNT+hT8d8Mz337mno3F9KdGEr9r4zWArwEuLDqg/cHeVRGDXQ6s1
X-Google-Smtp-Source: AGHT+IGPvIKAtzuyE+kJDEpxp1+YOIVYyB7xK1JogSqiQmN/8Hr+qG+MaYQ497JTgPGg977PPfAAHA==
X-Received: by 2002:a25:2b8a:0:b0:dc2:2f3f:2148 with SMTP id 3f1490d57ef6-dfd9fe91b33mr2103404276.29.1718135459480;
        Tue, 11 Jun 2024 12:50:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6b48:0:b0:df7:71d2:bccb with SMTP id 3f1490d57ef6-dfaf1659c71ls4283783276.1.-pod-prod-00-us;
 Tue, 11 Jun 2024 12:50:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7bkhyRd11l75UzDll76RKpws8JHe9Z1nLK7hYz3bWjHMI4RM0AZ+CXPied/kfdCOiyCJ7Ox35uL1d3PDAPySP30DpbZLJWiY3+g==
X-Received: by 2002:a81:be07:0:b0:62c:ffb9:bb87 with SMTP id 00721157ae682-62f1b5c98a7mr14435427b3.4.1718135458527;
        Tue, 11 Jun 2024 12:50:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718135458; cv=none;
        d=google.com; s=arc-20160816;
        b=SytbXr78XmwwA8+aprqRmIKvVCxJKBPH9zBTLOVUptWFn+vrYTBIRSfPPzTqPH1Z9p
         DnlnCWKdnOrQaR1AU2egcltTlUwZajRAddg+ahuJiCq6WrwBBW1l0FfEWek75R8EvCvJ
         V7JMAk6fiDWyIvmaLfBH+uIIfEKVko73PoBn05PaxpfNEOaCBMBTeG66wgkfSaWZNl+8
         Jv1PTdqLzDaAWbYtN5p7kvuRFAtb5NlyRmUT7cZCFtIPQFEsdw48aztnmzHqK60E2EjB
         lt5QZkPWimj9/IDrJSQQf+QDax4AVdJbpnG+R/iMLnP27wAHwwJWE7K7K6/XjWIe9x9L
         t9EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=VC/FKQpyiv8QuT0prkiboQ+mv2U8+abllOC5cV7bqrg=;
        fh=guVd3Qy42pSezhepvpUqxY/6nJAC10x4Y1G6Su4XM+k=;
        b=qbUjsfV1MeewILasdJfMB+jdLC0kdZrc7zkmN9Sc64IggGXguhGk+Pj5MOLoGc0Qsu
         7m97LnLhUpNDJoxI8OFm+L7p19/RpFM7sAu9hH909TNEpAsCerDXVtcucceuYOjmSB4z
         i9wHwR6/wZfIMe7IunfyIIZcXPAn2SWW9GGWDKGUuNZizDgx2qEleRZF7Bzb6M2y6ZNO
         wB54sB12A+wCADfcaKZVQWVXDHNoz1hSw9teFqJpHrh7dOhWZ3ArVrdfzSIgegDQpT70
         zPEQTW0JrYG0wUsdIBc6TgFhKuxEYUlYQKdf6/W7u2CcIYy6q+Z37leIFVH1SC+mcQ+v
         55pA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=D2u31ezr;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-62f1d9b6e3csi1147677b3.4.2024.06.11.12.50.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 12:50:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-33-8gRTYUeyME-bYBqyOGSTvQ-1; Tue, 11 Jun 2024 15:50:56 -0400
X-MC-Unique: 8gRTYUeyME-bYBqyOGSTvQ-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-421e17ae038so18629105e9.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 12:50:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJ1mV8Y+saBt4im/yyKc4F68+gK9DKwaN7ony0iv+LwsMMdxzC2Se/SwoFy8bFGPVKU2Ec7byglVdC7zMJQFENuRpqaoXz5uaBtQ==
X-Received: by 2002:a05:600c:1c91:b0:421:8028:a507 with SMTP id 5b1f17b1804b1-4218028a5f6mr70330535e9.18.1718135455374;
        Tue, 11 Jun 2024 12:50:55 -0700 (PDT)
X-Received: by 2002:a05:600c:1c91:b0:421:8028:a507 with SMTP id 5b1f17b1804b1-4218028a5f6mr70330165e9.18.1718135454911;
        Tue, 11 Jun 2024 12:50:54 -0700 (PDT)
Received: from ?IPV6:2003:cb:c748:ba00:1c00:48ea:7b5a:c12b? (p200300cbc748ba001c0048ea7b5ac12b.dip0.t-ipconnect.de. [2003:cb:c748:ba00:1c00:48ea:7b5a:c12b])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42274379b83sm16254225e9.28.2024.06.11.12.50.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 12:50:54 -0700 (PDT)
Message-ID: <fff6e4d3-4a11-4481-b28c-edfb072daf35@redhat.com>
Date: Tue, 11 Jun 2024 21:50:52 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
To: Tim Chen <tim.c.chen@linux.intel.com>, linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org, linux-hyperv@vger.kernel.org,
 virtualization@lists.linux.dev, xen-devel@lists.xenproject.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Mike Rapoport <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
 <80532f73e52e2c21fdc9aac7bce24aefb76d11b0.camel@linux.intel.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <80532f73e52e2c21fdc9aac7bce24aefb76d11b0.camel@linux.intel.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=D2u31ezr;
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

On 11.06.24 21:41, Tim Chen wrote:
> On Fri, 2024-06-07 at 11:09 +0200, David Hildenbrand wrote:
>> In preparation for further changes, let's teach __free_pages_core()
>> about the differences of memory hotplug handling.
>>
>> Move the memory hotplug specific handling from generic_online_page() to
>> __free_pages_core(), use adjust_managed_page_count() on the memory
>> hotplug path, and spell out why memory freed via memblock
>> cannot currently use adjust_managed_page_count().
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   mm/internal.h       |  3 ++-
>>   mm/kmsan/init.c     |  2 +-
>>   mm/memory_hotplug.c |  9 +--------
>>   mm/mm_init.c        |  4 ++--
>>   mm/page_alloc.c     | 17 +++++++++++++++--
>>   5 files changed, 21 insertions(+), 14 deletions(-)
>>
>> diff --git a/mm/internal.h b/mm/internal.h
>> index 12e95fdf61e90..3fdee779205ab 100644
>> --- a/mm/internal.h
>> +++ b/mm/internal.h
>> @@ -604,7 +604,8 @@ extern void __putback_isolated_page(struct page *page, unsigned int order,
>>   				    int mt);
>>   extern void memblock_free_pages(struct page *page, unsigned long pfn,
>>   					unsigned int order);
>> -extern void __free_pages_core(struct page *page, unsigned int order);
>> +extern void __free_pages_core(struct page *page, unsigned int order,
>> +		enum meminit_context);
> 
> Shouldn't the above be
> 		enum meminit_context context);

Although C allows parameters without names in declarations, this was 
unintended.

Thanks!

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fff6e4d3-4a11-4481-b28c-edfb072daf35%40redhat.com.
