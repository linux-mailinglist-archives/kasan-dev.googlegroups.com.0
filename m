Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUFN5HVQKGQE65T4KCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 55E8CB112C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 16:31:45 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id q3sf5522260lfc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 07:31:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568298704; cv=pass;
        d=google.com; s=arc-20160816;
        b=M0Cx93OMTxC9HBB7w5plcDoBBKBKc3DhsFIzcjz9iSKdJwfRswMc1xvVwmFgqo4Cmy
         N3LVVm+zSbVL8MgUdpDO/9AtNNFZ3zHVHSj68kJTjzSns7n39P8PoWOnmEIEQ19k8kRA
         ai8GYK6oswI5K1MQMicUcwNAKITeoyq8f7Iy4ld9nQO+EEyAQ1w0DYbtabYL0ugU1yBl
         KMSL+39GXE3JerHOsJ/UdQZeQ4J3SAWFrTPnUpfmgf7uwM71MulgRCRsEnymZC1jvC1j
         8N+AQStwRwzYJMEt+6vRS9IrhkEteNgC9bftgOajkxaMD1YzWyIsbu8tLSKluDPl3p5F
         +J5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=hp4huMI/gxHbUPCNh2vopmtnvBBMDA8oZSrTjB9F2E0=;
        b=J5f8vM0B+yo0CEWUyLXadrRbR7tNO6UOPLV0go8tgWkzAaJoQPtt0U0s1ZQCauur8k
         AeWRc+FBSt+JBzU6f8FkLa/uiZpUq3jj6h4KRrXjLPt+UoFKMggq8smWYrz2giN5Wyfu
         N4FIp4B1cZJGOJ4n1isbkAgdFjwoDvSHm0290O/Sf+0PoCjd+/nfwNrKXciow8DVtegl
         A2tw2dhbOjKHHYcaOGBQ8OIoU8IV5K6WNiJGtcfHbPUXyaJ1qPNt9D5n7vCvJN3k5PSV
         WayR3kecHSA5LoINNpR5zmen0JwKK3S4jIy2y7bzVXyRKZZ1y1D+3pQdWq8uLExL9o29
         LEuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hp4huMI/gxHbUPCNh2vopmtnvBBMDA8oZSrTjB9F2E0=;
        b=RbgCD+NAlQXKrQMKSnsH2X0z53n1t+PG99fYVNzcXLu/ZbiFiieX2ZuzpyD1be8Db+
         N0L+WZVjUxTJHXdF3tX1baGFKznNleQDNyyF56fAezHKZHBcdAY8d1ukJIgM5WClfcO9
         0eRoItEB25XfIy48vUw5DD978klIJ+cbPlpIbLjwf2AamZsp07h8QSN7rVEAAW0i7Pom
         v1skRCdYiqSxFcJE0jmfY0zzgRnCNKhh/2NSUVQzEOge82XYJqD+O/H4XBvxRiv4hHJi
         yIR+WMCR7dQXXDlPW1KgIg0oKpJjD+Y6pmZeWbzoxcVXZKZHYBLpiPOzNfFHcuJgZVBD
         H53w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hp4huMI/gxHbUPCNh2vopmtnvBBMDA8oZSrTjB9F2E0=;
        b=NxvBHKy3utFZe6SSy8j0Sy9blLpJIWqQSAiuw/SO/OVPVc+B581vfNBtnyFTdQFs6B
         4+lawOpltymiGOL3PYuQoUC5VN5UyXQ7kWKd+xOwzlB58eGkTjEqzv59YckkFBperQc9
         iNdfVl41ZFGGN/73FtfDLxuiwAFsTZGAtXPXefF1fX7VW8JDOFrfCTqUrxkJIsd4fplV
         vLHoGHxl6qHo630Cs4kYGlPIuQOj85fhYWK4BYiVcpij2MI0SY95SU5cvfZ00/x3vSw/
         ebokVmHkumcG0MAsSHC1Ile1BfT0wFboCN7agmVzTP7UrBwRRbgxPOF8ob/QRoU2FGvU
         mCYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXPC1i3hkOR8uX6dlnwy8MYZM78P6RpEz4Hr9llxigRiJBEO9R6
	YREBn9UPGpyI9VjMM0d5Nw0=
X-Google-Smtp-Source: APXvYqxx5XVszrba8eLx/Fs5N8evMEh0SpgGe9uolz02sYCO5gqJwSgpBRqVSPr1CNCeRmBwkI60Sw==
X-Received: by 2002:ac2:5a19:: with SMTP id q25mr5019588lfn.178.1568298704878;
        Thu, 12 Sep 2019 07:31:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3502:: with SMTP id z2ls3044390ljz.7.gmail; Thu, 12 Sep
 2019 07:31:44 -0700 (PDT)
X-Received: by 2002:a2e:551:: with SMTP id 78mr27239517ljf.48.1568298704235;
        Thu, 12 Sep 2019 07:31:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568298704; cv=none;
        d=google.com; s=arc-20160816;
        b=pFm/EXCWmZL0RkaMhnHuxV22ly8n/z77GFB62O4/TG4Slt/U/AX8kSCUcBtgrFWvb6
         0OI+cQcsehVJFgmL0WLU6mZd4z3DGr+GF6zwn2dM1kMD8jwGySFnYXMQv4LjvW+LcEN1
         BwBPoQ2koaqVjbAis7cjeAJ4fwJxs/oqALgWkVdAwGTvcGw5z6cMQsIGiNetdGs/JPlX
         0xrF9t0lrg3TFYZk8P4N+ZGj2K+eEmdPHWb1XDIAQutRRFrbT3IEd8F56RO47fE0w4Ja
         xee7IB9mXpXIbmhQ8yy0w4wE7LaC1agKFcvZwCfsVhwyxzrQxkj+lH5Gphbx7JFe79g3
         T7Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=qCGzGglAEEQOOYCVDQldaZkHXNa1qIvCBD033Zjl6YQ=;
        b=MiMF4NOeIpdLHLcz6IHUg6s3HR0MdBgkHfM28JaVry/51z+rEsM+k/7fsWBRQ7v/iF
         US9K2yC79xUZf2br8dsp3hmBJNy9VnmABTFYDukBekxnnMUi4c2Hlsq/MxRXq+AzCSW7
         G16OXFtFSJLw8SuZAV4BXne0GZGWPqbtYHK/GHUJ/wWBNb7xRZi/kqWcQEzuoNPuB7QM
         wgtiH3q4fHfjwV+t3cdr8u2sLtHxtoFFdIa7g3NHcPDBrQRn/TinL2cjfiEiHZyRu1Ur
         7JuHrd8Wni8yJMAuZl0xsPuFrHX/zoyHNpChyffWT1Jib5v8kML8H+Krpx1Dxr08SFLi
         FD5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id u24si517444lfg.2.2019.09.12.07.31.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Sep 2019 07:31:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id F35A4AFFE;
	Thu, 12 Sep 2019 14:31:42 +0000 (UTC)
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
 <1568297308.19040.5.camel@mtksdccf07>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
Date: Thu, 12 Sep 2019 16:31:42 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1568297308.19040.5.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"; format=flowed
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

On 9/12/19 4:08 PM, Walter Wu wrote:
> 
>>   extern void __reset_page_owner(struct page *page, unsigned int order);
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index 6c9682ce0254..dc560c7562e8 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -41,6 +41,8 @@ config KASAN_GENERIC
>>   	select SLUB_DEBUG if SLUB
>>   	select CONSTRUCTORS
>>   	select STACKDEPOT
>> +	select PAGE_OWNER
>> +	select PAGE_OWNER_FREE_STACK
>>   	help
>>   	  Enables generic KASAN mode.
>>   	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
>> @@ -63,6 +65,8 @@ config KASAN_SW_TAGS
>>   	select SLUB_DEBUG if SLUB
>>   	select CONSTRUCTORS
>>   	select STACKDEPOT
>> +	select PAGE_OWNER
>> +	select PAGE_OWNER_FREE_STACK
>>   	help
> 
> What is the difference between PAGE_OWNER+PAGE_OWNER_FREE_STACK and
> DEBUG_PAGEALLOC?

Same memory usage, but debug_pagealloc means also extra checks and 
restricting memory access to freed pages to catch UAF.

> If you directly enable PAGE_OWNER+PAGE_OWNER_FREE_STACK
> PAGE_OWNER_FREE_STACK,don't you think low-memory device to want to use
> KASAN?

OK, so it should be optional? But I think it's enough to distinguish no 
PAGE_OWNER at all, and PAGE_OWNER+PAGE_OWNER_FREE_STACK together - I 
don't see much point in PAGE_OWNER only for this kind of debugging.

So how about this? KASAN wouldn't select PAGE_OWNER* but it would be 
recommended in the help+docs. When PAGE_OWNER and KASAN are selected by 
user, PAGE_OWNER_FREE_STACK gets also selected, and both will be also 
runtime enabled without explicit page_owner=on.
I mostly want to avoid another boot-time option for enabling 
PAGE_OWNER_FREE_STACK.
Would that be enough flexibility for low-memory devices vs full-fledged 
debugging?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/613f9f23-c7f0-871f-fe13-930c35ef3105%40suse.cz.
