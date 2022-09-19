Return-Path: <kasan-dev+bncBCPILY4NUAFBBWG7UGMQMGQEQN27RGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C2565BCD54
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 15:34:17 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id b28-20020ab05f9c000000b003b42433bfc7sf9283223uaj.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 06:34:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663594456; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVKdB/icGrtbtdV14j5iHNUaiQNT40PT1BM3H2pBAygE4D8FfKlYQe1R33z7fziNjN
         oskLnrxEr3c6dXC8cY819DxTw+UTQ0Q1uSjDsO4UA+BVEEtEAaPIyoo9N52Ss7VJwufW
         IqCS+RHbyowcwAPVvC6/LmGlmAjqr/X4fsUHSM5OQy84Y9m9ppNL7Uy4IlOmW+4v/s5V
         iIGK8xK3VYZ7wycCXsnWFWhaWGKWpHIyIjZ509R1HA4a1K3qpUHFkGmxBCkp229qgPmP
         ya9IMCUw9YimeBXQgzLaXBLuII8RreCDrGJ+7YZGJEgv0qNmPpJgvV6CqTe+5P9J/s+e
         VwjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=5YvwsK9xqz5oTeFhpD/aYDvnyncIqUKoqNFCpokZgvY=;
        b=OfW+Wjhmj/gH+7z7VgptWZ9dSRVMZJc/OjYgYqZbYZElreNSlBde0H7vU1hcB4dQZv
         pjfNiVyvHUP2yudMo9WiR5LTMvT78lJrA6i5AcpaUMtEe+G9NaCZYm7DHlLFe+4bbLQ4
         DRK4+ZayONXRgkSYxblLLycsU4PkwaZb8gjwv7t0xLSai2ZIGMY48ESmXOUj3XuHLdwQ
         r+5fTq6ew12N7+mCFo5pVNMulfN+TtzKD96wmIaZbRUlab3JaK1ipOLgqi9/MrJusnz6
         X0EEWhrkxqt2cOI9JolmZjnWhpfPY/40+BWtFDtWGRgPfX2+y8QsIKhE4R132IXxKxiR
         hXYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GeR2OXeF;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=5YvwsK9xqz5oTeFhpD/aYDvnyncIqUKoqNFCpokZgvY=;
        b=E4Iw1xfbLe+LSgGppzuKcuET0rG+/FMnam1+Ut/4n8w4VamBj8YOsLK9zSfY5luCGm
         1OtPmAsJB/Gna/z9wolMk2/PST+e5yiNbpE9nzIcQDgijrGJI9PpK9SPlgs0g+OZ7DoB
         kUhQXkuH7mZX5GoCUpN05iPdeUot8s50oa3F718nqPufY3Rjlx5Qt3HxPxBjytXXSal2
         13eKRCU5gt98lY+nSxtski2T5mFvwyQvLGKAzvRW1qghPkq1G+pt6OOXsUxTbMo44WDt
         delTiBrVUN7TJma16L9SWAmdwjtjJhP/oGK4DG6B+1s3XKar7h1gHbwkVpWy5Iyu0QL2
         WLFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=5YvwsK9xqz5oTeFhpD/aYDvnyncIqUKoqNFCpokZgvY=;
        b=i8hI7JkUdPTSS7Gu660kFE11hiSyLV8oI9+4isKhHxcbRose7oJNMOMOlXco1315E0
         NLqEW1xwHsMinO5BiOmHBhodW3oYpG9qDYg2YnDNFC9adr9l75ogLkGhGuEwENAf5RFp
         oDpjPuMdnVzL2UjtupXGHh5gOvZB3V3TJZivWEV9aLXjKBRx5efFRKaSowuU7AQRkMB2
         B/C2C2MolB3TXwwQjKfjvZ50wVl60qZQPKZl5+xAyDSbuflKxFT2T3AD/rQD6s0d6r8R
         1WL+hiJYDFOGRmsb3nLlRCmE4t7Gx4x/wISDATnCxdGTXG+ztLVNhdYtvaNvwaKrFuNm
         olMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3k7hQxPIDL56f898cvUvewAdxqEvp6Li2zDrhDBPUr858TdFln
	SSj69mkyq++w2iXgUNgica4=
X-Google-Smtp-Source: AMsMyM7kPV3B8Wmw9AH+0n33hOQaRe2Rd5MvbpytevkemkuMMEptUlFLwqf4X3Ng9guvVgYyuJt0Xg==
X-Received: by 2002:a05:6102:2908:b0:398:ac40:d352 with SMTP id cz8-20020a056102290800b00398ac40d352mr5268208vsb.55.1663594456370;
        Mon, 19 Sep 2022 06:34:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e01a:0:b0:397:63a3:3998 with SMTP id c26-20020a67e01a000000b0039763a33998ls867267vsl.7.-pod-prod-gmail;
 Mon, 19 Sep 2022 06:34:15 -0700 (PDT)
X-Received: by 2002:a67:f684:0:b0:392:ac17:f9b0 with SMTP id n4-20020a67f684000000b00392ac17f9b0mr6258236vso.85.1663594455817;
        Mon, 19 Sep 2022 06:34:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663594455; cv=none;
        d=google.com; s=arc-20160816;
        b=uAIP9DbQY1fkw88Nkjm++mftClt6lhTYZyZa0JDBidlvYgvMFMQZt84hpsC8Euxv8A
         LF1bn0ME87VwSb9NoRzlmef2Ygyx3FObtYQiTi5PjfKwz2JoVQxLplYAyj1gNKaaJME2
         D3if8B+IeamgQpZUa0CKbvj40+sUsorzw/fwjG63Y1bs3Wiv+oRPKVNxWjnLTwb10FQJ
         ALmZiVvQgOjkm6szpCRf4g/0h0C+wlCWy9mdnWZEAwVqD51fBo0qMdmXZtIc3ypXMsc7
         YrTY3C4bisMKjlxG63J7iv2oMtUrbWRASY7m7pSvfSkZo0YoQFGQgj87h5e7AMNhmddQ
         +Lzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=+t2Fm2xukLMEPHf8ZaJI5wrWDEZGaB6Do9fL6MT3CtM=;
        b=DDwFnUj2MPpduht8nN1j/gPDFC3ALFevFmeoDCzXangIbYaJPNCRQmmYr5wkzwmyo3
         HZk29WF77ThS1z3pD3X73wxJ+x22JZfWvIszOKKW0Q5JR0lFIoR5f4TPIR9zdnCZLsUU
         q5/ZuVk87unyg6i7MN3nZ+g6luOyZpK6jbVcyjKg8sW8voWZUYYFVIgn6RVRJYqq3Y0+
         7ucyvaBFiUoWrbtvoRGDL+zJp2R+58j29girbsueZGA3x6hrUaK9yTidw4LC/Ikh6opU
         BmKXDk6jXVGw5rBdAbNTqYoriGk53iPvH2y/quMic9DVg+Y+fw0JETssOc4ro+MLqv+F
         8CRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GeR2OXeF;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 191-20020a1f17c8000000b003760f8bf2a0si799186vkx.2.2022.09.19.06.34.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Sep 2022 06:34:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-648-oeutMdS6M_WTwv6_veBJGQ-1; Mon, 19 Sep 2022 09:34:12 -0400
X-MC-Unique: oeutMdS6M_WTwv6_veBJGQ-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.rdu2.redhat.com [10.11.54.2])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 3F288811E67;
	Mon, 19 Sep 2022 13:34:11 +0000 (UTC)
Received: from [10.18.17.215] (dhcp-17-215.bos.redhat.com [10.18.17.215])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 3E10640C6EC2;
	Mon, 19 Sep 2022 13:34:10 +0000 (UTC)
Message-ID: <34b2bb18-ad64-ee10-37ad-3c2ab2387a0e@redhat.com>
Date: Mon, 19 Sep 2022 09:34:10 -0400
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.12.0
Subject: Re: [PATCH] mm/slab_common: fix possiable double free of kmem_cache
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
References: <20220919031241.1358001-1-feng.tang@intel.com>
 <e38cc728-f5e5-86d1-d6a1-c3e99cc02239@suse.cz> <Yyhlmq8GA5FnNoxq@feng-clx>
From: Waiman Long <longman@redhat.com>
In-Reply-To: <Yyhlmq8GA5FnNoxq@feng-clx>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.2
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GeR2OXeF;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 9/19/22 08:50, Feng Tang wrote:
> On Mon, Sep 19, 2022 at 05:12:38PM +0800, Vlastimil Babka wrote:
>> On 9/19/22 05:12, Feng Tang wrote:
> [...]
>>> The cause is inside kmem_cache_destroy():
>>>
>>> kmem_cache_destroy
>>>      acquire lock/mutex
>>>      shutdown_cache
>>>          schedule_work(kmem_cache_release) (if RCU flag set)
>>>      release lock/mutex
>>>      kmem_cache_release (if RCU flag set)
>> 				      ^ not set
>>
>> I've fixed that up.
> Oops.. Thanks for catching it!
>
>>> in some certain timing, the scheduled work could be run before
>>> the next RCU flag checking which will get a wrong state.
>>>
>>> Fix it by caching the RCU flag inside protected area, just like 'refcnt'
>>>
>>> Signed-off-by: Feng Tang <feng.tang@intel.com>
>> Thanks!
>>
>>> ---
>>>
>>> note:
>>>
>>> The error only happens on linux-next tree, and not in Linus' tree,
>>> which already has Waiman's commit:
>>> 0495e337b703 ("mm/slab_common: Deleting kobject in kmem_cache_destroy()
>>> without holding slab_mutex/cpu_hotplug_lock")
>> Actually that commit is already in Linus' rc5 too, so I will send your fix
>> this week too. Added a Fixes: 0495e337b703 (...) too.
> Got it, thanks
>
> - Feng

Thanks for catching this bug.

Reviewed-by: Waiman Long <longman@redhat.com>

Cheers,
Longman


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34b2bb18-ad64-ee10-37ad-3c2ab2387a0e%40redhat.com.
