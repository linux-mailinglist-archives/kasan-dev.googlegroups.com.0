Return-Path: <kasan-dev+bncBCPILY4NUAFBBH4BT73QKGQEM2YA7AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id E5E391F9F76
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 20:40:32 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id o11sf14750980qtm.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:40:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592246432; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9bLX3XFu/dCXjlqJQWSU9g17rxCRIL22XMXYaUsva7nQ5pOfkzhrQRYRchrzN3OE2
         yqV6+uPjilq3JR9ItOwVtKNamEdRgArrrC+8/VBy50XnGOriLMYzi208IzCsVuM5GmZL
         cb/hA6cZBpdXf4wPZj9y4RBUiyApBRXXU0LeU/pZi2hM/qhA0FzpXwn0XLK2jyjTRh6a
         MiPgJree8ZcsSd/oq0rMQMJ9zxD2t9Xof3IUgFibtaFQPtM0hODpNCxhPP+61DC5+ppq
         nJT84JnXnv8BVPeyDR63sGRWjrL5mhPMeQqTPYawVXEu2XhMcr1Xgxv0oPJTWqZXpG63
         GL3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=16gUPPGC8isPbHnndocb2TkS9FeuFFRWV8ZPOdjfc/8=;
        b=sRLPcdNSYGNiJ0gfG/n5FiJBPh9/xSUwpOk2BJcBbpsHJu9xp2DJM8lvAuePSroexb
         Em/ktD7yWpUYu31odoy1StJNRG7nOu3FGzHLu0FKJnR3T7iu8OEGVChwmzTu4M7GSxiw
         bEEnqDs2E4JJ5yohBUWxkxOlyHwUovFPyxYmofx4Uw54sO9ZpKVOvY1hu/A0NWnftqf1
         RQzUDDT1zVtXA9v5s8gnYBjhhnVoeEmj5oXONOdMNKi0aSnrTSwRAFMbvD5TUa9Hb4Py
         N4z0iyKy+2G/e8UN30HiH8JUys+b25z0VefvvhWM9vscgmD2p8ITeSuh2XrC+zLu/Arv
         mqyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iOSi6SGL;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=16gUPPGC8isPbHnndocb2TkS9FeuFFRWV8ZPOdjfc/8=;
        b=Ui7ZhbPfx23d2ZG6DyaczLMckrwENzUn1tHc4J330Ki2WzxRpC+cjUvARY6ZTcC0jp
         3uMwdN+e8okXNGPc/2gVr9Wj292SflhOztgNy91htFSsBAVR3Tiu7nINQupZCR18YJ8z
         dau5EEFgLsCSLScTKJ411BWgGyT5Q8THgT0K8sKJMid06vP+f/ug2RhfrM43uIFiYMyP
         vvo4jKmIDgNVONTH43wu+qE9sfv/PXVNPKlklrz5lVcWuWZpMeEKdH65KXW2LySd2UdK
         2+uC9ToIoLlZRhuutEHJKd4WLeqerewV0ZtxLwgHnGR2bj/SNoisEwbRbRNcR14YXUsf
         /gXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=16gUPPGC8isPbHnndocb2TkS9FeuFFRWV8ZPOdjfc/8=;
        b=Gp4RaU8lnGgNRQg5BUXnwfWnWRLHU98CLFR1Cs8TGP832djdqg/zM7O4HY7zqyBA7j
         3sgHcBBEQCq1Lv2qzcv5SKdDpJFik1KMoULnId74eR8aCHCx64o5BaR1/7o0zdyhBNMe
         0v1onOUvc92XBcoNV02PUWc/EMACYd2XTaJIchnbFHTWoDaRhrJWmF80Y3ckYC8eqDYp
         HaoBrZgPIVyQqEVz/cPy6u1IOakGIB2PDj3B9aZ9xq4kxe46R+E9JFWKU9NvmZ62FcbL
         94I0SKEDkuVIcUyXTnPSfqIxQD4RdQni0+Tr5db1GG3Lm5pPA425NgZsSMrXovzd1FyY
         +fPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qdpOS49NdsAvReYpMzXrhEnh5jZbARBCA1f8TwNuQBOb5NS7y
	IZ6Bj3+/FDs443lAafgyYuo=
X-Google-Smtp-Source: ABdhPJy+GdskNv88gNyeOUhHh79DCXOtDGheSJ6x/u6YwqOLDJGgNzz5UsEfASC9vc47b+q5sXZHBw==
X-Received: by 2002:a37:9587:: with SMTP id x129mr17033264qkd.184.1592246431970;
        Mon, 15 Jun 2020 11:40:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1917:: with SMTP id t23ls5775944qtj.0.gmail; Mon, 15 Jun
 2020 11:40:31 -0700 (PDT)
X-Received: by 2002:ac8:4e86:: with SMTP id 6mr17181658qtp.390.1592246431623;
        Mon, 15 Jun 2020 11:40:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592246431; cv=none;
        d=google.com; s=arc-20160816;
        b=tJMcpsPiLTW9j5ANf12JzPbN0/JqBrdZdmdIXZv/PkwQ5g4vij4vI0FLiI5kxiXfFO
         LE4AqF0I9rjevU9bsyyzMMmjAHo0XHhjO2pDdac99oZIMNHiYZq1s6lFvULAlW6LqWmy
         x8Ka7EUT7f/BH4SQJBwEZ5tuUs7EJxw4TRkRIV+bgEjX4OXbdzsuNFvuCtL5Jl2zIEjU
         UQ0AC/L1iSLqAwKCwDnW0QLUGr7BpMbt/y+8piIC54tCBvDK7ekwyB2SWVxUdKAx1nt/
         nX8GFObz3XJ3/H2jQjau1KWB8J8OgvM1L+kfv2VzS5Qug9MBSh96URS7tuYQjTKueaPt
         BbAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=3LdVapGy9WTsAkwpfNEzCTfQe3Pij8/lM5ySXZsHExs=;
        b=I/BVb2bPGTUjTIYL5LQCB+NBXyh8mlyawvT1Xgt8pqWUKFA9B2gEl9EXjw4oOr84nW
         /xetAmBB02UQm1UlAdS+NHK6at7K/dVIpXZgxVzRveKG1wieB+UDNCOQRVN9Qrtu19LW
         nHIgCZrJ6zun0jLbM8tRZ96BqCw5J07WWkbLtMPFplnnbTOjeE6rXG4ItT4qpszKNZ2G
         G9vJzWqatJ8Uu4n26IbE9EChfuaWDY29x35UvppffMzuLqXdwcA5P8SJkOkChxhXDWNB
         FV28XBhEaJ40XwaDc6l/LroHzJvoI8GLNo8vQjF5a9MOogRVpZP6sKZiYYbr3zaQdQ5L
         hi1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iOSi6SGL;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id f23si670251qtm.4.2020.06.15.11.40.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 11:40:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-513-n3G_ZfGUONug8wkjJytxqA-1; Mon, 15 Jun 2020 14:40:12 -0400
X-MC-Unique: n3G_ZfGUONug8wkjJytxqA-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id E5F43184D144;
	Mon, 15 Jun 2020 18:40:06 +0000 (UTC)
Received: from llong.remote.csb (ovpn-117-41.rdu2.redhat.com [10.10.117.41])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 3972B5D9CC;
	Mon, 15 Jun 2020 18:40:00 +0000 (UTC)
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
To: Dan Carpenter <dan.carpenter@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, samba-technical@lists.samba.org,
 virtualization@lists.linux-foundation.org, linux-mm@kvack.org,
 linux-sctp@vger.kernel.org, target-devel@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, devel@driverdev.osuosl.org,
 linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org, x86@kernel.org,
 kasan-dev@googlegroups.com, cocci@systeme.lip6.fr,
 linux-wpan@vger.kernel.org, intel-wired-lan@lists.osuosl.org,
 linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
 ecryptfs@vger.kernel.org, linux-nfs@vger.kernel.org,
 linux-fscrypt@vger.kernel.org, linux-mediatek@lists.infradead.org,
 linux-amlogic@lists.infradead.org, linux-arm-kernel@lists.infradead.org,
 linux-cifs@vger.kernel.org, netdev@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-bluetooth@vger.kernel.org, linux-security-module@vger.kernel.org,
 keyrings@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 wireguard@lists.zx2c4.com, linux-ppp@vger.kernel.org,
 linux-integrity@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-btrfs@vger.kernel.org
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com> <20200615180753.GJ4151@kadam>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <9d084be2-29a3-7757-9386-20dbaeb5fc24@redhat.com>
Date: Mon, 15 Jun 2020 14:39:59 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200615180753.GJ4151@kadam>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=iOSi6SGL;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 6/15/20 2:07 PM, Dan Carpenter wrote:
> On Mon, Apr 13, 2020 at 05:15:49PM -0400, Waiman Long wrote:
>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> index 23c7500eea7d..c08bc7eb20bd 100644
>> --- a/mm/slab_common.c
>> +++ b/mm/slab_common.c
>> @@ -1707,17 +1707,17 @@ void *krealloc(const void *p, size_t new_size, gfp_t flags)
>>   EXPORT_SYMBOL(krealloc);
>>   
>>   /**
>> - * kzfree - like kfree but zero memory
>> + * kfree_sensitive - Clear sensitive information in memory before freeing
>>    * @p: object to free memory of
>>    *
>>    * The memory of the object @p points to is zeroed before freed.
>> - * If @p is %NULL, kzfree() does nothing.
>> + * If @p is %NULL, kfree_sensitive() does nothing.
>>    *
>>    * Note: this function zeroes the whole allocated buffer which can be a good
>>    * deal bigger than the requested buffer size passed to kmalloc(). So be
>>    * careful when using this function in performance sensitive code.
>>    */
>> -void kzfree(const void *p)
>> +void kfree_sensitive(const void *p)
>>   {
>>   	size_t ks;
>>   	void *mem = (void *)p;
>> @@ -1725,10 +1725,10 @@ void kzfree(const void *p)
>>   	if (unlikely(ZERO_OR_NULL_PTR(mem)))
>>   		return;
>>   	ks = ksize(mem);
>> -	memset(mem, 0, ks);
>> +	memzero_explicit(mem, ks);
>          ^^^^^^^^^^^^^^^^^^^^^^^^^
> This is an unrelated bug fix.  It really needs to be pulled into a
> separate patch by itself and back ported to stable kernels.
>
>>   	kfree(mem);
>>   }
>> -EXPORT_SYMBOL(kzfree);
>> +EXPORT_SYMBOL(kfree_sensitive);
>>   
>>   /**
>>    * ksize - get the actual amount of memory allocated for a given object
> regards,
> dan carpenter
>
Thanks for the suggestion. I will break it out and post a version soon.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d084be2-29a3-7757-9386-20dbaeb5fc24%40redhat.com.
