Return-Path: <kasan-dev+bncBAABBIEUTTUQKGQEAF57Y7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EF7B6544D
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 12:06:26 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id w137sf2276158vkd.21
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 03:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562839585; cv=pass;
        d=google.com; s=arc-20160816;
        b=pjIvzoxopyz2kiZRiRoCgzYdMleFIlDdAONTzKamXSnMKYTk8/H7UhoDwZPkk4eghg
         girIzs56W74bExIJ2BHkhEEwC51BWivwIpwREu1WElALUBBbruvplVExaoE2MU8Pwyfo
         4VuYjOgNDWUg2gr+2eGdY2EPCyxFeOXGnpfisKADgJkJFp1QFv1yXQHE6ossyrMSC595
         cNua9ikJuU9pkPBbuQgNXUcHi3VOo2oGmz6lB8Cstov960w6VvQ6OSYV1HvM/F6FLea6
         IJwWcI7jNdHH31idZtlPJqhFUZQylG3kYewrVAUyFrSkYzMEQ4pq/9oZRHByb9uGSDmx
         uirg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=+ysfISMQFa7N7Y7PBucp9bT6BionZ8q8wP4zMyxZ9pg=;
        b=zJQTQMnGbC61JoYKMiabusAKQM5HXAeI0wAyHrrGhzJlQJuIdSgh7Y2E/W9SzSlwyd
         /DLPcXQ5aV9gwOYtLVek6zo8AY3JgnH/XfDSNRs72urQ21516AU5SGCkDNu72FU/CS8R
         prbL+JUz5cEVM0F4Wax7nqeN4GOL0riZseFoCGuFqbCMSy/FkWUyyYKBDA9XwwkIMtw4
         xdL5nMxeM1/z5wHZN0LPfw69DJeKEhbUjeWBUUe9OPkKq+1j4K0zG1Z2E9cyakihhEo5
         BMNP5EUC0hsI8vRZqYNzR/AyflnB6HdX+1K6W6AUZtqsneIh0yEV99BWaOmyOFfPBBNd
         gh1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ysfISMQFa7N7Y7PBucp9bT6BionZ8q8wP4zMyxZ9pg=;
        b=c5msIjwskyGQjsR/PtXKPZNxn+BkqxQn/3MNM23b9SCKwjRCzjDnf1Ye7L0yGabKJ3
         gzWCYmk0rZ6DoMjF+UWo+6/RDyGvL88cxciZgswIV8nMcraUmuXMBWDdu6eNNVtg4lz+
         zNTY96OILImYSd8JSWKh69a6DcRoBjPhoZ8UxaRlDgsaiJ1H4lacVjfyUnc4wFYQcQVF
         2FWUeVqSN3qdRzJrqlnG1qJ9Q2L5ug32Q1b2pinh8m10H6ZtWnNF1Qe2YCBpaJbcWg2/
         lkhO6ewmI8RyXLGbjGVGM/yoxtXxgEDm8j4YOkLybkJ7tzzGY7U67lLfiAOCLgmIo7uE
         GTfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ysfISMQFa7N7Y7PBucp9bT6BionZ8q8wP4zMyxZ9pg=;
        b=uQeNAMJb/PZV3qZScnw4yKdvq0fbBEHtFIbkM4fwovDsV+lUKH/mlQ9WTgBv5Sw59T
         jWxyiUuKbLjRv7Uf/nQtFoDDefSwrd6F1k1rb09K1ujMFmtC7+/6vER0lOCTtx4pw4dQ
         EWLKDolCv51MwDbFgmijbaNEfLlIvYMh30sQGwQ8RF6vQB5G+qEBH0V6oTYs+/0bVAMw
         B7AQI5VCtjHcgl5P4ryYpV4QfVfuBp4Br60YZYkg/T7z+uKctj4FEYXa3eiJVj0jWUDa
         d0WwduVa6ds/LIde/xkV+afnzWGu4uCgKrua/qxkAds3q61SS8CQKo7+NdPTxxb9aM/q
         8JOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWlC2i+wsCkZFdHKDRuH9dXB+aDImK1d5r9lUtDTsUWobYgkHkv
	kXWSBFs+OwrlXWN2QroSFF8=
X-Google-Smtp-Source: APXvYqxSHgeaCH//ZLWsJCvSP+QHhz9gs1P831YC4Tu4QLiHWldYOiX5w4xuY64PFai6Mt8Nwb0Klg==
X-Received: by 2002:a67:f60f:: with SMTP id k15mr2924119vso.57.1562839584727;
        Thu, 11 Jul 2019 03:06:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:e83:: with SMTP id 125ls202935vko.2.gmail; Thu, 11 Jul
 2019 03:06:24 -0700 (PDT)
X-Received: by 2002:a1f:7383:: with SMTP id o125mr2066329vkc.6.1562839584370;
        Thu, 11 Jul 2019 03:06:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562839584; cv=none;
        d=google.com; s=arc-20160816;
        b=UGdH9GefXuKalRQM0mCpHt+GKDR+Q8d2EnRENYs37M9nbIgw+wACwESoLJ7+upXwRg
         CKHkkrq10ErZOCr0TIq3sBr/9TCyqFciTCwJbspqzI4OS4bgtbkSQco1XlA3A1sXHjNQ
         RLMS3LQPmTkcRHnCmQVFuZPxVsWWadmA9UTF9+OpAgdzWoJ+nreDR17Q3TphoBH61YOn
         DLpIBSH24J5PC7WxAkt/8MYLJUUNlIGfS+NzRke++2foWc7A/kaklD8c6lQQ/YAJDjPO
         jq/5VVueFbJoCKssVVmrlSldFg4UcA2W4LjEOjX/zIyRvVtYI1fa3j4sr+6Khp+1CaiE
         aClg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=lBDaQaXRrUq4knov/Wq1uP79LCOzMma2QenhtGj5Gj0=;
        b=i8zvh1AODkqGemt1PgIg/cr8U3nhPKpP9g0SxkbhU0uQKR8wOhwOiEEocveDAZAKpe
         2pJaxxWMAExMN9vWpl7o1v2pNQEQF0tuKFJkiHNe68j4WCjou+ohQPm7pZ7AquT+PQG0
         EEJyvYhs4ImLBrCwgRBACw/A5vT1+tRNc+ZlHxgF0ClTbvD5z2nBNeU92MTUw7IROmM7
         moGr9MrlWoZAyll3MFd9uCjegzJxJ5D2RFVQZcQqI+GRyogNGYp0RJfOqdSEiy6eXSmV
         QDpGXmGdQutXnOjRL4jwDxVoG5EUcANJLJE5CRgCdYOgnF6mYj9YnvJ49rz9OAOKndMg
         dDwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id k125si285151vkh.4.2019.07.11.03.06.23
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Jul 2019 03:06:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 992731da7b244743b02a101ec454b63e-20190711
X-UUID: 992731da7b244743b02a101ec454b63e-20190711
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 749532910; Thu, 11 Jul 2019 18:06:20 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 11 Jul 2019 18:06:19 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 11 Jul 2019 18:06:19 +0800
Message-ID: <1562839579.5846.12.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>,
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Thu, 11 Jul 2019 18:06:19 +0800
In-Reply-To: <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
	 <1560744017.15814.49.camel@mtksdccf07>
	 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
	 <1560774735.15814.54.camel@mtksdccf07>
	 <1561974995.18866.1.camel@mtksdccf07>
	 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
	 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
	 <1562640832.9077.32.camel@mtksdccf07>
	 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: FCA1495ABCFBF051C3A138F429F412BB004A5166313DECBCF8F5873EED71160F2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Wed, 2019-07-10 at 21:24 +0300, Andrey Ryabinin wrote:
> 
> On 7/9/19 5:53 AM, Walter Wu wrote:
> > On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
> >>
> >> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
> >>> On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> 
> >>>
> >>> Sorry for delays. I am overwhelm by some urgent work. I afraid to
> >>> promise any dates because the next week I am on a conference, then
> >>> again a backlog and an intern starting...
> >>>
> >>> Andrey, do you still have concerns re this patch? This change allows
> >>> to print the free stack.
> >>
> >> I 'm not sure that quarantine is a best way to do that. Quarantine is made to delay freeing, but we don't that here.
> >> If we want to remember more free stacks wouldn't be easier simply to remember more stacks in object itself?
> >> Same for previously used tags for better use-after-free identification.
> >>
> > 
> > Hi Andrey,
> > 
> > We ever tried to use object itself to determine use-after-free
> > identification, but tag-based KASAN immediately released the pointer
> > after call kfree(), the original object will be used by another
> > pointer, if we use object itself to determine use-after-free issue, then
> > it has many false negative cases. so we create a lite quarantine(ring
> > buffers) to record recent free stacks in order to avoid those false
> > negative situations.
> 
> I'm telling that *more* than one free stack and also tags per object can be stored.
> If object reused we would still have information about n-last usages of the object.
> It seems like much easier and more efficient solution than patch you proposing.
> 
To make the object reused, we must ensure that no other pointers uses it
after kfree() release the pointer.
Scenario:
1). The object reused information is valid when no another pointer uses
it.
2). The object reused information is invalid when another pointer uses
it.
Do you mean that the object reused is scenario 1) ?
If yes, maybe we can change the calling quarantine_put() location. It
will be fully use that quarantine, but at scenario 2) it looks like to
need this patch.
If no, maybe i miss your meaning, would you tell me how to use invalid
object information? or?

> As for other concern about this particular patch
>  - It wasn't tested. There is deadlock (sleep in atomic) on the report path which would have been noticed it tested.
we already used it on qemu and ran kasan UT. It look like ok.

>    Also GFP_NOWAIT allocation which fails very noisy and very often, especially in memory constraint enviromnent where tag-based KASAN supposed to be used.
> 
Maybe, we can change it into GFP_KERNEL.

>  - Inefficient usage of memory:
> 	48 bytes (sizeof (qlist_object) + sizeof(kasan_alloc_meta)) per kfree() call seems like a lot. It could be less.
> 
We will think it.

> 	The same 'struct kasan_track' stored twice in two different places (in object and in quarantine).
> 	Basically, at least some part of the quarantine always duplicates information that we already know about
> 	recently freed object. 
> 
> 	Since now we call kmalloc() from kfree() path, every unique kfree() stacktrace now generates additional unique stacktrace that
> 	takes space in stackdepot.
> 
Duplicate information is solved after change the calling
quarantine_put() location.






-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1562839579.5846.12.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
