Return-Path: <kasan-dev+bncBAABBW5R47UAKGQEKKQXPUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id C64BF5B86F
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jul 2019 11:56:44 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id h37sf2001746uad.16
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2019 02:56:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561975003; cv=pass;
        d=google.com; s=arc-20160816;
        b=AuEpOInpGNYtp6Sucg8XrdwcvkKYrGxgDASvDSbZs048y+tSEPspyZ1LgELVnE1nFh
         e3qwamzMO/2tyySh4faDIY4ZqZFSAAl4ERnRzjbvcGWJeLu2bdvrAEM10vJfRtNgw+02
         h6O3twa4YID4gM/cKs87/9gM8upoQ34j7kI6alzffBJ/C8NOxyL9ahGHiY9O11OiwG7l
         85ATBX99SDyuFcJ0wp0M6HSQNywDQSGHGK/1U+988V+zjEQgQpLkjhe2zZhkEQvCrO7c
         uQV3j2uz+R4ZmArwyn1CR7n/3dynbmNf6hj2aC84QaoY+L+Qcl5+8vJCV3SzEa7ux0av
         gKEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=UpvimNwxXqFYQ3B42xCTIY4wCgHEhgw3KipRNVjPJZA=;
        b=RYEOzYUWkGYeOZ7yshxdKTIGIMETWs+iIW+vQe6Wtt6VjvhAIXbtHFcQNTV+RDwA+U
         3pNqMHiMa72NgYTNunoLrD4nD3Ez77pRN6dsYErC+MaXNC7EpXt0V1sxAG8x5xb1tXdW
         GZXoG9etM5sm4a0flzNxrc0tSMZXnYhriVklPe/+OC3p1EiP0yB63I61vj1MjxGKpjVG
         OB2FQ3MXWkecrV3UH6KDuao93OKK4wGzsd8f0OWLdPO4xBVBNbHB9i+vndQmBo2nH1ud
         oRzaMuv9pTolJK8VwBZzAXFEt3+LkqztL1saqqPMasOXpCf6AyYHtK9CWkQkgfoMcfY5
         XLog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UpvimNwxXqFYQ3B42xCTIY4wCgHEhgw3KipRNVjPJZA=;
        b=tiJjwL8xfNqDv+j9s6a14gh89kSclD1atcygwC2iVel8AfbIWwp1Y9yKlmM9Os2+PF
         VlAkfhuV4XiKIKJ+mBKS+WS6IMxJmxGxzKG3CwrphTJc5I/m6ft9FQlaXfGwVNg1DguQ
         vEDVZhcY7X2pCsac1WlSKlhVu4drFI3S5Lj30bcWGmB53hn16qR9pwdzQALYOAkjhgJ6
         AAUTwL5WHFSOO0KJ3+d5qhnzHyDqzkR52XPWife7gB3KZ869Qn0p/FKXl/IsjNbdtDtR
         Hy/bJmfLMxYSPhLN6IHjmvONrcfpcZ9P6VGm1YSyg/EfPUT2IMuL8l6j4fX1NQ7baeEs
         CX8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UpvimNwxXqFYQ3B42xCTIY4wCgHEhgw3KipRNVjPJZA=;
        b=rMn4EALHcdbjkIUwUKANugouICQhxpX9fCmpFWJGix8nUKgZWAHg/4oAbyF9G8qO4k
         N1V8mRmPGypjjxIFNPvX7RUgb7jLs+yhiPiefOfWJilmpQh7PQNXAOonsjgjRznbJfJ9
         4h2VFZMWUTMU41b65rbVLi3/wfklQ/aj8CAbDxTdsxb4xX2IR16Qqn8D1H+2h3Gix4Pr
         G4uwrirQnC352eMSP7OdoyxaH57iqAXWyj27oO7Bbsd9p1+y26d4LPa+P3Omvqm7vNQt
         IK2XhPqAZetknnP9XOU5uxqSpxRF/PMRyoHcU/uJRm1fbJSHuSyRkvvKVc3hFfFnVKH9
         4O6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVhVQbS2uT7oFkb5BJKs1e8tkDO7AaiUGDBhGeTJTz39RizfeaC
	Dt/SC/BLvMXm27TrqgRYCuo=
X-Google-Smtp-Source: APXvYqwNi1fhNvWPr0ZlAgUakJR0KLlnl5pQm6Sz1PnnImtC9z0cYEufXmBPGKPULjkeU+xrUp8I3Q==
X-Received: by 2002:a67:f281:: with SMTP id m1mr13513578vsk.184.1561975003716;
        Mon, 01 Jul 2019 02:56:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ad06:: with SMTP id t6ls828479vsl.8.gmail; Mon, 01 Jul
 2019 02:56:43 -0700 (PDT)
X-Received: by 2002:a67:688f:: with SMTP id d137mr14064183vsc.198.1561975003460;
        Mon, 01 Jul 2019 02:56:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561975003; cv=none;
        d=google.com; s=arc-20160816;
        b=W5GFknq80j9fkC8C+DBCu/HQgR+9EopeoM93tnC+1Lh18uxndOq8MZiFAH97Q+zVcX
         b6sHhKlxXIp8G6hPJ+coryD6GXE4MOz458weGxmAwsxVpo8zp5C17wDNhaYXVNQYN9Ko
         r+kyFhBOvoUCe7gKH7RR4OMhhJg2ndiJzj8UV5PAQ9agujDVnERpCtkt2DhvS6Vi0lmI
         hd+HLgN/Ct9VGItU0y7yTgTfOHXsRWSn6hVYeKp9oIq8fsGvI6WptFhYuP5G2XNGBcAP
         xTBcwXvjgBkjUOmpWAIJ8VfRuV4/JXWczXrkFttcz4ScmiQAYUuBnuHG+OiZ/0mE4s0d
         cC/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=QB5uWgD3NO3VbFr/pONkbxLISPnIjp30M+44zmcUrV0=;
        b=xwHKKiJyFW+nDnxCZXH86o8iKf/t4OrGSKxeuVFRXVqN4VJeuuJ2fXBDGVXYPtqm0w
         tUWgDlt8mxWTzeOqcC+888WOca47F2a1qqTKwlfJTY0S5yg7oPrgUf18Sy+pmZ/h6vDC
         7FyhlT3Px8+qDFtoY+dbLkpcDmw0BV3zmQS9VNfizEJHsJ97gb9mdypYZz/4qDtLU40g
         GraTuWOZn+GIdhepm9t/HXV06Jlswutx240V4qFvumS1p70fTe7g1g028m3mZBfzKaE6
         SaWkBGzEMZ2hgnvCQxQyRW8Gcvs8xZaa8MO50nsiRNyVj1f9FDY1lyF++fkK2cEx1cPM
         FyYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTPS id e126si377248vkg.5.2019.07.01.02.56.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Jul 2019 02:56:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 73d37207a7e94239abcbabbd212a7df5-20190701
X-UUID: 73d37207a7e94239abcbabbd212a7df5-20190701
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1208537169; Mon, 01 Jul 2019 17:56:37 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 1 Jul 2019 17:56:36 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 1 Jul 2019 17:56:35 +0800
Message-ID: <1561974995.18866.1.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
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
Date: Mon, 1 Jul 2019 17:56:35 +0800
In-Reply-To: <1560774735.15814.54.camel@mtksdccf07>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
	 <1560744017.15814.49.camel@mtksdccf07>
	 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
	 <1560774735.15814.54.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
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

On Mon, 2019-06-17 at 20:32 +0800, Walter Wu wrote:
> On Mon, 2019-06-17 at 13:57 +0200, Dmitry Vyukov wrote:
> > On Mon, Jun 17, 2019 at 6:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > On Fri, 2019-06-14 at 10:32 +0800, Walter Wu wrote:
> > > > On Fri, 2019-06-14 at 01:46 +0800, Walter Wu wrote:
> > > > > On Thu, 2019-06-13 at 15:27 +0300, Andrey Ryabinin wrote:
> > > > > >
> > > > > > On 6/13/19 11:13 AM, Walter Wu wrote:
> > > > > > > This patch adds memory corruption identification at bug report for
> > > > > > > software tag-based mode, the report show whether it is "use-after-free"
> > > > > > > or "out-of-bound" error instead of "invalid-access" error.This will make
> > > > > > > it easier for programmers to see the memory corruption problem.
> > > > > > >
> > > > > > > Now we extend the quarantine to support both generic and tag-based kasan.
> > > > > > > For tag-based kasan, the quarantine stores only freed object information
> > > > > > > to check if an object is freed recently. When tag-based kasan reports an
> > > > > > > error, we can check if the tagged addr is in the quarantine and make a
> > > > > > > good guess if the object is more like "use-after-free" or "out-of-bound".
> > > > > > >
> > > > > >
> > > > > >
> > > > > > We already have all the information and don't need the quarantine to make such guess.
> > > > > > Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> > > > > > otherwise it's use-after-free.
> > > > > >
> > > > > > In pseudo-code it's something like this:
> > > > > >
> > > > > > u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> > > > > >
> > > > > > if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> > > > > >   // out-of-bounds
> > > > > > else
> > > > > >   // use-after-free
> > > > >
> > > > > Thanks your explanation.
> > > > > I see, we can use it to decide corruption type.
> > > > > But some use-after-free issues, it may not have accurate free-backtrace.
> > > > > Unfortunately in that situation, free-backtrace is the most important.
> > > > > please see below example
> > > > >
> > > > > In generic KASAN, it gets accurate free-backrace(ptr1).
> > > > > In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> > > > > programmer misjudge, so they may not believe tag-based KASAN.
> > > > > So We provide this patch, we hope tag-based KASAN bug report is the same
> > > > > accurate with generic KASAN.
> > > > >
> > > > > ---
> > > > >     ptr1 = kmalloc(size, GFP_KERNEL);
> > > > >     ptr1_free(ptr1);
> > > > >
> > > > >     ptr2 = kmalloc(size, GFP_KERNEL);
> > > > >     ptr2_free(ptr2);
> > > > >
> > > > >     ptr1[size] = 'x';  //corruption here
> > > > >
> > > > >
> > > > > static noinline void ptr1_free(char* ptr)
> > > > > {
> > > > >     kfree(ptr);
> > > > > }
> > > > > static noinline void ptr2_free(char* ptr)
> > > > > {
> > > > >     kfree(ptr);
> > > > > }
> > > > > ---
> > > > >
> > > > We think of another question about deciding by that shadow of the first
> > > > byte.
> > > > In tag-based KASAN, it is immediately released after calling kfree(), so
> > > > the slub is easy to be used by another pointer, then it will change
> > > > shadow memory to the tag of new pointer, it will not be the
> > > > KASAN_TAG_INVALID, so there are many false negative cases, especially in
> > > > small size allocation.
> > > >
> > > > Our patch is to solve those problems. so please consider it, thanks.
> > > >
> > > Hi, Andrey and Dmitry,
> > >
> > > I am sorry to bother you.
> > > Would you tell me what you think about this patch?
> > > We want to use tag-based KASAN, so we hope its bug report is clear and
> > > correct as generic KASAN.
> > >
> > > Thanks your review.
> > > Walter
> > 
> > Hi Walter,
> > 
> > I will probably be busy till the next week. Sorry for delays.
> 
> It's ok. Thanks your kindly help.
> I hope I can contribute to tag-based KASAN. It is a very important tool
> for us.

Hi, Dmitry,

Would you have free time to discuss this patch together?
Thanks.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1561974995.18866.1.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
