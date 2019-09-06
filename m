Return-Path: <kasan-dev+bncBAABBXE6Y7VQKGQE5CMOLXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A624AB0DE
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Sep 2019 05:15:41 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id i13sf5815001iol.23
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Sep 2019 20:15:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567739740; cv=pass;
        d=google.com; s=arc-20160816;
        b=QMF4q7YtC24Uiwxmpffe+phz6+IBsMWmKjAD3S425fGN0dqbKFM9lKT5p1E9fkpkFp
         zM4QrzleY/KqUP3lGI7MeG1orsZKJ8dj7V4mOq7Vge4TYk+JgOQYf6wmR+4LaCCdcpro
         XpwacJ5NFTcHOkY282H00SOjGcSaejWVGfNhlupL8S4bOIy5GFB/QYKbs5par4jYD3rV
         2Nnr47TDKxxyG4zmgdRGSPMqZ5t9La0PlkrkwnKJ2UeN3xpQJZ0SvH3moD4H94Cqv+GJ
         5/CTzXtVXUjOljBazWpOjOXMHi6pFWecE2ErGQ8bhWq7qs91cQuVnSEQn3wnCQ1V/FwA
         oo3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Sm1zRQfLjEv5vTiPMh5YEqPRo1Wxj7pJbkkejAX6LQo=;
        b=OgmVtobpJ+feuL91afjlAtsB7QyultzYXPfNGW0bjo3CmFm9P9iKHpbKkOXsbDRveV
         xOqyf8fidcdC2w+rhJI7hHh1NFJABePOIOEZXUPWfOlhJEQ9U5K9hd/eFyyWGzYJgr9o
         KJF8Gr1PjwImnyeRfOdhoMxFH/j77Hn3GqIwUg/CiRMq5MaRYXT/HTSBpCxyiV55hAyP
         YQYAsnsvNesPnYi6HA3VrzqlZzzeRuarp/9izKjgdmpUQACbt5uxpH1D1dUzmN6j1rLB
         wELb8ey1T6mB+qtmU/3qgI7REgWP82u2WeWuyI2N+UPRyHmDKSZnOx9tV7dNJU37LeDa
         ss3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sm1zRQfLjEv5vTiPMh5YEqPRo1Wxj7pJbkkejAX6LQo=;
        b=c/WneUI8e/aV5WAPfCgz0shMG+9srn3lsLkRS3LI0lEeTU8xvE/VCG8Mxr315eLMJV
         EEBTprPQhAKepYf3CcvjO4KK7TOUhqmDgoqeioZz52hSjEnOwxEjgYV2RX5DY1p7MheY
         O/zarm/RARdawLFTYZKItJXdclU0RkBgD0z2cPPIcFTJS3EH+hgvMpVzaxCh8qWks3W+
         JhXn5cHnLpv8CYYstX3g5Hdv4asqkm0GLZxh/bwifqzvtsef9XnM5T8BEIXzhHfua7x/
         DP32AoaXf6SHZWpGqWy7kE0x1J6sQMqTUnwh0iLbGsFGuXs7dMl/tNLRvXuq8m5g/fyU
         6m2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sm1zRQfLjEv5vTiPMh5YEqPRo1Wxj7pJbkkejAX6LQo=;
        b=g7jw7hZhlisiTeXms5Bf+5+L2UwPeR4n5lPHhytf4BAstaCmVdeJzZH0ECvLUZRaUq
         cnq+kvSXBHqwCYP2HBxBRS9a9atyjQ8Vx4a/NqfxfUii1D4l5OGd73R3qn5Uu2P21pdY
         N3aSh947K0lgQOcZPt8i1KVxxp9MjB0CIiAlvwnXHK/PVm/AF+ONM/WDkbglSE9faGrb
         b6Ktq1bz6Eq+qEXkizVJQKzo6+IfqunDxYBR+tLywfO/PMdTMnWno84lBkQukBcNUNHh
         tUNocwSPqR2QPu6I3pSbo9NKgV/dxwuicYFR+Z0gI7F2VnYbmp4Hp09i/HKJtRKoaDK0
         OSIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVwq+XTosnJkCTv8+BdQpdnnZ8wPzfaTHFsE9jZt+bdfUEkTbDG
	7mTOKggZsyi4LVddH9pr1Z0=
X-Google-Smtp-Source: APXvYqwupeDndU3PDgYUWO8+jOqKvDhF74mhEOAWGBioK8oXVNoFqNn3jtgxHfAAOOmUKv1bLkXAPw==
X-Received: by 2002:a6b:b704:: with SMTP id h4mr4919735iof.218.1567739740196;
        Thu, 05 Sep 2019 20:15:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9254:: with SMTP id e20ls127501iol.9.gmail; Thu, 05 Sep
 2019 20:15:39 -0700 (PDT)
X-Received: by 2002:a6b:14c6:: with SMTP id 189mr1571347iou.202.1567739739973;
        Thu, 05 Sep 2019 20:15:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567739739; cv=none;
        d=google.com; s=arc-20160816;
        b=igTC1rFBO6UsfLIBFW38441ppuoXkDR2cbgorcw7fTBk+ci3T4setK7D5ld8YpVpdo
         ROub5Rz3QcR87Rc5aIOLVwalqlm9M9p8POElxbME/NybqZ/S7WCFW1D/TakH9q205Ad0
         18KQl1uX6w6WoUYhJLYJYfEGXbx8LHECyUjGmdvGg0iRo4i5DEe5+JGpDEiqb5jzYZuF
         JZhlnRz+ckUORdT1vvSi3EizTIh0pm581uGCi4oFdhsNLIlb3uH6b527Iv/lEt7grfQD
         bT8onAZ/qbd081P+Td42KLWzOW/uxgDsoOSQ8CMbnqrIvhjr9fYHnyYAz7Kn3jqsYLEh
         QPoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=r40OCDbZ/OnOJoAVBZvoLEch1OLsWF3BRv3RwiDta5A=;
        b=A10D7xw6vwi7nU8OzUgBbv7qcYIuQOsc/NU9ijciiTnG3UylgFUItIGTDiWBx8FyLv
         FqQI8HNQDfGuy9SEG5tW3IrFaAEa2z+qR7MtJ7xPymiNm19MmlA8o4RixIGUyZzXYGH5
         8TZoDJQPwrJBuKS8s7xAz9PsrX9UWOgGPfd8HNvW+Qe36hCAwpsN2ftFMI0yeaQGsGWt
         jcSARvOMyiwh5QRdXG87zvyqT2FjNnT4UeME+UMHSorPdxWsEZr5wIPmktGS0jx5JPke
         pCaW+tEeP61KinE1kQo8NqGrzaNHGtCq/w3f/lnQTnlerJi+1L/JAY79+by1qdbCJtrW
         Ed7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id q207si151713iod.5.2019.09.05.20.15.38
        for <kasan-dev@googlegroups.com>;
        Thu, 05 Sep 2019 20:15:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0c52a1504d08462fa88399dd2eb2bb08-20190906
X-UUID: 0c52a1504d08462fa88399dd2eb2bb08-20190906
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 791673129; Fri, 06 Sep 2019 11:15:34 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 6 Sep 2019 11:15:31 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 6 Sep 2019 11:15:31 +0800
Message-ID: <1567739734.32522.67.camel@mtksdccf07>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Fri, 6 Sep 2019 11:15:34 +0800
In-Reply-To: <99913463-0e2c-7dab-c1eb-8b9e149b3ee3@suse.cz>
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
	 <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
	 <1567605965.32522.14.camel@mtksdccf07>
	 <7998e8f1-e5e2-da84-ea1f-33e696015dce@suse.cz>
	 <1567607063.32522.24.camel@mtksdccf07>
	 <99913463-0e2c-7dab-c1eb-8b9e149b3ee3@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Thu, 2019-09-05 at 10:03 +0200, Vlastimil Babka wrote:
> On 9/4/19 4:24 PM, Walter Wu wrote:
> > On Wed, 2019-09-04 at 16:13 +0200, Vlastimil Babka wrote:
> >> On 9/4/19 4:06 PM, Walter Wu wrote:
> >>
> >> The THP fix is not required for the rest of the series, it was even merged to
> >> mainline separately.
> >>
> >>> And It looks like something is different, because we only need last
> >>> stack of page, so it can decrease memory overhead.
> >>
> >> That would save you depot_stack_handle_t (which is u32) per page. I guess that's
> >> nothing compared to KASAN overhead?
> >>
> > If we can use less memory, we can achieve what we want. Why not?
> 
> In my experience to solve some UAFs, it's important to know not only the
> freeing stack, but also the allocating stack. Do they make sense together,
> or not? In some cases, even longer history of alloc/free would be nice :)
> 
We think it only has free stack to find out the root cause. Maybe we can
refer to other people's experience and ideas.


> Also by simply recording the free stack in the existing depot handle,
> you might confuse existing page_owner file consumers, who won't know
> that this is a freeing stack.
> 
Don't worry it.
1. Our feature option has this description about last stack of page.
when consumer enable our feature, they should know the changing.
2. We add to print text message for alloc or free stack before dump the
stack of page. so consumers should know what is it.

> All that just doesn't seem to justify saving an u32 per page.

Actually, We want to slim memory usage instead of increasing the memory
usage at another mail discussion. Maybe, maintainer or reviewer can
provide some ideas. That will be great.

> > 
> > 
> 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1567739734.32522.67.camel%40mtksdccf07.
