Return-Path: <kasan-dev+bncBCMIZB7QWENRBUMAT3UAKGQE4WL5PCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id DBE4F4815E
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 13:58:10 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id a17sf4750472otd.19
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 04:58:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560772689; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q/G+z08A3sx7eb+JJ4Uyy7srd3tzgtuvCHxAcf9bEuE6ZEReAEDr/88pcERmW99Xo3
         vqazU3QlbYsv0kLmOm5+gVmp7zIp6ceLa0dl+XzBnXnfFVU5YBn5qpmcq+76oIQpsL6s
         We+asfsu/SvHIA3X/vNZqdi922LL39GKdyUrozZrIXO9sT4sfg82I3ZU9jN1pN8fOXMp
         5by7bCxfUnY6g/0tU/Q4ovsMWchSWom4LcBTPALAEa+y7vlNFV3wOoqjL4CvJyyfze6i
         MapVGmHdbuff6KGPri26V7o3GYH+0eP/W4qcOf3rFWZerb4mKd1hyjfws1PeFCpTzjzF
         lABQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JZXgsRV6Gomzabp9pwlZu7hR1KyUHYsQGO3zbRxoRco=;
        b=magaZB/HZ5oG6TZwqKMmrM3FeXrOSxSuQ+tXauzgbeuSr6A9zSU0ltThztmgivbFZL
         6CfnK8XJQqxwC/Pr3ID3v7WkbkLVZO///1KQ1lFrPNlm1c9gyXfI023SzCqmyLgZAAb/
         aMTLVbeAElqlgklbqj+Ir8FZBcr4hQ0iJF8Gq0EtG8MQkfrGY1b2Xw9d9SgLShWIwyY+
         Z5Rth+uQVxbigsIcAMBQhTfJ4IQf7nNSEDcnB2M4elLlmY3dyqznxSVk7Bcjtk7QOMlR
         crWkajSrJ+pWymlqjxrnGpDHNqdLSTwEUMBMESLmr46DqDmODTZBryyU+eFU3tbLxeqr
         jAQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="m/nic/1g";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JZXgsRV6Gomzabp9pwlZu7hR1KyUHYsQGO3zbRxoRco=;
        b=hqs8eOwXlMlNmc76b9+SgGk2cSY9aJSgqiMrs5gbhOMCPmzV1q+c2mRPxj+1Kvs38I
         r89C+I+bFKaNFhZOzXGNyKWZJMviVcqhlerJZlaewequQtZnf4VHS+AImI4v3SgzKr32
         sH4u6H5w1ei/SIWY3ZGyuCIDkfTe0ebqB2GfDKvdf96Zxpx67n64Xo7oMbsubp3k2DBB
         Qh046C3Jk0Y8LjY3vM3LFB4fo87wmYe9nrOPZYS9NRCiRuTUG31qgNDd3M34AbvznB0n
         /aIUYcZobFeDx1h6S6IgrqwJS3tXPYZocNLZDMQK6hfWwIJojI8EqSgsYqtNIgJutZJr
         zrdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JZXgsRV6Gomzabp9pwlZu7hR1KyUHYsQGO3zbRxoRco=;
        b=PND3RKrxQNpRohytwTbltxtjyI6CZpizct8eSx9PEYOyY5cMk1gVrn47+mSHSImbZf
         Dr3X/lhstdTyA5oVCLKUcsS8FYapvW1Y6EKVbpXespm9pFNIStoEbqrM87pswBn81uOL
         zFOqsnIYFi9AJXHWvbRsxuEk3SCp8T+XY2MmH34p6b8JhXeZ85uAl0B4R1X6JvlnmNNA
         Buo4zPhlINFfffDB/4vkWKaHJXCRtGbkv4xOvIgx0IL5UgPnlIGZ298V0gl5lI9a4P5/
         J9JnZxnthFQdz+iqS2T+1ejBR9f7CkRFWyb8PRPKK2gEVrM4a7VodPy3QFBrDkWCwvPv
         9+Xg==
X-Gm-Message-State: APjAAAVnZwKvHb9hUti+iBm9IV47ADApYdfLbTbyhG1SalU7bjtB5uLc
	krcIfvkF8RkRiMbM/czXK5w=
X-Google-Smtp-Source: APXvYqxxl8Om7u5/BdC8H3jl2u9migNMSjt15gEisp08328SX3q95LClXvtkFWftp6NNX0eDo6DNwg==
X-Received: by 2002:a9d:4008:: with SMTP id m8mr24732143ote.200.1560772689529;
        Mon, 17 Jun 2019 04:58:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6c1a:: with SMTP id f26ls2958512otq.4.gmail; Mon, 17 Jun
 2019 04:58:09 -0700 (PDT)
X-Received: by 2002:a9d:744f:: with SMTP id p15mr4183452otk.287.1560772689263;
        Mon, 17 Jun 2019 04:58:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560772689; cv=none;
        d=google.com; s=arc-20160816;
        b=EYAhBWmSQuc7gEUj2SLlxyBn4u1CxBQOu/eCuiv2X6gqGXiMghVnZjGx9o4ZU6Eo3Y
         lUViEMsv/XY9PxcNI6ktc7dr99DaYlmFGJ4LTqsulu34edSEsEDtgaNjhD1kuct+rpki
         5rhmqt4o3oS3OhSOJkIjZJSgJpACXoocJUQcrUP5LCYlcPWX7mAJYXIp7Za2ej/FCGKm
         WLO+hA/WAq1JSt0JWaZbCfh0OeeuIWkhyjuiGgJPeR1a+Jt/3olEJN5EAC0KTC1kRIDs
         fDVbW+o39x+hz+9PobVx4sOu0e3twOH1kCa4JMjhwwtCimg3TrxnTudwzCi893iVnbzy
         K31g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ueOYS1wFyeCCBxDCVsPVG5+an3vWjzFueCDlI0BJDTQ=;
        b=qmKCCZ4lyWg6iAHH/54ZMfd+zo7+bQWwDor87CpYTHUXXWyms4iWT7yiEfQsSVSRfK
         E9/eBEf0GXhrhFfChvrhjKunXiMo7mW/Kq9/MbwB7FF9tLMAb77GgrhgtqhpajPW7yVz
         vhvh6/ps8IOPUZaeD96zHhdplyYHmdQfebLylSOI0aZT2HsjIdTbUUBBpO/Ox8x+PQ2Z
         hjKQfUdgFZSZCkvHhNbGNcQ/uXEa27kqPmUGrGQwg6vHbjuTZW3CnfQV+Qx1v1Z2fzmy
         W0y5Mwcq7XYweF2VeXrNNKAtgvdhmDN14Yh2vynjWkrt9FjvHAuvSLwin9FynNnP+FcL
         ziPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="m/nic/1g";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id a142si673405oii.5.2019.06.17.04.58.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 04:58:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id s7so20410375iob.11
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 04:58:09 -0700 (PDT)
X-Received: by 2002:a6b:fb0f:: with SMTP id h15mr2795600iog.266.1560772688590;
 Mon, 17 Jun 2019 04:58:08 -0700 (PDT)
MIME-Version: 1.0
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com> <1560447999.15814.15.camel@mtksdccf07>
 <1560479520.15814.34.camel@mtksdccf07> <1560744017.15814.49.camel@mtksdccf07>
In-Reply-To: <1560744017.15814.49.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Jun 2019 13:57:57 +0200
Message-ID: <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="m/nic/1g";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Jun 17, 2019 at 6:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Fri, 2019-06-14 at 10:32 +0800, Walter Wu wrote:
> > On Fri, 2019-06-14 at 01:46 +0800, Walter Wu wrote:
> > > On Thu, 2019-06-13 at 15:27 +0300, Andrey Ryabinin wrote:
> > > >
> > > > On 6/13/19 11:13 AM, Walter Wu wrote:
> > > > > This patch adds memory corruption identification at bug report for
> > > > > software tag-based mode, the report show whether it is "use-after-free"
> > > > > or "out-of-bound" error instead of "invalid-access" error.This will make
> > > > > it easier for programmers to see the memory corruption problem.
> > > > >
> > > > > Now we extend the quarantine to support both generic and tag-based kasan.
> > > > > For tag-based kasan, the quarantine stores only freed object information
> > > > > to check if an object is freed recently. When tag-based kasan reports an
> > > > > error, we can check if the tagged addr is in the quarantine and make a
> > > > > good guess if the object is more like "use-after-free" or "out-of-bound".
> > > > >
> > > >
> > > >
> > > > We already have all the information and don't need the quarantine to make such guess.
> > > > Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> > > > otherwise it's use-after-free.
> > > >
> > > > In pseudo-code it's something like this:
> > > >
> > > > u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> > > >
> > > > if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> > > >   // out-of-bounds
> > > > else
> > > >   // use-after-free
> > >
> > > Thanks your explanation.
> > > I see, we can use it to decide corruption type.
> > > But some use-after-free issues, it may not have accurate free-backtrace.
> > > Unfortunately in that situation, free-backtrace is the most important.
> > > please see below example
> > >
> > > In generic KASAN, it gets accurate free-backrace(ptr1).
> > > In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> > > programmer misjudge, so they may not believe tag-based KASAN.
> > > So We provide this patch, we hope tag-based KASAN bug report is the same
> > > accurate with generic KASAN.
> > >
> > > ---
> > >     ptr1 = kmalloc(size, GFP_KERNEL);
> > >     ptr1_free(ptr1);
> > >
> > >     ptr2 = kmalloc(size, GFP_KERNEL);
> > >     ptr2_free(ptr2);
> > >
> > >     ptr1[size] = 'x';  //corruption here
> > >
> > >
> > > static noinline void ptr1_free(char* ptr)
> > > {
> > >     kfree(ptr);
> > > }
> > > static noinline void ptr2_free(char* ptr)
> > > {
> > >     kfree(ptr);
> > > }
> > > ---
> > >
> > We think of another question about deciding by that shadow of the first
> > byte.
> > In tag-based KASAN, it is immediately released after calling kfree(), so
> > the slub is easy to be used by another pointer, then it will change
> > shadow memory to the tag of new pointer, it will not be the
> > KASAN_TAG_INVALID, so there are many false negative cases, especially in
> > small size allocation.
> >
> > Our patch is to solve those problems. so please consider it, thanks.
> >
> Hi, Andrey and Dmitry,
>
> I am sorry to bother you.
> Would you tell me what you think about this patch?
> We want to use tag-based KASAN, so we hope its bug report is clear and
> correct as generic KASAN.
>
> Thanks your review.
> Walter

Hi Walter,

I will probably be busy till the next week. Sorry for delays.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V%2BPaZF3ag%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
