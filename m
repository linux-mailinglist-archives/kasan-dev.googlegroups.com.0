Return-Path: <kasan-dev+bncBCMIZB7QWENRBBVE7XUAKGQEC2NKHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8754606A3
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jul 2019 15:35:03 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id a8sf4310940otf.23
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jul 2019 06:35:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562333702; cv=pass;
        d=google.com; s=arc-20160816;
        b=r5q2ze6qGXG7g7L4OXdBiBtfeaf3RjaXYYo5ZhybcPEZOB+Ocr6m4sn6R9XSHifwTy
         HD5ZWXdgRycxX/PInBS/MKA/uN5pY2Jc0B0DUPdMxdP8+ruVb2Q5ZWc/cJrT2fyJEJ1P
         joTtWl0xVHL+C9w5ZNgNcjMwN/lL40kVCZZvii+AL3J+FicIvdfQwp3ZjWV5SqptlPVi
         NSyTAp7JjhCyJRYnjx6cEE2irKRJm+baIWO0In24a7kPeoEa8hga5Zr/A6TAJloAAHll
         E2p6+DkKJTH4YWJnPTB+1ipUtJHCiXqkukvGu7MqZZF0TqIRHEGFsiE0XXOjvL1V3Qcm
         K5Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RFY4WJ5zfYpyxMPQMbAyTAhfQ+7k8kXebePv3DTGPJY=;
        b=Yc54zyRKqMT3vRS+bXFWe2D15vnUrUChbf+zAH3rNlfUlDMT+7O7y9yi8ixKOiGAMo
         fWP/pr6JsPNGvbC3oOCcDnpzyfa/kDIknnBAjuiJA23zBDHvfCEsTeG63HY4IO5x4afn
         xlvFxpl05coyadeaxldpDAP09aOrruxQl8bEWuIBuxyQx9DtQVvbfZnLMC1ZpuECWY1S
         P+21TqItERYaZiQoiiMI/KXv4qH14FPBGntcJFy4ZPaO+RsolOlEhI03A1/lcgxfvSfw
         hU/APEJvamWpRh8kYoG/ScRFs4vXAPs/wnb+YYPcGgkfKSSly3LtBS9H4GssAxR7VwU5
         0vfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lnxerxt4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RFY4WJ5zfYpyxMPQMbAyTAhfQ+7k8kXebePv3DTGPJY=;
        b=YdkqPG42NmMDSkJCO9WWIyjdaBQgEOLsw7C2mA4rCkhH+cBZKs7CdYLfj6RqbxDtuw
         EpqhQGxQPxYAY5qjLNKAj/Ye106DpIlTVt0PVf8GLFINJdV4qidcNFzpKyXH8zi+zNFW
         A2l+aAeTadTcmfvn1r6NlIv/shbstzkenTQn6VX9B3X03riw3ppMmMo5ROhbdy1y1D0E
         Udks4xGuFEx9wcquwq7B0dTxDfXq83CI4KzxIqehGG6pv3AlYnoG3LOpIgH4EuqiUywS
         xcF7/lqqa6K9223a4Znu50vEIjnatGN7siuldJWjkAki2G3zGehLeXk8hpPhvS9UuYh8
         Aw3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RFY4WJ5zfYpyxMPQMbAyTAhfQ+7k8kXebePv3DTGPJY=;
        b=sKR5NW9cVpiEfNH7Ir6NdvrEpfU+FVnvW+q53JjwJEi0xlpqMKWTshrsa7lrwsLJc5
         GOVHaW9D8kHIiD/lsj/RHIzMx2PmTeA0yujcbPyH7OW4tM9vNBtVUG/e3UnLoH9bo4zu
         WPjvN8bdmUXuH5rJ9UL5ab27B5hiL8+kCMgrk67O7/heRqGYOK2ALZIbTZYuf9d0CSrx
         C5VCRvWl2Ah0mFIQjkPAZEWGRORprxoTgQmmfw+YZ08+CPzI0QUCPV3IJfSyqowHPLzd
         FKHzvZ7N+XxIaebpdKhm4alPhJ706fVOp2n1211PYbWoeGSZib83/RSfFCqs8B+HtGOM
         dUug==
X-Gm-Message-State: APjAAAVz9ttQfRkIXjFh24tDgY9RbXdJmG2M9qLWA+6qrL0xsD9OJB6a
	L+ndlp1KJKz5o2WIzvHtDUg=
X-Google-Smtp-Source: APXvYqxOC1JkDY0fpcrgpyjn5+jyA0eCTTr8+WEP+t21rlmVU1AiyU4B1zATdYoTuy8CRFw43FsHEQ==
X-Received: by 2002:a05:6830:154e:: with SMTP id l14mr2712945otp.365.1562333702400;
        Fri, 05 Jul 2019 06:35:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3e45:: with SMTP id h5ls1645020otg.11.gmail; Fri, 05 Jul
 2019 06:35:02 -0700 (PDT)
X-Received: by 2002:a9d:6195:: with SMTP id g21mr3083931otk.103.1562333702114;
        Fri, 05 Jul 2019 06:35:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562333702; cv=none;
        d=google.com; s=arc-20160816;
        b=QzCFVLvyZ5F+KS+BZx39acFC1Pq+w84NEzIJeYgh8dJE1AHWUDw38mo26Ne2Z9HUgO
         JTFj62inmT/Tw0Frc3rDxSMJzUZJ6si1PFjRyneMSqVeajMJ+NPfjlVW5GjSlFPIpYhd
         7VPozSQTrupw9lCTmK6OnWwCZOHGrdfo7HxJ5L4EPOBeGpdbd8eaWOpKGr75Lx3o4SD+
         AhVGS5vBjs5/8P3MLP6YuS0e8JDf8B/HUvPxZ0lUD95muXulDUZGz4WBQB2dviZcbCT4
         AvYUXEOTxvy2bw9YW0fJ0aPZQNoQnpYR4NMphx40SGizl+4vEeSr5ghJsGOOsjhpHOnQ
         FYSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z1fWimE5LBhG/grVg6eI87RotqFb0roHvhFn0bvlYoY=;
        b=V/Q8ZQcVPUBGCorTcXu3y66Ii+dn4uOGiViELtudmJ8BPQJTHcLnO7LvVX5ygSshyM
         3O4ndbWzjlq/n/suyoWHxWRckm/XjlM9M2nZvwFsd3ejwg6n9IPs9B7jV/Uabltsnl2q
         1bIAA7OjxotzuXZ8L1R/RGid3bdRZzq/8zb1KWlHeMBAJAOJZgMtXh/CFW5XlTcN0Fei
         Kuiya6mkj5NDvfgOehIejKrFrQXp1FyPsAhSGDe0VgzxqzwM0XaJXiJSpUNb2bA0JYEm
         5Qe2EN0RO/dABmGwOeqG70yp+YL8mXDc6KtFZR4GAEiNLJaZqbvMzu7D2Ds/2NOhnSue
         ZDRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lnxerxt4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id y188si509462oig.3.2019.07.05.06.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Jul 2019 06:35:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id f4so3670523ioh.6
        for <kasan-dev@googlegroups.com>; Fri, 05 Jul 2019 06:35:02 -0700 (PDT)
X-Received: by 2002:a5e:c241:: with SMTP id w1mr4038131iop.58.1562333701423;
 Fri, 05 Jul 2019 06:35:01 -0700 (PDT)
MIME-Version: 1.0
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com> <1560447999.15814.15.camel@mtksdccf07>
 <1560479520.15814.34.camel@mtksdccf07> <1560744017.15814.49.camel@mtksdccf07>
 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
 <1560774735.15814.54.camel@mtksdccf07> <1561974995.18866.1.camel@mtksdccf07>
In-Reply-To: <1561974995.18866.1.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Jul 2019 15:34:49 +0200
Message-ID: <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Lnxerxt4;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44
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

On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > This patch adds memory corruption identification at bug report for
> > > > > > > > software tag-based mode, the report show whether it is "use-after-free"
> > > > > > > > or "out-of-bound" error instead of "invalid-access" error.This will make
> > > > > > > > it easier for programmers to see the memory corruption problem.
> > > > > > > >
> > > > > > > > Now we extend the quarantine to support both generic and tag-based kasan.
> > > > > > > > For tag-based kasan, the quarantine stores only freed object information
> > > > > > > > to check if an object is freed recently. When tag-based kasan reports an
> > > > > > > > error, we can check if the tagged addr is in the quarantine and make a
> > > > > > > > good guess if the object is more like "use-after-free" or "out-of-bound".
> > > > > > > >
> > > > > > >
> > > > > > >
> > > > > > > We already have all the information and don't need the quarantine to make such guess.
> > > > > > > Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> > > > > > > otherwise it's use-after-free.
> > > > > > >
> > > > > > > In pseudo-code it's something like this:
> > > > > > >
> > > > > > > u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> > > > > > >
> > > > > > > if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> > > > > > >   // out-of-bounds
> > > > > > > else
> > > > > > >   // use-after-free
> > > > > >
> > > > > > Thanks your explanation.
> > > > > > I see, we can use it to decide corruption type.
> > > > > > But some use-after-free issues, it may not have accurate free-backtrace.
> > > > > > Unfortunately in that situation, free-backtrace is the most important.
> > > > > > please see below example
> > > > > >
> > > > > > In generic KASAN, it gets accurate free-backrace(ptr1).
> > > > > > In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> > > > > > programmer misjudge, so they may not believe tag-based KASAN.
> > > > > > So We provide this patch, we hope tag-based KASAN bug report is the same
> > > > > > accurate with generic KASAN.
> > > > > >
> > > > > > ---
> > > > > >     ptr1 = kmalloc(size, GFP_KERNEL);
> > > > > >     ptr1_free(ptr1);
> > > > > >
> > > > > >     ptr2 = kmalloc(size, GFP_KERNEL);
> > > > > >     ptr2_free(ptr2);
> > > > > >
> > > > > >     ptr1[size] = 'x';  //corruption here
> > > > > >
> > > > > >
> > > > > > static noinline void ptr1_free(char* ptr)
> > > > > > {
> > > > > >     kfree(ptr);
> > > > > > }
> > > > > > static noinline void ptr2_free(char* ptr)
> > > > > > {
> > > > > >     kfree(ptr);
> > > > > > }
> > > > > > ---
> > > > > >
> > > > > We think of another question about deciding by that shadow of the first
> > > > > byte.
> > > > > In tag-based KASAN, it is immediately released after calling kfree(), so
> > > > > the slub is easy to be used by another pointer, then it will change
> > > > > shadow memory to the tag of new pointer, it will not be the
> > > > > KASAN_TAG_INVALID, so there are many false negative cases, especially in
> > > > > small size allocation.
> > > > >
> > > > > Our patch is to solve those problems. so please consider it, thanks.
> > > > >
> > > > Hi, Andrey and Dmitry,
> > > >
> > > > I am sorry to bother you.
> > > > Would you tell me what you think about this patch?
> > > > We want to use tag-based KASAN, so we hope its bug report is clear and
> > > > correct as generic KASAN.
> > > >
> > > > Thanks your review.
> > > > Walter
> > >
> > > Hi Walter,
> > >
> > > I will probably be busy till the next week. Sorry for delays.
> >
> > It's ok. Thanks your kindly help.
> > I hope I can contribute to tag-based KASAN. It is a very important tool
> > for us.
>
> Hi, Dmitry,
>
> Would you have free time to discuss this patch together?
> Thanks.

Sorry for delays. I am overwhelm by some urgent work. I afraid to
promise any dates because the next week I am on a conference, then
again a backlog and an intern starting...

Andrey, do you still have concerns re this patch? This change allows
to print the free stack.
We also have a quarantine for hwasan in user-space. Though it works a
bit differently then the normal asan quarantine. We keep a per-thread
fixed-size ring-buffer of recent allocations:
https://github.com/llvm-mirror/compiler-rt/blob/master/lib/hwasan/hwasan_report.cpp#L274-L284
and scan these ring buffers during reports.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaMXTBE0uVkeZz%2BMuPx3X1nESSBncgkScWvAkciAxP1RA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
