Return-Path: <kasan-dev+bncBDGPTM5BQUDRB6MJ4X2QKGQECZCEYGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id D140D1CD9CF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 14:28:42 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id mr10sf17208630pjb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 05:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589200121; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z5CkBFFdl2rSIcz7V/Pjo9bC7gD7R8QY3hpcYWLePuqYTmCNRjSeNMwtS/KhIAJsTX
         iT6O85vY2BECSOaasOIS+T/ukFpCegZ3qlrAI3mw+GkasiK9bIeEhbeOGI9SlRCebUp9
         SCMWekdRl90WQ6f+X+hkC1U17HjEspx0qfpthUd1iiLbApkoC37Ea9o0jWXoiifKEHUS
         ZMXdG3GJRn5a0OlNipZnwYH6v9b1YzhP0HwDW6XqDW5ee5sIPixEkCJn9uEgRDMGTKIn
         HhSOod2TQgeXGSrPbhcJZBSmQzz+cm45Bcc/TylbdNv1+ohABfR3R18VEI1/W3yZVQj+
         pqDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=MjMcGQBsnk4o0ANFu/EqsNaJjN7MEkZdLklmXH/Wis4=;
        b=VJLwFRPcU5wrFBlqSv6+cbm8ufwkzLyvubPcLm3nHOrsvDNhcr0+EeX0xY8DH3Dq39
         YCp1IKvKk9vJcj0qfUVsiCvGmBgCSmlkO+PzyYJ5JxfvF1r6KwquaKNxloWXN1OApQdV
         0KdqHfxxg08tP3HZcGJJIK0hOjWm0wbDnhjnh2kbNSi+Wg6e924uzk6+5/NzdHrnwScE
         9Z3VvbphM4qPTmOjbOV6pkxA9Em4y2D4H3JVTi0yXs3x2CHifGDgUgLP1DJRZbsD7WoO
         J7iz3IHcN8tbe8uEpug4ajn7m6vwUUbqdnsd6XFRFxE2FSfwG8kdFYXhSqrIOwwLfPrO
         igEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ukbStsI2;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MjMcGQBsnk4o0ANFu/EqsNaJjN7MEkZdLklmXH/Wis4=;
        b=k/zOHrbsOMXP6R6eSprs/QcgKO4JfvTirkW5eA4WW3Uu6N+MBQnOwoc6yWfi2935Vl
         PMk3dKrGWRPHAPaVYbSh4Vj7dQMMLIQJhZTEkdCGi9psGZIURKeJ6BMoMmMW/ilidBqZ
         8pHhI47JNupbyoAV6Y4sdpxm/jCqH4ycaUxpPNWPTLVIjgG1jVxfClFbJl9ZN7xD2uJv
         SrezalVE3SR8s79mjISqssw6STj/WOBZmjguUwr6oGI3hB22cn2oeiaY5rqNFgx2b925
         kmz1moW0dVkmHs/WpfNZQb8NkBY+juquLU4R1IA3A4D9pyLOI4a5xr+vXbgtAhOYRSgc
         pFgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MjMcGQBsnk4o0ANFu/EqsNaJjN7MEkZdLklmXH/Wis4=;
        b=MfMOjFdyDClFGB+kWwJTRbPo8bbiQdC/+c/o8iNR6OJTVXni1tgr5z+M0MUOoOsPAR
         rnx/2YycES22XVWC3TopxZRy+og+/YgBa+6oQZS+Mr+KA9bZIcri4amSE/uK2N4mdXWJ
         WbnIaqKJuj4REtQyV+/Pb+4bEabwuLZsLyXuRJh6Qscz5WehoKHQT8cx0l+qQk8Ek7lM
         jGE5t+ZUS+a+2ZIG5MOQSSTAeD89OiyfCtnnsCWtXeFJBfGRKlMdJy7E77aupaBYVN3Q
         PBvPq7/LAKJQzfu7KBY2+UlK24WClBYoYATwknmyLLvM2xYUrEKacGfPxgNmRFt2EMr5
         xkOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub/LSYBdZUwbLCXignra4eg0/6JAPs+d550qoYomsGKuHWru1t7
	mTEvEvaCJ0XGZYGHFd67TOY=
X-Google-Smtp-Source: APiQypL+wwip4JG0K7e1L8oCVzjabdDK2aP3oMWseczBou3jYkgjOXJYQLo+lXYsnelzOzA/GI65Cw==
X-Received: by 2002:a17:90a:362f:: with SMTP id s44mr23969977pjb.156.1589200121473;
        Mon, 11 May 2020 05:28:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9117:: with SMTP id 23ls4619848pfh.0.gmail; Mon, 11 May
 2020 05:28:41 -0700 (PDT)
X-Received: by 2002:a63:33ca:: with SMTP id z193mr15060491pgz.210.1589200121055;
        Mon, 11 May 2020 05:28:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589200121; cv=none;
        d=google.com; s=arc-20160816;
        b=l9KdhqcLcVfWjg/Nn8x8xnpu7iZSnHwGPL/PSl1aUczqCjMCOdKCae5OugRgLYZfTK
         s3e+JFFSyzceP7PFrWnHuhTas074HxXsftzuD02Br8E9uIQwUffrPLb0KbvOSOL1ZPPG
         z1AE2fWuqQn4hc1JAPq/H/8CFxF1vFRDc/k8ex58ElpLOrSj7LDy8Gf4VLVK9H7Ww9S/
         heqN8Dkidz1j0VNyba+tUlu78Ng5r3ZRfFsephnIgIrHt4CWAcDdEWTZrSRK1iYRWZNS
         3J+bLiwNJ2A4G/nq4XkZHBveItWsIwU9frJVd/BpoB5diqiQVO3TDYxEFY0Wgett+EoS
         4BTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=NvUFl/nyWMQtSLxtEhrYtJGTbhQ4+CaOKOoibXsqZ3A=;
        b=BHlPOBDz6bgHqtimvU+3UA0QSU0jrI2mXqwjPEkp4k3V9WSl8m19Wo8nEGvE5gSxcl
         JztA5DMzfTtMMqmTl70yvtj41tgTzExs/BknZTb84BOIrsAVGs5/9J9rnjCESC9M+rBF
         8QLXuOYxaJpC0LeY9qPOCVHlSUipXsKMq9Ov5viDC29E6v8x3XO5zf1J2uh0sXrD6FXb
         QzUP0CunRQt+Eyv96VQnnGNpGKmu0B5wOi1fBM84jGgOeqzZSMu7CBfCyzFbwfvQJQVf
         o5Ubmk/BhkXqsXNZUH6Ou0wsMYIWK4SbODwV9lcuHgQ1ua1GEWMkI6gSEdcxU/RMaF1o
         y9Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ukbStsI2;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id ft5si760912pjb.3.2020.05.11.05.28.40
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 05:28:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c510657845044662adc2d050132d111f-20200511
X-UUID: c510657845044662adc2d050132d111f-20200511
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1099670116; Mon, 11 May 2020 20:28:36 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 20:28:32 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 20:28:31 +0800
Message-ID: <1589200114.12504.8.camel@mtksdccf07>
Subject: Re: [PATCH v2 3/3] kasan: update documentation for generic kasan
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev
	<kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 20:28:34 +0800
In-Reply-To: <CACT4Y+aL_R4uVFugsj3wXeXw2oXbe6KQ=YmwD0jCrUH_12ouiA@mail.gmail.com>
References: <20200511023231.15437-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aL_R4uVFugsj3wXeXw2oXbe6KQ=YmwD0jCrUH_12ouiA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 290DD9A3B46DD6EE89CC5895CB5144E598E477F52EAAE2AF1A33C4A1185399602000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ukbStsI2;       spf=pass
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

On Mon, 2020-05-11 at 12:52 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> On Mon, May 11, 2020 at 4:32 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Generic KASAN will support to record first and last call_rcu() call
> > stack and print them in KASAN report. so we update documentation.
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Jonathan Corbet <corbet@lwn.net>
> > ---
> >  Documentation/dev-tools/kasan.rst | 6 ++++++
> >  1 file changed, 6 insertions(+)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index c652d740735d..d4efcfde9fff 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -193,6 +193,12 @@ function calls GCC directly inserts the code to check the shadow memory.
> >  This option significantly enlarges kernel but it gives x1.1-x2 performance
> >  boost over outline instrumented kernel.
> >
> > +Currently
> 
> Currently is excessive here. Everything in the doc is about the
> current state of the things.
> 
> > generic KASAN can print call_rcu()
> 
> s/can print/prints/
> 
> > call stack in KASAN report, it
> 
> KASAN is implied for "report" in this doc.
> s/KASAN//
> 
> 
> > +can't increase the cost of memory consumption,
> 
> It does not increase only as compared to the current state of things.
> But strictly saying, if we now take the call_rcu stacks away, we can
> reduce memory consumption.
> This statement is confusing because stacks consume memory.
> 
> > but it has one limitations.
> > +It can't get both call_rcu() call stack and free stack, so that it can't
> > +print free stack for allocation objects in KASAN report.
> 
> 1. This sentence produces the impression that KASAN does not print
> free stack for freed objects. KASAN does still print free stack for
> freed objects.
> 2. This sentence is mostly relevant as diff on top of the current
> situation and thus more suitable for the commit description. We never
> promise to print free stack for allocated objects. And free stack for
> allocated objects is not an immediately essential thing either. So for
> a reader of this doc, this is not a limitation.
> 
> > This feature is
> > +only suitable for generic KASAN.
> 
> We already mentioned "generic" in the first sentence. So this is excessive.
> 
> This paragraph can be reduced to:
> 
> "Generic KASAN prints up to 2 call_rcu() call stacks in reports, the
> first and the last one."
> 
> The rest belongs to change description and is only interesting as a
> historic reference. Generally documentation does not accumulate
> everything that happened since the creation of the world :)
> 

Thank your for your review. I will fix it in next patch.


> 
> >  Software tag-based KASAN
> >  ~~~~~~~~~~~~~~~~~~~~~~~~
> >
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023231.15437-1-walter-zh.wu%40mediatek.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589200114.12504.8.camel%40mtksdccf07.
