Return-Path: <kasan-dev+bncBCMIZB7QWENRBOMO77XAKGQEMJMJXWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id A1B5E10C941
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 14:10:18 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id v71sf11992369vkd.16
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 05:10:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574946617; cv=pass;
        d=google.com; s=arc-20160816;
        b=gXh/+mSXuv+BTn1viOsUlzf1UtYpGiO/JM12RmhJ4xaaCnzTWhFF40P9RCModYBAKw
         E7ID9dfs/cRW5dp/pcofxHflblHHMEf/j5YfnZ162MWuNYJDI3Wto29VGqFfztCZJfHZ
         mB56LdAT6uAZuwNHLQN2eQWnYGCSGl2VsrTu5C5529f6ndauj5MmSKAbrlHoTV9S3f+a
         9U8XmksOO0rKfWdc2DLdkLLdyAK90H6HRF8AK40fpjsFSGn++9UT61LmisSbbnDAzouz
         +hsDl9rR4U/+J7PotM8mj9DxkD9GBQLAkBcSarZ/cBJjdZBC8ftZ+jQUAop2GEtYJACT
         mwQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R66kLKawyD/CfovPq/4y9aXpcc2Kyk06zrOb1sY4Quo=;
        b=m7G7ZjYYWXKd/Ok359WCK3NkedNVR+J7/RUhhgONrQ8sFZLbJuU12TlInXqAvqx74t
         b1EQzwqkBw3AFXG7IICzjp4eKNDq0YXFYhACAUbiP1MYgnsBBoMXaO2k0YztaBrYOf1m
         /nAQg0uN6nSHLOX0qa7bl7dSdNtYcVETeqQwFCGdjUlPM2xrxR7zUX5vonFpZCnGZYsB
         NBPIvVVyKiN1hMRmvBjYC1bPk8xIieULPt11dpw1p2VAkcYWojfpFYLmUc/maOHPZvl1
         6vr1fV9VtFhSAs7W9eM9kT2RRPIPmPJ9VKhE1Fcr5nqcfGIaGDGHEFw1N+gemj2aBtKX
         lauQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c0fy+grX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R66kLKawyD/CfovPq/4y9aXpcc2Kyk06zrOb1sY4Quo=;
        b=BVm1TRjtOCZnMEQQMB603cYzmSUlRBGR5b461PtHw17eF24PwrJfiHgNUt6jCIq8gr
         Zoca7uVlNlvMowNW0/sOPzdjiW8TrhX8y9yiiHIkI/IzfrUOTYnFkVhcLwMxL2UdCFBq
         6OBsPny8QsFDhWnj6MVArY2qeGC+6ngQbXuh0/akQDRn7N/6kt7YdIv/alfLTLWP/uZk
         vh/f7WCIKDIrC22i97OBh2h1e3v74HXJM41UVU5oYd8Lw13IzDteotv/i4SdaK10/dEE
         J2msdADV10qFAY1Austfpg75GLfgxDOqrisyiZ/lTrQ66XD1PjU484qbvdhu8nNPHOiI
         iqEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R66kLKawyD/CfovPq/4y9aXpcc2Kyk06zrOb1sY4Quo=;
        b=KCg5KggfjdPXOCKFrHtP7cEKSvm8GqIB+Y6wyWF83rx74t+i/QWwLAiAbHqBdQOCLq
         nQJ+DfzRPfP6gOKyRSebAj3NPT2/g/g5LXb9tNF+4mbKw+WE8tULgq+7aQTjRHxJNh4K
         zk9U83d4r4eOslcVZrHpeOFWJQ76HPSHXVimsq0sFqwGkJIZG442Ta3O3SuypznAI9Kw
         s+sNFNtYKxzm2PjFIe35HZWgEfsx+iWS1eU75yxMg+jYql+IrqLcTOgZzG1HwoRzSZYn
         udgbw+71opyO5ojxMsavMM8hUreZaHkpCrj8iMmUDcaYZPbkc0PH1mDmszSHmywlUTP4
         D3tg==
X-Gm-Message-State: APjAAAX5PBKMv/T11a8HbwCZ3A9B2Q0mFNBK/JAw2MM9xOCWEpxQs1Kq
	MDbSOZsPcA4/7Z0g9oGDS2M=
X-Google-Smtp-Source: APXvYqwjZEo6c7V0BuMEGKccuu7mc2KQcXdZfXIwyKQCg6de92nvkkF5iMsK9nHQq/nnoQoiiRsQuQ==
X-Received: by 2002:a1f:2b0f:: with SMTP id r15mr6235733vkr.91.1574946617558;
        Thu, 28 Nov 2019 05:10:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c107:: with SMTP id d7ls132759vsj.16.gmail; Thu, 28 Nov
 2019 05:10:17 -0800 (PST)
X-Received: by 2002:a67:e9d6:: with SMTP id q22mr30016679vso.231.1574946617197;
        Thu, 28 Nov 2019 05:10:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574946617; cv=none;
        d=google.com; s=arc-20160816;
        b=UwuFt+tbLDIDvGObxPq8H88Q0nG6Ck+dyCuNi45KPAFdtenIPudr3wVJ8aPlnek6wx
         7P9KwK9cxWzproCydaxRuEdoRK5b1dg7rqQddjTlHKuFXsi5bp8F8kHlmsTIYdWfTwti
         lBgw7e6sa4tJgjJa/IReooPZEDGWKoHomcfgt1jlNuoz8idNu4HmA7OTeYg8iBBG9cLi
         g1+fH/Ra/cb+3jLfiN0m/TxfIjBS/6q0SYsg42rjFUScm7OgUbvUZGa491ekdUD5rZHq
         gkWDg5CRK7BUTLi8EeDVjJnYhTSIN03JfZUT7FUMNKneSg84jPL3uem0g7x/LDiqbdqA
         2yQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XzZgQRCZD+3idslgSIr896JIp//k3a3oW/TZHuinsT8=;
        b=mu7FXqos9IaxKOmWYRAJJVbWaTaL+BIpNo5a32msAp+XULPgEpE87N/MajTXApeRe3
         Y2KpKA71378gFvxxh+OphXC1ud0y52I6mWr0++2EFHzYAd6riKJ8g8k8MjmeU0cyBvoX
         qQimdbuKM1mygTNZ7g1SMqaKKZM41xHkKq9clJJ1HdOsWU0D49hGwoGvDB5Oen4bPuwQ
         XLusVBdC1bejWsXtO04Kv2x20ESSjFUR+epaly2rrPdeCW3N4LXj6ybUkLt0kBjgpxVa
         R5HN61WlXF4qpWxkvDOVngezNrqafvT7LkGRS6U30RQAoj4IZ+jj5RbTQ0NRC1Gb+7sb
         LwMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c0fy+grX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id h143si675076vkh.1.2019.11.28.05.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Nov 2019 05:10:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id cg2so10289669qvb.10
        for <kasan-dev@googlegroups.com>; Thu, 28 Nov 2019 05:10:17 -0800 (PST)
X-Received: by 2002:a0c:b064:: with SMTP id l33mr10887868qvc.34.1574946616239;
 Thu, 28 Nov 2019 05:10:16 -0800 (PST)
MIME-Version: 1.0
References: <20191121181519.28637-1-keescook@chromium.org> <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
 <201911262134.ED9E60965@keescook> <CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com>
 <CACT4Y+aFiwxT6SO-ABx695Yg3=Zam5saqCo4+FembPwKSV8cug@mail.gmail.com> <201911270952.D66CD15AEC@keescook>
In-Reply-To: <201911270952.D66CD15AEC@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Nov 2019 14:10:04 +0100
Message-ID: <CACT4Y+b7YtWw57C-1mv1z5bTSa9YpnwhKsgMAtpMuc6J8KXBUg@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kernel-hardening@lists.openwall.com, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c0fy+grX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Wed, Nov 27, 2019 at 6:59 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Wed, Nov 27, 2019 at 10:34:24AM +0100, Dmitry Vyukov wrote:
> > On Wed, Nov 27, 2019 at 7:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Wed, Nov 27, 2019 at 6:42 AM Kees Cook <keescook@chromium.org> wrote:
> > > >
> > > > On Fri, Nov 22, 2019 at 10:07:29AM +0100, Dmitry Vyukov wrote:
> > > > > On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
> > > > > >
> > > > > > v2:
> > > > > >     - clarify Kconfig help text (aryabinin)
> > > > > >     - add reviewed-by
> > > > > >     - aim series at akpm, which seems to be where ubsan goes through?
> > > > > > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> > > > > >
> > > > > > This splits out the bounds checker so it can be individually used. This
> > > > > > is expected to be enabled in Android and hopefully for syzbot. Includes
> > > > > > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> > > > > >
> > > > > > -Kees
> > > > >
> > > > > +syzkaller mailing list
> > > > >
> > > > > This is great!
> > > >
> > > > BTW, can I consider this your Acked-by for these patches? :)
> > > >
> > > > > I wanted to enable UBSAN on syzbot for a long time. And it's
> > > > > _probably_ not lots of work. But it was stuck on somebody actually
> > > > > dedicating some time specifically for it.
> > > >
> > > > Do you have a general mechanism to test that syzkaller will actually
> > > > pick up the kernel log splat of a new check?
> > >
> > > Yes. That's one of the most important and critical parts of syzkaller :)
> > > The tests for different types of bugs are here:
> > > https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
> > >
> > > But have 3 for UBSAN, but they may be old and it would be useful to
> > > have 1 example crash per bug type:
> > >
> > > syzkaller$ grep UBSAN pkg/report/testdata/linux/report/*
> > > pkg/report/testdata/linux/report/40:TITLE: UBSAN: Undefined behaviour
> > > in drivers/usb/core/devio.c:LINE
> > > pkg/report/testdata/linux/report/40:[    4.556972] UBSAN: Undefined
> > > behaviour in drivers/usb/core/devio.c:1517:25
> > > pkg/report/testdata/linux/report/41:TITLE: UBSAN: Undefined behaviour
> > > in ./arch/x86/include/asm/atomic.h:LINE
> > > pkg/report/testdata/linux/report/41:[    3.805453] UBSAN: Undefined
> > > behaviour in ./arch/x86/include/asm/atomic.h:156:2
> > > pkg/report/testdata/linux/report/42:TITLE: UBSAN: Undefined behaviour
> > > in kernel/time/hrtimer.c:LINE
> > > pkg/report/testdata/linux/report/42:[   50.583499] UBSAN: Undefined
> > > behaviour in kernel/time/hrtimer.c:310:16
> > >
> > > One of them is incomplete and is parsed as "corrupted kernel output"
> > > (won't be reported):
> > > https://github.com/google/syzkaller/blob/master/pkg/report/testdata/linux/report/42
> > >
> > > Also I see that report parsing just takes the first line, which
> > > includes file name, which is suboptimal (too long, can't report 2 bugs
> > > in the same file). We seem to converge on "bug-type in function-name"
> > > format.
> > > The thing about bug titles is that it's harder to change them later.
> > > If syzbot already reported 100 bugs and we change titles, it will
> > > start re-reporting the old one after new names and the old ones will
> > > look stale, yet they still relevant, just detected under different
> > > name.
> > > So we also need to get this part right before enabling.
>
> It Sounds like instead of "UBSAN: Undefined behaviour in $file", UBSAN
> should report something like "UBSAN: $behavior in $file"?
>
> e.g.
> 40: UBSAN: bad shift in drivers/usb/core/devio.c:1517:25"
> 41: UBSAN: signed integer overflow in ./arch/x86/include/asm/atomic.h:156:2
>
> I'll add one for the bounds checker.
>
> How are these reports used? (And is there a way to check a live kernel
> crash? i.e. to tell syzkaller "echo ARRAY_BOUNDS >/.../lkdtm..." and
> generate a report?

I've collected the sample and added to syzkaller test base:
https://github.com/google/syzkaller/commit/76357d6f894431c00cc09cfc9e7474701a4b822a

I also filed https://github.com/google/syzkaller/issues/1523 for
enabling UBSAN on syzbot, let's move syzbot-related discussion there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb7YtWw57C-1mv1z5bTSa9YpnwhKsgMAtpMuc6J8KXBUg%40mail.gmail.com.
