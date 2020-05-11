Return-Path: <kasan-dev+bncBDGPTM5BQUDRBLGT4T2QKGQEUTUDVLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FBB61CD69A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 12:32:14 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id l26sf6484598oot.21
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 03:32:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589193133; cv=pass;
        d=google.com; s=arc-20160816;
        b=s6wfA35k1pKhyGfO2+4OvKKYBSlLMt1ZTt9WeelofRUWhuKMBXuxOKHbPtwdjNP2/4
         zxb6PLuwVVtH+td7Dd5RxXTS+SA5itJd8Dg9IbkrPWHsRdM7C2yJFjw30iA59akPjEi/
         0p4ZWflfn8WrYTbs+hHV/kpfsRkAGbQjd5tFqeWIUlv/P3EZfafuipHcY7J5CI95bVsr
         N9wMxHoxafmDj9e6FdTCaIVSwe5Q726UVQf6pML/J5EmREbEMdHLyUJeAgl8Kf/i3pyR
         k4CCXTus4yDUK/nM8Fi18N5E8eOnyXGv51FgouVVpzswMOCQqi9rffqmxyREYsDMGwdM
         wq+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=LjJMvkg3HhuCmdmopqqcClDfg8gIkdp2GEQ9okr6FHw=;
        b=omcTbZi+TOwXejVlNiwAUqvF/FyL0j5sKZC8NKA38rq9kUJd+7hVSPaSvhlGOXw/hB
         g2WVOdRRh27gUkYJZU0wslO2xsp6+7Zet4aQz3Q0YyoNo9wgrIIkH4kbLaLmpukn94So
         cztt1J3AeE44Bp1d4j/m4hOR4W5cD5AVcBUeQhNh7++QaeMNkJMOqTWFtrr/MMrKCkq6
         VLFP7E+EC8IcAnXi8bZhZLoo/B/UfQ2xDw+gxcS0rmQ8OlpGIGUHJ5xzJ0QXmCU54HKt
         i1j3YZK8cHQQwpuZc9alz/NGY/CQMlxo42br0MVlBehQn9RDpbZ0nB2qes8tOMRPxwPM
         IZvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=aHHSCwP9;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjJMvkg3HhuCmdmopqqcClDfg8gIkdp2GEQ9okr6FHw=;
        b=o1tG4dkKhrptBIqJf5SCWITb87xL3xX9c+dCESNW4eORZqOHxGAcoEMFvLIyrAMUoI
         RvXi8MvkDD3XpLv/djkobWPLfJnOR0U+iG/DBqJvBkn5J1MfUKX97oZ0dA0Kx2l5lcWP
         w1/qj99F5117RrB+m2Qzh612JkPpfSRXoMMYmKh99Ea0vSWeolIrUyhIdSsen0ZsZoY5
         N7LLYRhb/WI05CpoRuODTemJRQH3MfIftQUvAS3xKgW2Sxi6nzvthn+Y4QWW95v/q64T
         GVxRD306MA8JefLhSGNMnvgwI+ohRAfauV6rEO2mm6ARy7cHl/KLpbZkJa2MRDk6Adce
         5Ekw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjJMvkg3HhuCmdmopqqcClDfg8gIkdp2GEQ9okr6FHw=;
        b=ngHgUvt6pDORmAujhjeoHTc+1c8KqMMhiyPswyTFBMDIwp4lmE1Y7tKKYpJkj2fpJH
         xEAn/mWRtnrrCm6BYKc2aR/U8bk3QT+FzMPS2ww6RQrC4dp6ujw7+agTkMmt0POzfxf0
         c+QhFpUWVXT97lebApDJjtn84aNDQhCEXbiEri7c1bZELTIKCLMH2jnUYBc3ZBTiVtL6
         IfKj9pYRbqwdOatkvkGdZzhuSWLbeas7oAkk/D1V2PEyeTgrc+L2INkFWZVZzrDqDWuh
         nqTD3Hjr4sOuqMX2B02u7uwvDWT6DA3Ytc5yEZ6UzAdVNlME1BwfoE5w8zlXCXCYNlSc
         Px9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaQOKvYGz/lWIEQsvRZJlwYf4AxkEvZf/dB7aI/2EwPoFvBYzSq
	ndasjC/vtgqX5gS+TjvrLPU=
X-Google-Smtp-Source: APiQypKj68D66iLUDgluz4mYl678bHcTxv+aR2jc2A42Ibskq/6sWQ5m0BoUZB901Mya0rNQ8AQPjg==
X-Received: by 2002:a4a:9c55:: with SMTP id c21mr13081937ook.25.1589193133045;
        Mon, 11 May 2020 03:32:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1de1:: with SMTP id b1ls1904763otj.9.gmail; Mon, 11
 May 2020 03:32:12 -0700 (PDT)
X-Received: by 2002:a05:6830:138c:: with SMTP id d12mr11173249otq.161.1589193132689;
        Mon, 11 May 2020 03:32:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589193132; cv=none;
        d=google.com; s=arc-20160816;
        b=IquXYVnZ2aGzM2T6saS6/1W0wKNfrT5/uDiwCqRGBp2Qn9RJxcLyY/XTcKncaOxlAV
         23Qm+fwlUULJcKkkpD1ANiklKxQ80UM1V3htIxPeGO03PEJEpbkTotXRlU9DzfkjXuf9
         6JjeRXGfyjVo4H0aag/B6SF+1TB0jf6ZzBBaC0t6Yn4WuRjjpiyczXfxPB+aBNJ7zGXt
         Ds4i2nZHyw6pOgwmkJOF+iwGNQU9nvZm32Q/SS1ut9u0KOysmibdFbFv5mn8GALFLU6H
         TjYXOyb8bKRLzr4wkB/DJ56ZZhpJuGd0RVhHC1PtpZ6kflHRcDrkAZgY+XSN89Xulir7
         56xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=1U5wzqzVt4EBKPbHjQ+DbeiJr8CenT4487+ft0swDlU=;
        b=ngr4ybELI1wLcU067XGUfqYYc2KHnRed8rzIyAUPMIeWsksbQGKn7ez44ADUK5Xx7A
         xZsnHEwN49E5zAts1+BH9CDz39oDuvMp/4dJnWbf5JoZdp+uBoiPy9tkxOKoQ2QY0sJU
         68grgex38XXLpnBaGQgJ/8Q4EMxr59vTGl8u2C+6Vuimw2v0+9kyFw26Hh11jfqU+amO
         EtxryIMJrC4ywm8aOKOEHa9VqjnuelGlLv2CwLY9Ovgbgzlf8BLJBWUVzLgULZ01518I
         YiyCPiHP1UxHmn5gEHi9I2Z2h0m4xzFY+JY7AJUqMCb1u4ZR2v6woWJ5wmjtsV9LWRDx
         Gh7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=aHHSCwP9;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s69si1156159oih.3.2020.05.11.03.32.11
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 03:32:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 389c227b3a9f479087f09aec2c7d96d3-20200511
X-UUID: 389c227b3a9f479087f09aec2c7d96d3-20200511
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 424622642; Mon, 11 May 2020 18:32:08 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 18:32:04 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 18:32:04 +0800
Message-ID: <1589193126.2930.2.camel@mtksdccf07>
Subject: Re: [PATCH v2 0/3] kasan: memorize and print call_rcu stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Mon, 11 May 2020 18:32:06 +0800
In-Reply-To: <CACT4Y+aC4i8cAVFu2-s82RczWCjYMpPVJLwS0OBLELR9qF8SYg@mail.gmail.com>
References: <20200511022359.15063-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aC4i8cAVFu2-s82RczWCjYMpPVJLwS0OBLELR9qF8SYg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=aHHSCwP9;       spf=pass
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

On Mon, 2020-05-11 at 12:01 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> On Mon, May 11, 2020 at 4:24 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > This patchset improves KASAN reports by making them to have
> > call_rcu() call stack information. It is useful for programmers
> > to solve use-after-free or double-free memory issue.
> 
> Hi Walter,
> 
> I am looking at this now.
> 
> I've upload the change to gerrit [1]
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458
> 
> I am not capable enough to meaningfully review such changes in this format...
> 
> [1] https://linux.googlesource.com/Documentation
> 

Hi Dmitry,

I don't fully understand your meaning, our patchset's format has
problem? or?


> 
> > The KASAN report was as follows(cleaned up slightly):
> >
> > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> >
> > Freed by task 0:
> >  save_stack+0x24/0x50
> >  __kasan_slab_free+0x110/0x178
> >  kasan_slab_free+0x10/0x18
> >  kfree+0x98/0x270
> >  kasan_rcu_reclaim+0x1c/0x60
> >  rcu_core+0x8b4/0x10f8
> >  rcu_core_si+0xc/0x18
> >  efi_header_end+0x238/0xa6c
> >
> > First call_rcu() call stack:
> >  save_stack+0x24/0x50
> >  kasan_record_callrcu+0xc8/0xd8
> >  call_rcu+0x190/0x580
> >  kasan_rcu_uaf+0x1d8/0x278
> >
> > Last call_rcu() call stack:
> > (stack is not available)
> >
> > Generic KASAN will record first and last call_rcu() call stack
> > and print two call_rcu() call stack in KASAN report.
> >
> > This feature doesn't increase the cost of memory consumption. It is
> > only suitable for generic KASAN.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> >
> > Changes since v2:
> > - remove new config option, default enable it in generic KASAN
> > - test this feature in SLAB/SLUB, it is pass.
> > - modify macro to be more clearly
> > - modify documentation
> >
> > Walter Wu (3):
> > rcu/kasan: record and print call_rcu() call stack
> > kasan: record and print the free track
> > kasan: update documentation for generic kasan
> >
> > Documentation/dev-tools/kasan.rst |  6 ++++++
> > include/linux/kasan.h             |  2 ++
> > kernel/rcu/tree.c                 |  4 ++++
> > lib/Kconfig.kasan                 |  2 ++
> > mm/kasan/common.c                 | 26 ++++----------------------
> > mm/kasan/generic.c                | 50 ++++++++++++++++++++++++++++++++++++++++++++++++++
> > mm/kasan/kasan.h                  | 23 +++++++++++++++++++++++
> > mm/kasan/report.c                 | 47 +++++++++++++++++++++--------------------------
> > mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
> > 9 files changed, 149 insertions(+), 48 deletions(-)
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511022359.15063-1-walter-zh.wu%40mediatek.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589193126.2930.2.camel%40mtksdccf07.
