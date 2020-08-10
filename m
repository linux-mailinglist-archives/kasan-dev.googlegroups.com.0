Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNXTYT4QKGQEA5KBULQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1851124059D
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 14:12:40 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id u3sf6628328plq.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 05:12:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597061559; cv=pass;
        d=google.com; s=arc-20160816;
        b=QEfvCbauYNAI1am7Pvr2mlqVOopnLXayD5+uPTCdgJqWK5JrO41UatH6D9NREOmnQS
         38tuOXc3wRajYHDO3jY2P+bBw2DnXCixEmldUQVF8BGxezkiFt8ibrlI+6ztltB0ePVf
         Lsh5ZTFJZ6AQb8Ns80QLJKv4X/HOxQohSh7Fb33squ9yOcPQVRT42kqpSY9CS84CQxYW
         PCFTUmOGw4j+JKzEOSShCmC7imQiEvHiOrhRmHAdjRjzFxJpqJg/MCZT0mIqBv6xONf/
         cHdsimes9KXPNALOL4LPbNp5VzRjnDmd6v9Tsl/KM+NGvN7hQs19eH5wEb63XeTuj8VX
         LkzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=uMmrPQauU4E50sc6cjhdnNcDD4BhZKt1gbey/v5P78g=;
        b=MrW3vivkBIdHDeVbDIbTlAiWYDCcs6dFHQX6Z5q9BCzN7rMwL0CFBp4vxwO/uXe6Vh
         P65W9Za0HYbuwHTDZentTF+jthP2vdm8sYqkjdt8HYfPeNBLZg48ttVvUzWatlZHLqYd
         YvxUd7H8Sy+9tyLNRXybwNPdnB1QiWk2iVXEqkC49La3eHq1IuY/FzVGHHHaHfMX2UfB
         xZP7yBBvwmnM0aAureUFJ2TDHWTsdK/WBOeN/wf1nLlRvocQUhHivEb4D+GYdqQ+B0+o
         WqNMk17H5kIL6Uo5oFURidVxRf6PZuMdOEg816zEaScOWHUvc3/5gM45OcNN6KLBSETR
         gTOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cxIlhD2g;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uMmrPQauU4E50sc6cjhdnNcDD4BhZKt1gbey/v5P78g=;
        b=LgXUpaNLt+muyxJ5rByN9zSPtQPDyxMzl2rHE6StbTSGkhi1Tc5fhnveTPMQpkcxe/
         bTxqbQDvyrnawu5MnmTQPyM8i4hUVgh5jEfx/dmtuiKdF0LaYAbLIk//rCYLDK+qdzCE
         PEYub6P3rUhvrTmUVtQSbTB/+bl0n1PxL8z9OnYvgel7usTyAuK17X6AzHVntb0/G2ws
         vtx19rssCXCNQ6vJb7VdHx9OwwzZ1ogiKy6H8o3zi51OGeXlrUbfdMYIEP5/XcLR1Q32
         BCeJm3to82Y9SQ5wjAN1/zpzp0GO3sdNEKRMbjFvM3LTLrZ/htiQIU8J8XO2ZFLCmWkl
         sxWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uMmrPQauU4E50sc6cjhdnNcDD4BhZKt1gbey/v5P78g=;
        b=jQpXVbVKfluXyb3cyxIgsJqODRLVwdlCgOREZkp+aGqdIUDE/t5NhXd8Ga6veLxHX8
         Vb6uKK6p9QUxjHNeyIidgTfX6ebPnPpSkZ8SMPOwaZYy0K9f/onNMn0BC7mkajM5vekF
         IlajL8xgksP3YL7EKECWWWG8QyVwfwl9dpstCSIYnDin2lk4Lx3HhRljd6k0BukM2voa
         9vjwvGg0tqzN9X0an5VILvj2EFqZV5Nu14MBY66lmaDTe0sp/hODMsl46tUk6x+JY4gh
         yAqzLME/C2WJ6L+J6p2KASwt9Hd3G+VsPzQyxjlupUycyGF43SuGObYGiUIoSvJVbYxb
         m/ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320O0Ilkc1qnY0oBUoBn0WzzoVq3IOGWlIkMz4y1LLoY1BhHeAB
	N67Q63sKnxqEXib/NQl09Mc=
X-Google-Smtp-Source: ABdhPJyH50mxaGLkrhBYvgvnuZ8F4HHiaITtzcx6FHkIPsU6ewYWPBAGr+qDIK3D/YhzuNPPc15bKA==
X-Received: by 2002:a17:90a:eb06:: with SMTP id j6mr27218605pjz.227.1597061558784;
        Mon, 10 Aug 2020 05:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:88c4:: with SMTP id l187ls2277072pfd.6.gmail; Mon, 10
 Aug 2020 05:12:38 -0700 (PDT)
X-Received: by 2002:a62:79d7:: with SMTP id u206mr578037pfc.97.1597061558285;
        Mon, 10 Aug 2020 05:12:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597061558; cv=none;
        d=google.com; s=arc-20160816;
        b=lzUqP573QJHDZANzILcv+ymM6t2KNLsd7ahtJXinhu/Q9iiXpo4JNDcBaiGrXdO0mp
         UiQM9hPdY7wTT7XdJPF/21J2EeVvmHQn1j6MOjAHAA8n/mH+ErlTDTUCGfajwlEjjPs7
         l6C1zQnvCXOwyGovaDOF6Z8H1CLHPpLp/bFQN/BXj6GKLr6Y0hO86IWGz+OjTC+JQi3L
         ii8ApM7wpK6mJFVDOWBZj5dCyrL1y5FrvjhmEpnLb0Hgfmu7TskxmpDilIz4Jj5cbJt6
         QjDMtlOU6qbZQWu+XADj/5Q/IjHqlaI9wqJtjeDqbx1QSLSjgzgtPL0eMRYyVd4//4I6
         mj4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=85XI0r8gSm4pXV6KLRTXENKU7LoA4RXMZocUnSqxJRc=;
        b=pBCs8Rr5BoIxgvuT9fW1gKtP0oK+Ci3zr7GuIC+rbXrn29TD3wAT2UED2cm5Va3c0L
         9RNaIP8Kv8335joknbq6+8g0EdpxGbw1NOP1whNJSyZHU53m40vRw7BYnVsmTQbvfdUK
         QcZyiWqs2UGnBF+YT/W8UHs6Z7n9jXB3oiUhP29GEw5nQk7PL1qtkxp7HU5X+7KwM+4P
         x5M5WQqlaXlulmelO0V8H308Iany5bU1JcCY05l/Tcrsuk66bHN46sybecxY0HXTSwlG
         ReTlX03UKaBzz3xCr1AO+BCCFlV0tlXruRnY16WXSRzXrRxSKKpOVKPOyiSjf9tAFqyM
         1yVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cxIlhD2g;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id v127si961361pfc.0.2020.08.10.05.12.37
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 05:12:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c19a747bc3b34e1dacf458ee352624a9-20200810
X-UUID: c19a747bc3b34e1dacf458ee352624a9-20200810
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1866359265; Mon, 10 Aug 2020 20:12:35 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 20:12:32 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 20:12:32 +0800
Message-ID: <1597061554.13160.17.camel@mtksdccf07>
Subject: Re: [PATCH 0/5] kasan: add workqueue and timer stack for generic
 KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Qian Cai <cai@lca.pw>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, "Stephen
 Boyd" <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, "Tejun
 Heo" <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Mon, 10 Aug 2020 20:12:34 +0800
In-Reply-To: <1597060257.13160.11.camel@mtksdccf07>
References: <20200810072115.429-1-walter-zh.wu@mediatek.com>
	 <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
	 <1597060257.13160.11.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=cxIlhD2g;       spf=pass
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

On Mon, 2020-08-10 at 19:50 +0800, Walter Wu wrote:
> On Mon, 2020-08-10 at 07:19 -0400, Qian Cai wrote:
> >=20
> > > On Aug 10, 2020, at 3:21 AM, Walter Wu <walter-zh.wu@mediatek.com> wr=
ote:
> > >=20
> > > =EF=BB=BFSyzbot reports many UAF issues for workqueue or timer, see [=
1] and [2].
> > > In some of these access/allocation happened in process_one_work(),
> > > we see the free stack is useless in KASAN report, it doesn't help
> > > programmers to solve UAF on workqueue. The same may stand for times.
> > >=20
> > > This patchset improves KASAN reports by making them to have workqueue
> > > queueing stack and timer queueing stack information. It is useful for
> > > programmers to solve use-after-free or double-free memory issue.
> > >=20
> > > Generic KASAN will record the last two workqueue and timer stacks,
> > > print them in KASAN report. It is only suitable for generic KASAN.
> > >=20
> > > In order to print the last two workqueue and timer stacks, so that
> > > we add new members in struct kasan_alloc_meta.
> > > - two workqueue queueing work stacks, total size is 8 bytes.
> > > - two timer queueing stacks, total size is 8 bytes.
> > >=20
> > > Orignial struct kasan_alloc_meta size is 16 bytes. After add new
> > > members, then the struct kasan_alloc_meta total size is 32 bytes,
> > > It is a good number of alignment. Let it get better memory consumptio=
n.
> >=20
> > Getting debugging tools complicated surely is the best way to kill it. =
I would argue that it only make sense to complicate it if it is useful most=
 of the time which I never feel or hear that is the case. This reminds me y=
our recent call_rcu() stacks that most of time just makes parsing the repor=
t cumbersome. Thus, I urge this exercise to over-engineer on special cases =
need to stop entirely.
> >=20
>=20
> A good debug tool is to have complete information in order to solve
> issue. We should focus on if KASAN reports always show this debug
> information or create a option to decide if show it. Because this
> feature is Dmitry's suggestion. see [1]. So I think it need to be
> implemented. Maybe we can wait his response.=20
>=20
> [1]https://lkml.org/lkml/2020/6/23/256
>=20
> Thanks.
>=20

Fix name typo. I am sorry to him.
And add a bugzilla to show why need to do it. please see [1].

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D198437

> > >=20
> > > [1]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after=
-free%22+process_one_work
> > > [2]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after=
-free%22%20expire_timers
> > > [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> > >=20
> > > Walter Wu (5):
> > > timer: kasan: record and print timer stack
> > > workqueue: kasan: record and print workqueue stack
> > > lib/test_kasan.c: add timer test case
> > > lib/test_kasan.c: add workqueue test case
> > > kasan: update documentation for generic kasan
> > >=20
> > > Documentation/dev-tools/kasan.rst |  4 ++--
> > > include/linux/kasan.h             |  4 ++++
> > > kernel/time/timer.c               |  2 ++
> > > kernel/workqueue.c                |  3 +++
> > > lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++=
++++++++++++++++++++++++
> > > mm/kasan/generic.c                | 42 ++++++++++++++++++++++++++++++=
++++++++++++
> > > mm/kasan/kasan.h                  |  6 +++++-
> > > mm/kasan/report.c                 | 22 ++++++++++++++++++++++
> > > 8 files changed, 134 insertions(+), 3 deletions(-)
> > >=20
> > > --=20
> > > You received this message because you are subscribed to the Google Gr=
oups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, sen=
d an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/=
msgid/kasan-dev/20200810072115.429-1-walter-zh.wu%40mediatek.com.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1597061554.13160.17.camel%40mtksdccf07.
