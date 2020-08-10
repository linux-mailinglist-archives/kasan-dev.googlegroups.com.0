Return-Path: <kasan-dev+bncBDGPTM5BQUDRBQVUYX4QKGQEU36DQ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46A3224079C
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 16:31:31 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id p2sf3028589vkp.4
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 07:31:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597069890; cv=pass;
        d=google.com; s=arc-20160816;
        b=yBPbJO7rPvxGFiWJ3rNiXuGBUYBNxVlGnqPgYQbWP2jtJnc/kJcahxkPXFU6U5Cfx7
         ep5mD4wz0HiwXMLeyjI5UL+yZAnBZg9TPcHmxjwRT78v1YStd+vS7k/UAA9gHTS96t+j
         OrGWL5zQ2cOY/4kWDnX3tQNrWU9RmfHpQA4rMYwSWaATYMMEmF3InUFMtZMTdu5iHV+B
         0lMhlOdtO3JxO902cJiGQrEMDsKIfpP9VloofmO+u9NNQmaECL8p2NDIriqnpsw0U3Ag
         l/of8JWVKLM6Z+1EQwRLAY2hDWmGaFVoBmZgAjxzNLBuelwTMcL7Sb07ZiA+YdJMOA3H
         qpyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=4ePjit3YhbFI+LEjJoDjtWUBsoxkvzbmvEar/ps+MjI=;
        b=nRHZWPO9wkP3Xcye4rE9mxPqZf/8d3kBhFzMumJRTqVXsBYcq+r1NwCuNKCt96zHwA
         K4ao9PpXZeZ3vPN6mcZ5Fsx/211SdqjjG1779aecQ0+l1Y5QSB+LupQHUu/AmmMPTyqc
         DwUTFGNkIh2eKtkw2/bmJzLQ1y0rqFd+Pp/xMc4W3wul18/Cxorqap0J5+iIX/qp7rEk
         Dnimva5N3yUHJefz4ghoA5IZuO0dRUXQbQTHiXatGRMKYcsjr3VtS56NDeddhrd9D+H6
         JgN9oD4iqtLzKuzfRcwtc0YpmRjZp9uCZqx9IM/aGRYWnHQYajA3x44jAs3MlE3ZA4vN
         IJCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=I8jCLxoz;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4ePjit3YhbFI+LEjJoDjtWUBsoxkvzbmvEar/ps+MjI=;
        b=IYFB+Xqj2Ftr2nHTNtJJQ6yAduNIN9LhqN6qosdJatLlbdE/jzPl4nEvVzHaJRAS+o
         X1Vg8CR37XeUm7ivwz4B2mrG/ljq+8vy286zbFDvBY5MP0B39Z2XLXc7ehvUEVHfgKE3
         yiUP4CiF/37s2QeWwVWmG+I1w1W/+JRVXYkfWzyje9zRLTFbIVshb+0M4d1vyIPsKwb0
         jpDGAOmYx83ad9LbHrI7VN0cWoFMYxXv0B/wTiM8a9e3RX4MgClauQMBSB3BBuIdHOUN
         iLcXg1KIkxI6WA2WvrmlcjitU4v9Y/QHWltx+cFnEKIb0jtQ+iASaLhw1ZKTYJvNjSiH
         EM3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4ePjit3YhbFI+LEjJoDjtWUBsoxkvzbmvEar/ps+MjI=;
        b=lXdqLukaDPkRCOUv2aCDFHC3VVhpKgwvDhWuoQ0yGhlPmu31rIG81WwJaOdEAhCNlN
         nnz+km77ftFK8yPwn2iC5K+O3DeQ0y+vy/esTHn5aqduHjT1MwScHA2G4tIXxEvAx5Ef
         pvkSuvQrmS6TTOuGAGwF9fOXq+hH/tY5XmozHmYsa6nu9SyiHs08e5GxJF92d9PNNlWb
         4R/BD5PkdIOGkZFa12sNC4a9eGgN05bN43d2SPqPCG1W9evczZgwt0sYKEErqaE8mJCF
         A5O9XuInO7iFZAs94kWbEAvZ1jnNoJfFFBGz3auVYTQXrzw8o/sDLbA4VNURPRS4ysru
         gWOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IbNUa5yN2+//mrzcO/07giZHHWutxqJbHqV5GU/EkMjAV0hpV
	aZyjD+xjJR7wCKELB5FJBVo=
X-Google-Smtp-Source: ABdhPJzknyUiUr5l3b45ZE+wEmuygNEVeKBu2hQmEpWE+CYerEutYTBAnWAUEaLwBMQLiAyRpV/EHg==
X-Received: by 2002:a67:6305:: with SMTP id x5mr19575756vsb.35.1597069890250;
        Mon, 10 Aug 2020 07:31:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:211a:: with SMTP id d26ls874519ual.3.gmail; Mon, 10 Aug
 2020 07:31:29 -0700 (PDT)
X-Received: by 2002:ab0:630a:: with SMTP id a10mr9629017uap.20.1597069889859;
        Mon, 10 Aug 2020 07:31:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597069889; cv=none;
        d=google.com; s=arc-20160816;
        b=jJ3HqTUzWZq0zHaLOvqu8ydC3pYa1BMCZhhyoEPnXWIfAonpJ8ws/IhBoHhbXZpfjk
         S2ujQP+wkmnBuHfQ3hz7jxjZxjq7GFVtRyDSIXTpRAUQaUujdQhQcHrcsVpeyNcLkZZ2
         akqC1d2ksoq9XPJ8LrCuLeftudtxU/0yJeK6MRuKYvwDnF5jyv6n46wOCStengiRvUz0
         i6d4QJcWMbt8779c3SBK+dXCLlcEnVozJYmT3zDW/DV6vA1Wycj0VJwfVKIYEEWa3dzP
         7/sQpIwoZf+Yp5CUxs4c3CvuEaMRdYMhHDKevrlo+EM6OW3knJltvqSWBgsy3mVNkzKK
         a7jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=mciTdbGtLyle7sIBwwbHIL1yNy/ps2mp3cRnP7R9hZE=;
        b=UfWY+JXupsV4KsT41Di6dfjZcEEOclTEKUyGRb7YbhLVW3WP8vRryuG3OmfPzR9Elf
         N4E/ujXLKUXbhZqycSBHk957zkMUDea5XTVnKW3OC7OaljpF3D/ghlWADibd5ynLDn6q
         lBt/srjkkZMcqME0l1/GtFq6pt8wotPzOnkouHowpsfow870NvYKU/Tu6i/G1CHyuDe+
         mPDavx36MVTRnivNoaFrrMk7F9VN4XMOq6gaNH3baW90b6Y5c5E3geEcHD96zyWIERWQ
         L6HAFuZDzgeIN6k2D/MyUSRNXr9P/cc2NEgEwva9vHyCYvA8Rx/9225Mx5AhNDeDTSOG
         StMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=I8jCLxoz;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id j18si848468vki.3.2020.08.10.07.31.28
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 07:31:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 11580f1edfbc424b8638dfc7aa78a283-20200810
X-UUID: 11580f1edfbc424b8638dfc7aa78a283-20200810
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1849710283; Mon, 10 Aug 2020 22:31:25 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 22:31:19 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 22:31:19 +0800
Message-ID: <1597069882.13160.23.camel@mtksdccf07>
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
Date: Mon, 10 Aug 2020 22:31:22 +0800
In-Reply-To: <20200810124430.GA5307@lca.pw>
References: <20200810072115.429-1-walter-zh.wu@mediatek.com>
	 <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
	 <1597060257.13160.11.camel@mtksdccf07> <20200810124430.GA5307@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 8A3A2465FDA3BD14C3B68297CF0BBCE39CBA5A54C6BEEBE1128F4E5F8A7680C72000:8
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=I8jCLxoz;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Mon, 2020-08-10 at 08:44 -0400, Qian Cai wrote:
> On Mon, Aug 10, 2020 at 07:50:57PM +0800, Walter Wu wrote:
> > On Mon, 2020-08-10 at 07:19 -0400, Qian Cai wrote:
> > >=20
> > > > On Aug 10, 2020, at 3:21 AM, Walter Wu <walter-zh.wu@mediatek.com> =
wrote:
> > > >=20
> > > > =EF=BB=BFSyzbot reports many UAF issues for workqueue or timer, see=
 [1] and [2].
> > > > In some of these access/allocation happened in process_one_work(),
> > > > we see the free stack is useless in KASAN report, it doesn't help
> > > > programmers to solve UAF on workqueue. The same may stand for times=
.
> > > >=20
> > > > This patchset improves KASAN reports by making them to have workque=
ue
> > > > queueing stack and timer queueing stack information. It is useful f=
or
> > > > programmers to solve use-after-free or double-free memory issue.
> > > >=20
> > > > Generic KASAN will record the last two workqueue and timer stacks,
> > > > print them in KASAN report. It is only suitable for generic KASAN.
> > > >=20
> > > > In order to print the last two workqueue and timer stacks, so that
> > > > we add new members in struct kasan_alloc_meta.
> > > > - two workqueue queueing work stacks, total size is 8 bytes.
> > > > - two timer queueing stacks, total size is 8 bytes.
> > > >=20
> > > > Orignial struct kasan_alloc_meta size is 16 bytes. After add new
> > > > members, then the struct kasan_alloc_meta total size is 32 bytes,
> > > > It is a good number of alignment. Let it get better memory consumpt=
ion.
> > >=20
> > > Getting debugging tools complicated surely is the best way to kill it=
. I would argue that it only make sense to complicate it if it is useful mo=
st of the time which I never feel or hear that is the case. This reminds me=
 your recent call_rcu() stacks that most of time just makes parsing the rep=
ort cumbersome. Thus, I urge this exercise to over-engineer on special case=
s need to stop entirely.
> > >=20
> >=20
> > A good debug tool is to have complete information in order to solve
> > issue. We should focus on if KASAN reports always show this debug
> > information or create a option to decide if show it. Because this
> > feature is Dimitry's suggestion. see [1]. So I think it need to be
> > implemented. Maybe we can wait his response.=20
> >=20
> > [1]https://lkml.org/lkml/2020/6/23/256
>=20
> I don't know if it is Dmitry's pipe-dream which every KASAN report would =
enable
> developers to fix it without reproducing it. It is always an ongoing stru=
ggling
> between to make kernel easier to debug and the things less cumbersome.
>=20
> On the other hand, Dmitry's suggestion makes sense only if the price we a=
re
> going to pay is fair. With the current diffstat and the recent experience=
 of
> call_rcu() stacks "waste" screen spaces as a heavy KASAN user myself, I c=
an't
> really get that exciting for pushing the limit again at all.
>=20

If you are concerned that the report is long, maybe we can create an
option for the user decide whether print them (include call_rcu).
So this should satisfy everyone?

> >=20
> > > >=20
> > > > [1]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-aft=
er-free%22+process_one_work
> > > > [2]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-aft=
er-free%22%20expire_timers
> > > > [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> > > >=20
> > > > Walter Wu (5):
> > > > timer: kasan: record and print timer stack
> > > > workqueue: kasan: record and print workqueue stack
> > > > lib/test_kasan.c: add timer test case
> > > > lib/test_kasan.c: add workqueue test case
> > > > kasan: update documentation for generic kasan
> > > >=20
> > > > Documentation/dev-tools/kasan.rst |  4 ++--
> > > > include/linux/kasan.h             |  4 ++++
> > > > kernel/time/timer.c               |  2 ++
> > > > kernel/workqueue.c                |  3 +++
> > > > lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++=
++++++++++++++++++++++++++
> > > > mm/kasan/generic.c                | 42 ++++++++++++++++++++++++++++=
++++++++++++++
> > > > mm/kasan/kasan.h                  |  6 +++++-
> > > > mm/kasan/report.c                 | 22 ++++++++++++++++++++++
> > > > 8 files changed, 134 insertions(+), 3 deletions(-)
> > > >=20
> > > > --=20
> > > > You received this message because you are subscribed to the Google =
Groups "kasan-dev" group.
> > > > To unsubscribe from this group and stop receiving emails from it, s=
end an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > To view this discussion on the web visit https://groups.google.com/=
d/msgid/kasan-dev/20200810072115.429-1-walter-zh.wu%40mediatek.com.
> >=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1597069882.13160.23.camel%40mtksdccf07.
