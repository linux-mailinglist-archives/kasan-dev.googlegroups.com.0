Return-Path: <kasan-dev+bncBDGPTM5BQUDRBL7JYT4QKGQEHSCMU7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 37401240577
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 13:51:13 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id c2sf6540938plo.11
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 04:51:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597060271; cv=pass;
        d=google.com; s=arc-20160816;
        b=V0U6c9xC7gW+5vwp2pT8aRkv9CsWyDtAmz80N3lJtEts57nEKCu6vmChWmyLxg+Gx/
         5D5DLs7nAgsS3cKpqDR2XV34DkfgGC7DuM4lScBk9SHCZ5DgltIJcj1sNdTm7+epYtPk
         33UHaR7pJZ5eKS2bxWSw4xj9DDKZvlrpoGSID4/73zoNdS3nYjjwJd2sYzrHiJXF/J+c
         D//uYH6lQVLQi8zGID5JCH1OBlWAHLj+pM0fSFg2FyISg8BrpUkcWMrSb3/A/9fRX8VO
         209+o6o3p+A8ia0BWrypjrg1NK2z71iK60offZ7HyL52QpIZ4+oqYxtBNHX+KaoJENC2
         Gp8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=61F+y5m3brztBa+P5g67BPeTPNXDEwCjnLK0Fg9rCUM=;
        b=niCyhWY8sCNfUc39ZjnK++BLRFCCocVtsdjLCE45QbIb0bWl/vjD9H5+fjz6zXMk/1
         Jir+K5+bLFw7aG1Po9CpDNw/Ha06Zz6U4xirEUcBY0dRgwLIfNQ9JCmAy0JJ5jBm/9v9
         fYmSXmXZXT11+RKJfq2wvu9r+zXNi3jIvjYzfnPih/yvhwtMxXZt1WaEX9NJue2Zk0vZ
         UbIPLuSxVfbwU/HWz6yTcU0D/+LIvNETtJpWO2hJXO0jFLojPtXUM3bqVHNfYP7/sC7I
         OjdBCilhevc7QXgGIaTGI16HtFUndY0Z0KfFjB4tnWtgl/6RSyHp9pPSG3rnw95EL4O3
         1xRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=G86wgHW3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=61F+y5m3brztBa+P5g67BPeTPNXDEwCjnLK0Fg9rCUM=;
        b=jhOagsdZsZSdUx0Wmy70PJ8piNHhS7ops2b432nWBgs5OGY9j91siOuP37VjNeniaP
         ez6CbwzdIfMWfQI6CeGKGJZmbu8YPzWWijPFQYLxWs4/sjpMVTjAAM365FUnOoH4Rc/g
         9YWBDWFoBlCbQcbSJ1I0EyHrYwyAS5Nfx7vudDx9mWgmZMDKjc7V6RHNRUtp0n/LBmlO
         9kfXJjk4bUQ/QWLsU/+de5y7aPlT6zsfTgvxbMb/NRr07EBjqdRwmKZQ5onDkm4QBFwS
         oJjDmnk00MgXxhIJfUt7QthR95S68gpFDvcknBiYZ+cc+mFWVknQGq2G2JsBX6VVAcwX
         0KrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=61F+y5m3brztBa+P5g67BPeTPNXDEwCjnLK0Fg9rCUM=;
        b=KAM4A9RriZ8xLUdw/tuK5NguZBykI2Zyfo8e9zv55J6D46zDnr+vKEcWvO77cZB/YF
         gn9lew3bRFQY6FLUdiyD/E4enRc9tk7Flo3sMJ+9u42nPtdsLRI7WoKO4ppIK1Vp+r+S
         KyQULirIwKf515ufhb4gHUrhDQkgs5HsTvlbFYf2qrCe9u4mP1WTE/mXNrTY+8JBG8ka
         9bBB+it4jVaTzd3iVtwHjNpTXrXq7Na+kF2xeUuZsrWS+dY+FKetxRgthOWmONFV5Kn8
         AAZN0fSBD9pwemGTV+1SVdKKs5OtG5TVyirrCoxiA1Ewez4QTyqR5x0rMTuibQwaTfgM
         mUCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nhK9+aO7Gi6FhG1Nh838sYdkcE8jfWSE2PssOSnPrs4fFWXjb
	N+WT3EKvJfZqt9k5+8/hDAM=
X-Google-Smtp-Source: ABdhPJyL+UDozVpf16HW7J4qpOqClut9JGwaPhplEpXAU7LqpTtkkDzsuk+He+sikA7S3lukI6OuuQ==
X-Received: by 2002:a17:90b:f94:: with SMTP id ft20mr27530668pjb.69.1597060271444;
        Mon, 10 Aug 2020 04:51:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:fe08:: with SMTP id g8ls6862302plj.1.gmail; Mon, 10
 Aug 2020 04:51:11 -0700 (PDT)
X-Received: by 2002:a17:902:7b85:: with SMTP id w5mr23082125pll.22.1597060271005;
        Mon, 10 Aug 2020 04:51:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597060271; cv=none;
        d=google.com; s=arc-20160816;
        b=Pv7pGnrTzvENrgToFTVf7sKeibxyEaXPWPky9GD2HCXvOjsxsp4P+Jaxo/V8kO+58O
         qbNR2z+Kso6BkdRDIPY6rb/g1Am9raBnRVvsK+iGkYngn+4k7+7n+8KcbHJcDNbCoFTB
         KWi1kd88m1SF5ve8vopWcDkUvIylgDMKOqhy43XmROh1sfAAyjwQNgl7yvbrZZrL52dI
         CfETYbSaV5zG76zxJNWvlmorCf+u4uI+gd4QG6F3nKiIC4cM7mJZ2N5z+SVcgmbhCtag
         Qg+E0TypRMcdhkbwIgcXYSUFi3wjoIQRwtlnaH6eARJc+FDjwR5XgvfXDc8rmtrjy+Z5
         oIsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=XMYSeVf6j/BMh7fB37Fqh8Fu4b2tHaEyT8hlJ40JRlg=;
        b=qDJmmWrM6146PiYB6Oovjx/0ytajaLakjUN9Rj0Ffv7eCZj46XvxnyjhsSM7RA12cI
         jLZYQSjEcW3TUMXw7mfZn715eAA+p+HgV5Unj/WovBwHlx0zLeN7NfxLFiAndp5c2NXH
         6ylJA9R0/0NzUk68/otwAwpaVKqgBTuCLDqzgQhxWJMrxMsmHBjdLzJRAKn5Um+GLLV5
         58mmQYfuX85Xop2W2Odil4TciStab84NUkjbWN/2Y18DjJh9+RtF+ttKtxhkcuik0fYZ
         8+Jgp+YVRFA65L643V/NenkAHLbOGEx7YEHdqPbhM+E7Ig4wvK7fRJwjlbaBI0VzSiLq
         Zn+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=G86wgHW3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id c11si948485pjn.0.2020.08.10.04.51.10
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 04:51:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 727dccead9cf4613bd92ea7bd2e32a09-20200810
X-UUID: 727dccead9cf4613bd92ea7bd2e32a09-20200810
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 583491652; Mon, 10 Aug 2020 19:51:06 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 19:50:55 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 19:50:57 +0800
Message-ID: <1597060257.13160.11.camel@mtksdccf07>
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
Date: Mon, 10 Aug 2020 19:50:57 +0800
In-Reply-To: <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
References: <20200810072115.429-1-walter-zh.wu@mediatek.com>
	 <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=G86wgHW3;       spf=pass
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

On Mon, 2020-08-10 at 07:19 -0400, Qian Cai wrote:
>=20
> > On Aug 10, 2020, at 3:21 AM, Walter Wu <walter-zh.wu@mediatek.com> wrot=
e:
> >=20
> > =EF=BB=BFSyzbot reports many UAF issues for workqueue or timer, see [1]=
 and [2].
> > In some of these access/allocation happened in process_one_work(),
> > we see the free stack is useless in KASAN report, it doesn't help
> > programmers to solve UAF on workqueue. The same may stand for times.
> >=20
> > This patchset improves KASAN reports by making them to have workqueue
> > queueing stack and timer queueing stack information. It is useful for
> > programmers to solve use-after-free or double-free memory issue.
> >=20
> > Generic KASAN will record the last two workqueue and timer stacks,
> > print them in KASAN report. It is only suitable for generic KASAN.
> >=20
> > In order to print the last two workqueue and timer stacks, so that
> > we add new members in struct kasan_alloc_meta.
> > - two workqueue queueing work stacks, total size is 8 bytes.
> > - two timer queueing stacks, total size is 8 bytes.
> >=20
> > Orignial struct kasan_alloc_meta size is 16 bytes. After add new
> > members, then the struct kasan_alloc_meta total size is 32 bytes,
> > It is a good number of alignment. Let it get better memory consumption.
>=20
> Getting debugging tools complicated surely is the best way to kill it. I =
would argue that it only make sense to complicate it if it is useful most o=
f the time which I never feel or hear that is the case. This reminds me you=
r recent call_rcu() stacks that most of time just makes parsing the report =
cumbersome. Thus, I urge this exercise to over-engineer on special cases ne=
ed to stop entirely.
>=20

A good debug tool is to have complete information in order to solve
issue. We should focus on if KASAN reports always show this debug
information or create a option to decide if show it. Because this
feature is Dimitry's suggestion. see [1]. So I think it need to be
implemented. Maybe we can wait his response.=20

[1]https://lkml.org/lkml/2020/6/23/256

Thanks.

> >=20
> > [1]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-f=
ree%22+process_one_work
> > [2]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-f=
ree%22%20expire_timers
> > [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> >=20
> > Walter Wu (5):
> > timer: kasan: record and print timer stack
> > workqueue: kasan: record and print workqueue stack
> > lib/test_kasan.c: add timer test case
> > lib/test_kasan.c: add workqueue test case
> > kasan: update documentation for generic kasan
> >=20
> > Documentation/dev-tools/kasan.rst |  4 ++--
> > include/linux/kasan.h             |  4 ++++
> > kernel/time/timer.c               |  2 ++
> > kernel/workqueue.c                |  3 +++
> > lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++=
++++++++++++++++++++++
> > mm/kasan/generic.c                | 42 ++++++++++++++++++++++++++++++++=
++++++++++
> > mm/kasan/kasan.h                  |  6 +++++-
> > mm/kasan/report.c                 | 22 ++++++++++++++++++++++
> > 8 files changed, 134 insertions(+), 3 deletions(-)
> >=20
> > --=20
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/20200810072115.429-1-walter-zh.wu%40mediatek.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1597060257.13160.11.camel%40mtksdccf07.
