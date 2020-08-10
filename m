Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBN4CYX4QKGQEHREKD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id B2830240616
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 14:44:40 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id w11sf12610638ybi.23
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 05:44:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597063479; cv=pass;
        d=google.com; s=arc-20160816;
        b=rfgCVzxe6DOnS863Mz2ATt+8LKkuFBoz5qBQ+dWeegot1M11KzwW6wvTGXznyRTrGA
         oSrw7G/BihlDn8xcbX965C7v+15JhVQSuJwMaDp5Rv6w4UlSlxpp/w/gnw4d+g8oKk/Z
         UskLBGzlQafgvfj5UHiFAi7WNS5mtZW/6qjOdyFciBMrj1obqT61uKF3wIQ/qLwYho9p
         NYWNklKef33dWLzp0Ffq3nDUClVTeXA3fIq8VsCqZ9M85rN/yDUy9EPhNxVcAgOUTf7S
         y+xpdnkEC0h2Lo0N7BbFklb4xZbhrFArp6gvHYF8acXqLO0WO5LNPrhIg2yaEUdVz38R
         wXtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=NAljr7EiaEOL3nm/IfeZgt8iBlvGvlf+m8ipctrP6sg=;
        b=u6TzYO7PtAgfXzW0L2exLHNDd+Q6h1tKSAxtzVc9f+bT3V7EliSsiipZMBao+b3ubp
         pPW3cRPLKaUtg6Zqj5iTUDifbXjKRc/yLpGawHDAWxnIPhP1UPMuxLgJRLndbW9zqzJa
         p5NWCeo7AEpb4GZma0oiz+UPZ0d6wZZVQlBZAGfVa4vGOHv5AkexjC2zGdZeNMBzFXUk
         Ek8aHS03tMyLN6duQ2C3paD7G16H9Ka6VI6BAVGpC1WGSp1v0eLyxRVdAARhZxOafqH6
         WVVYYe5lhJplYzjasRBcAIAe0GlhK0/yqaoVwQByr/J3IyTCPvwENA2fMp2ti9kn0bZK
         vwqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rUgIUgpg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NAljr7EiaEOL3nm/IfeZgt8iBlvGvlf+m8ipctrP6sg=;
        b=QiaqQHFtptD02ypgVFotKAVTIdfyFNbylhA9jmZ7n0JDerCx97wQJXIu9KvyF6sJI0
         A80/tqHsfykpWi0JK9jrhQf6/0+mSxBURYlpfYpaYwLYiFmSTPr+fOiodj3Z7nXe7HJw
         pnPRNSUox5iyOppbTypXouxaFSDhQWBgTSYDvQgW4JzpeBRUF5fu8t8HX3o6y901b1Sx
         Lw+SDhlpMJl6bvSPrEyodTq5FqBcDQuVGSqWIxeq7d/tG81dcdP/AUhKuYO2hrMHK2Mz
         hSHm96lT+fFLGjZXDcuA7VcjTJquhbYaJ9ThKMZVz0KLBFhRT4Z+3jR88klxr0DGkEbF
         YI0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NAljr7EiaEOL3nm/IfeZgt8iBlvGvlf+m8ipctrP6sg=;
        b=BiDpAR8rY3cXS9VNSz0nvmOE42WfIoVwKRQExxipCM1MMHHXSrFTIbHvdy6nW+Es0u
         Hx+ZsKdsZ2FBBStg6zW7GRDbY6n7ZLo6DvvScflzfHv9OPzShnDe9fT4TnhQkApbeOlu
         bFr5IQwssNtNOX3vJcaPsIdBZfyTYEyang++tl7hn0/ult8i/atCULZ/jeEWCUTAl/xr
         kBeKe2cNZv6wUCWxO2SURjKcu/fSOfp6pbr86tx0O8sb1PvUsWNtIchRPGnP1csnD3/y
         WyyAGsLSX7MjA4t5TnV7vCRsh3mmLrbxikqvObu5VeGcnp2NsciEsTgsCx+EeO/j2L5X
         7iYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fYA9ePlAasCM/OQ3ZBhRCxqt3KmEnmsDYQ+gJgF1bwpTVHVl3
	RKRUS3Ofo00cBnnjTcEOj6M=
X-Google-Smtp-Source: ABdhPJybkoZS5dqQ7TBRKGlgvvgvJW8+FW45L4nz1QvULxb+R9ylaGk1b13WENOoDf3DBKiBrt3BVA==
X-Received: by 2002:a25:2314:: with SMTP id j20mr38594225ybj.508.1597063479506;
        Mon, 10 Aug 2020 05:44:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3c3:: with SMTP id 186ls2496485ybd.10.gmail; Mon, 10 Aug
 2020 05:44:39 -0700 (PDT)
X-Received: by 2002:a25:3c47:: with SMTP id j68mr29511274yba.59.1597063479165;
        Mon, 10 Aug 2020 05:44:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597063479; cv=none;
        d=google.com; s=arc-20160816;
        b=wVGsDnPxnKfoPbwau7d2EdKXvdGUWAV/6o2cF0wKkklEL9lU4t2rmtnePqqkvp8e9i
         OUQ3XL01L6OXwb+cJ363TXbRHRD7IvF+0nJh3h37+pkxD/3u1CP6j5NuQC4bLJ8kC3UX
         RoUvXQGJWxRb+1hLWPcqM0Wl58G99NnO8QDpNEkQvUkX95wmCdZ7BlAXqOGv7LlUSf/N
         QTa/AFHxUBxqycSr8IqZIjnFPttb4bYEt5oSstIUF43QZy7iSmWIYVhtS9Cq0WQvVu5p
         hODoAQt2zUnBfyERHybV+wAupEqK2r8DRsU2ktBDJGRBhhlxmXu57G7JKd06Omxl8DWP
         UzMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=gAr4D/ePrFPzg5ITCo7F2eiZjjapefZpMToAlkphjvI=;
        b=xzSdIX71JuB0h8f6PO82eg/9Vre2oGTRulWVPuVxS/jolewU9fF/nY/9kVHHAxtYYa
         w9ojyZDXe1KV3vG+H/aHY+eQVL7FQDJkD1cBsOXRErEGTIjunzHdrkLYbzNuil5eEOHe
         NTWiJ0/Ytqpd/+Kq0vGGU+vDhhNm6KR2fyq2K1ep3koBnAMgbu1f7Eb8dEK7dieZ+dPc
         ufD7tB0dnn2cYWXdd3J4YUtqSo1ByDgYKMZCFo1xnN0t537gl9xPy5EOWugBgku3yDeI
         XBaVsAXsjmUfnK0GqXePNrOd7Urnf7TYlYlj3j3n8aWjRX1bJ8buOg3sSTkXYL7qW+Tv
         p35g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rUgIUgpg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id o14si938063ybm.5.2020.08.10.05.44.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 05:44:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id x12so6571622qtp.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 05:44:39 -0700 (PDT)
X-Received: by 2002:ac8:47c8:: with SMTP id d8mr25413219qtr.32.1597063478706;
        Mon, 10 Aug 2020 05:44:38 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id l1sm15330349qtp.96.2020.08.10.05.44.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Aug 2020 05:44:38 -0700 (PDT)
Date: Mon, 10 Aug 2020 08:44:31 -0400
From: Qian Cai <cai@lca.pw>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	John Stultz <john.stultz@linaro.org>,
	Stephen Boyd <sboyd@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH 0/5] kasan: add workqueue and timer stack for generic
 KASAN
Message-ID: <20200810124430.GA5307@lca.pw>
References: <20200810072115.429-1-walter-zh.wu@mediatek.com>
 <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
 <1597060257.13160.11.camel@mtksdccf07>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1597060257.13160.11.camel@mtksdccf07>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=rUgIUgpg;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, Aug 10, 2020 at 07:50:57PM +0800, Walter Wu wrote:
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
> feature is Dimitry's suggestion. see [1]. So I think it need to be
> implemented. Maybe we can wait his response.=20
>=20
> [1]https://lkml.org/lkml/2020/6/23/256

I don't know if it is Dmitry's pipe-dream which every KASAN report would en=
able
developers to fix it without reproducing it. It is always an ongoing strugg=
ling
between to make kernel easier to debug and the things less cumbersome.

On the other hand, Dmitry's suggestion makes sense only if the price we are
going to pay is fair. With the current diffstat and the recent experience o=
f
call_rcu() stacks "waste" screen spaces as a heavy KASAN user myself, I can=
't
really get that exciting for pushing the limit again at all.

>=20
> Thanks.
>=20
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
kasan-dev/20200810124430.GA5307%40lca.pw.
