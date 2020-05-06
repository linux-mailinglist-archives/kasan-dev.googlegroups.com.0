Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNOOZL2QKGQEX6KJW5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 03B241C6FD2
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 14:02:00 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id m7sf963972ooa.23
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 05:01:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588766518; cv=pass;
        d=google.com; s=arc-20160816;
        b=WXA3r3kBksIfttgnWEMaRL32cp6UnGrbwH090Di2NIeFFkr6zR82NLaD1r6fo0hpl1
         P9c7QjK775LPBqsZ6eFgAWlJI3g+uHKPcraFOfzsp2tagbi17pbKpd3C0CUXaoNokk9G
         63wF2kL1b6Vg5GEt02Mpi7ay4fGiAn29AHOvlW6iP+I+i9vgVpJQGC16HephVSHdVyES
         ngk6p5lViFpuOiUHsjYKDlz92Sx2fJfVVaMyW5PCYbcTw4nQ0fqKsz9PAg/N3NS7mk9m
         q7AxyhRP0jhreWLQn24Kr7BoqCCGL7rzMGtAqOpPLpHyOU34quOU7AwdyfS0TpCBsmfI
         fWyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=eafVREhRh2ITgYG8o2Z6gKBIy/NC47y2ZI/tSpVUzdQ=;
        b=hTMi5tlNlvljrmYNN9dudsUiOqb1OIbfQKzfDeKOb9gLeAKtEg31G3ePRajMnCpQmT
         YHtGVPsUPKcApbHk4cyTUfg1NPygQGr6XxBvgcuiM/nawUHBMv+0sNfwJ3AKZiSmxKKV
         Pv1NmWPL5ekrf0iaNjFsc2xG18MqWooswup96xhbeqaO5KOVO+i2hlL6j+KSVLcLohEO
         /wX8wmHA7pkWoPyjJybC3/PaiRhMUsP5opNnAjCvsfVvR2t3oal8qqvQlcWxXdaKe9Jw
         4VtOVaGfOhycLYY9dKphyXGjvVm7pNex0GMQe3MbeWUo4MzlwLocHrVBQFowEFeMaWGP
         djBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Mcol6PT9;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eafVREhRh2ITgYG8o2Z6gKBIy/NC47y2ZI/tSpVUzdQ=;
        b=FW6/2j9PVVFmMstO31ZkOW9mJ33PegUmTsu5IiNA1vmWNRe8fI03NPOVjel6ZZbtlr
         eZ7IsiPeAeErZgmEpW+FoVzpGT77jn/uCS0Pzf0EjNw4UndxvaUVfs8kxAY7g2L0asQ1
         tqWbSC3hRKtKQsGAurCK3iSAbJpruu/+Ffi3yfeLcdsN5etbak3hIfN4WQw1hTludSOe
         L6r20cfTmVzQgHNg24Q43iQyTq4xhmjN+B29YtXsdwBxu8J877MQPxrVox2QlqgFnxY5
         ESurO/aaKUiF2/Z/dCc5F/TLnmYyWR03ubxsqWYcGrE4fqzP0odhewmpVxz+i/D4Rdfx
         Ovxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eafVREhRh2ITgYG8o2Z6gKBIy/NC47y2ZI/tSpVUzdQ=;
        b=juF90pX7/79aoDqaLItI65+X7e1c5CmM97AVn82QNsQNRHFlJ3EkZ+aoeLbFc0Dmop
         QvBdUfP53lyiYNv692/omHOofnJIPtP71WO/nQ9KHgkJ1g4Ny4203ddgpigF64iKKfzU
         +dscQVhw6kTiup8Mn3/TzY+Oe++3J/ZEsOHVNZZ7NJe8OcWE6CqbchAIT+PeweEKlbOT
         poTHmiwrqgV2AeMIbA1/kGupBws+TRfTCgJFaMqL2YEJd7g9t0IQrAo5EKur3OHFENEs
         b/tt5zfomwnTB4IRlWKxEIPjlVVabRpaIoeFC4o5OW9cDdJ0U5yYF2oC/a6z4m4KWxgH
         FOkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuasApYZzLD4WnWnuScse6wnrlGVqFkbImbnIK0quf5ZWCDahEj5
	rEMswnFp/y5vfu96rihHH5Q=
X-Google-Smtp-Source: APiQypKmy0iU2TNlMcncuHnOBe7T5Zf7dk7Amzk/kcVCwPxf3TuzDUufIErATSeHpuFtsmcSQEgl2w==
X-Received: by 2002:aca:dd57:: with SMTP id u84mr2255113oig.139.1588766517313;
        Wed, 06 May 2020 05:01:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a487:: with SMTP id y7ls102930ool.9.gmail; Wed, 06 May
 2020 05:01:57 -0700 (PDT)
X-Received: by 2002:a05:6820:164:: with SMTP id k4mr7023914ood.30.1588766516914;
        Wed, 06 May 2020 05:01:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588766516; cv=none;
        d=google.com; s=arc-20160816;
        b=tRq5fKkBG6ntck4gvIS2KAZW3c8XkR0hdy/rqvZeLdng4UuaOzUONNmPLaczhMjDxM
         MvhU+w55wg/TtdbIK4U5IAkzKxHuVKMNXCfuUOcJ4UpfRcWgxYyU6YzDwGWEpFMjFQOq
         m8KP4QdyzCknLD0CnvPKgWOz0m+q1WGbNega15s2R1BYUlb4GidIyYQdlG/cc+ehUh1q
         A11tTtZS9hT5bv17cDzn/5XjzVp0tUl2PkLc/KW3nodE3EqA44n4TLbELLX/0MImcMeL
         O/ExgMnT+Pl7aT3H+UfBpyIJWZFB0769DGZX/BNdNY1N+mp0PL/hTYJ6mDUehfmTsqLl
         CN2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=QP0Z6ozRv4E9IF9IdA2oNzT3UIfPRWDRnB6r6crxAtE=;
        b=sipAKMRcY0nKLSIBkDYFO9vxhv3C78XqM9HDR8WsW5HTKuoinduNvJ0k7GwsSt5psE
         rz3KkQEXk/Rp6Wk+/JtRx3jgODZMPD0DQnnUjd5odNL0YXXHX1d7rQUOxOMFx8vAb7ze
         nhBXvnP3MNrGQ6/8IJvIMlfroUSum/d03z5vjQ8vVvEjSQBJO6x/lzVpkcyGQa9BCBBw
         rmQeKK91UKaGfjIk7zITTulcN2PTonU1eORY4H7RGDG+srdt51Ifmc0cAaf1WI9fDOfU
         5I8X0UPtmrhwb/weE5D0mnyLr8s1R0svuxPmB+DSXBMpBFD3do1BUfFNz2vVIy70v7ZG
         zyew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Mcol6PT9;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s69si120987oih.3.2020.05.06.05.01.55
        for <kasan-dev@googlegroups.com>;
        Wed, 06 May 2020 05:01:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 968fbabcc65544d6a29314853d4acead-20200506
X-UUID: 968fbabcc65544d6a29314853d4acead-20200506
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 12963967; Wed, 06 May 2020 20:01:52 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 20:01:47 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 20:01:47 +0800
Message-ID: <1588766510.23664.31.camel@mtksdccf07>
Subject: Re: [PATCH 0/3] kasan: memorize and print call_rcu stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Qian Cai <cai@lca.pw>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, "Josh
 Triplett" <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux ARM"
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 6 May 2020 20:01:50 +0800
In-Reply-To: <CACT4Y+atTS6p4b23AH+G9LM-k2gU=kMdkKQdARSboxc-H8CLTQ@mail.gmail.com>
References: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
	 <2BF68E83-4611-48B2-A57F-196236399219@lca.pw>
	 <1588746219.16219.10.camel@mtksdccf07>
	 <CACT4Y+atTS6p4b23AH+G9LM-k2gU=kMdkKQdARSboxc-H8CLTQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 3E77E78FC4A39AC2C8C02C3404C5BF8283AFF9FF6F48C546033B172E256C57172000:8
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Mcol6PT9;       spf=pass
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

On Wed, 2020-05-06 at 11:37 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> On Wed, May 6, 2020 at 8:23 AM Walter Wu <walter-zh.wu@mediatek.com> wrot=
e:
> > > > This patchset improves KASAN reports by making them to have
> > > > call_rcu() call stack information. It is helpful for programmers
> > > > to solve use-after-free or double-free memory issue.
> > > >
> > > > The KASAN report was as follows(cleaned up slightly):
> > > >
> > > > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> > > >
> > > > Freed by task 0:
> > > > save_stack+0x24/0x50
> > > > __kasan_slab_free+0x110/0x178
> > > > kasan_slab_free+0x10/0x18
> > > > kfree+0x98/0x270
> > > > kasan_rcu_reclaim+0x1c/0x60
> > > > rcu_core+0x8b4/0x10f8
> > > > rcu_core_si+0xc/0x18
> > > > efi_header_end+0x238/0xa6c
> > > >
> > > > First call_rcu() call stack:
> > > > save_stack+0x24/0x50
> > > > kasan_record_callrcu+0xc8/0xd8
> > > > call_rcu+0x190/0x580
> > > > kasan_rcu_uaf+0x1d8/0x278
> > > >
> > > > Last call_rcu() call stack:
> > > > (stack is not available)
> > > >
> > > >
> > > > Add new CONFIG option to record first and last call_rcu() call stac=
k
> > > > and KASAN report prints two call_rcu() call stack.
> > > >
> > > > This option doesn't increase the cost of memory consumption. It is
> > > > only suitable for generic KASAN.
> > >
> > > I don=E2=80=99t understand why this needs to be a Kconfig option at a=
ll. If call_rcu() stacks are useful in general, then just always gather tho=
se information. How do developers judge if they need to select this option =
or not?
> >
> > Because we don't want to increase slub meta-data size, so enabling this
> > option can print call_rcu() stacks, but the in-use slub object doesn't
> > print free stack. So if have out-of-bound issue, then it will not print
> > free stack. It is a trade-off, see [1].
> >
> > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
>=20
> Hi Walter,
>=20
> Great you are tackling this!
>=20
> I have the same general sentiment as Qian. I would enable this
> unconditionally because:
>=20
> 1. We still can't get both rcu stack and free stack. I would assume
> most kernel testing systems need to enable this (we definitely enable
> on syzbot). This means we do not have free stack for allocation
> objects in any reports coming from testing systems. Which greatly
> diminishes the value of the other mode.
>=20
> 2. Kernel is undertested. Introducing any additional configuration
> options is a problem in such context. Chances are that some of the
> modes are not working or will break in future.
>=20
> 3. That free stack actually causes lots of confusion and I never found
> it useful:
> https://bugzilla.kernel.org/show_bug.cgi?id=3D198425
> If it's a very delayed UAF, either one may get another report for the
> same bug with not so delayed UAF, or if it's way too delayed, then the
> previous free stack is wrong as well.
>=20
> 4. Most users don't care that much about debugging tools to learn
> every bit of every debugging tool and spend time fine-tuning it for
> their context. Most KASAN users won't even be aware of this choice,
> and they will just use whatever is the default.
>=20
> 5. Each configuration option increases implementation complexity.
>=20
> What would have value is if we figure out how to make both of them
> work at the same time without increasing memory consumption. But I
> don't see any way to do this.
>=20
> I propose to make this the only mode. I am sure lots of users will
> find this additional stack useful, whereas the free stack is even
> frequently confusing.
>=20

Ok.
If we want to have a default enabling it, but it should only work in
generic KASAN, because we need to get object status(allocation or
freeing) from shadow memory, tag-based KASAN can't do it. So we should
have a default enabling it in generic KASAN?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1588766510.23664.31.camel%40mtksdccf07.
