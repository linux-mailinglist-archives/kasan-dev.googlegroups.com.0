Return-Path: <kasan-dev+bncBDGPTM5BQUDRBGONQP5QKGQENCE5GMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F225026A94D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 18:06:50 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id b127sf3863558ybh.21
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 09:06:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600186010; cv=pass;
        d=google.com; s=arc-20160816;
        b=YtzSkxBEhY4WUiJS6CHsMf4c5xQKjsqHk8h5UEi0JKnTeFp+nHhHb1K2gFUM4pOmZR
         3cvZRzPA9XDcu2Ty1j0Pe8ky8BsJOhkzJ2v5pSeBUy1uAH/0PPLwJfiWcST6EGsn8UeI
         l8tydIRp3sJG1grbr6jk9E1HVyEiKAiVqN46v7gJz1UrbzbxDzMQSt3XUkOg7hLBiiBQ
         FiKbkeY0bV8Xc2vf2Gs1m4H7kJQVS4gF2W2QpJHYMp3ESjb3nRg6ZoPRENytMzSAksAA
         Mp4GhpJPXeySWX4tPPoTzbcA5PEeIja2PpPuS0k30mesav2tuiBnIOlhy5VIfNnL+vju
         6xYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=Z6kPVa+edY7BPXgi2yRbSTYJwOLKp4hFGQLGxtdW6jE=;
        b=Knjjp5DlmnBIvgRUkEM/aLgCsrIGJDnRnmBCj5OFp6MgUVH7srHlB6y85kfNlK+Upo
         hG+4846BfhGher+2ZDLJZBFIV/lSfW2xScuvI+wm6pTPtCQ5EBdcjpIyEGxg+gz0o/p6
         2sWaOYItpY3dudkB9E/QIFtDUuY+w6Tv81h2tkB6xkfHneSb9IsHx2MtJPWswCLqFaKI
         ajPMwnLvQoz0g12xdxkbUBkgEy9wuCzsGCLIhWZ1k6tUDVMe0qeDklEMYEJQ5kzs+nDt
         LvtuGqHs/J0+MreP9yfTQzbF7VJTlPsBvL/ohcngKlzs9AnajFDB6W2es02Vr+30D7HW
         Vn1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fNVjQh6J;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z6kPVa+edY7BPXgi2yRbSTYJwOLKp4hFGQLGxtdW6jE=;
        b=Co64rc2hdxvZGW6skfkITYhTVvRdHWBpW9Bb3H80OJWWg8AIVOzpT0haVKSPyhxpKM
         186R4SA73oaYoEcCDh4VfSKWXSn6v3jjW4o7miJfYNd2cfoSuAXybXLrLeqnmuWk0Rgt
         mhH0xC4pSRvmFhQYsvd2yfVLkzoleKMjUtdRqFuIYlqPhcA5YDWqaY5AoJKADqcStLzm
         lx8dYikWPuJWPQmYwDQjQKj01wutwLnyaKUrv6D2za+qmNh/Ipko7rtH1X+mWeL5FZO4
         UrTsb+oQxvuETQnQmIT3pNOV64tF0YGJpm/9+ggUiI6LkLo8ruygXLvv9iZ3r6A42LCn
         Asfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z6kPVa+edY7BPXgi2yRbSTYJwOLKp4hFGQLGxtdW6jE=;
        b=PUh3ew6M2YVHEjvdOw9nDrB3zxN5x6irojv2SZ726KDzw3tLPlm121N1HyqNxWnQwb
         OnZpm4NB5iu8CG97Ze1K6bwwU9HKbMCgT8kXuxUf5G0BFcil+145Q8Mgo5G20PWyGAow
         AppvAEcuP0jDIsZVfrEJfFigZD/cRP1WZvmrx+7NC20Yuhu0/a3g3vEWnikklgzc1a8p
         vShFIwBDzFikd0cLoniI4mkXxVx/l8USQ4xgVqGOC7vqARd14JkjJ5XpQSieUA22eCAA
         9DES09d98z1v/YpttRGbw0/Xp3ipkZWy6FjXzmDP4g8sbA7Pi7P7DEaj2waelkaJn7pp
         USdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oHKEYHNPJb9N9YTAP0ALiiu1E3N61k0E+DjB0veB1o1btesru
	npVpii9pV11xwJwC+eaDPgM=
X-Google-Smtp-Source: ABdhPJxMBY7upWc96JM4WJwqJIA6IgW7YKwmP3CAt61an604JizrBgiZLm55fBY4di6Q6iS1+52JdA==
X-Received: by 2002:a25:d00a:: with SMTP id h10mr27693012ybg.309.1600186009922;
        Tue, 15 Sep 2020 09:06:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b29b:: with SMTP id k27ls1129145ybj.11.gmail; Tue, 15
 Sep 2020 09:06:49 -0700 (PDT)
X-Received: by 2002:a25:487:: with SMTP id 129mr28935775ybe.485.1600186009331;
        Tue, 15 Sep 2020 09:06:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600186009; cv=none;
        d=google.com; s=arc-20160816;
        b=YkjqCvpgO7nb/OFLGiuZPfcyZ1LC1lVYxPyX/uBSMjdITyvVp/tUren6rbfwxx/DRB
         aTD97eaygdHDrD7ILn9UTUzlbGKiH8WC6/3f0Z52Ct3MOinibJ0DAR37D0+QynnakG/d
         H2nNgzTTmF+TpFxZjzFVibWYkuTcSI+5s1MyrBWcpdku0mwT8MCd4t+ZC/wM8lnZBHBt
         0aYurp5Zut26ZEjxHss8NlsKkpcX21QaZZCL74aLHBmuaCz0dgp36cXF72kCkYVZus7/
         xlPPjyFp7WJKal/I1AAupWY0nT9+uF/rhjZ2gZQpE6+TO9x1cIjwzlA1I8hB+SB7Yt1S
         pJtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=dyxC8WhaSmjgvfJJHFnp0NhjfIxeFwAQsy17LIoKHDE=;
        b=zXV367eCoJHmt062BK6XYp/FbWAbYOyKVI+xG5u5c+vjPIC0tc3OdNc9sPN5ijAkXa
         PwH2QWY4zwL2p2fnI81+0SxCEkMjBWlIO+G4ptD7mB7IsVliSHF8OKlTPko2SNW9tpYR
         B+nrWrGRoUlp8B63ftmjThnIqhqaokCthTUa8ntvh30yWbiYtaf+psW59aSP4ZEEg7Xl
         0774gngh4BhPdTg3MeuNIH70P4iKAi8qJ6W2x2fhuN7uEEIH/Vsp+d+Jt3e0wFEgskaV
         4JVh+0p66ZCd3supRvhLsBRA4iTMBl5mHDKIrsdLVNBblmBIlbDKy+C13u+sSUY3G6dv
         k7/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fNVjQh6J;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id v129si716888ybe.2.2020.09.15.09.06.48
        for <kasan-dev@googlegroups.com>;
        Tue, 15 Sep 2020 09:06:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 03bbaf6be4644b71a8c1b0ef064e73fc-20200916
X-UUID: 03bbaf6be4644b71a8c1b0ef064e73fc-20200916
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1709786148; Wed, 16 Sep 2020 00:06:43 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 16 Sep 2020 00:06:39 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 16 Sep 2020 00:06:39 +0800
Message-ID: <1600186001.25944.3.camel@mtksdccf07>
Subject: Re: [PATCH v3 0/6] kasan: add workqueue and timer stack for generic
 KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Tejun Heo
	<tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, "Linux Memory Management List"
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 16 Sep 2020 00:06:41 +0800
In-Reply-To: <CAAeHK+xONO0NDWvernDXH72E+oyMtJr8JpWfok9wGRDVZ518iQ@mail.gmail.com>
References: <20200825015654.27781-1-walter-zh.wu@mediatek.com>
	 <CANpmjNOvj+=v7VDVDXpsUNZ9o0+KoJVJs0MjLhwr0XpYcYQZ5g@mail.gmail.com>
	 <CAAeHK+yVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ@mail.gmail.com>
	 <CACT4Y+b1OimWNQCx-rGvSgC1RheLAv9mv2xzRnwkn98AsdTgXA@mail.gmail.com>
	 <CAAeHK+xONO0NDWvernDXH72E+oyMtJr8JpWfok9wGRDVZ518iQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: AA21E673224F89C2DF2907E0064F3C128B0F5B7C7AFF54C00B058CC4AFE9D2992000:8
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=fNVjQh6J;       spf=pass
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

On Mon, 2020-09-14 at 14:25 +0200, Andrey Konovalov wrote:
> On Sun, Sep 13, 2020 at 12:17 PM Dmitry Vyukov <dvyukov@google.com>
> wrote:
>=20
>         On Wed, Aug 26, 2020 at 2:30 PM 'Andrey Konovalov' via
>         kasan-dev
>         <kasan-dev@googlegroups.com> wrote:
>         >
>         > On Tue, Aug 25, 2020 at 10:26 AM 'Marco Elver' via kasan-dev
>         > <kasan-dev@googlegroups.com> wrote:
>         > >
>         > > On Tue, 25 Aug 2020 at 03:57, Walter Wu
>         <walter-zh.wu@mediatek.com> wrote:
>         > > >
>         > > > Syzbot reports many UAF issues for workqueue or timer,
>         see [1] and [2].
>         > > > In some of these access/allocation happened in
>         process_one_work(),
>         > > > we see the free stack is useless in KASAN report, it
>         doesn't help
>         > > > programmers to solve UAF on workqueue. The same may
>         stand for times.
>         > > >
>         > > > This patchset improves KASAN reports by making them to
>         have workqueue
>         > > > queueing stack and timer stack information. It is useful
>         for programmers
>         > > > to solve use-after-free or double-free memory issue.
>         > > >
>         > > > Generic KASAN also records the last two workqueue and
>         timer stacks and
>         > > > prints them in KASAN report. It is only suitable for
>         generic KASAN.
>         > > >
>         > > > [1]https://groups.google.com/g/syzkaller-bugs/search?q=3D%
>         22use-after-free%22+process_one_work
>         > > > [2]https://groups.google.com/g/syzkaller-bugs/search?q=3D%
>         22use-after-free%22%20expire_timers
>         > > > [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
>         > > >
>         > > > Walter Wu (6):
>         > > > timer: kasan: record timer stack
>         > > > workqueue: kasan: record workqueue stack
>         > > > kasan: print timer and workqueue stack
>         > > > lib/test_kasan.c: add timer test case
>         > > > lib/test_kasan.c: add workqueue test case
>         > > > kasan: update documentation for generic kasan
>         > >
>         > > Acked-by: Marco Elver <elver@google.com>
>         >
>         > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
>        =20
>         Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>        =20
>         Thanks! The UAF reports with RCU stacks that I see now are
>         just =F0=9F=94=A5=F0=9F=94=A5=F0=9F=94=A5
>=20
>=20
> Hi Walter,
>=20
>=20
> This patchset needs to be rebased onto the KASAN-KUNIT patches, which
> just recently went into the mm tree.
>=20
>=20
> Thanks!

Hi Dmitry, Andrey,

Got it.=20

Thanks for your review and reminder.

Walter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1600186001.25944.3.camel%40mtksdccf07.
