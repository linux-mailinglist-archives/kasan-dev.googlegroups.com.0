Return-Path: <kasan-dev+bncBCMIZB7QWENRBSPD675AKGQETPBVRPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 80CB8267F32
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Sep 2020 12:17:46 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id t4sf7909324qvr.21
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Sep 2020 03:17:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599992265; cv=pass;
        d=google.com; s=arc-20160816;
        b=eV+4ffSO7zkx2vqOZEyznGJbcoKXxVopQdYn7vffgNhUxCwdHvs6i8hp7IWmlJg/rr
         bB3lijD6/9vjihRieNTgvCIkCeWkeFYjcXU0pwRh/yRqWWpRO8GZ7T/uwo1fJIK48Ete
         3GSSp6HsrluFI+QR/3G39st1EBN2mE5KttdSQ8HbayUu7ReJ7aRAmB6roX/A5gh/V0s6
         /eohp3iUn7mlHlvS5pL3IdTx+037An3WiYNzuoQcdPq7szIEVJBXDOpsqdfsdhKBmnez
         L1Yqq/Rmp33XeoVuaqsD7s2oll3BP2tdqZJgull94cj63Yfj1dozBY7+yWUyGBwnL8zy
         RFvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lVoKsZrBWwspWfi7ubUlj8rQ5Cjxswet1yU+8h9RWzM=;
        b=nnVY2vErcSAJx8p1qjg3N9cP/+FteATFTtyZ3p70s1gmOBaIEjjj6CRiU8V1K0dLrz
         MGKqsEsyvdOk1A/POcOfe5Y8JX6I7GKUKu556jpXYhgIl1qQqIxqwyvMxEvClNJnx68r
         8WN8zP/KKc7mQ8L3nK41uipw4Kjza7GTapZyU5TECXmEaikPhnPlAZZRsn101NnulkQx
         qLsioILiEy9hFzVlV4+N1x8lpeEovzQlXb8oGI3hecJxXNOk6YV7dzugZ8li+2ttCwi7
         vT2J/0nYxBAX7Ew+Ow7RtG0hcjgiA06gQlVLWXSRAT0KYuHwfKi3MaNZBFYqWvgt7Ezy
         lpsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nyykmS9A;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lVoKsZrBWwspWfi7ubUlj8rQ5Cjxswet1yU+8h9RWzM=;
        b=qCAGyxjS509wl15/jJZONUUKWevTR/Z2bE0vLYw+Hn2xreiw9enCGTxCrUHdhehYNv
         foDylw1Ns5+pYxYTSEUWSpJG13OqaQOU/h80Xw5WqxFtHi3gsBDcqFiLcrhh+eL2J9v4
         HlbrRb/4gkXIQKmRgWzuFc/LKpnMoLn+St6/M6HbRMy3Mr1nGwB34TEXW/KCqXitvHyZ
         ldZfZjxEZgYWzOIxnGo7aEROOeY+EQkyPS9DvKq/lEErYYPttubFYynX9UwEnaBzABuP
         eDSPhdMBbbP3ny3uISUd5lfPYzeTly7P/roJJwv166fDucw0f0i7oRHag7MtMs1D0OKl
         +mOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lVoKsZrBWwspWfi7ubUlj8rQ5Cjxswet1yU+8h9RWzM=;
        b=P8PtAnrB1+NpUsD6Qny11tJ02iko9kGzICYZK5qq9Oelv/CngfGKkeeF0oUaCcco39
         /LtDt088F7HwA7R7HkI+rKutLec9oKZaesII3T7IvYVV3qVEK3UcFtctPWYvwhxzDCFh
         oTqJZ7/QN9ugzdkjCIzhrz/awOQTPXmg1RY5F1G2rOkjfn2OfjYixqLBlFF/1cg/4iUF
         AXjinvxrGvvMT4L6EaGvnyBMOMCuW9PgTJ8gin9Y5vAuiKWNqqnakiqZgLRNAtlTpn+O
         uhh+1B9peC+ETTTZ0uM9C+L3JEcF+LIv3ZzDX0EyWEGMTdLjE8aJvi6KxLx92ebhTge4
         qTCQ==
X-Gm-Message-State: AOAM533DTbID6ZX8ObK2ZSWody6IC6oML+b+h1+kazxIakPB1jv+NrUg
	8JuwczUD6RBj5Kmk85iEuD0=
X-Google-Smtp-Source: ABdhPJw8v79UqFC++zZ+u0PMe1Ky27UmZ5Q9DzXAu6LOdNbaXOxu7bumLxo4L+EK4A9Qrove/3Cfxw==
X-Received: by 2002:ad4:5743:: with SMTP id q3mr8908193qvx.6.1599992265565;
        Sun, 13 Sep 2020 03:17:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:21a8:: with SMTP id l37ls2755234qtc.7.gmail; Sun, 13 Sep
 2020 03:17:45 -0700 (PDT)
X-Received: by 2002:ac8:43d3:: with SMTP id w19mr9348679qtn.129.1599992265156;
        Sun, 13 Sep 2020 03:17:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599992265; cv=none;
        d=google.com; s=arc-20160816;
        b=m7EIhuxCz8HLWTohUJBbzSbsrfUhJdBRQttuw1BpiBZkXp8Oqj6nwx7utLdOiwonrw
         MAueLfUVyLEDuL3vqzjheG7lSl52i2I+OIMlaY2EKJOPdjOnEJlmBJSsEhfFZgzvilG1
         LhWVhS8+hqF5d6qDF0xLq/OZ2J5/5KTOeRsNntgu6psrY09D8q0i70oLUid7KpcoJURj
         UjlJwxP0U5lfz3LG08Pp4k5jdL3rhkTXhCGmAsKI1sBia95INSI3sluD+xxwXSc/o/mD
         XDo3ybYuj5MZPSy0hMk3mCbvgqsgF01RBWdcsMC5fwZyI98bBIFwY1Qz2r0aSEM8V+N1
         qzpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2/rTINPcp/OFtffjcOu1onBIlOhuthR1U8PEEQixv6o=;
        b=mN8HKngMZOiW782YFVIgx6be25aa4N6bxjbrvNMDrjJ+WkWXorEZ8/fXQ/cKDtaE7j
         jH21O1UFgyXS+DhbJ5rA5tt+Bz1zWT/k2tF+aZ8cGJDUL5Vjc6aHpIQSE9LK+uwPph84
         aosG3YhSyopvTbCDhqV5dpOANSB0TrOc9biL6zhCClxtKqXyf9WfVtI+8PObjJYAM1kl
         CfpZt/iyTpAJ6ohb9lqASVM+K7li6yBkF+geUDT/U8R7mBSvVTIKczK76lTVwmMK/i1P
         dHe0jyY8hiejM3oVbcFSWS59kdWVt6mRaX1wsmwxJ6bVIarcLtXkvs8QfBt45R0ze0D1
         uaXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nyykmS9A;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id q5si371866qkc.2.2020.09.13.03.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Sep 2020 03:17:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id g72so14201888qke.8
        for <kasan-dev@googlegroups.com>; Sun, 13 Sep 2020 03:17:45 -0700 (PDT)
X-Received: by 2002:a37:5684:: with SMTP id k126mr8015895qkb.43.1599992264608;
 Sun, 13 Sep 2020 03:17:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200825015654.27781-1-walter-zh.wu@mediatek.com>
 <CANpmjNOvj+=v7VDVDXpsUNZ9o0+KoJVJs0MjLhwr0XpYcYQZ5g@mail.gmail.com> <CAAeHK+yVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ@mail.gmail.com>
In-Reply-To: <CAAeHK+yVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 13 Sep 2020 12:17:33 +0200
Message-ID: <CACT4Y+b1OimWNQCx-rGvSgC1RheLAv9mv2xzRnwkn98AsdTgXA@mail.gmail.com>
Subject: Re: [PATCH v3 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Marco Elver <elver@google.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, 
	Stephen Boyd <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nyykmS9A;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Wed, Aug 26, 2020 at 2:30 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Aug 25, 2020 at 10:26 AM 'Marco Elver' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Tue, 25 Aug 2020 at 03:57, Walter Wu <walter-zh.wu@mediatek.com> wro=
te:
> > >
> > > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2=
].
> > > In some of these access/allocation happened in process_one_work(),
> > > we see the free stack is useless in KASAN report, it doesn't help
> > > programmers to solve UAF on workqueue. The same may stand for times.
> > >
> > > This patchset improves KASAN reports by making them to have workqueue
> > > queueing stack and timer stack information. It is useful for programm=
ers
> > > to solve use-after-free or double-free memory issue.
> > >
> > > Generic KASAN also records the last two workqueue and timer stacks an=
d
> > > prints them in KASAN report. It is only suitable for generic KASAN.
> > >
> > > [1]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after=
-free%22+process_one_work
> > > [2]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after=
-free%22%20expire_timers
> > > [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> > >
> > > Walter Wu (6):
> > > timer: kasan: record timer stack
> > > workqueue: kasan: record workqueue stack
> > > kasan: print timer and workqueue stack
> > > lib/test_kasan.c: add timer test case
> > > lib/test_kasan.c: add workqueue test case
> > > kasan: update documentation for generic kasan
> >
> > Acked-by: Marco Elver <elver@google.com>
>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks! The UAF reports with RCU stacks that I see now are just =F0=9F=94=
=A5=F0=9F=94=A5=F0=9F=94=A5

> > > ---
> > >
> > > Changes since v2:
> > > - modify kasan document to be more readable.
> > >   Thanks for Marco suggestion.
> > >
> > > Changes since v1:
> > > - Thanks for Marco and Thomas suggestion.
> > > - Remove unnecessary code and fix commit log
> > > - reuse kasan_record_aux_stack() and aux_stack
> > >   to record timer and workqueue stack.
> > > - change the aux stack title for common name.
> > >
> > > ---
> > >
> > > Documentation/dev-tools/kasan.rst |  4 ++--
> > > kernel/time/timer.c               |  3 +++
> > > kernel/workqueue.c                |  3 +++
> > > lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++=
++++++++++++++++++++++++
> > > mm/kasan/report.c                 |  4 ++--
> > > 5 files changed, 64 insertions(+), 4 deletions(-)
> > >
> > > --
> > > You received this message because you are subscribed to the Google Gr=
oups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, sen=
d an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/=
msgid/kasan-dev/20200825015654.27781-1-walter-zh.wu%40mediatek.com.
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/CANpmjNOvj%2B%3Dv7VDVDXpsUNZ9o0%2BKoJVJs0MjLhwr0XpYcYQZ5g%40m=
ail.gmail.com.
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CAAeHK%2ByVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ%40mail.gm=
ail.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Bb1OimWNQCx-rGvSgC1RheLAv9mv2xzRnwkn98AsdTgXA%40mail.gmai=
l.com.
