Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMGC7X5AKGQECLBBZPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E5F0268AD0
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:25:21 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id c11sf12523346ilm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:25:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600086320; cv=pass;
        d=google.com; s=arc-20160816;
        b=0LSvlyMrR7weKMGnc9r4fUJ6DlSRxwbJfZI8J32nMV2Aof6eD7ufF9UsBSGM9SwI85
         9652nXNowak2KpLTwWe68vJCSWCAgT10/bsfeXE+wpR1qm8vHGZ3KoiosaLWeRHwKt3w
         z6Q5FQ1SLfNBNLU3MM7TK7BjaRmQFPnrgCYj3xUtW8dtoo02gtVRcgIZcLYz6FqViMuP
         aEdQLgf0qyYgDozRk1VHzmStXXTg51KTrPz+E1f9apVmKQ0AeKX6VVP1NUy0DPog0Tmp
         fRAGAkvceQtyf6i8wQxMNbYPf6nIAANl2sQQHvl6ePFcBYWVyg9/fjR1K+TPk2WbsY2y
         2Iaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v4blL5Mj1wS9F4B1NFQoERRCiLaVwUrSCiIE+ORX0vI=;
        b=ZBulxJuW9OTHeSy/tTmNdwMtuxfSWYqMTC5dsob8F0IzS7Rj4tr0s7p4m8riFr1/Dt
         qBVVc2ySpqnGvzGDzyR9kgyAPrOz6lsijY5LIqjIE0QM+7e+slkOgf0Uw0bopd9BXgyp
         VYpcrkdMjdEuHvOJflcbXuCt8XemJQkAStkpV4ovMeVVFxDMIUhuIXvZ0vUKniNoOUtb
         Dzti7QGqvfA5XHH6cVKMhj77DPqtppExJFL3Q7EpGxRikCbgXSM2Xke3Dy8Vc/8zDLve
         oOYJEj7tKA72lWMC6A1I8ExeJEmYrBJpZvG4NoCWonTWUtReyRbu0k4t8K2jhM9oiIGK
         JR6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H3keo0Rq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v4blL5Mj1wS9F4B1NFQoERRCiLaVwUrSCiIE+ORX0vI=;
        b=cuGXUNXPW066Sb8M52ypy+gUPxlJ1riOvcJud0BtVgpvNgvNz8p4lnNFn/yWW8NVcd
         yJhizEM5ESIJ2vlb2yzrUHmsS1DlP4oj/sOA1dbKirIAHB+aYSBoMZFZ7NeIZszfq8l8
         zWEv4G3kbI2pM3kxn7Z+t4ieiadrpEspZ0yP1o4wPLd6E9ezcSWtNHPWZFsrSjQbKM7x
         UZAwkQyEMrfM8osLa1/h0Bix690v6jZ5LgvjCBxaIjn8kpdZYIBcJXuLakrcD6EYFOn9
         ZEwbyNLwOHvwXHRkmJfVQAeOZx2C5hfoRtCA1oaJhm6etLXGMab9hRkGAyu+O0YUO8ZH
         cJXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v4blL5Mj1wS9F4B1NFQoERRCiLaVwUrSCiIE+ORX0vI=;
        b=cweGhAfXwcnllrzikzOJyBFqszu/uzdP4vxpvFfMnvUONdVdVGsBiZfC95GDkJ95Vx
         QD6HieA4rdoOPDnr9t/3MTrhovTRnum+7ILf2chtDWUsVuDyOCnP3ysTRJp1MZEPV/nq
         rSxDqTaKh48ZkM5TIjjxTR8VmhyCz9XfCsrIRdYmhvD+qMZ5AgimjuzlrZYKZnBv0wgG
         z+REsZ+hWtyVwLiDoZh5IbRAXhjcDWixyvgpFaAhzedmlCHZ1nE9EeLO1l3tpD7POm4O
         io+73CyEzJ166ciCCNWIbNan8GqoUrVqoZH5KJRq+XsyKGR4Ud+1jdTHGdsevyDFa9Wb
         JDiQ==
X-Gm-Message-State: AOAM532tWlpNnNj3dJF84aFLkCXqJQwmUEVAFvPtGDhPjdAW5HnQuAlp
	wBmDlYe4GM/KQGoMPkINe6g=
X-Google-Smtp-Source: ABdhPJz4iQMG8gfQVKra8AnpC4QT3ITFnzRyi+3TzZfaFL6K9TbsNms4W97kiU+Vv3b6whYr+bD3KA==
X-Received: by 2002:a6b:b48c:: with SMTP id d134mr11099548iof.115.1600086320144;
        Mon, 14 Sep 2020 05:25:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9d52:: with SMTP id k18ls1482281iok.3.gmail; Mon, 14 Sep
 2020 05:25:19 -0700 (PDT)
X-Received: by 2002:a05:6602:2f0c:: with SMTP id q12mr11305759iow.76.1600086319805;
        Mon, 14 Sep 2020 05:25:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600086319; cv=none;
        d=google.com; s=arc-20160816;
        b=BV1MvVRL3nNZYkHzj+3hDgYF+BBBMTYbWsHbLyytYiEhP3GtP0DtrdPqLi8iypxfZz
         z849F7EUY257u84vE3/BSIFNzbXJ2v57TyykVjwHhogKFROo8wzxvqBNM2oQlt67lvjo
         ssf8jbXGSuAAgOc2KzZ4HAN+UxbUSHyQbO7kFD09fw3cyZW/41uyfnD3WN/Csgb15lMS
         Xa5wRTB6ljwhkZzur9z7B6e4edxhaEIdcA4l3qng2p2WU8S+DgADAB3ufzBPd0UvuxsQ
         TJ3AAFhHLUo7/mrhSKfbEL6hGpE4yI0Rr3QSoCvcEZKCk4LJUE4xGylsoxLT+hSDz1b5
         ZIcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GFSPNOxQc9ciwHykJLsDnN5OLK2Zzkj9cGLxa9O7b54=;
        b=LB5l78CUQp/juUo9CHnW9NqPYvnn+0dver+GsegZCnF+WvMhWkjkKHWgFY1QJhfIf0
         ivfbeKAvmuPA5Eb+FeVx33I0NWAwS17DlyP2wbA3LG8gfXJaCHciLr6M89AQxDWjAVtR
         YA3SrGdz89ymBz/6gK3CJkduwUpqfLBlRJUj3hi3e20LQ4D80052naYgS4LDZ3GcRlAI
         DJdMKFa+3FwKfTn9PZ8mqk2RilWoJwxf7s2KH77y52psTkDrmETWd6DrNV/Xb9kuZetF
         tZaYphnxaYGGmD897pkBhXqi4XxoFYPZWzXrZm+tPy6Q8MvzxQPX/NfX6czgir/0UKVq
         MvCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H3keo0Rq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id m2si770974ill.5.2020.09.14.05.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 05:25:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id o20so12469251pfp.11
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 05:25:19 -0700 (PDT)
X-Received: by 2002:a62:c2:: with SMTP id 185mr12460883pfa.11.1600086318959;
 Mon, 14 Sep 2020 05:25:18 -0700 (PDT)
MIME-Version: 1.0
References: <20200825015654.27781-1-walter-zh.wu@mediatek.com>
 <CANpmjNOvj+=v7VDVDXpsUNZ9o0+KoJVJs0MjLhwr0XpYcYQZ5g@mail.gmail.com>
 <CAAeHK+yVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ@mail.gmail.com> <CACT4Y+b1OimWNQCx-rGvSgC1RheLAv9mv2xzRnwkn98AsdTgXA@mail.gmail.com>
In-Reply-To: <CACT4Y+b1OimWNQCx-rGvSgC1RheLAv9mv2xzRnwkn98AsdTgXA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Sep 2020 14:25:07 +0200
Message-ID: <CAAeHK+xONO0NDWvernDXH72E+oyMtJr8JpWfok9wGRDVZ518iQ@mail.gmail.com>
Subject: Re: [PATCH v3 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, 
	Stephen Boyd <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: multipart/alternative; boundary="000000000000a73b3d05af45205b"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H3keo0Rq;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

--000000000000a73b3d05af45205b
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Sun, Sep 13, 2020 at 12:17 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Wed, Aug 26, 2020 at 2:30 PM 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Tue, Aug 25, 2020 at 10:26 AM 'Marco Elver' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > On Tue, 25 Aug 2020 at 03:57, Walter Wu <walter-zh.wu@mediatek.com>
> wrote:
> > > >
> > > > Syzbot reports many UAF issues for workqueue or timer, see [1] and
> [2].
> > > > In some of these access/allocation happened in process_one_work(),
> > > > we see the free stack is useless in KASAN report, it doesn't help
> > > > programmers to solve UAF on workqueue. The same may stand for times=
.
> > > >
> > > > This patchset improves KASAN reports by making them to have workque=
ue
> > > > queueing stack and timer stack information. It is useful for
> programmers
> > > > to solve use-after-free or double-free memory issue.
> > > >
> > > > Generic KASAN also records the last two workqueue and timer stacks
> and
> > > > prints them in KASAN report. It is only suitable for generic KASAN.
> > > >
> > > > [1]
> https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-free%2=
2+process_one_work
> > > > [2]
> https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-free%2=
2%20expire_timers
> > > > [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> > > >
> > > > Walter Wu (6):
> > > > timer: kasan: record timer stack
> > > > workqueue: kasan: record workqueue stack
> > > > kasan: print timer and workqueue stack
> > > > lib/test_kasan.c: add timer test case
> > > > lib/test_kasan.c: add workqueue test case
> > > > kasan: update documentation for generic kasan
> > >
> > > Acked-by: Marco Elver <elver@google.com>
> >
> > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> Thanks! The UAF reports with RCU stacks that I see now are just =F0=9F=94=
=A5=F0=9F=94=A5=F0=9F=94=A5
>

Hi Walter,

This patchset needs to be rebased onto the KASAN-KUNIT patches, which just
recently went into the mm tree.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2BxONO0NDWvernDXH72E%2BoyMtJr8JpWfok9wGRDVZ518iQ%40mail.gm=
ail.com.

--000000000000a73b3d05af45205b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr">On Sun, Sep 13, 2020 at 12:17 PM Dmitry V=
yukov &lt;<a href=3D"mailto:dvyukov@google.com" target=3D"_blank">dvyukov@g=
oogle.com</a>&gt; wrote:<br></div><div class=3D"gmail_quote"><blockquote cl=
ass=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid=
 rgb(204,204,204);padding-left:1ex">On Wed, Aug 26, 2020 at 2:30 PM &#39;An=
drey Konovalov&#39; via kasan-dev<br>
&lt;<a href=3D"mailto:kasan-dev@googlegroups.com" target=3D"_blank">kasan-d=
ev@googlegroups.com</a>&gt; wrote:<br>
&gt;<br>
&gt; On Tue, Aug 25, 2020 at 10:26 AM &#39;Marco Elver&#39; via kasan-dev<b=
r>
&gt; &lt;<a href=3D"mailto:kasan-dev@googlegroups.com" target=3D"_blank">ka=
san-dev@googlegroups.com</a>&gt; wrote:<br>
&gt; &gt;<br>
&gt; &gt; On Tue, 25 Aug 2020 at 03:57, Walter Wu &lt;<a href=3D"mailto:wal=
ter-zh.wu@mediatek.com" target=3D"_blank">walter-zh.wu@mediatek.com</a>&gt;=
 wrote:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Syzbot reports many UAF issues for workqueue or timer, see [=
1] and [2].<br>
&gt; &gt; &gt; In some of these access/allocation happened in process_one_w=
ork(),<br>
&gt; &gt; &gt; we see the free stack is useless in KASAN report, it doesn&#=
39;t help<br>
&gt; &gt; &gt; programmers to solve UAF on workqueue. The same may stand fo=
r times.<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; This patchset improves KASAN reports by making them to have =
workqueue<br>
&gt; &gt; &gt; queueing stack and timer stack information. It is useful for=
 programmers<br>
&gt; &gt; &gt; to solve use-after-free or double-free memory issue.<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Generic KASAN also records the last two workqueue and timer =
stacks and<br>
&gt; &gt; &gt; prints them in KASAN report. It is only suitable for generic=
 KASAN.<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; [1]<a href=3D"https://groups.google.com/g/syzkaller-bugs/sea=
rch?q=3D%22use-after-free%22+process_one_work" rel=3D"noreferrer" target=3D=
"_blank">https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after=
-free%22+process_one_work</a><br>
&gt; &gt; &gt; [2]<a href=3D"https://groups.google.com/g/syzkaller-bugs/sea=
rch?q=3D%22use-after-free%22%20expire_timers" rel=3D"noreferrer" target=3D"=
_blank">https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-=
free%22%20expire_timers</a><br>
&gt; &gt; &gt; [3]<a href=3D"https://bugzilla.kernel.org/show_bug.cgi?id=3D=
198437" rel=3D"noreferrer" target=3D"_blank">https://bugzilla.kernel.org/sh=
ow_bug.cgi?id=3D198437</a><br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Walter Wu (6):<br>
&gt; &gt; &gt; timer: kasan: record timer stack<br>
&gt; &gt; &gt; workqueue: kasan: record workqueue stack<br>
&gt; &gt; &gt; kasan: print timer and workqueue stack<br>
&gt; &gt; &gt; lib/test_kasan.c: add timer test case<br>
&gt; &gt; &gt; lib/test_kasan.c: add workqueue test case<br>
&gt; &gt; &gt; kasan: update documentation for generic kasan<br>
&gt; &gt;<br>
&gt; &gt; Acked-by: Marco Elver &lt;<a href=3D"mailto:elver@google.com" tar=
get=3D"_blank">elver@google.com</a>&gt;<br>
&gt;<br>
&gt; Reviewed-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.=
com" target=3D"_blank">andreyknvl@google.com</a>&gt;<br>
<br>
Reviewed-by: Dmitry Vyukov &lt;<a href=3D"mailto:dvyukov@google.com" target=
=3D"_blank">dvyukov@google.com</a>&gt;<br>
<br>
Thanks! The UAF reports with RCU stacks that I see now are just =F0=9F=94=
=A5=F0=9F=94=A5=F0=9F=94=A5<br></blockquote><div><br></div><div>Hi Walter,<=
/div><div><br></div><div>This patchset needs to be rebased onto the KASAN-K=
UNIT patches, which just recently went into the mm tree.</div><div><br></di=
v><div>Thanks!</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAAeHK%2BxONO0NDWvernDXH72E%2BoyMtJr8JpWfok9wGRDVZ518i=
Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAAeHK%2BxONO0NDWvernDXH72E%2BoyMtJr8JpWfok9wGR=
DVZ518iQ%40mail.gmail.com</a>.<br />

--000000000000a73b3d05af45205b--
