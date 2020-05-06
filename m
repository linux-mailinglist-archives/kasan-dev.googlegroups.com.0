Return-Path: <kasan-dev+bncBCMIZB7QWENRB74KZL2QKGQE2AVFNOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB39D1C6D14
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 11:38:08 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id z3sf2029250qtb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 02:38:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588757887; cv=pass;
        d=google.com; s=arc-20160816;
        b=KpCMFetILSVxmZMzCL0QZLa+5wxnGZjIgMDD0Wza1+AvYd+LhoraGYsp0QtchUc05z
         300kk6w/dBP919xGGVZFopTXLhLJXoWoq0+JZd0u/dniq2mZ5tcz9AsbciqxJW4kKHHj
         cdTZdXR6A40T3KBSbh1De609zi77ov6wOdiaAS1Z+1N6k21h6ZNjQIRS3s0IDgtBG1/q
         AOhGnKts8tCxLg1IGpi2rpEuDI8iEFdEnJzUVrs588l1wWbt0bzUeWs3TCe/UDGHCn0p
         CYj1/FYhUSPrTdxR/haC22n2iAIVbZhMVaI2r83g/oQJvBtn7yZSBn99l960mTLRvkBL
         ezXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sib1+53o+8YopEe/EvuDGa8lNtewaGoSYnu5fp3N220=;
        b=qrPIm7SilR3mZs6jaymHZkXJvl+xSFT2DlNO2ESBJfIX9zEmMM2okFDCaaS6TVLCmI
         3oYe/v77vuGWGF8pNnxEC1ZPrfYDj9IXYQlkZcNh/0FDEaBec91IZS4kJjlZZPP79hrh
         WRplEcHL+9guGkSX8LJHkWmR6gQ70BzexQQiMBFEsKoVyqttJJE3U/mki5DSx+ii1rdZ
         zmhnioQAe32Uh50THlaXtDr7CnFjWKAhypOw/PRZTNThU235S1e+wR/3NdpXuDB7euom
         rz1D+5qf15o9s40SxtArtk6vMGF8BfaR51qzymrJNQ2L9yTQsVNRArt6WMVHS43Ywirx
         SMSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ncii/QMt";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sib1+53o+8YopEe/EvuDGa8lNtewaGoSYnu5fp3N220=;
        b=nhweoZDG311Zot5CQbSQjpHkar61L8N4YuxCoUYy+pZTvjastkwZRutVozLRU1csLt
         wHNgOGAMCFxX2MHLRLPT7dzdX2EWh+HT443FiLuutJqkp00D4pvCwkf6HN631L8RjhOn
         ZjOjWR6QCmMpaUa//aKWNkbr6s6qWk6zB3hZUB4yJ6E2yxNt1G7dpv4IkGVu6BZ0SIis
         jORZaMUwFiB6lDoEtMW04NRJ9gsUpJFrIpM6cREJvllGXdiEfKkJ4PxSBjP4oBOkGM2P
         WlUp/lTGPjIFAoIm/31eBVhZkly5/9iu/mHaZzvClLtNKhrMB6ScwRjlPngaq0iQ3AZA
         46Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sib1+53o+8YopEe/EvuDGa8lNtewaGoSYnu5fp3N220=;
        b=rn+WAEdIpF0mpKwgAx/5bVYvij38D1VdMOmotMZQNWFhdDxKwpHkQdQGJlveZHgziN
         BNzoh6cSuIMw4UZQHP9LPySOHoS0f16Ob1jsnq479oAuo4QG1dI6QBXJfr6WA5sDAxnB
         vc5fisZscKGdyDA53DUPvDxEl57Yq/3Nf1708utYk3gORH02TCyNluHuyK8U+JO46Sn+
         v5E6vVKTh1/cprPWzFXqHRr1D2v0jjgUO737adL5lYDbACHe6abRCW8WV3TKa+ohmJZR
         /15PaDuVsXIHVqKpwTgEO6ULrA9NqE0A2ya55PIyGIaB/651VhF+h+AxAVokK6e1KqEf
         i4+Q==
X-Gm-Message-State: AGi0PuZ37NhRsY4Ai+sLs1jOi/TQTxEjkN+Wl8qWz5RGkl3B39ugaudf
	t9y8dHH0NiI4ltFJIxDw4Ic=
X-Google-Smtp-Source: APiQypI1Z1cfTUldCsKZn0+vE5VnhSgcXeB7ZpjQL0inQcYHXT4Lc+vbAZHinEp9KhqwlI0l/kjz8w==
X-Received: by 2002:a05:620a:914:: with SMTP id v20mr605710qkv.107.1588757887426;
        Wed, 06 May 2020 02:38:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:f78:: with SMTP id l53ls202720qtk.2.gmail; Wed, 06 May
 2020 02:38:07 -0700 (PDT)
X-Received: by 2002:ac8:6f25:: with SMTP id i5mr7165616qtv.240.1588757887134;
        Wed, 06 May 2020 02:38:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588757887; cv=none;
        d=google.com; s=arc-20160816;
        b=EgB9zFtt2MOSRmbdK2gUlFGSDyfjocyW2QxiX54tdYPAR+E3n5GFMXkNi2oxn/1/t9
         AV31otCUkfVVYiH8bOHxoLzEwH/xfLuk5LubzcHu0qUauT3VD80jnQ2ALr9OQwX9Gor7
         ESrwjXAWPdmL+jcwdQFo7DCciUSSQ5WFYCvoS2X5TjSVNeJ2JiQJ0bdyTRGVi9ijE1XX
         oq76At5mzJWd+RFVawUshLSL60DKytV4QpOZ4PVexg9YHJtkVBa8QGbHdURhco++U3+H
         kmLd0tHmONWqbSG1ysvawbX//PnxAGwKvFk9vO5ikxYVO2TPVOYzQGMlH3YfmxA647OS
         KnGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=da9Msd6VhXx/3o4OwwaQEairzk+A5t5H6NDxBwzjlV0=;
        b=xXbyK01WyqyLLSrJ2Sbh9mtnPbl8tQ/n2SJOc0C18Po8SbFWI3FuWNXktM4SDOWWhX
         TtzUACKy4ZJdx3VszcQuKQ2BjP/S5/3n6pbYfUwkceQfcP3kuof8P5WQ6U5QHbO7uc4o
         Q+SL/+rWyPvC54z3C//1/rfPG5YddjVwdS0CrSVW/64hEuEU1jfca21PLGZ6W9Hf08sQ
         7FY1HDkx+pTJWUa4DwR4IYtyJePBGRxqYYD0HNaupFj6mj8WIhPgyiOGm+j2RD7BpNpU
         ls23mDBV2I3UwKHTrEV5mdA5+Ul8ihB2omNsm9TtCr/n+hwGK9x0pQddKnyxYl7E/OXy
         I/gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ncii/QMt";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id f3si96132qkh.5.2020.05.06.02.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 02:38:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id g185so1215342qke.7
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 02:38:07 -0700 (PDT)
X-Received: by 2002:ae9:ed05:: with SMTP id c5mr2109866qkg.250.1588757886424;
 Wed, 06 May 2020 02:38:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
 <2BF68E83-4611-48B2-A57F-196236399219@lca.pw> <1588746219.16219.10.camel@mtksdccf07>
In-Reply-To: <1588746219.16219.10.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 11:37:54 +0200
Message-ID: <CACT4Y+atTS6p4b23AH+G9LM-k2gU=kMdkKQdARSboxc-H8CLTQ@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: memorize and print call_rcu stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ncii/QMt";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Wed, May 6, 2020 at 8:23 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > This patchset improves KASAN reports by making them to have
> > > call_rcu() call stack information. It is helpful for programmers
> > > to solve use-after-free or double-free memory issue.
> > >
> > > The KASAN report was as follows(cleaned up slightly):
> > >
> > > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> > >
> > > Freed by task 0:
> > > save_stack+0x24/0x50
> > > __kasan_slab_free+0x110/0x178
> > > kasan_slab_free+0x10/0x18
> > > kfree+0x98/0x270
> > > kasan_rcu_reclaim+0x1c/0x60
> > > rcu_core+0x8b4/0x10f8
> > > rcu_core_si+0xc/0x18
> > > efi_header_end+0x238/0xa6c
> > >
> > > First call_rcu() call stack:
> > > save_stack+0x24/0x50
> > > kasan_record_callrcu+0xc8/0xd8
> > > call_rcu+0x190/0x580
> > > kasan_rcu_uaf+0x1d8/0x278
> > >
> > > Last call_rcu() call stack:
> > > (stack is not available)
> > >
> > >
> > > Add new CONFIG option to record first and last call_rcu() call stack
> > > and KASAN report prints two call_rcu() call stack.
> > >
> > > This option doesn't increase the cost of memory consumption. It is
> > > only suitable for generic KASAN.
> >
> > I don=E2=80=99t understand why this needs to be a Kconfig option at all=
. If call_rcu() stacks are useful in general, then just always gather those=
 information. How do developers judge if they need to select this option or=
 not?
>
> Because we don't want to increase slub meta-data size, so enabling this
> option can print call_rcu() stacks, but the in-use slub object doesn't
> print free stack. So if have out-of-bound issue, then it will not print
> free stack. It is a trade-off, see [1].
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D198437

Hi Walter,

Great you are tackling this!

I have the same general sentiment as Qian. I would enable this
unconditionally because:

1. We still can't get both rcu stack and free stack. I would assume
most kernel testing systems need to enable this (we definitely enable
on syzbot). This means we do not have free stack for allocation
objects in any reports coming from testing systems. Which greatly
diminishes the value of the other mode.

2. Kernel is undertested. Introducing any additional configuration
options is a problem in such context. Chances are that some of the
modes are not working or will break in future.

3. That free stack actually causes lots of confusion and I never found
it useful:
https://bugzilla.kernel.org/show_bug.cgi?id=3D198425
If it's a very delayed UAF, either one may get another report for the
same bug with not so delayed UAF, or if it's way too delayed, then the
previous free stack is wrong as well.

4. Most users don't care that much about debugging tools to learn
every bit of every debugging tool and spend time fine-tuning it for
their context. Most KASAN users won't even be aware of this choice,
and they will just use whatever is the default.

5. Each configuration option increases implementation complexity.

What would have value is if we figure out how to make both of them
work at the same time without increasing memory consumption. But I
don't see any way to do this.

I propose to make this the only mode. I am sure lots of users will
find this additional stack useful, whereas the free stack is even
frequently confusing.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BatTS6p4b23AH%2BG9LM-k2gU%3DkMdkKQdARSboxc-H8CLTQ%40mail.=
gmail.com.
