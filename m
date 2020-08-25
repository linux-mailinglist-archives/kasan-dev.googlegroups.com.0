Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUWSP5AKGQE35L3YCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A58C25142A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 10:26:43 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id e12sf14051091ybc.18
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 01:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598344002; cv=pass;
        d=google.com; s=arc-20160816;
        b=XTB+gzXiTg5nXl0VjmTgCuZNgvunSFsLjYHqZnIXftRHeGy2qFTn06fJCCMLIkOba6
         EJFJ7WcjMqgZBUhDPwpAOISvBGn33pfmxSxHHp1zwzOWAmX4qDc2BiqFrVfEONh5e3jh
         tjmqu89bfiknrJNBh7TfKk6vsswi61+600TUP5kBbFKdda0qGAkXmwxaQ92NjG1v2UdN
         m5ysdF4b9OaD2UoQ3Pww+Hc7nVWeZP34h3/5RF2pKA6s1YE5QbPwm3fJKTwcoDk7LHdh
         jUzoq+8i8wqrD7YW91qnsf0lvV6f9dMb4hQGBJmEs/Dh9FIgJhnm/od8azwrgbbwifr1
         c1oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dGWQeid2K0txN7020fvmBd3BMRaIKhuHSOIgEir2NcY=;
        b=u81RoqD7tjgpiOkVS2/aQw/RTvWZDRlopq//8kQnipr1kxpwngsOCfH2K8vE7qxDKK
         fntlMae6QmTQX7iZl0ynlRopyALGrpVONMQUy0bYT5UBVE8vLjPNaLyK+yQhTVg0RQIk
         Zwjy7nA134uJqObG4DtNgr3DqZRG2iKidt8kaHAhZy+w5FxwGelC/NP7ou8RJbqay+gJ
         OQuysG2bbfXLL4g8MlErmmK/c3hnvsvgOLCGi4jpf7a5B0rFlEVGFrHnDUBN1H6FY6EL
         w9BIIvhHzbRyZu3PtOsNc2w++Whntlx2uSUuM++kjqS/nvVmgpZ9q3nbjS1QSuVVqP7q
         XS/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mE7Ydj/t";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGWQeid2K0txN7020fvmBd3BMRaIKhuHSOIgEir2NcY=;
        b=OQ1PbYzSOR2JksPc6poAl7unMl2BDz3bcFaDCEKnoF7MHF5rMANKADKlH2shtL9UHD
         41v3Rxd/scKn5sbWz/NQxIw9d76lUCl+CGERgdqn1XHdiL9juEwmDxy84tZvKXV3lrzt
         GmVQfvB8xxDn9AHpsGK805J96yEXOysRRe9X/EReIqW31390MiiQ3p9FpRt35JSdIpfr
         vfKBh8qRuDc5JTJeiFuWBZx4R16j+eMiM2EV71UvVPxzsXAh55eBDbD5PDPxxdqi7f6A
         YYLsB0Ha9XBcXYLqDqWDp1D97z0t1vb+okaCgJ4qInCnHgSd/xUXA1LiZ4fu22ZkLU9J
         IfYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGWQeid2K0txN7020fvmBd3BMRaIKhuHSOIgEir2NcY=;
        b=ik/lKcA540MGGod8ZOObuzcNF+8tGOmq58Fo3UzbxFmeHQW9MuJ5C58v3gDTQquDqD
         MPwNRUtdnysPAT6NTxJGoqoEdzDI3o+MuCBID5/+V1RwEn5PYbcN4b6J1JIsTXNPnpAP
         3IOPEB2/5htHJay7J/ubi2X7FmpW+zLNzcL4oDKID1n1jEckn0EpRtmm9bCZw3tEIuVt
         Xt7QoR7wuOInQU59h9JXiuCCoj2kDvkOzvbLF21i8Z9p3HO+4/JIlyZDXPgf692jL98b
         h905mI3AMcxZEZI5x6a0IzqjPHaxOxoN/rACPFey/kZnbazGj7Azo8Jy+h8x5uHUg8ds
         ODlQ==
X-Gm-Message-State: AOAM532l+Ol9obr8gqipeCtwhmNsUg+euPA0VCoDRQzP0XeY9bpz+m6R
	/11ior98VBTW+nQ9h/LS8ik=
X-Google-Smtp-Source: ABdhPJxkBKU1YFevxYwx9AmSP0mQ/N6AGiVMq1XTkcXQECVBNBaeGlJMx4438MS37nC0g71ZBxy5qA==
X-Received: by 2002:a25:e782:: with SMTP id e124mr13374583ybh.92.1598344002654;
        Tue, 25 Aug 2020 01:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:b0d:: with SMTP id z13ls4958816ybp.8.gmail; Tue, 25 Aug
 2020 01:26:42 -0700 (PDT)
X-Received: by 2002:a25:2415:: with SMTP id k21mr13181114ybk.156.1598344002224;
        Tue, 25 Aug 2020 01:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598344002; cv=none;
        d=google.com; s=arc-20160816;
        b=swkwfqpwBEKbra6VP+b5bIHCTqxPY1bh/71l39bpZNfgOmKuI0jhR53eX+VmQo+TBo
         dQBi9Zi+wB/d6U0Mr9eLowf6/MAa0am7QItltFNZG7qHyPsOia+Anr+3E73TkZ/sAbUi
         X1bSCgG9XIYqdbW/jhPrmS7gpBtpw2NI2ShJfRLeSbhGOefg5zBkolnZI/qzCHyaKAwk
         2s5eBtwj/wOjRNyDf/x3yOjzfuhbrzMJR564CjHL6uikU/q+8dZDJPGLXZpjGE3+na01
         JnZ4aqho7LYdWoeipad2X+sonUjcAdYQh2V0ORc/aPn36RKXqa6EWRrUits9lW7ounC9
         5kxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FC5Hg6COXCLaWmmWNTz40PS96oTnHUqlyjZL5YEDjmI=;
        b=BD/m1jT5zKyeBoa8IkCGwAgMEzm0luT23kvr+aRQPx2jXLWb8vdQo/0ioJiZBbjBkr
         F85HHypELEYwNXWEZydZHdAFCsfzAyf1Koyo6fRJlyp6HiHBu55D86t7Putra15Zmubc
         ps8nSJBgug+jwcMaUqepgh8F2HY/vrfv+8PT7aER/8us963BXSC+h/CBL/W68ZWc8GWG
         XlnUQWRnzV6hE2cIkUWIpZoXSff4uZ5rkxOLBqKIhSqThbuRJV3cpHUlA4Bs6Kwk+ozC
         qwekni3eYCIuA/W4j1uq0tmwVwq4gj1pKo/NzOSwKxt3KRuIooWh1W6aWDztlxJmN6rF
         Coag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mE7Ydj/t";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id 7si713099ybc.0.2020.08.25.01.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Aug 2020 01:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id j21so1028602oii.10
        for <kasan-dev@googlegroups.com>; Tue, 25 Aug 2020 01:26:42 -0700 (PDT)
X-Received: by 2002:aca:aa8c:: with SMTP id t134mr407296oie.121.1598344001584;
 Tue, 25 Aug 2020 01:26:41 -0700 (PDT)
MIME-Version: 1.0
References: <20200825015654.27781-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200825015654.27781-1-walter-zh.wu@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 Aug 2020 10:26:30 +0200
Message-ID: <CANpmjNOvj+=v7VDVDXpsUNZ9o0+KoJVJs0MjLhwr0XpYcYQZ5g@mail.gmail.com>
Subject: Re: [PATCH v3 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="mE7Ydj/t";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 25 Aug 2020 at 03:57, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> In some of these access/allocation happened in process_one_work(),
> we see the free stack is useless in KASAN report, it doesn't help
> programmers to solve UAF on workqueue. The same may stand for times.
>
> This patchset improves KASAN reports by making them to have workqueue
> queueing stack and timer stack information. It is useful for programmers
> to solve use-after-free or double-free memory issue.
>
> Generic KASAN also records the last two workqueue and timer stacks and
> prints them in KASAN report. It is only suitable for generic KASAN.
>
> [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
> [3]https://bugzilla.kernel.org/show_bug.cgi?id=198437
>
> Walter Wu (6):
> timer: kasan: record timer stack
> workqueue: kasan: record workqueue stack
> kasan: print timer and workqueue stack
> lib/test_kasan.c: add timer test case
> lib/test_kasan.c: add workqueue test case
> kasan: update documentation for generic kasan

Acked-by: Marco Elver <elver@google.com>



> ---
>
> Changes since v2:
> - modify kasan document to be more readable.
>   Thanks for Marco suggestion.
>
> Changes since v1:
> - Thanks for Marco and Thomas suggestion.
> - Remove unnecessary code and fix commit log
> - reuse kasan_record_aux_stack() and aux_stack
>   to record timer and workqueue stack.
> - change the aux stack title for common name.
>
> ---
>
> Documentation/dev-tools/kasan.rst |  4 ++--
> kernel/time/timer.c               |  3 +++
> kernel/workqueue.c                |  3 +++
> lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
> mm/kasan/report.c                 |  4 ++--
> 5 files changed, 64 insertions(+), 4 deletions(-)
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015654.27781-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOvj%2B%3Dv7VDVDXpsUNZ9o0%2BKoJVJs0MjLhwr0XpYcYQZ5g%40mail.gmail.com.
