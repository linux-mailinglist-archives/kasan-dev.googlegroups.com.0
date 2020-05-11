Return-Path: <kasan-dev+bncBCMIZB7QWENRBNWW4T2QKGQE6O2YDCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 94E6E1CD6AF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 12:38:47 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id v21sf8425234pfn.18
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 03:38:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589193526; cv=pass;
        d=google.com; s=arc-20160816;
        b=NdagA4yS/UpGLdN6zK8FkDFvJOPtheJ9W0neo5WKnf0U7DIupBN6ULvfZkVfCrIpoy
         f6rBB7nAeESCkhNAr1JscXVvQ14Fl+IRUCMXPSVaBxnQqck6jv1QJYFO9xf/Dqzda3Dp
         CFnZf6HkR4aohsgaveZAjxDh6o9XviVxEk9eMFcUsFiFF/AeaVGIkHHsAlI4AoWrEJfl
         pvXP1uRwWh6hIBxUbb495gVnnJwx+yEL1apLfBkqEuRjReUT+7ekBO4j81T9C7z4mDt0
         nns3dK3rx5yTCjJiSanD7dfp3VPWmfZkTyiTMdMQW0LgerQ/OI8Ofkeo0wqTr9yads6e
         NQJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cljnK/JCfY1GEyQsNFhR2WOblwo76KcAfuN0CYDntt0=;
        b=nqjucijV01Z4YMkOKxqS7pLRzRnT71lxPtfkIMywLFSlK3wCEvFO5lsiKUiZzFn0tE
         ERylpmggQpGlPGbnk4ffTGnBGXLMXmCDHh3lu8oqdfV4bbst4DN7rPwgEEBGmEwo2I9u
         DKs5Phzcv8A7lY/mllx77Ctl2C6V/FAiPvD69tELJILIG9eqpTx0Q2Jr4wKtgMgoyumh
         SxeZ0Pot8U9vZXTGwoujHVKwl3ipEJqeO01r/V1dJYaA3VCRFxTLkfT+FOvp/QXpA2nr
         CtxuD4oqz3qK/nkjK+Muh5GeRztF0oQYXMChBGbEfsml7M98CMw+tGlbyzNvGtAsBCEm
         jUXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mqCzMPdN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cljnK/JCfY1GEyQsNFhR2WOblwo76KcAfuN0CYDntt0=;
        b=o2WR6SxZ7men1UzQxTSEMsKzkDYZSlfmBJVpy74jPIe+MrxJa/KrFd+WBWKFU5/FO9
         zKklwTrjqTEhUIR91UlYelimXC09Jp5z/wkOOg60ghMcHQQ9rQJ0nHVpUCWSxWKoO/8X
         IO4hHbHg2GtGfVjll1YPH2fZByteFKqnDxpAFdbhrOMpfvznNK41Q+yfpvg9qK4HRBik
         DPpXPdNCih8AwG8XNWk7GKa+J109Dzww4Gj8fQZmFUwE5AAvkHfycOmb0zZs15NuZKNY
         AadgfhwQnack1Ss94ruUAF42han9e4pzfBtVl6oPSZY01mrEwXTh7s4w0q/uFOWeHbbC
         j8uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cljnK/JCfY1GEyQsNFhR2WOblwo76KcAfuN0CYDntt0=;
        b=f4VaBE0GIOrNZ0L5mmN4BhV9pSnhEb5jJ90s4nKxBSWOcheJIkoNSlERtPJWmn/yZH
         nWkFVSSqd8cE9H076a6oz31DV+57bl4dw36yThyXQRtPQe5Oyhv4bTJhZM6pt7VlOEc2
         rxJcyk9UrrCDt6QqGwId0WZ+9/vnK+kjdajTf6pAChllxnnmAtVwFyN1jdFPkFdrmZRR
         nsVDvUtAW2rfgpc51JEDg7W9qQVxWK2zFal+DZjPaDl4fq/I3Ao40U1KR5/pfsoilApH
         thdjue3W64JBq7Iok4YJh7szZl1a6SzepTTgq9Iu10llUDlkq0rlVqbtgWJCyNk79Jvx
         kUGw==
X-Gm-Message-State: AGi0PuZs+XobPRxQ+YBQQNDUV4crCBXu9xwqF9PuKXnQCv6GdnYxo4jw
	xn+HaLPftYUb3iL/sUeLW30=
X-Google-Smtp-Source: APiQypKoDeXnZb75xK4zRu0YEUnl6xwXlU2Gx3yNK6AAIadjO4HFACJJ16mdBJC/hZtCPwUEMUSDkQ==
X-Received: by 2002:a63:f46:: with SMTP id 6mr14127185pgp.367.1589193526151;
        Mon, 11 May 2020 03:38:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:c31a:: with SMTP id v26ls4535108pfg.2.gmail; Mon, 11 May
 2020 03:38:45 -0700 (PDT)
X-Received: by 2002:a63:1d46:: with SMTP id d6mr14357189pgm.236.1589193525620;
        Mon, 11 May 2020 03:38:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589193525; cv=none;
        d=google.com; s=arc-20160816;
        b=rIgOFXj3xszO2Ou1mITW+7Gtd432vExekgFoE3nQMY4+hZmZD/ydy850ZS4Bpj5w71
         UgPvl+lh5nMFaAT1HGLaj83onhvl3XBlPsUVAt5i5/qetHCV94CXF4FJ2Yt+oPBz5BtF
         RzLfeICCE6/m9l9boeJnrpxNsV/ia1utA6r7LdFtakdTCY+GJH7tgaSlJAiLP33QtnHt
         4j2ZTwGIodHCLVMWaBzpItl30bN/KKgeGj0mr0X4S8Ql/97x1D06m/UqjVx2bwEDqYBO
         DkbcIGc+xje5iqp6fIb35gLjJHcXQ/tC8TMl6q8RuF4xV0u7MR9TC65WcORWl/5EZYFX
         PVhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Uf04Bplo4VLk4LrjpEdz9FsKxhkP+ZdN12Hn8z8gR3k=;
        b=c3HKz6N6dhIAVpkz2K8JEINQu9ORaQ/WjDDWvhxKLNCiQGSEiIR3YEru8L/b4C085L
         +YtkqTvxNLAkkZWDIqx5dTlUH5OKyLvsRf/T5dfjbEk4MdPzSEeXa6pi/MDvk7JhsHrs
         GZ6tT1Hrw7vttsNXGO5cwu6qh7ZxT6iXaRrsUpCE+LeuHi0zDhFB7S0FAIFTbLFLljkg
         mcrp4KMTXHYBhkoqzYlDIuBjnpEj3cIFevDZqb4NlHgVFQUnOtprPYfprTx5PV2ieXOT
         76dm+IjLoquU/OqNjFeqbMvktYPxPNmKITDzCF1fKHfebSo4om3vgxgIsCSQujQcTeam
         Wsow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mqCzMPdN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id s65si868290pfc.3.2020.05.11.03.38.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 03:38:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id 4so7479378qtb.4
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 03:38:45 -0700 (PDT)
X-Received: by 2002:ac8:6c24:: with SMTP id k4mr15495561qtu.257.1589193524519;
 Mon, 11 May 2020 03:38:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200511022359.15063-1-walter-zh.wu@mediatek.com>
 <CACT4Y+aC4i8cAVFu2-s82RczWCjYMpPVJLwS0OBLELR9qF8SYg@mail.gmail.com> <1589193126.2930.2.camel@mtksdccf07>
In-Reply-To: <1589193126.2930.2.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 12:38:32 +0200
Message-ID: <CACT4Y+b16+-R=nQs-x1iDBZwBZKgJWf22Q=o1MvqkGP+8ybzmA@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] kasan: memorize and print call_rcu stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mqCzMPdN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Mon, May 11, 2020 at 12:32 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2020-05-11 at 12:01 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> > On Mon, May 11, 2020 at 4:24 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > This patchset improves KASAN reports by making them to have
> > > call_rcu() call stack information. It is useful for programmers
> > > to solve use-after-free or double-free memory issue.
> >
> > Hi Walter,
> >
> > I am looking at this now.
> >
> > I've upload the change to gerrit [1]
> > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458
> >
> > I am not capable enough to meaningfully review such changes in this format...
> >
> > [1] https://linux.googlesource.com/Documentation
> >
>
> Hi Dmitry,
>
> I don't fully understand your meaning, our patchset's format has
> problem? or?

No, it does not have any problems. Your patch format is standard for kernel.

It's just complex patches in the standard kernel format that are hard
to review for me.


> > > The KASAN report was as follows(cleaned up slightly):
> > >
> > > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> > >
> > > Freed by task 0:
> > >  save_stack+0x24/0x50
> > >  __kasan_slab_free+0x110/0x178
> > >  kasan_slab_free+0x10/0x18
> > >  kfree+0x98/0x270
> > >  kasan_rcu_reclaim+0x1c/0x60
> > >  rcu_core+0x8b4/0x10f8
> > >  rcu_core_si+0xc/0x18
> > >  efi_header_end+0x238/0xa6c
> > >
> > > First call_rcu() call stack:
> > >  save_stack+0x24/0x50
> > >  kasan_record_callrcu+0xc8/0xd8
> > >  call_rcu+0x190/0x580
> > >  kasan_rcu_uaf+0x1d8/0x278
> > >
> > > Last call_rcu() call stack:
> > > (stack is not available)
> > >
> > > Generic KASAN will record first and last call_rcu() call stack
> > > and print two call_rcu() call stack in KASAN report.
> > >
> > > This feature doesn't increase the cost of memory consumption. It is
> > > only suitable for generic KASAN.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> > >
> > > Changes since v2:
> > > - remove new config option, default enable it in generic KASAN
> > > - test this feature in SLAB/SLUB, it is pass.
> > > - modify macro to be more clearly
> > > - modify documentation
> > >
> > > Walter Wu (3):
> > > rcu/kasan: record and print call_rcu() call stack
> > > kasan: record and print the free track
> > > kasan: update documentation for generic kasan
> > >
> > > Documentation/dev-tools/kasan.rst |  6 ++++++
> > > include/linux/kasan.h             |  2 ++
> > > kernel/rcu/tree.c                 |  4 ++++
> > > lib/Kconfig.kasan                 |  2 ++
> > > mm/kasan/common.c                 | 26 ++++----------------------
> > > mm/kasan/generic.c                | 50 ++++++++++++++++++++++++++++++++++++++++++++++++++
> > > mm/kasan/kasan.h                  | 23 +++++++++++++++++++++++
> > > mm/kasan/report.c                 | 47 +++++++++++++++++++++--------------------------
> > > mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
> > > 9 files changed, 149 insertions(+), 48 deletions(-)
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511022359.15063-1-walter-zh.wu%40mediatek.com.
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589193126.2930.2.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb16%2B-R%3DnQs-x1iDBZwBZKgJWf22Q%3Do1MvqkGP%2B8ybzmA%40mail.gmail.com.
