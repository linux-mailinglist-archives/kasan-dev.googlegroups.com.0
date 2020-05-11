Return-Path: <kasan-dev+bncBCMIZB7QWENRB6GE4T2QKGQE6Q25WAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 92BE81CD5C8
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 12:01:29 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id v8sf3905020otj.5
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 03:01:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589191288; cv=pass;
        d=google.com; s=arc-20160816;
        b=0sK6cRnuEBfvHGUBqSeyVbWQgnnqaza/XXKipo58y4lWQnRR65yX0cgpw1LTQEzJHN
         izN6IZyUsH8kuc7vA3ua3unWR7KiecY7h8f2TYYIpywBml0Suetvd7RI4hc1Sa9mhfYo
         CfwN7+thN8biaf8cXhNpv3KpZT5ImCzUV4oX1EzS16jQFwM2W1WjemdT2wvXWhZZDtit
         acUo+0Twr702bL8xyLZk3RdmHQTrxN3q+irZyZCQ27GnGH2NJVWhVX9Tqqkh2AKlIZaX
         7ChiuJJ2Hsn8DwAHMVGyebsAxL2FVnRh5dW5agTLAe7NBvJw8cXJPgAVEW+fr/ZCe9tj
         axLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZLGtxdBvzpbgcvC3G9UPMFCWK/b2EuIyqFyDHLuP3sk=;
        b=KzKHqZYNSrDYTP9/PWJnQoE/KT58ELhlYZc/P3NBGlMqjHMrrskbYNhj8X2nfZN8HH
         GAGTX2hHXu7t2ZefyAOFr8NAd5DVfqm68+ZY5EoGWYL0EuxMEbBVJvAQQQ00qVqjf1/U
         h7juRSViBL6e+YIqMsVLYcc2UshoT1X5F9ciTg9T37z7TnkhhaIFKvU5bpyX5pHX4e/r
         8ZjFwAZsbaKVps3+/wEapM9CbDamFqZZdTM8AbgMINg4LJi7uOOXvdAfzs/LKrkJdLrr
         vWEu2iA26myMMEDAou6bSHjZTzzNizwJO1gHP/8viDdRkpPnK86bGuKqmCKl5HDjgZcN
         msWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fc1FlTQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZLGtxdBvzpbgcvC3G9UPMFCWK/b2EuIyqFyDHLuP3sk=;
        b=fhEjdVH/8T+mg3NPUyMnR6L2zsjddLVyqkMGRF2YAd8jWtsq6oGZrShAJvHl96BTd3
         o4t/P772wcQb/9Sd6XZKnAczNq19K9ZsqUqE//XLtJaUEpMrMEjr0YTQrjgV9dvqCTGI
         la8Pb3a7VSiIB3t8V87PBpNp1uJUqeE0fokVBS8VRJ8XFhQ2fu5LpPIlQEFrXU6Gl1La
         IboiKzAmqj9mPr1XnbosRTia1kta56yP/tlIVrbtY8k2HJAwIjJQbDgZxaEV3yMJEMLD
         1DjLtF5MPWW/+CNpVcWOgHY9xgDsciIu9eNYz22dIIhOXlOqXsikYsgbR1UBpeEz0nlP
         tO8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZLGtxdBvzpbgcvC3G9UPMFCWK/b2EuIyqFyDHLuP3sk=;
        b=jp6sf49LfAConvamqNeK/j5jiVJBWxjophgD+eCVrx4Ffk9RAj3ria0Fh8vmr10vnW
         y0SRpYfEEBOxJaQJfewvMmcYDa3eQ2yYY9Nb5HhZuqnAmX67OGrCwetXZowj45CX/AFy
         p5vWPtT8QQLh9tnZVQxtAuYl6T6v3N2XuxgpGvUKjtw326+gS6UnnSVU6V+kJZ+cBaBh
         TkkZmfKJwVYkXKWINMIHJ4qJJK2KDaOKurG1BC1sQ4IgZ4KlQNqFhD+j7ga0IFilsdy6
         q9vD2NOEY9/lHqDdOuMBMHKF38ecmKf9162UZYdILDEI0ohXM4vLwnUl/qVzg0PiJUyG
         tL7A==
X-Gm-Message-State: AGi0PuZh/dsUl8IKtJNSUeqwCAcIp5TReJn59TzKNF5UuJlq1PNUPL3Z
	xfrAVvIf4GNZ1Zrpeq3mT/I=
X-Google-Smtp-Source: APiQypKEUbTGe2LJEhLW2tin8aVoq+T1yGS2DQg/OboAok9ISFIqgO7axl0DAcI59qnZ/58SSWYXLw==
X-Received: by 2002:a05:6830:92:: with SMTP id a18mr12396278oto.317.1589191288143;
        Mon, 11 May 2020 03:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3104:: with SMTP id x4ls3691133oix.0.gmail; Mon, 11 May
 2020 03:01:27 -0700 (PDT)
X-Received: by 2002:aca:c4d3:: with SMTP id u202mr19219441oif.113.1589191287635;
        Mon, 11 May 2020 03:01:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589191287; cv=none;
        d=google.com; s=arc-20160816;
        b=WPH6mw+sQe7cLf2N67EOVNsBrJqWF8QKvbdWITt1My0ld/ztSgFFAt2fagC7Y0jNg9
         E614pU5xLXK2EcjqXwfPm2icECN5Tweu8pQ/GfGfuois2EVQ3NJI1tVpzpzD7mpautnB
         KK0B55YRYT5gk0R5VR2VU+3sIFKRgcGL8U2PF5wOGWW8deFAHKuyw1X8jQK4PCcTyFaI
         R+CRVlxv0TnMX7Am1HeSF4SnLi4KYtOQVmUzPk4JaUcJAXiIggmGH3dJ+LmteXO69vGs
         kH8fDETiSI1flOR/Ju+dtqfq7uTs5N2HQSSc299CtMYrZBM0agRnBLoNCyNEJBiS+KUC
         IS/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dEBQw3076mBvIY7CBwoK5uqpgbduOcTYtDKSbai7h/o=;
        b=YFGI/xyPqT6upKJhVvDjh8BqOa04ka7tUvPTV4/NfC60BYmC3QMCosj8V59bX6IzD/
         flKczzwgCAja3N2pQWh8pnDOEVgfyxbGIPT0P6xe96QCWO+LcmilGHLUGe/CqevqEcYY
         /BnVgV+ute6riUl3r9AEa+jeDJXpkoyYr0qCiV/RGPIfBgm8xfiPp8Nwx4OXwGTCl/dO
         zjOEP3+7P4gT4VqaFBvQACYe5KsUc24OMKgZyVUfpOyMf2cwbPOFoH8c/HgRRjSLcsEM
         SLaGknXRzCiRh18R+spTUTT4kduNYyuq6i+Lcb5RxwAqMOHAxb/xIZOu9rzFrfC383zt
         yiBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fc1FlTQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id x23si398469otq.4.2020.05.11.03.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 03:01:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id ee19so761961qvb.11
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 03:01:27 -0700 (PDT)
X-Received: by 2002:ad4:5a48:: with SMTP id ej8mr15299087qvb.122.1589191286510;
 Mon, 11 May 2020 03:01:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200511022359.15063-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200511022359.15063-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 12:01:14 +0200
Message-ID: <CACT4Y+aC4i8cAVFu2-s82RczWCjYMpPVJLwS0OBLELR9qF8SYg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Fc1FlTQb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
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

On Mon, May 11, 2020 at 4:24 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This patchset improves KASAN reports by making them to have
> call_rcu() call stack information. It is useful for programmers
> to solve use-after-free or double-free memory issue.

Hi Walter,

I am looking at this now.

I've upload the change to gerrit [1]
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458

I am not capable enough to meaningfully review such changes in this format...

[1] https://linux.googlesource.com/Documentation


> The KASAN report was as follows(cleaned up slightly):
>
> BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
>
> Freed by task 0:
>  save_stack+0x24/0x50
>  __kasan_slab_free+0x110/0x178
>  kasan_slab_free+0x10/0x18
>  kfree+0x98/0x270
>  kasan_rcu_reclaim+0x1c/0x60
>  rcu_core+0x8b4/0x10f8
>  rcu_core_si+0xc/0x18
>  efi_header_end+0x238/0xa6c
>
> First call_rcu() call stack:
>  save_stack+0x24/0x50
>  kasan_record_callrcu+0xc8/0xd8
>  call_rcu+0x190/0x580
>  kasan_rcu_uaf+0x1d8/0x278
>
> Last call_rcu() call stack:
> (stack is not available)
>
> Generic KASAN will record first and last call_rcu() call stack
> and print two call_rcu() call stack in KASAN report.
>
> This feature doesn't increase the cost of memory consumption. It is
> only suitable for generic KASAN.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
>
> Changes since v2:
> - remove new config option, default enable it in generic KASAN
> - test this feature in SLAB/SLUB, it is pass.
> - modify macro to be more clearly
> - modify documentation
>
> Walter Wu (3):
> rcu/kasan: record and print call_rcu() call stack
> kasan: record and print the free track
> kasan: update documentation for generic kasan
>
> Documentation/dev-tools/kasan.rst |  6 ++++++
> include/linux/kasan.h             |  2 ++
> kernel/rcu/tree.c                 |  4 ++++
> lib/Kconfig.kasan                 |  2 ++
> mm/kasan/common.c                 | 26 ++++----------------------
> mm/kasan/generic.c                | 50 ++++++++++++++++++++++++++++++++++++++++++++++++++
> mm/kasan/kasan.h                  | 23 +++++++++++++++++++++++
> mm/kasan/report.c                 | 47 +++++++++++++++++++++--------------------------
> mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
> 9 files changed, 149 insertions(+), 48 deletions(-)
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511022359.15063-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaC4i8cAVFu2-s82RczWCjYMpPVJLwS0OBLELR9qF8SYg%40mail.gmail.com.
