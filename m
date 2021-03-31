Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUOQSKBQMGQEVVWGVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id EBAAF350513
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:50:26 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id fb10sf1595648qvb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617209426; cv=pass;
        d=google.com; s=arc-20160816;
        b=kWQqbF4zPq8UxbOUYfpiKGowXYlE6Tngz2LJ5FcdPCRlQHlf2iIeIW03n1sdhqHbNM
         5FXg8j4rmSFff93nqj5CdkboAiBEtmTQJ4L3T996/GBvLRaEMYvBxwu+SvndgRGg60ZX
         WsCE/3K7kXNa/gcI3HgtuMtr7Q+kGDuvS7Y4mZlv63w9nBRfmj4mRvwQHDSsI8lJoSLS
         MMHihgYo5Oybylr1A3leog/rS9gLqiB7TlfmwMjQlLPBGIPA+sfheLDV8TFee1MgDxh2
         E7trx37E7YY3OHDdiCCBG/YAfoUeILdOEOweE42O6NhMc5hxM2v7zpRzGwP3o6cWLg2Z
         Y3eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iOshPJBflZ+Wq4gdGKxtznrd6lRpiHpnxzdgGRldSME=;
        b=FKSuQizKmmSFmFvtli7eea+pMJlFmi8jY8iKxerpoHbd1hEDf9Xpg4PUN8ST2wEgQ4
         LltRP3RuRoQTxXTNC+dpnxkZ5Bhxw4BaWSFgtKkRwffl3t5+/qG6JL5VfZo6togP7C2g
         RcbrdX7Oxg0RWxjU9PY4KOul5cXIxyVp7ocXhB7a2IxH8k712ydfXXawqRCZ9hXdOQXC
         V+tyQljpMbaonx4Dwv87Sqg8/TdK4u3umPudPvgaGXhbx7J8r/XPvoCyyLkR1/eBeM96
         a1+7QPIEnAolWU0Zgno37bUlGtjBbJmuPEDLl7ko/WG/IrL572J1c2qTS7tc7/+BrHnB
         20lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ic5OrjlK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOshPJBflZ+Wq4gdGKxtznrd6lRpiHpnxzdgGRldSME=;
        b=r20TzDW5ozRCBGBtTmGx3YtEYaY7wQwB+1CG9ymbdfTvaGE/tX3vQj71/Q/KnvXLff
         qb17E/kEwqUwH8lY/B3dP3yFaRMHu/M63eat0Lh9qGIxgjX7O/pOKW760JVOp8/H65bQ
         fo057fTUBcLZFNP1PMrJss9K9m3OlTQZ2d+UZGsLI5NdditX/cTlsWEjsVBHTq97C57/
         KNiG+XSMpjFUmyFRnBKYCX+mByhRl7o1pSgdXR63iT5PIoGHSXaNumD78x0uWoqoVNQi
         tTzACfnn1zwn/ymx5PRcLRGdbMMVXel42BLCA9YVCljJEe7erEK0QWwVrwKi4MtStADe
         hWSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOshPJBflZ+Wq4gdGKxtznrd6lRpiHpnxzdgGRldSME=;
        b=KUHZsAU3yTzKhZ5EfwCLnjaWWzY3a0+EmQwXgyt82gJHSNto5+F5Vy96PkAYq2wrJH
         cAuk4RhEoVJTMh14/lmflo0RIXVFVQCKYDdix/EcQ5ffAbDjtYtRjPtHfJEHhufAX9IU
         ymYjNMTBQ6w8rOReGmJ43lIAmsMe2Q5JXNNAIJeTzircB6fZqKtMTX0g9iKQF44Ov+fg
         y2XdMrueV1Y1FyTkqnmA3VOe9h9jbPS5JW0LyBx2i+K6YUJYMKhMQ9pRuY3+ai9Kobls
         3N3QJfrOyHnj/kGIrsfPjv93XNtD+njgTI04ZLjVXxCwbYxoCglhihXwqMSlHlYWR9uN
         ghoQ==
X-Gm-Message-State: AOAM532ymx36WLwVBmgV9WoQxZBykF5uAd0TrU0NSU1B1xlgAGpO9b1T
	usKn00q+h383wsUWxrmKFiA=
X-Google-Smtp-Source: ABdhPJwXYQ5VFDlmk+P621J/DZ/X4hrKpTcWgYLykRyV/64HWmILcilucgjgDVzV1PP2zTvnP1Ofpw==
X-Received: by 2002:a05:622a:216:: with SMTP id b22mr3243579qtx.263.1617209425938;
        Wed, 31 Mar 2021 09:50:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a050:: with SMTP id j77ls1648393qke.10.gmail; Wed, 31
 Mar 2021 09:50:25 -0700 (PDT)
X-Received: by 2002:a37:5884:: with SMTP id m126mr4263298qkb.459.1617209425507;
        Wed, 31 Mar 2021 09:50:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617209425; cv=none;
        d=google.com; s=arc-20160816;
        b=Uz4tnHoNZrq2A56t1nHx3surq/6DVElBPv03cisV/i8Df/e3YKbWtDclkmlIBsLeIL
         QyPdkO0T0skGaTLmJrGSttf+2b5ZgZkKq484hWRkg1jOa/HpbdrnaP4tiL8ZIKrBxKVK
         iZDRhDZ0c5y7UCP7pqSZk6a88WnySIwrn1npEwtfZJigaEywdZbjFNg5zz6bSP1AUX9e
         4oGjkCjn/eLeXHpVTD8NxA2cQx1JjJ+nJgWBtWvet0d23WpNKiiVdzhdD3VJz42IXeaL
         9mUSxPskKldoYX697B4FG2azPERaedRhEp76EKa1CfFVI4S/3gosKHtzIWN3J5PYhxrJ
         9fqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rdpwslgy7i3fT+uqHNLqy9H/4PdpXsKpQtKlUmrnWNs=;
        b=Dlbd+oI4TEVudnCNJi3tuUE2+7x8fqGiAiieVb74imLZsfJpxUoZJSooSEIlS+xI7B
         6tUKsTYMTJ0FVWCy7MvN+5cM8/tx0+xeCknj6Uqqb7zmo5WNdq/54477FaqhAnvUdT3j
         pg31INPymAsX4mM4udQmFumy0cw8px+65zRAyZReRTp9EfB++LpXBDVd3mHPf7+19qRq
         tjCJUdFlwdehg1bG2o+Zujey+NIy8V73XUjQrxAMpTFN4mic2u3DPnGA41HD/lgqIs7N
         lXpFEmSDJfjI1VhkuXLIe62t6+Wx9JxdR0zQjAtzIoCN91eUGxeGcAdwF6SXlvC6M7JB
         lB4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ic5OrjlK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id b2si398660qtq.5.2021.03.31.09.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Mar 2021 09:50:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id y19-20020a0568301d93b02901b9f88a238eso19540040oti.11
        for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 09:50:25 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr3484254otq.251.1617209424896;
 Wed, 31 Mar 2021 09:50:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com> <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
 <CANpmjNOPJNhJ2L7cxrvf__tCZpy=+T1nBotKmzr2xMJypd-oJQ@mail.gmail.com> <YGSMXJvLBpQOm3WV@hirez.programming.kicks-ass.net>
In-Reply-To: <YGSMXJvLBpQOm3WV@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Mar 2021 18:50:12 +0200
Message-ID: <CANpmjNPGmzzg-uv3DGZ+1M+nDNy3WiFU7g3u_CzR-GBju+1Z_Q@mail.gmail.com>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
To: Peter Zijlstra <peterz@infradead.org>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	Jiri Olsa <jolsa@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ic5OrjlK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Wed, 31 Mar 2021 at 16:51, Peter Zijlstra <peterz@infradead.org> wrote:
> On Wed, Mar 31, 2021 at 02:32:58PM +0200, Marco Elver wrote:
> > On Mon, 29 Mar 2021 at 14:07, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > > (and we might already have a problem on some architectures where there
> > > can be significant time between these due to not having
> > > arch_irq_work_raise(), so ideally we ought to double check current in
> > > your case)
> >
> > I missed this bit -- just to verify: here we want to check that
> > event->ctx->task == current, in case the the irq_work runs when the
> > current task has already been replaced. Correct?
>
> Yeah, just not sure what a decent failure would be, silent ignore seems
> undesired, maybe WARN and archs that can trigger it get to fix it ?

I'll go with a WARN and add a comment.

This also revealed there should be a requirement that sigtrap events
must be associated with a task (syzkaller managed to trigger the
warning for cpu events).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPGmzzg-uv3DGZ%2B1M%2BnDNy3WiFU7g3u_CzR-GBju%2B1Z_Q%40mail.gmail.com.
