Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6DTTZAKGQEO4NHNKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EFDD15F9D2
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 23:40:33 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id c17sf6878017pfi.20
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 14:40:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581720031; cv=pass;
        d=google.com; s=arc-20160816;
        b=bpLq7GtlG4Tu9Z1l8ocUA9IySmNBksgx42oVolzctgiW0UUFmHKvF6v2Nf1tAN1obg
         7Bg6bD5RqdFU7hxDGM5Et4u6oMgEw++AeJb/6DBe6tiGYyOEzjTjCYRBCJ9fALAM0wSc
         v62fC3z2r08ygZ+OchjpOBELp8rJRMQP0niUyORkR+V2CwShMWz3xH/B/Q8/Gs7xwL3g
         fA69Dpe1raO2sL2s/0sai60+AblX8lMmHkn2L/IBZWCrEKbTDOrThmifbwNiuZjqNWfK
         P0Xf6BjOyK7+e1tsnEBXThfuwdNlFSkI2jD8RhECUHNCSU0CERdtCPNVs5dn9aualhQi
         kV8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TpWHHix8IybYwWDgr8zeR4CHJLiL7RIlzxXjbWbe+rc=;
        b=mnm15VJfddK+X4HwiDRnZ5vdvJQ690CYs97ICvwhXUL7uuZFjWrf66aQDDVBdGE2Jq
         hRfWxOdaOkUP3hAUJyFlPDOfWMePPtIp9HHfXolPjtYsnKX10s4MOEMLnSDn/r1n63WH
         ZrTiA3Er92daY5dFXTtAqBgn2/KlgIhvtRAqIY+v10VexiTLxmB2chLplM/ynqNu/3lB
         god7KKv2jy/mdT3p12Q+hymz86NaG8MT/qlKEeugeppprIYn/aDMAv6Z/K/HjoncWe7+
         ArksRdpT7MnW6EO4OY1Vi5dQfZ95k/UN2oRZ2wXjG3iLxAGieW5Axt1N6CcoboFIFCcH
         oBow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNIoPDTe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TpWHHix8IybYwWDgr8zeR4CHJLiL7RIlzxXjbWbe+rc=;
        b=ByZBU3nQJrmCW4hIZPJWZ60brz8kvK+YENBOrB6SCNL6YbCBY70ucaOrnYS0KqDPBs
         66nFzGocVM1F1Ny78RGD5SW8/aJVr9myLfOxIw2nMUoKNCmHIZYL9+SlfB4WQvJHj15o
         P7Ozy3/P6NTCG9DsjwGNbA/YoCnIBIyfMQV1+QuFRfIF83Ox7zscfmTZuc5vKN9zi2cz
         TfxssvdbCifK8W4bdEZ5k53C4o6in99F8e+0U2iuvUnZamN8Zz70jgbsa0uCG+5P1omB
         0dmV31eHIhxpHWubR6YHDT3EEbUalTuQ8dMQv1OCzIvm7vcIgUULeRTEp9oGderVzZ5q
         ldLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TpWHHix8IybYwWDgr8zeR4CHJLiL7RIlzxXjbWbe+rc=;
        b=E6zR8Lpkd03z7R1Eo5Ml7kPMPjqRLrgB/QmgJZtw/G5aAsjQ4WYW300usvjNUiZwtH
         WfvKfOpIl6fkK2JXYZ/HAdPh3euejkFLRaVAC939XddNuQbAO9+SOuKOyGwKtI2Z1pgd
         UBftl5cgxW1/GkfnWq3VunZkEHI8RizxP6F9p8gL+KuzOogTDB8uYUNSWQRxYCqlYNZL
         jY94GIYMbK1Kz35tTgWX9H0lb036WlNNnFNiYNNxt2PfYauYn0zjqkCMUbTZmnW8Bgtg
         +4PNB9gJH80alTjUWnF1Axd/Grr0Q+5trnhmAJy1V/mCxwqbP+Rq/VfEa3CLYAJEjr8S
         UnfQ==
X-Gm-Message-State: APjAAAXADoBSJnWc9VtH2ybkMJ3gSTwrHblELlqRD4wV2+9p4nPhXC8U
	zxdnUVpTJbh2M00Vy96fLXs=
X-Google-Smtp-Source: APXvYqxW1b7hGnN1WfLnQlkAOE1GnD6yWI+bnMJj49qyzFgy9RlyKsPd0bWceSFM6ZghcqhTk9oJGA==
X-Received: by 2002:a17:90a:a416:: with SMTP id y22mr6299931pjp.114.1581720031633;
        Fri, 14 Feb 2020 14:40:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a04:: with SMTP id q4ls2062462pgq.6.gmail; Fri, 14 Feb
 2020 14:40:31 -0800 (PST)
X-Received: by 2002:a63:741c:: with SMTP id p28mr3064660pgc.210.1581720031111;
        Fri, 14 Feb 2020 14:40:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581720031; cv=none;
        d=google.com; s=arc-20160816;
        b=qIFwlVU+UNU3hSOtJfYi4IO1cvCKJOeZKzJWfxyZCvnpxcSSl15ZrHoM9jyYJvY76i
         3AnfpYqFRPcrvkMC/+I0g47ddB8jrHy7jYA4gbaomoFetS182rmjscxnkIoVmOkKtdL1
         l7sQy8Y6c+e6A0kJcEbKqKlqlVh5Gg0NTo0lSR9aWtbTLaq7OThY+pofk93qlh7upyIj
         V34q6DiHduHH0MbjEb2sokQDKOb3ujU651P/R/z/cNSeAhYXbgsLY7lB/bRJlHBBnP+s
         QZJJRw6ueBQzV83NQAJauHNvbhQgDH2hLU2tz13ypeXUxzeWJYVzRFcg/0Ar7XpQzr8I
         bRWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hdUCkUaQPGH7DYVaPlBQDbYHyu3ovmz8XcQjdVGXb7E=;
        b=Di570p2qeMdNMoTCjweH6s4W/SlDb7uW4jVY8K6yTr7xOcqZMksA1wDhxJsBDFFVaY
         zsXvNcUNHc9t9kwwUMaGDqnBdvJuaHJvE0zL1LWIw9gu3WwXlkCdVBRcO/hAnQPVX/bV
         0DXg2/QlobuXfJHIc1XBzd/HjB5ofgJTKQUieP+2sacN+CK4zGXWUMcOSWj5UxZuzBjq
         zFdDTn80j2A8apEq/2NhmMQ7f9hEaItfLLp/ibUuQ2pkigB8QxRZq8TubD9Y9Hh6LZ2q
         BqlnFU9LR3A6TbKHWDiY41owDNnUMR+3WhZBALA1Z5qUIL6zd9LMLzBqBGU7hUgxuJZo
         4geg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNIoPDTe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id t34si119613pjb.3.2020.02.14.14.40.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 14:40:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id i1so10948514oie.8
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 14:40:31 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr3254251oiz.155.1581720030113;
 Fri, 14 Feb 2020 14:40:30 -0800 (PST)
MIME-Version: 1.0
References: <20200207120859.GA22345@paulmck-ThinkPad-P72> <1581088731.7365.16.camel@lca.pw>
 <CANpmjNPbT+2s+V+Ra3C-4ahtCxyHZzOLzCDp9u7c339vN6u7Fg@mail.gmail.com>
 <CANpmjNOXma=Px-EMMp-F5dij2BaF8iZFj-3WGCXf+bXrdtdU5Q@mail.gmail.com>
 <CANpmjNOdUZJz9N1ydecFrOgpqOMgwOT576dxo97XooPwwED3Hg@mail.gmail.com>
 <2C38E1DE-647E-4B90-98B8-D7F3C0512ADA@lca.pw> <20200214094423.GP2935@paulmck-ThinkPad-P72>
 <CANpmjNN17WCK=4=ZUfcKEARarYEheZ+L88JAKm-qG_zXM9DauQ@mail.gmail.com>
 <1581709863.7365.77.camel@lca.pw> <CANpmjNOqwS0OWduzsYRRygxpbtVR_x7vmWGAip73qj+caK+KXg@mail.gmail.com>
 <1581718076.7365.81.camel@lca.pw>
In-Reply-To: <1581718076.7365.81.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2020 23:40:18 +0100
Message-ID: <CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw@mail.gmail.com>
Subject: Re: KCSAN pull request content
To: Qian Cai <cai@lca.pw>, kasan-dev <kasan-dev@googlegroups.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PNIoPDTe;       spf=pass
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

+kasan-dev

On Fri, 14 Feb 2020 at 23:07, Qian Cai <cai@lca.pw> wrote:
>
> On Fri, 2020-02-14 at 22:48 +0100, Marco Elver wrote:
> > On Fri, 14 Feb 2020 at 20:51, Qian Cai <cai@lca.pw> wrote:
> > >
> > > On Fri, 2020-02-14 at 12:03 +0100, Marco Elver wrote:
> > > > > > Lately, I have spent a few days reviewing the reports. There are still way too many
> > > > > > likely false positives that really need ways to control them efficiently other than sending
> > > > > > hundreds of patches using the data_race() macro. There are many places write and
> > > > > > read only care about a single bit, i.e. page->flags that is safe from a data race.
> > > >
> > > > The bit operations are tricky. Just sending 'data_race()' doesn't fix
> > > > too much per-se, so let's think about this.
> > > >
> > > > For now, filtering the marked atomic bit writes (like you have below)
> > > > and unmarked reads, you may use the following config:
> > > >    CONFIG_KCSAN_IGNORE_ATOMICS=y
> > > >    CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n
> > > > (The Kconfig defaults together with these 2 options should give you
> > > > the most conservative reporting.)
> > > >
> > > > That would certainly get rid of all the marked flags writes (which I
> > > > assume they should be) and unmarked read cases. Although I still don't
> > > > fully agree that all the reads can be unmarked, for the time being
> > > > let's assume that's the case.
> > >
> > > CONFIG_KCSAN_IGNORE_ATOMICS=y will not work in many places where the write is
> > > only under a lock where there are many of them. For example,
> > >
> > > [  460.852674][  T765] write to 0xffff903d862d107c of 4 bytes by task 810 on cpu
> > > 5:
> > > [  460.860130][  T765]  css_killed_work_fn+0x9e/0x350
> > > css_killed_work_fn+0x9e/0x350:
> > > offline_css at kernel/cgroup/cgroup.c:5098
> > > (inlined by) css_killed_work_fn at kernel/cgroup/cgroup.c:5385
> > > [  460.864965][  T765]  process_one_work+0x54f/0xb90
> > > [  460.869713][  T765]  worker_thread+0x80/0x5f0
> > > [  460.874110][  T765]  kthread+0x1cd/0x1f0
> > > [  460.878068][  T765]  ret_from_fork+0x27/0x50
> > > [  460.882368][  T765]
> > > [  460.884577][  T765] read to 0xffff903d862d107c of 4 bytes by task 765 on cpu
> > > 103:
> > > [  460.892114][  T765]  drain_stock+0x7a/0xd0
> > > css_put_many at include/linux/cgroup.h:416
> > > (inlined by) drain_stock at mm/memcontrol.c:2086
> > > [  460.896245][  T765]  drain_local_stock+0x35/0x70
> > > [  460.900899][  T765]  process_one_work+0x54f/0xb90
> > > [  460.905640][  T765]  worker_thread+0x80/0x5f0
> > > [  460.910031][  T765]  kthread+0x1cd/0x1f0
> > > [  460.913985][  T765]  ret_from_fork+0x27/0x50
> > >
> > > The write is under cgroup_mutex to remove CSS_ONLINE bit but the reader only
> > > care about CSS_NO_REF. Those still look safe to me.
> >
> > Right, at this point I'd say they are data races I'd expect to see.
> > Simply because this one is safe, doesn't mean the next one is safe.
> > Also we need to ask a few more questions here.
> >
> > What are the assumptions?
> > Where can this function be called? What do we know about the callers?
> > Do they use it in a loop?
> > Are concurrent writes to this bit possible? If yes, we should
> > definitely apply READ_ONCE.
>
> My observation is that the ratio of real issues vs false positives is really
> low.

False positive appears to be quite subjective when it comes to data
races, and everybody has a different set of preferences. We know this,
and KCSAN is already pretty configurable

What is your definition of false positive?

> > If not, you could apply ASSERT_EXCLUSIVE_BITS(css->flags, CSS_NO_REF).
> > Looking at the code, this bit only seems to be set on init. Since this
> > applies to all accesses of CSS_NO_REF, maybe a helper function to
> > check if it's a ref-countable css?
>
> ASSERT_EXCLUSIVE_BITS() could work, but my observation I might need some courage
>  first to send those patches to subsystem maintainers because most of them if
> not all will be false positives and could easily test their temper. [1]

One of our goals should be to mark enough intentional races
(eliminating data races), so that at the end of the day, we're left
with only the critical ones. Although right now, we're not there yet.
This will take time and careful fixes over a longer period of time. We
can't make all data races disappear in a week. The way I see it is
that, the kernel has data races, and we need to understand them, but
wanting a tool that just declares the kernel data race free is
impossible, because the kernel clearly has a number of unsafe patterns
that we need to investigate.

There are 2 options for you: (1) keep sending patches, trying to keep
up with data races as you see them; or (2)

When you say that maintainers may be unwilling to accept patches, then
I claim that only pertains to those where we haven't fully understood
what is happening. The only patches I'm worried about are patches that
include 'data_race()' or '__no_kcsan' (or KCSAN_SANITIZE_file.o := n).
For all others, if the reasoning is solid, it should be an
improvement.

However: Concurrency is tricky. And it is all too easy to miss a
number of cases, and that's when the patch should get scrutinized.

> [1] https://lore.kernel.org/linux-arm-kernel/20190809090413.c57d7qlqgihdyzt6@wil
> lie-the-truck/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw%40mail.gmail.com.
