Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSOQRCAAMGQEJ2NGQFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id DCB752F897E
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 00:42:02 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id b38sf1885208uab.19
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 15:42:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610754122; cv=pass;
        d=google.com; s=arc-20160816;
        b=ArSd3u6wNkkeTfQDGzLFutI2o4U0yB35kNPLQGidlcO7kTCxEe8L0DDvWT8r0hghif
         E1aj2d0C7B78Ozoz4yCZiaJwQtAKqce1FUFg3YvFZ92AuZukN0NAvGTz76DMkBOUcRR7
         o0wc+WULUO+IHKx7FmOWfx4onQHXSRHa9g/R++nUo+xizwSJKzyOwRqUV8pfXW0VnkGG
         6GNCn2rsG46t33e00M9ieM6wxjza1aPdPr4AbsgsLYWGsV6M6wVWPp7FhzEim5wU5XpV
         wZmB+wIQc8cDC8En5urfwSqnkPOYOfZtLbrytkHV8fgVx0qTq/eXYI0ZUqL/zCAswiws
         SSzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/2dWRGNiDPWJeIiC035Yzr6rV7rEPLFaupVlTaQ/Sis=;
        b=ZsEy7ZP9Egpn8TNOtuvE3reaMEN9X8Z5RjNP2s2jBu5DsDJhuzsv4AQ8JGYB8ghM0d
         xp//U7yy64JrT934RaOAeIlyyw5wAGXNgKlbNL9qkpBfxslKFEoTsmDWE+vz3vJMLtST
         Ub9JbHsBbyFJWSiTyo/YY92Xd3XWvpKpx8iX8vT01/KOhpaGA7nYBFsihXw2IA7Znysb
         HNUqdnXtlAeGY8wHWQCfgiuLxNyq9ndZei7hc2rRQ2NqsCyHdfvfaKtuefaiLPDv82Oo
         TaY1kOTki4ZB8z3KFRcOhQj83HFaESa/AoE/26zj1XNNJ38xoHS9QTiRh6cNaA4S0EBD
         ltIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mwaW8nNO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/2dWRGNiDPWJeIiC035Yzr6rV7rEPLFaupVlTaQ/Sis=;
        b=P0bkRSZPXvNcmk/puzRtlKdZKILg7iF/OPgV2vZ7/LuwjVEzNkKRALPlUrXFy621CF
         G5NrYo6ncUGM0KYfnOEVJROgHTJ+HAzJYRP6SdaWcqzClNYhc5+I1LtefehYHuA6bqUz
         1/M4vdNG9rTJRoDLlpLYqk1zYPg0NtbSxnoVaw7ykknNiqPSjvT2YFS8WDi6bzTog+3J
         Aoa0u9zld3pnYhrLJYebe960+peIefVCAQ9F8S51MTpp4Y5uebXbsCFBdG+H3jbdoL9m
         n9ui2GN0nrL2uqDF6HafspkVeb1elOSHD7UjL3U84N2IGETg2CX8D92DjnpGWxiZzV+c
         VKag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/2dWRGNiDPWJeIiC035Yzr6rV7rEPLFaupVlTaQ/Sis=;
        b=V1XhL8bKNOCN7sY0mGzCWKNBQRiSenZlK2kIYn+zdqxt06bKRAEaQb62FVUIgPQU9q
         EBLj1/KgcVTySaG2gH0lVJgyTjbZ1fa3f+GNbVuc3JGbYliDfIHqL5KmQB+6LJebVCLc
         XrepglqILY+F9SPpp94knLYza828kcYCDYRg1unwIDoxqpoYZx+YD/CNJcYHzYgHaqWG
         0HUI2SPrTUwOjcMYsS0YxbexVUDgPl4NUIV8uwWrDMjT1fytXcUnVzqtyNEUNKnX51Eg
         TRKbc5XoBM2cpncv1pSE8aFvJUE9oVjjlfJ302QMXeQ07m6mlp3CyfNqcTQW25ya5DGK
         veRg==
X-Gm-Message-State: AOAM533pldhzx+me0sTqIeNoLpazyR+blvRtPrlAUBU/8+t1qk3ulORm
	vO9VNcTfec6VrrbtLbh2FBQ=
X-Google-Smtp-Source: ABdhPJwqh8AiJre+PofbN3TpluWW44aw0TDAPYUJs8mqKvyGxNWBWIyMOyD4DsgGpO+FuuiHOJ8tnA==
X-Received: by 2002:ab0:3894:: with SMTP id z20mr11746842uav.82.1610754121983;
        Fri, 15 Jan 2021 15:42:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2409:: with SMTP id 9ls857631uaq.1.gmail; Fri, 15 Jan
 2021 15:42:01 -0800 (PST)
X-Received: by 2002:ab0:1c0a:: with SMTP id a10mr11786794uaj.89.1610754121416;
        Fri, 15 Jan 2021 15:42:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610754121; cv=none;
        d=google.com; s=arc-20160816;
        b=iMI3A6T3hqS9xMNyk7x7GvF+vqYs7mDX+2w3I7oFDIY+sbnM5wF3WuhbhNmbLmTi33
         g2E4zu1ZfCczwcFyGmPI+kvImga2TWAD4KCB4BPv+aGo+sSbUalSXWxc07sER6s588jh
         e4OuRmR17BYMV+1ToL3hXXOU5QACJpQTGpvX228INeSluDcjim/g38rz8mXNMNlR+DVs
         CPyfwrzgP8/MVJVxF4D3Ic4YCbkNX8+LvO4TA24TwUgbMVqy4BilbPqDwtOrGoC2f/jn
         1Fl9FdVInDhf0va32Tfiv5yOMVdtDpFVsjy+jewMwMbbWHCv17Jaofjl6ZYNET/a+19W
         j5pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+vf2mv3ce7DHbGNAfPAeihSYLyEs49+dxZFxLcYTSIQ=;
        b=cvd/NClXUkM9lQSyqPGqXmCawkFhBjwSbKi3OJgkBlPSMzNk7PcnNEcPBy5Y+u89mJ
         SQfo+asRr00QpBGfD865QFJtsx3CtS9rBrLsViM7pYPDvsOLZ2JdoLhnGtbv9BRd4nL8
         s1clEwH/xrrOxhxEnB4mfuMXPCqPPvxTFLY3hjqTDXoQnNYUFPhD8qgilCNA6L2QDUsF
         7Aswh82yQa7dL8xTVK884brwo+U49vuTjgQrwcv0q4ChGU4STyvywllTld1d65ZM4oSH
         VNX5qnmCPAjB7V62efFc0q/nb8ymd4QefjQqJ3pKkJd9B/qXEo/gSBbo1GLa0SiFTu0U
         XAqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mwaW8nNO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id m19si684800vkm.5.2021.01.15.15.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 15:42:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id j20so10243181otq.5
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 15:42:01 -0800 (PST)
X-Received: by 2002:a9d:6199:: with SMTP id g25mr10230665otk.17.1610754120789;
 Fri, 15 Jan 2021 15:42:00 -0800 (PST)
MIME-Version: 1.0
References: <20210115170953.3035153-1-elver@google.com> <20210115215817.GN2743@paulmck-ThinkPad-P72>
 <CANpmjNM9++GSuSHH+Lyfi23kW8v0aXLX+YbD20UX8k5jAAaSnA@mail.gmail.com> <20210115233156.GO2743@paulmck-ThinkPad-P72>
In-Reply-To: <20210115233156.GO2743@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 16 Jan 2021 00:41:49 +0100
Message-ID: <CANpmjNPDkqULbPQZw29axaBaueWs-H8BeyDrEHSBn=xgtN7Lkg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add missing license and copyright headers
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mwaW8nNO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Sat, 16 Jan 2021 at 00:31, Paul E. McKenney <paulmck@kernel.org> wrote:
> On Sat, Jan 16, 2021 at 12:21:53AM +0100, Marco Elver wrote:
> > On Fri, 15 Jan 2021 at 22:58, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > > This one seemed straightforward and I heard no objections to the previous
> > > two-patch series, so I queued them for the v5.13 merge window, thank you!
> > >
> > > If any of them need adjustment, please send me the updated patch and
> > > tell me which one it replaces.  Something about -rcu being in heavy
> > > experimental mode at the moment.  ;-)
> >
> > Thank you!
> >
> > I would have given the go-ahead for the other series next week Monday,
> > but I think that's a holiday anyway. :-)
>
> It is indeed!  I guess you had Wednesday last week, with next up being
> Friday April 2?  ;-)

We did, correct, and the next one is quite a while then. :-)

Happy holidays,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPDkqULbPQZw29axaBaueWs-H8BeyDrEHSBn%3DxgtN7Lkg%40mail.gmail.com.
