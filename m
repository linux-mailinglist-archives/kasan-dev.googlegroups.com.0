Return-Path: <kasan-dev+bncBCO4HLFLUAOBB4U43HWAKGQEQ52CXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 411C4CAF60
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 21:39:31 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id b6sf1587989wrx.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 12:39:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570131571; cv=pass;
        d=google.com; s=arc-20160816;
        b=kNkVHL8iI+lwR4x3EQNVi2c7qHgFSiJhKwLtvGOB3pwuSqp5gExAtTfoTB01qJjf7H
         G+LwO3rBGo6cRem5I5WMENVo5apCnY345vavAKSXGufscz6iH+6R2QQypRGqsOeewcOD
         KDfZFJ9OqN0Qy9foEl9ReRL03PdUoNklSGztHdbJtl7GyZJgjySfrP7LZQUhjifFJOQ+
         2fnI2qjftEjbnsbsu+ajYduNOofZbXiXKRt7dIwuJ9sznAo+oHioyr89YfWJDZaSEgso
         8VG5L8zNqNy/6JL3vqSL/evvFcS6jDp7ZVvpkWQZNeElBu45sR8sU9rXReWH70sJQ25U
         Xy3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=b+LkxZ4reo/pX8kAtkBOWR034WN/MyVhoSJZy3cdn5Q=;
        b=zJCFvepFIMnVODGlInXG8uWa3w2V0HM6sRuIlUdFK7aq2sqPCROFfflgmRmcR+l0Oo
         v5oB8bjLN9QWlztI0yGBd5UzKDHYMHX5Gg6n3826OhdT6UZ37X+Otw6QxMvdeBl+j+si
         PvYm+89qUrzYxtYoxYAfsMQmme/Y6sToa+/t62M42xBo1U8eiIyX4MhAKOkIly2Ah7bf
         NDOmBL572s6kEXqXpJVZ5rcxS3+Eerc5H3vDh4NBYl6aLWFLLO0pNIg+RMJLu88jkevr
         U7iZinT7SZxzFXkZ5Ka9Jhpo0Ees06iuI1H4i4gQ36sHSY1Biujjfdi0O8iZYKVDIe+j
         aTlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b+LkxZ4reo/pX8kAtkBOWR034WN/MyVhoSJZy3cdn5Q=;
        b=MQ1M3C/vL8QDSfrVpIrDWQQpd0GL9EwYNCQz4TJ/la5PGuQ4NbLKEgXTkOGgYD9K5K
         q7YxezSZu7tryVI7gsheh7EQcUALs2E93/WMjLWwLbgJuaQqN4LyOUJyP3mFxfJ35MnI
         oRaFPkfMJv3o0Dc0tgA+x9cJ/dvzshP1ipwfSQvKBFEJ/SYVtBl+kKBzew06P9BZoF/K
         71Z1Fflvb94qgOdgteOYIuYrSiYPbg138JxCmlQTPBjEaVNJlCi8joYp8WgJ3LfC3W03
         /UUEvCNzm2IAOp8sfyCL1dDN1w2crc22/1WFDx9uS353B8hIq/XoDx3Qr5OFCRVPqVNW
         4G5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b+LkxZ4reo/pX8kAtkBOWR034WN/MyVhoSJZy3cdn5Q=;
        b=nh9LtDT+q5Nlozq961J01VYT7pbbMwNBqrFiwUXFqoRiSM+tCOi56d1kfoNCdzdANw
         4JcTVKbd7RXy7Xc9BFGb7ZxsHXjW3B6jtGSfb6BcvmmrsbMnJfjiLknxgbla7iYjgVQv
         rGCtwH02D76UakxeyhVh1Bkbw6Zyu9hBo9mGNAYHhkfKNuCDtOrYGts7OT374NYQCYfl
         hROokPd35lGyWFHNhFKuH+z0batGN9K5aw7O3pUHFzzPvY5Eb9xud2Z07uXPSEXFNJDt
         mkg9Pclrxe3kzdSRionq99f9PuxfjpANN0CEi9pErMspJC/P6556nZJ0gaes0rQBoz+A
         HUvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWA1Sbz7LIVShUHcYg5xSMZRBUaSvd8dmys5fIpioc0rrOme6JS
	acR9PRU+cwhNDSHhhoBmedA=
X-Google-Smtp-Source: APXvYqwD9S3I1Lp32PULTFqFLSqxJfSQq/gKjFvT+h8X9Z6ZMu4jgKIEbsBQyZ81h44EiuEdnmOJ4A==
X-Received: by 2002:a5d:50c8:: with SMTP id f8mr5640207wrt.96.1570131570944;
        Thu, 03 Oct 2019 12:39:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ecca:: with SMTP id s10ls2063743wro.9.gmail; Thu, 03 Oct
 2019 12:39:30 -0700 (PDT)
X-Received: by 2002:a5d:614c:: with SMTP id y12mr8759603wrt.392.1570131570473;
        Thu, 03 Oct 2019 12:39:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570131570; cv=none;
        d=google.com; s=arc-20160816;
        b=KEUI9kDxfSTZT3AjlzeDhnInBgC4hGbSmxwT9rgf3wuS3rxZhbLKteLLXBedZQStlr
         13EbDmGtISs57jFwkVsMrjxdhU9b64PjJLKLRog+AK7YRCWmDmiwN/wU+sooYbBbW9tw
         NBY26jcHGdmiynIqPWck7o45KlS5KziQ8HTqzXl62DEHaTFaqPAmtGQflqwNVVAKHhY4
         Y9ccR2VcN9s9CebmukJlDNKSsaZo3SoDq51rmtG98x4SlstVojHD1Np3w2pQ1QzyI6Dk
         rknnnRg62/UFBXqN4E4O2HHs8s1is/5TBOgqqK9p5hayAkpdJqyxw3Unj9aGlFp4vfqA
         o0Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=gthgzJMow0tglmb6xVXLKhR6XWThMEjGreCffaMqdW0=;
        b=Hu2khvmDDt140Xe3a4heamSK4rTs2m8R2w6jKVRKPngas8q9UZEwPF3pQzu0xrKk8i
         QaXQ4EzNT/+2iw3KecckTxVrv6HYepDSFZymyISeNk7SeaHu2smPMA5DO+0ejhlRNoRr
         i/S2dcVz2woAhfybfrNI3iyeBlHjmZeqIc89I4hBSl0wZT72PNQTgUKOwmQiUASW6LsU
         MuK4SHsVvMhzHmUxo+goqqypoQsgPTcasHGPd9LxprNOJoASLM6DQMHknpG2aKP9yU12
         AAna7dzdP4VPSKP/IIVCG1reK2tBDecEeooUw+lzC1skxgsyuF4fxl0aLw3ORHI36JOr
         05rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
Received: from youngberry.canonical.com (youngberry.canonical.com. [91.189.89.112])
        by gmr-mx.google.com with ESMTPS id i7si235501wrs.1.2019.10.03.12.39.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Oct 2019 12:39:30 -0700 (PDT)
Received-SPF: neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) client-ip=91.189.89.112;
Received: from [213.220.153.21] (helo=wittgenstein)
	by youngberry.canonical.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.86_2)
	(envelope-from <christian.brauner@ubuntu.com>)
	id 1iG6wj-0003Qd-67; Thu, 03 Oct 2019 19:39:29 +0000
Date: Thu, 3 Oct 2019 21:39:28 +0200
From: Christian Brauner <christian.brauner@ubuntu.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Joel Fernandes <joel@joelfernandes.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Daniel Lustig <dlustig@nvidia.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191003193927.fvkc4tu66guv7edu@wittgenstein>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com>
 <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <CACT4Y+bNun9zAcUEAm9TC6C_e9W9dd3+Eq9GwPWun1zzQOtHAg@mail.gmail.com>
 <CACT4Y+Zaz9+t6LDW5csyezeHQ+whM-wPcta+REa0ESDj4JXPGQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Zaz9+t6LDW5csyezeHQ+whM-wPcta+REa0ESDj4JXPGQ@mail.gmail.com>
User-Agent: NeoMutt/20180716
X-Original-Sender: christian.brauner@ubuntu.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 91.189.89.112 is neither permitted nor denied by best guess
 record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
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

On Thu, Oct 03, 2019 at 06:00:38PM +0200, Dmitry Vyukov wrote:
> On Thu, Oct 3, 2019 at 3:13 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, Oct 2, 2019 at 9:52 PM Marco Elver <elver@google.com> wrote:
> > >
> > > Hi Joel,
> > >
> > > On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> > > >
> > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > Hi all,
> > > > >
> > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > >
> > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > > >
> > > > > In the coming weeks we're planning to:
> > > > > * Set up a syzkaller instance.
> > > > > * Share the dashboard so that you can see the races that are found.
> > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > point it out and we'll prioritize that).
> > > > >
> > > > > There are a few open questions:
> > > > > * The big one: most of the reported races are due to unmarked
> > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > to fix races might be required. Comments on how best to proceed are
> > > > > welcome. We're aware that these are issues that have recently received
> > > > > attention in the context of the LKMM
> > > > > (https://lwn.net/Articles/793253/).
> > > > > * How/when to upstream KCSAN?
> > > >
> > > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > > one way of pruning is if the compiler generated different code with _ONCE
> > > > annotations than what would have otherwise been generated. Is that still on
> > > > the table, for the purposing of pruning the reports?
> > >
> > > This might be interesting at first, but it's not entirely clear how
> > > feasible it is. It's also dangerous, because the real issue would be
> > > ignored. It may be that one compiler version on a particular
> > > architecture generates the same code, but any change in compiler or
> > > architecture and this would no longer be true. Let me know if you have
> > > any more ideas.
> > >
> > > Best,
> > > -- Marco
> > >
> > > > Also appreciate a CC on future patches as well.
> > > >
> > > > thanks,
> > > >
> > > >  - Joel
> > > >
> > > >
> > > > >
> > > > > Feel free to test and send feedback.
> >
> > FYI https://twitter.com/grsecurity/status/1179736828880048128 :)
> 
> +Christian opts in for _all_ reports for
> kernel/{fork,exit,pid,signal}.c and friends.
> Just wanted it to be written down for future reference :)

Yes, please! :)
Christian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191003193927.fvkc4tu66guv7edu%40wittgenstein.
