Return-Path: <kasan-dev+bncBAABBM5C33YAKGQE7EQAZFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 42CDD1361F2
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 21:46:44 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id e37sf5010690qtk.7
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 12:46:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578602803; cv=pass;
        d=google.com; s=arc-20160816;
        b=MPJqdTwvamcj+AwlBF88mYl16dmmvttyB3DBYjf6nAX+IgHe9466CgMdz/uYlmPBw2
         Vmvl8470gNjkobJkEWdKdx10/hRI3Mrp3PE5h2DBIOVW55+tGvz9vJ6DInryrDE2hX4l
         jfqfQ+PBzlFj4vCsmUZJe0sBqceqNnm7s6vChgcCRkDmJPDNnRnYgpDSYD4ajwECJqh5
         dH+bgfHS5xQnbAA31Uj+cZpz26kYunSApR5jlUbL1oTyIIowUlCSCqdc/uc4r6JYliF+
         AZJwyHElIgw5ooAeYFFTNAZSvtaEfp0u4Pt2b3zdi52de6zKZZfm6c06HtkkZGWlJqaj
         4WlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=F0LJCd77kCP1zOAj9fvwLajYbaqGd5K/QnOcRMqWyN0=;
        b=rftdZZPcyQOSPCF3PfnD/v1xS4yLQg3JRvxHf5ewpC1g2/rX4SrhEQ2CN9LsmtE4La
         0fPaQXWF4rx72FZbG7MF9O4MRDNwacNJhFA8O6g4s5hecWWXZ40Cdq5E7HLaWQJ2/r6Z
         WciwUMJy7cyiorWvuVlte0KWPsaNv0kBJceydee259hDL6Q6Ah1PDzy/gi2f2ARmCdyO
         ZbIbIiIpsat1tbzak7tE5bF5wxFoyl8wenrEXQ0IwnuXziTsNulksEEZ/Wxtc/qssetB
         LrV2LMfmmIRXCXmwXGtXa6pSrQFQEG7wZ+vK/NVK7w/m68O08kh5TCDXVXrCk6tzApl5
         8stg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TJDZxhO9;
       spf=pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F0LJCd77kCP1zOAj9fvwLajYbaqGd5K/QnOcRMqWyN0=;
        b=mnyxCfli3/dZLryG2U9hdfoAqE6ebvQU5mcuTrS0ksC6YxNrWfJCa8uGgUzGHaicJw
         EliGEC9nZQctDSa2qamItsmf5viOyKbRrYO3qfi2oC1mkFSYF0JjvLRbn82qeHu4BLKT
         4HzoIgt/dPlhVjj0RNWzGy30+1bMUmd/RrU5dyfkO9SkifB1tUBWIVKVohiMYS6A8Hb0
         Ju35aLuR0je0c/1OUNHYST6IQ2ms392cPzfXJVTo0s/aB78K3+sjY23MKuZSu5kkLXwD
         OtxDUHxDOnLk/lEbWpHvtJ+/3BE6YhvJvxKjiSPvHOM2AkLqiRgaE0CzAW+cbELKZ466
         CqsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F0LJCd77kCP1zOAj9fvwLajYbaqGd5K/QnOcRMqWyN0=;
        b=OhsNXHHLHxf/y4ZuWN8BLxEYmhs6Rw3HghxIHmkn/eKVauHUBMwFdmq5gLgPtsvRKm
         lkRoCCK6PSogXM1PMfQjw+swvZnuyFTeaIMIVFyy9W6J2RSZy8k6CpyvwIGnzCUk0Qpr
         p0SbPm45kYQXJfRnaMo1i3OiTqLBWufXzPCRbZrXlUKzgzAoZie5UvwKe3RFrbtHrfa2
         R+Xu0WZHFYtfP+oTERdPBhVJuKmt4CH1vbIEEDOB4PuLsoPWOVMNnRVY0mcNvj4KTUUA
         zaVHUazZrH08wPgHfSh5UEsjL6cUl0eoVetjydRLVBWiefxJVS9Vb8EPWdvx0H38FD4S
         dlUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWnW+Gl/PcHFD+ThE13r0BOx0hL+cJHBn93vvuGUyDG7JRjktKZ
	S0W6DBy3ZI7v2sDcjxphwYI=
X-Google-Smtp-Source: APXvYqxChQROPnQiK1sg3qWxY1bZishy8ZLfKMBJN0aBdtmSIW6HP5q7V3y/+zRJB6IYw6URnUhZlQ==
X-Received: by 2002:a05:6214:108a:: with SMTP id o10mr10257472qvr.246.1578602803248;
        Thu, 09 Jan 2020 12:46:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9f92:: with SMTP id i140ls1292158qke.11.gmail; Thu, 09
 Jan 2020 12:46:43 -0800 (PST)
X-Received: by 2002:a37:9ec5:: with SMTP id h188mr11694027qke.435.1578602802960;
        Thu, 09 Jan 2020 12:46:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578602802; cv=none;
        d=google.com; s=arc-20160816;
        b=lYalBP4KcKCe0ejwROOsszh+a0kvAyjEN7SQwRKmmbwqZYEIcWpKz6yBIGzya/D4Y2
         p5osWkPNpdLgz7Ow6C27kgfBoI/v0BrfJ68k9qoud6p8tCZmpC8RQeufGJSNcOekajGt
         7ipF23Z5HcWXgzi1ShBDuLpZfHXxDuj5S6SUFVRvGrTsuFZ4FskxihWl1ciy5O8LRSzJ
         LdjyHIw0hUjiQw4I4Q61sWcA2TIiIOS1KM/whqeWSDBUKfV+33/PAnjxlfQd6scC2aOP
         MOSFLKSpsN9ULbEH1LwirV+auOe+f6QBcU6GxaNZS0cnwZ2XOFm5a6JwuBTkZu5Ys8gg
         vQwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=7KvsjX7S0YOH65KqyOw09EuFMyLRQS9an/veXj3aZR4=;
        b=T6caSDCL3DYSkixmTco8/tFiB26rBnwb+uVRwHOWi8z/ikzy7ATYQBDMDnmdnVANJZ
         BgxLRzCU6V7MbUSz13ksAtexjpefV8C0d6kokWAa9Ypvlil1kLgU/nVg7FWuh2jTa2G0
         MNiSGOoRtxNbO2lerKhArlvaqY2EO4ipQpSiehwouvcOdVkwSBNrb89ZpwTwFnwGpaWK
         xnDMx7LVMcvCm4kO0Ec13HUbsp3ehoWvMsbEybCDMbJzFLkbX9+EY919z6+zILlPD00B
         UV5sg5JqdZylnyP+R+DlRR3HmU9JQwoAp/ro/FN8OKnLSYO9zKq6BJoEcAI8GZOfKB7/
         g+Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TJDZxhO9;
       spf=pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o36si339309qto.4.2020.01.09.12.46.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2020 12:46:42 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CA6F820721;
	Thu,  9 Jan 2020 20:46:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 7775D352272E; Thu,  9 Jan 2020 12:46:41 -0800 (PST)
Date: Thu, 9 Jan 2020 12:46:41 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -rcu 0/2] kcsan: Improvements to reporting
Message-ID: <20200109204641.GW13449@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200109152322.104466-1-elver@google.com>
 <20200109162739.GS13449@paulmck-ThinkPad-P72>
 <CANpmjNOR4oT+yuGsjajMjWduKjQOGg9Ybd97L2jwY2ZJN8hgqg@mail.gmail.com>
 <20200109173127.GU13449@paulmck-ThinkPad-P72>
 <CANpmjNP=8cfqgXkz7f8D6STTn1-2h9qzUery4qMHeTTeNJOdxQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP=8cfqgXkz7f8D6STTn1-2h9qzUery4qMHeTTeNJOdxQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=TJDZxhO9;       spf=pass
 (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Jan 09, 2020 at 06:42:16PM +0100, Marco Elver wrote:
> On Thu, 9 Jan 2020 at 18:31, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Thu, Jan 09, 2020 at 06:03:39PM +0100, Marco Elver wrote:
> > > On Thu, 9 Jan 2020 at 17:27, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Thu, Jan 09, 2020 at 04:23:20PM +0100, Marco Elver wrote:
> > > > > Improvements to KCSAN data race reporting:
> > > > > 1. Show if access is marked (*_ONCE, atomic, etc.).
> > > > > 2. Rate limit reporting to avoid spamming console.
> > > > >
> > > > > Marco Elver (2):
> > > > >   kcsan: Show full access type in report
> > > > >   kcsan: Rate-limit reporting per data races
> > > >
> > > > Queued and pushed, thank you!  I edited the commit logs a bit, so could
> > > > you please check to make sure that I didn't mess anything up?
> > >
> > > Looks good to me, thank you.
> > >
> > > > At some point, boot-time-allocated per-CPU arrays might be needed to
> > > > avoid contention on large systems, but one step at a time.  ;-)
> > >
> > > I certainly hope the rate of fixing/avoiding data races will not be
> > > eclipsed by the rate at which new ones are introduced. :-)
> >
> > Me too!
> >
> > However, on a large system, duplicate reports might happen quite
> > frequently, which might cause slowdowns given the single global
> > array.  Or maybe not -- I guess we will find out soon enough. ;-)
> >
> > But I must confess that I am missing how concurrent access to the
> > report_times[] array is handled.  I would have expected that
> > rate_limit_report() would choose a random starting entry and
> > search circularly.  And I would expect that the code at the end
> > of that function would instead look something like this:
> >
> >         if (ktime_before(oldtime, invalid_before) &&
> >             cmpxchg(&use_entry->time, oldtime, now) == oldtime) {
> >                 use_entry->frame1 = frame1;
> >                 use_entry->frame2 = frame2;
> >         } else {
> >                 // Too bad, next duplicate report won't be suppressed.
> >         }
> >
> > Where "oldtime" is captured from the entry during the scan, and from the
> > first entry scanned.  This cmpxchg() approach is of course vulnerable
> > to the ->frame1 and ->frame2 assignments taking more than three seconds
> > (by default), but if that becomes a problem, a WARN_ON() could be added:
> >
> >         if (ktime_before(oldtime, invalid_before) &&
> >             cmpxchg(&use_entry->time, oldtime, now) == oldtime) {
> >                 use_entry->frame1 = frame1;
> >                 use_entry->frame2 = frame2;
> >                 WARN_ON_ONCE(use_entry->time != now);
> >         } else {
> >                 // Too bad, next duplicate report won't be suppressed.
> >         }
> >
> > So what am I missing here?
> 
> Ah right, sorry, I should have clarified or commented in the code that
> all of this is happening under 'report_lock' (taken in prepare_report,
> held in print_report->rate_limit_report, released in release_report).
> That also means that any optimization here won't matter until
> report_lock is removed.

Got it, thank you!  And yes, lock contention on report_lock might be
a problem on large systems.  But let's see how it goes.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> >                                                         Thanx, Paul
> >
> > > Thanks,
> > > -- Marco
> > >
> > > >                                                         Thanx, Paul
> > > >
> > > > >  kernel/kcsan/core.c   |  15 +++--
> > > > >  kernel/kcsan/kcsan.h  |   2 +-
> > > > >  kernel/kcsan/report.c | 153 +++++++++++++++++++++++++++++++++++-------
> > > > >  lib/Kconfig.kcsan     |  10 +++
> > > > >  4 files changed, 148 insertions(+), 32 deletions(-)
> > > > >
> > > > > --
> > > > > 2.25.0.rc1.283.g88dfdc4193-goog
> > > > >
> > > >
> > > > --
> > > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109162739.GS13449%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109204641.GW13449%40paulmck-ThinkPad-P72.
