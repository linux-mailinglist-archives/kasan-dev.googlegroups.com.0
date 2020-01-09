Return-Path: <kasan-dev+bncBAABB4OG3XYAKGQEQK5VRWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 8352C135F5C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 18:31:30 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id p12sf4640009qtu.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 09:31:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578591089; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpUxmphgVg2BEtzPTQDAk/VZGAMEGDL4/WyhGY/XuNGNFXU5FiOlxWdEhoiW/sSVkg
         c82CUd26vgWAz0nzIXEC8mxT3ijgGN9PmB+9cVoDE8efoqQUzjJV12IubuOroBvIZkXG
         g19ZqONTzny6ZShg+796k5R3LaU8yFvgJ4sKAfAKAxJrzdHrBJd79ebNLiTo85izYCp0
         ccwYC9vj+agaLzpx1Aci1T4LFZvf+M2Kz4DT/Is8SHod2U2F8MydtFaNtjxcb3TXK3x9
         n/d137MdWV5qjxyVhFgvhSxPG0YzGJmpr0MBGQw7oY2zi0dl9zDSmrsz4IegtxCbaEK7
         AU/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=42UWYD87UPaweYwoOJPo4djhYey25W4TZ7mNNDpTGYE=;
        b=vFEbPQDDPxnLzBK5rV5IohL4Idvf7BJ2u7qfJe74X7JD8VSRQMT4xV1A5YfQZxqrJ6
         CWh2aNE3Enm1T8DRTp5563sQ/giiapNcZjUGMMKwkSbLSyDAYafpHPfYu2SKSgr2YsVE
         emlUPkZkJS57LL+px4PIheo7lv2hS14L9YXSWro1gEw8isjf7rylx3lsolKNCKZiPAp9
         jDqVw1lGo3EEyMbkb4B/khbnaCaMl+W4Qyvu5djhUT8PDlqj4W9Ve77Tc49/VMuf9M8R
         jjRyuzEXlsvKxQuv4Nf/aEecb8rdUmfT8Gj4sqdOpnMQJoptycrpQMETxwpEWqfkX9lm
         UTiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=okV7QnL7;
       spf=pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=42UWYD87UPaweYwoOJPo4djhYey25W4TZ7mNNDpTGYE=;
        b=Cr6A/sjtRIoXFAhOCoawoB+4jLv3R58mFR+QxsLGrQKVTxdQKdx1at/lZ1p3ApGIsA
         At8IXNwom181dE2E0t9hhNiswd6lu9/DIOYDmDqyrgGvwEFqO15z1PGqpQ2W3U4tHDMS
         KkePHRyQffquU2S5mGVAZA063i87DNOYNIOUBw1vq9d99TvhpofE1Gy17sTowkfJ0jv0
         1jTZf4QhOQ+vv+BlEQ7nNwVv9Xpmx0kQZ12Ofb7wQC38871oaJFqFXW7yBSLHt3Kf+oD
         mhGM1IX31zBboBW5kNaBC7RKZBHwPiJgxYsedjSp0xERu7lrhDhXw+I4NWz2TGEKH8s1
         EBgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=42UWYD87UPaweYwoOJPo4djhYey25W4TZ7mNNDpTGYE=;
        b=dPq8EGLqv6B3Wuevr1ueZr6+3AN8OZAACL+CxAdGawXSU3X/I8HlaSDVxCOP8CQpc6
         OLovdk2WlxJVhlF3G/OXKojvFSKhi9MxmGWE8uqkxtrPHN0+lYlmwF+Ekh76kiSUiz5+
         pW7MCfK29LoO4R4fEsp80WNxHsFKoOXL9WCd5yL/dnmyQx7qk/a3w9EJbMVPOgjHbV4N
         4POkemhwavTxLhsElSLQ/VwXg/TH3PdWvN1IPAXiGGIy0VxLmw05K4KYe/tghrXVpYKD
         y9wup12LWHZPXm9FrtNK4eyS853F0/oO3siDbdB7YoVyoYroSyxdKTCCnsdYcIBPiNEb
         pMdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVLtbF4gFLWt9MchTjvxNMq33TpDPn4zC68EXYBmZv1Fk69FVDw
	r8uv9eR0Mzo7pDpmeSIsqRI=
X-Google-Smtp-Source: APXvYqwi/17kHY4xqVJHYbbUqh6Lh+IuksyXJl6+gD5/KZ5tHkVDAP/yM/cGFuDnGzPrGQns7B0+7Q==
X-Received: by 2002:a0c:8dc5:: with SMTP id u5mr9906072qvb.168.1578591089311;
        Thu, 09 Jan 2020 09:31:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1021:: with SMTP id k1ls470408qvr.4.gmail; Thu, 09
 Jan 2020 09:31:29 -0800 (PST)
X-Received: by 2002:ad4:498d:: with SMTP id t13mr9436454qvx.58.1578591089018;
        Thu, 09 Jan 2020 09:31:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578591089; cv=none;
        d=google.com; s=arc-20160816;
        b=twBkKry22uNcbCAQb8dQwlZv9iIdFCwUEbH8yfBONf70ouomiqIUjKThsL/S946T/D
         IZML8yG3qAPy7yMH4D3aUVWSkg3mGXAZE40kbEio6nl/+xM/Fg3uj048jWlti/oEmzaA
         BJZheC/1nc4v2hJqdbxMR9jk+I2vPaDMmoC8SCoNINQteOE/yiJXnnPyae7S5O4QyYI/
         v7DzwtkLLazCBHxW6FCMteoywtyBz+OoFpkaTzUyxJ0ZG3/yYq5bUDWrhW0+c9JuH0sq
         Vkw+qoPxl2bp7M5y9nvMwZVtLXgqMlL+g8ztg72W+G+h2dsOCwcwRl77vNDpmx+0AVCo
         SoDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+sqboeOqspBferF0yBDXgOWkjy1Oizc0fvzsk/EVKMk=;
        b=w9H7Y3f4BlJb+i7Lph5rk/0Pzit/o3QWcPWLPmp5IsH7QzWfMEkqmlBhQMk3CQw3D4
         qsKbyX1jBUwTpG7Kfhj+ux+Nhs9hKFHPeQUxlwfB6J/IWnP+wiN4EISIOVAFrfd9goy7
         Ve/Vt6WR055i9cJ2z6RG20nmlI3C0rT+ZD6RDkWIRR71holbh14a7HRiYF6bYmROFTMf
         ak9RLd/OgPSlAA9k4CDUTitYEitsEp+tXd38vnK2Ia4W1ntx/y9Q7ZZje//QpXHlKOo5
         yO70E4mrMMcaI5cQXkcZalB2UlGhVKxjzrI6elgRurufYCOinJ9vO6o5YqaTkbA2YB89
         sqqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=okV7QnL7;
       spf=pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h17si256469qtm.0.2020.01.09.09.31.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2020 09:31:28 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E551D206ED;
	Thu,  9 Jan 2020 17:31:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 94605352272E; Thu,  9 Jan 2020 09:31:27 -0800 (PST)
Date: Thu, 9 Jan 2020 09:31:27 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -rcu 0/2] kcsan: Improvements to reporting
Message-ID: <20200109173127.GU13449@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200109152322.104466-1-elver@google.com>
 <20200109162739.GS13449@paulmck-ThinkPad-P72>
 <CANpmjNOR4oT+yuGsjajMjWduKjQOGg9Ybd97L2jwY2ZJN8hgqg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOR4oT+yuGsjajMjWduKjQOGg9Ybd97L2jwY2ZJN8hgqg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=okV7QnL7;       spf=pass
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

On Thu, Jan 09, 2020 at 06:03:39PM +0100, Marco Elver wrote:
> On Thu, 9 Jan 2020 at 17:27, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Thu, Jan 09, 2020 at 04:23:20PM +0100, Marco Elver wrote:
> > > Improvements to KCSAN data race reporting:
> > > 1. Show if access is marked (*_ONCE, atomic, etc.).
> > > 2. Rate limit reporting to avoid spamming console.
> > >
> > > Marco Elver (2):
> > >   kcsan: Show full access type in report
> > >   kcsan: Rate-limit reporting per data races
> >
> > Queued and pushed, thank you!  I edited the commit logs a bit, so could
> > you please check to make sure that I didn't mess anything up?
> 
> Looks good to me, thank you.
> 
> > At some point, boot-time-allocated per-CPU arrays might be needed to
> > avoid contention on large systems, but one step at a time.  ;-)
> 
> I certainly hope the rate of fixing/avoiding data races will not be
> eclipsed by the rate at which new ones are introduced. :-)

Me too!

However, on a large system, duplicate reports might happen quite
frequently, which might cause slowdowns given the single global
array.  Or maybe not -- I guess we will find out soon enough. ;-)

But I must confess that I am missing how concurrent access to the
report_times[] array is handled.  I would have expected that
rate_limit_report() would choose a random starting entry and
search circularly.  And I would expect that the code at the end
of that function would instead look something like this:

	if (ktime_before(oldtime, invalid_before) &&
	    cmpxchg(&use_entry->time, oldtime, now) == oldtime) {
		use_entry->frame1 = frame1;
		use_entry->frame2 = frame2;
	} else {
		// Too bad, next duplicate report won't be suppressed.
	}

Where "oldtime" is captured from the entry during the scan, and from the
first entry scanned.  This cmpxchg() approach is of course vulnerable
to the ->frame1 and ->frame2 assignments taking more than three seconds
(by default), but if that becomes a problem, a WARN_ON() could be added:

	if (ktime_before(oldtime, invalid_before) &&
	    cmpxchg(&use_entry->time, oldtime, now) == oldtime) {
		use_entry->frame1 = frame1;
		use_entry->frame2 = frame2;
		WARN_ON_ONCE(use_entry->time != now);
	} else {
		// Too bad, next duplicate report won't be suppressed.
	}

So what am I missing here?

							Thanx, Paul

> Thanks,
> -- Marco
> 
> >                                                         Thanx, Paul
> >
> > >  kernel/kcsan/core.c   |  15 +++--
> > >  kernel/kcsan/kcsan.h  |   2 +-
> > >  kernel/kcsan/report.c | 153 +++++++++++++++++++++++++++++++++++-------
> > >  lib/Kconfig.kcsan     |  10 +++
> > >  4 files changed, 148 insertions(+), 32 deletions(-)
> > >
> > > --
> > > 2.25.0.rc1.283.g88dfdc4193-goog
> > >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109162739.GS13449%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109173127.GU13449%40paulmck-ThinkPad-P72.
