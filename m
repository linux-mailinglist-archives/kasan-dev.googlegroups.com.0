Return-Path: <kasan-dev+bncBDV37XP3XYDRBD6C3GCQMGQEI5DQY5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E2D839781D
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 18:32:17 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id a21-20020a62e2150000b02902e4e5d37f10sf7654970pfi.11
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 09:32:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622565135; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAeCzu81rfsha7q43slAb58eIXaMsXIhR/MyOVRMj0D8z7r/RvQuRDUQT0qnR9UWjE
         SYDl/l3CvxzIGKg+2UVzrybkAayq+iHCuD8wHhmtH5CJ6Ol2cuVAupgk0t2EfsVr4YDH
         C6jX+rliT6ZMnaReywsx47qYQirVUqSC2wEiF8HennVFv2lNOB+MJDbD+yAKTWJKvg/q
         toJPMnXqgOp6/R6WqtcOzV6fPzc9pQHzjP7wH+Ulz31UtwgUbKc9bxDcnTea0xr6agRu
         bMpo4dYyl/jb/BtUO0ybIJHoTG5Hl7SmPVHmZF/MNbiwPAaWBJQrN6uH/KCvOl2JNvz7
         E+bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=so90Ri0/R/jv2/pU5W4b9Jh+60NxXWBrQ4pn+xs7ZDM=;
        b=Fajv7LDJ/fiXamyYmEd8TB8kdQ6wNJy2jAr6aiRPzbMLi+fRznqcuCqOMqJ/Qhf55C
         oaZXPBEpBMUvuejJcgzSvBe+qE7gDCNrTLHTfMqvZDnLw1sq8ijTttakfwVU8s7kt27j
         v5GykF4Qsbc7Zf8BVi8HqZBsoCvDVM/d52ICuJnSEB5G3xhkDak6uSE90jaTAipV+yd0
         QgT6YIaD62BEuN02N9JlFJpLNaKak+6LT83Ny4uriTE0NoXLwUtgDs7pdesQFCmkqQAy
         BAryuTaNScC6Q9Q/I4UmKicQ5Etu+YuA0M3qQSrVklm8p6nMSyj1NV0UK3MV0MVk4GMl
         fX5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=so90Ri0/R/jv2/pU5W4b9Jh+60NxXWBrQ4pn+xs7ZDM=;
        b=cuyfTTsPHkQYbKW6uXMyf4yQDd2XtuNw4oDdhIXy+xXPvXpFm9jR/1JgIpdrklT2zS
         ekxpTIX6z2aZZTgEl1euVhj6O1N+yhSdkP/E7hBqbFHKJuhfiwbEYWnoMQpIn8M+QnOZ
         ljG9/96OBUZs9utGcw3sLIGQam+KEW12fZbGjDjh2v+cOUtxsC/OgsrP20sj5DgDbRFd
         M6ufB3bm0iaEkwLVE781CZFuKbv+wGZEfJYYoHRMdbMukv0sxrq0yc5Y6LJ4Dxp/kG0g
         VBoeo9HbsNv/zpNTc8SvxQJN5APNDHriyXJT1FaJTTwXfojMGXtSW5w3XAQ6TWyFNgVO
         0psw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=so90Ri0/R/jv2/pU5W4b9Jh+60NxXWBrQ4pn+xs7ZDM=;
        b=Rzj83wwMEZ/mShhBHIH0NWTRs9d/dcRH4EZL+gyK3IJMos5EyM0w8KOeyqTR/XFFWg
         trfBpNlUVSekykx/2INnYSmdXFO8yGI00SoNeo/MIC1Zfzyhq9vHJ2U08geshjo3x4MY
         HoIZeIcYXOP9PveJOWZn950xYiImb8/jWM4j/zb4Zwj8DmHCwgMp75C4bBxvjMPRm23P
         Uw7LH8IUL3tAGOPUHY840lRqmSgcyyqUg16WoDzhyPg7MCNWsFEVtgxtUSXacPLB519j
         MKUQFPBxsH5Ont1H3kI5QVdltzBC0sx+G6ZQ1pilYSOAR6D47fpa0sbe0sRbApk+uVvc
         1s9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jxxXjNGCU+sE+W8tPPS1LmDAVoVzVTyFIMrTCjCoubAcQXWQU
	9bGKG5NGtFmokKTsbkoXch0=
X-Google-Smtp-Source: ABdhPJztfUMJYd27xJoPJAXM25JT6PLWIho/z+fUBvAKUfCEKUUZmQclZLy5iRtqja5bEpDMovNJsQ==
X-Received: by 2002:a63:f74b:: with SMTP id f11mr28845573pgk.327.1622565135578;
        Tue, 01 Jun 2021 09:32:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:92cc:: with SMTP id k12ls7961761pfa.11.gmail; Tue, 01
 Jun 2021 09:32:14 -0700 (PDT)
X-Received: by 2002:a63:5052:: with SMTP id q18mr28651586pgl.349.1622565134864;
        Tue, 01 Jun 2021 09:32:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622565134; cv=none;
        d=google.com; s=arc-20160816;
        b=Ng60p2UFvN9rQuG2tNhYlPZPjStGksM5Z8SKO+2iOjwu+2VKUGWVChVulbJVUUVK03
         94A6UfinEO+yfcuXhGTPLMqOyzrJ2XojttFzhXTqkX7MR2Lha4XuftA9xIN6+TcYbPxl
         TGcUKYmIiGDihu3H8W5zGXYiQtVtCsaruDOGCEu6hwlMtrz+i+Jk4I7+GFXV+bEjjH9Y
         8u/yHXxvreQ3eHghdeG39SfzeWmYvDN4w6RFXNRwmHcCEzdpZIM056hwOvtyBOmoY/5Z
         iclzBuCcneb/0MW2YbNrzxngLJfxpXKOpYjDAFmNJtNy2qV4AMsjY8u0jCn6VB9q2wXj
         lfng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=n7oyhjPEVD0l7LOMwL6cMDKQeJSCkrmBZcKZq2oMx/Y=;
        b=RswAjlHErv6D4Mi+nC+VwR015cfdNer5VsuCLFzF/189V5d7/SatuqEGa3Qhz4L963
         gykj7zAo9LnFj8GQC7tC9IWNb5aNFYUHHiUFV3fC7ETF+NIN7lfsyrvPgJgFYUGrpUn3
         Kmv0mXcsKLjTHHCUkV/k3POtux36ZjTAGgVxPqhmmkSbHFx3CobREKIk6d1+TGjZe9PA
         +7Iks///2QaZ+Q0+l8YF1bwxCbK7JLg8WSffWc44vO9SY2eBbn6W8W7RqeYmzU4ML/JJ
         qVv73Pfmqpxsp2DJyPxXbrgKzY9iYBpZsensT9CnbsqWHRp6YrRqZQTSFcQNTnn53+s8
         wXjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u24si1360053plq.4.2021.06.01.09.32.14
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Jun 2021 09:32:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D32FF101E;
	Tue,  1 Jun 2021 09:32:13 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.0.106])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 498B63F719;
	Tue,  1 Jun 2021 09:32:12 -0700 (PDT)
Date: Tue, 1 Jun 2021 17:32:09 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Plain bitop data races
Message-ID: <20210601163209.GC3326@C02TD0UTHF1T.local>
References: <YLSuP236Hg6tniOq@elver.google.com>
 <20210601154804.GB3326@C02TD0UTHF1T.local>
 <CANpmjNNOoVg5hcm0-omi-CB9zPVnKxBdCir1WmD0rMpoAQSOjw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNOoVg5hcm0-omi-CB9zPVnKxBdCir1WmD0rMpoAQSOjw@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jun 01, 2021 at 06:18:44PM +0200, Marco Elver wrote:
> On Tue, 1 Jun 2021 at 17:48, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Mon, May 31, 2021 at 11:37:03AM +0200, Marco Elver wrote:
> > > In the context of LKMM discussions, did plain bitop data races ever come
> > > up?
> > >
> > > For example things like:
> > >
> > >                CPU0                                   CPU1
> > >       if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> > >
> > >       // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> > >
> > > This kind of idiom is all over the kernel.
> > >
> > > The first and primary question I have:
> > >
> > >       1. Is it realistic to see all such accesses be marked?
> > >
> > > Per LKMM and current KCSAN rules, yes they should of course be marked.
> > > The second question would be:
> > >
> > >       2. What type of marking is appropriate?
> > >
> > > For many of them, it appears one can use data_race() since they're
> > > intentionally data-racy. Once memory ordering requirements are involved, it's
> > > no longer that simple of course.
> > >
> > > For example see all uses of current->flags, or also mm/sl[au]b.c (which
> > > currently disables KCSAN for that reason).
> >
> > FWIW, I have some local patches adding read_ti_thread_flags() and
> > read_thread_flags() using READ_ONCE() that I was planning on sending out
> > for the next cycle. Given we already have {test_and_,}{set,clear}
> > helpers, and the common entry code tries to use READ_ONCE(), I'm hoping
> > that's not controversial.
> 
> Interesting, please do Cc me as I've been thinking about if we can add
> more bitop helpers to avoid having to READ_ONCE()/WRITE_ONCE() or
> data_race() the accesses, which thus far never looked too ergonomic.

Will do!

FWIW, I have an old version pushed out at:

  https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=treewide/thread-flags&id=971e3a9ace1d896ec8f0995037a25808ed6028e9

> > Are there many other offenders? ... and are those a few primitives used
> > everywhere, or lots of disparate piece of code doing this?
> 
> AFAIK it's all over the kernel. For example all current->flags
> accesses somehow suffer from this everywhere. Also various accesses in
> mm/ (KCSAN is disabled for parts there for that reason), and a bunch
> more in fs/ that I keep ignoring.
> 
> > > The 3rd and final question for now would be:
> > >
> > >       3. If the majority of such accesses receive a data_race() marking, would
> > >          it be reasonable to teach KCSAN to not report 1-bit value
> > >          change data races? This is under the assumption that we can't
> > >          come up with ways the compiler can miscompile (including
> > >          tearing) the accesses that will not result in the desired
> > >          result.
> > >
> > > This would of course only kick in in KCSAN's "relaxed" (the default)
> > > mode, similar to what is done for "assume writes atomic" or "only report
> > > value changes".
> > >
> > > The reason I'm asking is that while investigating data races, these days
> > > I immediately skip and ignore a report as "not interesting" if it
> > > involves 1-bit value changes (usually from plain bit ops). The recent
> > > changes to KCSAN showing the values changed in reports (thanks Mark!)
> > > made this clear to me.
> > >
> > > Such a rule might miss genuine bugs, but I think we've already signed up
> > > for that when we introduced the "assume plain writes atomic" rule, which
> > > arguably misses far more interesting bugs. To see all data races, KCSAN
> > > will always have a "strict" mode.
> >
> > My personal preference is always to do the most stringent checks we can,
> > but I appreciate that can be an uphill struggle. As above, if there are
> > a few offenders I reckon it'd be worth trying to wrap those with
> > helpers, but if that's too much fo a pain then I don't have strong
> > feeling, and weakening the default mode sounds fine.
> 
> Because I'd also prefer to avoid weakening the default, the new rules
> will not be enabled by default. But in the past year, I've found
> myself trying to keep on top of new CI systems, robots, or drive-by
> testers trying to use KCSAN, and every time there is significant
> negative feedback because of too many of these trivial data races that
> not many care about at this time.
> 
> One recent discussion in particular [1] prompted me to have a think,
> and I realized we need something simpler than writing long
> explanations to avoid discussions derailing. Having an even more
> permissive mode might be the simpler answer to those cases until those
> folks come around (gradually, or perhaps not so gradual by e.g. a data
> race crashing their system).
> [1] https://lkml.kernel.org/r/YHSPfiJ/h/f3ky5n@elver.google.com
> 
> On syzbot we have several stages of moderation (although initially
> I'll also enable this new mode on syzbot). But every time I suggest
> moderation to other CI systems that enable KCSAN, they just disable
> it. So I'm trying to bridge the gap from both directions: fixing data
> races, but also making KCSAN more permissive. Once we reach a point
> where KCSAN is mostly silent, we can then gradually make KCSAN
> stricter again by tweaking options.

Sure thing; if adding that more permissive mode makes the tool more
useful, that's clearly the right ting to do overall.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210601163209.GC3326%40C02TD0UTHF1T.local.
