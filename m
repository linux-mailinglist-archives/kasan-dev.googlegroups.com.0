Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBOM3XYAKGQEXX5E3HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DFC3135F81
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 18:42:30 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id e11sf4134713otq.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 09:42:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578591749; cv=pass;
        d=google.com; s=arc-20160816;
        b=mggwNv541AjM0coK2GBaPeKy64d6zIn82g9KmXPRgPP6VBatHRAPrZT/Ecs/ebgMWx
         TZ8tm2gIKmhW1fuTyFt9qlq7rYF0+mZUY/44geDHS13mEd2C7Onvrsr4uneCxKYfSq1r
         /HjJIGP2rJZh7bqtvUCBQXv7BG/+1iN9GKLPVUCCV4zIPSVsZ/R1AS2oQyBR2uC1I0Mn
         Sayu3xIYS+i0fqV2BJADZxFBip0CLcnpiwxX4Y/c3hI6EazZBwFhk4alJG55bGjLtDH9
         u0Wvzq126nn9P0BKABKGloWLWKAKwrbRi9YEylWO2YP8n+ks1ZlIme3VypBfp3Bkp+Tm
         JBUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=onPm7An1sYaDi5fUVLepTe7Gu9qNPNZxcXahO1oejak=;
        b=Xnf3GeIcfZRWgtgm+scG0AcrKxBci6gzvOov2s1bAIB5ObvrmAWWh4iVjIqZpZHZQu
         zVT2pUSr7LiGrntdtrWRKnWxuO3Ezr2lcUHu8atH4cCi05ozmz2iGDehp7r88HnPFSoi
         P+k7nTY4mEQJYvyzcJvtLdEOQF6VF/hCa/DPC8m5r3HQcLvLR08/GRhumqdg/lnWzRcb
         THKOw/m9JxkG4fbzYl9a/FLRNIX3sJ5nzoynKx1JIcipxd6si73XyXZ7jN7MrfYoETci
         RQhr9Lh4PpU/I7VzD5+cuzKiBSe0D8aTmkCxWYMmwbtHW42kUlLtwpTvPLnasg0o+AKG
         /8tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jdjv0vum;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=onPm7An1sYaDi5fUVLepTe7Gu9qNPNZxcXahO1oejak=;
        b=UvN8kpRYBqCom6eh6J0NBc5hkfQVc2h0e4G00KMAh5S/RxOmYg216MaHPZ8AXzO53n
         towiKTH46RT5cGwQLWOkf67tG8KWOuPMlVWaWvEDm3HhyNvU3mrdaknFWM7NFaY/CQ7x
         lp6Nc9fjs7sBOzbPrUAXhq/aruNUkuF/C5mZDKZXvLUsj46f37gdhA728NnZGjYQjN9p
         fdDl4zcilgDKXuUpuCga59fpzVZYctc9kwiEdLVQmJNrxsnY6F1zXr1l7w4fpwMb3+hB
         zeeS5444Ht8ArWiWYsMpNu3WjnieFTqkG2GzUuaj7ISsLCamfVqcDR1kdYRJslwqVBpg
         9SYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=onPm7An1sYaDi5fUVLepTe7Gu9qNPNZxcXahO1oejak=;
        b=dJG4iCArRlf1q0YZ4rfc57oFc5WwS3u3jtu/hfA6Au8T8H9iVsLfw1Awys15CkVPtI
         UtKhw8bj8W3qKNwnyiVC7DhWfkC7/BGyjFNTwrtbNlzBLN/MkTsGncp8Z2cNYBEtjy5O
         76hPnn0apG/1k7J1bKE3UgHNL4ZZwX97+ZIdZHfAHld2Ak+muEEFwJqelycNZQPO15PN
         7Sn6mOTzJm/kQNOX31uAUgqpi8i+g2XVklu3ydKVtbJSIShyWVpG08cj/EsFEWPAm7oY
         0/qs2/uV+giIIrNCDwCx5t/osMU+U3v+7UJRbr+DUYi12EyRiPXFVehHf/CcGgzUAjqL
         A+kw==
X-Gm-Message-State: APjAAAVc07Rlw3Q3nKDw9GYr8eTnpVlF4OHk7NrEvAKLFTSqGK+DuUMD
	lxPXcVcjH2zlZsI/KAZVXsM=
X-Google-Smtp-Source: APXvYqyHHabwZAGmpkWCJml0GVpRDQjkT/cy8+Zv3yR5VmKmdUs/sQ1nAJho0DGDVoER0OpmOyCcNQ==
X-Received: by 2002:aca:220c:: with SMTP id b12mr3976895oic.55.1578591749172;
        Thu, 09 Jan 2020 09:42:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4a4:: with SMTP id l4ls554326otd.11.gmail; Thu, 09
 Jan 2020 09:42:28 -0800 (PST)
X-Received: by 2002:a05:6830:1e30:: with SMTP id t16mr9642463otr.220.1578591748677;
        Thu, 09 Jan 2020 09:42:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578591748; cv=none;
        d=google.com; s=arc-20160816;
        b=Muy+IM0iSpSN8pZrO/R0ld9Vc1G4X1ju4t6UsQdXuMbz93PEZiEmCaRmwi+EUWW32d
         lHDXXOPxdsK4UoHQIQCfsdQBpIujFZrOs2JSuuZySfzw1ZWaoML1PvvZlZBHcGgBT5rN
         n0bKVddhDKaAxbuucTkuiKaL4eGJnokgGj5PZeGdcABE+0g+nkCcmJKADbdSDxQoDYye
         U6WFVCaSkQJ9drqAs7ziC95n9KlnFs6a9eCNXGAcr0ubuVwvozfsKwpOtSVKKh/cuiE0
         LbQWIBGbE57WRiqmeD93Pbs+PPPUyXbOO0J7zTLLMxMdFi0MLmMwH5PRDoCDOcvBmCsq
         IUYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qJQU304VHQkkMGXJtC4nL1fGnD1E/KBCjfdV3OkjqvE=;
        b=gdjn/iN+RKeBozDr8bMkAkZ7YaGQ9br4/pM9PopIBUy03ZUGY/6pIiNjLIaV4vcJ79
         GyvZ1ZcegTc9DnUbqz/dzNSs6chcc2lbaHYl9nl8ekQxMUsPI5dbbNxvwmXk07qQ1oPX
         bctFNFhVb37yLrAnzwAvAF/uMtPJ9ULCnTyLXbzLm7C8SA6QxtL75Ec+hfzCjwR8i/Qn
         OErf7eKT/OMdoEMWsXty7f7DjzaCsU2zx2uTQKokWmShzB556vg9A8lsiOGlMmzbS3CM
         EnfeMQhwtmeJp4ScYc6E4sxs2sWBao71tnsUgI7aSbhQxhN5VVCz7mnZaKTX4JEnGdP+
         Bz+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jdjv0vum;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id c23si482076oto.4.2020.01.09.09.42.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 09:42:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id k14so8090405otn.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 09:42:28 -0800 (PST)
X-Received: by 2002:a05:6830:1d6a:: with SMTP id l10mr9858656oti.233.1578591748089;
 Thu, 09 Jan 2020 09:42:28 -0800 (PST)
MIME-Version: 1.0
References: <20200109152322.104466-1-elver@google.com> <20200109162739.GS13449@paulmck-ThinkPad-P72>
 <CANpmjNOR4oT+yuGsjajMjWduKjQOGg9Ybd97L2jwY2ZJN8hgqg@mail.gmail.com> <20200109173127.GU13449@paulmck-ThinkPad-P72>
In-Reply-To: <20200109173127.GU13449@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 18:42:16 +0100
Message-ID: <CANpmjNP=8cfqgXkz7f8D6STTn1-2h9qzUery4qMHeTTeNJOdxQ@mail.gmail.com>
Subject: Re: [PATCH -rcu 0/2] kcsan: Improvements to reporting
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Jdjv0vum;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Thu, 9 Jan 2020 at 18:31, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Jan 09, 2020 at 06:03:39PM +0100, Marco Elver wrote:
> > On Thu, 9 Jan 2020 at 17:27, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Thu, Jan 09, 2020 at 04:23:20PM +0100, Marco Elver wrote:
> > > > Improvements to KCSAN data race reporting:
> > > > 1. Show if access is marked (*_ONCE, atomic, etc.).
> > > > 2. Rate limit reporting to avoid spamming console.
> > > >
> > > > Marco Elver (2):
> > > >   kcsan: Show full access type in report
> > > >   kcsan: Rate-limit reporting per data races
> > >
> > > Queued and pushed, thank you!  I edited the commit logs a bit, so could
> > > you please check to make sure that I didn't mess anything up?
> >
> > Looks good to me, thank you.
> >
> > > At some point, boot-time-allocated per-CPU arrays might be needed to
> > > avoid contention on large systems, but one step at a time.  ;-)
> >
> > I certainly hope the rate of fixing/avoiding data races will not be
> > eclipsed by the rate at which new ones are introduced. :-)
>
> Me too!
>
> However, on a large system, duplicate reports might happen quite
> frequently, which might cause slowdowns given the single global
> array.  Or maybe not -- I guess we will find out soon enough. ;-)
>
> But I must confess that I am missing how concurrent access to the
> report_times[] array is handled.  I would have expected that
> rate_limit_report() would choose a random starting entry and
> search circularly.  And I would expect that the code at the end
> of that function would instead look something like this:
>
>         if (ktime_before(oldtime, invalid_before) &&
>             cmpxchg(&use_entry->time, oldtime, now) == oldtime) {
>                 use_entry->frame1 = frame1;
>                 use_entry->frame2 = frame2;
>         } else {
>                 // Too bad, next duplicate report won't be suppressed.
>         }
>
> Where "oldtime" is captured from the entry during the scan, and from the
> first entry scanned.  This cmpxchg() approach is of course vulnerable
> to the ->frame1 and ->frame2 assignments taking more than three seconds
> (by default), but if that becomes a problem, a WARN_ON() could be added:
>
>         if (ktime_before(oldtime, invalid_before) &&
>             cmpxchg(&use_entry->time, oldtime, now) == oldtime) {
>                 use_entry->frame1 = frame1;
>                 use_entry->frame2 = frame2;
>                 WARN_ON_ONCE(use_entry->time != now);
>         } else {
>                 // Too bad, next duplicate report won't be suppressed.
>         }
>
> So what am I missing here?

Ah right, sorry, I should have clarified or commented in the code that
all of this is happening under 'report_lock' (taken in prepare_report,
held in print_report->rate_limit_report, released in release_report).
That also means that any optimization here won't matter until
report_lock is removed.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
> >
> > >                                                         Thanx, Paul
> > >
> > > >  kernel/kcsan/core.c   |  15 +++--
> > > >  kernel/kcsan/kcsan.h  |   2 +-
> > > >  kernel/kcsan/report.c | 153 +++++++++++++++++++++++++++++++++++-------
> > > >  lib/Kconfig.kcsan     |  10 +++
> > > >  4 files changed, 148 insertions(+), 32 deletions(-)
> > > >
> > > > --
> > > > 2.25.0.rc1.283.g88dfdc4193-goog
> > > >
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109162739.GS13449%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%3D8cfqgXkz7f8D6STTn1-2h9qzUery4qMHeTTeNJOdxQ%40mail.gmail.com.
