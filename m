Return-Path: <kasan-dev+bncBC6OLHHDVUOBBNEGWOFAMGQEWBFNPMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 40CD64164D8
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 20:11:01 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id h6-20020a50c386000000b003da01adc065sf7507813edf.7
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 11:11:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632420661; cv=pass;
        d=google.com; s=arc-20160816;
        b=gzsEhHJHpOiWB5k/HVtGu1Wtxf81tA9/csTMgFXijIbzaPoQ+saf/eikmj8Tp8ccuX
         NCwh/GZc0CfBOCBJlXUGGl2rhF2u7swZ4q06q6ydMXmc3ofKC1X3xhFkFx6MVMz2zDIZ
         zcIIHeJpvcnGf7O7CPQFTK2fgEBcHz9wAcZpd389fpAZSNlFLr2o3fXjhwFy3e5owQRk
         d4JwKuDkpCIfw0zrXlyZyFgy+68AaBOQDrSa0Jpjw09tRpJxJWIu/vMDfXyYL6mqd7mn
         WCoxV10D8xmfibdSsXh4xKtpU7yBGpdEl+s2YcusG9BFsc86JgyF+4irRxp3TSe2nuz/
         4XVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7YHcONCRVhSPMEU6etgqzP+yR9ZfttUA0e1tdMPyEF0=;
        b=FhwqvgZ68sHigMsR+NjG1AtywPPArz0yrM2xY9OpguAmziBk8brnp1eXdzUcrp8JGZ
         ueTL1Oi/uPR/6RfYs1Ppthv4TCDLdtDdTNo1EQfIg2ftRVi2HbAFt9xCjmMZzTCqeJxM
         S2oCCqB3dijouBcrIANNCyavxsFAKXkfYqIymWei5ZdaMtl0D6pSi8fJLPvDovGH9W9o
         gOHIz5q0br3i1VFAmoz28Eh0+y6pyI7kHUOsXqGTPqor9t1i/rTnyjcC0roX49OluUzx
         MLCmjBo6OVVAz/iZtGM7dl3OsqqJtBNu1U93a8aT70YWqNHTutoA1/LYXzYRq5sc2b/D
         6RXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cr7nWdSi;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7YHcONCRVhSPMEU6etgqzP+yR9ZfttUA0e1tdMPyEF0=;
        b=FtYf+6pw3T27hcDEPa3T35LJC9njosmsjbydEbiVLubqLhmWn2uTlRP42Td+t/gmQz
         ACvpVFLUyhBB3scsSln8KqkVSd/drH+sxNiQ8yTmg6hYnbss3vZczbg2Oy8GmmwD6lag
         +vrplyw/oU9Ym/7BnNHKXMb3ciuuMFZrK+5j7Q303WKnE1LfG7Q6R1F0HWlV5tIdiCie
         Dtd1msDvRq27vfZ1xyBPAgYsOY6Nf7C0CT+95y6i0iOyZOxrk6e1DfeAsqgblg5UiuP8
         oiXbty91IEpFxWeyc4ffW2TFtbUivBHz6y/ikoqdu208RdM+hXpbXPbhfmWx8Q/T3DFJ
         ZPuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7YHcONCRVhSPMEU6etgqzP+yR9ZfttUA0e1tdMPyEF0=;
        b=VNZ01Xx+1QQehsCfnx32U2AcNwFkC+XEOSyn6OLfg3KsvQSo42doRIaFJnyo6aESGD
         rqLMYqHMbyt0Zfo4al053o/LAyPkkGcshutSckxl6mLqY2QoQkAE4xTEXjWirUNJjFjW
         iBEg1K2jai9QSrTxb1yE1KfsNtm2BWp8DrbZVRUqRL84c56D7yZS/zstglbqqM6G12M8
         x9NwsnVoSdXiRrh8niI8yIUMvPoGEezk1B25bhIIVrqhUrQiHx/jB9jbBqoLZ2YdMo3v
         fEBUf6JnVCmH2RuntcM1jUNGnOXD9+D/oR0ACM6wdecK/r+XuxIWWY21TCdnt5cSfZ5K
         hljA==
X-Gm-Message-State: AOAM5335ZPE2GkY02EyTJsiwkd9XW5hmurQlVcnkJX8ouOgRyKQtjLmT
	gcedr8SREdfyqEpgEoK6mbk=
X-Google-Smtp-Source: ABdhPJzyK4nHPw5V4egfecQKeU7p29EUvP74WZZJU2IPNMqeQlk2ELRC/MYpCug8kPPSUIDLJJ8L+Q==
X-Received: by 2002:a05:6402:16dc:: with SMTP id r28mr12152edx.339.1632420661012;
        Thu, 23 Sep 2021 11:11:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:18c:: with SMTP id r12ls6696560edv.3.gmail; Thu, 23
 Sep 2021 11:11:00 -0700 (PDT)
X-Received: by 2002:a05:6402:40c2:: with SMTP id z2mr67332edb.340.1632420660065;
        Thu, 23 Sep 2021 11:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632420660; cv=none;
        d=google.com; s=arc-20160816;
        b=YQrAexvRnZ5rNULhn1ojnEizswL0WPsV3lvBp0Q3exrRlxHxvNRSPRuOWG/eRMSy/e
         /kHpbmFoWJMbN6Ny1PrHIWFZfNRvnBTqg3ljbn3JLbM37p31mUqCDsfJ1PrFy7s3lMpb
         oLMcgQwpJJBA3Z4Zc1GwC64owW0BlXHBCOU/t47QUcv8W0RYr4wAqgLYVyXBaim/IDxC
         RHo0FNnD9IStjFkqn1sSmHB1M4NSJYwRkV94Kv+FVZIFTvKKphDZ2aES+CpqAcAe/Tmq
         honn2PG2WgErhMrhoXQhF8P5zPq9Bw+j0eIKivU9PJjZq/V3KFDmAkVkvNiGHKKw4xiv
         nK3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=21ubOOR9VOR5U3seg3iEPN0lJ/0NLAApRhv0qLePyFk=;
        b=jIVWvB/EMDm+SupcpNOv40MKG5NXEppb/Qe4YpLcRrrOGT2xKOKA1KE9lfxYHHnANt
         yJ8s9SDHhYu0h5mzQpsUeGkJadfzadDRQt/u0Sa7HRYox90d6XsHpd4qg8DwsHOSJ3O3
         J/xEcEJE17vZZFvtvAxGZbHALIwAYhgnmqsphuq+RW0XlCL/pER2trPd21og+a/aazjr
         xY1ilyxt+5dwYsQVQR0151h9+Xvf5Tp0TVk7GsbzlkdsvVYfOuN0ebKV+lYB/l6g6ZZ4
         Tb7L/eIurh5uQKiErLrNkyqnK1YDwBghZAFYnUvFgv3oEj9acYyjFWo0LbQzQt284iiI
         kmkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cr7nWdSi;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id r23si542329edy.3.2021.09.23.11.11.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 11:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id t28so6292457wra.7
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 11:11:00 -0700 (PDT)
X-Received: by 2002:a1c:7713:: with SMTP id t19mr6090094wmi.162.1632420659610;
 Thu, 23 Sep 2021 11:10:59 -0700 (PDT)
MIME-Version: 1.0
References: <20210922182541.1372400-1-elver@google.com> <CABVgOSmKTAQpMzFp6vd+t=ojTPXOT+heME210cq2NA0sMML==w@mail.gmail.com>
 <CANpmjNN1VVe682haDKFLMOoHOqSizh9y1sGAc4dZXc4WnBsCbQ@mail.gmail.com>
In-Reply-To: <CANpmjNN1VVe682haDKFLMOoHOqSizh9y1sGAc4dZXc4WnBsCbQ@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Sep 2021 02:10:48 +0800
Message-ID: <CABVgOSk3iY7-8h=uJRNwN-UoWYxVZ1dNALzuE1MMLswKUkXfqA@mail.gmail.com>
Subject: Re: [PATCH] kfence: test: use kunit_skip() to skip tests
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cr7nWdSi;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Fri, Sep 24, 2021 at 1:58 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, 23 Sept 2021 at 19:39, David Gow <davidgow@google.com> wrote:
> > On Thu, Sep 23, 2021 at 2:26 AM Marco Elver <elver@google.com> wrote:
> > >
> > > Use the new kunit_skip() to skip tests if requirements were not met. It
> > > makes it easier to see in KUnit's summary if there were skipped tests.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> >
> > Thanks: I'm glad these features are proving useful. I've tested these
> > under qemu, and it works pretty well.
> >
> > Certainly from the KUnit point of view, this is:
> > Reviewed-by: David Gow <davidgow@google.com>
>
> Thanks!
>
> > (A couple of unrelated complaints about the kfence tests are that
> > TRACEPOINTS isn't selected by default, and that the manual
> > registering/unregistering of the tracepoints does break some of the
> > kunit tooling when several tests are built-in. That's something that
> > exists independently of this patch, though, and possibly requires some
> > KUnit changes to be fixed cleanly (kfence isn't the only thing to do
> > this). So not something to hold up this patch.)
>
> I think there was a reason we wanted it to "depends on TRACEPOINTS".
> If it were to select it, then if you do a CONFIG_KUNIT_ALL_TESTS=y,
> and also have KFENCE on, you'll always select tracepoints. In certain
> situations this may not be wanted. If we didn't have
> CONFIG_KUNIT_ALL_TESTS, then certainly, auto-selecting TRACEPOINTS
> would be ok.
>
> If you can live with that, we can of course switch it to do "select
> TRACEPOINTS".

That's probably more convenient for me, but I confess that my use case
is almost always wanting to run the KUnit tests, so I'm not unbiased.
:-)

>
> On a whole I err on the side of fewer auto-selected Kconfig options.

Yeah, it's perfectly sensible to do it either way. Maybe the right
option is to have a .kunitconfig file which has TRACEPOINTS enabled.

It's probably not worth doing if there's still issues with kunit_tool
parsing the results when the test is built-in, so this should probably
wait until KUnit has a way of running code on init/exit of suites as
well as individual tests within those suites. KFENCE is not the only
test suite which needs something like that (nor the only one which
does some module_init or late_initcall stuff which causes some
formatting issues with builtin tests).

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSk3iY7-8h%3DuJRNwN-UoWYxVZ1dNALzuE1MMLswKUkXfqA%40mail.gmail.com.
