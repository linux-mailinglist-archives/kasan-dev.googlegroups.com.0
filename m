Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUQ4PYAKGQEUFNQ3GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 04E36137674
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 19:54:24 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id r30sf1766004pgm.8
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 10:54:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578682462; cv=pass;
        d=google.com; s=arc-20160816;
        b=Flv58KGtUCliEeZtnmjTXmr6mLyjwC5LwDuudseVw97bOcjlRTBOI/T8LosUshzp1Q
         69wimgxsg5CQHgOSENq5PfP27iGO+W1bT+LbUZ/0HYZrFqsBBzBxcXD8nZynJyYQFA58
         qVA5CNXigYTFGL4YaIMXPFKEEuAwaXVQeUKS73hm99kEwaJWy+MbBVyRlGBnNsv5j+Dr
         JQMLqATYbXfin6we1XFSiAAJJ0v1/4UqPPTn5+ffRuwoTvJxccSHYwYuhY95xcEdYbz7
         Fk9FKl10ag8H1z6aifsYCySetGhRgbKw4phKZwI/zCp8wXDYaYcP+AziBhKO9kM7/lHr
         7y3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xmek1KF2ansBYvJ8OyVEFH+tcSte5+oUQ0ui6I0T7k8=;
        b=h36KHVRGOWJaKcumJqKV2Rt8EQPK1G0VFMzO/Wu7ILxvNMYMtbzqUwQKmMJ7tgYI0k
         kGnixERUwiaiVZglqa3eV6iX9n+owwfHJmaiO97jxpgl77JSOumtmPlFsW7kkVJ75asP
         MFJ6n93xcGRco2n2bpIhaFLOVJK0ljxUHVa0UraUyE+VryCW/3AeCOvYM8MKWPBBYtST
         +R2V2R5n3jIAPHs4AMqmrESJKLRIVENy3O/bApe30sgvISUu+KFYNBbZmhv193T3wg7h
         8ywsdvEiPe1SkIxg0nnLpFXf/7GeVq09xuyAQtn5/FRwMbc2nqVfAUXeTPnBOk0ygLw2
         c9xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="W/6dxF5y";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmek1KF2ansBYvJ8OyVEFH+tcSte5+oUQ0ui6I0T7k8=;
        b=h9XlRdGAIsECTMFXTPs++x0RaytjOzFAKNE0ziQY6U7JRH8ijxxTVT/Aqgjeh2LTPn
         ipDTRS3qQ3oSAkNycAa0hyIeQLa+9JFizGhj/2TlVvJt5UHr3VvihCLfTbssuCnNSoiN
         /gttx5t9Bs5XY4lzzPz1I2p43We8E/k6QcXGm6wNTSILNNIFjNoZbwMk/zcDwcprjTAA
         YJbUF6xnRgOlZF0nJEanSHXpaHRdUs0ggI9og1YJxHeKIC6NVQWboIQUSb4SqtQiq2gr
         djIykm/IkfLQAm1FDrpe8+Bkyg2CxDe2CKsnzTttK/+i+H/puLkWmeuuw6n3s8EdxYBe
         vtKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmek1KF2ansBYvJ8OyVEFH+tcSte5+oUQ0ui6I0T7k8=;
        b=bNByFIhjqC6f4tfA8zNo7ob/sdgJ5bzQBKTWY3V1WTR/XrhEh96PL6k7AdbU1XqJXZ
         14lgD3DB9RJpAKEODXZq7Axof5/dDNduEp3ER4AS3QHd6A9im7V4FqX1PzA/iOvoVuqS
         3JsSLsky8YjW1geFB/mwj/PFhjx4jhsbZV1bzPhlMz3sCi/7l1IZhIehDc+plDIy/cdB
         B2byb+pqkeQ7bzCsVAN/86XDt56fbh3awM2Flxwx5edyWLBvfs8MUQzw1RLvYv0IKTuA
         X6Ck5ptcfQ8MrTEk2GgGWnDpz3GXNDIymI0LOEu1+uhyOwHQpqaPep1VU51lJ+2qGz6S
         HKoA==
X-Gm-Message-State: APjAAAWWXNvPyNusZrevmvlX/d+d5dRyfn5fqqfsppVD3olAYjUdG97R
	VkZt575v7CPT6IbLHwqRhmA=
X-Google-Smtp-Source: APXvYqw7lXY3rakz2QLTqy4N0Bk9Q3wDkqw2uGORJJBj44QzNaBQq3WkO/IoVrQGSwF4KMX9/WDfLw==
X-Received: by 2002:aa7:8708:: with SMTP id b8mr5874050pfo.184.1578682462722;
        Fri, 10 Jan 2020 10:54:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d207:: with SMTP id a7ls1582361pgg.1.gmail; Fri, 10 Jan
 2020 10:54:22 -0800 (PST)
X-Received: by 2002:aa7:8d8f:: with SMTP id i15mr5670129pfr.220.1578682462357;
        Fri, 10 Jan 2020 10:54:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578682462; cv=none;
        d=google.com; s=arc-20160816;
        b=Hwi4/h9FEpbu4qESl1NxcTAnwiFGPuER9af3QyXQp8Z8lHojsvtSeSpLi4Tky+CuqO
         V1bRJDJrM2pertpicBlyTz85inCXs1BdVfzcMV5hGeN3YizFIZvlZpHNYr8KxoeN/9ZF
         mWb9ohA/FOEX+6Ek1qerGI5zTeXY/bL13+zkPDYphcOscnFU/NGL2T/V806daDLD7l4e
         I6CxGR/l4AwOwz9O7gWuCPC+PirnZeIEMZoXq2CBjbxDvDQtR6yv+56EXuD58Fek6l2A
         Ux4gz+yfCRfeznbA02VJP62pU5VRvl/dPwQn6RdYSDf/zBPklQ0Krmr1NBAVpgu6JijG
         6MVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QcMlx17bbe46RkMKi52DH8y3hZ3BUHEjTIS1UBwAyfk=;
        b=GpHxKs7Tcc8+NFEgKpFB2HRmsvuDCbM2CmnWzomZJJAw2Ko+9oZB0Ae3v0VFkhlVn8
         QY4z+7MG6cEIDqZ8kHIJuUzBWJdvKFeg29CsSo6ItiPxIPwTROeXjf+lnmO8EkGc8+E3
         tbCiC/aJMmQOvv9td/A860qQ0mBnWggMijCnKJ5PZswgiVQrLPmyjA2O5V6QoFit5n9h
         8rRwslpuApcVaZ/sDvzseCtWceY91xBATLDWvIwM5fj7rBQGSTXlJCPd5dc/TiLpu25n
         67nsF3y6j3zDVBF4tUrGADf8qay3GDpKHWvifFX7tJeYooULRMYlbF1huiNWZr6EypXK
         JtPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="W/6dxF5y";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id a24si134262plm.1.2020.01.10.10.54.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 10:54:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id b18so2966349otp.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 10:54:22 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr3925122otq.17.1578682461403;
 Fri, 10 Jan 2020 10:54:21 -0800 (PST)
MIME-Version: 1.0
References: <20200109152322.104466-1-elver@google.com> <20200109152322.104466-3-elver@google.com>
 <CANpmjNNt_+EQHLFZyV5_Wq1frU3A=Rh8y5P7Zjp-0cAU2X7N6w@mail.gmail.com>
In-Reply-To: <CANpmjNNt_+EQHLFZyV5_Wq1frU3A=Rh8y5P7Zjp-0cAU2X7N6w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2020 19:54:09 +0100
Message-ID: <CANpmjNOcjdr6HNaSP4Q7GTR72vx4bSMa_2O=_9oQwcz3xFk=Wg@mail.gmail.com>
Subject: Re: [PATCH -rcu 2/2] kcsan: Rate-limit reporting per data races
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="W/6dxF5y";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Fri, 10 Jan 2020 at 19:20, Marco Elver <elver@google.com> wrote:
>
> On Thu, 9 Jan 2020 at 16:23, Marco Elver <elver@google.com> wrote:
> >
> > Adds support for rate limiting reports. This uses a time based rate
> > limit, that limits any given data race report to no more than one in a
> > fixed time window (default is 3 sec). This should prevent the console
> > from being spammed with data race reports, that would render the system
> > unusable.
> >
> > The implementation assumes that unique data races and the rate at which
> > they occur is bounded, since we cannot store arbitrarily many past data
> > race report information: we use a fixed-size array to store the required
> > information. We cannot use kmalloc/krealloc and resize the list when
> > needed, as reporting is triggered by the instrumentation calls; to
> > permit using KCSAN on the allocators, we cannot (re-)allocate any memory
> > during report generation (data races in the allocators lead to
> > deadlock).
> >
> > Reported-by: Qian Cai <cai@lca.pw>
> > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  kernel/kcsan/report.c | 112 ++++++++++++++++++++++++++++++++++++++----
> >  lib/Kconfig.kcsan     |  10 ++++
> >  2 files changed, 112 insertions(+), 10 deletions(-)
> >
> > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > index 9f503ca2ff7a..e324af7d14c9 100644
> > --- a/kernel/kcsan/report.c
> > +++ b/kernel/kcsan/report.c
> > @@ -1,6 +1,7 @@
> >  // SPDX-License-Identifier: GPL-2.0
> >
> >  #include <linux/kernel.h>
> > +#include <linux/ktime.h>
> >  #include <linux/preempt.h>
> >  #include <linux/printk.h>
> >  #include <linux/sched.h>
> > @@ -31,12 +32,101 @@ static struct {
> >         int                     num_stack_entries;
> >  } other_info = { .ptr = NULL };
> >
> > +/*
> > + * Information about reported data races; used to rate limit reporting.
> > + */
> > +struct report_time {
> > +       /*
> > +        * The last time the data race was reported.
> > +        */
> > +       ktime_t time;
> > +
> > +       /*
> > +        * The frames of the 2 threads; if only 1 thread is known, one frame
> > +        * will be 0.
> > +        */
> > +       unsigned long frame1;
> > +       unsigned long frame2;
> > +};
> > +
> > +/*
> > + * Since we also want to be able to debug allocators with KCSAN, to avoid
> > + * deadlock, report_times cannot be dynamically resized with krealloc in
> > + * rate_limit_report.
> > + *
> > + * Therefore, we use a fixed-size array, which at most will occupy a page. This
> > + * still adequately rate limits reports, assuming that a) number of unique data
> > + * races is not excessive, and b) occurrence of unique data races within the
> > + * same time window is limited.
> > + */
> > +#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
> > +#define REPORT_TIMES_SIZE                                                      \
> > +       (CONFIG_KCSAN_REPORT_ONCE_IN_MS > REPORT_TIMES_MAX ?                   \
> > +                REPORT_TIMES_MAX :                                            \
> > +                CONFIG_KCSAN_REPORT_ONCE_IN_MS)
> > +static struct report_time report_times[REPORT_TIMES_SIZE];
> > +
> >  /*
> >   * This spinlock protects reporting and other_info, since other_info is usually
> >   * required when reporting.
> >   */
> >  static DEFINE_SPINLOCK(report_lock);
> >
> > +/*
> > + * Checks if the data race identified by thread frames frame1 and frame2 has
> > + * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
> > + */
> > +static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
> > +{
> > +       struct report_time *use_entry = &report_times[0];
> > +       ktime_t now;
> > +       ktime_t invalid_before;
> > +       int i;
> > +
> > +       BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 && REPORT_TIMES_SIZE == 0);
> > +
> > +       if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
> > +               return false;
> > +
> > +       now = ktime_get();
> > +       invalid_before = ktime_sub_ms(now, CONFIG_KCSAN_REPORT_ONCE_IN_MS);
>
> Been thinking about this a bit more, and wondering if we should just
> use jiffies here?  Don't think we need the precision.

Sent v2: http://lkml.kernel.org/r/20200110184834.192636-1-elver@google.com
I think it's also safer to use jiffies, as noted in the v2 patch.

Paul: sorry for sending v2, seeing you already had these in your tree.
Hope this is ok.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOcjdr6HNaSP4Q7GTR72vx4bSMa_2O%3D_9oQwcz3xFk%3DWg%40mail.gmail.com.
