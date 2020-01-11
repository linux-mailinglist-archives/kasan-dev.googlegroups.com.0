Return-Path: <kasan-dev+bncBAABB7FS4XYAKGQECANPO3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C4D10137B79
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2020 06:13:33 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id a20sf1800710vkm.22
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 21:13:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578719612; cv=pass;
        d=google.com; s=arc-20160816;
        b=ihCl3ckNBLHlpk7vGHWoD50tByGwbmbZH3BfoFcSV7+5mW80Zjtx/K4ci5ifWyaEO7
         B2QnPs/leOTfwOs9FNy1PzqtgVciJI0InNtRBpyDhIZf369V4Xdzj5R84iQ1CNn8KEBF
         N+jSMhGaK1VtwCIpHTlt3JOw5G15bMzHAALHCX+SJpH+XSmp/9l2K+xVgQ9UOBqNCIlt
         /1hpiPHCDIyWDmnDeT72CQnkSvz4e8x7V+6o0BG/SlHL9nwooupCZBycrUUKrRifmvqC
         oMY8ocyZrWjDP5cCx/8RVrO0pt7/bPcegRAiNI/7L/4toJ+lnc0fpxnZfCWLeZ1LqqqX
         2XaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=mmjerlxziJNi462I0n1bfDeVJk4golwXZbHqRuYegGc=;
        b=yxkyNoKq4nzG6zO0Lt7cfLFaTJWpAHPWditX7LGNjPBFNSUSJRZ14+hZ8n4SmquR78
         ch5pMOzT/i4rr7PQU4H+eWIHtQ3A3yq4vBIugAUXIgCpY6ty2xSq7eu6VTvfr+xKvM57
         Mr3bBbIzNGw0KZrrs/mdqMBSVcuCevHCDsS3vJYehttJHURmBxBT2/xWQxPpgq/QVldH
         i1S78OCIm89uqUW1CQB8EMLMtitgCKTJmP7UVmm3gQIpWK6nPmERyIcbg0Hakv8uqJCw
         iu+Ybl/jg7Pzk7dX/m3V5wUM5V8Dcct8sGqZXH9LYPGXRByT3Kkh7xH4UkyHUXlmrGtR
         sjsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rYcvO1RX;
       spf=pass (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=sZ6w=3A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mmjerlxziJNi462I0n1bfDeVJk4golwXZbHqRuYegGc=;
        b=bh/L1NMSvWsqx2Cvn+L/QVQd2kg+0UfywDiSWu8b9cNhx8EyTVnCCrD6rmnggHa1NL
         HNllkP40dhYJJYHdjaLdBmvorNystVsWTXSs0CRvcegHupJc9Fyx+U6xJMJQC9Ruye53
         7aMGZqVilJjhe1Fk9QhyYrya+ICUkpuNdC5e99k9whWKCD9v4/jV5vVDu8FZNXhzDGSV
         Ubm4QwzGW2Fm5VKJVi+c6mXnUMvMV3/LD09gFQXM2TbBCgh2uLU1W8q5s++Z6q1eF6mr
         kPO6UzwId6w+jE+AqeFDdLTsoX2Q2FBmwyxm0ggDLf4cwXnfrVCsoAwUfU/8/Mqpoar9
         geGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mmjerlxziJNi462I0n1bfDeVJk4golwXZbHqRuYegGc=;
        b=MlYrG1X0ituQ5WW2kb/EYcubhXJj9cQPx2e29vrtUakjmlUJ1Y/rxynTrOdCJlz/Yg
         mVa43hC+o9WQg3bRpHKnQyEYJbmYvsv//emFugyWsfKUCTt1W/FQv3GsxkFBZhISLNNd
         qtZdusUBPfeCLdmtnHuad7xzyf+10nfuaCDg4KI7gwMv24ZWOLvmIFqSXsKYYsz9TPnB
         pC/jvmQOtaXTqtDtOf7vOrBqTzaL3hyU+oGEjQpCGQLtVFieM4PzN4LPajayNQAkaTGE
         Pl+NEF/PTCZoAYlHaYPJI/hQOfpBAUQKH2a7BivKr/1N7y5IvbHCHSLvk+l+5qfs86bT
         eP4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfkVrq3gC2mZGn7ZRdU3/+I1TUnRg3suNkvUqyU9y1xdo4UFNe
	AD5ghg1pXiT78LNPN5BU/sw=
X-Google-Smtp-Source: APXvYqxkyWGSqFfKn9KlGnZjLJG5MnC5Au4dQ7Y2r0DVaLJfppK+cmOwSEuI1arsNNYWrk33pHm78g==
X-Received: by 2002:ab0:7049:: with SMTP id v9mr4295383ual.95.1578719612287;
        Fri, 10 Jan 2020 21:13:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c20c:: with SMTP id i12ls641188vsj.14.gmail; Fri, 10 Jan
 2020 21:13:32 -0800 (PST)
X-Received: by 2002:a05:6102:20c:: with SMTP id z12mr3886973vsp.32.1578719612028;
        Fri, 10 Jan 2020 21:13:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578719612; cv=none;
        d=google.com; s=arc-20160816;
        b=ZL1M91JNfVNSW/160+P1xBcR0tw8IWoJbLUeurFQWmDbJyfiEX9P39p9pKISFbd2S2
         7xDiJ3ISwBx8HbnxZY79pljmY38DD2MVyKDkSZHMRSdpwY3bzAsfhjHUR/83HNa59nqD
         7/6YPWWAxyFfHlYR50vVUblzL25+/shM53kHFyex4yIfHOmEbuueE8BqxTSp2DZOoN4Q
         FEdHpqAgyZRU0rOGzZ96i1knVOcc3NOzcEN42AGY9UPrKSBhG0DRzmzdAqG/MmlQ2XAM
         T2og0g1iB5dAUCJR5rpjcLVzAX8aepBNKg/K1JR1qiOX9F+UYLGubIAkhTN4Jg+b2EOg
         tGHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TJbyE/MSXaZBlg9XQfpVJR6fmaJSUwRaj3KGDRF+J0c=;
        b=x0H/Q/HL1ZXf+J6f2TjZORl7fWwU3X/iPeWsGPeeF1VF4iE/W8eE9BCToJxHK9Gg5g
         SPLiRUiIR8HjQ0tfY03xG5PLHWTJygaOWkLBDcjisqTbBGxAmYuTHKMkhLBqrnpidihN
         UHLw6hAHlQMZAhTU1rJMjs52R0Pcxb3rkP1ysvXshB/1lXNYwQnuG0hwJk7pD51TmWOB
         qTokLj8VUnIdThVFzzGEgiUFKOMnRZkXmaR9dehvOMgRP67SB3GTapOqIUZKYJxL6jv0
         Nzs3AAk4b63w0l5O/E3aE6V7Tc7KJQFgwNHCsbNIgUlBPyezq+/SuGybV+uM/7Td+4Vu
         GLAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rYcvO1RX;
       spf=pass (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=sZ6w=3A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i27si202513uat.1.2020.01.10.21.13.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jan 2020 21:13:31 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C69B52077C;
	Sat, 11 Jan 2020 05:13:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 859AD3522887; Fri, 10 Jan 2020 21:13:30 -0800 (PST)
Date: Fri, 10 Jan 2020 21:13:30 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Qian Cai <cai@lca.pw>
Subject: Re: [PATCH -rcu 2/2] kcsan: Rate-limit reporting per data races
Message-ID: <20200111051330.GG13449@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200109152322.104466-1-elver@google.com>
 <20200109152322.104466-3-elver@google.com>
 <CANpmjNNt_+EQHLFZyV5_Wq1frU3A=Rh8y5P7Zjp-0cAU2X7N6w@mail.gmail.com>
 <CANpmjNOcjdr6HNaSP4Q7GTR72vx4bSMa_2O=_9oQwcz3xFk=Wg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOcjdr6HNaSP4Q7GTR72vx4bSMa_2O=_9oQwcz3xFk=Wg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=rYcvO1RX;       spf=pass
 (google.com: domain of srs0=sz6w=3a=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=sZ6w=3A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Jan 10, 2020 at 07:54:09PM +0100, Marco Elver wrote:
> On Fri, 10 Jan 2020 at 19:20, Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 9 Jan 2020 at 16:23, Marco Elver <elver@google.com> wrote:
> > >
> > > Adds support for rate limiting reports. This uses a time based rate
> > > limit, that limits any given data race report to no more than one in a
> > > fixed time window (default is 3 sec). This should prevent the console
> > > from being spammed with data race reports, that would render the system
> > > unusable.
> > >
> > > The implementation assumes that unique data races and the rate at which
> > > they occur is bounded, since we cannot store arbitrarily many past data
> > > race report information: we use a fixed-size array to store the required
> > > information. We cannot use kmalloc/krealloc and resize the list when
> > > needed, as reporting is triggered by the instrumentation calls; to
> > > permit using KCSAN on the allocators, we cannot (re-)allocate any memory
> > > during report generation (data races in the allocators lead to
> > > deadlock).
> > >
> > > Reported-by: Qian Cai <cai@lca.pw>
> > > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  kernel/kcsan/report.c | 112 ++++++++++++++++++++++++++++++++++++++----
> > >  lib/Kconfig.kcsan     |  10 ++++
> > >  2 files changed, 112 insertions(+), 10 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > > index 9f503ca2ff7a..e324af7d14c9 100644
> > > --- a/kernel/kcsan/report.c
> > > +++ b/kernel/kcsan/report.c
> > > @@ -1,6 +1,7 @@
> > >  // SPDX-License-Identifier: GPL-2.0
> > >
> > >  #include <linux/kernel.h>
> > > +#include <linux/ktime.h>
> > >  #include <linux/preempt.h>
> > >  #include <linux/printk.h>
> > >  #include <linux/sched.h>
> > > @@ -31,12 +32,101 @@ static struct {
> > >         int                     num_stack_entries;
> > >  } other_info = { .ptr = NULL };
> > >
> > > +/*
> > > + * Information about reported data races; used to rate limit reporting.
> > > + */
> > > +struct report_time {
> > > +       /*
> > > +        * The last time the data race was reported.
> > > +        */
> > > +       ktime_t time;
> > > +
> > > +       /*
> > > +        * The frames of the 2 threads; if only 1 thread is known, one frame
> > > +        * will be 0.
> > > +        */
> > > +       unsigned long frame1;
> > > +       unsigned long frame2;
> > > +};
> > > +
> > > +/*
> > > + * Since we also want to be able to debug allocators with KCSAN, to avoid
> > > + * deadlock, report_times cannot be dynamically resized with krealloc in
> > > + * rate_limit_report.
> > > + *
> > > + * Therefore, we use a fixed-size array, which at most will occupy a page. This
> > > + * still adequately rate limits reports, assuming that a) number of unique data
> > > + * races is not excessive, and b) occurrence of unique data races within the
> > > + * same time window is limited.
> > > + */
> > > +#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
> > > +#define REPORT_TIMES_SIZE                                                      \
> > > +       (CONFIG_KCSAN_REPORT_ONCE_IN_MS > REPORT_TIMES_MAX ?                   \
> > > +                REPORT_TIMES_MAX :                                            \
> > > +                CONFIG_KCSAN_REPORT_ONCE_IN_MS)
> > > +static struct report_time report_times[REPORT_TIMES_SIZE];
> > > +
> > >  /*
> > >   * This spinlock protects reporting and other_info, since other_info is usually
> > >   * required when reporting.
> > >   */
> > >  static DEFINE_SPINLOCK(report_lock);
> > >
> > > +/*
> > > + * Checks if the data race identified by thread frames frame1 and frame2 has
> > > + * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
> > > + */
> > > +static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
> > > +{
> > > +       struct report_time *use_entry = &report_times[0];
> > > +       ktime_t now;
> > > +       ktime_t invalid_before;
> > > +       int i;
> > > +
> > > +       BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 && REPORT_TIMES_SIZE == 0);
> > > +
> > > +       if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
> > > +               return false;
> > > +
> > > +       now = ktime_get();
> > > +       invalid_before = ktime_sub_ms(now, CONFIG_KCSAN_REPORT_ONCE_IN_MS);
> >
> > Been thinking about this a bit more, and wondering if we should just
> > use jiffies here?  Don't think we need the precision.
> 
> Sent v2: http://lkml.kernel.org/r/20200110184834.192636-1-elver@google.com
> I think it's also safer to use jiffies, as noted in the v2 patch.
> 
> Paul: sorry for sending v2, seeing you already had these in your tree.
> Hope this is ok.

Not a problem!  Pulling in the replacements shortly.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200111051330.GG13449%40paulmck-ThinkPad-P72.
