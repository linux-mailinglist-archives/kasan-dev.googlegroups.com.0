Return-Path: <kasan-dev+bncBCMIZB7QWENRB2XSQ2FAMGQEMFWUHYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id C6FB140C297
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 11:14:20 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id k4-20020a67ab44000000b002d107a4903bsf398029vsh.20
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 02:14:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631697259; cv=pass;
        d=google.com; s=arc-20160816;
        b=G4xjNg1RO44l9hF6qU1LHH4JTx1RMmTfLSAZhCmgk0/o5Beg6oUfoeJaSl8sKHGzMG
         akt/XR+70NNI2m/6120LR8yTkC/JqCXzHEb7PIqXLPcAn0o+S9uZ4iyvptCs4fVfGKHp
         jeGotdcrx0ZB34UVcq8lvRMo8tB1bAWpsNk4h3CcUTXfbIlAlAGj4Rf+1e4ykCrOvWCs
         CYBsQjPA9Gifik1JLkynlUTPsXkgBQ70riE7wWdHTjthsPUVgJj0Y8aDPDznsFHlZYDG
         GNpZy0N6hkqHYcsW1WcqF1gXgLsR4SMbVXztiOmBfGkuK9Vqv8bRMl7LCqopg7tBxIzm
         K2NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RZsikyYLzEMHIkKMhMBznGWSO6XUVbCsMjPESPPQDUY=;
        b=ddzJPr54zDdTZmx6zlAhOPQE6+FC5wsP74SgNpLMkwMhm/6l5giYn0DArgQdukqHyw
         dVQE62OGOf6kxZF/9ceNIXQPmUorBE0edHGaueIdZ3Bfm7HTSMtatVrLH/+XnWHfhxG+
         BYT88GLtZdvOwZr/QBgVlWae1Ttg4H0ByB7aLrFlqWBch9Xb8O6T2pEXK7vpjp1Z+TaM
         XUvedJ/mHHZ4BzFrd41M6QW+q4AOGQb/c+TkmbQ/Re964dyXAXff/G8jGVuq6bwdZyU1
         Ri/p48w7LhnsFpD78qULZYMK1SKFAcGnhEAMg34sl2FzzJydUHe9yqtR+rkdIh1w6eB5
         x29Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QsgOKFYH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZsikyYLzEMHIkKMhMBznGWSO6XUVbCsMjPESPPQDUY=;
        b=Abx24URS9CaacLQx/566UrWTP8QAcylZAmH71f8xapGtVLuAvYqvv/nvj2visd3ne8
         stH+uA34QHzy8gI0Aa+M4F1Cm3DUzx/DvTDhIeuNDFhAh1oZUx5hEBf8JgXAPwzjsb3F
         A1psGiilPiru5ys20VDHUEEpCkAaWY8JaSu7/kblQla5E9gKtf65snoCsXOtxF2BJnY3
         tZ0iSkM7CKfckwwxErZuZ3emSvOoetokr8/HmDTfc/wzpeViVH3NTFUFBMK8rAd6EJFm
         U84z8w+NHsRQyyBMbvK0IjgpoRDynWfxldsL310ZW2MhMFPfUSjYUo9xL4kJR/fMHEKm
         zkiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZsikyYLzEMHIkKMhMBznGWSO6XUVbCsMjPESPPQDUY=;
        b=a814cIaRCmgs7bBZDxThRO7ahXU1ZOTNBBAQG26hxZLBZl4zK7aCLrdJm0xf3yyyF4
         ibtkTNJIady5JmeESA6Ygr+iIDAzFNyqH8Izbxj3WCfkO3vgmybeu+joeDQYtu8wAGDk
         Q9BjyKK3FZIYPMZ1FH88XNUuk/IQk2ZIryVolvYflPyVN4TgOQCSi4wn1ZedRVwmA8tN
         kAYtLtyrPWU9qCzrlUJYet2UCIg1r4DVRoXw0+W8aAB2B7MHvS2pg50m6EoTnV1Uv3Yt
         fn+eUZAS4N6rLhkDmnCvU97uD8xrKQE1aF2NY6/2K1NJFgi0pvRSSmTZQoBy9R+0ODHj
         ukvA==
X-Gm-Message-State: AOAM532SjNUYqCOwRp+xs4iEKSdKXuTRLBWHIndg4sMLxRGN17ZJrd1Y
	3lyFF16tlg3TP6QI6816948=
X-Google-Smtp-Source: ABdhPJxEapxncQQTHme29r30kcmpgFvHClCIy8fbNwzYxt9pvHOO4dsPoUK9Dn8PvJUxuw9wqdYSyg==
X-Received: by 2002:a1f:de84:: with SMTP id v126mr2188397vkg.12.1631697258311;
        Wed, 15 Sep 2021 02:14:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c89a:: with SMTP id v26ls282007vsk.0.gmail; Wed, 15 Sep
 2021 02:14:17 -0700 (PDT)
X-Received: by 2002:a67:dc8b:: with SMTP id g11mr2496656vsk.26.1631697257840;
        Wed, 15 Sep 2021 02:14:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631697257; cv=none;
        d=google.com; s=arc-20160816;
        b=N5wuWiF8u3cYJ1m9CdAYzClK/k6b24tsPTF6Vu2hHeqmDFcDtD9QqBSorEV8L37UOT
         4YbMnMYIg/JUk8dSgHqzhwWnofea/yYP+uHIWdoGBJAgSN2Q1F5jWUZa4UO0xT2mAUSC
         ZExU/kO4x0M/7TJBBEzqxqdAw1pxDn9dUnTnledmJHCtaxdheHAG/i2wKFTKE6Vin5XP
         hq41XHjaJBWTjrq9eDEVpEipI5vzWZ4m9YEMTa5AjJU7b7SdDzEIoGQUhY+aFFcuGlZw
         OC4Uc1SNvuX1/MjQBpkbHfwdVFSke5Ew/ZL697I7DSNwwgEpvRSI9oVal1ZRWAEpdgCO
         i7Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n2R5sQocnc5nHBs+VrySqd2CEimyp7idPHRQqGykyb8=;
        b=eDBNpNr8VmCsEgpNMoB8kdUyjZ5ziM8IwIH4VlXaBIauGnixAMHiV//Hi/XVORpC9c
         osYwFFZePH9btTA/gvKTwDykZ6KJytw00pBHAcoZYJAi8zpDDhQVGodPf5Q2vM1iWaVU
         ty6m9iiWSscqo8vg+BrjgmKhxvq1DoTdYOBg4+tfI2gSnVvbmvHzaXtJ1SPD20uVlqnV
         QVO/49OZwCkiXlW8S9urDXX/9iDOC8LrqeweRXqSNIqcRBQ1HFt250Js1JgaOIJkPR++
         75OYNIffPIkTPpKb9tc3dGc9QtG9vRu/297Ob7q9wyTJX1FaXinUKGF/h9z99WmA2nHF
         2/Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QsgOKFYH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id u23si86522vsn.2.2021.09.15.02.14.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Sep 2021 02:14:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id y128so3332173oie.4
        for <kasan-dev@googlegroups.com>; Wed, 15 Sep 2021 02:14:17 -0700 (PDT)
X-Received: by 2002:aca:f189:: with SMTP id p131mr4569843oih.128.1631697257294;
 Wed, 15 Sep 2021 02:14:17 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000eaacf005ca975d1a@google.com> <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx>
 <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com> <87mtoeb4hb.ffs@tglx>
In-Reply-To: <87mtoeb4hb.ffs@tglx>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Sep 2021 11:14:06 +0200
Message-ID: <CACT4Y+avKp8LCS8vBdaFLXFNcNiCq3vF-8K59o7c1oy86v-ADA@mail.gmail.com>
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Hillf Danton <hdanton@sina.com>, 
	syzbot <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>, 
	linux-kernel@vger.kernel.org, paulmck@kernel.org, 
	syzkaller-bugs@googlegroups.com, Peter Zijlstra <peterz@infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Johannes Berg <johannes.berg@intel.com>, 
	Kalle Valo <kvalo@codeaurora.org>, linux-wireless@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QsgOKFYH;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22b
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 15 Sept 2021 at 10:57, Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Tue, Sep 14 2021 at 20:00, Dmitry Vyukov wrote:
> > On Tue, 14 Sept 2021 at 16:58, Thomas Gleixner <tglx@linutronix.de> wrote:
> >> Now what happens when the mac80211 callback rearms the timer so it
> >> expires immediately again:
> >>
> >>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
> >>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
> >>
> >> bcn is a user space controlled value. Now lets assume that bcn_int is <=1,
> >> which would certainly cause the loop in hrtimer_run_queues() to keeping
> >> looping forever.
> >>
> >> That should be easy to verify by implementing a simple test which
> >> reschedules a hrtimer from the callback with a expiry time close to now.
> >>
> >> Not today as I'm about to head home to fire up the pizza oven.
> >
> > This question definitely shouldn't take priority over the pizza. But I
> > think I saw this "rearm a timer with a user-controlled value without
> > any checks" pattern lots of times and hangs are inherently harder to
> > localize and reproduce. So I wonder if it makes sense to add a debug
> > config that would catch such cases right when the timer is set up
> > (issue a WARNING)?
>
> Yes and no. It's hard to differentiate between a valid short expiry
> rearm and something which is caused by unchecked values. I have some
> ideas but all of them are expensive and therefore probably debug
> only. Which is actually better than nothing :)
>
> > However, for automated testing there is the usual question of
> > balancing between false positives and false negatives. The check
> > should not produce false positives, but at the same time it should
> > catch [almost] all actual stalls so that they don't manifest as
> > duplicate stall reports.
>
> Right. The problem could be even there with checked values:
>
>        start_timer(1ms)
>        timer_expires()
>          callback()
>            forward_timer(timer, now, period(1ms));
>
> which might be perfectly fine with a production kernel as it leaves
> enough time to make overall progress.
>
> Now with a full debug kernel with all bells and whistels that callback
> might just run into this situation:
>
>       start_timer(1ms) T0
>        timer_expires() T1
>          callback()
>            do_stuff()
>            forward_timer(timer, TNOW, period(1ms));
>
>
> T1 - T0   = 1.001ms
> TNOW - T1 = 0.998 ms
>
> So the forward will just rearm it to T0 + 2ms which means it expires in
> 1us.
>
> > If I understand it correctly the timer is not actually set up as
> > periodic, but rather each callback invocation arms it again. Setting
> > up a timer for 1 ns _once_ (or few times) is probably fine (right?),
> > so the check needs to be somewhat more elaborate and detect "infinite"
> > rearming.
>
> Yes.
>
> That made me actually look at that mac80211_hwsim callback again.
>
>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
>
> So what this does is really wrong because it tries to schedule the timer
> on the theoretical periodic timeline. Which goes really south once the
> timer is late or the callback execution took longer than the
> period. Hypervisors scheduling out a VCPU at the wrong place will do
> that for you nicely.

Nice!

You mentioned that hrtimer_run_queues() may not return. Does it mean
that it can just loop executing the same re-armed callback again and
again? Maybe then the debug check condition should be that
hrtimer_run_queues() runs the same callback more than N times w/o
returning?


> What this actually should use is hrtimer_forward_now() which prevents
> that problem because it will forward the timer in the periodic schedule
> beyond now. That won't prevent the above corner case, but I doubt you
> can create an endless loop with that scenario as easy as you can with
> trying to catch up on your theoretical timeline by using the previous
> expiry time as a base for the forward. Patch below.
>
> /me goes off to audit hrtimer_forward() usage. Sigh...
>
> After that figure out ways to debug or even prevent this. More sigh...
>
> Thanks,
>
>         tglx
> ---
>  drivers/net/wireless/mac80211_hwsim.c |    4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> --- a/drivers/net/wireless/mac80211_hwsim.c
> +++ b/drivers/net/wireless/mac80211_hwsim.c
> @@ -1867,8 +1867,8 @@ mac80211_hwsim_beacon(struct hrtimer *ti
>                 bcn_int -= data->bcn_delta;
>                 data->bcn_delta = 0;
>         }
> -       hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
> -                       ns_to_ktime(bcn_int * NSEC_PER_USEC));
> +       hrtimer_forward_now(&data->beacon_timer,
> +                           ns_to_ktime(bcn_int * NSEC_PER_USEC));
>         return HRTIMER_RESTART;
>  }
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BavKp8LCS8vBdaFLXFNcNiCq3vF-8K59o7c1oy86v-ADA%40mail.gmail.com.
