Return-Path: <kasan-dev+bncBCMIZB7QWENRBMWGQOFAMGQE65YNE5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3751E40B66A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 20:00:20 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id w2-20020a63fb42000000b00255da18df0csf9850360pgj.9
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 11:00:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631642418; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vvcq1N7oOj2Iwzx3fCVhoqpmYhMuZ158tG0z0C9htuRdM294uDCHl+bedn/a83jHEA
         bQMGewB805nURCe5wCZDkBrz7f+3z6vmJeDCIpbvmx9wCCtGHSQgVucg+9xy0Fb+lj5Y
         nAZA09SE4mRljONXLhVEK4bCX1VOa1oUy4GWiiLmZULmOm3WFIFZrTLPFLSUkC4jpfmB
         89JCD1+ItV+/KHs3uk8jM5UiOjaaUYSgXrivGd8EnDVkA/zONu+u6F3Dpa1N1+ScbzY5
         e4n/VxV1Zri/3U48QxfbDHghlvA8QOpwNkL7alVSnZBqK8uDnBCIc9of6DPxiXAktVcO
         H8Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=K9PHIYWxtO7Dsm34nMzD6LkUxtGmytnlAIzzIQxf5kI=;
        b=JNKZho+mr/+HEv1555kNMW0fDpXWgK/NX1ANaxw+P3h6Ce119gpe7m98O1dwTZnVVc
         odRiptaBa/IPwgNUtmzkz/usmr2TmVvQoBO/kZfFao0wLJhGvP5n62DrwUgBHkzhkggW
         mNIcUs4nshumd3OmfwYDLSbMRzcEAADEmLNMXvxSOHRV3d5EgDq3wH41He628RPx8GwS
         zlTD7+LqV8Lmu1vUOi4VMETvBbz9DrbhZlth5KbgwCsuxiG7P27PN3cZCWDLe8cGRQNU
         Z9bSBenkFpztAQyGt0vyTlT20vrObA10m32XF+222dN51pt2Puj6h/QtQOL2evm0E6ZD
         VYlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ShQlUJke;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K9PHIYWxtO7Dsm34nMzD6LkUxtGmytnlAIzzIQxf5kI=;
        b=HaNsuoX+SsDC0OarE/AjyTRxGBoN06HY+hsc9F6oV+ggQ2ODNYpc4dyC2SwNpXHIx0
         BHo4K+pQYQAAgznFGbU78nVc0yuoFpoyXKiHsgpkq+mwk0G6d6T52UkedWQkxnA5BMv1
         6hoL0D68l/toRCHZ8EOwMKLmu0Hjg5ms28Ss4fV+d2ILRvej558n7gG62bL7POnV+GD4
         jZiVIoq/nQX2Yc4IHeuiSyJOB+lxgvvlK0yplh8Ida8jinsCOWAv6iS/HREyKA7i1Dx2
         5iZ4fIWHHVWflKSVN4jsG5nWsClXGA+yfnPNh7Rg+2wk7k1LjqECLoTIBgpMvEVYN5WQ
         jYKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K9PHIYWxtO7Dsm34nMzD6LkUxtGmytnlAIzzIQxf5kI=;
        b=T6tFL+spgNtnbMsAVq/9tfQxTMQq7FT+P3tnaossjNbSqDj8Z7gZ6aiXo6F9cbzEfW
         QWUpjk175ml98W5UkF6WoTXJV4cTKQARVLhexCX8Kq9UWSeeB+JhvFOtCpbQPRHBX5qL
         9Z3Z94To4E67JOh5wYJQKzVm+kVOWt4KFu0Y9/QkFQecaHEFTFU2zJzzQ6BySPUV3TRD
         mMpCIh12HqQDdf5RFQqOmDS0i7BIzX/BsKNA5SYIdi5dlN7zo5GRNpw8Eh2rPHod4ChG
         luGjGDc67Hm6qh9zCEgx5KlKOMDa0Tus47GFtrpx2AgwH3FqqPZznH1lQJuGFvBIMPrp
         CGLg==
X-Gm-Message-State: AOAM5312PX3Qfp4PGow4KLx0IMMGv2V/CDZpkrjUxvtuG2Ki/VDV5TkH
	tqmZpM20H2khHivd1gkwoBw=
X-Google-Smtp-Source: ABdhPJz126psPTGJmhJys7McHX5epGZCEeJeXQ/k+Nm2berniDyzR4mROnsdXDuBDNj3efJ5NYN1hw==
X-Received: by 2002:a17:90b:4b49:: with SMTP id mi9mr3101350pjb.79.1631642418556;
        Tue, 14 Sep 2021 11:00:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f81:: with SMTP id q1ls1133470pjh.1.gmail; Tue, 14
 Sep 2021 11:00:16 -0700 (PDT)
X-Received: by 2002:a17:90a:294f:: with SMTP id x15mr3558523pjf.36.1631642416655;
        Tue, 14 Sep 2021 11:00:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631642416; cv=none;
        d=google.com; s=arc-20160816;
        b=DZBuK/MBT6raf4pxzD6uOJweleAePzLnSI7R91GsOl8CrIb8KMLUWlR30BG9h2FnYr
         AZkNwDNxL4nlkNvP4bQjq4gx8jrWm/48iZ4wksfsrVVmxAa+/A+B6SsOFfmyOizuRteH
         JPtes5DBdty8SDJXNWh9+1PzTNr3cde3ky2iDC+E0I6t2nx1JBW8AO01l3SwAkJoZSTh
         8ZG0L+0ju1nTdroKPYt2qKVXhFbNk1CTXS6NgFc3xFc+Edl9XSeFaFZW5poX9hgcgZ0d
         +mhfI1OxXqNu3lbSc9b5ep3wghbwlGvLRNm18qJBhmbdvcUADriMkD7U8/T9dzxLhnbV
         1Qzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=abYYEHNJJXsCK9xEzjjhn2BOAEkX0oOtIZ/c7rdmSQY=;
        b=NjUvLMiKi3F37sYRU84FAle2IdKEtPvfaFw0mrC+feB5L7MrCrdL2tsQ2w54zCEFeG
         1bOEx1TD6URrMLSduYfumFT3ujspNE8V2C6YdTjrhrC+/W3XqlDMyKcfVP7qPQ9W+RU8
         DNTAimT+obUgIvf7qC1eTPmIE0kaVJUcqzq8I4TdlC0EJUqkVTH1bHdYsuVgwtNEf1S2
         KQQ9owB5rf6gScu7RMHpj8+9973/3/u8o2U4AnA+3e75YqSwBul908FMZ7EftD6JLTU0
         uwOzXi9B7QKR9xvo6H5gp+LvNxRJGrHAanJxXF/yR1SgwPjrjS+Uq4dO3RaQTXOsoYYn
         Hi+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ShQlUJke;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id w20si884512plq.2.2021.09.14.11.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Sep 2021 11:00:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id bd1so364155oib.5
        for <kasan-dev@googlegroups.com>; Tue, 14 Sep 2021 11:00:16 -0700 (PDT)
X-Received: by 2002:aca:1109:: with SMTP id 9mr2342557oir.109.1631642415672;
 Tue, 14 Sep 2021 11:00:15 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000eaacf005ca975d1a@google.com> <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx>
In-Reply-To: <87v933b3wf.ffs@tglx>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Sep 2021 20:00:04 +0200
Message-ID: <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Hillf Danton <hdanton@sina.com>, 
	syzbot <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>, 
	linux-kernel@vger.kernel.org, paulmck@kernel.org, 
	syzkaller-bugs@googlegroups.com, Peter Zijlstra <peterz@infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ShQlUJke;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f
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

On Tue, 14 Sept 2021 at 16:58, Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Tue, Sep 14 2021 at 20:37, Hillf Danton wrote:
>
> > On Mon, 13 Sep 2021 12:28:14 +0200 Thomas Gleixner wrote:
> >>On Tue, Aug 31 2021 at 15:45, Hillf Danton wrote:
> >>> On Mon, 30 Aug 2021 12:58:58 +0200 Dmitry Vyukov wrote:
> >>>>>  ieee80211_iterate_active_interfaces_atomic+0x70/0x180 net/mac80211/util.c:829
> >>>>>  mac80211_hwsim_beacon+0xd5/0x1a0 drivers/net/wireless/mac80211_hwsim.c:1861
> >>>>>  __run_hrtimer kernel/time/hrtimer.c:1537 [inline]
> >>>>>  __hrtimer_run_queues+0x609/0xe50 kernel/time/hrtimer.c:1601
> >>>>>  hrtimer_run_softirq+0x17b/0x360 kernel/time/hrtimer.c:1618
> >>>>>  __do_softirq+0x29b/0x9c2 kernel/softirq.c:558
> >>>
> >>> Add debug info only to help kasan catch the timer running longer than 2 ticks.
> >>>
> >>> Is it anything in the right direction, tglx?
> >>
> >>Not really. As Dmitry pointed out this seems to be related to
> >
> > Thanks for taking a look.
> >
> >>mac80211_hwsim and if you look at the above stacktrace then how is
> >>adding something to the timer wheel helpful?
> >
> > Given the stall was printed on CPU1 while the supposedly offending timer was
> > expiring on CPU0, what was proposed is the lame debug info only for kasan to
> > catch the timer red handed.
> >
> > It is more appreciated if the tglx dude would likely spend a couple of minutes
> > giving us a lesson on the expertises needed for collecting evidence that any
> > timer runs longer than two ticks. It helps beyond the extent of kasan.
>
> That tglx dude already picked the relevant part of the stack trace (see
> also above):
>
> >>>>>  ieee80211_iterate_active_interfaces_atomic+0x70/0x180 net/mac80211/util.c:829
> >>>>>  mac80211_hwsim_beacon+0xd5/0x1a0 drivers/net/wireless/mac80211_hwsim.c:1861
> >>>>>  __run_hrtimer kernel/time/hrtimer.c:1537 [inline]
> >>>>>  __hrtimer_run_queues+0x609/0xe50 kernel/time/hrtimer.c:1601
> >>>>>  hrtimer_run_softirq+0x17b/0x360 kernel/time/hrtimer.c:1618
> >>>>>  __do_softirq+0x29b/0x9c2 kernel/softirq.c:558
>
> and then asked the question how a timer wheel timer runtime check
> helps. He just omitted the appendix "if the timer in question is a
> hrtimer" as he assumed that this is pretty obvious from the stack trace.
>
> Aside of that if the wireless timer callback runs in an endless loop,
> what is a runtime detection of that in the hrtimer softirq invocation
> helping to decode the problem if the stall detector catches it when it
> hangs there?
>
> Now that mac80211 hrtimer callback might actually be not the real
> problem. It's certainly containing a bunch of loops, but I couldn't find
> an endless loop there during a cursory inspection.
>
> But that callback does rearm the hrtimer and that made me look at
> hrtimer_run_queues() which might be the reason for the endless loop as
> it only terminates when there is no timer to expire anymore.
>
> Now what happens when the mac80211 callback rearms the timer so it
> expires immediately again:
>
>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
>
> bcn is a user space controlled value. Now lets assume that bcn_int is <=1,
> which would certainly cause the loop in hrtimer_run_queues() to keeping
> looping forever.
>
> That should be easy to verify by implementing a simple test which
> reschedules a hrtimer from the callback with a expiry time close to now.
>
> Not today as I'm about to head home to fire up the pizza oven.

This question definitely shouldn't take priority over the pizza. But I
think I saw this "rearm a timer with a user-controlled value without
any checks" pattern lots of times and hangs are inherently harder to
localize and reproduce. So I wonder if it makes sense to add a debug
config that would catch such cases right when the timer is set up
(issue a WARNING)?
However, for automated testing there is the usual question of
balancing between false positives and false negatives. The check
should not produce false positives, but at the same time it should
catch [almost] all actual stalls so that they don't manifest as
duplicate stall reports.

If I understand it correctly the timer is not actually set up as
periodic, but rather each callback invocation arms it again. Setting
up a timer for 1 ns _once_ (or few times) is probably fine (right?),
so the check needs to be somewhat more elaborate and detect "infinite"
rearming.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYd3pEfZhRUQS9ymW%2BsQZ4O58Dz714xSqoZvdKa_9s2oQ%40mail.gmail.com.
