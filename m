Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP557SVAMGQELZFEYMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D750D7F5B84
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 10:43:28 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35aae217e57sf6256185ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 01:43:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700732607; cv=pass;
        d=google.com; s=arc-20160816;
        b=JiPHIpPUtrvssu3Y0Lo/1yEV8XFz2ZQoUmv4g2VThKN64SCSqdJvfpKucDTBGP6sai
         Be4l4FvPMZwLoW69NjS4b4GZw9spDzUInHRu9Dt9cIBLwZjadiDECEc/Cd5dQJXmsIMQ
         g+UQFjSxPntYiDZZNFqzoEL0ks/0tAsJNNxXnen/nY1E7FNuiYlGRyIDfRLwLMuLlwFX
         f08sWuhkqdrkbmUg7l7FZZHz6LG5b+fAM1VbdRZ5Pv6g6pyg+9iWUgExtXPYOiDVB7dt
         A7638iM2abnDsZk3hvajvtV0Fb+dLF1gkIZbr/pOhtuNu+UR4sjglrMI0ddR9/a7XJj/
         YgBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/kLZAK7vD5baL9ypr86M8p1zQbS3cMO3doIZZl4tRwc=;
        fh=LubqLcB7navSDf0Nt52CtUnJ6CDCRU0TM1wxMFuJtiQ=;
        b=X4Z6l0412SZczvIBM4AoRhxR/adIYHdGJU50Zneiu9mgRiT4racrtp9WUeYVrXoSKF
         FEC47tbqjnC7i0JerLgTudds6juEIYNZwrKd1xDJeigBSTJwxuvNxvyf9boPmuhOgo9G
         Vd2FcMvkj8q4/8uQqRvPHpwuba7vqxPIbgndSWeF31bdzFzVQCiZjldWIXpP9NQTI/IY
         Bz7U/R6wslhj7ELR+aBZh1yGsYX9B+QVFlzv9v9gZ+j+ZYcE50rVxcROhTflrWDmy791
         Zej5807u0jM0+1RynfjzVKYKdvia6b7sM2oWYhayeM9DUPKv8NfrocLkEPS8/s2+XUVI
         t4Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ghIe3CNi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700732607; x=1701337407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/kLZAK7vD5baL9ypr86M8p1zQbS3cMO3doIZZl4tRwc=;
        b=LSngvYWQmJzEWKO/7kp+HDBnMyYyRjg/SrBnJdZHOfZHTNPDv+kFRhzyBK5U6Tq0ib
         zIQCWdelVI4mQWuW2RZyKRXK8MnGGBPsTCp6NSFsFkJ4gdwlBKME6jC9rGtZSV1bZ0dg
         ZHPoJJafPB5PHto7GeZhJdB3yL0EZqADlXjAKv2SI2cHBhbTB/1BHcq8Wjpij4LrbWSx
         xhEkkfacgWIW7iO9E+1b9TuZe7T6nSm71nDoiiI3gvGxjxRDOZfEzFyaYIaIHrl0Ejvq
         4tkFZjWrnp8tm37BDGn9aKKPL2lQJhyHUteKAgyXgJ20LOcbNlU/v5zWjhIN1rrbX1at
         vfng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700732607; x=1701337407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/kLZAK7vD5baL9ypr86M8p1zQbS3cMO3doIZZl4tRwc=;
        b=QhUVSJ1XKKeeP0vmZsMyuw/i13vpev3oKHFLD73fAY1GRWEiLn2tY6y2FnYB/RGEBi
         cu2vM+Fkk3KQ0kGq/9k+cSHQ/YzaFiNxGf+UAfDBqwv1bV0FJNBxQNjDmnWSIej7ir0W
         pjfJAcYqq3+Te3cZ7SJKvs20co6dyQsedY0zR4KyNQ5OB38pIq9rvUBg5F4m+7ZmQQ1i
         acJRWYqhaSYfYWSZEurNIon+69O8EYympqTc6zAWw40SmvqTfdQdWXav0S+4tmgNOHNP
         Xre6TQVWuUwDWa1Q7sz+I4h7w5gplVaxRxmsI00IGspvVUgeFVjaz/Ahb4wYPnRTmj2e
         Bk9w==
X-Gm-Message-State: AOJu0YyWv3aT9QdO3CMMAVj6aQrGxCVpgD5xWkmuPi7BWdWOu9iXbFUZ
	DwZKWqtlDZ/ER60NqzDsHAVueg==
X-Google-Smtp-Source: AGHT+IFiR/RTIicWaXRVTl/Ij6ERmfU9Xml8vbylGTWvAoBzGebm37FPOKrE3TUEY7YM9c9YJfqibg==
X-Received: by 2002:a92:d6cb:0:b0:35b:112e:60d2 with SMTP id z11-20020a92d6cb000000b0035b112e60d2mr4872469ilp.22.1700732607690;
        Thu, 23 Nov 2023 01:43:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3711:b0:359:3c28:e053 with SMTP id
 ck17-20020a056e02371100b003593c28e053ls29502ilb.1.-pod-prod-07-us; Thu, 23
 Nov 2023 01:43:26 -0800 (PST)
X-Received: by 2002:a05:6602:489a:b0:79f:9574:b93c with SMTP id ee26-20020a056602489a00b0079f9574b93cmr6117168iob.0.1700732606659;
        Thu, 23 Nov 2023 01:43:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700732606; cv=none;
        d=google.com; s=arc-20160816;
        b=ktCMOXWqQhH+uZQ5miizQBEI9w+jjbKFimk9KH8yKIFwU/8o91pv2IQy1DNT8mwGrE
         Do+NwQh6nbSPJaGO1w//j4dFnKRNMEZEa1HybKcs0HhIftfPtvbiEx2/lyaKV0JdxGSb
         BiHDTqQXboIBDRVMh2WYtrCXBFbXBh/+jjsE7U8LejIarHCJgxgpTFV/qPor3FyFyQg+
         y/hBipBREp87z/IyOT6SuNrLuyzBPE+AmHLGBaiSgFuThgtjaQPDirLo+Ij/JxJCWBPK
         2e6x0gFuBzBngdEayfobRhwpAFxGPUlZphoW5w8wMl3bcGIHrC7MSov56hhiJmgloIUd
         gvGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lryrEVp0pcZo60SdyGtopQxDXDiRzsB0TNAuuSGzQ+0=;
        fh=LubqLcB7navSDf0Nt52CtUnJ6CDCRU0TM1wxMFuJtiQ=;
        b=pcb3Pkw10Y48bOreu4uWsdJOAfreiLrhzmXq3lEHuoRNg20wAz1b5WP0b5Dj7dvv0d
         Rg1n6AftoYtyi4hfy5JOEbFmQOVw7r9zdz0dcvOOgJSCBN1eoKAcg2G2G1uKhnUwrObt
         EAGNlCCQeYQseHDMsXlhiIA/zFxFXGSkGhlNzThuUD6UdYevacLsWgQ1bxnIHuPoevjP
         skTJViV2QCHBtPEnJip790xs4R//XS7mAZobCKsGnfXU6BOT6IRPZ4vpdfbx0FhKdJhR
         FxSVD2HHffSsZnL+QfAR+aD8gUJy/rGdCVV0J0N4hNSbyAYMlIGG38hlKIDnnzjQVgDg
         gKmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ghIe3CNi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2f.google.com (mail-vs1-xe2f.google.com. [2607:f8b0:4864:20::e2f])
        by gmr-mx.google.com with ESMTPS id n3-20020a056602340300b007b00d2ec6eesi43914ioz.1.2023.11.23.01.43.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 01:43:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as permitted sender) client-ip=2607:f8b0:4864:20::e2f;
Received: by mail-vs1-xe2f.google.com with SMTP id ada2fe7eead31-462a1a2717aso228791137.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 01:43:26 -0800 (PST)
X-Received: by 2002:a05:6102:1004:b0:45d:aa3e:a78 with SMTP id
 q4-20020a056102100400b0045daa3e0a78mr5613596vsp.10.1700732605928; Thu, 23 Nov
 2023 01:43:25 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752A2F21C050D701945B62799BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CANpmjNPvDhyEcc0DdxrL8hVd0rZ-J4k95R5M5AwoeSotg-HCVg@mail.gmail.com>
 <VI1P193MB0752E3CA6B2660860BD3923D99BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CANpmjNMejg7ekEhuuwdxpzOk5-mO+xn+qEL1qmx8ZVQG9bz_XA@mail.gmail.com> <VI1P193MB0752D8881930F88BACFB56A499B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752D8881930F88BACFB56A499B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Nov 2023 10:42:48 +0100
Message-ID: <CANpmjNNHe7YnA_n_Ek4_NJuq99jOH5PJfWtAkc5u8fMNJpFOSA@mail.gmail.com>
Subject: Re: [PATCH] kfence: Replace local_clock() with ktime_get_boot_fast_ns()
To: Juntong Deng <juntong.deng@outlook.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ghIe3CNi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as
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

On Thu, 23 Nov 2023 at 10:29, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> On 2023/11/23 6:19, Marco Elver wrote:
> > On Wed, 22 Nov 2023 at 22:36, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>
> >> On 2023/11/23 4:35, Marco Elver wrote:
> >>> On Wed, 22 Nov 2023 at 21:01, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>>>
> >>>> The time obtained by local_clock() is the local CPU time, which may
> >>>> drift between CPUs and is not suitable for comparison across CPUs.
> >>>>
> >>>> It is possible for allocation and free to occur on different CPUs,
> >>>> and using local_clock() to record timestamps may cause confusion.
> >>>
> >>> The same problem exists with printk logging.
> >>>
> >>>> ktime_get_boot_fast_ns() is based on clock sources and can be used
> >>>> reliably and accurately for comparison across CPUs.
> >>>
> >>> You may be right here, however, the choice of local_clock() was
> >>> deliberate: it's the same timestamp source that printk uses.
> >>>
> >>> Also, on systems where there is drift, the arch selects
> >>> CONFIG_HAVE_UNSTABLE_SCHED_CLOCK (like on x86) and the drift is
> >>> generally bounded.
> >>>
> >>>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> >>>> ---
> >>>>    mm/kfence/core.c | 2 +-
> >>>>    1 file changed, 1 insertion(+), 1 deletion(-)
> >>>>
> >>>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> >>>> index 3872528d0963..041c03394193 100644
> >>>> --- a/mm/kfence/core.c
> >>>> +++ b/mm/kfence/core.c
> >>>> @@ -295,7 +295,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
> >>>>           track->num_stack_entries = num_stack_entries;
> >>>>           track->pid = task_pid_nr(current);
> >>>>           track->cpu = raw_smp_processor_id();
> >>>> -       track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
> >>>> +       track->ts_nsec = ktime_get_boot_fast_ns();
> >>>
> >>> You have ignored the comment placed here - now it's no longer the same
> >>> source as printk timestamps. I think not being able to correlate
> >>> information from KFENCE reports with timestamps in lines from printk
> >>> is worse.
> >>>
> >>> For now, I have to Nack: Unless you can prove that
> >>> ktime_get_boot_fast_ns() can still be correlated with timestamps from
> >>> printk timestamps, I think this change only trades one problem for
> >>> another.
> >>>
> >>> Thanks,
> >>> -- Marco
> >>
> >> Honestly, the possibility of accurately matching a message in the printk
> >> log by the timestamp in the kfence report is very low, since allocation
> >> and free do not directly correspond to a certain event.
> >
> > It's about being able to compare the timestamps. I don't want to match
> > an exact event, but be able to figure out which event happened
> > before/after an allocation or free, i.e. the logical ordering of
> > events.
> >
> > With CONFIG_PRINTK_CALLER we can see the CPU ID in printk lines and
> > are therefore able to accurately compare printk lines with information
> > given by KFENCE alloc/free info.
> >
>
>
> That makes sense.
>
>
> >> Since time drifts across CPUs, timestamps may be different even if
> >> allocation and free can correspond to a certain event.
> >
> > This is not a problem with CONFIG_PRINTK_CALLER.
> >
> >> If we really need to find the relevant printk logs by the timestamps in
> >> the kfence report, all we can do is to look for messages that are within
> >> a certain time range.
> >>
> >> If we are looking for messages in a certain time range, there is not
> >> much difference between local_clock() and ktime_get_boot_fast_ns().
> >>
> >> Also, this patch is in preparation for my next patch.
> >>
> >> My next patch is to show the PID, CPU number, and timestamp when the
> >> error occurred, in this case time drift from different CPUs can
> >> cause confusion.
> >
> > It's not quite clear how there's a dependency between this patch and a
> > later patch, but generally it's good practice to send related patches
> > as a patch series. That way it's easier to see what the overall
> > changes are and provide feedback as a whole - as is, it's difficult to
> > provide feedback.
> >
> > However, from what you say this information is already given.
> > dump_stack_print_info() shows this - e.g this bit here is printed by
> > where the error occurred:
> >
> > | CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
> > | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2
> > 04/01/2014
> >
> > And if the printk log has timestamps, then these lines are prefixed
> > with the timestamp where the error occurred.
> >
>
>
> Thanks, I found that information.
>
> Since this information is at the bottom of the report, I had previously
> ignored them.
>
> I would suggest considering moving this information to the top of
> the report, for example
>
> BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa6/0x234
>
> CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2
> 04/01/2014
>
> Out-of-bounds read at 0xffff8c3f2e291fff (1B left of kfence-#72):
> ...
>
> This more clearly correlates this information with the occurrence of
> the error.

Most kernel warnings/bugs/etc. show this information at the bottom of
the report, hence KFENCE also showing it there. If you look at
kfence_report_error() where it prints this info, there is a mode where
KFENCE also dumps all registers via show_regs(). show_regs() itself
displays this information at the bottom as well, but showing a dump of
registers at the start of the KFENCE report is pretty distracting and
looks ugly.

The placement of this information is not the best, but at the same
time I found it to be the least bad compromise (when also considering
the mode where it dumps registers). We could of course untangle some
of these functions and e.g. have a show_regs() version that doesn't
show that info, but I find that to add more interfaces to the kernel
with unclear gains - overall probably not worth the time effort.

At least that's the reasoning for why things are the way they are
today. If there is an easier way I missed, any clear improvements are
of course welcome.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNHe7YnA_n_Ek4_NJuq99jOH5PJfWtAkc5u8fMNJpFOSA%40mail.gmail.com.
