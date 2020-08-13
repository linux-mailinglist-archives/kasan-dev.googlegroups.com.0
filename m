Return-Path: <kasan-dev+bncBDAMN6NI5EERB7GQ2T4QKGQEIT4UK3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A9E7424397A
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 13:48:12 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id j2sf1994371wrr.14
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 04:48:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597319292; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDIyCrUloogAzi9WebS/5U7dKYjFyOaXqWWcBlnAi2PPjSfmkZnPzyQiuV2xUNke6I
         ynC2qfCOLfIiALEk2rSGW0biZ5aCEhkdGbrcqy3lVwJgmN8945ZewdkRUch1Za4g9oiz
         ir+Ew7TRlH1CTUoMQj6yWWNPm5bEDeoZg7Y3KLd4CQrYoYciXUN2uq9JGE0I1QOeOVQi
         A2b0MloO2iSk83hDOROCXkp13HEeR6ZvlV4pBNuRTD4JMJUqbApD4rtlKRQyp/fx8npw
         a4q3jSiEAMq6gEGFeNVRHqgr9hxljxXL7x3XvKOCiPKAVPy+XQpAhdu+1P1Ts+ZdNP8m
         RdcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=UsJGh3iFBjuv1B/9S6mBO5dhz11uVs4Jir4I6a7NNCI=;
        b=CoNKa1ZLO+ZaD/wix9UPew3YmkyFv0uio5HoVh/r2IQdmbVdI1VuVsqQrT0j3kXN62
         HLjH8k04Qc0LGOJg3ID4suVrQhaKnivhVoyjB6oGmBWoKeR/HYaQHXvKN0rkvSwikC/y
         nJ+39/a78GxsYWcj0f4SRFoXx7j7NpwP5R/tn3B3sX/qVh+f8lV0+e7gNjCM9y0brFRA
         l6sx37X0eq7wkjlx1r3XnN8aaob7qXdnqTzUC61HEDJ7lO+1hc+NXF/9/ilSYyVF0y0U
         hWZKn3DcrKUS8Hu1KY0KM8CLOwItdeqrDGJlDH/JHdXCCw9dwkzbKGwMBk1K4lGjOJlL
         OptA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=19xIPU0M;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=aHunRBTH;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UsJGh3iFBjuv1B/9S6mBO5dhz11uVs4Jir4I6a7NNCI=;
        b=Y2xfHvwK2qQQ4WFth+FXik/1KCRekgLa64SBksTomuEn85AhplF51A/liPHtqfTp1X
         Kn3cbkcHXzPPBg/KtPBhsfCLZ9Sq+nXi6zsUXhvDsl+2nDht8KmeejvQsLwGA7/H8wni
         WXnvo2FOFMNEyE8ycDeYAUg1bIWCSUkyMoAxlFe6SZW4PeMzYq05LcQzDBHbALFoZGr/
         hHZv4Tao+xRkljWtr30K2pJCXBzvqMe7RcmGriz6YMDthspy454zLDlF9ATWUaHEAeoh
         SGDprLaQJIHP2Gz/UH2LL9cm8mRy2FVMxHl60v0ITh2Vo1wwEyjJnCW4zej0fr9YY944
         T3Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UsJGh3iFBjuv1B/9S6mBO5dhz11uVs4Jir4I6a7NNCI=;
        b=IPnDzu3MIYsyp7k+Bi+AVosRTu0tLEeL8KKFueejvn2nd/yDvVgixYrBFuDBg7YojM
         2TMKYZepmn/jNlB69jGvTCMLnOToGCJZdexsS6WfWDfCH0rmP+J0uyoUbDH8Kk9Aatx+
         C+sFfNaB2r+wdECCht6qg1IASW7SWBHRjmm9U+eJ4uYJnACB4JGy41KFzHHIce4zePqN
         LGk86iSRv0g0Y1seP51kz91sEAeGBY9YooGNMPb3JdO+lXVH/wuJ92j1ghnscsZaakZ/
         mQSQebG1aOQMQObWoQYiJee1LYkHeig6TJ7pqNMZjnyVMxC1V56kC3AvwBfY0OT4olwB
         wDZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n3CJCzEYwXV+d4k648hEjtjJUU0IcbeWDpOd808V/rmNZOtHp
	qOT/8lnzH3535nGqj07IvAs=
X-Google-Smtp-Source: ABdhPJxic7SAGMHWECaOAUE66lQsJEmI9+iV2V+P8OytHwr0ed0YfgaH0PQ07EGNcALLWsjxyHMgKw==
X-Received: by 2002:adf:ea85:: with SMTP id s5mr3992654wrm.55.1597319292361;
        Thu, 13 Aug 2020 04:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:804f:: with SMTP id b76ls2423615wmd.2.gmail; Thu, 13 Aug
 2020 04:48:11 -0700 (PDT)
X-Received: by 2002:a1c:9a02:: with SMTP id c2mr4415803wme.16.1597319291865;
        Thu, 13 Aug 2020 04:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597319291; cv=none;
        d=google.com; s=arc-20160816;
        b=0qRGHa2iBJmGmgfcFWKaJ95s0DzMBhArCKxtuZXeDoVd5VGaUaYtDTtyuzCOySWKVE
         7WX0VzTq6vdfWkzlGJY9YwXglp25bDZQEI2qEtVOdF59qwdstNroHmRwYyw/PjYekxLg
         yBazLWGDhACHUVykcMsHZhJ+9BbhDiTLSmkJy61jVasagV0LD6hvmj0oIxvUCsWgKMBR
         eIPsQhMetd6TtyGGYT7JaVTRI2J74iMd8HjbU0qVdtP7xzG3Lh7lM1SyBJOd8NAgzev3
         EqL7Mqbekdas5Z/K2uvAeWdQ8nTQC8FQkt1sh/L+VSUjRTzaIF0FfmieV2oT3aASYp93
         s5EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=ZlgM8Obqrq40lXXZU4JOaZIlny7V1P2EsiDmKMcB++g=;
        b=F1M+Sm2fKWjx0OS7oFDqS8kHG1aLQaccpV78gKPWIiW6+zlsdve7CrbzFdXJW+8Bly
         +GdP5nowbCX3ciY+04vvAX6B2qa2JuIMzO80VJSJGEwhjANNqMG5Mn8cXboZrWlAbOf0
         d0vIIdM2fIdlM/mgLTqU96LaNqNY+NANzGKMt445QDdwkxmC0Kkusxi0zvFT2xa5KC8y
         kOwKTI+DSRKg/in5x6UQz/bH+dY/egRqCX0PWHPdoeIo/hgrFKVPel2qeLKAB5XWrTxt
         5ITDNBzYZV0suh9UGMnbh/Hpnw+sDmO/Ne6pXTJg6PmPzDRLWYtHIaSbxnuQ+zMF5IeE
         rU/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=19xIPU0M;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=aHunRBTH;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id o134si197784wme.0.2020.08.13.04.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2020 04:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH 1/5] timer: kasan: record and print timer stack
In-Reply-To: <20200810072313.529-1-walter-zh.wu@mediatek.com>
References: <20200810072313.529-1-walter-zh.wu@mediatek.com>
Date: Thu, 13 Aug 2020 13:48:10 +0200
Message-ID: <87d03ulqbp.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=19xIPU0M;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=aHunRBTH;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

Walter,

Walter Wu <walter-zh.wu@mediatek.com> writes:
> This patch records the last two timer queueing stacks and prints

"This patch" is useless information as we already know from the subject
line that this is a patch.

git grep 'This patch' Documentation/process/

> up to 2 timer stacks in KASAN report. It is useful for programmers
> to solve use-after-free or double-free memory timer issues.
>
> When timer_setup() or timer_setup_on_stack() is called, then it
> prepares to use this timer and sets timer callback, we store
> this call stack in order to print it in KASAN report.

we store nothing. Don't impersonate code please.

Also please structure the changelog in a way that it's easy to
understand what this is about instead of telling first what the patch
does and then some half baken information why this is useful followed by
more information about what it does.

Something like this:

  For analysing use after free or double free of objects it is helpful
  to preserve usage history which potentially gives a hint about the
  affected code.

  For timers it has turned out to be useful to record the stack trace
  of the timer init call. <ADD technical explanation why this is useful>
 
  Record the most recent two timer init calls in KASAN which are printed
  on failure in the KASAN report.

See, this gives a clear context, an explanation why it is useful and a
high level description of what it does. The details are in the patch
ifself and do not have to be epxlained in the changelog.

For the technical explanation which you need to add, you really need to
tell what's the advantage or additional coverage vs. existing debug
facilities like debugobjects. Just claiming that it's useful does not
make an argument.

The UAF problem with timers is nasty because if you free an active timer
then either the softirq which expires the timer will corrupt potentially
reused memory or the reuse will corrupt the linked list which makes the
softirq or some unrelated code which adds/removes a different timer
explode in undebuggable ways. debugobject prevents that because it
tracks per timer state and invokes the fixup function which keeps the
system alive and also tells you exactly where the free of the active
object happens which is the really interesting place to look at. The
init function is pretty uninteresting in that case because you really
want to know where the freeing of the active object happens.

So if KASAN detects UAF in the timer softirq then the init trace is not
giving any information especially not in cases where the timer is part
of a common and frequently allocated/freed other data structure.

>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>  static inline void kasan_record_aux_stack(void *ptr) {}
> +static inline void kasan_record_tmr_stack(void *ptr) {}

Duh, so you are adding per object type functions and storage? That's
going to be a huge copy and pasta orgy as every object requires the same
code and extra storage space.

Why not just using kasan_record_aux_stack() for all of this?

The 'call_rcu' 'timer' 'whatever next' printout is not really required
because the stack trace already tells you the function which was
invoked. If TOS is call_rcu() or do_timer_init() then it's entirely
clear which object is affected. If the two aux records are not enough
then making the array larger is not the end of the world.

>  #endif /* CONFIG_KASAN_GENERIC */
>  
> diff --git a/kernel/time/timer.c b/kernel/time/timer.c
> index a5221abb4594..ef2da9ddfac7 100644
> --- a/kernel/time/timer.c
> +++ b/kernel/time/timer.c
> @@ -783,6 +783,8 @@ static void do_init_timer(struct timer_list *timer,
>  	timer->function = func;
>  	timer->flags = flags | raw_smp_processor_id();
>  	lockdep_init_map(&timer->lockdep_map, name, key, 0);
> +
> +	kasan_record_tmr_stack(timer);
>  }

Are you sure this is correct for all timers?

This is also called for timers which are temporarily allocated on stack
and for timers which are statically allocated at compile time. How is
that supposed to work?

These kind of things want to be explained upfront an not left to the
reviewer as an exercise.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87d03ulqbp.fsf%40nanos.tec.linutronix.de.
