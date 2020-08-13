Return-Path: <kasan-dev+bncBDGPTM5BQUDRBPPN2T4QKGQE2G2ZXFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F6492439FE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 14:49:03 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id y13sf4280601pfp.5
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 05:49:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597322942; cv=pass;
        d=google.com; s=arc-20160816;
        b=blESysNq0gvV8DuW9BJzqXeZl6ntWdR0LTc2CCh+pyM00H3NNxYPpMeGxEts6hB6Ay
         2RVkYqvIWibMnn2fHVIHWM9Uj+lTVDxnMA+96s48eB2Stc4HansACIpuP+vqaU1BNQix
         Me3TT8ieYObCx5xrgXn18cosBpI+nIzrYDrJxEClhWbXzLD8PAvDE1rjlkaef3R18XmA
         izH7O0S03iJH0dOP9FD35yIA874i4d27PhTKJj55xNQt8ewMbo4x6eaKkUOmDf9grvFP
         5t3oOdr8nk87+ywiCLIwku9MGOWVT+e7QeCeBHfG5TJxJjW7IY7oYX2Ak7GdM5pE5niV
         E0sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=w7kghWgVv4AiJ9Azq1nH/dDHciAyP5p/48pptHi5dS0=;
        b=KI35bDkFuDvhsnkpcF29vk7j4OLcPhPhSg2JIRJGtKTu3UdXQiThLyBrw3z/v9caHf
         Q0f26S3//j9/Dv7m3ukFRpbSG0s91v1sXueXt3DD676LhVU4BEMFNqOtR5g/mVsTGEWU
         y0YtYbwTtZmcSBgcHpYs1NYu1ca6Ht+640Udh1x/2xJDPBIV9RUPNyv7eRNty0s8krGX
         M8Id/mvai8i47MbMgTp38N6MlMrJrdpK7P6VS72bXtHBZEBv1avzN3N/H7B5gHSFR2Dk
         Ro8Jf7ckOfzrI4RTPdyX177wK9ZqDF8KThilADmcDhdBGNFzWqytoK9KCqyGrvHI4juh
         1NrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BOIL1Rth;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w7kghWgVv4AiJ9Azq1nH/dDHciAyP5p/48pptHi5dS0=;
        b=Ei+uHQsSXBis017TqQYSZst0SfCoLV7Q4gMeyjz9nyctYYUXBucKWH0LTEhO4D3suf
         0wusJiuCmGo0Ua73qe/lSi1uaNpMms4a4cn/Mqq2Fi7BHGQIbH5BNot8kkqcZ986MfmW
         3vTUoF1TDkZ5rbkOhFLm1IIsBeQ9GJW9tLAowp95r67ghzlmhAGANUVBHSZACXpf08sp
         fd16qAxFZ3CW0nh4QeRhau7XlMwGR6ZbMivmtckbgTZdRp85UCQ1MLnmF61LuWm9zQ74
         RO3ozECtMVCu6Olzr6ISw2yg4pdS8tS+xQ2t//1EpYoOPWGRoJ1LRITzq49DDjBbk8Il
         +DRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w7kghWgVv4AiJ9Azq1nH/dDHciAyP5p/48pptHi5dS0=;
        b=iHzUIwLCi5zaQ+XgbFhAbQOC+V6OMDzcX/WiKm6rCm57L6RXfsLehR1EXS34cYlblF
         J2foNl+g0qqBpVO3tfDCWwfEQ6lPAhd4woKCeyOhG6Xq1rI8BkbYbHg11TC1lA7gMG2Q
         OihCTNNHhcWybh2sRfr7ApA3GsKu0cgj9qlg84och98bPBupec7MKSZp9aJHLb/2ppIH
         ixVxK0yObVKvhOlISLWQaB4Q/Aegm+0ogaiyDwRQupFlgbXsaIT2AQiWiLTq34fnTiBB
         MKblhwzVYf9cKq3wR3LVbKS6Gyf6Pn3pZ+oaACU/DileNjxwJjWA/ic2Z4aWcUpyPW3x
         o+gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532776BbplDE4F1iYFInUZ/SloKLHi8eBxAJ3hHjHUcrxVsiZybm
	6ztrqzromD/WZEFfJ9Z6G3Q=
X-Google-Smtp-Source: ABdhPJw5AKc9j+/LhkrBTJC7J4Ygdfvu8fiJAzTM00mh/qJAfTWGpePjSneMPS1GxIR+ykuEOO0+Vw==
X-Received: by 2002:a62:7f06:: with SMTP id a6mr1201741pfd.300.1597322942013;
        Thu, 13 Aug 2020 05:49:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:720b:: with SMTP id ba11ls2279749plb.0.gmail; Thu,
 13 Aug 2020 05:49:01 -0700 (PDT)
X-Received: by 2002:a17:90a:ea83:: with SMTP id h3mr5263952pjz.170.1597322941474;
        Thu, 13 Aug 2020 05:49:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597322941; cv=none;
        d=google.com; s=arc-20160816;
        b=plmpnYvXGx8pU6G+gnabt6w817g5sHzVcR7EVksKfahsx/PzZnmykN+t2PfZVot+0h
         5xv4YNXMTCCrcgUw6IiVB7CNsS3dwnqWSbuvdSML5xQqWxQ+LZYnT2wjt77s6TqHntZs
         DMD46Vbg/rt0QJxgcf+bm0NzJNd6HKFwVd3tJiwiejClC/cMZLRl7wHEYpDXFU1oG9Js
         8Vc9BTX9WwyH1+a6ZcS4UWOUgw01WEyas2ljUjH7VXNTLQn3lQjs3Ul+kxskdMFK6Dx9
         ovx76srBhv809UEkUOf1GAf9U/37l9A/87YA6IL54gDzP4VNQpkLhJedhocIifYeHDRf
         kjtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=aaE6HcSMNBLCW8HhXQtINfxBXNzqkMSqUtGQrGAVPSM=;
        b=qDDVyF4175OWpp8gL1RYK7DqkVKyzOzBK+FaDRSip+ju4E5d/BnEtoTwnUWSp4vZ6p
         juyJh7diMgYDmVeXWuv9OPjwhoiqZEGN2RxrUnzgLMtg8M0m6x3zZ4LDxjeIuSgTDxCp
         St5dx9MwxXP5XvrFfMrqnIZp1pIgkApaW1qw3MK8EmBIPi2PEH+7EmcPtjCvP2+Qoc/B
         9cqskv8SPygNumu1AaFPk3g7v5xSNz4dsLV8meqwchYjOjNhtYsSAjuaQK/ESiLIlcFe
         ccc/4vRJdBv4xZtYOJwosiKLr+8m3LSzrihwv57R3xJE3UhWYMzE6xVFafmpWgfNwlBb
         +ExA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BOIL1Rth;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s76si229092pfc.1.2020.08.13.05.49.00
        for <kasan-dev@googlegroups.com>;
        Thu, 13 Aug 2020 05:49:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: f4c7400723df461b99ba43db2a1c039f-20200813
X-UUID: f4c7400723df461b99ba43db2a1c039f-20200813
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 388844126; Thu, 13 Aug 2020 20:48:58 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 13 Aug 2020 20:48:55 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 13 Aug 2020 20:48:57 +0800
Message-ID: <1597322937.9999.42.camel@mtksdccf07>
Subject: Re: [PATCH 1/5] timer: kasan: record and print timer stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Thomas Gleixner <tglx@linutronix.de>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, "Stephen
 Boyd" <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Thu, 13 Aug 2020 20:48:57 +0800
In-Reply-To: <87d03ulqbp.fsf@nanos.tec.linutronix.de>
References: <20200810072313.529-1-walter-zh.wu@mediatek.com>
	 <87d03ulqbp.fsf@nanos.tec.linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=BOIL1Rth;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Hi Thomas,

Please ignore my previous mail. Thanks.


On Thu, 2020-08-13 at 13:48 +0200, Thomas Gleixner wrote:
> Walter,
> 
> Walter Wu <walter-zh.wu@mediatek.com> writes:
> > This patch records the last two timer queueing stacks and prints
> 
> "This patch" is useless information as we already know from the subject
> line that this is a patch.
> 
> git grep 'This patch' Documentation/process/
> 

Thanks for your information.

> > up to 2 timer stacks in KASAN report. It is useful for programmers
> > to solve use-after-free or double-free memory timer issues.
> >
> > When timer_setup() or timer_setup_on_stack() is called, then it
> > prepares to use this timer and sets timer callback, we store
> > this call stack in order to print it in KASAN report.
> 
> we store nothing. Don't impersonate code please.
> 
> Also please structure the changelog in a way that it's easy to
> understand what this is about instead of telling first what the patch
> does and then some half baken information why this is useful followed by
> more information about what it does.
> 
> Something like this:
> 
>   For analysing use after free or double free of objects it is helpful
>   to preserve usage history which potentially gives a hint about the
>   affected code.
> 
>   For timers it has turned out to be useful to record the stack trace
>   of the timer init call. <ADD technical explanation why this is useful>
>  
>   Record the most recent two timer init calls in KASAN which are printed
>   on failure in the KASAN report.
> 
> See, this gives a clear context, an explanation why it is useful and a
> high level description of what it does. The details are in the patch
> ifself and do not have to be epxlained in the changelog.
> 

Thanks for your explanation, Our patch will use this as a template from
now on.

> For the technical explanation which you need to add, you really need to
> tell what's the advantage or additional coverage vs. existing debug
> facilities like debugobjects. Just claiming that it's useful does not
> make an argument.
> 

We originally wanted him to have similar functions. Maybe he can't
completely replace, but KASAN can ave this ability.

> The UAF problem with timers is nasty because if you free an active timer
> then either the softirq which expires the timer will corrupt potentially
> reused memory or the reuse will corrupt the linked list which makes the
> softirq or some unrelated code which adds/removes a different timer
> explode in undebuggable ways. debugobject prevents that because it
> tracks per timer state and invokes the fixup function which keeps the
> system alive and also tells you exactly where the free of the active
> object happens which is the really interesting place to look at. The
> init function is pretty uninteresting in that case because you really
> want to know where the freeing of the active object happens.
> 
> So if KASAN detects UAF in the timer softirq then the init trace is not
> giving any information especially not in cases where the timer is part
> of a common and frequently allocated/freed other data structure.
> 

I don't have experience using this tool, but I will survey it.

> >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> >  static inline void kasan_record_aux_stack(void *ptr) {}
> > +static inline void kasan_record_tmr_stack(void *ptr) {}
> 
> Duh, so you are adding per object type functions and storage? That's
> going to be a huge copy and pasta orgy as every object requires the same
> code and extra storage space.
> 
> Why not just using kasan_record_aux_stack() for all of this?
> 
> The 'call_rcu' 'timer' 'whatever next' printout is not really required
> because the stack trace already tells you the function which was
> invoked. If TOS is call_rcu() or do_timer_init() then it's entirely
> clear which object is affected. If the two aux records are not enough
> then making the array larger is not the end of the world.
> 

My previous mail say that we will re-use kasan_record_aux_stack() and
only have aux_stack.

> >  #endif /* CONFIG_KASAN_GENERIC */
> >  
> > diff --git a/kernel/time/timer.c b/kernel/time/timer.c
> > index a5221abb4594..ef2da9ddfac7 100644
> > --- a/kernel/time/timer.c
> > +++ b/kernel/time/timer.c
> > @@ -783,6 +783,8 @@ static void do_init_timer(struct timer_list *timer,
> >  	timer->function = func;
> >  	timer->flags = flags | raw_smp_processor_id();
> >  	lockdep_init_map(&timer->lockdep_map, name, key, 0);
> > +
> > +	kasan_record_tmr_stack(timer);
> >  }
> 
> Are you sure this is correct for all timers?
> 
> This is also called for timers which are temporarily allocated on stack
> and for timers which are statically allocated at compile time. How is
> that supposed to work?
> 

If I understand correctly, KASAN report have this record only for slub
variable. So what you said shouldn't be a problem.

> These kind of things want to be explained upfront an not left to the
> reviewer as an exercise.
> 

Sorry, My fault. Later we will be more cautious to send patch.

> Thanks,
> 
>         tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1597322937.9999.42.camel%40mtksdccf07.
