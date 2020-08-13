Return-Path: <kasan-dev+bncBDGPTM5BQUDRBWPC2T4QKGQED4ZLJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 03BEE2439C1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 14:26:03 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id cp23sf3991520pjb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 05:26:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597321561; cv=pass;
        d=google.com; s=arc-20160816;
        b=RL9Xiph/EM/I51GkkvrF3rhb2r3fyQ73OEGiFdDyvGC2sjmFlvQhJ0zlfILQgG3Yym
         wap6bH02pmqqijueAvtD1iSpD2w35VSAFHpjl9H/T4SXqXOP3hUzBSYwLnFSD8o+NyIL
         6eDJ1aHbnLg989WjYG5H89Vh0oLRr+cDVSq++KX2kdQ6JejAra0DdSiJp4IQSle14L3R
         1THwLlql+cPIfKq9qhUL7vhsecZIMXUsQVV8nBGnPN3nzGIKKyZchz87zBOdmuEGsSHO
         Efv7lrUG4ak94y3ETQ+Ssw2NupBLuX5HG80hnCGGELydSkTCVIrJt9hDU9GiRoduo+cG
         a8QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=yXgCyStEPmsllZTFdtvo155lQd16JWTvfBCOsIZrQ6U=;
        b=IKB7HrvH4WNKD9QLVPyKqqtDQ1zhYYIYGgqhNM/rsMa31IETIP+Mqvw7lewO9VoubE
         l5ud4hBJ+iI/MJNpX8chB6cssM2OnkwpxL1O+8+NcP0bnhT7/w2UYdYi2Z/njnmdddwA
         jVLKRDdo/a9j+4sNIIY4SvPnPoaMPohQl+A+FyWPKzU4XHAbiFpCn1ZUTnYTn6zygOYp
         TFBFLIg1ORLex/YFJ1NgTmdLbGnQaf6zsfHf31ANwQHPGvWDqVuLHzyCnsESQDgWt29o
         Y2kJBQ7gsQgcZRvly/G33WfOd9/TIXCFhuFHlgT7GPN2EWomtuyLvOu3s3x6vgdj6BOf
         8GGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=GmWMcG+B;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yXgCyStEPmsllZTFdtvo155lQd16JWTvfBCOsIZrQ6U=;
        b=EKpj9x/DZ0A/+jCNa9y2rqq41PaNObbF8V62UiNv6Ia4qT39wumoWKak0Xyqkpsx7G
         2smkx5vDU5NZWuENyhyMz+3o0v5oK0Z+Z194XUYID05bBlfYqW093n0MJfkbTBhCUxuD
         7anEFx9XhQ6yRHJL2Z8filQoobaCouPskbRRSZrwaxdbXexpqsihA9LU2YpZv5Q2oFAG
         wp1G9rVsrHNwY90mV1RRDvG86FDgordqNczuC7K5aZ++kK4aiX0+2zqfk7rEUJ9oxM8z
         RxOzqFzcWNRZrC2MO7bHZXbTT93VviXIpbiKo2TP88XeMmdMZJIIpXl81YQXhRXDDpB7
         7KuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yXgCyStEPmsllZTFdtvo155lQd16JWTvfBCOsIZrQ6U=;
        b=iNDkeL/EV0ExlPSLHQAqz1MsSWRUuhCUlNKnlPjlPPu1ECtCvRzRlvE21VoNdOX8+z
         fIgzlOXNLTVfhpog8HQ+PfYDCPHZiPhixUAtnFesckjB/MWZ+zkLb+VkQAlZV7k4Bh7/
         j72skkJiJM/gZ2og6YA+lxKph8HyJBT40euihEsI45OwSOsCmtrGlywKCZoryJpKn1f0
         9LifuGBw0P0WE9kPHQ6wQcvf6pmgSDoUlv3rtAkRdXt3dlzPgoQ708vLsEhQq/uPYzdQ
         ez+CIc7TYFAK2o89lHrHO1Jg2vACFaDJKRAJVGtvsRp4R+6Wvn9EXJUBdg5LsNZqgC8/
         0cGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rBcTPp039KPClVrU1YlIbgnYfEBTrG5yluvYwtcWdp5sOgiEd
	Gjvxxrqxh5viteWMCCgpOgA=
X-Google-Smtp-Source: ABdhPJyrbkr37JK5DZC4qwTSSMAx+AC4wlbsg9My4rWwQUXTbh1R6E2cuYl6GdzzPbjyFkZTn2KtXg==
X-Received: by 2002:a63:6a47:: with SMTP id f68mr3388101pgc.170.1597321561519;
        Thu, 13 Aug 2020 05:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:524e:: with SMTP id g75ls1938872pfb.10.gmail; Thu, 13
 Aug 2020 05:26:01 -0700 (PDT)
X-Received: by 2002:a63:584a:: with SMTP id i10mr3546960pgm.315.1597321561078;
        Thu, 13 Aug 2020 05:26:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597321561; cv=none;
        d=google.com; s=arc-20160816;
        b=L18N1+HNJpyn+WAXiZobT56QnTnPsuyyw96+jFwwhFG056a1knFaxpArNys6qYqbrY
         fsQ5ASn5TWvKHfQcxre/YvhQuiB3OcywO76uIrciStDRfZ9ia9izGTS8sc72kbdj2tkP
         CXqSFwhN/fPkvLg18AeHIuwKXJG8ipAqZWiNo785bSD11Ol5vEoKsV083beNLt3sfxqV
         MoIb+OL7hqT3ctn6vqNhUEEHgPERk7GGkxTr+fmv8vk5o2nIw6Vlos6qpSdFRCVFo75h
         fSvxqdq2Yu9t1K3EDpK1lOASGN2sCwo/2sPW4EY2uEujJcDYTw2yuUyxwO6LYH5J8gnh
         9qXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=e41c5oYHqFyVyE7RzGdj+2oNjx9zrZ3d7b52Xcy+lRI=;
        b=kLLfdSKjD+WIy2SjGhcLTl3R2Nk3jI63oEvz2Uu9REAEm/IWYRf7JqhfQf2Mcirr0a
         G0pjb3KTnZTE1Edy1d3sDMILEqdkFOe0qEBd9L86XPEeiVg6dVrN7EEuTT5R8o9wVTah
         2Apr/iC/P4Cow+8AXFy7dkSEv6HIHNnI9e85BomDjYCNRkxwcQTH17BJM7JouNdSh1/9
         umvFo68bg819pNiRhVdjmlPhtlVvJJuSfX9mECNBXlH1/FhYI75mpi7DUkIIRnPQh4vT
         kUfV7C9BNWPDOlahhYDnxkwBDaq5yrkVla/Cc+/9Bb8E312pBtbOL/4iTy+w/LQRason
         +N0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=GmWMcG+B;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id bx1si476864pjb.1.2020.08.13.05.26.00
        for <kasan-dev@googlegroups.com>;
        Thu, 13 Aug 2020 05:26:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 9372ecbb5ab74080b5bf5f10feeba9a3-20200813
X-UUID: 9372ecbb5ab74080b5bf5f10feeba9a3-20200813
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 316300702; Thu, 13 Aug 2020 20:25:58 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 13 Aug 2020 20:25:54 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 13 Aug 2020 20:25:54 +0800
Message-ID: <1597321556.9999.27.camel@mtksdccf07>
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
Date: Thu, 13 Aug 2020 20:25:56 +0800
In-Reply-To: <87d03ulqbp.fsf@nanos.tec.linutronix.de>
References: <20200810072313.529-1-walter-zh.wu@mediatek.com>
	 <87d03ulqbp.fsf@nanos.tec.linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 6EB2F04DEDD30544E1EE481F458926A2139F49991264C64715B53AF6C629549C2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=GmWMcG+B;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

> For the technical explanation which you need to add, you really need to
> tell what's the advantage or additional coverage vs. existing debug
> facilities like debugobjects. Just claiming that it's useful does not
> make an argument.
> 



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

It is what we want to achieve, maybe we have shortcomings, but my patch

> So if KASAN detects UAF in the timer softirq then the init trace is not
> giving any information especially not in cases where the timer is part
> of a common and frequently allocated/freed other data structure.
> 
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
> These kind of things want to be explained upfront an not left to the
> reviewer as an exercise.
> 
> Thanks,
> 
>         tglx

I have already 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1597321556.9999.27.camel%40mtksdccf07.
