Return-Path: <kasan-dev+bncBCMIZB7QWENRBXM2RSFAMGQENMYATJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FDCA40D619
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 11:24:47 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id r10-20020a056830448a00b0051b9c05a2a8sf18193183otv.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:24:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631784286; cv=pass;
        d=google.com; s=arc-20160816;
        b=bzHoMY09m5p/hXa4CfP75aCZz/chgtOmq6fco9aB23yDDmI0sO4McqhVGhzuhAZos2
         x9AVg1rnlG4Hg2b7QYa72gu8MeGIjecTEAOgA/3pxaVN4PkiXMdZ7jT9XtHTsWB5r4cr
         ZIb7UJSI9y1ukF2a/sP7/yX4VwBHyju/NRBEcDF2G1C+UtPHPJwrkkwiuzkI9bMCddvC
         MbrMGCAhfYrT6rghFCS792h4pCJ+is3rM3ci8kkFQUuwvNsRMDtt3lFf4FT0ROpNZc5Q
         fe3QQiP6r7dsBrF+LK0VKvyQnfZv22asqdRBoskHvA+7V9ztzW0duAEY+OCYxgR4yrqD
         7NFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WSiONAKCV5uLJ1cpZunYnHx9YlZj7dadlbAtjcOt1M4=;
        b=YsD5BWFTy2RgeOJjK57N2GcN7vXJ9+fDkudTlHDMjY+F8ID9GzdeHcmGsfaL3Sj83w
         9N4zC1kcdI9hkkClyRumCmScOZ0cCxfreycuqHVUh8B1tlzxgIcP1UJrVxDJilbgDjdf
         zU+24EVXoKlgEO1ITaafRBYjPnxr/htidhDxQSPLRHsTw3m0Jcb2xQ0elQ2Byyxzt0Il
         tup+9W5f/9cBmGtsrAPztuZjEW5xr5SwnpAfezbPYv8fieMPoKaV79uErsQArDVizvIh
         4E9BLdphBKIxxSdztYhZOSyo5z0tAEeIA2Ff34FI1bNgtnGrekDystzDcRKnbIHruSe8
         rRLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SbSTnF6Y;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSiONAKCV5uLJ1cpZunYnHx9YlZj7dadlbAtjcOt1M4=;
        b=k3dNq8DhX+WoVkYmONS/JbAOPQZkeEAQQlSGVYpyGyfxTh6OqNh69TaOsqlpawZpEG
         D4QrfeGOa87uVI03FtJYJbi5AbDAwt1AWYb4gsJkxm+IkmyUJSo768re24Udi22tIxrw
         7UGZfdEzVPCkkC3fz605y+281+hlNuTF9Tch/xWCkJm+QI7Knzb/YVWWJO5sTgYYHn4f
         0qjhiNlww7n0waniVBfnk4LzAddnzNZyX9eW4l1ICzmcaJ86bg4tlffYenf99W6tbiwl
         VE4U5o1asIihyYxP1HgtyUj0oo5HTpGbe2LkGfRPcjq0o1QxBNIInVDGArE4K1IJf8LI
         kPLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSiONAKCV5uLJ1cpZunYnHx9YlZj7dadlbAtjcOt1M4=;
        b=T4hURqhA0OKBEO70KkkEkeXMNNV/N1qp5BVWHH/Jpud3pVBBmK3gVBAPanQbZDITds
         ZH1W7/GvI9t6uK5zQLMfY9hDR/vChiG+ATCV5op0GaFY1L+S6ZAfNNy/o0p9jtJl+ThF
         vw21M9fMYGj5Tn3xF+QTB4m2GZ21wG4xpmwnZHU1C8ivXK5BruyvCQcVEkEHbuu5/N4s
         TfJuGcMoV7+f+uskOG15QffP8h+7wGKqBnLjtBNQOOWPQLMuNED/9KTiL6TTBkuRXiSb
         R0aKJiLKI9tkKyIulaHolXz+hic6WZBYcNx1M/9b9+3dvyaZ3Qp+dRNeT4gfDtBqJjP7
         aO1A==
X-Gm-Message-State: AOAM531fFOFwrwNDTfH+1G4TPBvajpKPn2147iW6vp6lfAt7d/XKNBti
	p82sg6a6+bfsliOcSe1etlE=
X-Google-Smtp-Source: ABdhPJzsdkPzqb7yBR5tlTMebZTnUV7RFnXqGjP3WchBjsnYj/uBqAMROwdcYwd65jCrj/xgIun+9w==
X-Received: by 2002:a05:6808:657:: with SMTP id z23mr8643718oih.113.1631784285775;
        Thu, 16 Sep 2021 02:24:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:eb0c:: with SMTP id j12ls1651157oih.0.gmail; Thu, 16 Sep
 2021 02:24:45 -0700 (PDT)
X-Received: by 2002:aca:2310:: with SMTP id e16mr2975947oie.64.1631784285463;
        Thu, 16 Sep 2021 02:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631784285; cv=none;
        d=google.com; s=arc-20160816;
        b=nCbM8bAnHSvjmko3O7uTGEnC7LgxydsbZ6PNZQZhVuFRE4zBZC6Jx8uixfkhHx05pP
         +LgyB/0Ati9vmb5So8ZJkoCmQbsgKc8wehKn1DZ4KpPWFKI7PEtFDFXKEa1995sWWZ6J
         QvZlARz17fwFmWXhSD2gONw5kU3rTFxEvznOECwaRL4T+FnalsHbGI6gZHgRCm3Pu1dD
         u8lSXR5aX1duzG7vqhoVrtpvvt2wHO9tbEQFRn+C+Kd9RIkmZjs5YN3Pdd7bPzjdqVJe
         klomx3vjtlXgvf/H2z+f4y6bLAJUIL+VUEJYj8eIoyGauUBMb3tlHTPuIwx84yPwmxn2
         1R7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YJJaNclf3wzSnd6KFncvUtNJPgnZ1G90tgAnEdwOG7Q=;
        b=ah+sTvMp0RPodUX6sadl9GsFapnCf7SI0Jt7sGOZjta49SvN1ERCm3ybdwpircY6XE
         bMohv5I2YHaGpo3yCrg8laQJ6tCJZu9UQ/jSB/uYQvFdgykVU+p+Nv8uzjH1MBv6YIDW
         /WtTUUrVYF3+Hv+iGxyRzq3pkJnw4vZGVWDuA/c+h/zGUky6d5Gijez0cE1Bm8gl+bTD
         PLPxithRtBO3IP2Uo6L5FX88CbslG+BwxKpSEjusl026S3nc86Q0VfU3arxm9otXXacQ
         Nr/zycHylbrtHVbFt3P4iMS7rRtnbL8UjXwizwLoXdx4VGUg0+YdGVj9tV1AOFRoaoag
         V2aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SbSTnF6Y;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id b1si496830ooe.0.2021.09.16.02.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Sep 2021 02:24:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id n27so8288199oij.0
        for <kasan-dev@googlegroups.com>; Thu, 16 Sep 2021 02:24:45 -0700 (PDT)
X-Received: by 2002:aca:f189:: with SMTP id p131mr8669427oih.128.1631784285005;
 Thu, 16 Sep 2021 02:24:45 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000eaacf005ca975d1a@google.com> <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx>
 <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
 <87mtoeb4hb.ffs@tglx> <CACT4Y+avKp8LCS8vBdaFLXFNcNiCq3vF-8K59o7c1oy86v-ADA@mail.gmail.com>
 <87k0jib2wd.ffs@tglx>
In-Reply-To: <87k0jib2wd.ffs@tglx>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Sep 2021 11:24:33 +0200
Message-ID: <CACT4Y+ZCRiwobf0rGUoMiUEi=6Eoxvvgxxv-c+AhH=7U6M3LXQ@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=SbSTnF6Y;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231
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

On Wed, 15 Sept 2021 at 11:32, Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Wed, Sep 15 2021 at 11:14, Dmitry Vyukov wrote:
> > On Wed, 15 Sept 2021 at 10:57, Thomas Gleixner <tglx@linutronix.de> wrote:
> >> That made me actually look at that mac80211_hwsim callback again.
> >>
> >>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
> >>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
> >>
> >> So what this does is really wrong because it tries to schedule the timer
> >> on the theoretical periodic timeline. Which goes really south once the
> >> timer is late or the callback execution took longer than the
> >> period. Hypervisors scheduling out a VCPU at the wrong place will do
> >> that for you nicely.
> >
> > Nice!
> >
> > You mentioned that hrtimer_run_queues() may not return. Does it mean
> > that it can just loop executing the same re-armed callback again and
> > again? Maybe then the debug check condition should be that
> > hrtimer_run_queues() runs the same callback more than N times w/o
> > returning?
>
> Something like that.

I've filed https://bugzilla.kernel.org/show_bug.cgi?id=214429 so that
it's not lost. Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZCRiwobf0rGUoMiUEi%3D6Eoxvvgxxv-c%2BAhH%3D7U6M3LXQ%40mail.gmail.com.
