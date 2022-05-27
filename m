Return-Path: <kasan-dev+bncBCS4VDMYRUNBBFO2YOKAMGQESRDINZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 51C2553649E
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 17:24:07 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id j2-20020a056e02218200b002d16c950c5csf3249113ila.12
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 08:24:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653665046; cv=pass;
        d=google.com; s=arc-20160816;
        b=eY6vKBaxZHqmiyb+WcDXJgMlu67x5v4A/Zo8QaefTiJTIPU/pyg6CFc3iqjlB/nIRC
         i4GoizU1iA1vpZiPG5TmyV6Et+tn7M8EyyVgNBi1CPk+GdukytZ3BBwV/ceYLszVFzMq
         6tS0Cs2BWgv0Hw0FU3zFljGdIqO45nw6ISSUx2Mm6o1sudUblsUzva1vsgNAlt7OYZN2
         coZnch+yp7Edw8fpj7ZCWax/2sejJZ3InDfVXubUOEhQhOkJtRYDPNlADY6WI11j3B+P
         tpRxCJLO9zWOIEmLY1gffUGibUgi1PzAZAs0dh2ArIEiwON6O9V0777iATGz3yo2Iwds
         2pjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=nuSwMwN9e2AhmM0jfOMiEv4oMpT5Wmg9kefouIJsJ3w=;
        b=c9jQxOzjDAIHw6pCC/Jrvj12t48P3TnyAZoC2D0V0h5CMHuDeH5OMd9cZJnpBQN0Jh
         7u/GKP+kRWD4Am50VBR7ZSxKt8Km8jQCYgVx7mSVczh2Kz3Dh6A4e4ubZJkTjC8krv7K
         40JpLA1MMXsCmH3CLh49mIwHLWZZqaJZ/cURYCrugSuo44zQE15Dr75BhIGbEScHzjYx
         s70IeJGIHU7SlYa2tEfFNj25fraoM17VbVtdWa+zwwfYTTGgIY/hDRyiwm4WSaNTlnaM
         sw3/vozSPsxwK7S5jCkEbNVDwsifdAI81/eTaL4Et4WFL8u1Zi2FGvaTpPd3L/AKsThB
         QeCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=c8fjdlvP;
       spf=pass (google.com: domain of srs0=cqga=wd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=cqGA=WD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nuSwMwN9e2AhmM0jfOMiEv4oMpT5Wmg9kefouIJsJ3w=;
        b=FTQj3A2YN9pxryt0xTF9IUV0MZtxhmfjVHnXBsC3eRQdkB1FUDJ9nqQwPeoZuiZ2Yx
         HcVKXdf+oGmR229GBLJT0tfpZy5MIJr5tSg4a6YFQPSzFkXTdl40QiPx7gLQuz2/A8Pm
         DUpFKp90w6jNddhKP8NzQRwngFCXAenOIdmpwlIt8zG9B2oXGNMkzaG1OIRifU0JEn/O
         N6+WTZ2GjUUiB/lqgbRj34z8Ww3FUzcHE3tRB1ki2WwBER2xpNYJg95Ua0esn+MYvR66
         s/FJfBVTQEJmVEBMtMhaYO2B/4j0I7d0v8Ef0dDwFM08gGxZe2HgaMa9wKRbbG7rSZjK
         UlMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nuSwMwN9e2AhmM0jfOMiEv4oMpT5Wmg9kefouIJsJ3w=;
        b=36pzwsEVOCnTSgHCU62+3ykh0+ed3eHh0/zb7T3htLfPIpOei/NY4yXD755ACVg34K
         GRKa48mnKWG92xEVEugQ33l7S8maCJyoY5ilRh7G09gAKjKVneW5de1OJsr4wWnge3D1
         JBhTdSxAokji49zne1MfrUgFZcoKIlrtdf72kbc7+OBD8ZP9ydBp32seWCTGBtAyR8ne
         FdYXmMMoL/jFpRCl1aw/lzibVZHiM6xjspGR9sIdyWmKmWwe+hxCsNB84o/U0xAazySm
         l84friGgm+F4l+oNI0kHpMO+QBcyvNQAKoiK7aQkUBzlepTe/iB9R3dVdFo/N6HBjZBr
         ahog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KFUpS2OtID7aYPXpJ4FtaB8UJNROUdzS668EECdlJtImBzZKJ
	BeqZ95vcWs10SBZ8E2PIow4=
X-Google-Smtp-Source: ABdhPJwBOZ/1lTPnIyKTwjZYnKDUKYgMOU/4lJl0Et6QNGnUuTC4j/RMPGfQg98JyBsM3bEWo7sc5A==
X-Received: by 2002:a92:d98b:0:b0:2d1:da7b:ed73 with SMTP id r11-20020a92d98b000000b002d1da7bed73mr7918004iln.204.1653665046041;
        Fri, 27 May 2022 08:24:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:16ce:b0:2d1:be27:b1b2 with SMTP id
 14-20020a056e0216ce00b002d1be27b1b2ls2116080ilx.3.gmail; Fri, 27 May 2022
 08:24:05 -0700 (PDT)
X-Received: by 2002:a05:6e02:144c:b0:2d1:95af:24d0 with SMTP id p12-20020a056e02144c00b002d195af24d0mr15196818ilo.178.1653665045329;
        Fri, 27 May 2022 08:24:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653665045; cv=none;
        d=google.com; s=arc-20160816;
        b=lpOlEW1aksQK6aaca8PPxRtOwC7zqCzMZQVsN5Fy4SHlxvO9AVBqxPXkLF2WEHJmTR
         5DK8DQYkdAWKZEq9DXUTJ8Zr/kTgU/DTPSE0ug28gR5o6IU6ibHhXgcExX/l9vTc05g6
         JruArom5DwTrhpPdFXEJRqAwETacyBGVmCjUHS4LjOc23tK3l9ppdfHOOywEtLlO9SDZ
         VdnVT+hZoHij0gv/R0daixu6Tf3G7rFKkoyxUgByjLtv1cEgo84cUiwJbg9rFcAFm5Ws
         A8788Bkf4bJeON7AfcDjBFb716W9afbI+mKAPRnbW/QlXC+l6/HUZ++Q7VmmOcRAvsJ3
         q5zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JUba1wVtUerj+qGNVUI3r6MRjTQGCk+73MFBnTW6Wd8=;
        b=sVSJsHCrrGXC9hYZYEvDqAOSYt9+Ey0QjMxML+qAp52y1mvA5Zb0p/BPoWysgCX4Dz
         MLGpi7j29js2Sjbb/+98uIWpqXLD8aRfY/lydCQfO+YA4o8lNVVN4M8a/kjMS+Nd1VyT
         Hi8+XsC/2lrYEIqz47avYmEWEFHzCHpZl3kUzUmigoTtfc92Od29Ge/OWiA9N4XIF2PO
         14xFE7+p+5u6DEiFbc2CWPZPLuAJorNrAg36hStUvahTiHCY8NU1k13T+Ug9RqjzKVa5
         JNFxKXQ2Gd85r2yYqZa4VEbjXff+wdJyruwomyiq+prk+geEyB/dkHXKpxZ3/PpovOjy
         wBUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=c8fjdlvP;
       spf=pass (google.com: domain of srs0=cqga=wd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=cqGA=WD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id f12-20020a5d858c000000b00657979e6e4dsi256329ioj.4.2022.05.27.08.24.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 May 2022 08:24:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=cqga=wd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E818661D4E;
	Fri, 27 May 2022 15:24:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 568CAC385A9;
	Fri, 27 May 2022 15:24:04 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E95DD5C017C; Fri, 27 May 2022 08:24:03 -0700 (PDT)
Date: Fri, 27 May 2022 08:24:03 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Johannes Berg <johannes@sipsolutions.net>, rcu@vger.kernel.org,
	kasan-dev@googlegroups.com, Johannes Berg <johannes.berg@intel.com>
Subject: Re: [PATCH] rcu: tiny: record kvfree_call_rcu() call stack for KASAN
Message-ID: <20220527152403.GS1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf@changeid>
 <CACT4Y+bm++gFi8QYNk41g_ihZuvrMO5O2T_3E7r0h+_PRfShuQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bm++gFi8QYNk41g_ihZuvrMO5O2T_3E7r0h+_PRfShuQ@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=c8fjdlvP;       spf=pass
 (google.com: domain of srs0=cqga=wd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=cqGA=WD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 27, 2022 at 05:13:18PM +0200, Dmitry Vyukov wrote:
> On Fri, 27 May 2022 at 17:07, Johannes Berg <johannes@sipsolutions.net> wrote:
> >
> > From: Johannes Berg <johannes.berg@intel.com>
> >
> > When running KASAN with Tiny RCU (e.g. under ARCH=um, where
> > a working KASAN patch is now available), we don't get any
> > information on the original kfree_rcu() (or similar) caller
> > when a problem is reported, as Tiny RCU doesn't record this.
> >
> > Add the recording, which required pulling kvfree_call_rcu()
> > out of line for the KASAN case since the recording function
> > (kasan_record_aux_stack_noalloc) is neither exported, nor
> > can we include kasan.h into rcutiny.h.
> >
> > without KASAN, the patch has no size impact (ARCH=um kernel):
> >     text       data         bss         dec        hex    filename
> >  6151515    4423154    33148520    43723189    29b29b5    linux
> >  6151515    4423154    33148520    43723189    29b29b5    linux + patch
> >
> > with KASAN, the impact on my build was minimal:
> >     text       data         bss         dec        hex    filename
> > 13915539    7388050    33282304    54585893    340ea25    linux
> > 13911266    7392114    33282304    54585684    340e954    linux + patch
> >    -4273      +4064         +-0        -209
> >
> > Signed-off-by: Johannes Berg <johannes.berg@intel.com>
> 
> >From KASAN perspective:
> 
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> 
> What tree should it go into? mm? rcu? +Paul

If Johannes is johill on IRC, I already agreed to take it.  If not,
we might have dueling patches.

Ah, "Berg" -> "Hill".  I never would have figured that out without
this hint.  ;-)

							Thanx, Paul

> > ---
> >  include/linux/rcutiny.h | 11 ++++++++++-
> >  kernel/rcu/tiny.c       | 14 ++++++++++++++
> >  2 files changed, 24 insertions(+), 1 deletion(-)
> >
> > diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
> > index 5fed476f977f..d84e13f2c384 100644
> > --- a/include/linux/rcutiny.h
> > +++ b/include/linux/rcutiny.h
> > @@ -38,7 +38,7 @@ static inline void synchronize_rcu_expedited(void)
> >   */
> >  extern void kvfree(const void *addr);
> >
> > -static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > +static inline void __kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> >  {
> >         if (head) {
> >                 call_rcu(head, func);
> > @@ -51,6 +51,15 @@ static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> >         kvfree((void *) func);
> >  }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func);
> > +#else
> > +static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > +{
> > +       __kvfree_call_rcu(head, func);
> > +}
> > +#endif
> > +
> >  void rcu_qs(void);
> >
> >  static inline void rcu_softirq_qs(void)
> > diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> > index 340b3f8b090d..58ff3721d975 100644
> > --- a/kernel/rcu/tiny.c
> > +++ b/kernel/rcu/tiny.c
> > @@ -217,6 +217,20 @@ bool poll_state_synchronize_rcu(unsigned long oldstate)
> >  }
> >  EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > +{
> > +       if (head) {
> > +               void *ptr = (void *) head - (unsigned long) func;
> > +
> > +               kasan_record_aux_stack_noalloc(ptr);
> > +       }
> > +
> > +       __kvfree_call_rcu(head, func);
> > +}
> > +EXPORT_SYMBOL_GPL(kvfree_call_rcu);
> > +#endif
> > +
> >  void __init rcu_init(void)
> >  {
> >         open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
> > --
> > 2.36.1
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf%40changeid.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527152403.GS1790663%40paulmck-ThinkPad-P17-Gen-1.
