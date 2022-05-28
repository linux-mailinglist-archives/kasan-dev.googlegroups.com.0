Return-Path: <kasan-dev+bncBCS4VDMYRUNBBXHLZKKAMGQEF7WIH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C457536ED7
	for <lists+kasan-dev@lfdr.de>; Sun, 29 May 2022 01:53:02 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf3583216lfa.10
        for <lists+kasan-dev@lfdr.de>; Sat, 28 May 2022 16:53:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653781981; cv=pass;
        d=google.com; s=arc-20160816;
        b=uxqyxLp7YIM/DH8iKsx0yFAUx8cri1OYsDl8e4d+fDu9tf4afXR7bKjxb7uYJJapqf
         ntCvEWQdWZo9yCsgbTFC/wbf7M9qigPB4KdNO/HRgQYchzzKBeB/Hiz1ZNSX9AwVUo1G
         H5HVfAVWFhkzeSC+Jl8utF/S6hmu8Z+f+BZ/MG1D89YHLawxmEk1OY99f56TUNjdillA
         q9evsAyM1MGvysF42nmdKwyrNP/ffC/e7/0WGKT3mGVbWw8rH945Q3AtQ0lIwmyPDafB
         /SiQwdg11HFElwlnlt3LXtJZJT2UI1HCszY9v1yEPCPpCse5RZcv1nNhdSqwbRdBHfvs
         MnpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=7QqxIBNqDMDP9KSPFlTsn9yMS1TLKNf6r5mHXk59eVw=;
        b=wtK37N9evvP1wgFT7VhRB+I9XwSbWyErpXLJJ1EghNK6DiMwFRa/gRE9CpgMrxXwOU
         urHo0l3txLl3uxHiaj8C4KQMSuzGx0mG1rSwmThFHaDB3iVaIJ9ILVB4BIa9hlicx71K
         lZR444L7qKU4Md5oB72wLKRzCW8zB61ijroLG1WnSnuBnZp7ZVWXEGwq6N6rLguyPfig
         gY34x9IhCTPVIaToz8qlIomJBjmP6MqUUGB4Y92YFWj9m+KP4mRyIEakvVyp835BPbN2
         NlXZVDRrMfupYJVs6/fkWf4zbryRJ/mBgYJYs56ZJQyh7xY5PzjtOcEg2Go8mkFXU2hg
         psLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jnfSkj43;
       spf=pass (google.com: domain of srs0=yjrd=we=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=yjRd=WE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7QqxIBNqDMDP9KSPFlTsn9yMS1TLKNf6r5mHXk59eVw=;
        b=gpNnJYV+6oI/ZrGUt3542Z9+GWh0vybu9Ys49fZV1f69RQKH42ZM6KVARA24HxLLn+
         ILWH+zYH8m1RlT/1cSgs9P8s1N4uTV4AvDBgFVDW1CRZuQUM1Gy/6cJio6xR3T3W0qAi
         5Xt98ZSccVuJW+WHiG5tscClhDcClVeVrB7gbbKipE/XAO77yEqJIBOIsC0oCJoP8ZgF
         mFkUvHlPeQqlLGPxYKqDKAld3li5Di5IklgNtjzYNyxMLsbwDXvqZuvcXmxlbRiHK3AI
         C1lO3xnFLteXYMlxrVGtc1pblAo/JcD2rJ29NWKwKhJBZTW3PZrBSWCaBFB/NMlaIL7v
         5edg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7QqxIBNqDMDP9KSPFlTsn9yMS1TLKNf6r5mHXk59eVw=;
        b=pggmMLS4SV85vBsVltJxxDGJ2Ff1T9Qm3eaNU6/YjHXCw7QmvNpZv7cPa8HwhpLHxy
         GXuIMMq09Xt07vd51ziQXIomYj5wooVVTE/vOzzp41tXmsh4eVriSftahLNkft0wjiBY
         Ng+XUDxHL1i9XE9sJ2xQg9uQ/GKJDzaDPLZs3OFDwPrZnC4THVLd+HhZsfmVGpfeqqGk
         vo9LbKD8waS+41ELvKMbFFKS/rdsT+ZzGFOjnB/Mw7/R3StF+LiahWiEZPMFJ5989ROF
         gMY2TrR/3Ga7IAwqRPHUeIjBMJpyVQ5F3IF/EWRny9O57BBnskvu830lLpXoq3f5SExE
         u9IQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zmFzshNa0O1EXBLaewfsh0LfG+gljN5LzT59Z4EZ3jSCAG/VX
	vc5jRh4F3SJ+/3vEsKjMPQM=
X-Google-Smtp-Source: ABdhPJxNNX2I40tMnsr8Y+jikgcuAzBXbcYG53zxoVSROIquAbneP1zzHtZMTzrW9Gt/kXv/JAynUw==
X-Received: by 2002:ac2:5047:0:b0:478:7ee4:592f with SMTP id a7-20020ac25047000000b004787ee4592fmr19165055lfm.576.1653781981338;
        Sat, 28 May 2022 16:53:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als3045726lfa.2.gmail; Sat, 28 May 2022
 16:52:59 -0700 (PDT)
X-Received: by 2002:ac2:43a1:0:b0:478:5867:5047 with SMTP id t1-20020ac243a1000000b0047858675047mr28241329lfl.37.1653781979713;
        Sat, 28 May 2022 16:52:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653781979; cv=none;
        d=google.com; s=arc-20160816;
        b=O48N7SfeyI0tcqvtTU53oH7oUekixfX0Hm2+MTBFP8vA5qgFNhHijMnNPv6fT7XTgA
         tL77wsmYunz1j0/UTHicn1iVVHloRm7as+s/X/NddfwvprRHvsjkXTB2PfNJ+2113f3f
         ssOO3PZkJ3g9toKfqwOdc43HfDlyl29rFF9s3fIflOgT6sbMa1iuaoeNzehdJwGCpLIm
         VM94g7uVrCIdMcDMT9F49l23ym+8M0PUvkTznTFsrUuO7pBoz8D+zx0IPfOvUdL4nt/b
         JO5kSOrOIT8SawAly0PU9Q+TlOKhaSA7aRioenhHnPZ/PCniLwQjnYy8jXkQ6+npEf1d
         SbzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ECI0gUyq0vJxXCylw1jeM479pRGtqonOKb4kZqJDVvs=;
        b=nlzai8fS0HWvEOf3htDQIfhPl6pU5U4fm2I8CA1hyVzohu5CeKW6+X894nZIN0u5Y1
         HIjxhGo8FWwb112wZat7U7focvfDN0SrNeOkuveJ9BiWSpSQIyAjBwvSt9kTAdfvAk5T
         edgoY8yjWplmYWwrsOsO40ANzDsJGqeKea+wWlKVqlBUvNmQf9dHybSooMQg3tZewJ+u
         3OoXUt/Qo2UxLau9dkdmC3F3XGfYxOu/I1C0yT1MxeQYj1ubj7mgQbqqbyTSRdO6lj8H
         ewze2mirpQDpTvD7bgm+57iN/2nuz5zxhxHCAlQmc9lIqfyz8ElgiT8ep08LLSVf4ndk
         3qjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jnfSkj43;
       spf=pass (google.com: domain of srs0=yjrd=we=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=yjRd=WE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v15-20020a05651203af00b0046bbea539dasi340108lfp.10.2022.05.28.16.52.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 28 May 2022 16:52:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yjrd=we=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E4726B8085F;
	Sat, 28 May 2022 23:52:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 97C10C34114;
	Sat, 28 May 2022 23:52:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 318FF5C0269; Sat, 28 May 2022 16:52:57 -0700 (PDT)
Date: Sat, 28 May 2022 16:52:57 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Johannes Berg <johannes@sipsolutions.net>, rcu@vger.kernel.org,
	kasan-dev@googlegroups.com, Johannes Berg <johannes.berg@intel.com>
Subject: Re: [PATCH] rcu: tiny: record kvfree_call_rcu() call stack for KASAN
Message-ID: <20220528235257.GZ1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf@changeid>
 <CACT4Y+bm++gFi8QYNk41g_ihZuvrMO5O2T_3E7r0h+_PRfShuQ@mail.gmail.com>
 <20220527152403.GS1790663@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220527152403.GS1790663@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jnfSkj43;       spf=pass
 (google.com: domain of srs0=yjrd=we=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=yjRd=WE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 27, 2022 at 08:24:03AM -0700, Paul E. McKenney wrote:
> On Fri, May 27, 2022 at 05:13:18PM +0200, Dmitry Vyukov wrote:
> > On Fri, 27 May 2022 at 17:07, Johannes Berg <johannes@sipsolutions.net> wrote:
> > >
> > > From: Johannes Berg <johannes.berg@intel.com>
> > >
> > > When running KASAN with Tiny RCU (e.g. under ARCH=um, where
> > > a working KASAN patch is now available), we don't get any
> > > information on the original kfree_rcu() (or similar) caller
> > > when a problem is reported, as Tiny RCU doesn't record this.
> > >
> > > Add the recording, which required pulling kvfree_call_rcu()
> > > out of line for the KASAN case since the recording function
> > > (kasan_record_aux_stack_noalloc) is neither exported, nor
> > > can we include kasan.h into rcutiny.h.
> > >
> > > without KASAN, the patch has no size impact (ARCH=um kernel):
> > >     text       data         bss         dec        hex    filename
> > >  6151515    4423154    33148520    43723189    29b29b5    linux
> > >  6151515    4423154    33148520    43723189    29b29b5    linux + patch
> > >
> > > with KASAN, the impact on my build was minimal:
> > >     text       data         bss         dec        hex    filename
> > > 13915539    7388050    33282304    54585893    340ea25    linux
> > > 13911266    7392114    33282304    54585684    340e954    linux + patch
> > >    -4273      +4064         +-0        -209
> > >
> > > Signed-off-by: Johannes Berg <johannes.berg@intel.com>
> > 
> > >From KASAN perspective:
> > 
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> > 
> > What tree should it go into? mm? rcu? +Paul
> 
> If Johannes is johill on IRC, I already agreed to take it.  If not,
> we might have dueling patches.
> 
> Ah, "Berg" -> "Hill".  I never would have figured that out without
> this hint.  ;-)

And applied with Dmitry's ack.  It will show up on -rcu after my next
rebase.

							Thanx, Paul

> > > ---
> > >  include/linux/rcutiny.h | 11 ++++++++++-
> > >  kernel/rcu/tiny.c       | 14 ++++++++++++++
> > >  2 files changed, 24 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
> > > index 5fed476f977f..d84e13f2c384 100644
> > > --- a/include/linux/rcutiny.h
> > > +++ b/include/linux/rcutiny.h
> > > @@ -38,7 +38,7 @@ static inline void synchronize_rcu_expedited(void)
> > >   */
> > >  extern void kvfree(const void *addr);
> > >
> > > -static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > +static inline void __kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > >  {
> > >         if (head) {
> > >                 call_rcu(head, func);
> > > @@ -51,6 +51,15 @@ static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > >         kvfree((void *) func);
> > >  }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func);
> > > +#else
> > > +static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > +{
> > > +       __kvfree_call_rcu(head, func);
> > > +}
> > > +#endif
> > > +
> > >  void rcu_qs(void);
> > >
> > >  static inline void rcu_softirq_qs(void)
> > > diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> > > index 340b3f8b090d..58ff3721d975 100644
> > > --- a/kernel/rcu/tiny.c
> > > +++ b/kernel/rcu/tiny.c
> > > @@ -217,6 +217,20 @@ bool poll_state_synchronize_rcu(unsigned long oldstate)
> > >  }
> > >  EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > +{
> > > +       if (head) {
> > > +               void *ptr = (void *) head - (unsigned long) func;
> > > +
> > > +               kasan_record_aux_stack_noalloc(ptr);
> > > +       }
> > > +
> > > +       __kvfree_call_rcu(head, func);
> > > +}
> > > +EXPORT_SYMBOL_GPL(kvfree_call_rcu);
> > > +#endif
> > > +
> > >  void __init rcu_init(void)
> > >  {
> > >         open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
> > > --
> > > 2.36.1
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf%40changeid.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220528235257.GZ1790663%40paulmck-ThinkPad-P17-Gen-1.
