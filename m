Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBWHCWOGAMGQER6ESYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 966F144D506
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 11:32:56 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id r25-20020a05640216d900b003dca3501ab4sf5016696edx.15
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 02:32:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636626776; cv=pass;
        d=google.com; s=arc-20160816;
        b=vIJ37QHrEYbVyzRb0x4nBjmRslMvk1R45joGAmYDTwhESXEICf245OEgjXzV9sj7c4
         AzxQeHcWVk2XQOk+MkmjOiECCOvYEmNiD8B8ZzXLloSq/FXXb30c8BRLLFklGVhfXdkS
         3MZEUxY+7+4OboXnl+G/5apPL0fbhUeGgciiYk61zjIHXGEx+slspXGaBeDbwudN2UTP
         l+nOL4J/snc4SfCnjzJR9LPhSkcHRKaYbou4qatTtnMQmfL00eyYumGSdHdeANhJpo3R
         wlUa5uhvdWuKUZH/9lNXHQIOfuN+7PD6jDm/rPM8euCBWJcZhCg/gY7LSQDKuKP16yyZ
         7uLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=xm9OGD6bbjGEGt1Asey37fvXBZe6kLWWm6VK83n4TyY=;
        b=qBlSkJjh0y2bLt0xOjz+6oY5tABdiWwI16Xn78x0xnH+DwQnHy+WPx/a43cEcD3npy
         lHlp4q7ULSSOtKWO387VOCDt1fA9kCpwlG8Dnt75EcAMbM9TjHoCI6YoDTY17KAm58vz
         EgtcTV6dedQ+PdhpIN74gHKiFSCrZn92P4lKGwFTikqTe6FrCqzMzGpIPKgAo/E6V3uW
         BDcniRoNfmzs1wGFLwCtkHwgMfQZzNuR4QfSmAzZheAZ2FkWQkRNaoR3+JOOPErBJvKS
         uQjoFmKYHu7ct5lOj6x3PNYHzMuGpJgGU5jveRpZwbGzhxJ8o+2Q6HfhvmKPWy1uETOX
         BKnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="R6tRD/0B";
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xm9OGD6bbjGEGt1Asey37fvXBZe6kLWWm6VK83n4TyY=;
        b=cRtc5FOKO/7EDyHmhkQubpvvwMU7YVLixzWnDXllPbA2D2XlvSTufZVZ5FV5okiW+X
         qPc5gXTsEwvvuZ038iDM+bzFwQONkvtOzxhpeRdKZvZWFlsClysa0o69lMFWuI5p/CXj
         OhIPvPjNqmUD7JALpQ6WsdDu+wuNeuOZjIN+zmx4C++5vlcVtZDbVi3EUeWuBqiNEuil
         5nu5qEaLkWPjVWSKuzJaP8urPXSJqUXp5JNUhy88QUsjK9CUmHFfdQpI862/2tfps3/1
         Tf8KWI1PzpTacr55KZfIc6FZffiBQ4miu4YxRGMAjzeq8sR7/oXUjZ/p3lLSILpINO5E
         lKaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xm9OGD6bbjGEGt1Asey37fvXBZe6kLWWm6VK83n4TyY=;
        b=fdLSmYPFMRri36zbF2rdbA5gSmveW1XeQdpsesvzq7qWI83tw3Mta7n4DKfUjGCFQY
         ZD8cZc6ZwSgdovSeXQSWUF0W5aFaW2mWNX2N/xwm9A4SEqsK63Cx1OKQSnuj843eqMlP
         LCx3+v73mubCI2GVeFvUjzXfGmUwFQiAoC9t1NLJPbiGjLMXxzvcGJt9Kyi8QimJdWbC
         z0o4KXfaMKNgol/E6NA6hJGwWJ+8mWrrjD9/MqsXYC4HAkMI1BRPL3wO3+j68e0MS+Qp
         4XofLnAoQ1V6XmjBVN7IZtUYb0nWjWTz8JkKRuoFW+LCYVf1IweIz7RLqFK/RtkcMoX/
         wgGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320yKe3jVbyY+HMUbBCpfKhaZCDwFbg0/t9M9csXBlRLh9VpOV6
	LHSiWrxXiaFjN0O8Jr6i6PQ=
X-Google-Smtp-Source: ABdhPJzI4vLj/oEsVg4ACUo1OTImsDblwuL/qeIbcOp0kWyxXtwOA6+keIqjLI/c2y1Ub+efww/YmA==
X-Received: by 2002:a17:907:ea5:: with SMTP id ho37mr8579393ejc.133.1636626776387;
        Thu, 11 Nov 2021 02:32:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c0d9:: with SMTP id j25ls2644663edp.3.gmail; Thu, 11 Nov
 2021 02:32:55 -0800 (PST)
X-Received: by 2002:a05:6402:100e:: with SMTP id c14mr8757027edu.196.1636626775516;
        Thu, 11 Nov 2021 02:32:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636626775; cv=none;
        d=google.com; s=arc-20160816;
        b=tNkU3rtvrVBEjl9xv/BK1nRBaIQhhylggocfhuIoVF5Zcz0TDfYSRqwLQE4/G5UczZ
         8BEcCxpKc+Rb3aK2T5LG4qh1NZnbVkZv/B5vu7T2j566/kivaTKbJ/ScU7aJlgwpDe2G
         aSRrxErPWXx62vCbZPfK6/FIhrt61MsJlEuxkDVLEkttdFQhmQKKR4lTmoPgm5Wq3ILp
         pdhWNAhyrjfVVoigosjOBJSnYg7TLWVC7S/EGvyl+2qw/V9SzVHoJz/SMPpcWs9z/2XX
         DgHJPd5bp66sBo0M62/pPR6F+8gPNpN6Rfod6Hko/ltG9RfkXvCk5jBjtqiuk68vTQH+
         JCUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=G8PeXTTA04PjDj1/ZfDX1iaxCoVke0go0QXwSQqofac=;
        b=adXm1DI8IWh4ZIsWCyYDkrLKOtyF6dblTf1w3w6+cLmi+XTUvJjtDdJxWhnBbPdoL2
         m46WweQjnlrflOha8ncId5GhGy+LyaCrFRDMhGQmPueheDUMh9gyz3bkyojJqFNAtYN2
         G407lDlLv6j9AqihHWgbOjVqhePjx97ecAZ2wOJLqIAgyGXATqDQIjVJCDbHUpddy+KG
         PMAu0aimPhe839JFlSY0fwxu4COuQHCr8TyRJURXHbakN1xDtje/qQ6HeB3r9QtQJ5AL
         2pHvmybmT5VDhmCHjsQrqF2gh3QqUbRmfOPV+uTZGrqi4QXaBm82teWUZ1N7TPvXuo8b
         3Nlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b="R6tRD/0B";
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.19])
        by gmr-mx.google.com with ESMTPS id d2si183518edk.1.2021.11.11.02.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Nov 2021 02:32:55 -0800 (PST)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted sender) client-ip=212.227.15.19;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([212.114.172.107]) by mail.gmx.net (mrgmx005
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1M7b2d-1mmUIP1zLR-0083Gp; Thu, 11
 Nov 2021 11:32:48 +0100
Message-ID: <26fd47db11763a9c79662a66eed2dbdbcbedaa8a.camel@gmx.de>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
From: Mike Galbraith <efault@gmx.de>
To: Marco Elver <elver@google.com>
Cc: Valentin Schneider <valentin.schneider@arm.com>, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker
 <frederic@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman
 <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
 Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>,
 Masahiro Yamada <masahiroy@kernel.org>,  Michal Marek
 <michal.lkml@markovi.net>, Nick Desaulniers <ndesaulniers@google.com>
Date: Thu, 11 Nov 2021 11:32:40 +0100
In-Reply-To: <CANpmjNPeRwupeg=S8yGGUracoehSUbS-Fkfb8juv5mYN36uiqg@mail.gmail.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	 <20211110202448.4054153-3-valentin.schneider@arm.com>
	 <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
	 <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de>
	 <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
	 <CANpmjNPeRwupeg=S8yGGUracoehSUbS-Fkfb8juv5mYN36uiqg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.0
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:uuwX788BL/oP1FC37c/JIA2AX9+HNeNHkFeDgDrreyZCxwfBg0P
 B+LG2N6R4OuzGdOAYShamBgnrdfwteiTsZbAt3bWKAG4xA8ILr8IE8V8eRKdYmsI+QT4ieO
 hSGLZCIAvzMybM5e4d039bw+2e9jg0wvFDF+Hvd9V0aPc42JqL2Hq55llwqtmw1QBPduxu9
 rFSdKtZIpm4OcQmGqQUXQ==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:tJHMHumK5Ow=:WzGr7EVNBA75U29zZgCq9T
 SH5u6IUYmUgYVPKQC6dyltXmdR8eq//e3pTu2OzThSYmBIu9/NaxZ2/IA2sKuJiyK+yFTzrz5
 I/HO/mwgHzqLmwD/0DWQMgoQhcJpYCfbUYZYKy2TLdqLRVhNV1A2Cjk2BZZuEU4Do2CUwT/eM
 wIpShikX11920Uxw/YETz5drZBAPyyvz9zJqk/yQ+rc1KXFv2e0FBOJfDN6wEd+Gvq5+cjGLR
 dyGZUYeYODZMUpuAR85mw6IR2cGW64i+9ROqZnuoDJdUJwBRt+1vI6UopW20ZAPB/6XSgIzoh
 6Qs6/0y24T0Er4XHnZTI2cxFbzvUnZKvsR4fvInhTvyNC83jalZoD1Bj1iMtAIY+QIVXLv36B
 EXoxruXp/NcOvv19ewBKC9sC3iOmUxILYXSVj8UevLj7pjHUJ3Uu5EXqdLz7yT23WIbN3WDig
 CeBx418hv8rdQKUQbvsxRGQUbuKhDkKh3z5e8gLXQqFumqYJGhKfmjmdMWSfA6zHwzaA59KS3
 LPz6U15vXGZ6c/2oKKQqPRWTF8pS9TwACFE/m96KICA5cmF1WA6aV3ryOGXmsyVWSFunp1Xnj
 xZzIm3kkyWYtZ0Fn92uNtY2TecsMSPaxL8sNQjbv8mkMzJwFpskie7EeHrKwBKM6jqtyHqD5B
 8kyqZ6IMr+cytx1g56gpncODPICpz4oRGhGVvF7pwteqmz4jEZ9JWbf/4vegn1Ak3iF3gPZMy
 vSQ6BrmBGzZc7t2mMtOXTWPCVApr4Q+uOifNKAEMe241zzCFDUvW+pOFXeUVLEaDU43IwDudY
 6MCeRNbQctVEBAKnkUQS0Il/dZw5JazqlnaS+aeeYHa8AwzmoqazLXcfq6OuwXJ8SEE1xj9M/
 BkhTYFoSE4jk6klAhutpMoNIKHo1L6ZYEQkj4ZQVR1vsW4SJax+xiSDDvdlUzRIU4LLOgYA/V
 aHo+bkLFBdQ+afhD7Hf65ElPd7tZCgK4bAQL3A2Yjp/2g4iJo39sib4bpoEylT0GjY2v0SLhz
 KqXTT4atTgR1C/Gw4S5+sH+Xz7Kwu/yZKR3BWH3smtCZrUkBNdhxpFKI6IXxJdOHsdn7oGbho
 RB/Uuzm8D7VlZw=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b="R6tRD/0B";       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Thu, 2021-11-11 at 10:36 +0100, Marco Elver wrote:
> On Thu, 11 Nov 2021 at 04:47, Mike Galbraith <efault@gmx.de> wrote:
> >
> > On Thu, 2021-11-11 at 04:35 +0100, Mike Galbraith wrote:
> > > On Thu, 2021-11-11 at 04:16 +0100, Mike Galbraith wrote:
> > > > On Wed, 2021-11-10 at 20:24 +0000, Valentin Schneider wrote:
> > > > >
> > > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > > index 5f8db54226af..0640d5622496 100644
> > > > > --- a/include/linux/sched.h
> > > > > +++ b/include/linux/sched.h
> > > > > @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
> > > > > =C2=A0#endif
> > > > > =C2=A0}
> > > > >
> > > > > +#ifdef CONFIG_PREEMPT_DYNAMIC
> > > > > +
> > > > > +extern bool is_preempt_none(void);
> > > > > +extern bool is_preempt_voluntary(void);
> > > > > +extern bool is_preempt_full(void);
> > > > > +
> > > > > +#else
> > > > > +
> > > > > +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> > > > > +#define is_preempt_voluntary()
> > > > > IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> > > > > +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
> > > >
> > > > I think that should be IS_ENABLED(CONFIG_PREEMPTION), see
> > > > c1a280b68d4e.
> > > >
> > > > Noticed while applying the series to an RT tree, where tglx
> > > > has done that replacement to the powerpc spot your next patch
> > > > diddles.
> > >
> > > Damn, then comes patch 5 properly differentiating PREEMPT/PREEMPT_RT.
> >
> > So I suppose the powerpc spot should remain CONFIG_PREEMPT and become
> > CONFIG_PREEMPTION when the RT change gets merged, because that spot is
> > about full preemptibility, not a distinct preemption model.
> >
> > That's rather annoying :-/
>
> I guess the question is if is_preempt_full() should be true also if
> is_preempt_rt() is true?

That's what CONFIG_PREEMPTION is.  More could follow, but it was added
to allow multiple models to say "preemptible".

> Not sure all cases are happy with that, e.g. the kernel/trace/trace.c
> case, which wants to print the precise preemption level.

Yeah, that's the "annoying" bit, needing one oddball model accessor
that isn't about a particular model.

> To avoid confusion, I'd introduce another helper that says true if the
> preemption level is "at least full", currently that'd be "full or rt".
> Something like is_preempt_full_or_rt() (but might as well write
> "is_preempt_full() || is_preempt_rt()"), or is_preemption() (to match
> that Kconfig variable, although it's slightly confusing). The
> implementation of that helper can just be a static inline function
> returning "is_preempt_full() || is_preempt_rt()".
>
> Would that help?

Yeah, as it sits two accessors are needed, one that says PREEMPT the
other PREEMPTION, spelling optional.

	-Mike

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/26fd47db11763a9c79662a66eed2dbdbcbedaa8a.camel%40gmx.de.
