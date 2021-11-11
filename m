Return-Path: <kasan-dev+bncBCV5TUXXRUIBB3H7WOGAMGQEYMYBBVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E3F844D5E2
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 12:35:08 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id l187-20020a1c25c4000000b0030da46b76dasf4631712wml.9
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 03:35:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636630508; cv=pass;
        d=google.com; s=arc-20160816;
        b=oAJ7zaowSxajPV55fye9ztb0WD5jImz4KcnzEHWtfDVl8kI7S43Nf2NS6Vq7j68Lax
         OZjnmrt0ZL1pJ0fPNuAHj2pPtSFKyFL06r/yS7f145ix8d6RcqqZ76mqqU1aN3ovD+uU
         1ZsNoKm7lf6uHVAwn0qmwiJQdyvA9X6xAtUpue4gFGwLZzhxVOx9C2GK/EpIemYt4EkG
         FutXRwav0dBk/gciJbsE5LBf3WhMoVaC4tqewJwfuW5VbEb+fig+WZTjp5DN5lnHb1BP
         KcBQWcFpt8Xv6rooyEJdGzt5xpXhxXznNxqLjwFoIhDjOEPrzN6Yoj6Lyd6P5+V/Dy3i
         qtgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=etIZ2z6QiZQ67h4LghDZ8iDoL4/cqW9yZEfP+XDg67s=;
        b=XkMyEenwjA2ndPDU2HriaEfJBk9cO4NdXWjuglCAeRquJdT8afUS7FUniqmIY2cRQB
         9sFgbdEv5hoQetnzNVINwMhXcFEgf8/BNXTMGCc6xYkZmthySGVl8TxhPtgZ0zcVnJDU
         svhYtW8h8qnoOulbGO4o7k79L62BDL1t5htL6kNu5gMdyPpLvZW1O1ZFlXsS0EFOizi/
         JOxMM4g79Iq/2k+drS26R8ga/m2i1PJmRIH7UYOvJcHNysZGzDtUm9WZZrhK890gw7e/
         be2ebtBOpGV+4HRlh81t9J2vTkUFgSDjb2ycTzV3LSAFELaDF4O1wvTjgIk7updNHxUU
         5K0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Y25YDRrK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=etIZ2z6QiZQ67h4LghDZ8iDoL4/cqW9yZEfP+XDg67s=;
        b=g/2WsmxT6cUiL9VCUNteGv4H35rDUJ4PCh6xytefxnJfRYTe2aZm6vx3tKX89syy8G
         oy9aasikuJtxuZuU5haGOxvWCZZepBMaS6dnBVihzZFo/ZYWiLo4IGkMpDcSOzHNlvyv
         QsEnoV+151NTynrviLoGH2xeCYjaqNIiVCitrqUvcVKOKaxJSxfrIE8+YxOReOBuerGD
         5j56AAoYW2enYlp1ObObravzZhjEFnP3TncZEqNS4Zq/G247yTpx/tQ2jDVfjn7c8KuN
         fu9tC0XdsbsYq99WJwayjc5jjzPem94zLra7n0dOiZ30V/MzsWZtQCUhx/1OXyobJKHh
         rmSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=etIZ2z6QiZQ67h4LghDZ8iDoL4/cqW9yZEfP+XDg67s=;
        b=ZGdPC2MWbkuVrfi83b/bxj0MBCusWlSyBXfKTRoHTGhKSI3XsarPot1n0uNOitfdsB
         C9qy5x3FfZu+1ILEbU5vy+DJFMaLq+J4eMh23TP6+XWL+qZL4/2PJ6KFaHSFigBkFxfu
         HjQjR2NdogK7HQAA1/VHlhiiFN95+CdvfSfFx/kr4x1DHTYfab07PrVFxCow6/7OemnC
         EbLo8BkYGToc6N2R7dFMnkU+Na9mxDVEkq96vmg2TjscD2GeAPzEEKHVp12ZMq72oleD
         fad5sCX2PTeNl4ub9jiL6eqoQVUBOElDVR6f5EUqYCxCUj3GDZytqVV8ofQ9AxQBBbVo
         vQ/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x2Ksb2Mr4afMkT6hHaK83MIiht/DjQsxZOI3qV8zNgCxCqy35
	cCr0hxu/Dud2GHbW/ra6aXs=
X-Google-Smtp-Source: ABdhPJzC9FIKBsm315cesjUO1mIlhPRsAFG0ijsdrEvsfBVxxVHJFplp24tOseXEIXwhYEiB8GphzA==
X-Received: by 2002:a05:600c:1c20:: with SMTP id j32mr7230893wms.1.1636630508331;
        Thu, 11 Nov 2021 03:35:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ad6:: with SMTP id c22ls4767756wmr.1.canary-gmail;
 Thu, 11 Nov 2021 03:35:07 -0800 (PST)
X-Received: by 2002:a1c:730b:: with SMTP id d11mr7550489wmb.17.1636630507378;
        Thu, 11 Nov 2021 03:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636630507; cv=none;
        d=google.com; s=arc-20160816;
        b=qcIuJOS78mYiGDVSaTUTQ/uSnPTb7Zppl6vQ62RLHoeyxzwJyk4GdC9cR7Xs7Qbj9N
         caP35f+4G+Gh81pKPuxTtooSziM+DfRCzRs1oKpAHzf4duHIYB7S+xElGr44AVa57Ml2
         u3gV5asHbdVfeEBMoLz2vs671PQ5E7JAIBkfrYUZCt+037ZYICipxMXwRb7JK3RKplzW
         rBFa4m2htge3FJZJ0bFsw4BVGjPrjXVQofSIikHnnoiWay32FT0QSVwcUNovdRLoVYRD
         xmIBkwNzokHV0nyqM++8zRFVlELfhthIf0XloVtysxFFpVdYhBxdhYmp52eIJh1UJMaT
         sY6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PnbX+gQU93tJ4Oopo9HMKbJdOiep79gIINOH60lEP+Q=;
        b=UUqTHBACDnodHas4xS6H9BlakonXeP9TJL9fDPTQdj1WYElo2Lpp9Vs4hBPylSfDHQ
         bgH78Y61x5IgDPa+doIgHpYhCleBc808qilbZelvTYT5HHq3r0PwrijguNcUzc/o3GxA
         pfq/j75RI8ZW0qkc8uCU+TN1BnaPTNClGa9cLsIugIeLBze9Bxtrpah3EAl1aOnnp72n
         UBtkutK26QlnUZviBVcua3BA51pD3oop0GSVWPD/I1pULXaSYWXcLNMJUMPOPmwGU4HK
         LsLU9hD6Pa/Cs93ZP93n/T/3wZFOhArsH3BD3dCxbEwHXo/lbm+jTxadKD8Fzt44BzAL
         dUCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Y25YDRrK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id x20si230530wrg.3.2021.11.11.03.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Nov 2021 03:35:07 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ml8MA-00FSKN-3e; Thu, 11 Nov 2021 11:35:02 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F07A930001B;
	Thu, 11 Nov 2021 12:35:00 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DB9E6203BF719; Thu, 11 Nov 2021 12:35:00 +0100 (CET)
Date: Thu, 11 Nov 2021 12:35:00 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
Message-ID: <YYz/5BgYwHQceKx4@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-24-elver@google.com>
 <YVxjH2AtjvB8BDMD@hirez.programming.kicks-ass.net>
 <YVxrn2658Xdf0Asf@elver.google.com>
 <CANpmjNPk9i9Ap6LRuS32dRRCOrs4YwDP-EhfX-niCXu7zH2JOg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPk9i9Ap6LRuS32dRRCOrs4YwDP-EhfX-niCXu7zH2JOg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Y25YDRrK;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Nov 11, 2021 at 11:11:00AM +0100, Marco Elver wrote:
> On Tue, 5 Oct 2021 at 17:13, Marco Elver <elver@google.com> wrote:

> > So this is where I'd like to hear if the approach of:
> >
> >  | #if !defined(CONFIG_ARCH_WANTS_NO_INSTR) || defined(CONFIG_STACK_VALIDATION)
> >  | ...
> >  | #else
> >  | #define kcsan_noinstr noinstr
> >  | static __always_inline bool within_noinstr(unsigned long ip)
> >  | {
> >  |      return (unsigned long)__noinstr_text_start <= ip &&
> >  |             ip < (unsigned long)__noinstr_text_end;

Provided these turn into compile time constants this stands a fair
chance of working I suppose. Once this needs data loads things get a
*lot* more tricky.

> >  | }
> >  | #endif
> >
> > and then (using the !STACK_VALIDATION definitions)
> >
> >  | kcsan_noinstr void instrumentation_may_appear_in_noinstr(void)
> >  | {
> >  |      if (within_noinstr(_RET_IP_))
> >  |              return;
> >
> > works for the non-x86 arches that select ARCH_WANTS_NO_INSTR.
> >
> > If it doesn't I can easily just remove kcsan_noinstr/within_noinstr, and
> > add a "depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION" to the
> > KCSAN_WEAK_MEMORY option.
> >
> > Looking at a previous discussion [1], however, I was under the
> > impression that this would work.
> >
> > [1] https://lkml.kernel.org/r/CANpmjNMAZiW-Er=2QDgGP+_3hg1LOvPYcbfGSPMv=aR6MVTB-g@mail.gmail.com
> 
> I'll send v2 of this series after 5.16-rc1. So far I think we haven't
> been able to say the above doesn't work, which means I'll assume it
> works on non-x86 architectures with ARCH_WANTS_NO_INSTR until we get
> evidence of the opposite.

Fair enough.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYz/5BgYwHQceKx4%40hirez.programming.kicks-ass.net.
