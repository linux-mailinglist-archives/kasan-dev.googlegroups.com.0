Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEEZT37AKGQELBTLDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id DF6EB2CBD3F
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 13:46:08 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id f2sf2980542ejx.22
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 04:46:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606913168; cv=pass;
        d=google.com; s=arc-20160816;
        b=JXdiREboLvCUxgndtzYnx55qTkDEj+reqiJGGPf+6heTLqfUTIyT6nWtNurSBO9cyY
         Ndt6BinpEzXP/ErosBYKTN1wK8/QxwJ9/r8OClslWVxAnYp9vE+vNkmxOvd67ep72bFK
         N17M8chAWdbaM+E12xEBNQKNfXHQQBETPjvk5fIsZoBkhDUQFT1zstz5C7CP6Sa2j0zg
         CxO5DiFythrzElzdjTVfXwa9h/CHepy+GFk+MT7AGDIzeLCAU7loRawvP7YSXk/dBbIT
         a1GqB1dCGC4ArHgz12fFYaAkwT4Vnjpej2e8jpOG4LlVFBoHraxjxYuknKFGXE8WjSxC
         Iq+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=dGAsQ2EZaLnm8FjrrJtFh/N48YbxcVYwB3b9NUU6cG4=;
        b=wA/CFw87XXutWfoED3NB3eN/pMI9WDXt0G7uLOqwCz03x7ftLeMiLXea90E8gS7K9j
         lo3Va1qaLFPfIRSjrSUhbEruKT9gx0ZW5rKGcCeJY+F1V5vyHD0FSbxRq+S4pg2Gtqur
         1MPqypB8ILDVXULo2xray6Q/PVA92f49yj2M8tH/9DNCKVrW2HWTwFXeICUWeDoazDh6
         pesg6rEivn4LMuAHBTtAvYH/CQYYgZfqO6PH/tqSBsAOtsvPiPhL36Xg0gSJGPQOdH3r
         MgIsxnssXt0YnMeuHfeymuLOs6p5AT63YWhUGy9AqW5f0vhuFOhy4sHKvu3rOewAtP+O
         vVqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hGq9Pbcb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dGAsQ2EZaLnm8FjrrJtFh/N48YbxcVYwB3b9NUU6cG4=;
        b=cmP7LHZKBAZj04IcCjrwZyqB8oMyAbtILQzmNx3k/LAy5AbTWC2d92qupwqyU+VnYu
         IwuLiG+qvqWgNPxZ0fzhqTW1QO7SaB/047aZNx7Oro+87rrlM1BHNp6Q214UcXzd/9kA
         BklNPbaZ4Jl1VOoc3auC5JpSAnzEu5lIdSqKzGfV9eS18UOoMjuTjrjLM9SeQwHw4wmr
         lJjvEQ/BoADQXfd7dTeNpQJ2oz5+pdgBuVye0Q5qwCWPE+t9oe1O0KDeEvsAb/Mnn18t
         PKFZxtPuqDcxzJQX6XK4ONaPO6vW3U/ygPVlUTaBfA4vKwF1afkgfH2p/MGImgyI/oAJ
         LpSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGAsQ2EZaLnm8FjrrJtFh/N48YbxcVYwB3b9NUU6cG4=;
        b=CTxGLTVgt0zKxQX/8Yra2bnNWl6QUWTjJmbTJPLU+KWMv4KPws34WUAZlechB/z/jF
         dx0J58L31B3qP/RC5+KFLv1vQyl288tN8i9Jac/YdOFBEg/aNhw71TSximTB7tO+2OSV
         pDtVXGgZItc2gWItTxfWRo6oWQed1KTDNPNdNl6l1ZtwNJlNMMql8jRfvom+mCnD+Svx
         Yp25XrFY5YWocFA9Y/lBoq+MX77Gne2Fgot1TkcZzmnz2k5JZ3SYHGOhZOjZ65+d0vRw
         UdUPhHY5mRohmEEJY9o8AV2N2jDkI3oehCRrFgytJQO1m41GxhPRh4knFXA8Fp7qBY4L
         K8cQ==
X-Gm-Message-State: AOAM532R6fXMKH9rOR4KMcoioH4sQz7s8wEVjtocCihJ6XNH561SNQZl
	RVbwySEO87aw70BO46byp1Y=
X-Google-Smtp-Source: ABdhPJyiiAjQyEyR9pAhauU03JLMAbwLMnbASApvOp/GR9zwT12nvAOczNrDDnlBQ7FWcOQD9+uGMg==
X-Received: by 2002:a17:906:e28c:: with SMTP id gg12mr2211860ejb.74.1606913168705;
        Wed, 02 Dec 2020 04:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd15:: with SMTP id i21ls1585237eds.1.gmail; Wed, 02 Dec
 2020 04:46:07 -0800 (PST)
X-Received: by 2002:aa7:d6c9:: with SMTP id x9mr795907edr.96.1606913167706;
        Wed, 02 Dec 2020 04:46:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606913167; cv=none;
        d=google.com; s=arc-20160816;
        b=x442AVvzIy0lq8IIctBflO14ytgSnF27htDizkN/uPflaGmUNFSF8zO+mX+aip4tno
         uYXyzjq+kgpiqrnDrEawFvLQAKa1qVCrrIh+cJESrD/59wP5dua8ZA24ZO4jnpPXIQBB
         8vm/NRch2+qFJQQ8K8hOYdkLi6ss4C7pbJQmap7R3UOLeytrvAkuLo8wcAilTRhXDq6g
         5PP7v621wmhleno3Jwyy4khZgxDZt9vYN5I7TXEhNPAGLfQ49mhdmtkdfwN3Wts1i0Lp
         PkPOW1Pm47RL8HWVhlW1rTspaD3bYBK5zi2zTpUTNog0J4juTIYAWe55YSA8aZKrl/+k
         n/FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=JMXEOWWxx5MozsU4h0iRRlvceWnNx2T359aAQ/QO3yw=;
        b=dLiQI2n1MLJyVG/Jc3uSxw1wwaoWRoGkBdR8fTSHu926TdL/yKHqzvY4vVmbPMIQU9
         A8PIKIuX9yZKHTUbVV9a4izjeLOABBZSI8LCXjEVHy6wkxjmW874OFrakRglkX6c8/mc
         QPsdwaZ16ICGezNNNAMvacutexvR0Mmw084SWVVubzj+TSvu34RMdObWtYcBRibi++tB
         3p41lYpsXHu9Y4uzSxA0GIevkK3JXItIGNl+FDn0xWDYItuZe5giMaWnDKUt31I4zWDS
         Rh7I6iYzWGS8SP0h6GcvCzuAWkdB0HMqXYFvbe1KFik5EhJsT4PrXPIPCSM74Phj819o
         HOhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hGq9Pbcb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id r16si72115edx.1.2020.12.02.04.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 04:46:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id k10so6816609wmi.3
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 04:46:07 -0800 (PST)
X-Received: by 2002:a7b:c308:: with SMTP id k8mr2959505wmj.76.1606913167261;
        Wed, 02 Dec 2020 04:46:07 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id m21sm1885898wml.13.2020.12.02.04.46.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Dec 2020 04:46:06 -0800 (PST)
Date: Wed, 2 Dec 2020 13:46:00 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?utf-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Any cases to prove KCSAN can catch underlying data races that
 lead to kernel crashes?
Message-ID: <20201202124600.GA4037382@elver.google.com>
References: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hGq9Pbcb;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

Hi Dongliang,

Thank you for your question, which is something we're currently
exploring ourselves. We're aware that there are currently numerous data
races on syzbot's dashboard, and it will take time to sift through them.

On Wed, Dec 02, 2020 at 08:05PM +0800, =E6=85=95=E5=86=AC=E4=BA=AE wrote:

> I am writing to kindly ask if you know of any cases or kernel bugs that
> prove KCSAN is able to catch underlying data races that lead to kernel
> crashes.

Have a look at the last slide in:

	https://github.com/google/ktsan/raw/kcsan/LPC2020-KCSAN.pdf

> Before asking you this question, I searched data race bugs from
> Syzkaller dashboard for my experiment. On one hand, I tried KCSAN crash
> reports, but it is hard to locate a PoC for reproduction. On the other
> hand, I found some race bugs that trigger KASAN reports or WARNING. Then =
I
> disable KASAN and enable KCSAN, however, In two cases(65550098 rxrpc: Fix
> race between recvmsg and sendmsg on immediate call failure
> <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commi=
t/?id=3D65550098c1c4db528400c73acf3e46bfa78d9264>
>  and d9fb8c50 mptcp: fix infinite loop on recvmsg()/worker() race.
> <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commi=
t/?id=3Dd9fb8c507d42256034b457ec59347855bec9e569>),
> KCSAN did not report any problem during PoC running. Finally, I failed to
> find any cases to prove that point. Therefore, if you know of some cases =
in
> which KCSAN can catch underlying data races that lead to kernel crashes,
> please let me know.

In the following I'm outlining some background, and my current approach
to reproduce some suspected race-condition bugs.

Just to make sure we're talking about the same thing, first of all, I
want to highlight the difference between data race and race-condition
bugs: https://lwn.net/Articles/816850/#qq2answer ("What's the difference
between "data races" and "race conditions"?)

Clearly, data races are defined at the programming-language level and do
not necessarily imply kernel crashes. Firstly, let's define the
following 3 concurrency bug classes:

	A. Data race, where failure due to current compilers is unlikely
	   (supposedly "benign"); merely marking the accesses
	   appropriately is sufficient. Finding a crash for these will
	   require a miscompilation, but otherwise look "benign" at the
	   C-language level.

	B. Race-condition bugs where the bug manifests as a data race,
	   too -- simply marking things doesn't fix the problem. These
	   are the types of bugs where a data race would point out a
	   more severe issue.

	C. Race-condition bugs where the bug never manifests as a data
	   race. An example of these might be 2 threads that acquire the
	   necessary locks, yet some interleaving of them still results
	   in a bug (e.g. because the logic inside the critical sections
	   is buggy). These are harder to detect with KCSAN as-is, and
	   require using ASSERT_EXCLUSIVE_ACCESS() or
	   ASSERT_EXCLUSIVE_WRITER() in the right place. See
	   https://lwn.net/Articles/816854/.

One problem currently is that the kernel has quite a lot type-(A)
reports if we run KCSAN, which makes it harder to identify bugs of type
(B) and (C). My wish for the future is that we can get to a place, where
the kernel has almost no unintentional (A) issues, so that we primarily
find (B) and (C) bugs.

It appears you were trying to use KCSAN to reproduce bugs of type (B).
What we need to understand, however, is if the bugs you have been trying
to reproduce with KCSAN are in fact of type (B) and not type (C).

That's the high-level problem out of the way. The lower level problems
pertain to how the current default KCSAN filters numerous data races.
So, when debugging, my default recommendation is always going to be to
change the config as follows:

	CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=3Dy
	CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn
	CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn
	CONFIG_KCSAN_INTERRUPT_WATCHER=3Dy  # add this after trying above

Then, as you run your test-case, gradually decrease this value at
runtime:

	echo $SOMETHING_SMALLER > /sys/module/kcsan/parameters/skip_watch

Alternatively, or in addition, try to increase
/sys/module/kcsan/parameters/udelay_task.

For debugging purposes, it may even be fair to insert
ASSERT_EXCLUSIVE_ACCESS() regardless if the bug should manifest as a
data race or not, as it can help highlight what you're looking for as
the reports start with a different title "KCSAN: assert: race in ...".

Thank you for your interest in this, and hopefully you'll be able to
proceed further using the above -- please ask if you have more
questions. We'd appreciate if you share any results, as it will help us
understand how we can optimize KCSAN to detect more races of types (B)
and (C).

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201202124600.GA4037382%40elver.google.com.
