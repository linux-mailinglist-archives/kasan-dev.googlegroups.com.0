Return-Path: <kasan-dev+bncBAABB2G4ZD3QKGQEGCAX4NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9792C20573E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 18:31:37 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id y1sf16141465pff.19
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:31:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592929896; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLksG7BU3owW2fdAVpluOtW4eM1YWc/yrUosVLoOneOdHctqb5iTkDFXtD48jKWMov
         fPIrA/dOTmzWF6PoVEw52sPKYCpBXVDvL0glmWHHhID498Lu4Qvi6OrydLXZLCJT+HYC
         25zKtX1t2jKKhorqb/7Zq1oMnLEFfbABg0HiU7l37gehEQ+lO3SV/ZlczeyTUCYWDx/h
         1pr1ZTxp9hQ6Axb/scrkZbNF/jZ8iT/vlpNWbMEM25SdgGiWqPML4xAx33MopIOl41iZ
         MQz5Tf87a+bIIwCXsZlHeLOz4ShjKp8ErprU9RWVrlhJyqnZlmf5A5iEteGuxZ7s1dWh
         R8KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=13ToxZDwcWUmyU/SOdc35saBmeK2hgGrga60fZfZFis=;
        b=u2jjUHPGcHEB+lnT7NEyLJJUiPLAjIVCltnTEj885Rn08olPU/VU1wHs+0JqVOH05o
         Dc8NB7vp4sx1Wfsj/iqZ+AXGnRWw3G6396z03Gh+wghoUs6TG6S/vVRXICWf6netLz0x
         R9QYKpzY1e/ZONhlfHob4qUkLz8Fv3oWTzuJNMqBTTolvbqP3SFd9c9PjIIDBqgkGhAq
         bR9ySWZ5qw/99R1wg3O3VhdOdIlswyyV/5tc/6jQRBxla7734bepNd1emIU/X6Q7MGww
         HHUQvD/PP4NMlrpn3OpSU/9NCcIv283nu0ngSPu+ocDx6tcNNguZnDoH3LyZwbXFQYbJ
         I/ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Y0lWgEkH;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=13ToxZDwcWUmyU/SOdc35saBmeK2hgGrga60fZfZFis=;
        b=TkfXv+jB1CaHysBDm9YfXzDK5GI4l9i88efD0n43NAJz5FCnF0uXf/MzAtAa43cQd3
         +46Z+iyF4HuLJbL7Ozt+0Gbdck2sHY9Te+n+77GqE5AytVh6PQQcHv6bcK7pjbZd865p
         ECjCaotmipoI0EpT1m+Yk4RZcYuvJ5Q3ay6DWWRuV5zwkKrYerxTm4sfx1Fo+fne0Gm8
         dsBkNqY1RE5oW3iN8HZzP/YiYN8VJdotCZ/yjqn7qulvB2UGarlY2/lctwZ/q+tOmHLS
         9Q1vjxvaFxRmL/vpvA86pk7x5HwL88TZci8Sxe+BFvwBcEc07IO4/RIgm3hG2J2qTKXg
         ml+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=13ToxZDwcWUmyU/SOdc35saBmeK2hgGrga60fZfZFis=;
        b=DFW9yYqwEpd9gYOVDhsXmTDQ9deYjvK4jaB9v7yf0vVV94Zcw+0oGRhElFJExfSgqp
         kTI3mzrzlC44e8jdMyCS6M0yrLJfEqgp/SOFkGWtPHugWL2BTtK4+fYHchmKx6OYwB7S
         2fK8Ic8tEBOA5U/6NH0PI4tiqZ4u0n4khLKtX7hbhxI0Z9V5JuSqYC91/vW+U/eCu1jg
         pBD7cp4wcn/rXE1g5a2qGggpaU/cXu2X0KQZFIZ2qB0vJdF4RvgMKvh8OYkjJJQb/pr0
         MIIznt3mLPW0og1/5ct6zJo4G60GpE10V0a+Xja9SklL2zIbUXh3OsFAO+zTgpQmudHp
         CHng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533efoG9GxKD4EJTnpWg/CtGF8FFHdhtGF/x/KlJHeBpyekuVq2p
	Gc6tIFcriZHtzeI7yAhAwZw=
X-Google-Smtp-Source: ABdhPJw2PbFER2FX8F2SskS6PPY0QhwN/UYv4Ft3fYQ3cJ47jK56IYU0z3SoSiNtFaKWaQrSb+AA4w==
X-Received: by 2002:a62:1d81:: with SMTP id d123mr17428703pfd.38.1592929896174;
        Tue, 23 Jun 2020 09:31:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e312:: with SMTP id g18ls6857423pfh.9.gmail; Tue, 23 Jun
 2020 09:31:35 -0700 (PDT)
X-Received: by 2002:a63:e018:: with SMTP id e24mr18204079pgh.103.1592929895827;
        Tue, 23 Jun 2020 09:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592929895; cv=none;
        d=google.com; s=arc-20160816;
        b=qexIER/+FuxblrPRdjihzeZyEa3ZnD4soco3eDA7iEh/OQId9QFMIbzeFsVJUFiAwd
         wcAhxaIBNbnzpw/QAx7ADBqOVKb+Dcfu5Ztpg0d3OsQCxhhNgBgojFUqu/sZGL3RrKZJ
         xdgUehmtdKK3ik8qWd4LyN0Pi93QQLiv82KjhslzQU2AUy9c2SywzOTVAEXMqjUT05Lb
         a4gm+EYAS3/EaytrzpbIyxXo0cqBqOfGxLLsl32oThDuX3fdF4NW00ptNhpeaDV2FaDU
         em1ehPhI01hnsAZk+8Mh7PHe5c+vLMai3WibOTaXplmc6r+m+2oEskBE+k14wIH7D7OV
         b+2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=bXZmyqbk0BJJ03WSdcOqsLtyQawQh1CMc1cxUuUpXyI=;
        b=VDn65JANyB0T99t4BmYkTIXvzy/WE3dMcCdoc+H1ZiM4cMbxBMHFe0RmCgWqW0gNNy
         GZrlIOZLQ7KjOsFs4kC89yXlHjWX78KaXWtZ9oWAG5Hk1sMfw6nSI3Qn5TjlJcasclUf
         xNvxJaZV/tmD1a13yAQcg5kvmKQRQmagDvu7aISaqNikG5BAA7Z3dvfPmFkwBr5DXMdg
         mpQ0UisOgEK1HJtndb1utsSp8MLyNj0+nqsmz2yFygSrznoyBtwFyXrVW2PWIum3JvZk
         4B0xiBR4ESR9hLbcUWp2Tg4Yq+3pFOCCl/SCI3fCP0sa0HfMehlFTuUfG8sQpzQBJ7QW
         CP5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Y0lWgEkH;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g10si830957plg.3.2020.06.23.09.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 09:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8DC77206D4;
	Tue, 23 Jun 2020 16:31:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 77DC83522657; Tue, 23 Jun 2020 09:31:35 -0700 (PDT)
Date: Tue, 23 Jun 2020 09:31:35 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com,
	Ingo Molnar <mingo@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>,
	Boqun Feng <boqun.feng@gmail.com>
Subject: Re: [PATCH kcsan 0/10] KCSAN updates for v5.9
Message-ID: <20200623163135.GL9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200623004310.GA26995@paulmck-ThinkPad-P72>
 <CANpmjNOV=rGaDmvU+neSe8Pyz-Jezm6c45LS0-DJHADNU9H_QA@mail.gmail.com>
 <20200623134309.GB9247@paulmck-ThinkPad-P72>
 <CANpmjNO_2N5PB6MOQqEgpwNKmTtLrSNcY+-a2fVncESyjuO=Wg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO_2N5PB6MOQqEgpwNKmTtLrSNcY+-a2fVncESyjuO=Wg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Y0lWgEkH;       spf=pass
 (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Jun 23, 2020 at 05:06:26PM +0200, Marco Elver wrote:
> On Tue, 23 Jun 2020 at 15:43, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Tue, Jun 23, 2020 at 08:31:15AM +0200, Marco Elver wrote:
> > > On Tue, 23 Jun 2020 at 02:43, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > Hello!
> > > >
> > > > This series provides KCSAN updates:
> > > >
> > > > 1.      Annotate a data race in vm_area_dup(), courtesy of Qian Cai.
> > > >
> > > > 2.      x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.
> > > >
> > > > 3.      Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().
> > > >
> > > > 4.      Add test suite, courtesy of Marco Elver.
> > > >
> > > > 5.      locking/osq_lock: Annotate a data race in osq_lock.
> > > >
> > > > 6.      Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.
> > > >
> > > > 7.      Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.
> > > >
> > > > 8.      Rename test.c to selftest.c, courtesy of Marco Elver.
> > > >
> > > > 9.      Remove existing special atomic rules, courtesy of Marco Elver.
> > > >
> > > > 10.     Add jiffies test to test suite, courtesy of Marco Elver.
> > >
> > > Do we want GCC support back for 5.9?
> > >
> > >    https://lkml.kernel.org/r/20200618093118.247375-1-elver@google.com
> > >
> > > I was hoping it could go into 5.9, because it makes a big difference
> > > in terms of usability as it provides more compiler choice. The only
> > > significant change for GCC support is the addition of the checking of
> > > (CC_IS_GCC && (....)).
> >
> > Very good, I will rebase the following into the KCSAN branch for v5.9:
> >
> >         3e490e3 kcsan: Re-add GCC as a supported compiler
> >         03296de kcsan: Simplify compiler flags
> >         d831090 kcsan: Disable branch tracing in core runtime
> >
> > Please let me know if any other adjustments are needed.
> 
> Looks good to me, thank you!

And updated on the "dev" branch of -rcu.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623163135.GL9247%40paulmck-ThinkPad-P72.
