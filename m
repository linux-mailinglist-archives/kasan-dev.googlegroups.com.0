Return-Path: <kasan-dev+bncBCV5TUXXRUIBB2NG3L3AKGQE7R7TMIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 36EBC1EC179
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:59:07 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id k15sf18355805ybt.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:59:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591120746; cv=pass;
        d=google.com; s=arc-20160816;
        b=PVH13Y/nLLBIT37mouPuti2zGp3ipm8sCLczBq+qQyamI92Av3QkTddiGulr+0V5ql
         sNQtmKvRpJh9GyjHtUK6Lq+OlbynE3QMI1uCLuQ/kxkgAct1SqTOT+oYuYewiHiiKo61
         KX0Wdw4GHM7vpazfpuNCi/vq0PJMnFHvQhQIHEKeVK7cGGwOhnR/88O6C38jwsoCoH1R
         N9z3z5Jbv127fCozOyfrd4k510y8AVAeKTKpzYbrnXiFczEl8Yc0TKdVV9zGsGitWucG
         nppbid072hEcCwYEJYYMTOLuM/XIO8d/Pa+/2WlbPsLvTyWmSp7Wa74N/DWKFLF2ri+g
         n2MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+9SEMebk1o+QeE40OYbxp0K3rfvZeFYovqv836skYDg=;
        b=pILQBT3UcC8aPKspqmSOTBkBERCD0rFNP8EoHrEdqWtrtu1fJsfcr6X9OpcOOud9Ev
         tJXmESciMpRn1+/I4iRiXVR0wnRcOE3VhNZoHKPvfIbpYJsqg8ott9PSuM05nenTI3gX
         852PwuSeYlQrPhgulzUoK5Ar6bt4d2NRjen/cQrGjIP94cuSS38YqmUzKKG6Q0MjaEaM
         6q3EZFINc2chYSMdIRUxABfvC0jyoJHNVmxzS2Rur1VHzBmX8r08uq6LuArfWUllv6v+
         W+G6DemEUmKCCrw++nzYdvNHGdFsBIhpt5Gb4RBHfrTfUx+h/AL8F/L1fh/GVBlwUR0K
         HhfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=h1ZqR31o;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+9SEMebk1o+QeE40OYbxp0K3rfvZeFYovqv836skYDg=;
        b=RQchiwD6tb9D11l3RSvZrl0vJ0v4qsN3yFcZ25b/ORvU3H4sDl0drFCbx2q/4FtMyW
         1Tla/4G17f1vmWaq54y5NyM7E+DVPUMV5MvlrLzKJX6rqRUbdB98j+67g5cYLK/Z/srF
         d14tWrCAgTSTg+irRWdzjgXQYU6LQNWANgCKWSRoT0n8SIltPs5R66zS6z729QymmJJb
         rPWb2gt2KuttW9lxXGaWZM2yDSx7c/6s69+VD4q+B0ZYeTqVWeiEQhhfH2J/i4K8nR2e
         IzHpFuBpSO3y+14f1K9NRqSxH7sEkLCdZGZe9y3MxipUWmY2bXhLx6MSIl96YgprQfyf
         RW8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+9SEMebk1o+QeE40OYbxp0K3rfvZeFYovqv836skYDg=;
        b=ALcg20N7N4ivGE1rIUANcsi8C/0C9EHQRgXAlrFeVevpJ+tVqjh1jB1IESQzs6X4wT
         zt5nbQLAIwtv4Ny07VqFA4TPzoqkQtRWp/PEZ3j3RVcXkXc22nO8/7VE/IfBwQaX8ln0
         fOx5WsJS8oSpUahFQqMiYyKtslindybZlZ/NdxrffqPTiC8RdUAXXxNLpPPNVkSBiyEE
         iEJbO+WPei/qf+FChXoWCJsB7mlNKQASImYMJVA3dGcqRXnKNSWVFcoyeUxuMesJAmdF
         GCHXPNJRAYNpYqLMHW1IITdVUHj3opeFUvZocZ6EjLH62iqDEizlAwN4WavxhffpU0T3
         r7/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZLwmSCMKrL8w8qIsbfhtu4iPKGOX+lI+paqN6q2AiEtifM+va
	DRi6Z6GjWcfxqkWdGM90Xlc=
X-Google-Smtp-Source: ABdhPJxH5RZxnaTRJphLvLrXDktwr5z/0KWcqXB95wsEotzN2hXU57G5Ol5qjgMPieF8nstslRDKuA==
X-Received: by 2002:a25:b281:: with SMTP id k1mr43085708ybj.108.1591120746055;
        Tue, 02 Jun 2020 10:59:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cd43:: with SMTP id d64ls7144932ybf.6.gmail; Tue, 02 Jun
 2020 10:59:05 -0700 (PDT)
X-Received: by 2002:a25:dfcc:: with SMTP id w195mr27175150ybg.372.1591120745712;
        Tue, 02 Jun 2020 10:59:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591120745; cv=none;
        d=google.com; s=arc-20160816;
        b=lnykKh5xmmSOubtxZF1y5KagCK/fnm1XAxHQ6lhqQCUmignvRk7WAGPb+yTwFBikn5
         1IXUzqCpfmx6WcjDw5fZ1KXGW0XGLR6SESQAOlxln/rQ9Uv3LasfJd5/N5LVO4EbStG/
         S9UXHL4k8ntfYU4v+/BlsN++owpssCfKx+B9G7MaYvSJjEBoTMXr2uEwI7smM5uxt1Yt
         Kbo+Kk1704OJAjRvnxo7J/Lkm69wiVezWtp8VAS8HX6ifU/vSLHauTvCzVz5W2Z5Kgc1
         BOLR6v7PyRXxvNy5bNwS0SD0e3/uDahcTLTLykk2GXB1RYcXSpVtt7uYPrTMIqDQeB0/
         f3qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5Y3HKI5svjaEX0i1wQ6y4ya6URar/l/ginxsdDN/q0M=;
        b=eSsfOJ+ai+lqjfv4gZvxKFHUe1Xc5luEqumjwaNqwLf+3RJQ8n4pBSMIq0bvALk1Zo
         +tVKZ5yhpbCtC+0Sf0mbVe/Ul1rAraFgRQioH9l0GLCw6Y62pQTt2pA6TjKe7tH9Amfz
         8T8tTteh2+/KSnrPj0gEYo/glb62tVyULaHG0ylNjZ4dQPcnD9LXsl2a/A9iBI6o1rb3
         oaGYqayGOLpyd8y//OnFb8sjQRoVmkI1FgUJQVRpOqP0rNIBnlep1MLQsGP9eNudrbTd
         qbg9DJEiGmM/LpFwzWKUPKxjHkL/OA6//7RQmlcz9rHBh8vi22C41LHGI/DarMTwLbbI
         Uo5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=h1ZqR31o;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id r143si7532ybc.5.2020.06.02.10.59.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 10:59:05 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgBBl-0000yt-5m; Tue, 02 Jun 2020 17:59:01 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F3B9C3011B2;
	Tue,  2 Jun 2020 19:58:59 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DECFE202436F2; Tue,  2 Jun 2020 19:58:59 +0200 (CEST)
Date: Tue, 2 Jun 2020 19:58:59 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	syzbot <syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com>,
	LKML <linux-kernel@vger.kernel.org>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	Oleg Nesterov <oleg@redhat.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: PANIC: double fault in fixup_bad_iret
Message-ID: <20200602175859.GC2604@hirez.programming.kicks-ass.net>
References: <000000000000d2474c05a6c938fe@google.com>
 <CACT4Y+ajjB8RmG3_H_9r-kaRAZ05ejW02-Py47o7wkkBjwup3Q@mail.gmail.com>
 <87o8q6n38p.fsf@nanos.tec.linutronix.de>
 <20200529160711.GC706460@hirez.programming.kicks-ass.net>
 <20200529171104.GD706518@hirez.programming.kicks-ass.net>
 <CACT4Y+YB=J0+w7+SHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ@mail.gmail.com>
 <CANpmjNP7mKDaXE1=5k+uPK15TDAX+PsV03F=iOR77Pnczkueyg@mail.gmail.com>
 <20200602094141.GR706495@hirez.programming.kicks-ass.net>
 <CANpmjNOqSQ38DZxunagMLdBi8gjRN=14+FFXPhc+9SsUk+FiXQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOqSQ38DZxunagMLdBi8gjRN=14+FFXPhc+9SsUk+FiXQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=h1ZqR31o;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jun 02, 2020 at 07:51:40PM +0200, Marco Elver wrote:

> We have all attributes except __no_sanitize_coverage. GCC <= 7 has
> problems with __always_inline, so we may just have to bump the
> required compiler or emit a warning.

GCC <= 7 will hard fail the compile with those function attributes.
Bumping the min GCC version for KASAN/UBSAN to avoid that might be best.

> > > Not sure what the best strategy is to minimize patch conflicts. For
> > > now I could send just the patches to add missing definitions. If you'd
> > > like me to send all patches (including modifying 'noinstr'), let me
> > > know.
> >
> > If you're going to do patches anyway, might as well do that :-)
> 
> I was stuck on trying to find ways to emulate __no_sanitize_coverage
> (with no success), and then agonizing which patches to send in which
> sequence. ;-) You made that decision by sending the KCSAN noinstr
> series first, so let me respond to that with what I think we can add
> for KASAN and UBSAN at least.

Excellent, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602175859.GC2604%40hirez.programming.kicks-ass.net.
