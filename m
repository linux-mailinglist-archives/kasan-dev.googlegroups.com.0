Return-Path: <kasan-dev+bncBAABBA67W3XAKGQEYXZVDBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 229DEFCEE7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 20:48:21 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id z3sf4570931pfk.22
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 11:48:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573760899; cv=pass;
        d=google.com; s=arc-20160816;
        b=p4ATBe3OLwRMgqhhQptvdH57EWN/O6uGFCixMa0Z2LqJBp5pSWhPSlLGQ+obb6ahPb
         bQhn1BPc0BfB2cJ4LiEpp2mPfJhRlATie6aHnR8iT/Pqns/4XxIaUEotTAUxgIa1ikXf
         VPVgFtbp2FO7eW+LJwWZnQrPGhPuaDY7vNNiCP0LMXzQGevQtbUCmvLS1NIKmUmV2h8N
         nQOH0gB9h3s3wS1CRYkxxOUxDXDLwk26pYmXqdLoETLuXB5oMU1PnaBhe12vPgV9UKRz
         TiANwqNKCc17gG+Buvcf11MHL/ZYFNUnVgVMMGmsNHq0RRoF2x3LaWmUs+9W3egfDbew
         ZbpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=mM3w2fQAmiG5vP2osqdp31Hzg43EnPpydV0QvWu5jio=;
        b=0Uec5jwAhFciNN2jzBBmXyfF56fdMMlcYPZJfxBkcM2YWoq3OBiVgE/dHAUTS7mcp0
         ZVkMu70C6n1tGJ40Nuh2UcqAZmk/nAx8dLd2QJ8GEnY/YEBoEntbgT62qmXDhPwrqJPJ
         HcATZgRLIhepaDR3LTkCQynPs1UnhbEesNwdbIGRjaOxy7lHP1RWcQsxAxKRWv6MIZd4
         y6SE9LqOr5BFNRgsqm0AmFD5TNAmPRFmENYnURlLsF0SomywD4es1GwjKOy7ckVK5C1G
         OX7idpgbb2BcVVVI4SxgpRPD/QexJZ/YMr66jyp1l0LeZyyKji36YdAOPpJ0J18fOJRt
         PmPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=cdfsnpNA;
       spf=pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mM3w2fQAmiG5vP2osqdp31Hzg43EnPpydV0QvWu5jio=;
        b=KsSRLLzVra5c3C7ENU2Bhg6F9VClM/3xXB6zS8eqaEzKLV52+bf8prih54VDFtdpzU
         HP4BU7vlORbg9MMW2cVxzLJ1pqGrIvo0dupAC8riey1nRVZWxlMm8X8mNQtF7/EnMYjK
         8fm3a0HiQ5m1iZFzF5RAclfukFAz3rEGppWQWN+ylAL+RR2iaWAEIQVW235+UaADPm9j
         XYIxIuDWdtBx2vpPOm91elLqNnZgPhX5ELP0G3MRZMfQY206OO8y5i2KzRpEBX1tx1HS
         5/bCg2cXBrrUjdl808Z0SPTSAyCDBDyOKbVAUdL3+KRmZRMqLLNn9yeCaIHusKFPncus
         ye7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mM3w2fQAmiG5vP2osqdp31Hzg43EnPpydV0QvWu5jio=;
        b=ZPAOQU2RWPgspMp0HWFR+oYj1x4RoNlV7XYPYOaUMYg6UznisLtOX7oW24NouPSmUP
         Z6/Qje0nP7DOBWsGySt4nhBL1EUW+TrkAYH9Z6ptKnh+du+blR0FapZKhN4v7CZt9RFS
         Ti5CCzA+FqZ65055ySzTwZ0lnY31AgiFCln+yYeQuiIh5+Ho1AcQTenepe7WvSK2fEfD
         kNlkowUyH5eseIO2D5BgZQuM7MnPCUxZqfm9qq8RCdsD4k82u9aP7XbD+J8weAm2L9HY
         YfJYG9KNSMlp1E9SgcgZhZT60jLwab53CyfGlGXF21TUbfbSheozuV+pjFVkphPkonA1
         zOmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXmWpGC4p8WU287EP16RvOHj0gWKkAlOskJwbJ4lOEQ6yxLFIf4
	l63r0P5DBn13pxmXRs9/Mww=
X-Google-Smtp-Source: APXvYqzUN9WrKJ0RbgwlORGepm2Va23+mFn2CFL7cYbCGuhGd7ODmmB9S1/IoaQArnIlwAcfk2OUMg==
X-Received: by 2002:a62:1c89:: with SMTP id c131mr13124146pfc.168.1573760899574;
        Thu, 14 Nov 2019 11:48:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a70b:: with SMTP id w11ls1043664plq.3.gmail; Thu, 14
 Nov 2019 11:48:19 -0800 (PST)
X-Received: by 2002:a17:90a:1f0a:: with SMTP id u10mr11629192pja.49.1573760899310;
        Thu, 14 Nov 2019 11:48:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573760899; cv=none;
        d=google.com; s=arc-20160816;
        b=QRZywnQqqKw7fBv6ZPigMxiW/jn0WMi7MHOYfad95hmcidodkAOBFyDF5sc5vLVJrg
         UAxh4/g92f2QpsV5S9FwEfYdC+9K+wAQgLHFeJ5hzJUD+ln3emSA5UMaU5glRv9DbHgf
         pFuvS0pqRw5YHAmcwuz/DylioKL9CpjtScPRWe+rPkY08WyTdYJEQ773J+leSozFL0xh
         ZD5ga+VkB0CjJtVO0NqPSpfXW1u3/n0ieceKcrmXwByOudOImkah3EuFnrXT4hYefCcU
         PqZ3Gw8K7OVwvAxZeiupwgvKdTrh7T1hqZ+h0gr5z0cGsE9N3341pNvYzMsEKxQpoIq0
         QL9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=E5sI5xoyIyHQyKEBx6ll3ltuHGTT9SthmS+OsvaTnp0=;
        b=p+O/YESLA4FKkOkwcqjQceAnwXxIiSgnsnfzX8eWV65q7JijBm4b7PIFS8dAaZ2Kl9
         nc1pcTMwr9xi//yTdkmVXiy3rG6xMUn8IIQx3AzSyzit9Oo3Ufqd+uqvAVtlSzcHoaun
         wsDH8AvbnPQOTEn/EmNIdWyCDLf695D2/AefAfUxPjfFY2uzfq7cuE3tJck8Me9CSGw3
         e3F5dyluM22Gryrcer4QNQWqL+j5VZcFQtwWkTEehf0la6jSaVKa2bs+9LgfBFiIlY4p
         ZvcCbtGBw4lUjhXvgsCYnDA6dgQdlsR2fcPtMPWFOunPUXY4LSDQF5HDTLx4Vi/mOJt3
         iS5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=cdfsnpNA;
       spf=pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w63si217389pfc.1.2019.11.14.11.48.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 11:48:19 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.129])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DDE2720727;
	Thu, 14 Nov 2019 19:48:17 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 7C62435227FC; Thu, 14 Nov 2019 11:48:17 -0800 (PST)
Date: Thu, 14 Nov 2019 11:48:17 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191114194817.GO2865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191104142745.14722-1-elver@google.com>
 <20191104164717.GE20975@paulmck-ThinkPad-P72>
 <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
 <20191104194658.GK20975@paulmck-ThinkPad-P72>
 <CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno+o-Fe+7OYKmPvCboQ@mail.gmail.com>
 <20191105142035.GR20975@paulmck-ThinkPad-P72>
 <CANpmjNPEukbQtD5BGpHdxqMvnq7Uyqr9o3QCByjCKxtPboEJtA@mail.gmail.com>
 <CANpmjNPTMjx4TSr+LEwV-xm8jFtATOym=h416j5rLK1V4kOYCg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPTMjx4TSr+LEwV-xm8jFtATOym=h416j5rLK1V4kOYCg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=cdfsnpNA;       spf=pass
 (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Nov 14, 2019 at 07:05:34PM +0100, Marco Elver wrote:
> On Tue, 5 Nov 2019 at 16:25, Marco Elver <elver@google.com> wrote:
> > On Tue, 5 Nov 2019 at 15:20, Paul E. McKenney <paulmck@kernel.org> wrote:

[ . . . ]

> > > It works for me, though you guys have to continue to be the main
> > > developers.  ;-)
> >
> > Great, thanks. We did add an entry to MAINTAINERS, so yes of course. :-)
> >
> > > I will go through the patches more carefully, and please look into the
> > > kbuild test robot complaint.
> >
> > I just responded to that, it seems to be a sparse problem.
> >
> > Thanks,
> > -- Marco
> 
> v4 was sent out:
> http://lkml.kernel.org/r/20191114180303.66955-1-elver@google.com

And I have queued it and pushed it to -rcu.  It is still in the section
of -rcu subject to rebasing, so if you have a later v5, I can replace
this with the newer version.

I am assuming that you do -not- wish to target the upcoming merge window
(v5.5), but rather then next one (v5.6).  Please let me know right away
if I am assuming wrong.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114194817.GO2865%40paulmck-ThinkPad-P72.
