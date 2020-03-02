Return-Path: <kasan-dev+bncBAABBWVA6XZAKGQEQBNRCRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B4B1762A4
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 19:28:44 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id w4sf155437pjt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 10:28:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583173723; cv=pass;
        d=google.com; s=arc-20160816;
        b=SqqSKDRtPPjN+4SYPf8sBtFdgiGRNQxu/pim8dYurjXzk/bMjO/87ES1+hIoEp+4sP
         hJ8HYYnEQcsjcvj7Wimvbj8AIcEHcgfukwsPjXZtf/LZSiWfpP1CfZDw9BFdXGKwHSWm
         Le1IyBPkdv3avo5BZYiQNC4RL5fqIapuWzW7qowIbEgArF1sc93ucBbDZjAHAkfhJLr4
         YpXblq/uCUfpS//Ag1uAWrV+WYBAjqzS1OChp3Wg6VUeX82XFL0RJJwpPk3GXkR5U5h4
         0TylAFzLiRc1viOxC1fOwqtkYFeTT6maq1Mwv01aFbyO3pD/bS6FE03ualZRRxDq6vt9
         FQjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=0XbPgyYePq6f4WGeEb+pcfkQ0H3imScZAbUN9N+KfRY=;
        b=nvTyIuZKkkWPTCv9yU4mrcF9wJM74Jp0vcJ2MpLzaJYbx1DzNt31AUsK/x4otp0AGC
         u11qdCYBGDAh/JyfeAOLnd5ijGqGZ+66IPSIHDekC36Alv8IcafatueIwfz6C+Ax2145
         MGYJ0DJgLzj/F+KX5TZFgt7do6rP6a7IeQ8Mkd1/60oEM9xHB/SxS/IQsXF26KQng3aA
         D2gQeTCecegEBhViL9ScZ/gZl2mx8hJCSpy3QvBYM/F0bwl5kC4lzsSYWWg6HHtPyDmN
         WNMDegpXjbHxSuvqmq31lEgqshUfIlpbnV3OeXv/R5Y8xj+1LqzoAoNcx//Xfpa+TlZM
         v+/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=A8NiIANr;
       spf=pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0XbPgyYePq6f4WGeEb+pcfkQ0H3imScZAbUN9N+KfRY=;
        b=TsUErRVep/nd4kAvbghdqfJSLDR4uZpKhkmMowc6yhuzM+OFuKikrd5rGaFWU7vDvA
         ZShqGxF8jfDBoacxK36lliV6KgMirBG052Cpk3nlT972HD76ex5UC4T4VlG757qbmMjh
         WKl/cS6P6cWApMNgIF+NypmEFczSjy8fwgfUJVwx3TXlBXmx1tFnVSrjajSp3KasHdhL
         8hEUnQj5wfyVyeM4H9dI6lck/JqRTr2ZJVi91w4hPLXA02zzQEOGQFWMVgEDOBgUw3mh
         EJ76gWTjAdvEK2ySQe30rQ2ncXT8C0L7zOGyeQ6okHUREHEosrJ581pivT7bEaVKFdLb
         vPzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0XbPgyYePq6f4WGeEb+pcfkQ0H3imScZAbUN9N+KfRY=;
        b=Twj3NWhYmPmjCVbCdgQlbCPC78zCeXU+tqq8S0lYgE9G8vCsYSgsy8ohDcb5XZymUJ
         T+A+EfO4F0T5YMskSjbm0Ukw3ezHOXhwEs5LMSamtUZNJaY7GR/lLo/LBqH31TXzwidw
         WpjeMkLr75hWFMwMI9oNrTFgJme0v3YxyO5dbaCdMpRc4Inel4wRDMteFkVpke6hd3OS
         K8bADDS6cMuXiLfWl9xMbVUbJk/5nRXouvrb+jBkuqAGoNZ/g4ScTfO0xZ8Jlgw+1WRl
         LckAg4VciwGdtDefwYRhfLni1u/f4YnU/vQefV/3Emh+0macB3GFyTKadbAa9CzXNspr
         +6CA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ089/ldQfwEdUVknLGWZ5aMTri5X1ge7cREZ5UV7zvPad6ZyN3r
	qXyA2jmCeFcZ0SUBSwH3Y6Q=
X-Google-Smtp-Source: ADFU+vv4XNqdeFTZEf/usazRKrbsjghc1dGDASlFieRaoSDg8FluvVzSp33uDvAPlHQqTJSSVUHz1A==
X-Received: by 2002:a63:e80d:: with SMTP id s13mr233723pgh.236.1583173722896;
        Mon, 02 Mar 2020 10:28:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:934d:: with SMTP id 13ls59275pfn.3.gmail; Mon, 02 Mar
 2020 10:28:42 -0800 (PST)
X-Received: by 2002:a63:ad42:: with SMTP id y2mr171177pgo.445.1583173722521;
        Mon, 02 Mar 2020 10:28:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583173722; cv=none;
        d=google.com; s=arc-20160816;
        b=vB3xu9eMdrODuGtcltB/MM48nTX5iFvxiZP+sqTXTJLcl9rK7cN0cxO56jK+QPtwfh
         TVseAmNo4CJI0DBuGkkkTirNt8NYa1WUfPDRSZ1ZawO7WzLwDcVhMsRIkPBcF/CoR7Oo
         Sz2cCOh9ccHPExMHNuGWbYBZurShxN0yj/nhQtlYoKIX+4nB0flOKGOdfLwszPa3sHRi
         fp1d+vyG8mCWCPLHe0anDWiFWJE7F5MC2xec3k6vBwMKm3tvoMwzu8boQD3pLpKqWGza
         oc+T1KLrB9KHDRMtzNtbpW8qRVYTyvXhLb0m1QUy/Ujp4sxZk243UFM7YMQoykMxUWMU
         svHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WFE07g+KlPJv8299DawKKjQjhqW1Zo+ieRU5MiMCbnI=;
        b=g7XRzKw24BqQhEKfvv9cTaLMR72GrlJhFpVfo4Egbgs2eTZHGmTOpqyXAX1u0FI+el
         tQPxLh6xbrkTFTvINGJ3U/cJK5eYuQzsJuyBwD7KU5HHrjKcjCu8kkLLXHLC1v0TuCuI
         At9dkqH8hYG1KRusTwFLrmgW81+0sI+uUK5XVGnRMBhy9qaMEE+pVy6Cgm06o9xl5NO1
         ygf6oymGLN8GcAwM+dAJLapp7jL0Ne9TdHriVmjyyi9lRz1DgnRjncdS1+HVzjhHqsfc
         ToTlnBZNxlhfBphbC/vFNxrRDp4PlOsEoRUzvDWcU+mv7uKd5UevqeCJshNIdBiwumF2
         gC6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=A8NiIANr;
       spf=pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d14si655888pfo.4.2020.03.02.10.28.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Mar 2020 10:28:42 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2EAD620842;
	Mon,  2 Mar 2020 18:28:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 073EC35226C8; Mon,  2 Mar 2020 10:28:42 -0800 (PST)
Date: Mon, 2 Mar 2020 10:28:42 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: David Laight <David.Laight@ACULAB.COM>
Cc: 'Marco Elver' <elver@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"stern@rowland.harvard.edu" <stern@rowland.harvard.edu>,
	"parri.andrea@gmail.com" <parri.andrea@gmail.com>,
	"will@kernel.org" <will@kernel.org>,
	"peterz@infradead.org" <peterz@infradead.org>,
	"boqun.feng@gmail.com" <boqun.feng@gmail.com>,
	"npiggin@gmail.com" <npiggin@gmail.com>,
	"dhowells@redhat.com" <dhowells@redhat.com>,
	"j.alglave@ucl.ac.uk" <j.alglave@ucl.ac.uk>,
	"luc.maranget@inria.fr" <luc.maranget@inria.fr>,
	"akiyks@gmail.com" <akiyks@gmail.com>,
	"dlustig@nvidia.com" <dlustig@nvidia.com>,
	"joel@joelfernandes.org" <joel@joelfernandes.org>,
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>
Subject: Re: [PATCH v2] tools/memory-model/Documentation: Fix "conflict"
 definition
Message-ID: <20200302182841.GJ2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200302141819.40270-1-elver@google.com>
 <8d5fdc95ed3847508bf0d523f41a5862@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8d5fdc95ed3847508bf0d523f41a5862@AcuMS.aculab.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=A8NiIANr;       spf=pass
 (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Mar 02, 2020 at 05:44:11PM +0000, David Laight wrote:
> From: Marco Elver
> > Sent: 02 March 2020 14:18
> > 
> > The definition of "conflict" should not include the type of access nor
> > whether the accesses are concurrent or not, which this patch addresses.
> > The definition of "data race" remains unchanged.
> > 
> > The definition of "conflict" as we know it and is cited by various
> > papers on memory consistency models appeared in [1]: "Two accesses to
> > the same variable conflict if at least one is a write; two operations
> > conflict if they execute conflicting accesses."
> 
> I'm pretty sure that Linux requires that the underlying memory
> subsystem remove any possible 'conflicts' by serialising the
> requests (in an arbitrary order).
> 
> So 'conflicts' are never relevant.
> 
> There are memory subsystems where conflicts MUST be avoided.
> For instance the fpga I use have some dual-ported memory.
> Concurrent accesses on the two ports for the same address
> must (usually) be avoided if one is a write.
> Two writes will generate corrupt memory.
> A concurrent write+read will generate a garbage read.
> In the special case where the two ports use the same clock
> it is possible to force the read to be 'old data' but that
> constrains the timings.
> 
> On such systems the code must avoid conflicting cycles.

That would be yet another definition of "conflicts".  Quite relevant on
some older hardware I have worked with.  But what we are concerned with
here are cases where (as you say) the memory subsystem will do just fine,
but where the fact that the memory subsystem is called upon to do the
necessary serialization constitutes a bug of some sort.

There are unfortunately a wide variety of definitions and opinions as
to exactly what sorts of conflicts constitute bugs.  The generic pattern
for these definitions and opinions is "a concurrent set of insufficiently
marked accesses to a given location, at least one of which is a write".

The differences in definitions and opinions center around exactly what
is meant by the word "insufficiently" in this last sentence.  We will
probably be tolerating some variety of definitions in the kernel,
and given the wide variety of code contained therein, this should be
just fine.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200302182841.GJ2935%40paulmck-ThinkPad-P72.
