Return-Path: <kasan-dev+bncBCJZRXGY5YJBBYWN6WCAMGQE3ZIJ5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FD8637FCD2
	for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 19:50:28 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id a18-20020a0cca920000b02901d3c6996bb7sf21932447qvk.6
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 10:50:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620928227; cv=pass;
        d=google.com; s=arc-20160816;
        b=jNUeUUH/3Dh3OwNNkPqiwmrHmms12OI7OQgdjAhrIVOBjVVTDTW/jGg/75o5kPpl3I
         4gf+0zyPg8Edgyjx0uU9QfsgIVTeYl+kG5eZ1TjsOPJEl6y+T8DZfCmT8OJp3yjqrR5n
         irF8O0EFWKtcVh6IQ4k0uC6wrCtcHbyvnrYH3xC8xaEn+KH00T53VlMe+BN74Drj8h5P
         XxUzKTTL9S4RswXwFFhO/cTKICmqjDBgLt2vsaiEcpKSJxUuaOb8GIE+00E8LalOaBd7
         6ANFSoRAdy3NjcUEYHWd6mXcx7E7LgDh0vv1pxyqXA5lsg4tR+ocsB1jSh3N1gZsaP1N
         z8Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ytbsVqvVYQ8NeTEQKBTMx5cqbrnxjnOUIs7O2T6ayek=;
        b=O6ywjJiJeN4BG8x53cCruXURIvKFB6S60VXjsQaoYsOi64M2QC8EKMznJC1WW9quz9
         L8z1DN8k32wPYzVVBgSgOASbhNjCY+9UICt5/e7oldtIj/fJIhWWA3J1WGVGXJMjpHos
         UrY4Ht1Y3uwMEa3WMp2W4PJgR9DPPI+081f18cvW9xfwYKo2SkgqExZiKrNLAhTtOhu/
         63cOysnwYfZCfidGsOpsxnxPl4ae15AgbBK7bXXezrV++G1a7JHXSWmbYUPxj5U2kSwc
         3aOd+/EKSqOF5d/AIiJRQ4wgKPy+hH0LiI/XLA5xiBWU5jeRLkruckB/qZTNPAHqeS9a
         QnPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P4cjcE91;
       spf=pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ytbsVqvVYQ8NeTEQKBTMx5cqbrnxjnOUIs7O2T6ayek=;
        b=sxnRqaO3r3GwFnqLfC0znjvXvvsvi3qvoLO0Lx5l3ysoii02XEoSqLeipb2f9LWqni
         bDtvATmjvZeFu4pTtmuWEmWdz+6L063WEC/mibxNP5QxPoSnbyKOyyaHX5vXutz58b/e
         zo8VWljL2vnVsLYjbP9svpDKRj8Nug2H04YODx9oJnzkH1oCBTJDOdlxTKEQ4U2QxG9k
         GApI1i3DPZNZa+YGCN3Wcta0ZXap3+ICl5XnR7Srs/ipXOg8Dzrd1IV2u0VnTaVnJNer
         SWMlipaSlKo/TCEeQfFGobLCE6N1qi8km0maragq9JT19s6XXSTOfGZOHi0IhYE4j0s8
         Kz5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ytbsVqvVYQ8NeTEQKBTMx5cqbrnxjnOUIs7O2T6ayek=;
        b=XLrl8ojtU3VN+BV5bTDFS6nyeNzqLpsKeUbrtOqHahqfEANhnUcVaC5Y6rdT6jAAnL
         WiTZtd5u2DAyNMAs4KrPRs7yfX4A4ZxXOv+2QGby6rFTusu3Plh14YF4G6Z18xW8wdGi
         H6Kzw5K/NWQ8bU6vfxR1hXe409koJlSUeNwGYwMhjbO7AzbVEr3Ybew0F6aecubpDkxx
         1JBSQ3/WgfFAIc6pkWJKH1TZPF/xEhCmAHD1/XlIJZEsT2WMJPGMCTH/pXGfvdKHXX09
         NCFYf+NbvHvhLWf+GMAF8NQ+6R7Cr2/erJrKJaq9BlUCs3u67uJAJkdvBosLx61BYyjq
         TA1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vAD6nFShiUQcLbODgt9ZkwxJ06FQKdyTq4l0r2HcsEVx8Z9u1
	qIMoHvz5i4K6+sFX3Fs9HpY=
X-Google-Smtp-Source: ABdhPJxyH5x7grMFqpo2NCndudewXoqsIOVI1hQepyPxx86SJGx4qpDUCFpsWuNV+lk6+B3rumuUjg==
X-Received: by 2002:a37:96c1:: with SMTP id y184mr34945769qkd.61.1620928226985;
        Thu, 13 May 2021 10:50:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3024:: with SMTP id 33ls3392784qte.8.gmail; Thu, 13 May
 2021 10:50:26 -0700 (PDT)
X-Received: by 2002:ac8:7ee8:: with SMTP id r8mr38618836qtc.56.1620928226523;
        Thu, 13 May 2021 10:50:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620928226; cv=none;
        d=google.com; s=arc-20160816;
        b=gxa8Vy5riXHhMpDxIjOSoNeuyfgdqr4vfu6o+tF++gfpKfjmN6+69pZhYsa29VBs3k
         3mZqXil7wHI+Vix5yE72UvfVvwPAD5nvZHXjazXd+7dXGI2hG5NpPH5jdVuFS+wDxyd9
         aRRALE0bRd8ANk7Sm4TU/OKnbbYXO9G946703WzNM5zm6Htp3H0un8F21MjubqmpBhUM
         dXOKj1jXYV0WsZdqHx8M5uA71zOJGMz2yL5+HbSREOxyRwyGHgA/W15S845hTkIZ56G6
         wtFu6L7cD57PIjowlAaFfNubmANMuKO7CiZPkPImGXP5DJx9aMV5alouHNiKuG7qVPsO
         FHgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lzXFb4SEo4//fmcfaM7zTePgev1HHole1E1qTpe1Jzg=;
        b=Rpn1h0kbIkDansxF0E6ZMS0zWiewn2PC5S8dFd4AXCWCTZ5Qqf9c881QLCrmGcGbof
         d6ycAWTivsgOc4XN1TqGXYySjxNXPCvSQyvgV2g2MvSlQnEr4vjR+vMFZAC2o7VaBBtR
         VSDmxDwQce/ks6/i6NZu7hb2iE0YuaOPb5KKCkTyYVhOWfjzn5q+hFzu7VuOA6bsT7RY
         wDzDJZMkq+/aDy0x/ZT+wJHB2PBt9FWik5PLD0tExVSG1MZt6CVgTFL2RN49LSRV6QKO
         M1RFklamCNsLpL3gUTKMI0bpw8a9AzyJAJB2334OO123378O7LizD1A7zgAUN06f9kqI
         KUsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P4cjcE91;
       spf=pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p16si411665qtn.2.2021.05.13.10.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 May 2021 10:50:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6FE1E613CB;
	Thu, 13 May 2021 17:50:23 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 22B995C014E; Thu, 13 May 2021 10:50:23 -0700 (PDT)
Date: Thu, 13 May 2021 10:50:23 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Akira Yokosawa <akiyks@gmail.com>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com,
	Ingo Molnar <mingo@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>,
	Boqun Feng <boqun.feng@gmail.com>
Subject: Re: [PATCH tip/core/rcu 01/10] kcsan: Add pointer to
 access-marking.txt to data_race() bullet
Message-ID: <20210513175023.GD975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
 <20210511232401.2896217-1-paulmck@kernel.org>
 <a1675b9f-5727-e767-f835-6ab9ff711ef3@gmail.com>
 <CANpmjNM48id0b+H=PqFkCBDSyK76RFTB3Uk0mNeE2htu3v8qfw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM48id0b+H=PqFkCBDSyK76RFTB3Uk0mNeE2htu3v8qfw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P4cjcE91;       spf=pass
 (google.com: domain of srs0=cslx=ki=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CslX=KI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, May 13, 2021 at 12:53:44PM +0200, Marco Elver wrote:
> On Thu, 13 May 2021 at 12:47, Akira Yokosawa <akiyks@gmail.com> wrote:
> >
> > Hi Paul,
> >
> > On Tue, 11 May 2021 16:23:52 -0700, Paul E. McKenney wrote:
> > > This commit references tools/memory-model/Documentation/access-marking.txt
> > > in the bullet introducing data_race().  The access-marking.txt file
> > > gives advice on when data_race() should and should not be used.
> > >
> > > Suggested-by: Akira Yokosawa <akiyks@gmail.com>
> > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > ---
> > >  Documentation/dev-tools/kcsan.rst | 4 +++-
> > >  1 file changed, 3 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> > > index d85ce238ace7..80894664a44c 100644
> > > --- a/Documentation/dev-tools/kcsan.rst
> > > +++ b/Documentation/dev-tools/kcsan.rst
> > > @@ -106,7 +106,9 @@ the below options are available:
> > >
> > >  * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
> > >    any data races due to accesses in ``expr`` should be ignored and resulting
> > > -  behaviour when encountering a data race is deemed safe.
> > > +  behaviour when encountering a data race is deemed safe.  Please see
> > > +  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
> > > +  tree for more information.
> > >
> > >  * Disabling data race detection for entire functions can be accomplished by
> > >    using the function attribute ``__no_kcsan``::
> > >
> >
> > I think this needs some adjustment for overall consistency.
> > A possible follow-up patch (relative to the change above) would look
> > like the following.
> >
> > Thoughts?
> >
> >         Thanks, Akira
> >
> > -------8<--------
> > From: Akira Yokosawa <akiyks@gmail.com>
> > Subject: [PATCH] kcsan: Use URL link for pointing access-marking.txt
> >
> > For consistency within kcsan.rst, use a URL link as the same as in
> > section "Data Races".
> >
> > Signed-off-by: Akira Yokosawa <akiyks@gmail.com>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> 
> Good catch. I'd be in favour of this change, as it makes it simpler to
> just follow the link. Because in most cases I usually just point folks
> at the rendered version of this:
> https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html
> 
> Acked-by: Marco Elver <elver@google.com>

Queued with Marco's ack, thank you both!

							Thanx, Paul

> > ---
> >  Documentation/dev-tools/kcsan.rst | 5 +++--
> >  1 file changed, 3 insertions(+), 2 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> > index 80894664a44c..151f96b7fef0 100644
> > --- a/Documentation/dev-tools/kcsan.rst
> > +++ b/Documentation/dev-tools/kcsan.rst
> > @@ -107,8 +107,7 @@ the below options are available:
> >  * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
> >    any data races due to accesses in ``expr`` should be ignored and resulting
> >    behaviour when encountering a data race is deemed safe.  Please see
> > -  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
> > -  tree for more information.
> > +  `"Marking Shared-Memory Accesses" in the LKMM`_ for more information.
> >
> >  * Disabling data race detection for entire functions can be accomplished by
> >    using the function attribute ``__no_kcsan``::
> > @@ -130,6 +129,8 @@ the below options are available:
> >
> >      KCSAN_SANITIZE := n
> >
> > +.. _"Marking Shared-Memory Accesses" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt
> > +
> >  Furthermore, it is possible to tell KCSAN to show or hide entire classes of
> >  data races, depending on preferences. These can be changed via the following
> >  Kconfig options:
> > --
> > 2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210513175023.GD975577%40paulmck-ThinkPad-P17-Gen-1.
