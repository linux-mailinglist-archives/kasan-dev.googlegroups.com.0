Return-Path: <kasan-dev+bncBAABBWGO5X2QKGQEL74JYFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F18F1D056D
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 05:19:53 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id s23sf10088171ook.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 20:19:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589339992; cv=pass;
        d=google.com; s=arc-20160816;
        b=S2SOnitU4K5mmWNDiUBEOh29PLa+rqw4wc2bfJvxV1xv4L1S+ivMmRtE1Qq8dVYCnO
         cGFU9ILUrCuugMrsLICWykWS05yQp156VqzGY2apcAPq/BW7l20QAKTLkGsQsaC7Uua9
         432jNvHJjoPPyUwpCskCp5Q+0WwQJCp60aelE3T/P5rzkqwwYlv+COguNm2j9kZ9UAzS
         I+5VVj/Up2EH491cuDP+YXC9tgaid1f44v/QjIF0SaHOIvLAGXnI24oLWg54qNQmrT45
         tJ9esWHAOQLkNzz/PP1A3XZedBq9OEqjAPe8Y6WrLoOKddHv/aD1/oGkBXxJtcmPhVXB
         QjDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=LFkgpvemeyAoP1fW1t/Yt7iUOCl5KJ0xF/mhSr6vV+M=;
        b=Xgp87f9ky+8jfXTDtKEOZOJAqIBn4RkHBnDDHep2jF+M+zSDFcTZphCOrMsXqI4Bwt
         836Uha8R0lwHPF3UwGDsfpdbl3ycWityBUY570AP5To678QqUKh5NC2KbeUf1jKflnCW
         uxDuGYXmddvdg+ABFu12+H+rxqsScBGlUXWE3dS0zkpRfI6TQSKR0/o8ykz6fNeA7WHq
         RZrPDXpLXWRQ4158ucq7H0cU/X+mO2DNNTjo3dEdA56PVvF0PsGTyiCv02d0vjesrj9P
         EUAQpLrXwF03BtfAE+dMyvbhpiisQFDuhEfWWv7ZZZiXKo9JzUvpL9d+9X9Rlb7YxNrM
         UoeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=kdXcrlFV;
       spf=pass (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=h0+r=63=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LFkgpvemeyAoP1fW1t/Yt7iUOCl5KJ0xF/mhSr6vV+M=;
        b=hP1YpeOEckuPp62uS8HDuGk9KJVnNfABdIC/eq3C2jYejTDTio+eNUVcC3pkn2/8XZ
         JeSfXFM+3Dword+CPe3luDADtWTa1/NAvQJT/5ufJIaWjdHC2uVKIWGJ6oBdzpAud/8R
         z2e2TBgSdt0sFu9n7XzkBaWU0qMxdL0GNpoGzXHfzHMsnrPAB0PmhSOTsuf8kYmwy1oy
         PQTJnyyiEVEuCdKv+noWmEBI29Igiu4n8O17kpkPWQd5osO0I1PHuPob+KtQgryrcWfz
         LhbSKq6WZF1Nlf7Ra5RuBKVFs6cK3P1AE8M4b9tPxfROb2Clszwwic76UkW7+St3GfBw
         WQTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LFkgpvemeyAoP1fW1t/Yt7iUOCl5KJ0xF/mhSr6vV+M=;
        b=HJTEWF+PK19hwdxbw5Hy6uAZD95kf64AXI3JHuMOzzRPnodzfzMhuMZw9B7k0nhRd1
         Xye+J+UbAx0XxgB4INRl9LEatRXpuKkuLzwaFv6MMMbylkfogODyQor0iErkE+fcPjN2
         xAzMlhf4QRRUySrgwrQ1VghmMVuyt+7vc/Kxri5njTBp7tiylr4Ak9OzM8NRnDa3+f7j
         gPX7hjnkOhNsN7dNxIRXTbCWZuzr+PjnhjptskZvWoWmwkUfIJYfQ82wykdHkGxKLhOe
         WXyC9Ju1CE9FAmdHF2DGvy3zB9aXl6BF6ilw16t+f4Ta3egL4TGTXTJO+31SLLvbgHbd
         Aexg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubmPoyI6H5PARp9Xoxou05SKAA09i+20WLr8JFOiuBinUVOYE1q
	fKjaMb7jVsaiRsvuH8rtvJE=
X-Google-Smtp-Source: APiQypI2AM4ln7XokGtEXD+yUG9Tkbs3lndb/zFzYRJwHmDrrj8qZIzvqg5gaZSVL6Ix2Jl2q7j4sQ==
X-Received: by 2002:a9d:7d15:: with SMTP id v21mr18880023otn.182.1589339992492;
        Tue, 12 May 2020 20:19:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf10:: with SMTP id f16ls223725oig.10.gmail; Tue, 12 May
 2020 20:19:52 -0700 (PDT)
X-Received: by 2002:a05:6808:30e:: with SMTP id i14mr12913703oie.168.1589339992157;
        Tue, 12 May 2020 20:19:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589339992; cv=none;
        d=google.com; s=arc-20160816;
        b=bZT7mkk3+KsccTlm7F8eT+M/V+gjBtOVe5K1Ew8W6QC15+6efgBAx23LAjnjKDudno
         zamYx7gaA3wVScoGSN0gB6cDaKXJ7kbL3870ZXzhKo2ftrIF5UfZF0kA/3ooz83HSIso
         H5lxNdjDbk7tmbyYk3eSCaNKGJD9fGpd4U0aGm4CMO7Zz52QbviWLpWpD6ymrpG5sGrD
         4dyIsXkDI3Lthno/otUfN5R5us8doNhzfRSddXYly2jMUCnRuMIUoCEBmmul9muuUV9/
         W3kNJRVoC/kkgeQOAds2xKmyM4WneExV1NpiuJNQWF2LraUCA8WSD9/3hDJORFS9D5tN
         aNwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=k5+gVntB2zuiEhFbeM7hVzz9GS4bb4MeaovgHE4syhI=;
        b=x3MVfJXKDK8Cbb0ThRZhoVHrsApuwZCACDwKlHyAVsvfgAaU7kM/+GkGLK6pt7Nm6A
         Fgz/AHsXoNnoVTrchuAtEkgXVsh3w2A82SeyoV1/+KH8G5rWYgIgvLkTHrmEIm1+xdbV
         r+tQvPlV46cDfQg1Hy8FPb1L+fs4XN1bSIVeNeAq0wOCHl05EVZsY5MS+JIjt01T+Nkc
         drXpd5staCAO9EJZoe9oq2b7CuZHCGpWq2fKDG5hMdsdfPw0R9PdH48jX640FkTnnZSO
         nNOJToPLBweYwB+Hqbbsi1tRTKWwT/Dfxzzq1Cy+kYCfUd7A/HUeFwyWfZ5vjNMB38o2
         mXtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=kdXcrlFV;
       spf=pass (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=h0+r=63=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y144si285774oia.5.2020.05.12.20.19.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 May 2020 20:19:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4CA0420714;
	Wed, 13 May 2020 03:19:51 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 349373523471; Tue, 12 May 2020 20:19:51 -0700 (PDT)
Date: Tue, 12 May 2020 20:19:51 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
Message-ID: <20200513031951.GO2869@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
 <20200511180527.GZ2869@paulmck-ThinkPad-P72>
 <1589250993.19238.22.camel@mtksdccf07>
 <CACT4Y+b6ZfmZG3YYC_TkoeGaAQjSEKvF4dZ9vHzTx5iokD4zTQ@mail.gmail.com>
 <20200512142541.GD2869@paulmck-ThinkPad-P72>
 <CACT4Y+ZfzLhcG2Wy_iEMB=hJ5k=ib+X-m29jDG2Jcs7S-TPX=w@mail.gmail.com>
 <20200512161422.GG2869@paulmck-ThinkPad-P72>
 <CACT4Y+aWNDntO6+Rhn0a-4N1gLOTe5UzYB9m5TnkFxG_L15cXA@mail.gmail.com>
 <1589335531.19238.52.camel@mtksdccf07>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1589335531.19238.52.camel@mtksdccf07>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=kdXcrlFV;       spf=pass
 (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=h0+r=63=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, May 13, 2020 at 10:05:31AM +0800, Walter Wu wrote:
> On Tue, 2020-05-12 at 18:22 +0200, Dmitry Vyukov wrote:
> > On Tue, May 12, 2020 at 6:14 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > > > > This feature will record first and last call_rcu() call stack and
> > > > > > > > > print two call_rcu() call stack in KASAN report.
> > > > > > > >
> > > > > > > > Suppose that a given rcu_head structure is passed to call_rcu(), then
> > > > > > > > the grace period elapses, the callback is invoked, and the enclosing
> > > > > > > > data structure is freed.  But then that same region of memory is
> > > > > > > > immediately reallocated as the same type of structure and again
> > > > > > > > passed to call_rcu(), and that this cycle repeats several times.
> > > > > > > >
> > > > > > > > Would the first call stack forever be associated with the first
> > > > > > > > call_rcu() in this series?  If so, wouldn't the last two usually
> > > > > > > > be the most useful?  Or am I unclear on the use case?
> > > > > >
> > > > > > 2 points here:
> > > > > >
> > > > > > 1. With KASAN the object won't be immediately reallocated. KASAN has
> > > > > > 'quarantine' to delay reuse of heap objects. It is assumed that the
> > > > > > object is still in quarantine when we detect a use-after-free. In such
> > > > > > a case we will have proper call_rcu stacks as well.
> > > > > > It is possible that the object is not in quarantine already and was
> > > > > > reused several times (quarantine is not infinite), but then KASAN will
> > > > > > report non-sense stacks for allocation/free as well. So wrong call_rcu
> > > > > > stacks are less of a problem in such cases.
> > > > > >
> > > > > > 2. We would like to memorize 2 last call_rcu stacks regardless, but we
> > > > > > just don't have a good place for the index (bit which of the 2 is the
> > > > > > one to overwrite). Probably could shove it into some existing field,
> > > > > > but then will require atomic operations, etc.
> > > > > >
> > > > > > Nobody knows how well/bad it will work. I think we need to get the
> > > > > > first version in, deploy on syzbot, accumulate some base of example
> > > > > > reports and iterate from there.
> > > > >
> > > > > If I understood the stack-index point below, why not just move the
> > > > > previous stackm index to clobber the previous-to-previous stack index,
> > > > > then put the current stack index into the spot thus opened up?
> > > >
> > > > We don't have any index in this change (don't have memory for such index).
> > > > The pseudo code is"
> > > >
> > > > u32 aux_stacks[2]; // = {0,0}
> > > >
> > > > if (aux_stacks[0] != 0)
> > > >     aux_stacks[0] = stack;
> > > > else
> > > >    aux_stacks[1] = stack;
> > >
> > > I was thinking in terms of something like this:
> > >
> > > u32 aux_stacks[2]; // = {0,0}
> > >
> > > if (aux_stacks[0] != 0) {
> > >     aux_stacks[0] = stack;
> > > } else {
> > >    if (aux_stacks[1])
> > >         aux_stacks[0] = aux_stacks[1];
> > >    aux_stacks[1] = stack;
> > > }
> > >
> > > Whether this actually makes sense in real life, I have no idea.
> > > The theory is that you want the last two stacks.  However, if these
> > > elements get cleared at kfree() time, then I could easily believe that
> > > the approach you already have (first and last) is the way to go.
> > >
> > > Just asking the question, not arguing for a change!
> > 
> > Oh, this is so obvious... in hindsight! :)
> > 
> > Walter, what do you think?
> > 
> 
> u32 aux_stacks[2]; // = {0,0}
> 
> if (aux_stacks[0] != 0) {
>      aux_stacks[0] = stack;
> } else {
>     if (aux_stacks[1])
>          aux_stacks[0] = aux_stacks[1];
>     aux_stacks[1] = stack;
> }
> 
> Hmm...why I think it will always cover aux_stacks[0] after aux_stacks[0]
> has stack, it should not record last two stacks?
> 
> How about this:
> 
> u32 aux_stacks[2]; // = {0,0}
> 
> if (aux_stacks[1])
>     aux_stacks[0] = aux_stacks[1];
> aux_stacks[1] = stack;

Even better!  ;-)

							Thanx, Paul

> > I would do this. I think latter stacks are generally more interesting
> > wrt shedding light on a bug. The first stack may even be "statically
> > known" (e.g. if object is always queued into a workqueue for some lazy
> > initialization during construction).
> 
> I think it make more sense to record latter stack, too.
> 
> Thanks for your and Paul's suggestion.
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200513031951.GO2869%40paulmck-ThinkPad-P72.
