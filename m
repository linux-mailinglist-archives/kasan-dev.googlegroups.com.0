Return-Path: <kasan-dev+bncBAABBRUGSP2AKGQEX6U3FOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id CD00619B19D
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 18:37:27 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id b21sf330326qkl.14
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 09:37:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585759046; cv=pass;
        d=google.com; s=arc-20160816;
        b=zXdpCQ0qP8AK6nQUOOp2ppF35b5o5WDEaaThSgFPaGQaLB0zl4xU6RYWoXqUgFt1Gm
         emsJeyOcVxKIhrddZP8dVCIngPqSKrPY+2PTpUivXlfLxLLF11eCYicIBdkXDdn2DNZd
         eCotZRirWvhDgUYe2zMB1V9iATxDFdnVh7zsBGOKRYfGgD1eOd46AdERiqI/bdnIAwAU
         H9GHVgqkvcZPI3Zh/2M40a6p5xSaVW4lsiIvILfAyazKjKjowwF9lHsblHS5W3HPAy5U
         IS1MIS0sQznEYmqKHmwdfSOeUQ1EFtNdaJ7y4VSCO+k47CHa1IZKV39krVEwtzkvmegc
         oQAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=q5EtT5tWgAVnu+1yXQFTf1N4hbPrRypNLUHWvu6TYvE=;
        b=LYpaLBDs6mCXOccR8gufAvr9wimMlOAu+WDMgJXTkV+oAyEWwIKj5hYhocdJBpWys8
         L91NT/UsPukuyfW84VkhjFSdm6GGc1LLTlFAK0ESKaVXx8MGGNw5EKQqk7ffsqYnvCMK
         RGL3R+TZNbFPSvbkIZ/wEG4ZZ50DGIeUptkbc/E4KstEzMB/F2VkUHfj3CoGBGZDcDH6
         jpKUVznoaso7bidr6dCYahtSjfvxrM2xVX4mR/UBEq0BHHn5itpWAhSiu0TlfmhVTbkS
         2xTbnEgbjDmwpfVD+nndgvc0GDllodbad8ARzoW7bJYnVYzepIt/CtPgzxSLeYXEaqnI
         SChQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=nCt9BQq+;
       spf=pass (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GeTk=5R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q5EtT5tWgAVnu+1yXQFTf1N4hbPrRypNLUHWvu6TYvE=;
        b=dt1yHUQgdH4s6ClWZaa4FvexG32qhGYiP4WlnWrxsA7UMHbo16iap0eJ75X8F8GfCg
         1jjHQ8ThYlzpcblHMTd0cdSg5FmO2hXeCM5K8yo7Z6CS8qb0zFXSAMldspu+RiVzvrei
         gTeW6a1QYz9UBBrus8MVjgm/U2SorLXMnNcbfaezQj04Zw5zH+Nua7f177zrAGuLIWiY
         GQnt30OefFvBJvXul0cvvTy0cnlUsE7zpG1VOfZ4ZaioE1o/xPxl9RMEZvrjRkDv/g0R
         Y4oiJyWpd5PQ/ENo1mGHHQXqrhRbbiGCGHJCmbbmMycscSuXSVBcwhsyJKYSOwgcxfB2
         xuZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q5EtT5tWgAVnu+1yXQFTf1N4hbPrRypNLUHWvu6TYvE=;
        b=UQOZwhgr15AY8R8BMH/O8LdQnrVd0tqQcJGqwmEsKPTb6bAY2ytSYPbeB+MVG7cWxK
         Yqp+14Kx/dX8YR1LOk7R7x2V648lEpeOAj1xIEnrDG+1NyTGIoyK+uZh2LgzQpwQSutV
         KruW73W6vdSCEwFRftb0S5ip6z5Wcm8jeibKtm+tfbP5HS2+0QWauGR6Lhkg4bBkbdUS
         hHlhVPIWoxyXXZiTInOWt3uKzU3aAF3luQg30nWSo309S+imtshBAVJYotWsozHnIury
         vvCWBnbf48V05aJddw0aPCgQfM27r92iMV0nnRyKM4UyACPyNxrODl0BUylvN0TOMvm/
         3ctA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1uy8X0Ng7YxpVyMnR+1ynYTa6nk7sL28DDh1YL9XO35F3oStoM
	E4LpBAKP4wsXfZz3RZzLkZo=
X-Google-Smtp-Source: ADFU+vvndFg5lSIwAV8zV7Vx06yL1wGEaiYw7joa9xAS+MpyB6q+f8EOJnYPeBQevcFbxL42xZwxdA==
X-Received: by 2002:ac8:6898:: with SMTP id m24mr11455068qtq.65.1585759046685;
        Wed, 01 Apr 2020 09:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:f1d:: with SMTP id e29ls175706qtk.2.gmail; Wed, 01 Apr
 2020 09:37:26 -0700 (PDT)
X-Received: by 2002:ac8:1b2f:: with SMTP id y44mr11555082qtj.25.1585759046192;
        Wed, 01 Apr 2020 09:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585759046; cv=none;
        d=google.com; s=arc-20160816;
        b=C/59B6UKlN8gJ4KHd1rjvSIdL6VMP3dZ6G/fPCtkxgnh7pr+f1SPwqhEX7m6Wkw3xS
         g5OyOe4hay+Ih2ubfNGtvVgfcNku3zebdNdsmUKm5h/CYTrMUC4X9H2mA+KEUZ7PGBUN
         43PhGoQ6klNaLh7kqr1F0v0UXuwC4Yya9P1X/UnSoWNIuXzEXCn5rtbNoqnlL2HCpeHJ
         HhK5g2BTs47wSZwWbszRYogLJhywk4Rr1WN58U+bvub/Xo5ZtP6biegrLaI0blzdRNNV
         n1i1ZVV1dUWXyIERvQsLqAl0E1IHaO5xFQFX6NpAH/FGZB76WugvMmk6vicxZX3lftXc
         w8Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=LotuAqsyXfDMvO7VgZEOXuweM9bDKPmxHwUETtYnkcg=;
        b=Ah5fyzBhB3GWBB14ngbZzVNnO+AObEwJ4eEyXv2+ykr1yjxkuA7HaH8jY9QKbEMtlW
         qhydgFhQJL8O4OyXYdmTyC4e4GnJtkEEzf2KnksTX2pKC7veQlu35wPfC9u+RalygCW8
         IgFQ+UN5vMsnGl4S1iIRdmAxL76RRBccB2vTIGXhxpZqhn9HGvsXYjPpO3maCLjjrUYA
         EwFxGfFCOdGXE/OJ/Y3Dtu8HFNxdbepZFDtfGaiKWhn6mC0VG2cBBTwcI7+nuYK9pYrr
         0/D11WxIrRQGjT5xD6bZtsAWX1xOtKDKS491cuXYzodoxscgOQx9is6mvWkI/dBvvS8/
         yd8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=nCt9BQq+;
       spf=pass (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GeTk=5R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j56si231117qta.0.2020.04.01.09.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Apr 2020 09:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3641820658;
	Wed,  1 Apr 2020 16:37:25 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id F39493522887; Wed,  1 Apr 2020 09:37:24 -0700 (PDT)
Date: Wed, 1 Apr 2020 09:37:24 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Will Deacon <will@kernel.org>
Cc: Marco Elver <elver@google.com>, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Move kcsan_{disable,enable}_current() to
 kcsan-checks.h
Message-ID: <20200401163724.GA19865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200331193233.15180-1-elver@google.com>
 <20200401084002.GB16446@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200401084002.GB16446@willie-the-truck>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=nCt9BQq+;       spf=pass
 (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GeTk=5R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Apr 01, 2020 at 09:40:02AM +0100, Will Deacon wrote:
> On Tue, Mar 31, 2020 at 09:32:32PM +0200, Marco Elver wrote:
> > Both affect access checks, and should therefore be in kcsan-checks.h.
> > This is in preparation to use these in compiler.h.
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/kcsan-checks.h | 16 ++++++++++++++++
> >  include/linux/kcsan.h        | 16 ----------------
> >  2 files changed, 16 insertions(+), 16 deletions(-)
> 
> Acked-by: Will Deacon <will@kernel.org>

Applied both acks, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401163724.GA19865%40paulmck-ThinkPad-P72.
