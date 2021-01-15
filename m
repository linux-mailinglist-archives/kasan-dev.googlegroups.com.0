Return-Path: <kasan-dev+bncBCJZRXGY5YJBB3OLRCAAMGQEQYEDDYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E992E2F8966
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 00:31:58 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id e4sf5312784oii.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 15:31:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610753518; cv=pass;
        d=google.com; s=arc-20160816;
        b=Azql1eSt7+LLbECSk6PWLGqGmHKhtuN1ayCfQYHwKtzmtfYpt78EE3vxKHeBGw7zQ3
         gEvLR55uCXMO9rhxCwZcapT5+Fr+IIbiSyC7D6rutqi5+wjum4AgPVD4AdJZr3WaXUWJ
         +Tb57F+cVqepiuQwNo4QaRO+s81jgKSoSv1stpfKxhLtvhDvCxAq4LvwutAKVR6goNHt
         Sry+N6Yd2yax0s6rrH8Lq44CBCN8xG4qu9vyTTISIh38UnoAX7BScODy1D2gBPeXV/5u
         ZDbENT1+5gReYP8yhvtCChgM9YbCAhcqULFrDlrvMN2UhNUoRcd9vXZnsVPZ5BO51Nk7
         9FXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=8h5lGxsygfZuuINjvDQC8a4l12nLJefApR/yWL5R11o=;
        b=P+/UlisGDVLrRcz1y3CnSZC96xmvK8nvBElg/WTHtSgt5xlK3BAY/OG9cJai3ROjAm
         w5inRjzRwMM+o/W+xIIYYmaYzQRPJPCQPnQvGwHo+RBzTVAUQdN/O2UKzDu886nesWaN
         xsWcfQo9AEiNks8X/HBOfHJvmzFC4SaCMv3SX9yP+sKHZR2pjkOk4jwc/rWQRLk8XYFU
         gOL1UGhPLPKeToL/HTJ1t4lyMO6MRn1nSS1wMcVXR9LM1i9Fb9ZNiYHNsHPbpA7Zqwrk
         7s5stixcLmi+MgGgF0fN9aoviogXS7LJRqrNju9F1yeAtQ+eLJx9s/h1aNS8EbtSSRp6
         D5rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hMGnU2je;
       spf=pass (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hXhP=GS=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8h5lGxsygfZuuINjvDQC8a4l12nLJefApR/yWL5R11o=;
        b=Smz0kO+/tSplVYQCP/l67x5xFUbSqWpW6ki1iJ7OqCQyMfkObIUEfGPTvbMKS6n0w3
         zONqJelWWX3BL4yzWUp9u8FiNR8eF7VVJAiYK7A6Kxgszhy1fE7w/srGKTCujRwj2fsf
         RkuR3aoVBy4VXdlDSKNvmpw1L1WkW1dc0JjnUNIyK5msgUlq80iIoCdcPTKxgbeZVsUB
         lpC7bTOnhQinjnjvK9K42rv+fzyWzsrZEoTKA5MkAqTKl7kxAPTO9Zrpi7+X48Cl1xHX
         QhZVADoXOCSV4skiHUvwn+4dhWM2m3kiqzvq0LXBWu0u4MlzC+d06UCFq9fKd1OkfkBR
         /l4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8h5lGxsygfZuuINjvDQC8a4l12nLJefApR/yWL5R11o=;
        b=MEAqWkY8sgy48E4vQhIbh/ycv/Vq1xd05X4uDB6JGUGx2ch+/mbJZJNqswK4OFeNsL
         sr1Bnrbz7S41E24653Rc0pMGScJIR6gLjH4yT23U90EZxjzdzFhtKtdkFDwr7dPLQgye
         ka5AbnkSzANCfGMAAMJGkDSiFCT6xNxHST20UsRqPCmQzEb+M7km6Z5CyYTcIGCvPBiP
         NB30FzocQA8J2mke3aMkHJJwFjJDZhclulxnSL4r66DwCEg10aXYRkmpmVAj3TrKEHW5
         sdhxlc7D8zd4dAN/yQSOc7Wo+Su7yt6q57kmMAOWTFcgQFBn0iSLuUmQFzvJWDl2Ylsa
         o2sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tu9Jlw2ShQCxNrCdj84scxIno9PoKgDt0iJ8ALJ18jKd9WIUE
	0QP9a9lydPspOAqp21/wZFQ=
X-Google-Smtp-Source: ABdhPJzfG4KLgi5y4dBvgiqZ/yo3xaNqu3/cAI/vmINUCvFeGc7yz2NOHWO7nSOu3uOl0vUz+1zZhg==
X-Received: by 2002:a4a:6c45:: with SMTP id u5mr10196511oof.61.1610753517989;
        Fri, 15 Jan 2021 15:31:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fd82:: with SMTP id b124ls599326oii.3.gmail; Fri, 15 Jan
 2021 15:31:57 -0800 (PST)
X-Received: by 2002:aca:d98a:: with SMTP id q132mr7309340oig.33.1610753517607;
        Fri, 15 Jan 2021 15:31:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610753517; cv=none;
        d=google.com; s=arc-20160816;
        b=URmZ972W0IwiHaheU965H0JD0abibGz2P3xCEpZMIlwcHMNU6qRPaWtdr8dglhIBB/
         S4WCDAbVnBAVeeVHd4s1Z88DXmHlFJqzNndgl+LdC6s2eB0MF6TOLxsU3bHNG0Uc6KNd
         CgsAh/A6q0lnmBpipjaN6CITPfVcEWJVqP8C1JNLveyLQM03IUff/IUfqBkxFsBu+5qc
         lih6sBUH3z4BBrCTj9jbdgNBPJHR5ORpJwwWilIIiQFHCst8LyJbo1/JmpG/dnCsT+Yq
         aZ8DQV6fpFtXA0akFGF6SNTacWDZK5J7RF5hZPeiVC9tyXRAzvBzK0G2fTKrclo1J694
         oIfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=x729KXcmZ1dypB2YT+nOYRLhfQoPiobjzEM0lRUm0Bo=;
        b=vatQ6Bd/l1nOsPGT3CAJhvGgAgRf8BCTzqZht+iY6UkXyhTqVws8fGRsfcsffV5DQJ
         yf4eRlDcnv4jb5UI9frvY9KU6TW/kBniGMQgyiUegqEV2zhJqWdRFVUuWL6vYKWo2EsP
         uNGlQ1RvWKqSTPSEauXzZURko/nXoBYCHMYJYNH8JZcvjiYvxsfqUjPhPj4gSTgQ+GEZ
         uTDp0dIYVPyHwhwhHHDKgBLV/B3nkaFqgC43A1BMpKYJnSZj3X5m54W7TK3bxehTjf0z
         BCdMAsGL98fZonbxtTBt1UDWLeyw4ogHJ0nLnoK7IknnZe/ZFFbKmH6C3ONaiTwowybw
         9m9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hMGnU2je;
       spf=pass (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hXhP=GS=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f7si712583otf.3.2021.01.15.15.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 15:31:57 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B7C9B239ED;
	Fri, 15 Jan 2021 23:31:56 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 741BE352162B; Fri, 15 Jan 2021 15:31:56 -0800 (PST)
Date: Fri, 15 Jan 2021 15:31:56 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add missing license and copyright headers
Message-ID: <20210115233156.GO2743@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20210115170953.3035153-1-elver@google.com>
 <20210115215817.GN2743@paulmck-ThinkPad-P72>
 <CANpmjNM9++GSuSHH+Lyfi23kW8v0aXLX+YbD20UX8k5jAAaSnA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM9++GSuSHH+Lyfi23kW8v0aXLX+YbD20UX8k5jAAaSnA@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hMGnU2je;       spf=pass
 (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hXhP=GS=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Sat, Jan 16, 2021 at 12:21:53AM +0100, Marco Elver wrote:
> On Fri, 15 Jan 2021 at 22:58, Paul E. McKenney <paulmck@kernel.org> wrote:
> 
> > This one seemed straightforward and I heard no objections to the previous
> > two-patch series, so I queued them for the v5.13 merge window, thank you!
> >
> > If any of them need adjustment, please send me the updated patch and
> > tell me which one it replaces.  Something about -rcu being in heavy
> > experimental mode at the moment.  ;-)
> 
> Thank you!
> 
> I would have given the go-ahead for the other series next week Monday,
> but I think that's a holiday anyway. :-)

It is indeed!  I guess you had Wednesday last week, with next up being
Friday April 2?  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115233156.GO2743%40paulmck-ThinkPad-P72.
