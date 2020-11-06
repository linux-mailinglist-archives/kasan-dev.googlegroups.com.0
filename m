Return-Path: <kasan-dev+bncBAABBFODSX6QKGQECYOYZOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA1292A97D4
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 15:45:42 +0100 (CET)
Received: by mail-vs1-xe3e.google.com with SMTP id z9sf599409vsl.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 06:45:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604673941; cv=pass;
        d=google.com; s=arc-20160816;
        b=gM7NUsPIqGbom4HYrzUh1DFNChG4d2jANhyzAPOGQDkoKcyYds2eC5ikXUXdOVZGng
         Y0mlMmVKN0pmjj1b7g5jnqq/ElA3pOifexEq2yWSoO8/1dZnXYrKVskx+EHlKfLZaPhn
         ScTy+PBTLaFsXrOiMtnIHbG0b4S8SsJiQUicF00Sn9D6fwdt+sZULfiwdNtAUW/mMdxh
         rvzXfhkQnllf5q023QuBKUvbbnvGvC1K0TPlykt150KcYtK8KgUnGacg2zTx6ljhaGua
         XyL0zqObU5V9BffWmwzn7oYDa5LYtJ0AgzcSo6lRrqpXg19FkG5HakbLi4eNrK1M17HU
         r72A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=JLmVbvSqWmOqtGgYEChqLEeubWdQMpi8zxeqeOKXKeE=;
        b=l3vZlEbgeVtx4iQ2lPf9fqbbdgVlPX48biC8i/uGcpHhlRlav9cPvYkm8TiRHZrtU3
         PWu3HTeaXrHFcubKGVE3laKpk9XITl8/6pIjJO6Tc7hh0mUpUCjI7RFPjq8ko3RMzl1I
         HUAsM5TPbXTS2aPhI0lUTYMU+HMpRZ7Mwn1Fa9tjqkLev3eclba/zGZQ+4zpvxilxQ85
         ZLqABbUzoOA7QM1MVjpgckZKgp40FoZ9RIEMnV/RYPPNgYjbu7VIOdq5p6oNwfbLBkGs
         WINHw2VSProcwhaLAA+nlEgKj3EyzgCq+xIg7NKdt0M4cZ7fFxNALFwqddqVR3UVfcEk
         U+rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="dQscj/OT";
       spf=pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JLmVbvSqWmOqtGgYEChqLEeubWdQMpi8zxeqeOKXKeE=;
        b=ZKCjxWY4QttpWRQnQwZx7VX+9Yhc/sAi0SQgAtb3Y/6PKGefiLjrBfqT3qlnrm+wUR
         Uf93InV3F6BoE7f9RoAreyQL5SaPGBlwY99MbwheTR9TqN07dIjUFQiWyMV7WjfDu7kz
         DJCXjKZNA9u4J+L7jC48oPQgCo8bRvtp/QhILc6JZl57V4gE4mV/aQAyTdow09nvCYCQ
         1NPKaCwQlsqPHwOmvq8vx6bSTOEjn2tNAeeJ0ccKF3txobmjfNDdnRjzkcwaf3G+s2Vq
         Izc39focRslkTddju+jpnORMX8D0nQPH3ELzBbQWwvCOs37MaKxi05KfzKDv20m8ewt3
         mUHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JLmVbvSqWmOqtGgYEChqLEeubWdQMpi8zxeqeOKXKeE=;
        b=GgojXvGT/+q4XPxCEvwN9xJ2aJ0yDAsllE+oiJrrrUs4yljqJHioiigSxKjNoN7pla
         cQeGLR+RzquZ/eThruyByoHZ5CY6dqrnEV9fOxILUNyhrxXDdzdm/NWW5g5wMkW99s18
         m2BomNWY1ymsXIXY5CYM199CixJVRLl9pcRo66AjCysuS4xxTeQEtB9gnv2h7peqm486
         7APxy+K57x374hNsR8nAIlxw5Ki8T1b+btFOCzqhT3zcdik2qSUY4H1FoJbRtqaUNHpd
         gmH86F3nnjKMWV5IkeJTx2naYIwzCIo4JdKyHOc29VDMbU7g42pBoDQ2ZF2iGjzqLnM/
         wHqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533d4QbO8DjpkncrUTY1X2XiEPa5DFx6yapyktTRXzzryJYC/CdV
	WAx2rTEpvEMsEtOFPrE2nyw=
X-Google-Smtp-Source: ABdhPJyHhUpeZCUGVQZPgN78OfgtkWqo1pXrpRBGk/C7ppa8FCqwTXSg/tFA+gJN6OyOGrocZUxtCQ==
X-Received: by 2002:a9f:2428:: with SMTP id 37mr993484uaq.40.1604673941698;
        Fri, 06 Nov 2020 06:45:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:649:: with SMTP id f67ls98263uaf.8.gmail; Fri, 06 Nov
 2020 06:45:41 -0800 (PST)
X-Received: by 2002:ab0:654a:: with SMTP id x10mr1060156uap.78.1604673941148;
        Fri, 06 Nov 2020 06:45:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604673941; cv=none;
        d=google.com; s=arc-20160816;
        b=URzl4nB2HgnfHXc5ng0iiklub7FJz9o/VCNPWmBr3aLRihPUxXvYZZIFuHyK84jYem
         Wx6OZKBPi0J+Bvijs1RrBUKfGO18a7Ce01ekGbdrlMujDfacqCol/54+MFPl0n4hBfQk
         LoYRaHQFZzf72BpcagxbZdUzbQ0wCOzg529Whp/QbdyxXdrXFqJ+H5rEe+6UP696gf73
         7aYtZsIv4hnTuH6BFQ0aPIFwpSMfbUaw4G4+OxMeCq/PSqRB0PxckCqXxhsY36XWwpCU
         DfcrN7O0yYGDaFwpGQjsu455ciLCoeOmvRpCrL6ZRwFwmyVeSRnaapvquKXHv1rkK4eR
         whvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=JXQ0VH9J0/PobWHuzOTEqPLsIiVQ6kUM+YhxZJMzUyI=;
        b=olhUtoWqr+8j6qWXNoqFp01azz8DZUG6lVgZYvkGt8/aLWqeu2wT7dNqEkllCa8Mgf
         Vb3roBSuFsgrcp6pwOVnlqiwv1slkvMCby9Uq9yhlyh3Hphmz6YpLJIXxZRiCbx7kmZc
         xCfYP/O7KBd3Q7isgLkFBBFb33Lq0tG6VjKHIeeI19te9tM4iRUZStpszBWqQp3fJvVR
         56jNiwqAwu9nZIueBxMYbUknPM1nEceMLWAeNsdWg3byWWWnASFk9GywhEYbVqB/lLlR
         QbzjhBx4NakUeMaP3fPDoXU1asr58nI8dpusyUtdF4ABRuOVyNO7tKsdyRnkuiZoYvwO
         HY7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="dQscj/OT";
       spf=pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t26si100380uaq.1.2020.11.06.06.45.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 06:45:41 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9BEC320724;
	Fri,  6 Nov 2020 14:45:39 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3A439352097B; Fri,  6 Nov 2020 06:45:39 -0800 (PST)
Date: Fri, 6 Nov 2020 06:45:39 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN build warnings
Message-ID: <20201106144539.GV3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201106041046.GT3249@paulmck-ThinkPad-P72>
 <CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="dQscj/OT";       spf=pass
 (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 06, 2020 at 09:23:43AM +0100, Marco Elver wrote:
> On Fri, 6 Nov 2020 at 05:10, Paul E. McKenney <paulmck@kernel.org> wrote:
> > Hello!
> >
> > Some interesting code is being added to RCU, so I fired up KCSAN.
> > Although KCSAN still seems to work, but I got the following build
> > warnings.  Should I ignore these, or is this a sign that I need to
> > upgrade from clang 11.0.0?
> >
> >                                                         Thanx, Paul
> >
> > ------------------------------------------------------------------------
> >
> > arch/x86/ia32/ia32_signal.o: warning: objtool: ia32_setup_rt_frame()+0x140: call to memset() with UACCESS enabled
> > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_prefault_relocations()+0x104: stack state mismatch: cfa1=7+56 cfa2=-1+0
> > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_copy_relocations()+0x309: stack state mismatch: cfa1=7+120 cfa2=-1+0
> 
> Interesting, I've not seen these before and they don't look directly
> KCSAN related. Although it appears that due to the instrumentation the
> compiler decided to uninline a memset(), and the other 2 are new to
> me.
> 
> It might be wise to upgrade to a newer clang. If you haven't since
> your first clang build, you might still be on a clang 11 pre-release.
> Since then clang 11 was released (on 12 Oct), which would be my first
> try: https://releases.llvm.org/download.html#11.0.0 -- they offer
> prebuilt binaris just in case.
> 
> Otherwise, what's the branch + config this is on? I can try to debug.

You called it -- yes, I am still using the old clang.  I will try
out the new one, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106144539.GV3249%40paulmck-ThinkPad-P72.
