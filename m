Return-Path: <kasan-dev+bncBAABBU4QV32AKGQEWOF3IIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 366F019FE75
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Apr 2020 21:51:49 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id l12sf243188pjh.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Apr 2020 12:51:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586202707; cv=pass;
        d=google.com; s=arc-20160816;
        b=rstgRP5Z6a0kmZGBlfZ5dZ92WsuK3aMBINiIp164URJlqvJYtmVh7Id0xb9a/NZnjr
         8WBdAH7bkrB604KDofRQCv1qe6LwnJ0P5CJOChnluC6Gor/0nG8GKdHVvSjdIFH4hZj9
         1Gu9JOxTwlQDPkM8bWtQoKsBLCjVueuKvNTJH/PhmvXcKcGWkwSTuYZ8qGLTl7YOnbxJ
         GhgKb0jBg7dL0/C1Vp0KE4KSCQTCSTnVxrNwwYEg+BHR+hlzyFvBUxcfv6LpGAkzY7Hq
         UMVU9I92TwcAe9Y2EIhiLtzNriGt5DdzMgW6A+qWeUQLU6SfZwRb+y7NS9YDyMhFW5h3
         3F1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=/WiXXUlexhMzaUQc/0tpJi7nYp/CkvUXpT4IP7gIMYw=;
        b=aKpntoE+x16+3qRaOOD0Xgg6MabSzVb6Rc5az532Vd/zrb0B19eyX9DFV55nTunXBP
         lIckVGT9rCGtkA3jtzyPNAogirui0S2ep+eYq7/Yo6M0bYJ754pUz6aznVkUlVr1UwU6
         7rB9RDQQjvJa+YEiKQWDUUpzeYBq8Fo4n0Qo+p2Tpj4TLJgzsZ4eLAKa6dQcjq1fe/hN
         pbMm13lrlWbu5ptsf0QGxarMSiEhNcavVtseZ7yG9zbZWBO3wpqvnXnbsKFA3MAkX/fi
         WgWxBBiE7rcKnXbX2KnYJHwssdLLPNTzufVH+22TqLE9R6vFAiAsDj/41d3dfSf+EQ3T
         c0cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=e+YhQu2V;
       spf=pass (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=HppT=5W=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/WiXXUlexhMzaUQc/0tpJi7nYp/CkvUXpT4IP7gIMYw=;
        b=HrYbYvEgSREwJAEv+WRu+8MKBJOLKPZ04mJ+C/PdeaUeZ0D5PE+CrqH65/gaepP2Om
         hDQrEUoK9uWvriW3IcYByWOlIkAxLwF/7jNv1ZT9CoK7FGvdnyZfwKlGrw3O2Z4S37nm
         7EavbQ9EQySreMn9xuLrektiHMblvPFx7qkqjKVIf+c4YlI4TSIjw81DUBlEqBxNt86Q
         T70SVeEugResIAC0ZcIpSVkPni6RQlbwhkdnJYhZrdsiZH2WPu1jiS0CtRk4Nf3q1N5h
         FYocJzgws1reMrvCnatO4ONuCGYJqA/ITENEzAl7Ac9cs3UhbPmSGkdO8raTx6YGks04
         ReoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/WiXXUlexhMzaUQc/0tpJi7nYp/CkvUXpT4IP7gIMYw=;
        b=dUcqVnweGRBH4u4q0d8XawDCTRlJL7HkQchjEnefVVIeY5aMUGdzWAlLmyTNDQ/mQ0
         WXFMZQXh4Do7sjBRTQwnvG+O5lE/GFIxfKJloCEE86gg+1EG7F57LAWlTP0FSgL6CV0B
         ow2VUcORF1RXPESg9Y0dLZLpBboFhkX8rzGAgsF+EVnK/ZYLoaGQCKdE88p6emhojwXV
         Sz7oCnRYMrSYkARtydfxsb/gUm2NuaqgHaPGHK8nFbdPcXK1FdnlC1okOQa7wYlL00av
         KWfU9EhKuLA7UTupatKwpq7/IoIw11qooYyzPhhSvVj9CrNcE17SDQox5OaQr4op2R2A
         Zr6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pua4FXI3iNpYTe7CC4oCVBK6aIjURmcriXKKDe56QW+5ym5TzAQ3
	Zzzu8FinznkZgJRFBg0nL4Y=
X-Google-Smtp-Source: APiQypIhondHr9OBAfJQlrqXVSNpvXpsEZ15lMfgoVOVAWwNnnsfo8XrFh1Gkjdhtk4UuIF4cmtCCw==
X-Received: by 2002:aa7:8645:: with SMTP id a5mr1115604pfo.74.1586202707553;
        Mon, 06 Apr 2020 12:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:834c:: with SMTP id z12ls409345pln.5.gmail; Mon, 06
 Apr 2020 12:51:47 -0700 (PDT)
X-Received: by 2002:a17:902:d705:: with SMTP id w5mr22163339ply.68.1586202707197;
        Mon, 06 Apr 2020 12:51:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586202707; cv=none;
        d=google.com; s=arc-20160816;
        b=HWj7/etfiOhR8Nv92tPBE+6PP3bCOvw952nE+MMo01q7R7A/n6yp5s6FEXnO82xgda
         qGTiug0rmf+HHBE3K+hfw6dbtXxouzkUVM/ITTx8g+jM0I9qRzKmRPNjAPDoFaq95Rl3
         706PL635fHn8IXWvbdjQwKxNew0GqQR7E7b2vFcPPHD/fg69Yb0fSZXf7+ts1ebVXRVE
         HYJxmCSXRbGyRaLdqMpVmxTgx1YpnBeJVtNLrph3KcT0cVoF1OPVFSw+VnIJjxUz66Tf
         LzR5HhlHTYPFZMybvZNcSIlNNNtM5DzwW//Z/86P3Cjy+tpkK6qI3QiVbbTS12pEKXya
         JoOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=xpGOtml6Kmhv270LqN0YHqOdk7wdbdZ+cf5jEHPvypU=;
        b=oTsOpJoOZGvJoI3dL8F9DHmwsasdMA580jIECCfT6UtJUUcOFHfSOsi794AMtQqQUG
         CzaIZjf7LEIJD4bx+U/zJHf3gCHPMd9a2Ql6tcGeHRmX69lKVs3m5Ibm5z5he1QagMwc
         cEB9JD6gZV/isdfta/4QE5Nre2l1fO6cvQncrJki/34oVSftBJCCXZZaOALGV7wWXpF9
         lag0ID59FiM10FdZz+0Gcl5zm3m8XxeUBuaFvVUjIVwEsIGCpqKTqtH6ct1LZhmF+nJi
         k9Wp9G6NoeL/q65Epgfj2xpODODOv1+E3Wx+k6vj4AXPW3QmGI0Ynnn64h2ZZoQvYIFi
         fqGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=e+YhQu2V;
       spf=pass (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=HppT=5W=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c16si84993pgw.4.2020.04.06.12.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Apr 2020 12:51:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C311420672;
	Mon,  6 Apr 2020 19:51:46 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 7DEAA3522B48; Mon,  6 Apr 2020 12:51:46 -0700 (PDT)
Date: Mon, 6 Apr 2020 12:51:46 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
Message-ID: <20200406195146.GI19865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200406133543.GB19865@paulmck-ThinkPad-P72>
 <67156109-7D79-45B7-8C09-E98D25069928@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <67156109-7D79-45B7-8C09-E98D25069928@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=e+YhQu2V;       spf=pass
 (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=HppT=5W=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Apr 06, 2020 at 09:45:44AM -0400, Qian Cai wrote:
> 
> 
> > On Apr 6, 2020, at 9:35 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> > 
> > It goes back in in seven days, after -rc1 is released.  The fact that
> > it was there last week was a mistake on my part, and I did eventually
> > get my hand slapped for it.  ;-)
> > 
> > In the meantime, if it would help, I could group the KCSAN commits
> > on top of those in -tip to allow you to get them with one "git pull"
> > command.
> 
> Testing Linux-next for a week without that commit with KCSAN is a torture, so please do that if that is not much work. Otherwise, I could manually cherry-pick the commit myself after fixing all the offsets.

Just to confirm, you are interested in this -rcu commit, correct?

2402d0eae589 ("kcsan: Add option for verbose reporting")

This one and the following are directly on top of the KCSAN stack
that is in -tip and thus -next:

48b1fc1 kcsan: Add option to allow watcher interruptions
2402d0e kcsan: Add option for verbose reporting
44656d3 kcsan: Add current->state to implicitly atomic accesses
e7b3410 kcsan: Fix a typo in a comment
e7325b7 kcsan: Update Documentation/dev-tools/kcsan.rst
1443b8c kcsan: Update API documentation in kcsan-checks.h

These are on top of this -tip commit:

f5d2313bd3c5 ("kcsan, trace: Make KCSAN compatible with tracing")

You can pull them in via the kcsan-dev.2020.03.25a branch if you wish.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200406195146.GI19865%40paulmck-ThinkPad-P72.
