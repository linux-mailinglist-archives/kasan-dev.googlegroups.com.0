Return-Path: <kasan-dev+bncBAABBK46ZX3QKGQE4L4TE5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 251032073F2
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 15:03:41 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id q5sf2809767pjv.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 06:03:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593003820; cv=pass;
        d=google.com; s=arc-20160816;
        b=C/0S558v31/Lu+KJH0BSOz/p589iv7x+Zb1IjT6VtEgGRdMZ98ZH2x/MetE7Mp4USj
         CA1c9+95+Wka6ec8erS5FUxh3He75hPZVNreNvsyGgD/2zZw6LWIocsF6jx0rA4Bqc86
         gGku07T+RiUvuEAqdIxkNANgWXywrOhe2fMO/JPSc6bQMfjrWDgqH2kehlcHDdaMoodd
         ZULJIgUX540yZTmB4XN3qFkDR2jeixEjFUO7j34PPhSdpUXQvv6LLMAmCOay7yfAdg4D
         0PqqyAiQQHU/e16rRuyeHKyCzsIQwW1nW2KuVqmobQIq1lpkG8MLqYO/SCxvNqmBXrkw
         sFJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=607oSZp+v+ZjmSX64Qbky04I9wLKLaX0PieTg0Nfx7k=;
        b=lpIXepuW2TlHqKHyTspdVVUKtaCQVHTOuNQ3s8fIB8M9qcHAtLLkkdRXsiWK9o7PD9
         ivKHJMbk29EH5tsaiOgwx/I3FAThbjlwU8OidCraxx2OqpT3sTG7FWdPKGK0DOpMRLZz
         IFgHcRFsABIkqNHyeCCryD9l+kigz/Dgj28BpzmYR77BTi40GPkLLKs4Cp0phPu5L9si
         EdHM3QEjYJKKAspUOK3VcCduSIKfivqIIarhx1xmWpU+Vrw9DEfwr/OajwCtNUsi+dCC
         uj8dMeC6hjR9q3kBUhkWQlKeje8x+Skm0OdH32kzkF/Fq2OX3deHLOpvveC7DVTA6f5e
         cIrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eUtzm10V;
       spf=pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=607oSZp+v+ZjmSX64Qbky04I9wLKLaX0PieTg0Nfx7k=;
        b=lJVIjdcuFgfCYI1R6Tt02nommEXyVBcAtdPR+c6n76wlpDClYKOr/tcqbnS+4wD8oH
         Xzk938ne0x0vUp0eJ8G9M0tRCcWqh8D7l1hqO2bQ/E7S6ymzPQwE8EzYTBknycgfTM34
         HoAGXXhiYMO4S7YXHWEqr9g2KaFfb3QWM9kvnN2FcNuPZOU8UpBi7yRcF2ycqfhPlLj0
         D1qHVgXpQ5SgHPsb/2YDQW9PpJ6fh9nwzg8S7MNfg2wbVt51kfMJ/sR1CndVAFf8V0u0
         NFEsQx+doRHukZsy5Y5b3V2IHi8VADz2OSMac9zyFjPCyTC7HLHNOALqf0jLUZKQXbQT
         nmRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=607oSZp+v+ZjmSX64Qbky04I9wLKLaX0PieTg0Nfx7k=;
        b=TCQz/8WNPkNrB+Be28/efhc+kdA3HpjpwnaVNfehIUiVcTBNTqgm3erjMZJz6GqfIA
         LFu1cjZxd1EZvcSUt5zyr5LfOTeW3YCd4wu+EYu4XgvkdMNYY/ItOOfeKaXG63LOv9G2
         veAEWQJX8rEkl0+u35RcI0ppld7LyRnq80AWe1HkXcuO3RpwPUnyNarHG3wEh/JH/xqF
         WeTLSpHbA7cYaGI/iwldfCIkrJpLOisqyKA8CnM4AVXbNhbdjhR90MIkuBHro2iSZ/W/
         i7Ag9YI81uGKHIILuJ2jgpaa28egrF0bu4HrG67G00q0CFNCT7lGHs7GrimOsEXHQjEH
         TkqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YDmeZdFtaakMNChGuD8GHnx9mR6/+6xcBAxNmg6aKufcV9BpZ
	Bgb3ruR1tpRxZKzwew0Ox1A=
X-Google-Smtp-Source: ABdhPJzuc9ub37x7Bqpv00+zh/xvR0eaJziAE875t/a4AAjAHVYIfTFfd/dOL6jdkdFtauyjy7AUdQ==
X-Received: by 2002:a17:90a:4fc7:: with SMTP id q65mr27439802pjh.25.1593003819643;
        Wed, 24 Jun 2020 06:03:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3acb:: with SMTP id b69ls1054046pjc.3.gmail; Wed, 24
 Jun 2020 06:03:39 -0700 (PDT)
X-Received: by 2002:a17:90a:e50b:: with SMTP id t11mr29238516pjy.109.1593003819066;
        Wed, 24 Jun 2020 06:03:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593003819; cv=none;
        d=google.com; s=arc-20160816;
        b=qrGyHFSDsxMFFNMLn6/mC9ddzMarlK0I1pdtcKsxRU2UOFWGk+xqZCGXmivEuGu/J2
         m/Syb57642rRLg2jx3KgCNyCCGYjOniAECk4jRjVYluaJvyrwc/GtB+A/wKb7/jfBRwm
         FcyJoiK0TpxkFPJUalxmTqNePNKde80k3MCQpOglgUI4XRPVBE8vMjv2HqrKsI5NhpZ5
         CK7WxWkmQlBWsrAm+5aN/RlaMOG3t3JTSWXQYnORdM7+rInArxXzs3yQLrHpsCA7NM9I
         DiF/CF8U6AgYn4gXDa128vFmImYkkpwl4Cr7O+XAuU9GmIh10KGjJoUV5lg2LE32ocZ3
         Sqwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=nMYHYgl+5XiseOCYF/S+DDvNnDaHwJt8bau1KHlpQuc=;
        b=jPAh61LFEUhID8m64a6vm+UExdAQ6RtPlwije69ns1DLe+yXVmYRnF/i8uUAuHnmmf
         iFxMUMK6XyFz9QGvj5OvNZnFbSx2yo5cvfeLo1HE1IoQZExBJfb/5SSTltlQAq6+vZFG
         D6QUL4xKMl3KPw5EnZhzQDF8JEmk8c0g3cDb/ue1jHRjQ8TL7ZzD4p8feWAz1JKEcWcT
         8ELDC3ZLr2pech2Oo74tLtCMlLlUl8OsPg5mpt0WSfOLQvhYi4sa4JHdEX/xlMeEGfPh
         P4S58Z8cM2pur3IGAAjQF6dETViSOJ2BTBLwlPIOv78kur0mLfnVBG4VkgSsXpwObPb/
         cJHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eUtzm10V;
       spf=pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q1si1116222pgg.5.2020.06.24.06.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 06:03:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C23C22082F;
	Wed, 24 Jun 2020 13:03:38 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id AA3743523267; Wed, 24 Jun 2020 06:03:38 -0700 (PDT)
Date: Wed, 24 Jun 2020 06:03:38 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200624130338.GF9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
 <20200619221555.GA12280@paulmck-ThinkPad-P72>
 <20200623204646.GF2483@worktop.programming.kicks-ass.net>
 <20200623214433.GX9247@paulmck-ThinkPad-P72>
 <20200624075249.GC4800@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200624075249.GC4800@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=eUtzm10V;       spf=pass
 (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jun 24, 2020 at 09:52:49AM +0200, Peter Zijlstra wrote:
> On Tue, Jun 23, 2020 at 02:44:33PM -0700, Paul E. McKenney wrote:
> > On Tue, Jun 23, 2020 at 10:46:46PM +0200, Peter Zijlstra wrote:
> > > On Fri, Jun 19, 2020 at 03:15:55PM -0700, Paul E. McKenney wrote:
> > > 
> > > > Just following up because I don't see this anywhere.  If I am supposed
> > > > to take this (which is more plausible now that v5.8-rc1 is out), please
> > > > let me know.
> > > 
> > > Sorry, I got distracted by that NULL ptr thing, but that seems sorted
> > > now. If you don't mind taking it through your rcu/urgent tree for -rc3
> > > or so that would be awesome.
> > 
> > Will do!
> > 
> > Just to double-check, this is the patch from you with Message-ID
> > 20200603114051.896465666@infradead.org, correct?
> > 
> > Or, if you prefer, this commit now on -rcu?
> > 
> > 	5fe289eccfe5 ("rcu: Fixup noinstr warnings")
> > 
> > If this is the correct commit, I will rebase it on top of v5.8-rc2,
> > and if it passes tests, send it along via rcu/urgent.
> 
> Ah, I was thinking about:
> 
>   https://lore.kernel.org/lkml/20200615162427.GI2554@hirez.programming.kicks-ass.net/
> 
> seeing how I added that instrumentation you wanted :-), but either
> version should work for now. KCSAN is sad without this.

Glad I asked!  I will substitute the one you pointed out above.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624130338.GF9247%40paulmck-ThinkPad-P72.
