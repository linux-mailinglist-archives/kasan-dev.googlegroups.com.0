Return-Path: <kasan-dev+bncBAABBXFETP5AKGQE34QJPJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C6842539A8
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Aug 2020 23:21:34 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id 15sf2213999pfy.15
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Aug 2020 14:21:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598476893; cv=pass;
        d=google.com; s=arc-20160816;
        b=p9O3dC4Oh7CtcW90tcKQSNpSNI1vy9KS0SyNGifB8U9SK97A6Gjf/uxK1CW/+Fs9yZ
         CXv4tvWSmMbgA1cYj4uSI2epWwmeAltVmjWHYUPUZpDYlRKpY2Tpyd884SLya08MNb7w
         +8nrU2AEPjPmdKHxz0AwOIQQB/zyVKZaMT0pm5Us9Z0bztj61f44oAeIwnK4a/y1Km+p
         wtCh/zwDyvE1dy9tonSXDA2m9ZNph4ZW55puH+B7vM18j0McZwuHCMpiGRuPvLmwKael
         e1Vyk5vp7Jgs8T6d89q8yB5cx9FhWkMNxgtdCdWSjbHk27Q1l9o+rutFm8W9TBgvyi7C
         QGWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=AsDmFihP/A1yo1hQ8KL0HX4yLl1Q9o/knK0Aw/NiKts=;
        b=NLEsSVy2s0LyhCNevJBqAMj186z9sjGeIcj/mY439s3YbHCz6ktqIypMsObLroeyUO
         tun2W7lh7QV5TSEJwxuiKsOnSUzVm7vzXkmHqqRCf0IHBH296kDCpebxNaYJ8dVrNtd6
         8GcEuhTh1E7X52XHOpCSw2M6LvHwKCMuTRr+5isRbnG/3dcodF6QJdlH02UHDc4fYn0x
         /7SbcLDe4WMvh33faePW66+uqOkU+jOidffmpLNVJt+XDOYGkv9X6txYQZNFtyNC4FHP
         AyjkutVpFAGJTctrKs4RL87opGCwJfr97NwFNazJMRkg5in+2t/srEsfpyhorHO23Tbr
         SyjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=G5eB9+Pt;
       spf=pass (google.com: domain of srs0=vf6r=ce=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Vf6R=CE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AsDmFihP/A1yo1hQ8KL0HX4yLl1Q9o/knK0Aw/NiKts=;
        b=dOWjbohpuOJ7SipXW0EjwqR385yWJlpeuk0WZorhJj77ZtyyBpl15KvC1lJttGFKlT
         4L5SDpFeYRrGu/hocwBt/waWf0BGkBUvDlb/fss2m/FTHuAVqtTaOmXmvHQ61kUQ4MGI
         Q9GBaEMe4IYzkYE/BkqbJccHMJzGp5uqZh6FbpdbcLcQOOBvU6/60jcQF0vKm8InORjD
         oKO4j9sYDnUBowgmKDrd2kjIDktcHbFzc/Yr9O620qgZuma2sU/za7peR9DpIrNlaaeb
         5oVhrkYhZUdXm7MwygXbWxTL4WXfzMxkrmzeqqd8W9KFHRGVttskHf1PVKrUb8MN0QVW
         LtCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AsDmFihP/A1yo1hQ8KL0HX4yLl1Q9o/knK0Aw/NiKts=;
        b=J3Zm1NvhTMCT7hTYbUhpFz2ay+RsfHwpWEA/36mInJk9diEfGFAfehRwswMnb0nc2E
         gB3KDLlRmwSG463pUdwFmtHeajds0mCaBnaCgGM8ar6eK8JJkQyFfaGusiYI5Cle28OR
         IGnA7vRM7X/jVEe6hnKppRoU5C8SN4ru/jzrCLkYU4N0MmSXafDGSsoARld3RGgjlVbz
         TJD4a8lzPE/Fqom05ceov9+8mSYEuYfaKho2JxqNQaJlYbrGmVWUmfhBQ7F1W5+tieNS
         pwKbn7MKMYIlH9M/DdP6GJWOXhksBU7dZGtbJ+1YcqhBAQ5ego5bxaynYBZggDFqqj9H
         jxnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+BFee1IQNiMvATuCrfHqMqQfUu7RrMTsnAOi1tEmGdeWT0uKy
	HJ/XyzMiR/vviXRod71tcWg=
X-Google-Smtp-Source: ABdhPJy4mhTEvJkW0OltOYILu76eBlLS+6qVMkCwIFZuKbXtGvK270g6Zz1PtwqwQ+7LoyU8V3H4XQ==
X-Received: by 2002:a17:902:6a8b:: with SMTP id n11mr13135033plk.156.1598476893003;
        Wed, 26 Aug 2020 14:21:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c244:: with SMTP id l4ls74552pgg.9.gmail; Wed, 26 Aug
 2020 14:21:31 -0700 (PDT)
X-Received: by 2002:a63:1d4c:: with SMTP id d12mr11884768pgm.365.1598476891150;
        Wed, 26 Aug 2020 14:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598476891; cv=none;
        d=google.com; s=arc-20160816;
        b=FIo9HsjIkqtPKqlna8JaAzOsU2AODGWOSM8HOR09BCLbTfmA1MRJ792g6KiSb0Uv6O
         Srzn6w+Ee5kUyCl8SD2WLLAbnmuyh6Ytkcm3lXY0XaqW5wx0XE7iKF17vPFOmApGIyl0
         NAxRyL3TNgrMigPrynRmjOgAXRHt+S3d3PTsK1FRb5MsahDryARdBcXMt4aBsqE0iyXY
         v15m2d+7cvNn7sFmNtBkinAjKRkfsATLy/Ra7+rPOPeM9xjA8XgRcNOrRFo69Aqnd+Mf
         z04GjVJL2AC654Im9yxz/TiyisWKQ+oheuwfWC5+bCm2z4wB6yR5A8vx0qCxmjR34D8A
         Gghg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/vlhsGfwizxaSUTtjqPPHQi7YwgiZLWtNN9C64aqcxA=;
        b=fu16rHYgBPUuy4oTE7agf3ZPYD93brSVr5vDRhr/KqokVdP7xQKf/ZuJdWZWfPv2OU
         yfxvXf54I3e6zOEAWXoQnYavUNP/HK/+qjzx3qIp5pTzspgQ1bg2IviQeQe4F32O2hcB
         +r+m2mtAxyWQc1FGjpBEaYAHHciVY8k1vtOpc1NX0snCejRCdoIb28R0P4sva/HTfQpW
         APLRzz/M4IGo3DI01PsYp2CFlrQwpVvJGiAcAaCOcBJSDOm3AqBoCjgCuAFOTsIMHtiI
         VPxuCehoSH6cEW4komMCe+J3/+gvVZiEjIX8Sja7pKQ64xMyq+yx6Mc3cKhPOvgMKpmZ
         TCNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=G5eB9+Pt;
       spf=pass (google.com: domain of srs0=vf6r=ce=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Vf6R=CE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ls7si140156pjb.2.2020.08.26.14.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Aug 2020 14:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=vf6r=ce=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D67F920737;
	Wed, 26 Aug 2020 21:21:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id AF6FA35226D9; Wed, 26 Aug 2020 14:21:30 -0700 (PDT)
Date: Wed, 26 Aug 2020 14:21:30 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Use tracing-safe version of prandom
Message-ID: <20200826212130.GU2855@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200821123126.3121494-1-elver@google.com>
 <CANpmjNMLL+Xqg0MQrtBMxLunUGXVP-mAXKqRH5s0xNSfAUhrzg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMLL+Xqg0MQrtBMxLunUGXVP-mAXKqRH5s0xNSfAUhrzg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=G5eB9+Pt;       spf=pass
 (google.com: domain of srs0=vf6r=ce=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Vf6R=CE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Aug 26, 2020 at 02:17:57PM +0200, Marco Elver wrote:
> On Fri, 21 Aug 2020 at 14:31, Marco Elver <elver@google.com> wrote:
> > In the core runtime, we must minimize any calls to external library
> > functions to avoid any kind of recursion. This can happen even though
> > instrumentation is disabled for called functions, but tracing is
> > enabled.
> >
> > Most recently, prandom_u32() added a tracepoint, which can cause
> > problems for KCSAN even if the rcuidle variant is used. For example:
> >         kcsan -> prandom_u32() -> trace_prandom_u32_rcuidle ->
> >         srcu_read_lock_notrace -> __srcu_read_lock -> kcsan ...
> >
> > While we could disable KCSAN in kcsan_setup_watchpoint(), this does not
> > solve other unexpected behaviour we may get due recursing into functions
> > that may not be tolerant to such recursion:
> >         __srcu_read_lock -> kcsan -> ... -> __srcu_read_lock
> >
> > Therefore, switch to using prandom_u32_state(), which is uninstrumented,
> > and does not have a tracepoint.
> >
> > Link: https://lkml.kernel.org/r/20200821063043.1949509-1-elver@google.com
> > Link: https://lkml.kernel.org/r/20200820172046.GA177701@elver.google.com
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Applies to latest -rcu/dev only.
> >
> > Let's wait a bit to see what happens with
> >   https://lkml.kernel.org/r/20200821063043.1949509-1-elver@google.com,
> > just in case there's a better solution that might make this patch redundant.
> 
> Paul, feel free to pick this up.
> 
> I wanted to wait until after plumbers to see what happens, but maybe
> it's better to give the heads-up now, so this is in time for the next
> pull-request. It seems that prandom_u32() will keep its tracepoint,
> which means we definitely need this to make KCSAN compatible with
> tracing again.

Queued and pushed, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200826212130.GU2855%40paulmck-ThinkPad-P72.
