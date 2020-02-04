Return-Path: <kasan-dev+bncBAABBYNA43YQKGQEQVBKGOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D2D151D6E
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 16:40:19 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id 206sf5083105ywt.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 07:40:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580830818; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJjr77WdO1gq8uvCx6TzeE/dG46cOZA7I+oMq7KwTq18HemJs5cBbU5mSrvXv2jKnr
         kQ6S52spmw8Ck26VezlhxLTze4w7TDa0hcoVI25ITNkRGKh6JLnXhKqwHBFDGIfSDO4H
         +TTl8xjG9S9SDObOQ9b2eLOr7F7PVfR1DRXfLpCEH+BC0ZR+YuKO6/geBzjGsmYz/vXc
         BU8HFre+Dh45FUT6uvice5woOFSaMIzM7upUR3fk5KB6bBI+pF0/iwBU0HRnoa9x+EIK
         EtLFfk1u44d0pkbkG05rqP2YzfzPOw1XyHu+8gZQT0uZNMSI91Ygy1BcmBFSfP5wxnrC
         uGug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=IG/qG7Nc/OlHKlCr5nV672dzQBLjVBjyeaXxRdzdubo=;
        b=oh4gQygq01Ir3IGvuyPueor3kOGflvXrrP4VHkf4jJGN4PihTQOxv/DQ5z06ghr7zs
         xIH4n5lYi40ZkQHzaI18eyd0LA1ajTHoo8KQXwCDhms3ZPiXyNMMuClZMeWAuaIIKapb
         6tna8rrJTryYPId8kdQNgBctZgMQ3gIzrX06GFehwFA5BakkjdT8EpPkEYZXm6hK5cYw
         WB2UUKu00SuO3Qh2Bl4pz9/oxxEFML6VRJp02f8s7Dz7JC0y67LHrsYEX3xp0Z2f8Ky5
         SLMqqMwl4gtSLmAoDFnacvt/I436eQnRau0ucf3uuJ96w/j9zS10c9Pqe9D2XnJgEcOl
         5YBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vodTEsLi;
       spf=pass (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2yFN=3Y=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IG/qG7Nc/OlHKlCr5nV672dzQBLjVBjyeaXxRdzdubo=;
        b=EUh7BIMACrMt2psrCxJ8YADhp/H+KUIqF8OQGfWilX7LaVRMBDjX5u7BWYJdcgl3ET
         13MYzoUAGIpi4h7BAsf/bABA53um9TaUQoWtrlcxSuBxb/GwVzRHPtse6CGDdlKA4ryL
         Wv1whwXUJcHZCTsL0cdeEzN/Dq9I+sSdq1wXmyPO2i/jnvzxfa18ZRk5RJO37yhL0Tp3
         otNJAP/GAb9Z9SjP7JzurXIFvi2DfHfNq0IlcnNlTUhlk2ct9ffQq0QpD/jegYlpcbDJ
         KpfaP2+kfIke+JwHq+4bGRVzYyS1Ewpl37SlZ72Sn4FNRskzrQduGNmB7ap/rpTiY6YC
         vi4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IG/qG7Nc/OlHKlCr5nV672dzQBLjVBjyeaXxRdzdubo=;
        b=BWJTUPIkht+/BCgEM8icloBA7pwmOW19EpcZ5J2P1ehcAx4li5TkhzPcJRm7lDD+lm
         I/Vl3Sc+KkVo4pN/lUTmtyKIUFmcxKFW+DsHvg7X/OKaocBRmTPIBVkasIs+HzW/NItD
         eNG1xxtGdKZw/PHaxBrd+xwk7VDSzR/aRu/UGHPTpMFm+wEeY9XfLM7+roBFdlQWnGJy
         wadSGAfiEzTNfLWli+YQeaoYuvMd3pbs9CcmRENCm8SMtf0/wmxzeGAMsgxch82N3JM5
         WXA5LwVNMHJb92L7UXIiLIJ4zHAZDXUWgSIZo/EeS6zHeTGFJLNi1r0uK7o2kjxloH1B
         cv/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUhGyiq6/mDCx3ujP2qcmI/zPJN5oXUMUTv3q2p0O7Uw1bylQW+
	PrXd0tN6Smqkgpzh3WqosO8=
X-Google-Smtp-Source: APXvYqyBUU+cqzLrKzAy3EhsWBFW399+qzIU5jbQNrwWr5bfnVjTdhed2Nq23vGiNR0cI9cBkK8T9Q==
X-Received: by 2002:a81:5305:: with SMTP id h5mr6230873ywb.31.1580830817107;
        Tue, 04 Feb 2020 07:40:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:381:: with SMTP id 123ls788795ywd.9.gmail; Tue, 04 Feb
 2020 07:40:16 -0800 (PST)
X-Received: by 2002:a81:a503:: with SMTP id u3mr6472700ywg.476.1580830816776;
        Tue, 04 Feb 2020 07:40:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580830816; cv=none;
        d=google.com; s=arc-20160816;
        b=Ny8dtA5B8M7WfH+mOmC8JOriqIM44b+lTU5uu6JHo/qr0nIscksEAEnDOhfHU67Qqv
         zE3xVXJTmsHWwZc900hRaehePVfOG6PpptRoWsG+sRP6u0i3inABHtljq46ubtIe0P7C
         ntFPjGUNRu9jVqDM5yXHrtUuq5wOMplutVn9+jUiChHRiO3najGBiYjVqyerX1ru+6DL
         5qFSMCx/dxuM97gTCZbZo89sVOksM5O9zfDxQ6W8n0vZ25ySnJaghq1ljU1+OWugp2sT
         Ru2k4X7DChkvDUmjpjm5EFIgflI49oAgJ9+JEdWOoJk+hGpzuUVG2IdevIYuFdn7TD/6
         3xgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=90ClAjQpsU5CSe8sVzwLWWPxmOO+KWFxPGZXr3JkN1M=;
        b=MZJ0aHEXKFN8dSd6EnPhvxY65amDEQdD04Xx6ArqyeRLCNSLx3l5CPJm304V29294b
         1xFJ3tZB04W2nIQEd5SHJCeedvlK1yDq1wX3kJtyhsownxJkRs9ptwtklbUOjl6c655y
         MjmuofovAUTVOpbui7ZQp2IGYur67WieVoKz06hWGHyUfOw+jutTZuL9i/0+0GNhztze
         M3fko6nyJuk1v/i1XGDDKj4AICu2g0a3lhiHvPxLc3aAsxqPkBB4Vatvx157jfCpaYyS
         PlRbHsqCvsb3ipPRsr8JGyIenVi0f6GgV9ruZamGzikwP7M1IvOIu0+o1/190zCMPBqE
         4QwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vodTEsLi;
       spf=pass (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2yFN=3Y=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t82si1310998ywb.2.2020.02.04.07.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Feb 2020 07:40:16 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CAB1720674;
	Tue,  4 Feb 2020 15:40:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 5D8DD352270F; Tue,  4 Feb 2020 07:40:15 -0800 (PST)
Date: Tue, 4 Feb 2020 07:40:15 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 1/3] kcsan: Add option to assume plain writes up to word
 size are atomic
Message-ID: <20200204154015.GQ2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200204140353.177797-1-elver@google.com>
 <CANpmjNMF3LpOUZSKXigxVXaH8imA2O5OvVu4ibPEDhCjwAXk0w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMF3LpOUZSKXigxVXaH8imA2O5OvVu4ibPEDhCjwAXk0w@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=vodTEsLi;       spf=pass
 (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2yFN=3Y=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Feb 04, 2020 at 04:28:47PM +0100, Marco Elver wrote:
> On Tue, 4 Feb 2020 at 15:04, Marco Elver <elver@google.com> wrote:
> >
> > This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
> > writes up to word size are also assumed to be atomic, and also not
> > subject to other unsafe compiler optimizations resulting in data races.
> 
> I just realized we should probably also check for alignedness. Would
> this be fair to add as an additional constraint? It would be my
> preference.

Checking for alignment makes a lot of sense to me!  Otherwise, write
tearing is expected behavior on some systems.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> > This option has been enabled by default to reflect current kernel-wide
> > preferences.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  kernel/kcsan/core.c | 20 +++++++++++++++-----
> >  lib/Kconfig.kcsan   | 26 +++++++++++++++++++-------
> >  2 files changed, 34 insertions(+), 12 deletions(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 64b30f7716a12..3bd1bf8d6bfeb 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -169,10 +169,19 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
> >         return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> >  }
> >
> > -static __always_inline bool is_atomic(const volatile void *ptr)
> > +static __always_inline bool
> > +is_atomic(const volatile void *ptr, size_t size, int type)
> >  {
> > -       struct kcsan_ctx *ctx = get_ctx();
> > +       struct kcsan_ctx *ctx;
> > +
> > +       if ((type & KCSAN_ACCESS_ATOMIC) != 0)
> > +               return true;
> >
> > +       if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
> > +           (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long))
> > +               return true; /* Assume all writes up to word size are atomic. */
> > +
> > +       ctx = get_ctx();
> >         if (unlikely(ctx->atomic_next > 0)) {
> >                 /*
> >                  * Because we do not have separate contexts for nested
> > @@ -193,7 +202,8 @@ static __always_inline bool is_atomic(const volatile void *ptr)
> >         return kcsan_is_atomic(ptr);
> >  }
> >
> > -static __always_inline bool should_watch(const volatile void *ptr, int type)
> > +static __always_inline bool
> > +should_watch(const volatile void *ptr, size_t size, int type)
> >  {
> >         /*
> >          * Never set up watchpoints when memory operations are atomic.
> > @@ -202,7 +212,7 @@ static __always_inline bool should_watch(const volatile void *ptr, int type)
> >          * should not count towards skipped instructions, and (2) to actually
> >          * decrement kcsan_atomic_next for consecutive instruction stream.
> >          */
> > -       if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
> > +       if (is_atomic(ptr, size, type))
> >                 return false;
> >
> >         if (this_cpu_dec_return(kcsan_skip) >= 0)
> > @@ -460,7 +470,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
> >         if (unlikely(watchpoint != NULL))
> >                 kcsan_found_watchpoint(ptr, size, type, watchpoint,
> >                                        encoded_watchpoint);
> > -       else if (unlikely(should_watch(ptr, type)))
> > +       else if (unlikely(should_watch(ptr, size, type)))
> >                 kcsan_setup_watchpoint(ptr, size, type);
> >  }
> >
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index 3552990abcfe5..08972376f0454 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -91,13 +91,13 @@ config KCSAN_REPORT_ONCE_IN_MS
> >           limiting reporting to avoid flooding the console with reports.
> >           Setting this to 0 disables rate limiting.
> >
> > -# Note that, while some of the below options could be turned into boot
> > -# parameters, to optimize for the common use-case, we avoid this because: (a)
> > -# it would impact performance (and we want to avoid static branch for all
> > -# {READ,WRITE}_ONCE, atomic_*, bitops, etc.), and (b) complicate the design
> > -# without real benefit. The main purpose of the below options is for use in
> > -# fuzzer configs to control reported data races, and they are not expected
> > -# to be switched frequently by a user.
> > +# The main purpose of the below options is to control reported data races (e.g.
> > +# in fuzzer configs), and are not expected to be switched frequently by other
> > +# users. We could turn some of them into boot parameters, but given they should
> > +# not be switched normally, let's keep them here to simplify configuration.
> > +#
> > +# The defaults below are chosen to be very conservative, and may miss certain
> > +# bugs.
> >
> >  config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> >         bool "Report races of unknown origin"
> > @@ -116,6 +116,18 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
> >           the data value of the memory location was observed to remain
> >           unchanged, do not report the data race.
> >
> > +config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
> > +       bool "Assume that plain writes up to word size are atomic"
> > +       default y
> > +       help
> > +         Assume that plain writes up to word size are atomic by default, and
> > +         also not subject to other unsafe compiler optimizations resulting in
> > +         data races. This will cause KCSAN to not report data races due to
> > +         conflicts where the only plain accesses are writes up to word size:
> > +         conflicts between marked reads and plain writes up to word size will
> > +         not be reported as data races; notice that data races between two
> > +         conflicting plain writes will also not be reported.
> > +
> >  config KCSAN_IGNORE_ATOMICS
> >         bool "Do not instrument marked atomic accesses"
> >         help
> > --
> > 2.25.0.341.g760bfbb309-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204154015.GQ2935%40paulmck-ThinkPad-P72.
