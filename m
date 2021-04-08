Return-Path: <kasan-dev+bncBDAZZCVNSYPBB77OXSBQMGQEJDH5YBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 60761358AB2
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 19:04:01 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id a6sf1559596pfv.9
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 10:04:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617901440; cv=pass;
        d=google.com; s=arc-20160816;
        b=hg4VJ6wzKtX4puAmngxsnR+cp42mcLSwfT1EFZzRDqQLVB/EnGm5vW0NEk9JRB1L8g
         m8A2AhvbyD/G3GzFuiTEhPDaca8n53IN4rzbAF41n46qLTcXYShX24jZ3CqVMBHw9ri3
         H2xvjQ2WXSPopuwSkV8lxFbC6b5rHr7+g5J02KEY7GZLvDUo6Glu7cnImHa4wLpTVe7P
         HK6yfPoLBo0uYHr4fGpuYCjW4zlUSVsdQ62ORPcgQAqloZXQGGIpqFsVY8h/DMdCeAl5
         fI31aSilJaONp9ezQ/DT9FSKsgd5MN1WUiH6Lmc8sKTfWsuJmdYQKGRHDNUBINGSIJOs
         ZO5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=d/8LtfDNBUXOENZOlr/tK4q0OG6t+GwwYD6xRH4gG8E=;
        b=XIYvYPZ+dWaMdhvpd+8YtDZ+yb68awuCqzNLl/5FErzvUxqdN/lO1NLysOBvCSkbOr
         H1tC/+AmYFnLWIkuipBVqTgii9E+XwLNP+TkGLbuuhbObYtyadRy0ddXJ7joK4oJ5skt
         3sKHKM4GyaN26Oed0wJ7/HzhhhzLeboPg4SmXboZKpCC74ofKD4k2dHlU78ZJ0WRUBNl
         v7WuxUZrpjbeY/zGC+yiEBpVnD44xN9FQ18T8hTkHnn2mk8Rvj2JrQ8eKdGc2p9Jx5/F
         yGCiMdGMXhnZl31TYVu3rzsLxosnmDGAasT0rvrxLbhqJJ18wimPkZG/gCsuSQ6HSjIA
         3faQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WS0PzOme;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d/8LtfDNBUXOENZOlr/tK4q0OG6t+GwwYD6xRH4gG8E=;
        b=NS2CxGu1mn5HdNAQ3pqOy5CCwZxUDF5Zmu0b66hp31dVxdJ+o7AnxzKPzCV06Y+VqA
         KMWtl8risO1G/0YdihdWQgOA3DsZR5rm+uTgAMJkwzJftk1I2EQ+K5hcNpAR0b0FsjtV
         tXC5tTnPJYJCPCbUEyK+xWtB1aJnrsttxDxURIBKOCYZCIsZzfw3Utj10epo/6sQqUXa
         dOvXVR8P80v0ChXx9Hj9vokMrI6XfB/T9kADRQfu0SUYGNc73DNuKWUNKjKchw3Oh7vm
         4sefrkgEav5yz79HdJMpZM4nemqXmQ4WxdfoBwzjNUVCz/1lp6aJdxilQsdqDP4MhhIB
         8KCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d/8LtfDNBUXOENZOlr/tK4q0OG6t+GwwYD6xRH4gG8E=;
        b=jQPcnCrqC1jOFkkMF65jY5y/wMOUAJY8hVI7kIGSX5XPf0NfI5tg/i+yVzMk7vwCCV
         2KTcH67X6neMvgQvhzd2bE2fMAU8uy9wTAwCqJ+KrqbMEFA+1ibCVSaCjGJ1bfdY5jm0
         ld6it6RGO8XXU6OzsR1m1DMmNj/YMQ58SEMSZlaaHHIp4GQoaoWUmC7z+FbLOYTqXCwF
         jbRlBJeey97ThoTVmLZ9wx83ho631ym09gDU+sqZwOz0RWUBc3bTBqaCsQ4dUw3t2tzj
         chuEYGsAfWFo2MdDl8wjQ1rQG5XRiWCB3OEv5zb41R4zRqxaSlA2ju/+7JKkPKBRc+1q
         s9HQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Tz6bYVcRVFOszGGLHV/d/5hEo3Ssi4nC4zLolE9hWbgDn2Z4r
	Y11heFHaarrF9sSE+EMuTbg=
X-Google-Smtp-Source: ABdhPJwyqgqu85yfCJKzMq0mUd4fTps2sInboD1Jvaxk0BZFPmAReX/x4PP0x1J0WxYB4bXms/Y2cQ==
X-Received: by 2002:a17:90b:3545:: with SMTP id lt5mr9351625pjb.194.1617901439995;
        Thu, 08 Apr 2021 10:03:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31cc:: with SMTP id v12ls2812825ple.9.gmail; Thu, 08
 Apr 2021 10:03:59 -0700 (PDT)
X-Received: by 2002:a17:902:e313:b029:e9:263e:f5f9 with SMTP id q19-20020a170902e313b02900e9263ef5f9mr8666229plc.53.1617901439457;
        Thu, 08 Apr 2021 10:03:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617901439; cv=none;
        d=google.com; s=arc-20160816;
        b=D30UxxRruq65+lxxveSy/tfNDaML0QSqwWTev1wdx3Xm3SX68/H7FsvNq2EJdbGYKn
         8wE9Q38Uam8I9sQmIBYw4bZA6FKiBjl32TjHnPpnJxbSSrCm+QaQLDWPtttyrspGjOgY
         y8e3siijSMFmnmHZojOZ+B4KJIHFmPjijUHZH0VwYsH9gnYYEOAUaU9/Kg884dXS7aOu
         TNeMg7Nm6bGsl6JhKgPaNQC4U46qW01g5MWB1h1R8GZJym90eygxm/gJxztvFmRyn1oa
         GynNraMNV2Xnt6hFkyIWxaOTPmU31FNRvXYct1YS1x9jUvqNoTmZAnoH+bgJcrh2BO6Y
         f1oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aWAxZ3Yh4m8YZ4f0Iyd/D3s1X5FrdjWQNv90X7zNboA=;
        b=aQHqfk19IrXpHcuzfjSB19y7b+ZMhiGQeI9DkdiqAld6kODnfx+qzmTHpEwNRsgcjD
         6/fWxo9SEij7LAf6NSTk8Yr8UmR8SXQEVVAjPRhZqmUI86H5aYZ1v1jNPlpSKI8VIGaQ
         UD4ZZT2OxrE8vo/984+opMYK5zp/3OzDixbB4aGEjRWYFQbp9HfWXCJ+st+5Y0BqcmM2
         GBhqtpwYUJtD7MsBS7bQjhdnWzusIfES+w/lruoVtR6aljEX/+HJDzVytHAIeZeWFGMu
         a79Gp1sZV1l9uiv7BpCkefANVC0E8rIobmpRc1Je9IlMJE65g9p6cSKVtuIvNAcDHWVg
         NlUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WS0PzOme;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z22si5530pfc.6.2021.04.08.10.03.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Apr 2021 10:03:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 13FD2608FC;
	Thu,  8 Apr 2021 17:03:57 +0000 (UTC)
Date: Thu, 8 Apr 2021 18:03:54 +0100
From: Will Deacon <will@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210408170354.GB18321@willie-the-truck>
References: <20210408143723.13024-1-vincenzo.frascino@arm.com>
 <20210408145604.GB18211@willie-the-truck>
 <20210408150612.GA37165@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210408150612.GA37165@C02TD0UTHF1T.local>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WS0PzOme;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Apr 08, 2021 at 04:06:23PM +0100, Mark Rutland wrote:
> On Thu, Apr 08, 2021 at 03:56:04PM +0100, Will Deacon wrote:
> > On Thu, Apr 08, 2021 at 03:37:23PM +0100, Vincenzo Frascino wrote:
> > > diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> > > index 9d3588450473..837d3624a1d5 100644
> > > --- a/arch/arm64/kernel/entry-common.c
> > > +++ b/arch/arm64/kernel/entry-common.c
> > > @@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
> > >  	CT_WARN_ON(ct_state() != CONTEXT_USER);
> > >  	user_exit_irqoff();
> > >  	trace_hardirqs_off_finish();
> > > +
> > > +	/* Check for asynchronous tag check faults in user space */
> > > +	check_mte_async_tcf0();
> > >  }
> > 
> > Is enter_from_user_mode() always called when we enter the kernel from EL0?
> > afaict, some paths (e.g. el0_irq()) only end up calling it if
> > CONTEXT_TRACKING or TRACE_IRQFLAGS are enabled.
> 
> Currently everything that's in {enter,exit}_from_user_mode() only
> matters when either CONTEXT_TRACKING or TRACE_IRQFLAGS is selected (and
> expands to an empty stub otherwise).
> 
> We could drop the ifdeffery in user_{enter,exit}_irqoff() to have them
> called regardless, or add CONFIG_MTE to the list.

I'm always in favour of dropping ifdeffery if it's getting in the way.

> > >  asmlinkage void noinstr exit_to_user_mode(void)
> > >  {
> > > +	/* Ignore asynchronous tag check faults in the uaccess routines */
> > > +	clear_mte_async_tcf0();
> > > +
> > 
> > and this one seems to be called even less often.
> 
> This is always done in ret_to_user, so (modulo ifdeferry above) all
> returns to EL0 call this.

Right, I was just saying that if you disabled those CONFIG options then this
isn't called _at all_ whereas I think enter_from_user_mode() still is on
some paths.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408170354.GB18321%40willie-the-truck.
