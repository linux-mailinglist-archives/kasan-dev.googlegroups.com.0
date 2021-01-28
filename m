Return-Path: <kasan-dev+bncBDAZZCVNSYPBBEN4ZSAAMGQEG7RD4DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id AB586307F9D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 21:26:58 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id x11sf5771824ill.17
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 12:26:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611865617; cv=pass;
        d=google.com; s=arc-20160816;
        b=LIDUyu6NaDoU8MiDZZ42o1EfBbax1qtwyWA8vDCN5176o5UCoAUsNBCNnyD/CoJs21
         crGEGnwhlU56U7exBulS8HDUAad6EHQg1rOIRLKlQxCfZuVU6rcwsZAWJ3X5mrlZF/CP
         haQAbThz7S/mwkIDRNBrXVuaniTQPD0aXQ0Z/cla/ucsFq3L28ymyuH/ZDoIKpF6tALv
         Jtass76qEho6BsUFvzvfNmj7cSF6oZ30NZsn3m7Ip6u+9MDGD2C+uV2o38IYHGR5CDT/
         lKiO5WRRy95gNCnQ8YsAt/nnUsZB8QQ+pbatnkQerbAqod4NF8S9iUSQ66gUW+fjyNlU
         TKHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=SSan547+zz+wGy9FDAByqqRheIZupf2phafgNAgvWE8=;
        b=dtvC0KcNpW4IdApLMNsAswrirLP80FlN8Mlnd0408ffZ34oaJg8PaCMDN4nOX33zy9
         eyBZBH+9U1PauKfGUZWmQImjlHyljNjNyfgKgmBKpjrQ00p1bNWP1+HHQoPDnA+utQyh
         x+gfZ4eAuj9WyjyCMiBYm7mWtWLuKKcBLyVW+D2S7pG5nmBeviH2XlffDT04DL7kAzT3
         fQIrhe9KZ9I2EcWpBXkOYT8h4RaVOBExSb9mHCaMsoepnmdRyDzVuSOKDQv935ehBWxs
         hYZcsUpev3+RQdlDJXvmx5hXcz2Fh/gcqndRDtq3kQbipiHbdHoEALN9SBUilCwq3NMi
         byKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZIVCMyxW;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SSan547+zz+wGy9FDAByqqRheIZupf2phafgNAgvWE8=;
        b=av23KjS9W2fEf26G3hu8Hg/PmnjxVw+oCxJ+hguikF5lMV+v8UPCkyqGQE8QNFBzcD
         iXGqYUY7YQUB/wDbN2jMWBk+9fv3TOn0be3Me4CMRBlFQnUHM1/9h461Hzo2luFjkDsj
         qlafXNs4CNVjsqzxb5oi7GO5bFcShPIhbowaTQEXu3KX9CvUnf1zs5MTuaPN8EJdX/ai
         sbcbjKVNT82IDm40ZIrJhnZQy4bMbV8TlFtLe/zn7hujqc6cGgDDOpf4yiaxEWOsXZMZ
         mqz41c/68SAfe20SWHjZR5izZgXu+oJHlU1cq9sbruvKLsKBHBgCd8b/0gkY1dMIWPqB
         qdLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SSan547+zz+wGy9FDAByqqRheIZupf2phafgNAgvWE8=;
        b=bPwivvmI7IGhUXotM8E0ZlLNougASPbMcFGAhAhRIGcUaqEMjq7gZye9MNDjupnA2L
         bchZAS0X7sWX3CMqkul4uA2jT46Ad58eUi400JsN3H3RAIDxGEIfpO27RYPYVUVa/+qv
         0dnOKtAtmu5cX0U59I0Xtde+jNlUHCaj1QBODbR/biFq58mV/LWMNP9kvVR7VBtguXEc
         FsBC/i2gN2nlCy+eL7aXTN9pcczDjRYuoB73QSZOPdD16iPufbQChI24BA83tKrrUgY2
         9hJfYRLD8C/ytwARwvdt/fv8sFX4oF4QF8ZMKcmevqgifLnw4SYjOYW/YGRkwYRf65j8
         Gr+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OPlHX9AAcYBjxK7l3TBqhSbWIafppur7JSVXIaS3X4Lnx3pwB
	wu3yGyQuiAMclJdfd2WWlzc=
X-Google-Smtp-Source: ABdhPJzgU0MZCs3LNUww3GmbnQaRNPUbAplcBPLJdipC76Xs0FgUd3zPu4ssllen3x4R8Q6iPlMdIg==
X-Received: by 2002:a05:6e02:1aa9:: with SMTP id l9mr694811ilv.108.1611865617751;
        Thu, 28 Jan 2021 12:26:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170a:: with SMTP id u10ls1693856ill.9.gmail; Thu,
 28 Jan 2021 12:26:57 -0800 (PST)
X-Received: by 2002:a92:c7c6:: with SMTP id g6mr648793ilk.248.1611865617367;
        Thu, 28 Jan 2021 12:26:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611865617; cv=none;
        d=google.com; s=arc-20160816;
        b=RYvfqoH6nQQW11lkG7SP1HgFMNM4hZ9/xXCzvtihLwub056MB05ONi6pdkBTP4tOBp
         2JxvPRgzRGKKgkPIYbUByrs0r8mfpn9sfb+L6N+WBWNcEHemGZJWJ8AyN5RBs211Dxcf
         Tn8saOk9XCTcKO1iqpRQphOcx9ZAj+aLgGhxy9vSl91cgmUuVDHhwZaiBDv/a5VIMUxC
         0/XgWfvrRW04dAWCNh3TMvE/yEM7tz9GJGC7yS606UqhWopg2b+/vOQc4wpyq4qno0SF
         AUUbDk4/6+2S2lCjmwAviYmaQ0xybvVAAkDxXRlj0rATEB6HZ9LoMVNxcH0PejIRpHsy
         e5Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KBtWx7NLD0iJkcg6GJnW/OL3qJU37kkwdpST1VF4lKA=;
        b=ZDc4NzuDk5lpD4cPI6vvkPcjk6W/yV2vZlSsS7qvmO1lRnUJ6FYRyfQbvEIeiQ/kSr
         AnvZZhynFi5ce/fzNaSJEVND2q+M99pRpcQNe82BipbAVLclESd1ZTy2VhMGxCzDhn+G
         sOf9wFJ/inlsu6eGMutV7J4eIUmxbj/FK2PAZcMEskh0mME1Xeor4vxn/gKhk+tsDmrh
         A0RdSrsGqaISqsm0z5A6SjLVqyZHkJOkdzlPyiugZtbMNlmxiOYk3FqNfPvP6bKp6KFY
         F5vAPpZWccVfFT4cn3xSsg7YtHZM2ARBhV0mI2XXvDCrIdKrDV+h3P0vOZAT1TCczjNH
         HoYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZIVCMyxW;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o7si319733ilu.0.2021.01.28.12.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Jan 2021 12:26:57 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8D79B64DA1;
	Thu, 28 Jan 2021 20:26:52 +0000 (UTC)
Date: Thu, 28 Jan 2021 20:26:49 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: akpm@linux-foundation.org, andreyknvl@google.com, ardb@kernel.org,
	aryabinin@virtuozzo.com, broonie@kernel.org,
	catalin.marinas@arm.com, dan.j.williams@intel.com,
	dvyukov@google.com, glider@google.com, gustavoars@kernel.org,
	kasan-dev@googlegroups.com, lecopzer@gmail.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org,
	linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org,
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 4/4] arm64: kaslr: support randomized module area with
 KASAN_VMALLOC
Message-ID: <20210128202648.GF3016@willie-the-truck>
References: <20210127230413.GA1016@willie-the-truck>
 <20210128085326.22553-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210128085326.22553-1-lecopzer.chen@mediatek.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZIVCMyxW;       spf=pass
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

On Thu, Jan 28, 2021 at 04:53:26PM +0800, Lecopzer Chen wrote:
>  
> > On Sat, Jan 09, 2021 at 06:32:52PM +0800, Lecopzer Chen wrote:
> > > After KASAN_VMALLOC works in arm64, we can randomize module region
> > > into vmalloc area now.
> > > 
> > > Test:
> > > 	VMALLOC area ffffffc010000000 fffffffdf0000000
> > > 
> > > 	before the patch:
> > > 		module_alloc_base/end ffffffc008b80000 ffffffc010000000
> > > 	after the patch:
> > > 		module_alloc_base/end ffffffdcf4bed000 ffffffc010000000
> > > 
> > > 	And the function that insmod some modules is fine.
> > > 
> > > Suggested-by: Ard Biesheuvel <ardb@kernel.org>
> > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > ---
> > >  arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
> > >  arch/arm64/kernel/module.c | 16 +++++++++-------
> > >  2 files changed, 19 insertions(+), 15 deletions(-)
> > > 
> > > diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
> > > index 1c74c45b9494..a2858058e724 100644
> > > --- a/arch/arm64/kernel/kaslr.c
> > > +++ b/arch/arm64/kernel/kaslr.c
> > > @@ -161,15 +161,17 @@ u64 __init kaslr_early_init(u64 dt_phys)
> > >  	/* use the top 16 bits to randomize the linear region */
> > >  	memstart_offset_seed = seed >> 48;
> > >  
> > > -	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> > > -	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > > +	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) &&
> > > +	    (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> > 
> > CONFIG_KASAN_VMALLOC depends on CONFIG_KASAN_GENERIC so why is this
> > necessary?
> > 
> > Will
> 
> CONFIG_KASAN_VMALLOC=y means CONFIG_KASAN_GENERIC=y
> but CONFIG_KASAN_GENERIC=y doesn't means CONFIG_KASAN_VMALLOC=y
> 
> So this if-condition allows only KASAN rather than
> KASAN + KASAN_VMALLOC enabled.
> 
> Please correct me if I'm wrong.

Sorry, you're completely right -- I missed the '!' when I read this
initially.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210128202648.GF3016%40willie-the-truck.
