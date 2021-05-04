Return-Path: <kasan-dev+bncBCV5TUXXRUIBBGFRYSCAMGQEGHVV6HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F95C372844
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 11:49:12 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id k9-20020a17090646c9b029039d323bd239sf2890826ejs.16
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 02:49:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620121752; cv=pass;
        d=google.com; s=arc-20160816;
        b=u+kjqrYXVStZH1nWXZkcDlEu5tk+9O1I2OsNV+JCj8keO0sDFJMkTUVlLdZCfsdfvP
         t4vuEQo/Hh9jLILMa2sI9R9drTE+6ur+JxCc4g0hERro5Z86AtJ+dn452FDn39fR7QTj
         oDiW3zXbYywMOL+1Okt2amPvbArKQKQTeL+AlTJetd63MdcV8OD4u3+R8ncMTAFMgrp4
         SkqF9OhsLAeAJ1z1FcFkeJNVOBuNNTnuwUSYHuoY2GgdAXn/WDSi841TOpZqHGX4enPB
         tSPV5gwFc20x6lKAQExHpYgNUbVFh+3pTMAREHTlewsODcIz0hgZiCr5Dri4QZQIgVs/
         b8Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CB6fWQYDMdgcAznTi3/NDw1Qsl8Ld2Fu+On61xKpsRI=;
        b=DYQ90qds05hcob2u3x+kBZGo8dvU8ALPoSf83uLieIMH248Fdh4vc2ztk58O2CG+Be
         aNF2qMVjjG17/qSyM15R2FZ5KJh2yV6kbsnl7iQiD26ZDD4WKlQKA7F49RHxT66lc5m9
         JTAp7UqgIhqgTemR4Trr+ce0EmNwTpSEyJNIGQxjqHQIsbFVBXHOsLl1H5DO7Xmq/vD6
         IuXosVBZWzVMBLD6d4ALFt98nvlMAygu5v3SaryEJpUsQdN24VqcMQoH7vFBMQ3BIaI3
         GoRQz2NwmrIR9EPhimSI3dqki9HiUehiMCyKx4aO0eMuQJX5nx3QUnZlaoG3IJX+9nCH
         4e0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZF3tmLP+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CB6fWQYDMdgcAznTi3/NDw1Qsl8Ld2Fu+On61xKpsRI=;
        b=G/Gt8Av+2bKV9Ynn1/9AbGAz5zMyWCEqIpPoF6HwyxuREX6FvsiB7MxIKqhdlfEMLq
         BtcFYFMruzLlxC8PgiBxxM84gdxwDmHCVFr00p9vlvet3tSpkTTwmLVKD22HwltzTXyD
         5O98qqMp3qtad58aRzZIxa69BXDPB5Xevz0hG1zjHnDe/6Z02uWYsa3iNvw/TgQWNQ8A
         kF0RdbilYLSMBxV7kjZLrG7kgAhUNsisNuXRN4XUfemzafWznbAgNEAaP43stDi+DikX
         p1KLNLZWT+VFMSJrGAI23VqJAwswRtE6UXticnSBjyP2lCzeT9MzpPAySixdyrxvXl1i
         ILZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CB6fWQYDMdgcAznTi3/NDw1Qsl8Ld2Fu+On61xKpsRI=;
        b=r5/VrAO3xQyk+e4LYoOeVXrQqHqY4EdCTwO8JQGyahmshUOs8vFYbUx0e5M8MOdjxr
         iyl2Re7ezNCmfbuYBazIZ/vtvpLynCWZ3e+P+vWmOQBdve+WeHSGWqsFkBuG7j+Pto0+
         ZJCexYrwqF71d6Sw4z+DAJrOQjinoUOrV8fPKvyZbnrzrlldxkd6JNXcPlPIjkVnVGXW
         XGwENEc4duolDJyPINfeRVmlytccb7FiXfJTmVXSgbmrtEgbetkGVbGkOPNJLtrlIXDy
         a+Ae0GlstkcNi7GBMfzQPX1Uq9XLTlQwPYRe8Z9Vtbmnuk9Jk3gDUt7EFv3hA2XjSl+Z
         Ipfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OfD0cGHOk5+NyTMz9l6gJZ4IObAzDe1v7A1ZImNlsiimXfYXX
	YoFUXcatrfF/dcsZN8fwT2g=
X-Google-Smtp-Source: ABdhPJx13P4IhBr6xw1gW2ZFsYNXtCAllyuXtFIbVuL7LkzHvPVGCZSCms/ZRkIgdZB0NLhUz8Qt3g==
X-Received: by 2002:a50:f296:: with SMTP id f22mr25075854edm.254.1620121752386;
        Tue, 04 May 2021 02:49:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cd:: with SMTP id h13ls2808676edb.3.gmail; Tue,
 04 May 2021 02:49:11 -0700 (PDT)
X-Received: by 2002:aa7:cd83:: with SMTP id x3mr24688524edv.373.1620121751515;
        Tue, 04 May 2021 02:49:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620121751; cv=none;
        d=google.com; s=arc-20160816;
        b=Unhq0W/JZnIg/5CM2PEe/3hSHZHmRPMIqy/vR0dtxtFIzHd7KspywP2sjlfxRBeuHl
         cLaSNx8bu5SuHkbJUQQBmjdVuhgG68UOZxNfm5fnQ3Wsk4RAr0VKrRSQo5CJJYystMeu
         LA5ey1W7cbrkWsNapAEaxGIgXNvUouoAwBZINlYGQIZ2QKfeIrjI5VWA18G9PUv46gjJ
         OLBFecpyOVjW/HweP8bSEgreo9jLBUgq7+Y/TaEC757BzcA7TYAb9Ivh2Q5btVmuz00Z
         3nzc5mJ1dFN8BJGgWYqzgWYllvFVW/AhW6M5YgVeFPdZRpjg3x6iw8Dmx4bnS2z1EwVR
         PvTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=v3J7n0hMzc3/Uwkfxm+uPhLPqR/xUmsvFlQQlOHA4BQ=;
        b=UVE0K17b5pMY6cay7vGyaLCSkPWTiTcC9pe04vo2FhI3sjdDdSPuyn02sIjFJZQHSi
         5/OIFUXAkiOMvbpq33wvDAd4ZIv2lSVhte8NDXcnu5JkjHAytB5V6U5wkE2J2ujl6iz/
         C1lvYTl5Y6WgoEZ5euxV+1gH8xCZXHgX0x/SVsJ0JDP/NMe86b409NMsuQ8yl/ubpppq
         Z/ZJ5/Dlyg7n3WGDcFb65qQ66Zq4jqD6Xu3Hq4fX3U6s/7NtFdgF5iWczc0uaHokvKDI
         xLbLPc3Yy1AClDE1fXrhmicUR8CxiH0VoLiONmkPDQnaTEpLGuIISK+m953ISdD3bvUl
         fQQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ZF3tmLP+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id y5si25498edc.5.2021.05.04.02.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 May 2021 02:49:11 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1ldrfx-00FuWt-9T; Tue, 04 May 2021 09:49:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8464830022A;
	Tue,  4 May 2021 11:49:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6B9A1207C950B; Tue,  4 May 2021 11:49:08 +0200 (CEST)
Date: Tue, 4 May 2021 11:49:08 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andi Kleen <ak@linux.intel.com>, LKML <linux-kernel@vger.kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] stackdepot: Use a raw spinlock in stack depot
Message-ID: <YJEYlAo2HU8KfyxI@hirez.programming.kicks-ass.net>
References: <20210504024358.894950-1-ak@linux.intel.com>
 <CACT4Y+a5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+a5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ZF3tmLP+;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, May 04, 2021 at 09:23:34AM +0200, Dmitry Vyukov wrote:
> So why is this a false positive that we just need to silence?

No, it's a correctness issue for PREEMPT_RT.

> I see LOCKDEP is saying we are doing something wrong, and your
> description just describes how we are doing something wrong :)
> If this is a special false positive case, it would be good to have a
> comment on DEFINE_RAW_SPINLOCK explaining why we are using it.

Documentation/locking/locktypes.rst has the low-down IIRC

> I wonder why we never saw this on syzbot. Is it an RT kernel or some
> other special config?

IIRC the kernel isn't really PROVE_RAW_LOCK_NESTING=y clean yet, so
mostly these checks aren't on by default. printk() used to be a common
offender, but I've not checked the very latest printk status to see if
that got fixed meanwhile.

> A similar issue was discussed recently for RT kernel:
> https://groups.google.com/g/kasan-dev/c/MyHh8ov-ciU/m/nahiuqFLAQAJ
> And I think it may be fixable in the same way -- make stackdepot not
> allocate in contexts where it's not OK to allocate.

That would be preferable I think.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YJEYlAo2HU8KfyxI%40hirez.programming.kicks-ass.net.
