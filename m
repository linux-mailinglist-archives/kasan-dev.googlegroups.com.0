Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2WE7WAQMGQEC2VPNKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF68D32B685
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:18:19 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id u70sf4025380vsc.11
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:18:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614766698; cv=pass;
        d=google.com; s=arc-20160816;
        b=tRLdSH57rZt7I5xQOVB5YKIA+FNWfffVW+I34+VDIhAiZQnJRAtRNyL2ePEMOn+FMk
         0GLHEmr+e8KeC3ZphVBm/3ET4VsDLQzNJDtYU8Ah4ZsmVPQIqTw4VCRoocwMSZh7EZj7
         BCrWf6tN3RFbc877MJ1nQJMoEqoUxtJuo1KYbhdcn7QC1uBuoCS1dfycpJdx9DXXHIJk
         To4nxFVcpzCDou3cu19HwTgHm1F4KKimd8gsRXNA8+9KPS87kljPIxd8lNvP+R8iu51q
         t9aUnQ/9CV+5ySH3V5PsSTJhN+fbXiblbolxq8K2Zcmx0pg9dN236FPaqIy9c2Thv6iS
         ByEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ta4m9mJkB66iuR4gWb8GKPtDSFgsSoifGPifWnvHOxE=;
        b=z5/1At+U3zlba3I67Vmj80hDGc6YccHJ6SKn3Gejb9gu9z4VwIlYg+u+TPiw9+bPRt
         mCapWOfGafeXQZ3qn3gRgJtMPxAITzGe9z+Dii2rkEmyHIQot+5oj2zR+k8q9UQkagro
         lyG+0D4a+KbjXKeSjTSEJi6Oq/uZxkVxphClrV96IAWSataBqHLXl0nZae+hLjHK18Ci
         Ic/LkEvrbWPx5yqgboBGBdiJ2jbktxZoQSutTcXROR6QY6iJkAGu4TzYlIaZ0Maxm0S4
         zN+wCD77++aqmhDb+aZtspBhQYnusBEnirxUkfzW7NzbwSI9V1bcwkSB2LKe4loNWZ66
         h4hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jxIUAfJ3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ta4m9mJkB66iuR4gWb8GKPtDSFgsSoifGPifWnvHOxE=;
        b=lpVrOJQaNvQyM+99dlqvrcSaeIwXstCAHfxBffOcfc4gkQU73rlGRLmdHhZCyvXjwD
         i2nwFPKEqIoaRWyZ0T/EfiNExJToS6lyPNohEmIWz3doA0cbd2Hy/cDYm/+cDqRiOW8n
         +lnq7hQNBM1uaOpWI2pNdbWDTgMk6UO0UdE4HbhCRr0CRi2XmfPF/CgmnpC3FOt/tltP
         EgYVdHV8N4WGmN/FVmFmInELN3GcNJkB72Pvw3vvscP5Za9rZ1dFsjfVwlWh4jH8IadV
         sRU22pQ5vEdPEeIovUE/J2DstisqGt7BERDx2bVpOBb+URu0+Th4gPfAY5I10d+GpmqN
         kQcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ta4m9mJkB66iuR4gWb8GKPtDSFgsSoifGPifWnvHOxE=;
        b=NjYi/1IlJqgtkuZZVGU4b1+HudBdTWYhR+ZxhIEAVLhl1Ac3x6iIOwokiTCQtb9qA9
         vR19LzqEpwH0ZtWNGML68qU6lso+yZqRUlYMMLd8iVnVlnamHV9g7hr6/GjgLt0np8B+
         b8ZkjV8m3m1Gv3mkjJcVrzbRILrth0//qKqVhV2JV6AQGY1kNWGRAHfFbd7tSno5Ks3y
         fjXJt8AyFXJrQLeJr6P89C2eb84FZYmr7MuPrRRc4AH7+hVZwcn9O7fZznTJWvV/wJIQ
         nmyhJ4ooe/MMFRrBAICAA5LBbtzW2ZtTsgnxA3PB/S6xIy3B+t7jyXO+ufYLgOIurDIF
         ZMYw==
X-Gm-Message-State: AOAM531nVchyIYu0O36w0C+ebt2YSEY4VK0Wu7m9mQQj73iDCXw3MVvD
	39sOmz+1oivwxngno/utPwA=
X-Google-Smtp-Source: ABdhPJxN/ZgmktK542z/bwMneC21wvUjx1NEGUcQIBCq+2rIDopxH0UBqOexYk7HQfsjWbA6sRiW4Q==
X-Received: by 2002:a1f:abcf:: with SMTP id u198mr1218293vke.19.1614766698627;
        Wed, 03 Mar 2021 02:18:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls196119vsm.3.gmail; Wed, 03 Mar
 2021 02:18:18 -0800 (PST)
X-Received: by 2002:a67:ed84:: with SMTP id d4mr1266242vsp.52.1614766698053;
        Wed, 03 Mar 2021 02:18:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614766698; cv=none;
        d=google.com; s=arc-20160816;
        b=APNMYygK/32J3u9L0vCJjFo+KLnJgOYKUxlfqWKBHggE0J7PKbgwCFwGwO6a53G7fy
         Ehvj8TnhokDY0iHCTNeBBKa/jFFkHWZqOf/LRhArxQV0SXZ54KZPcNhXizX0AxGriSYQ
         Yask2aCVyxzfJxFW6TZo6+ZxXrgY2U0b5Qzg9kJVULogPMV+MNxGEwhKjxnMTuIgyVPA
         TJ0f6sIaDFyOQxcg7CNQyzGjnbmzBFYooq85aWSsenMZLA1LDfwdcZUO2PIdzy6U/pg8
         6qkviJbXJpvaenBmeKg35Qw3bpmZ+ajuGaxqLhSCzpxvKMHWgrfEtiD37TmbT4Xln1tb
         F0FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tizoAoxj1MkSbHFp7V2+QcWvWzsNKthubw4LeYpfuqI=;
        b=o2AS/uA5VUFKXmmZXiyY4ZoNGIjPaktDsYqVsbC4y3M1HBtUrFGMWzaLyeqSgvzp26
         d7BoD/tGJdiIyw8uvPWGMOW+4kNrZ64NReVNtmE4TCcwzgBi/u+7A/z5wOe/XWKmIWhX
         cId6P8W2wybPTayJQb4i/v/Bh+rTbhKGAzOIbHTCjYGg59Zd1vOMXyF1YqQbBG0odBtQ
         ug+vrwPo2C6t1IKHqkayaLmeYtqHm1V3rPxthhlWDX765TQytwwJap8JT/oWJNqg5Sav
         +GA7rRSt/ZhN838JCyLkQn62u5+QOIrhuWzW4tORDqUhyJddUpCVpUiTLjPZApibYTbV
         p8JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jxIUAfJ3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id r5si1045483vka.3.2021.03.03.02.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:18:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id w65so1792450oie.7
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 02:18:18 -0800 (PST)
X-Received: by 2002:aca:d515:: with SMTP id m21mr6810808oig.172.1614766697628;
 Wed, 03 Mar 2021 02:18:17 -0800 (PST)
MIME-Version: 1.0
References: <20210303093845.2743309-1-elver@google.com> <YD9dld26cz0RWHg7@kroah.com>
In-Reply-To: <YD9dld26cz0RWHg7@kroah.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Mar 2021 11:18:06 +0100
Message-ID: <CANpmjNMxuj23ryjDCr+ShcNy_oZ=t3MrxFa=pVBXjODBopEAnw@mail.gmail.com>
Subject: Re: [PATCH] kcsan, debugfs: Move debugfs file creation out of early init
To: Greg KH <gregkh@linuxfoundation.org>
Cc: rafael@kernel.org, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jxIUAfJ3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 3 Mar 2021 at 10:57, Greg KH <gregkh@linuxfoundation.org> wrote:
>
> On Wed, Mar 03, 2021 at 10:38:45AM +0100, Marco Elver wrote:
> > Commit 56348560d495 ("debugfs: do not attempt to create a new file
> > before the filesystem is initalized") forbids creating new debugfs files
> > until debugfs is fully initialized. This breaks KCSAN's debugfs file
> > creation, which happened at the end of __init().
>
> How did it "break" it?  The files shouldn't have actually been created,
> right?

Right, with 56348560d495 the debugfs file isn't created anymore, which
is the problem. Before 56348560d495 the file exists (syzbot wants the
file to exist.)

> > There is no reason to create the debugfs file during early
> > initialization. Therefore, move it into a late_initcall() callback.
> >
> > Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> > Cc: "Rafael J. Wysocki" <rafael@kernel.org>
> > Cc: stable <stable@vger.kernel.org>
> > Fixes: 56348560d495 ("debugfs: do not attempt to create a new file before the filesystem is initalized")
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > I've marked this for 'stable', since 56348560d495 is also intended for
> > stable, and would subsequently break KCSAN in all stable kernels where
> > KCSAN is available (since 5.8).
>
> No objection from me, just odd that this actually fixes anything :)

56348560d495 causes the file to just not be created if we try to
create at the end of __init(). Having it created as late as
late_initcall() gets us the file back.

When you say "fixes anything", should the file be created even though
it's at the end of __init()? Perhaps I misunderstood what 56348560d495
changes, but I verified it to be the problem by reverting (upon which
the file exists as expected).

> Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

Thanks! Would it be possible to get this into 5.12?

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMxuj23ryjDCr%2BShcNy_oZ%3Dt3MrxFa%3DpVBXjODBopEAnw%40mail.gmail.com.
