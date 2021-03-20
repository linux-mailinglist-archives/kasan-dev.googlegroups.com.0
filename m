Return-Path: <kasan-dev+bncBCY5VBNX2EDRBMVF2WBAMGQEQ7F5YEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 63B8A3429A8
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 02:41:08 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id h8sf12347912pgd.8
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 18:41:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616204467; cv=pass;
        d=google.com; s=arc-20160816;
        b=UbEu6qt9Jt+OVOskK65cBv8qefXmaI2z81r3nq/fNX9I0CheFE49FzS8CGYuN8wM5y
         WejI5cTxdmZmJ3pMqqP5DTNV5YB+UAh027ZhhWjCMxIFvYMYre8pqB9yjX32eMjQirh+
         bnhCSfU9Onw9dqdUz9WMsnGtKFRX+8Qa09uEdxYkLFFpFx4+UQg9i0txbozKZVkG6xFT
         /fSR4dP8RpJB7DCubZd5xBKR7UL4Vv/A+u7HN1tZH2afT8FsmLurHHA7D7odU/xp2Hkr
         CU/wa9A7rQ7kdFKcLg1R7Nrq84MwKdK213z/h6tGYCoyUyZ90IZg3jEx+80YO92F7WKO
         QADg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=LI1yVRPS/fPjmDoY1c2l7Aq2pZr00jjeScweDYlsbLA=;
        b=Owf4+hwQDWmc7HWivRuWqJovVxTJgVI4N/6BqHPqTEqxwOLA24isYrYf6FJFuLz/st
         vuO2hzqTdOSRouai/c6o31zU0h6jNZd+zv2gK1OCLvyvEv9JW3CrvFHIAht1kCYx85Dj
         s2X4Vr5hfD5H9+jMVtNvksya2tjQ9qOcLFVDH+1+EB9uAV1nYXZy3FfctE7j5FlPJhiR
         01G6BYUvjJnSL67yda45ey9CVUWZ+HYcRi3RXPOKezgwgIOG6KRncml9RvjGO64QaXzL
         vco+0My0glHNaFiwRatjnfi9LGI5mS4kXDBPmQHOO8elbUuNRZaOh/4fLi8lOBLLvwyj
         0T3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sOLb6Dan;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LI1yVRPS/fPjmDoY1c2l7Aq2pZr00jjeScweDYlsbLA=;
        b=TQW39d5mMqwZSDsYh/NiqdKEZX882hxtSXfSciDtSketuHUu/Qb0wxuxngfdE/hbos
         9Y1YDGqF7iUFWGVfyz0voZ1nsOcV5mOICZEVgmuiIpiubs42mj4qRsl2Wi33OlFxsetC
         Ces/Z3O3YciclF0Z7HtDS1U+okTKz8koV540vBbgE/IqYmT0WwgMTQMCQRJpbhzGePuq
         nlo6YO2sGetOwe1UYIMbDswW7MjmCA2ewb5KD+VvbJMjdFupc4aoGjeBSnOmLRUcZxou
         2hB17ZncLCWQ4KVq8d8TK3JiiL0Xkktn76cUA4/D7EnZKU4gArFZvJLUrcY8kJuYp7ec
         bNng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LI1yVRPS/fPjmDoY1c2l7Aq2pZr00jjeScweDYlsbLA=;
        b=u/qmosPTITv6vhSeEdZW4BTM0eBcSj6Src39WNwcTIMxymBdBa51L1R+ZfnXZ/jLV3
         dflbt97CaXeJq6hPngaP2e2jgARz7wXodewd0lJaZdiVT6GdB1boKMMGu4jhEYghdKRB
         xgWZUXXK2XG88MLRCjSiNukaZlFR2FZjtxbQl7ICxhu13BYsLK89n9K5AecjwYNn017S
         srEhUDyskHilDp4J7eTLnNAbKNmwWHbx703NVJCVCbdCtuQEeb7FXPscqnGr8kpie7CI
         UKc4/fwqV3oEzAkv8MymylnsTIuIIQzrQWb7d+rSRKyUb3dlqMW0nlLQG+A4IzvgZWL6
         X+tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LI1yVRPS/fPjmDoY1c2l7Aq2pZr00jjeScweDYlsbLA=;
        b=Uy1JtePfs9AGNDVe3DorUUZbZ2mylFeVHGF97QqflcDn4ZX/n95zExS/93qdZyvnsz
         VBOpHDWNJvJvKRjNSOdu0YcIpEw/yUrAPzk/UWKax57PoVAqwIXphdW4pIxJcTdkwTPA
         ZnWumtyPC6b3RS7lzyRXsCxltwLnNUQzgsD5HaVgmggIlW5Y92YXfhwHVwjRFmMTCT2X
         nI0oAqfTVUvFLd8qGLirNGjhWIngRXan7gDAqNyr3zLDsJBeKNtb4iAa/IJokzrxyo8P
         f0/dj7atyRBFwXp6nAkqUrYWIkc4le2UsiOhczxBqA0oYhsQ96j1HeZskrb2+y33H0D4
         fniA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320AfnsR6knr5W4d2MLSqhRQ+5Zk+gjQjYlvH1YvZ4xNaiLtQfu
	Wkv2kcnsIq+a9K/wkHDrkB0=
X-Google-Smtp-Source: ABdhPJzO9qd3MRqayB3q6sxgMP9HpEF2itw8PJPmGJB5RKdUPMGLam7dlhOZ3iJ/tkJgvOcD0hLdiw==
X-Received: by 2002:a62:2b85:0:b029:1ee:e2a2:cbee with SMTP id r127-20020a622b850000b02901eee2a2cbeemr11495997pfr.78.1616204467068;
        Fri, 19 Mar 2021 18:41:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c40a:: with SMTP id k10ls3654682plk.2.gmail; Fri, 19
 Mar 2021 18:41:06 -0700 (PDT)
X-Received: by 2002:a17:90a:e64a:: with SMTP id ep10mr1324659pjb.105.1616204466535;
        Fri, 19 Mar 2021 18:41:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616204466; cv=none;
        d=google.com; s=arc-20160816;
        b=0rvE9bTg80mDG656FFl9yTvHHdlzcb7oxvflTpq+3Jw6ljyxUECqTN/UyQpy2wsas/
         NSa63oP2C2YRTMOzGqgxuIm4bYXqmw6i6Pm+R99abmUrmT3+wp/V6qDe53dCvxmv1DO0
         rDF1hbq1J3rTYDGWoi1FUsGd2vfrfIFoMjVMaviDnduirwmyau//HZX0ZEXHld2X+c+3
         ukwME6Wr22NIiL8zYf9n4FAZ5IA/n3hNaFCiujAOJw/X0GlNSY1svMW1NslBPtdtQZwx
         5AubkQ7Odzf71vlX2Olon3VTsAyS1oiKuv8LFzhK7O9LxCvGTwyG0tOa2xflvNLKQXKG
         cXhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oWdIOPAkZfr1BoujvrjjbGLV84XJk3QFa5vSlgO7ACI=;
        b=tzfrfzvypZ1nyhKzUaMzCMM76ELQ1kKxHmQbnm9oUhkHPsaxusg+smj94NyhacbBPK
         iIrdGh2QGKY8dcNzN5U8aBtgRiVXL8Jk/PB7dDY0Ko5PxslsiH4SYdXzJ+k96LJ4dSHC
         Z83p9B3AVOvb1VcsOFl9Cw/zsZwlRxkzCcVgXOmBiilci9kXr/7tKZXjxttZilwOxjHa
         wFhai535mAbreIfo/cWzBu46zlZKnL2E5sYSkDnTCTGNXrzTwizTWgQK9kTAIfFRupa1
         /3GEXEB27oSeMasmdqhbG1sKCCE6vpgnVd9ZtHWb3bFy3Y7UfXEt9tx0ywt6H1v0vgxC
         RwNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sOLb6Dan;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id y11si549344pju.3.2021.03.19.18.41.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 18:41:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id v3so4863804pgq.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 18:41:06 -0700 (PDT)
X-Received: by 2002:a65:44c5:: with SMTP id g5mr14108950pgs.295.1616204466016;
        Fri, 19 Mar 2021 18:41:06 -0700 (PDT)
Received: from localhost ([103.250.185.142])
        by smtp.gmail.com with ESMTPSA id y29sm6830981pfp.206.2021.03.19.18.41.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 18:41:04 -0700 (PDT)
Date: Sat, 20 Mar 2021 12:40:57 +1100
From: Balbir Singh <bsingharora@gmail.com>
To: Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 0/6] KASAN for powerpc64 radix
Message-ID: <20210320014057.GA77072@balbir-desktop>
References: <20210319144058.772525-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=sOLb6Dan;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::529
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Mar 20, 2021 at 01:40:52AM +1100, Daniel Axtens wrote:
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU.
> 
> v11 applies to next-20210317. I had hoped to have it apply to
> powerpc/next but once again there are changes in the kasan core that
> clash. Also, thanks to mpe for fixing a build break with KASAN off.
> 
> I'm not sure how best to progress this towards actually being merged
> when it has impacts across subsystems. I'd appreciate any input. Maybe
> the first four patches could go in via the kasan tree, that should
> make things easier for powerpc in a future cycle?
> 
> v10 rebases on top of next-20210125, fixing things up to work on top
> of the latest changes, and fixing some review comments from
> Christophe. I have tested host and guest with 64k pages for this spin.
> 
> There is now only 1 failing KUnit test: kasan_global_oob - gcc puts
> the ASAN init code in a section called '.init_array'. Powerpc64 module
> loading code goes through and _renames_ any section beginning with
> '.init' to begin with '_init' in order to avoid some complexities
> around our 24-bit indirect jumps. This means it renames '.init_array'
> to '_init_array', and the generic module loading code then fails to
> recognise the section as a constructor and thus doesn't run it. This
> hack dates back to 2003 and so I'm not going to try to unpick it in
> this series. (I suspect this may have previously worked if the code
> ended up in .ctors rather than .init_array but I don't keep my old
> binaries around so I have no real way of checking.)
> 
> (The previously failing stack tests are now skipped due to more
> accurate configuration settings.)
> 
> Details from v9: This is a significant reworking of the previous
> versions. Instead of the previous approach which supported inline
> instrumentation, this series provides only outline instrumentation.
> 
> To get around the problem of accessing the shadow region inside code we run
> with translations off (in 'real mode'), we we restrict checking to when
> translations are enabled. This is done via a new hook in the kasan core and
> by excluding larger quantites of arch code from instrumentation. The upside
> is that we no longer require that you be able to specify the amount of
> physically contiguous memory on the system at compile time. Hopefully this
> is a better trade-off. More details in patch 6.
> 
> kexec works. Both 64k and 4k pages work. Running as a KVM host works, but
> nothing in arch/powerpc/kvm is instrumented. It's also potentially a bit
> fragile - if any real mode code paths call out to instrumented code, things
> will go boom.
>

The last time I checked, the changes for real mode, made the code hard to
review/maintain. I am happy to see that we've decided to leave that off
the table for now, reviewing the series

Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210320014057.GA77072%40balbir-desktop.
