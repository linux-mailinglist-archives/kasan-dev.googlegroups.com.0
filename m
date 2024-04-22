Return-Path: <kasan-dev+bncBCF5XGNWYQBRBFXZTKYQMGQEK7QUEPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 291EE8AD4F6
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 21:38:00 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-de54ccab44asf55918276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 12:38:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713814679; cv=pass;
        d=google.com; s=arc-20160816;
        b=kcBXOislP6NqlDP1+OQmc9yvGx3Y+oBHDEP7LQKbtvQHvSsVBPG3lJE6tqvpKAK2LQ
         k0WfVILqmUt4EIy0YuWqpENYeyKLISIdA0IcqGCWcFhctpu7WmL3oM59q6QCJ/ai6VBe
         /KN9DztGdVllI7a5OVtR7opRgg29JDU8zPToJzZLQnSXRrr+ECBIm+aJ72Wa6kycT/47
         MUh1lgErA4dFxmYkkY01iM6ufMHs4NiOzejq5g1cRKDGIiPw7vtA9RyAc7BZS9Hvu2rZ
         +wC7kkajvlYtuKcbrjIbJMyEV4pdKbWA9/gB8IWkfvln0v34gBMl8n/f5eho87ZKKcRW
         aJfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AOW5BPrjM3QK1ZP/GHmrP/rqDwhnCOyklmdN8Fqx+wc=;
        fh=lpD7+noljgkgZJX4dKM7uqvsaqyC8pG8qGby0YdLC7g=;
        b=xj4auKgTIP6Ypiinmy+L2v7yy8/VXi7WiJMN6BTHQEtru/252tro/GF4qdLXYAp5YF
         iqeUiFcMjqelTqXfDAvafHtMLPW4DEV8McmloA4dn6DZVXaGJ/WqSlYVQmnwxpGLLfUB
         3eSZgOIojcR0dvCCjy28TgJ0hRGPGc/8A7tAn2KgKX9C4kAbtFk8FiBPaHyoSGAXmgLh
         r90WoFSh6phq7wm/nSJc+3CQ7A7tTKJjjpvgl1PwUcYi3LvHftQCniq4KFZUTz4aWYd9
         U9U8jMZOB/rAoVDhT7FY7hOQEdoOTgLsUVNfOxTtsMyzrGGcoH+6L3p/DHjKhUJB2run
         6t0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=J4CAvmxD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713814679; x=1714419479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AOW5BPrjM3QK1ZP/GHmrP/rqDwhnCOyklmdN8Fqx+wc=;
        b=tS5r24wsqqXaUfF5Uoh6sGVrZwuLCubZ2EOq5nToFM8pqPl6gt3fF2M24D45UxpiZY
         /poLBsQ+owrjRQBYmH/AIl9Gk8xECB2asH5FZ7eFQ3oQG/gjcVDmJg8gM11vK2RI8ebX
         O7s/H/O5zkcHRi7Wl3KO85A6TPOdIn02c7WIjKGwXydFSSzpS1zLhqZw0lCxpI0hp3Bq
         SdyYjTWKaKdeZM4StTViqbjE52dXlZYPk0aj78VkwY1xE5EzYoA18pF3PDIpg1KPQMHI
         pd6nvhdGnLqR2XcQoonyrbRK1XfeJg7bLVlkMpzfViLD1b5lA0Jq1km9qkvZ/VRdRC+k
         WMtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713814679; x=1714419479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AOW5BPrjM3QK1ZP/GHmrP/rqDwhnCOyklmdN8Fqx+wc=;
        b=sMsnxIMw6p+WcdQprXDqfHg3iwiC4y040goexZnc1rmbZtvqHwg5+Fs74GdF1ydvbo
         83CjXaJbWCKL2OJ4YAE2vxLqapttb63++ntxDtRC/tOZ6if4d5eRzIXHlZmh1omYfr9B
         FLIjI3SzRj9SeU4EqNNfGa0PhjPALNHHCNG2OPSTgI0C47CBKQr9E64IpV22IEWtYFy6
         qzN8d4cV6pLuyrY8NJ9Pqie1p9D0mN4kr7FKVYwgHkjYQMQEXjOkPhuVkpBdHn4vK7fY
         EtmRnQLqEX3f9UmIXBQQC3bDX6aIlwbIlpy9DT97rgc392qMRedCR7IKFVa9OOuaGK0G
         0bKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8SG1k7Eqbc739ALMmyQulKqf5FkgWGFHyIQ/5exhqpKf0V5WOMHpTn1n0lKg84cZoWbflnxQ8EyuvbUeTFM0db9ksThJVmw==
X-Gm-Message-State: AOJu0Yw8jnwMUy0SEyMrlt2jQ8rsKdGXrAPE+JxDEN6RpYK7TnhsLKS2
	VmdIjzYGEBM8D+FLkiss6RHp19E7i0LwBPpTF23a/EhFDUcTe4CT
X-Google-Smtp-Source: AGHT+IE2BAWXjzkg1Hiz02Kmyo9IFjUFamaLJFIjr7uoGaQ6hz3CWSAvf2fHT3VFfMofOPG/5KcUuA==
X-Received: by 2002:a25:6604:0:b0:dc7:4671:8ae8 with SMTP id a4-20020a256604000000b00dc746718ae8mr8641574ybc.65.1713814678817;
        Mon, 22 Apr 2024 12:37:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d054:0:b0:dcc:717f:41b7 with SMTP id 3f1490d57ef6-de47ffd6b1bls3424201276.0.-pod-prod-07-us;
 Mon, 22 Apr 2024 12:37:58 -0700 (PDT)
X-Received: by 2002:a05:690c:c1e:b0:61a:b30d:9fdb with SMTP id cl30-20020a05690c0c1e00b0061ab30d9fdbmr12800847ywb.6.1713814677974;
        Mon, 22 Apr 2024 12:37:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713814677; cv=none;
        d=google.com; s=arc-20160816;
        b=bHMabOfII/SkibUhBw7iX/7IKwZ/vdIk8aDH6QsXW5WfL0UBLa71KSeJPPx55cRHbk
         Q1PHJceONN+4OHLmKyGk/0de4bhm5J35+kUU9wlFdAbKi0CjjrlXRPwLzRSczaXKu7v3
         j63z2IXBXe0yWNU6k/7HywdDsLGeiStGJPWeqylivAzOscDdXUWgeAuvYMquGyd910xD
         dRSUsKeKe7qh7t2ahC3LRdK2+vwlxeNscXvBmmOama69pzmHY0JwYt7x58EpVPTxzVR1
         Sy7ImiF7m4Dr1JA3inF0SSsZxbQFCAinzWR/BhOBp/QNr/eEQbMKU5B+pG7DgwIc06K0
         Lk1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=as0cYQmfAJzlRnvnIzXSIZotxCgJMX7g0i3uHh78aBI=;
        fh=7vXUBfeIBhZajighND0JabQYQZtyfxRFM7iIgOFeMTQ=;
        b=G0eW0RDnZTzi+KTZYWg73NUJlHTx+0NlLdIGOkVa6hbOe4VniTOWb6lzCkfOsskGqh
         PuQOl2yvbrPoTFAMN1F1Ai2h6CFPDEjQJ5zUIijKTYUgh75zhefSt1ezXTUahh0+hrbQ
         2kglD9OYOPb5ZCb0RSYedLSULud8NMJDzwZjGnXluDMCU2Urjxa2GJCwKZwvQRtXN3wp
         r5GFU71QKPASfjqzLPb1Y0hvooBDezXoHOZBMz/75VtxQ0xpPhEKu6kihlyopAY4KmSb
         8HUEwTqJ4iOPCUPWC/onH9LIltuvUy2vTRJqPazM+3lTdzY5/qrpWi4H0PrF0+ZZ+Hco
         HQhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=J4CAvmxD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id i15-20020a0ddf0f000000b006185e0c6aadsi952889ywe.1.2024.04.22.12.37.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Apr 2024 12:37:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1e83a2a4f2cso25937115ad.1
        for <kasan-dev@googlegroups.com>; Mon, 22 Apr 2024 12:37:57 -0700 (PDT)
X-Received: by 2002:a17:902:b714:b0:1e2:8832:1d2c with SMTP id d20-20020a170902b71400b001e288321d2cmr9407232pls.27.1713814677095;
        Mon, 22 Apr 2024 12:37:57 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id q9-20020a170902a3c900b001e3dff1e4d1sm3294737plb.268.2024.04.22.12.37.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Apr 2024 12:37:56 -0700 (PDT)
Date: Mon, 22 Apr 2024 12:37:55 -0700
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Subject: Re: Weird crashes in kernel UBSAN handlers under Clang on i386
Message-ID: <202404221236.273AA69C0@keescook>
References: <202404191335.AA77AF68@keescook>
 <CACT4Y+Z2T+A2xwZ=MOVnoUewAxnTcQ3B4AcCKpsUyp2TFSX8Ng@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z2T+A2xwZ=MOVnoUewAxnTcQ3B4AcCKpsUyp2TFSX8Ng@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=J4CAvmxD;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Apr 22, 2024 at 08:06:00AM +0200, Dmitry Vyukov wrote:
> On Fri, 19 Apr 2024 at 22:38, Kees Cook <keescook@chromium.org> wrote:
> >
> > Hi,
> >
> > I've found that Clang building i386 kernels seems to corrupt the handler
> > data pointer. I'm not sure what's going on, as I'd expect syzbot to have
> > seen this too (but I can't find any cases of it). I've documented in
> > here:
> >
> > https://github.com/KSPP/linux/issues/350
> >
> > It seems to be present since at least Clang 17. Has anyone seen anything
> > like this before?
> 
> Hi Kees,
> 
> We don't have any i386 instances on syzbot. We have an instance for
> arm32, which still has some value for the world. Does anybody still
> use i386 for anything real?

Ah! That's explains the "32"-suffixed VMs I saw in the dashboard. I'm
not sure anyone is using i386 for "real workloads", but it is still
being tested for things like GPU driver development (which is how this
was found).

I'll keep digging.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404221236.273AA69C0%40keescook.
