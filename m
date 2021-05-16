Return-Path: <kasan-dev+bncBD7LZ45K3ECBBXEYQOCQMGQE4GXMC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AD95381D47
	for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 09:40:13 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id x10-20020adfc18a0000b029010d83c83f2asf2062909wre.8
        for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 00:40:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621150813; cv=pass;
        d=google.com; s=arc-20160816;
        b=vmrvT6EivH2OjcpzDgKfMyP4YlCQbs/Op6LZVlPOlBtOC8Y5KX2D6s72REtBW6Gf03
         FVEepiWFVLz49r1MyfUUJjekL0zmaF9t25REcZTlf2mInaWmA+JpfTRnQ197/biDHXy0
         fVajR/91UQLkqMhaBeW72/sQUqWCIvANzlWmt5OAsZZ8INhIW0CIPFPlRlvaaYF+Kqga
         7mEVj2D5Nn+t0FzHEPwG3oloZQziQXIZ2TyiqP9OBQXRtRQlMWTspdjsqYDvWsYfYpWh
         4JwjbowKN7oWTLxI/mnx6ETc+Rp5m6P8102sVG3VnunPpYycgderHaGtmrLfMuK7VZQO
         7Uag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=69lGhU7Jd8GloGAIhTawpgtac8ZydQdim4bomZr70/c=;
        b=BaIzB8Nx0YVVSFbhJtu7e5feUvqH+DnfLeTkeDd585CRUVGHNLRwytPjP6M0YsdfNl
         RVA8gVRdpjyJAb6A4kA0z5sJaso97OucL+baUKVh51A61H+tpbKda9gKmWgtc6Vj31Ve
         dcUD+z40Zo/l2T3/b6ZsDeJ0/xjjecja8lPcYcANEtOL6mEWNm1HJAMSNdWQgg4vuxgd
         wEiTx035pQzMaNor6pm9e3ib0pFWkGmEKbjDloL4mWLYNuW1/FDrbcp8CnLp2kwVeulF
         x21VL6FcV/TFGQGhu8Xe+uck/i1EE6WEEcQcAFHY/XUxMlfpqIRJdfy1Zy0Z/3zhaCV5
         DvjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=o+vUNgad;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=69lGhU7Jd8GloGAIhTawpgtac8ZydQdim4bomZr70/c=;
        b=L3ph1HpbWagw2wbeN7h7bzeyD0H8HtbvtcIuJqpROP/OltYRYOwHcwS/XLktEPzCnU
         HnFchpTjFgIScNj6Fdu4CeK+DsFOtM5wt5/HVgSz3pUy1nEO57zSKcQ24cQsVDaXEXXA
         W0AeIAZyGLz8e5ysixlw5O4f2nxESmOM84CpufX5ctdahyAudKMAxWrcpAEfp+st9ezN
         FECdJgo/Fzm1C/WU7dYyFFBRcmoVsijUE6IQFy6vz+3XmVql6vQQVCPIdmbPPh0ivTc5
         SzDZnhdg9su2Gqu9g56Rp+QTp2UgVFi8W3/4Uevuijr9+Yd7651ddhn/3OzyEno0skkx
         WbIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=69lGhU7Jd8GloGAIhTawpgtac8ZydQdim4bomZr70/c=;
        b=Q0aClTzus6hBFtN0bm0yAW3OQZHqxsq4/loXYUYIF1R3QILsfZ/exeMPhBU3avW71c
         uLqJ144M/Y96Fz4IITw5p3nSljJjaqa8oY82yNCNKxrbtan5eKdo5rwdN6rYRj5LOx7+
         WJ9V/lFRkeAy2QVoPHyv/azRAP1IPip6UWb/11WDBzympU7HTKuVJjy7ayXF+r1pWL+C
         mOi23LDi9m8+gUFVMC77gBKUOXV9O+BqLKYQDhHldKyx0tsVOqC7/EAFDKBH5wZggPwq
         iNaOzgn/iMzX0yMc4gmPBZi898vq0Kd07Xed0LKtY19u7eEWgG/J1a3XfIgzv3Bg3lmp
         WDyg==
X-Gm-Message-State: AOAM532VNcU1z9wmts8MeUTQw86lzUvRgUPShwvvjrjTE3WWJoR8HIC2
	GaS+rqSREW/GHntozFh5W+0=
X-Google-Smtp-Source: ABdhPJzzTehAQkFZYC+NHV5vUA2pnmoMs86SBtCK3aNPh3ixuV2J51nN1daD0MRMGzqCRS00THAo7Q==
X-Received: by 2002:a05:600c:154a:: with SMTP id f10mr58906348wmg.31.1621150812932;
        Sun, 16 May 2021 00:40:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f844:: with SMTP id d4ls4440752wrq.3.gmail; Sun, 16 May
 2021 00:40:11 -0700 (PDT)
X-Received: by 2002:a5d:43cc:: with SMTP id v12mr12259790wrr.215.1621150811907;
        Sun, 16 May 2021 00:40:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621150811; cv=none;
        d=google.com; s=arc-20160816;
        b=TViN86GtpHCJWB3nfm5E9jxvtJqUKe2lez5SdyH6/n1QKwlThWegLgIOWcIZQD3aG+
         r40NFv79D/OpVSAk5G74/RYXF8L7VfWH9pfIaI63eM9NGQqXfsxAN2v2RYK7ybyJCDo8
         aSUUI7VXZqC5/zjuMDzgdB8oMNtq7kS2q0c4/NDWUOhF//rPidIXIPaApnkwzYQlnYNA
         IdhvXIdXYf+81Q9vcvaCz5286EVejLErpuW8Np1B9fraxx4LpPiFKlyE4CNQg6/sl4y6
         ED3jSQOf+thOmlVuAWhlmPfkPMVO2SAxLe+BfOEq+A8MA1B4xJAgym7LWY41txHYUsjI
         i2XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=atWgUCMhsGNXsz/gNWslNxnGXhNwsHL+hDk1DcVED5I=;
        b=SZ0G4aUvCvdIntqngz1xeyFQIN+St+VN9087+HIXP2SKT73xSIpOKwKBBzC1fjUJFo
         5jFM5jyJ8rpAYchiDzRO/ee12qNrCgBai8gjFJyekiZGFeO6E35M/1Fs9PlowBY2bWwn
         EnqSxZmDEZoq5WWGMpR4/WCEuaCK5Psq4CrU52PNghWdRSHQX0OlPcZ7b7OEEaOFMdCR
         EU0iPLdzPfHsF2hmU0k6AMg8nYgXmp846ue0V/Czp7RMI21suidFKCy9enpJnFwSa32q
         vVL1NOSdt02uXTKg7lj+dTbY7Y3wWHXmPCbICQe5hGEJPGkYrA9yBV+0eRaO0aINZjnc
         Im+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=o+vUNgad;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id j13si99961wro.5.2021.05.16.00.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 May 2021 00:40:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id s6so3145607edu.10
        for <kasan-dev@googlegroups.com>; Sun, 16 May 2021 00:40:11 -0700 (PDT)
X-Received: by 2002:a50:fd13:: with SMTP id i19mr22824583eds.386.1621150811730;
        Sun, 16 May 2021 00:40:11 -0700 (PDT)
Received: from gmail.com (563BBFD3.dsl.pool.telekom.hu. [86.59.191.211])
        by smtp.gmail.com with ESMTPSA id qo19sm1799357ejb.7.2021.05.16.00.40.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 16 May 2021 00:40:11 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Sun, 16 May 2021 09:40:09 +0200
From: Ingo Molnar <mingo@kernel.org>
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Marco Elver <elver@google.com>
Subject: Re: [GIT PULL] siginfo: ABI fixes for v5.13-rc2
Message-ID: <YKDMWXj2YDkDy1DG@gmail.com>
References: <m15z031z0a.fsf@fess.ebiederm.org>
 <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
 <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org>
 <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <m1a6oxewym.fsf_-_@fess.ebiederm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <m1a6oxewym.fsf_-_@fess.ebiederm.org>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=o+vUNgad;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Eric W. Biederman <ebiederm@xmission.com> wrote:

> Looking deeper it was discovered that si_trapno is used for only
> a few select signals on alpha and sparc, and that none of the
> other _sigfault fields past si_addr are used at all.  Which means
> technically no regression on alpha and sparc.

If there's no functional regression on any platform, could much of this 
wait until v5.14, or do we want some of these cleanups right now?

The fixes seem to be for long-existing bugs, not fresh regressions, AFAICS. 
The asserts & cleanups are useful, but not regression fixes.

I.e. this is a bit scary:

>  32 files changed, 377 insertions(+), 163 deletions(-)

at -rc2 time.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YKDMWXj2YDkDy1DG%40gmail.com.
