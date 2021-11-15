Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6U4ZKGAMGQEFD7GPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 435FE4509E1
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 17:44:43 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id v10-20020a1cf70a000000b00318203a6bd1sf165541wmh.6
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 08:44:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636994683; cv=pass;
        d=google.com; s=arc-20160816;
        b=wQIJlwXWSkGqi50r/zgkcsvmOb3wkb1hURAU7dN0/hc41LCruD5BFwEHnGtBF9Leq/
         kMykm7+Jkp+/JXdDXz4k996E0Tf8hIvPLhd0ueEGGYmEeo/TwZ55ycWHYai00Vdrg5tF
         KGxOlYUerVksXHDmSW4BgxXp9UdBwINsH1s+yYen06afFzNx5kHLfdKSbf7WQlfJzxjn
         iRd1xnWnE7G8qJXg19CLUOS6tSg4ldM82eQZdPDfduALaTR1j8Dupf5NVv5KQvrkTebh
         SB15HovtQoUOhL8o6T4dtuD/FqqDsr5FoqvunqAGroF/G7IjTWazzP6nRWib02OFI76r
         uskw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zmwtMJGv35YasUZBC51Vpw+VDNEVDZlOFtj5/Wz5dAo=;
        b=FONIdPusSPN286cIYsWD/P2v1pSEShtyYSi+Wbno9y/f2ga6X7fhRNOhnj8N2n809d
         3KlkV3Y9HAgZtbDFhU9IvJLHungleF0UlcPgP53TX0s2YBF1w9Yd+82Xlu5xsUmxGA4q
         n1n5g7gz9Dw2Q26GoItPEUQh8zfFgcPW/LW6eMRT+TjPwtJ8HxVq/2aXg15yUADFu8Wa
         p2DxPSaTE20LPLHNLmxu9Ax4tUkhFwm9rRkRKrvUwF6VGraPlept4eNz35PxOXriSNlC
         A/BPcFq9XPUbQv3f8QvK1o39adG5byvnnPWTMzAm0aXkPB52h+Wi8TzcF4naUoGeGYiA
         bTkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g0iqrBMJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zmwtMJGv35YasUZBC51Vpw+VDNEVDZlOFtj5/Wz5dAo=;
        b=FnDSxzHu01giNubPEeg4/kZtmlhDipyGRCPJxU9XpdGCmCBD+fJrCuDQJWCm/hI8zY
         FcI664mAQpM5jxoNc0uKUdiEqZzv8MGrG1IwaCUcPQq2hRzT69QkyesyYbTowhHeadK3
         miqRKugh1hwbOXLQqUfR+cfFiFT2g5S1YlnMyHNp6Zc/Lbr1h2coDC0XsHr9HJirk2ob
         rakyXyHO/1ayUPVtlHc6v5fhOybNx9dshnkU/fWNWufBhan/l0tjeE1UQ11nim6pomw/
         JoJbAB6OMoSP89ronMIPqXScgaxeq43zfj57nq2vmeGF8BSMUmPrmCOm7lve4ehLglsk
         xXMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zmwtMJGv35YasUZBC51Vpw+VDNEVDZlOFtj5/Wz5dAo=;
        b=KMvZnAcS11Hr9ql6UQwgzRpa3p+O2GU2g/psBz0Se7rQA7qbzsyNM6lbt2YuPOj5E4
         mNh8I+t0bKibtCcVcQpr1C0+Re2abVWz3GHCsa/HVY3snT9BoNg8QXYyhGKwURN60P8W
         JVrF6iSvG+nXBmJterOOdr/9l72G1OEsklbySqJB/5rBmkAMFWjUR9k4B/QG9Kx27MjD
         PiiE1YVVBAmHRsRZEYkyY4zc3ChKGUYtnp7Jladw7FMMaM//9WClKSYdgV5CKdkjTBwx
         avAOwelCyORzmTgu4LUmSPdU6slzL2X+LCd7pjnA0DOW/1h8ARgv2OYVyOpktN+VWrDN
         GHcQ==
X-Gm-Message-State: AOAM530TxXrIJVpEP4OZIh6ZV/YknqiVhE7l/JqOATRSzf5K47TpT4JC
	TjEtrXRCb12izP3EiENXWfk=
X-Google-Smtp-Source: ABdhPJyOrTj+cjxF294f2F0kosypPg2Mmsizo44c9LvIKfdfjEq/7HaHwWF7YzKcR2P0ufpX5AWEJA==
X-Received: by 2002:a05:600c:3b8f:: with SMTP id n15mr61782444wms.180.1636994683075;
        Mon, 15 Nov 2021 08:44:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls11219041wrr.0.gmail; Mon, 15
 Nov 2021 08:44:42 -0800 (PST)
X-Received: by 2002:a5d:4704:: with SMTP id y4mr430228wrq.85.1636994682093;
        Mon, 15 Nov 2021 08:44:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636994682; cv=none;
        d=google.com; s=arc-20160816;
        b=XovxtTHM48DCa8O6iAl6kgdNYU5H4XSSOU2ElWYg15jrH1oQQNBLyqnfwODUOGlhjD
         veJYquD78t913YEcQVo9FCfaStYxj/RzpXu5+izJL1XOrM1FIpKwSrS00kbnSugs+94H
         mC5n4YWUvs2+2NIJYeCOSAE0YTDKhIAUVncK1KQKI4z35xvasC+M3AA9mLrcQ/dV11MY
         T0p3DA3lbFbBrmuiqusaf5ozsax7EX552yKI4uo+/ZG+sML9WaNoeU8ms3Ksmz8pwH8h
         tIskK6DgmUJ2O4QpX7DzrrxjQrC4Cm0Yl6WfT04BHELJSxVEIs0Q1cK3GnSXeLdfLnpr
         VpYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ebmLJNm972HwzSUFY9uX5jVcx5/iRccpx4YVQ/Ccmok=;
        b=ubBew8PLVOszujjLQ5ED95AtHNWSzZTdLjgnn/HgOxjkuZWeQOWSz3BRDRfhkrVJbq
         k4VRXAkEmKjaCzN3lHesY42S2D2gc3/o+6MAxUyCDbc4tomyhyEJYqIKd5TsmmdzkzA2
         M1UPYTq2yfGG94BD6KPRMpd43qTKZJN/pdzhzoRCVENSr22IuKAVX5A9+xxEKP+0HCJM
         dMoOoG5wU0EadJdiTULPFurrMN8jVrlGVQyye4yiLiTODxHntNzfXpzP718M03E5CPZZ
         CkZ4gFYOTViP0DYowCLbDXywWj0YTGjT0HkB61ejeZKjj73jVoLKypQV8Pu+e7KpwcfF
         ryaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g0iqrBMJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id o19si990649wme.2.2021.11.15.08.44.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 08:44:42 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id n29so31911686wra.11
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 08:44:42 -0800 (PST)
X-Received: by 2002:adf:e810:: with SMTP id o16mr394870wrm.359.1636994681553;
        Mon, 15 Nov 2021 08:44:41 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:6385:6bd0:4ede:d8c6])
        by smtp.gmail.com with ESMTPSA id 126sm19916816wmz.28.2021.11.15.08.44.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 08:44:40 -0800 (PST)
Date: Mon, 15 Nov 2021 17:44:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>,
	Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Nick Terrell <terrelln@fb.com>, Rob Clark <robdclark@gmail.com>,
	"James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
	Helge Deller <deller@gmx.de>, Anton Altaparmakov <anton@tuxera.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Sergio Paracuellos <sergio.paracuellos@gmail.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Joey Gouly <joey.gouly@arm.com>,
	Stan Skowronek <stan@corellium.com>,
	Hector Martin <marcan@marcan.st>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	=?iso-8859-1?Q?Andr=E9?= Almeida <andrealmeid@collabora.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	"open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>,
	Parisc List <linux-parisc@vger.kernel.org>,
	linux-arm-msm <linux-arm-msm@vger.kernel.org>,
	DRI Development <dri-devel@lists.freedesktop.org>,
	linux-ntfs-dev@lists.sourceforge.net,
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
	linux-pci <linux-pci@vger.kernel.org>,
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
Message-ID: <YZKOce4XhAU49+Yn@elver.google.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=g0iqrBMJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as
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

On Mon, Nov 15, 2021 at 05:12PM +0100, Geert Uytterhoeven wrote:
[...]
> >   + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter):  => 263:25, 277:17
> 
>     in lib/test_kasan.c
> 
> s390-all{mod,yes}config
> arm64-allmodconfig (gcc11)

Kees, wasn't that what [1] was meant to fix?
[1] https://lkml.kernel.org/r/20211006181544.1670992-1-keescook@chromium.org

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZKOce4XhAU49%2BYn%40elver.google.com.
