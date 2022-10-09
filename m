Return-Path: <kasan-dev+bncBCLI747UVAFRBRXRRCNAMGQE7ZZYGDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AFB595F8900
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 04:58:15 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id y4-20020a2e9784000000b0026e1498eea4sf2438329lji.13
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 19:58:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665284295; cv=pass;
        d=google.com; s=arc-20160816;
        b=KOaQRnThNgHk4xHc2H2NIxznjTk1YuFhhrd9rExlgCsts/Z+aFT2hwvjFJBGvX4d3y
         UJTzk59fKcRT26rnzEr2MtzKDYURj6gTdBX1DspzwqBLss88AnZfmCyqga+1yzEh8qzU
         z8rrxsR+Z7OtFWrF2yC8fd+fxxJVJqcxy70dHremPGuKnjDxxCIsOwHSg5LCr7ofCsgp
         dtAfqubX0uX/FGG1g7C3ipfP505VRfZz66thuuy+8Psv/lwt2QloFPyhH9abJUvK4eeG
         aLhAI9j4DaJ/VqvWby6z0P/eywTbNda5w4YzPbTNqC3s+DAX4r/X6gzeePVftXNHb2Sk
         zFXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9nAcn5N5lzPIYxGjPISh9UGZTr3YzckNx9VRUnwRhTU=;
        b=zEkPB9sz/afMaNnzY3Hm76ExoVQiBdACwOvQz5Z7fzHWBlgDOCVGpMjz9u+UkA5rnk
         /Bkcu2u3c7aYoVzgD9Y5/wD0Oy+z/qroELQsXAmrTV33BSq2HlfCw4ZznJg9fidakeG+
         fOb4jqEMptGVgUiUXAzvL1SxeLbV5kesHmFQcm6/zQEYGaaFHPYhjMfF8I7lzVdle/bD
         j01fcGfF+jisYgmD8Z0g4/u3L19EBlBKjMd/8HPADUd0SjJJ/SDWTl1Xpxm7VFYYx3xr
         G0szk0nGyfGjaxGgO2y/gq8P4Zt9/zWen0RQ0UCrhLcdYpM8nzoYSTmon/maF+cIaVu7
         f//Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=BCnShyLw;
       spf=pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9nAcn5N5lzPIYxGjPISh9UGZTr3YzckNx9VRUnwRhTU=;
        b=broTiXEML2Bu+q8EyOfSYRCA7Oy8y41vqDQh+N18U6/eA2CouXQSliw/E5kH/VY8uA
         YJ/fM1bAs8X3m2Rzk/A8pniGNwx7TuInSnnJ6e24yYSHGqBSrWAPv/lWX8QAHjJWhWf2
         fAFJcSUo8ZF15udvGIS8B7M72QApSGhiA/j+d+z2vAD6QlYOc6SzFzuLqs7PZotX74/3
         squ5VY/IGVWhajjn8bQQmGM15dCcPraWyYpJPVjhuxxRqoN2eQlNnBoOfzCVnaXfQx3l
         RHxPxVo5vFW+cfQEFBpirYX96+IiloGKTz+4KkAIwCtn8yrUM4gY5uRHXJpTt11v3wWk
         nbBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9nAcn5N5lzPIYxGjPISh9UGZTr3YzckNx9VRUnwRhTU=;
        b=AbJhZQXkNBOvVoe7MXyluYJUSBt5SxVgPvhJZtP1kx6Y5Wyx6nQWfdVb3HYcXvPHEK
         IPVDAvP2OcV/u2ZXze7kOJUj8J6I185LrmfgdX3GX0TinXaCEzTZWOsn3FyFMWVop6ys
         MH8OM9VPr7A0fdeH1b4PeO1gzcgREjZwizMhVQYLY8Wp3chIzSaBhz1j1UO4wXyyaPsi
         BhSyNT5UTu279hXYg7NcP/rcLZGms1julxj6CaATdoc6X43hfw+DVGR6eHmlfhhZeDga
         hsr+bDekXguo6Xk/6hA8JBblOW9KtwuKzSfb1PbYjikaYpYGq+e4iX6M/Bj096BEnYdv
         MQaA==
X-Gm-Message-State: ACrzQf1Js99YnYSHdWVsHwcM6g3c25OXdb02d9Tpr0Ug+7AVZMI+ylV7
	qEoo0pq4IhbG8CwZ06JgQuU=
X-Google-Smtp-Source: AMsMyM7iVZLL0x2REFsOwFI78Yo2Z1GSTyWkLi2a3ERtrwZ1oA/uFtmYpg25jXETZOvZ7p7XFn3feg==
X-Received: by 2002:a05:6512:22c3:b0:4a2:7da9:440c with SMTP id g3-20020a05651222c300b004a27da9440cmr4135590lfu.490.1665284294922;
        Sat, 08 Oct 2022 19:58:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9097:0:b0:26d:fb4f:eb20 with SMTP id l23-20020a2e9097000000b0026dfb4feb20ls1547299ljg.10.-pod-prod-gmail;
 Sat, 08 Oct 2022 19:58:13 -0700 (PDT)
X-Received: by 2002:a05:651c:1609:b0:26e:93e8:b6e with SMTP id f9-20020a05651c160900b0026e93e80b6emr1286544ljq.456.1665284293391;
        Sat, 08 Oct 2022 19:58:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665284293; cv=none;
        d=google.com; s=arc-20160816;
        b=MmPICHbRDDbAPt/Nonz8qh7x9L+qNVycl8C26XH+PYfeKW5jDWAhy6vGrXCMq0iHpG
         lrpYOUeFpuwckBaDnnAM+oTOhTy7BGX/ckp+XDHpyoS4attxWaRxhEy+uQsVVQiH2LZ/
         toQxJqyqJqJ2iz7UKWyt4hIAVS5QMFWyhKyGYU5lbEhsTvRmjBkEhAdDBJK3pcM+zwH3
         lqcLAn7DL0ze8Z+IS21ppxXXmDO2TEm27DZsCVVVVds+yrsW9sCrs6OPEr8Gl9iN+SlI
         WA6MMuyR6hbrAKA8x3FQxSBgTRZRYzhZFyL7lDXzkpeVy5vqKz7CaCLBZxi1lBbGjqw+
         +qcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PTr9nvXhCIMgKxMMIHmKX/lEwOczzX2VojqQXIdEQXM=;
        b=dxqYjqgomxMeubaYnlQD84gjh7jyxBgewZNxH5Xlbtb8EiwFBNHr0WDPyYpFC91rkU
         sDVPa5F5Ps2QU5Wmcn8e2UeQJ61FkiX0fqAzcx2bR1j3W0LKB6OshL964x5hmOKlTrmy
         6rNE46iJwV/HMv97+cJJNWbBqYLRCTYGPce7lAESxPJQQlyg1HcLgOftoDp7Kl8YGeu+
         /GtnM9Rz6/DT+HXuMQYuE9EmQsEu4pxAQVqh6bvsdcswluZ49LusuedLHEH4hCBo9VvT
         h1cuR5nWdX9/0nJrRP6O+upJ70Sg5zivKwSyIYf9mOBfaBCX3zYItjRiDbAUJeArACcO
         6pqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=BCnShyLw;
       spf=pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id e10-20020a05651236ca00b0048b224551b6si262680lfs.12.2022.10.08.19.58.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 19:58:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 80CD3B80B91;
	Sun,  9 Oct 2022 02:58:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E6F02C433D6;
	Sun,  9 Oct 2022 02:58:04 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id b38280f4 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sun, 9 Oct 2022 02:58:02 +0000 (UTC)
Date: Sat, 8 Oct 2022 20:57:54 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Laight <David.Laight@ACULAB.COM>
Cc: Kees Cook <keescook@chromium.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>, Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>,
	"dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-block@vger.kernel.org" <linux-block@vger.kernel.org>,
	"linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>,
	"linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>,
	"linux-fsdevel@vger.kernel.org" <linux-fsdevel@vger.kernel.org>,
	"linux-media@vger.kernel.org" <linux-media@vger.kernel.org>,
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-mmc@vger.kernel.org" <linux-mmc@vger.kernel.org>,
	"linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>,
	"linux-nvme@lists.infradead.org" <linux-nvme@lists.infradead.org>,
	"linux-parisc@vger.kernel.org" <linux-parisc@vger.kernel.org>,
	"linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>,
	"linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>,
	"linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
	"linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"loongarch@lists.linux.dev" <loongarch@lists.linux.dev>,
	"netdev@vger.kernel.org" <netdev@vger.kernel.org>,
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>,
	"x86@kernel.org" <x86@kernel.org>,
	Toke =?utf-8?Q?H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Message-ID: <Y0I4si9+cMracPAq@zx2c4.com>
References: <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
 <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
 <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
 <Y0Ayvov/KQmrIwTS@zx2c4.com>
 <202210071010.52C672FA9@keescook>
 <Y0BoQmVauPLC2uW5@zx2c4.com>
 <69080fb8cace486db4e28e2e90f1d550@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <69080fb8cace486db4e28e2e90f1d550@AcuMS.aculab.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=BCnShyLw;       spf=pass
 (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Sat, Oct 08, 2022 at 09:53:33PM +0000, David Laight wrote:
> From: Jason A. Donenfeld
> > Sent: 07 October 2022 18:56
> ...
> > > Given these kinds of less mechanical changes, it may make sense to split
> > > these from the "trivial" conversions in a treewide patch. The chance of
> > > needing a revert from the simple 1:1 conversions is much lower than the
> > > need to revert by-hand changes.
> > >
> > > The Cocci script I suggested in my v1 review gets 80% of the first
> > > patch, for example.
> > 
> > I'll split things up into a mechanical step and a non-mechanical step.
> > Good idea.
> 
> I'd also do something about the 'get_random_int() & 3' cases.
> (ie remainder by 2^n-1)
> These can be converted to 'get_random_u8() & 3' (etc).
> So they only need one random byte (not 4) and no multiply.
> 
> Possibly something based on (the quickly typed, and not C):
> #define get_random_below(val) [
> 	if (builtin_constant(val))
> 		BUILD_BUG_ON(!val || val > 0x100000000ull)
> 		if (!(val & (val - 1)) {
> 			if (val <= 0x100)
> 				return get_random_u8() & (val - 1);
> 			if (val <= 0x10000)
> 				return get_random_u16() & (val - 1);
> 			return get_random_u32() & (val - 1);
> 		}
> 	}
> 	BUILD_BUG_ON(sizeof (val) > 4);
> 	return ((u64)get_random_u32() * val) >> 32;

This is already how the prandom_u32_max() implementation works, as
suggested in the cover letter. The multiplication by constants in it
reduces to bit shifts and you already get all the manual masking
possible.

> get_random_below() is a much better name than prandom_u32_max().

Yes, but that name is reserved for when I succeed at making a function
that bounds with a uniform distribution. prandom_u32_max()'s
distribution is non-uniform since it doesn't do rejection sampling. Work
in progress is on https://git.zx2c4.com/linux-rng/commit/?h=jd/get_random_u32_below .
But out of common respect for this already huge thread with a massive
CC list, if you want to bikeshed my WIP stuff, please start a new thread
for that and not bog this one down. IOW, no need to reply here directly.
That'd annoy me.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0I4si9%2BcMracPAq%40zx2c4.com.
