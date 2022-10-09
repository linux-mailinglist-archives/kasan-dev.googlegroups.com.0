Return-Path: <kasan-dev+bncBCLI747UVAFRBH5QRONAMGQECJF4DYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E14D55F8BAE
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 16:18:08 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id az35-20020a05600c602300b003c5273b79fdsf1858750wmb.3
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Oct 2022 07:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665325088; cv=pass;
        d=google.com; s=arc-20160816;
        b=AVUAxP/FJS5CQlectiWSxn7wljF0+kj/rR6cNnaEKx2D3ySpIgHfKPeSDgyNYZ68BH
         X9hcqRrzUjyEngIKTqnk3yCZbjcPG1SgOJ547zUx9QIzQPzhZzx3/y8Vsm/eWuyC3mKj
         +IacDpBVDlaoIHSzBmQzjwUBUM5SsqaNgP3sjUAOX2F5PrKhb8pxZv8zVNqzRK54qqeO
         ZHYaCLsITDeQwVAXbk7xe+F7bmp8RcthUkca8pwS0+2pk09P0WCESTYPl0tXQxRc/zcs
         KimKZPbNEkXYzbuBjb7wqb9CO6IBn4N4IkiPv9+3IpbQbQSvBuKP8GOPoSqCGsl+42F+
         jnZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=p7UAYMmBt3n3GpgFXcw2ACgwydXlZoWrxwfXJwxh1YY=;
        b=NPR66kl4Sm3iukmGBo+H+Lv3lg9ayhjNe0ry4+9k3V6/8BRQlkcKMqEEaHKDmeAFia
         naEfmst8DCjdRLb4ifCNHbv0IOAYCLYHiBT54/JPGlbb+oLvb8e4Uga7OPkAP8BNLtgm
         TTNXjhSwj/gVVXvlTkvEuWiJaZKQTkpOx4LTlwA6ZXxgla5vnol4mCDDdQzKnIbdEvm8
         xUcXDZ0shdd1oiAVNgxJO2u1uHEf6kzHdrfJOJU2KNtpsnxiHNtfWpw6pgH62LNQOZp5
         fpUVkET0gJkGTfYEVVcVr2rrIh5brJcnxB3OkQq3B2HiHsyLAoNO/G2AVhBCY9vqGv0u
         ZSEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=YgHbN0I0;
       spf=pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=p7UAYMmBt3n3GpgFXcw2ACgwydXlZoWrxwfXJwxh1YY=;
        b=BOkceFzCEWx00WtbTIe8aPrGE7tNzscSLtmT2NkLTzn6A7SdOswbVMPOBZ8N9SuaR+
         2lz3UqHANyRPkREmUf0EwlLgVPSRTCXceuCfAT0sK0gPTW6+90CZ6QVPbPaXqg3EU4ND
         tTmUaK1x4lwR7z6TbJ0RSnlsmbOC+fUFI7UNQa2bE3I5DAFIKq0wlUqw08TklBEg9rnD
         Y9fC6N4PcDpbVb3ACSM0n2UhpR3c3aFdm0QBn1qnw+PQreJ6KRuSX018d7MpT+owz3AW
         3yxpAJVJ1p80pCP4dQgj3H0Ityt6uqxZWO+0XGz+fOzwlFTtPPOoHeak1jUG/u3PdFrS
         aAnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p7UAYMmBt3n3GpgFXcw2ACgwydXlZoWrxwfXJwxh1YY=;
        b=GBoyhMb3cdge1s8j4I2GmZlGxAa3qVXCdl+7C4ogPLHRgBCmRHzog9ZgGK1XBzYOPq
         Pqq75mfXlqEWItXOk1qDdrU6T8wKUCXtPm3Cy5w7pacWe+T4vhsCgnOo19CvTqaFjTmv
         zdRbtXeRsVfm6vgG52HzezRt8lRpoYb+6Wq1zcF/LGF6+13cCbbaAdWcWqQZsMb5nHxK
         IfYs25CHkUExdvANCdfs4rJHLcElwaAi/QqYwxZGzqf678hWYjC6FaX3QGYNVxtSc9m+
         clVUliOnLqsVPFHBf2Ga8pMChOFiwNWKbKUwmHLRIXI8ZGLG/FROvuJpjyL86hPAUQfP
         JwfQ==
X-Gm-Message-State: ACrzQf19v+7knNh4IC2D2QiDrgq3XCvxmndBWNobOgDjk+y59gM9Hyrk
	4woMfYGqlYDW/enGiDGYw7s=
X-Google-Smtp-Source: AMsMyM7qYdwMIs4I0WJfdU2YXzzG1kuCZgJepy2ZLj2b6B/uWJ4oEp7evhXZlYOwCHK3/Qm5UMvxEg==
X-Received: by 2002:a05:6000:186d:b0:22a:45a3:7935 with SMTP id d13-20020a056000186d00b0022a45a37935mr8559516wri.209.1665325088375;
        Sun, 09 Oct 2022 07:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f0a:b0:225:6559:3374 with SMTP id
 bv10-20020a0560001f0a00b0022565593374ls6492132wrb.2.-pod-prod-gmail; Sun, 09
 Oct 2022 07:18:07 -0700 (PDT)
X-Received: by 2002:a5d:6906:0:b0:22c:d6d5:6322 with SMTP id t6-20020a5d6906000000b0022cd6d56322mr8987440wru.355.1665325087069;
        Sun, 09 Oct 2022 07:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665325087; cv=none;
        d=google.com; s=arc-20160816;
        b=L0kjyOahg+BX1UljYpX0x6W6JyMxdC8kSmM7aB3SWiJV64pqJEDGDeL1SxQI8D61d4
         LRQrQG7RTIw78hCVVVZ4yH5DulPhMQPmE9+Dj2zNEfMEPjubPoOXFh/KCTBmriz5sdMC
         wZh0WJ70Zx6VZEjXWq1C48F/yWeyb0A917Hk+YOAzd/Nvr/KJIhpykTSNtwWWw2JWeFq
         0FuY1dxZ/wexL1qbfOjT+7r+HdmUakaifW+HzDUJTSDkIiCOLNJtlc8p+Jzsvnn/zRd1
         0sLbYOCqjpRAa3sCOm5wUodW2X5SEvKAINNPGi1kby4pEKCJsvuBcxo7DfAzVPLrX056
         msig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oirLAgHKzqbm2tDuRRRruxvBPFu6OuA1m1Bdo0JewVo=;
        b=ySG+z5wrKTLORZI0+9/aHUxTT3eR3afDKiF9OKZnZ2y5VkpGqk4t3wlwFLlKhKdwoS
         nRLpJHvC6olTmT9aprpeQbKDJn6d9SPGjh+MgSsNt2NmjDCPrwFGWHFszoBXRLAyp6Sb
         FtKTK95Eax+GGqOCtKiieMngOM/KoJTFfsdaRtsH6dqvhpNBU/+IqFQAGxFi1siifJi6
         jBGkLvd2G+4kPxHGj/QpXOCGAF3u7Hgw1Ha6Lgd2hIE5YesRaSxt5ILCmQNc6WZcsJYC
         QjIfGsUjvGr3QCxX5gCMKBkEaxjLDHgTti9pON0j9dtKS8fG2aWx3fGBskmCQouho9c0
         kCJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=YgHbN0I0;
       spf=pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id p189-20020a1c29c6000000b003c6837bbe40si23542wmp.2.2022.10.09.07.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 09 Oct 2022 07:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9F728B80C91;
	Sun,  9 Oct 2022 14:18:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 659D2C433D6;
	Sun,  9 Oct 2022 14:17:59 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 76b4077f (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sun, 9 Oct 2022 14:17:57 +0000 (UTC)
Date: Sun, 9 Oct 2022 08:17:41 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
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
	Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v5 0/7] treewide cleanup of random integer usage
Message-ID: <Y0LYBaooZKDbL93G@zx2c4.com>
References: <20221008055359.286426-1-Jason@zx2c4.com>
 <202210082028.692DFA21@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210082028.692DFA21@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=YgHbN0I0;       spf=pass
 (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
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

On Sat, Oct 08, 2022 at 08:41:14PM -0700, Kees Cook wrote:
> On Fri, Oct 07, 2022 at 11:53:52PM -0600, Jason A. Donenfeld wrote:
> > This is a five part treewide cleanup of random integer handling. The
> > rules for random integers are:
> 
> Reviewing the delta between of my .cocci rules and your v5, everything
> matches, except for get_random_int() conversions for files not in
> your tree:
> [...]
> So, I guess I mean to say that "prandom: remove unused functions" is
> going to cause some pain. :) Perhaps don't push that to -next, and do a
> final pass next merge window to catch any new stuff, and then send those
> updates and the removal before -rc1 closes?

Ooof. Actually I think what I'll do is include a suggested diff for the
merge commit that fixes up the remaining two thankfully trivial cases.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0LYBaooZKDbL93G%40zx2c4.com.
