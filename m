Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBQFSQ2NAMGQEOA4DOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FD1E5F85CF
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 17:37:38 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id y10-20020ab0560a000000b003af33bfa8c4sf2862445uaa.21
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 08:37:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665243457; cv=pass;
        d=google.com; s=arc-20160816;
        b=eXDW+vNnTffmWRRmj1BZSLmMG4V3EReqU1t/FH090GbX2qYwg10ttnjChBTSMXGP4n
         9nHocIALIZw0KmjgxGGFIHTLE5O/y5AtpVoESI+Ft/o8mpdFimxNhVZyjXVKFbXlnGmC
         qJmkX4ffQGI+xocte3sm4E0e1iQlUrY0iAQgVLEhS/ZAEok53bs+MiPp+2cuTDpGfXne
         lU4dPSDJwcHgEqxRoXDyTXFz1CgmtpNOeeMriTdp/Ur9J8Q7OEJ+6O4lpoSX3HxFJ+jw
         +8ltm5QXuKpMWs9/fxIgyXurBpJKvy6jvinD5j26bKEFRTBEol9ptxijaAZWgchURt4W
         QQ/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Rp2G4Yg57iqoP3g9UIl1mRJlfP1nzFeg4fJEgHbofXY=;
        b=Ij9KOLD/vTvuYWxaJLBuRfgAHtRaoQwBq8BKwHp95MXYVDMu5ec44potuafES+b50Q
         kzxaaJSNJuEnFBV5O4HoxtDzwv4m07VaxgtaXzqmoPN2+NzZRDr17s8K3q7phvvhdZTl
         a8DwjynmmfjHTDwBtMJrA2PQGcoVWbkkp7g8yvcUcFzGA1d7QR2WARslTHaInMnE52aF
         WB20vdg3Z8FeTbKPl25+Y5HdyVP5Fz2JHk2jnzpCQARFgEga0a+GhcL2LQErnXPRCyvY
         y8cmZytugtPvHiM1WYAS400Mn0QHC0floQ6Me83XpHWigiz6VC5mYTa1UN9OmPhkm5qc
         RMqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="lpPo/Fws";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Rp2G4Yg57iqoP3g9UIl1mRJlfP1nzFeg4fJEgHbofXY=;
        b=E+ylwbP53SdekxCLlEGEyFlY8dcdGpE8g78/btiYQ3uXwVQsV3JF5eygBM1tdwLHsg
         hZ5Bc99kCr8eWM7H/nEUz2o2OSRPk8Gmij4jFt27WuTbhp0HHlUNYbljyCgH48m7tzIk
         R//6oWOFTTqBFvoB+Ib0T8/MeCzYVE6+Md+w4NJwRbxS751Lf9JNpZcnccC03hGj543F
         qh5CrQG85vUZJGcWv2vNFcc75aXcoZDZYOmCQllpRrmiOOrd/97wcfJB2Kxv0+VvLrO4
         24rQF++Z/BdOj586i98uq0bCgDwVOdRWSyoVz2+3M5DlrDxHj8YcD7ZNgy+RoZRi4Bcz
         Ih+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rp2G4Yg57iqoP3g9UIl1mRJlfP1nzFeg4fJEgHbofXY=;
        b=7Ko57ZeQDxVAQNnFbW2A92ef6Isulur3SsbzxJhtphz2LFDawS+NGekWRPU6YcwE1D
         GDrwsLztvRFADqEfnMSSkVMX4xJoBvS2d1IbicRxIonM6M+6SbqpA8iPPbdEb1olZQVY
         DwuTuuJFFXsLYxre5K9TxKFkt6mlAi/vGVlYQl8sgMMcCM6rpNOIOOxGZHL7p4yf7yNI
         2EhywBl4HDBG3Cr7KPp6e4DYdsdwOy2wXC8xBlPz1TGJVSI6qw8HD5ClAhrN76jC0Jn1
         pOO7QVs0gvRhnrP7KgTBwcJ29xbMr8N+QsHpgWQkTIkHLhZD6J5jp53o99NZ3+t8dONl
         MyiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1dbYZYYm9jD+WbXRDI/FnY900Ppm6L00bMfd9arRTX3A7yFYUW
	6/13pmeOQ7yjS4K/SOg42Qw=
X-Google-Smtp-Source: AMsMyM71XL6TTVdJnj8ANfbwWoU97iABvgVh00G+iqrLrfBnKHn3c9fx0O58toVKxArEALpuDxoDpw==
X-Received: by 2002:a1f:7d0b:0:b0:3aa:ff25:da8c with SMTP id y11-20020a1f7d0b000000b003aaff25da8cmr5640125vkc.21.1665243456962;
        Sat, 08 Oct 2022 08:37:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:a649:0:b0:3a2:c7ad:e747 with SMTP id r9-20020a67a649000000b003a2c7ade747ls1574919vsh.4.-pod-prod-gmail;
 Sat, 08 Oct 2022 08:37:36 -0700 (PDT)
X-Received: by 2002:a67:e118:0:b0:3a7:6074:dd7e with SMTP id d24-20020a67e118000000b003a76074dd7emr1959420vsl.57.1665243456327;
        Sat, 08 Oct 2022 08:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665243456; cv=none;
        d=google.com; s=arc-20160816;
        b=sAnt19U8IcgdtKlBWQxHiyTotRNd92OtlV3tv8EP5CO+CPaUSe7OFk+b5MsuKF0Mj9
         EcqRZW2gGKJ6EdP5xD/8zMUno1R2QjQX/EFPgsrTeow/i3y05/fhsWFZwY1IO9uVVmME
         9bmTMsyLsYPEsRqsiDi2yyetdS8w28hTgM/cOR7bZqgMn5vVzZsGxaxvOhuCV2vU7+r5
         ijCSmsMxdMbmP+bMWz79qcSJDhB1P9FQvVzchsfPcaWL+ISMSlAcRhPXrkhrROjzS0Vg
         rAtFmKsRMdDg2DR42RSRzIlI/Cpniu6ps52fevS5quxaWzDxxD5PkZDBA7zgMXJ1j6Nl
         m3xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bo8g+SxknBc7mL91mpIAIhUPb4yIUdN8DS3Dg4Vt0Yc=;
        b=TMg9o6E+bO/wacgSeksRAi0D9cLTXTPxrE2ysfS4tYfQXpVdFads6Xok3jVtf825IZ
         Gamob+xOBuLHzUhcYvNFQHOLpmA6UkHBPIiRJbWQCLVyb539SN2hMWXvLbZe5zmKIOG6
         0+CMjE61sOacxvj5hmTLV+VYc8QkVjNiKioRcOX67bcaMMIkuv1arxvPVFJWQyTmxHWv
         lYpkZMsCEH0JJ2IK3GOs9CaJ1FgX5oOn3gxaWq1yGcX4mXnyMKuC28KByo/lAG0QyEiJ
         TS0yIJnPlR5XfHtA+pQGw3IlE30+C6KpjsiNNDfaI+mmxlUuMqVhuSqAepQR0b5fT9Ie
         W+SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="lpPo/Fws";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id r11-20020ab06f0b000000b003d919da0471si924687uah.1.2022.10.08.08.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 08:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id ACC8A60112;
	Sat,  8 Oct 2022 15:37:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6325DC433D6;
	Sat,  8 Oct 2022 15:37:33 +0000 (UTC)
Date: Sat, 8 Oct 2022 17:38:15 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?iso-8859-1?Q?B=F6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
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
	KP Singh <kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
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
Message-ID: <Y0GZZ71Ugh9Ev99R@kroah.com>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b="lpPo/Fws";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Oct 07, 2022 at 11:53:52PM -0600, Jason A. Donenfeld wrote:
> Changes v4->v5:
> - Coccinelle is now used for as much mechanical aspects as possible,
>   with mechanical parts split off from non-mechanical parts. This should
>   drastically reduce the amount of code that needs to be reviewed
>   carefully. Each commit mentions now if it was done by hand or is
>   mechanical.

All look good to me, thanks for the cleanups.

Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0GZZ71Ugh9Ev99R%40kroah.com.
