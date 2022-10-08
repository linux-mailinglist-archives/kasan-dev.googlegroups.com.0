Return-Path: <kasan-dev+bncBCLI747UVAFRBQWZQONAMGQE4SZLYXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5963D5F82B3
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 05:21:40 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id kk6-20020a17090b4a0600b0020af381d1c4sf5305177pjb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 20:21:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665199298; cv=pass;
        d=google.com; s=arc-20160816;
        b=VKRez0mOU8GaOCc/bK0XZwPXqfkk0Df+mf7CKAWbQdxI7BxBjr+7JJ6blbllSlXHBI
         F4aoXXBU6/zc2dDNy3MlZCtwvKYpHCINBAry+D8A+FfxXQGxoYxaFqTNvXrnVgaQQ1da
         YWjV8KEryBngQsex/whbuxzmLfCK6eo5/o/cEoed8AKVDCMs1xfpZdJi1PNaJGHNbG3X
         UuX8c9a4jjmX3R/Jo5QsFhL6qCq+KglCbLMkSQmeUjgz91KLgzmQJlcSg65uN/oo+JOi
         OBaLsqRJZ7pv0GxUVvd7uFkec8H+Y5UvchrTXmbfovCkRkxFtoZnjsCRkuL5HOneUIiW
         vNXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vQWR7IurlSODrWHjMeM3PQy/EjN12NgzC0sa9l2ceK8=;
        b=eor+FO+CdADajHyNRf6SYiQvmpGdzUY3e5E/cv2vdzV9oAdnKCv/D40FMWDXU20mgn
         NC8E4p4YE+rKVukJyCHw0cCjQhVZsW3t56868WeFBbxzJC5bixD34w3PXckc2EFpPb/J
         bHohv0cb10IoVmulZHtLTIFdeBRuon+6wXo73T0zTmrP60blmPlLyNBhKYMM2qwvsMNK
         dtezpUBx6kWTGlOlM4FOF383fbIJmtBInQELm8YyhfoHUFbmJLm2WoosBVDrLOmlF9NO
         jc1gbj/x9erFlT+nZXILXZlCRdgxznPvkq8QHcRySgVV4uzx8yKD0wZTll6T/Snji/UZ
         Va8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=QJwXB42z;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vQWR7IurlSODrWHjMeM3PQy/EjN12NgzC0sa9l2ceK8=;
        b=mBU4/JlAJrvfri5MBDcQxXnRxID2Wqf52dCFwsxgQmSGt0t5cOClft6H4X2gzVAxf1
         bIFtBEU0qUDT8HaEd09rhjCQy7zugtMYP1NHYtCtwbaz0yKIHbTDhuh741B4FjH0nfgY
         b3OlIsxHp0vvyoCZzhaLAzzluhsSEKrdG4qwG/38xPQNlE/sQukrG31+X125KAQKuSpO
         1MjmNpVPRsoAZ0NRNs644CogXdagN60oUL5EodGHfpVgPAy1tHrfhfA/fKyzgIXIv59F
         6JXO7Z/9Q3X7w7MwA26wB3xCrC+MIXq8hi5bssBcoEyNFNVaxYOJBMC8qyC//zFeZnSi
         IT5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vQWR7IurlSODrWHjMeM3PQy/EjN12NgzC0sa9l2ceK8=;
        b=Koej9BlGa3SyLcUZt6NzK6VwzQUBgWwSCQWE57q8M5NAVgDJaXKlKFWCYlRfjuHglN
         NDmmGEF7YhusPrdi4sOrImCtgsXy+E7ibkot1CniZXVdKcPbksgYVb1Gpp5DVNpEnHAs
         f3mvE8hODFASGLQTKrpeL6FeltCAytSvGMddL8et+/EKJt+Kk8htP/v8VeQMmLKykDvx
         aQo6d1+K64fg1gvoxyLy5YNwLwAREQdyKcp73DfGoEotMJH5AB1dlqYY1VSTQuWFnkXw
         qTSwyXMJplV1S707TEaNtubNTViwc4KbMfEzyxlxc0LCxPr/3VPGFlSOexwsoLajnGnu
         oCMg==
X-Gm-Message-State: ACrzQf25x9HPS9jXF+3L7SpHM1dyEdAYf6N3fTJv1YC+jb+s0RUhNssh
	jOXNKE8awcDZWeXub6QPQi0=
X-Google-Smtp-Source: AMsMyM7F2cQccde7Bfr94Fn5ioGJX8dss1LCaSAG7K6sTn/AxVUnz2+mwPV/5lldXb1LxEJUxtUXbg==
X-Received: by 2002:a17:902:bd05:b0:179:bbad:acff with SMTP id p5-20020a170902bd0500b00179bbadacffmr7941748pls.170.1665199298595;
        Fri, 07 Oct 2022 20:21:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:240a:b0:16d:6f9a:131a with SMTP id
 e10-20020a170903240a00b0016d6f9a131als4852441plo.5.-pod-prod-gmail; Fri, 07
 Oct 2022 20:21:37 -0700 (PDT)
X-Received: by 2002:a17:90b:2686:b0:20a:d838:25d2 with SMTP id pl6-20020a17090b268600b0020ad83825d2mr8597664pjb.35.1665199297727;
        Fri, 07 Oct 2022 20:21:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665199297; cv=none;
        d=google.com; s=arc-20160816;
        b=PaB43JqMnRe1IO88K4H1Yd8rBbCOAU0gVaRmkwPmRwlZ21Fahf628xY5rqITKgCJ9Q
         JrBt9kCOfhpfut/tbxICS+PXG5nutA4ErjkXNT52rP9WZ4+TuoM9RzGb5QWbTlqJm4wA
         NuV3NDPIwbKyazKLal6l7OPcvhI0FQ4pIH4ScFE3kp+gpClPUOOLeOt+QVdFLsWTl9FU
         NwMCkqYm6ztMAWbQYub2YFrLlcgBF+d3QZP+SaX/v2TdY/eRzbysu2DMGSfGQkduy3JT
         zmZzn9/5nibBaXoDpMD64XcVAHWo4aE9ML2Tpecv5KRsQn1tOEyRRGRKVCTtxH9ftiua
         814g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=L9NKrsR7tTYpbn5X6JuYO0fYdKTzEIaHBiFinguj7aw=;
        b=p+p5mLqzABXcbmqpvAVYP/+ULz4dutmYz5WPNRz7OuncAl2HimB/klQiY6ED6YdzaT
         wlrhDrCOEUOWK15jAobQnQO5eO+9UA8PcdbAqxOMOQJKh7b5zvEIWgQuH81WnmFvMlbJ
         LKuJX9O8+w2qfVJRzX/+QyiPj5+RQzg6XAQYUABE3zDl1ms1n3sX0EK4MnN7cToJiN5U
         BxcL7dGFG1vYYi1H3eEbH1NEoRQOAKZxWnfmX3o/pQfqg21cbjefoNwwbYLb8QMIaUy2
         lkdkOTpLfPDRcw5hRPuRiTAydCVia9hcC3EP4GioDENi6021ID4hNBWe+3wyTg0dK6Sh
         X6oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=QJwXB42z;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n27-20020aa7985b000000b00560eeb33bbasi111321pfq.6.2022.10.07.20.21.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 20:21:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1AC9D60DE1;
	Sat,  8 Oct 2022 03:21:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5142DC433C1;
	Sat,  8 Oct 2022 03:21:30 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id ea268ade (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 03:21:28 +0000 (UTC)
Date: Fri, 7 Oct 2022 21:21:20 -0600
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
	sparclinux@vger.kernel.org, x86@kernel.org, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Message-ID: <Y0DssPFp2rY+TrPp@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
 <202210071241.445289C5@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210071241.445289C5@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=QJwXB42z;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
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

On Fri, Oct 07, 2022 at 03:47:44PM -0700, Kees Cook wrote:
> > diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
> > index 4f2f2d1bac56..56ffaa8dd3f6 100644
> > --- a/lib/test_vmalloc.c
> > +++ b/lib/test_vmalloc.c
> > @@ -151,9 +151,7 @@ static int random_size_alloc_test(void)
> >  	int i;
> >  
> >  	for (i = 0; i < test_loop_count; i++) {
> > -		n = prandom_u32();
> > -		n = (n % 100) + 1;
> > -
> > +		n = prandom_u32_max(n % 100) + 1;
> >  		p = vmalloc(n * PAGE_SIZE);
> >  
> >  		if (!p)
> 
> This looks wrong. Cocci says:
> 
> -               n = prandom_u32();
> -               n = (n % 100) + 1;
> +               n = prandom_u32_max(100) + 1;

I agree that's wrong, but what rule did you use to make Cocci generate
that?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0DssPFp2rY%2BTrPp%40zx2c4.com.
