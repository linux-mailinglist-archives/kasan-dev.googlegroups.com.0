Return-Path: <kasan-dev+bncBDBZNDGJ54FBBXXLS6NAMGQEKH5H4NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E2A35FBE0A
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 01:01:51 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id v125-20020a1cac83000000b003bd44dc5242sf171435wme.7
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 16:01:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665529311; cv=pass;
        d=google.com; s=arc-20160816;
        b=SPeUJmiXqJhXGiI06PGRX8m5OvSuGgihbHySFfu/IEUST+2qJjQ5fVp1xSn8OpS7tK
         mNLQsxUfi7SYyBLI1YsplFCi2+BA8VGIdTEtB2H0JoJfQVhER9AM7VmlWbzcAC15BinB
         vGU3R3tDX6lcHtYHQc23/Ckxy49HMVmrXHs3jYFobw7Nt+usA/Exx0+x9HXlKpNAUSDZ
         5LJbgSD8c5bpcRwM2v9AdoNIc+J6OAv4QmQEgoCXchrd3Uw89cROTa9GmQnhllmfofWB
         /6/GvqJMDEA47mIXQAdVge97NKfDfBYGlanQr4R8ZxXBq/XNu9G/R5PfUZr9GLwaIRdj
         xZFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=r2nsMe8TypwldBiK27fYYFt11qbhkflPHB24yQ7hXMk=;
        b=uEXcY/gxQ0sA0tFazZfCclpHzJ5VsRIM/kV3XxY+BdLjE6mXR0kmAFT3p7CiXYLaam
         gDwzt+rYID38tuQxi5VePswioXd+x11gA4an2kNSg7qCKaAgVORfZU5GaQUo3EaVEjfA
         Hik1rXsYp2gP/pwvqZ7le9NpocR7Y0zA/PZxrwWLdeKNrd59sBoTV6KxB8QtPgb2sZk/
         2vYF+hZVAokDcfPoeVHu7XuOFB5W5xhJZTyiaDdFVBOwEi6ElGy6g31p6aAx3C19YQWI
         zYZnPjcz8hmJuk7Jh4WyTveKcmIIQeGwgN843sfGdCHM4me0F+WrQvILtbJeRII8918r
         0kLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AJFptayV;
       spf=pass (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r2nsMe8TypwldBiK27fYYFt11qbhkflPHB24yQ7hXMk=;
        b=ZA9+TjKgX5Rc38caq5+IvqANx6w44VTr7iqNwIldcyKEbcxV29NYtsuZNETlM7RfAA
         J5VembnXrbRjoE9wasIFeXWrr2iY4/VZ52VeAE+YX05GskWvhcsCNT45N5jVqyrdfLnZ
         tDZaey1k+mICvgUpQf3XWsLFghXXaLfCBOz04KGeCEYrcU7pYUVwzpRTsN6+XSEmlpqX
         b7zZinEEKcDiZRoN++40MJNE++18pMPDMqiUNGOqAJoezRJKSpUct0FDHCUMs7rNJLn7
         RSTmY2RC/c32jauqaBGkHZ1+Fhokwepa3W75iLCL2rvubUvKvFl1x8MQ6gxPJSDk6WjT
         dxJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r2nsMe8TypwldBiK27fYYFt11qbhkflPHB24yQ7hXMk=;
        b=67Ctx45EPS7/vfFQlIE/CEA7ZdOG/Us9MsDKjQlqALBJkFcFfyDgCZ1L611ZKo6oIN
         O127R4tp6Xcjj8IcNG33zzurpWWjhTrzoero4L0OQ4dpmsk0uUxS+kJnn4D7rHfUlAc0
         Efdtn4wjy2Zcj8M+DhPToM9RsQMrCA9k2I4LoOKGAryH+wtQv+hOyvpz/guEQsrYrI0X
         OgNfB8lWaAD9euUiFNM6Scd/yFeACwukypuI4bYQQXvPhzaG+4W3uSgziD/tS0cHcjbl
         Mm0nOAVfOw4wsJA45FilAKIPeHvGuenaLBSCrjh8WgRHz2g7t2zJrrlmoVsQZLU4pmZ8
         kY4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2hsnRMcadJly56hHrJ3L1Maph8ES0AH+Tdroc/ABkMUc5DM1fx
	+nkCjFajfjHUqvVvO2MyBqk=
X-Google-Smtp-Source: AMsMyM7GtfjL+8Ha1XN4PzkGLnqvhVTvUBrexnxpH3YNGA/NMu41L4V+xyLjIxJU/7Mv542FkLYQaA==
X-Received: by 2002:a05:6000:1562:b0:231:1b02:3dbb with SMTP id 2-20020a056000156200b002311b023dbbmr5750208wrz.685.1665529310919;
        Tue, 11 Oct 2022 16:01:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:23c:b0:22c:d34e:768c with SMTP id
 l28-20020a056000023c00b0022cd34e768cls17389489wrz.0.-pod-prod-gmail; Tue, 11
 Oct 2022 16:01:49 -0700 (PDT)
X-Received: by 2002:a05:6000:809:b0:22e:66a9:1212 with SMTP id bt9-20020a056000080900b0022e66a91212mr17524781wrb.710.1665529309668;
        Tue, 11 Oct 2022 16:01:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665529309; cv=none;
        d=google.com; s=arc-20160816;
        b=PthrKPXPTGQxaxXnpK1n+UAO98H6wLpxa9Crh4z/tH47YdjfZrcL1Mlo+cVCVaTaDB
         Qi4t92kMhxh0ErrXZw+e4a9Rh5E3uYi/BnyK6m7T2oQBodiMocpG6ZLyTPuWP0/4Ltsa
         F7Ky1KEtko6xgoucgL2z+urk3bpug0jjyDYsHGyErzy4+mgvqu5rrdcidHgGSjwcCZRo
         kcdQ8kD/NvLuQVDQYergAzT8SbS4b857OcGhKxhsm9ROTXVp0GPIKn/Zbjtv8VHIeH/i
         4AGPMj1P6GpHeF87lCul2bLrVjwuG73b5y/Jg/v+Ob1m2P5X/dnt6mLV9sgG0/eIe7Gb
         RX2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VwPTXPyue1Iwyo3nMwIU0O5/kb5ACm9LWgfhy4EE16w=;
        b=VbWqNBnFb0dFITjT2RzdNVvnY/X+UhfOILsnIaT7Fkg8K4Aui+xqflgg/yrUT3bbm7
         GMox2Nbr9t65jt+9cNloDIss2pxY6PBi91asLRkfBVltl0pgL9YumwBQdmVvnoMwy+J9
         Ei1vtKgW7vaX/4rpkPSzwytyDMgFoYiQMopKEDj7uOgTMou7VUnkg/3iW6Ivu3bNL0nl
         pwiVEuu9Pk8L4X39LeVuwrA0t4YUc9VUEcYzAuGGhIRh8QeQFnhv/p8aXV3MICEai8ht
         b1ucJ0d6yJLmdX0wY05ld9NDBZLCOb8BX9f/j6BJDe/iI2zIm8IalpFt7hpJBPzP/6OL
         rd3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AJFptayV;
       spf=pass (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id bk6-20020a0560001d8600b0022f74ffaae6si308944wrb.8.2022.10.11.16.01.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 16:01:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 40993B817C0;
	Tue, 11 Oct 2022 23:01:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9723CC433D6;
	Tue, 11 Oct 2022 23:01:45 +0000 (UTC)
Date: Tue, 11 Oct 2022 16:01:44 -0700
From: Jakub Kicinski <kuba@kernel.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev, Andreas Noever
 <andreas.noever@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Andy
 Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov
 <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph
 =?UTF-8?B?QsO2aG13YWxkZXI=?= <christoph.boehmwalder@linbit.com>, Christoph
 Hellwig <hch@lst.de>, Christophe Leroy <christophe.leroy@csgroup.eu>,
 Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, "David S . Miller"
 <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, Florian Westphal
 <fw@strlen.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter
 Anvin" <hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>, Helge Deller
 <deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen
 <chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>, "James E . J .
 Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe
 <jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>, Johannes Berg
 <johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>, Jozsef
 Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, Kees Cook
 <keescook@chromium.org>, Marco Elver <elver@google.com>, Mauro Carvalho
 Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, Pablo
 Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, Peter
 Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>,
 Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>, Thomas
 Bogendoerfer <tsbogend@alpha.franken.de>, Thomas Gleixner
 <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, Ulf Hansson
 <ulf.hansson@linaro.org>, Vignesh Raghavendra <vigneshr@ti.com>, WANG
 Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>, Yury Norov
 <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
 kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
 linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org,
 linux-mtd@lists.infradead.org, linux-nvme@lists.infradead.org,
 linux-parisc@vger.kernel.org, linux-rdma@vger.kernel.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
 linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, loongarch@lists.linux.dev,
 netdev@vger.kernel.org, sparclinux@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v6 0/7] treewide cleanup of random integer usage
Message-ID: <20221011160144.1c0dc2af@kernel.org>
In-Reply-To: <20221010230613.1076905-1-Jason@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AJFptayV;       spf=pass
 (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, 10 Oct 2022 17:06:06 -0600 Jason A. Donenfeld wrote:
> - If you want a secure or an insecure random u64, use get_random_u64().
> - If you want a secure or an insecure random u32, use get_random_u32().
>   * The old function prandom_u32() has been deprecated for a while now
>     and is just a wrapper around get_random_u32(). Same for
>     get_random_int().
> - If you want a secure or an insecure random u16, use get_random_u16().
> - If you want a secure or an insecure random u8, use get_random_u8().
> - If you want secure or insecure random bytes, use get_random_bytes().
>   * The old function prandom_bytes() has been deprecated for a while now
>     and has long been a wrapper around get_random_bytes().
> - If you want a non-uniform random u32, u16, or u8 bounded by a certain
>   open interval maximum, use prandom_u32_max().
>   * I say "non-uniform", because it doesn't do any rejection sampling or
>     divisions. Hence, it stays within the prandom_* namespace.

Acked-by: Jakub Kicinski <kuba@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221011160144.1c0dc2af%40kernel.org.
