Return-Path: <kasan-dev+bncBCLI747UVAFRB45EQONAMGQENVUY7MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EEF75F81DB
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 03:29:30 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id j24-20020a4a92d8000000b0048059a9a597sf305821ooh.13
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 18:29:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665192564; cv=pass;
        d=google.com; s=arc-20160816;
        b=sUlibuetvjPsiu7bbU9Je68BpVToLcTTIOnjL/nPuXgfUCV0rvYsxKG8fZ4EpNxVbS
         Wc8xC0ryxrsgRP24X/D6TuKJou5B0TgW2VyO5ep0TuItv/QpCx0yQtFySqTi7zP9kE6I
         67qhQ2MO4ivJyFxTCbNoJyOIa4v0pJf67Ij0PeMm+HNkpQqalKyFMqm4gOMvTBOU425c
         CcwePmuGX7rW4cEgwy4tkxSx6hwEw2QRJtJlwtV7i1V56+IW1f/Mn7Y7fGSCNQF8gKzx
         x0W9XNCrFkVkIOtxJJeyo6AsoA9H3oreEQVw3cqOWMPFyDpUhaqU6BpPcPs3pJamr/fF
         h/zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=vqu+vjmrX6XmnZaCr5Jg9hBO2GsUTDx9tUjc8bakK9M=;
        b=UYpYlzmJOQmV9m0TR1LJT59qK56cTrczWisqkr2btJMFbvNByetoTFXCXgR/7Y+mCP
         gqG4rfphfjgewObo1ypWGVUQGChdtHYEHBP6AXGnbPvtqJNLOl+BS4Kfnz6qDnQAxnqF
         fuIYhC6sH0EG+2OovcCNqOC+nRK//k3Oz+FHfy60QzfUloRt6yuwoVilgZOXIPviHeNb
         VG+ZmqXVGj8mBDRSmcnBZlVPID9BGag6JpSnFQ9cEosyJzKdrzPdJIn8M045LCt2PtkY
         A0Jk5aOaqhiIfsGsAebjR8pfnmxRGg4yKSIqEiCJq3oOnSGgOx+K2/zqM80c1EgVFHQa
         oaIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=F0WFV840;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vqu+vjmrX6XmnZaCr5Jg9hBO2GsUTDx9tUjc8bakK9M=;
        b=khRiXR0wcgmEDn193DItygTqRiGMrB7yosFenzeTCdjXnR1/YIepPj+mAHW+VVMuix
         HdH7mej+8drf7qZPYBteqGJj7yu7hceocM9AUasOdpstGo2SGEwLEtx11EYnZ8J2cXH3
         yZSMxRjwr1KB2kotXC7jLyJMRcu1eCuGq8yyzrqiTDzzIfmWlFV696VtBMlrMiTrwQRY
         beLt5sQR88OH2KHHMvdFhDly68x44F4e5/rcCQwQR36N+ToXX1MV2ZgX4EfOwHZdrR1V
         hlw+26hiTyTostQvBCg6Z9CyFHcgAih/g3DcfyMIjrlRpvlkIMF7qnhl2qe/zmEQrOyv
         AhIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vqu+vjmrX6XmnZaCr5Jg9hBO2GsUTDx9tUjc8bakK9M=;
        b=6md1khJeV8YQ9mSMybygYdRGiKXFdDXsQw1NDcnadru3+/Vl8gJjlfDBt+ENdBTvGn
         RKIC/ydXNVkdnYVsmsik0sVN0jZJYnrA4sG6LGGg9Bjljt43iiCmXqMgb9RawLH7P8KR
         phrqVHoFCJQfwr62YzgIzw7LIh1BE1WYy652dch9LcdSHKS9LcmXxGdfOZgF9NYZF9tF
         AeGTDD7Y1vvZH9nRYM75bvyC+9glBCtLI48VkurpLe3YmA3LC7HYYPbG5fWqBqzUSp7x
         38/RpM5d8PTunw8IYZSaJsEpUqwmiZnLLFO54NhNX/mrWnVrE3Z+XZ2ZgQSmodR2BYBY
         /+Gw==
X-Gm-Message-State: ACrzQf3vOUmi7oiuESCX8l2CGukysPVq1aVN/IdyBV4oZODyPYwXQEXz
	qzvkoFMuR32pf44qcDTsBfw=
X-Google-Smtp-Source: AMsMyM7aM4UoPcGFzjPcJo/nSdkqUe4Nhx/9N6ECINLFVfpK5U8Hzt6H9M7dLz7Qa0UJuBfPhGLrxg==
X-Received: by 2002:a05:6808:144b:b0:350:a06a:f8b7 with SMTP id x11-20020a056808144b00b00350a06af8b7mr3897896oiv.272.1665192564037;
        Fri, 07 Oct 2022 18:29:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d385:b0:136:39a4:9094 with SMTP id
 k5-20020a056870d38500b0013639a49094ls471027oag.5.-pod-prod-gmail; Fri, 07 Oct
 2022 18:29:23 -0700 (PDT)
X-Received: by 2002:a05:6870:4587:b0:12d:97b0:b083 with SMTP id y7-20020a056870458700b0012d97b0b083mr4233313oao.213.1665192563350;
        Fri, 07 Oct 2022 18:29:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665192563; cv=none;
        d=google.com; s=arc-20160816;
        b=KU8qDmaiRp/EzehJGKPQbQWaxTWm7rLORHnHdnDl7T3TeeMUn2ISb5tdbrL2ZdR26Z
         AAnb+JonALP0uR6eNMAwvkGGXpyP36WUy5ZxwA0gD3cDtYTx+b0uxWtBHyaPxVFwn5nO
         rj0oRzjC3onbYzTMS2R1JAYn5tBXBe5elR3z1gMo0f/FK/TxXD5ujAXkMLxXScpj7kt/
         OiBKduooD/4vRiXEG9bV2uKEsMTk3xaYIKc1V0PUPk4SZg2ElfULwVFd6aIWcIjJ8brl
         Fgfb08HiVnPPlHKfXL0h4YCk8NqXBme63rHEsFaZG33Lb+RcS+lsu5ELObTp4XaapK/+
         TctQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=2a2X1YlfkZ0pGgKe1BT3qPauqYJUuDonzfwdbODwUj0=;
        b=hoKnEhIRbf0/rdZL8MupbLsKKKFu2i2coQDEm2T4wn3xgGKqKAhvUof0VbZWesn9QM
         9vfggjHQqk34A/7jmamAGe4IuF1lAe6K1cZxkCfnHDJnZDERDjbAqy43iX7GLIO/ElRX
         mSlkqxq7Ga7Rlns5es5Y4HLKyMcnT3OiOMltkWVBhxIPVc/ibdU4ys2qtc/hgix4HawH
         EqAJVx1XnWg1GizcY24QeTMh8OnffqdmhkcahptZSNrVKW2HngKgroQBriFIiNwFzA9G
         7ywHCiVU0Ge4k/4+xNPxVcP/GFokO9rzgqNl95HgZAHUB+yYaJDYNlCQylr4ZkV5XP95
         Bv2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=F0WFV840;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id g50-20020a9d12b5000000b00660cfc41a05si172218otg.1.2022.10.07.18.29.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 18:29:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 880ACCE1926;
	Sat,  8 Oct 2022 01:29:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B6C01C433C1;
	Sat,  8 Oct 2022 01:29:12 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 08b122db (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 01:29:09 +0000 (UTC)
Date: Fri, 7 Oct 2022 19:28:59 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Darrick J. Wong" <djwong@kernel.org>
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
	sparclinux@vger.kernel.org, x86@kernel.org, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Message-ID: <Y0DSW4AAX/yA3CdI@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
 <Y0CXYjV8qMpJxxBa@magnolia>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y0CXYjV8qMpJxxBa@magnolia>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=F0WFV840;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
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

On Fri, Oct 07, 2022 at 02:17:22PM -0700, Darrick J. Wong wrote:
> On Fri, Oct 07, 2022 at 12:01:03PM -0600, Jason A. Donenfeld wrote:
> > Rather than incurring a division or requesting too many random bytes fo=
r
> > the given range, use the prandom_u32_max() function, which only takes
> > the minimum required bytes from the RNG and avoids divisions.
> >=20
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > Reviewed-by: KP Singh <kpsingh@kernel.org>
> > Reviewed-by: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.co=
m> # for drbd
> > Reviewed-by: Jan Kara <jack@suse.cz> # for ext2, ext4, and sbitmap
> > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > ---
>=20
> <snip, skip to the xfs part>
>=20
> > diff --git a/fs/xfs/libxfs/xfs_alloc.c b/fs/xfs/libxfs/xfs_alloc.c
> > index e2bdf089c0a3..6261599bb389 100644
> > --- a/fs/xfs/libxfs/xfs_alloc.c
> > +++ b/fs/xfs/libxfs/xfs_alloc.c
> > @@ -1520,7 +1520,7 @@ xfs_alloc_ag_vextent_lastblock(
> > =20
> >  #ifdef DEBUG
> >  	/* Randomly don't execute the first algorithm. */
> > -	if (prandom_u32() & 1)
> > +	if (prandom_u32_max(2))
>=20
> I wonder if these usecases (picking 0 or 1 randomly) ought to have a
> trivial wrapper to make it more obvious that we want boolean semantics:
>=20
> static inline bool prandom_bool(void)
> {
> 	return prandom_u32_max(2);
> }
>=20
> 	if (prandom_bool())
> 		use_crazy_algorithm(...);
>=20

Yea, I've had a lot of similar ideas there. Part of doing this (initial)
patchset is to get an intuitive sense of what's actually used and how
often. On my list for investigation are a get_random_u32_max() to return
uniform numbers by rejection sampling (prandom_u32_max() doesn't do
that uniformly) and adding a function for booleans or bits < 8. Possible
ideas for the latter include:

   bool get_random_bool(void);
   bool get_random_bool(unsigned int probability);
   bool get_random_bits(u8 bits_less_than_eight);

With the core of all of those involving the same batching as the current
get_random_u{8,16,32,64}() functions, but also buffering the latest byte
and managing how many bits are left in it that haven't been shifted out
yet.

So API-wise, there are a few ways to go, so hopefully this series will
start to give a good picture of what's needed.

One thing I've noticed is that most of the prandom_u32_max(2)
invocations are in debug or test code, so that doesn't need to be
optimized. But kfence does that too in its hot path, so a
get_random_bool() function there would in theory lead to an 8x speed-up.
But I guess I just have to try some things and see.

Anyway, that is a long way to say, I share you curiosity on the matter
and I'm looking into it.

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0DSW4AAX/yA3CdI%40zx2c4.com.
