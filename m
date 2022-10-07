Return-Path: <kasan-dev+bncBCN253FDVEJRBZFOQKNAMGQETLGQFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB555F7F95
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 23:17:26 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id 3-20020a056a00072300b00562968980e6sf2702855pfm.17
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 14:17:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665177445; cv=pass;
        d=google.com; s=arc-20160816;
        b=mjq3Q9s4HahbaTcEVnWExvk2H+Xmat2ksPEz4kkgi90Dx80FXMEbQMDQUdwZ29O6KJ
         4auHMXIDpMRZtxEaY/HmX2cvaxMbGuOd5vaJ89I7mIyjuuCkNEU2inevqTWhvQIN8skq
         Xipg7wsiyEgR/dmx9qAk6Uod/s2yZuoHGdyLd3Edi9YgIxp++zA2d1vws9BZmIEHcRoH
         4sFtb8C90kIuVocGqd68hjU36BA5490FeiJAGJKN3orQK2Ykqg8NBebMtgESF97GxY9z
         6oMK2B1eXKifGIJwovZRmvBHB6/jNnYe/f4cTg6Lh5ziffxhRRp+XaAzriqB/gw1fcrl
         GL2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ofe0MljtTCLfB3SDOVRniEw6gPwaEHnSPfq1maptatI=;
        b=vJS5WJdZ+EZ5qGu0Cs5RjhMFXhlyf/Lg7PYpFbBv6dZ/SM0l98Lp+wZmvQPUAfag31
         xO7rkzBf6DWRyy4GHhrMO5G11t3WI3Ar+jIbknhPJuzoXbBveBbLqGK4+CEMj6wbFZ14
         hoN4pGBrPFGTrJUPmlRUVbqyVf6JXaxfO7aWxTkE+0fHkHOcug6r66mmuPGMeHb96VBd
         cqA30z+gtEvPpwRy+4mxwcTZSD55OebqFbM0uIfYOVoWV8AYDhTWh3bph1zWzEpP49JS
         OMMel/faXKZyxwjLsvl06s5UYVn6Wos4dMd+Oms2D29Gj6MhQptRGQVZMYJAQIxRMcTL
         qoUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WvIpI0oG;
       spf=pass (google.com: domain of djwong@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ofe0MljtTCLfB3SDOVRniEw6gPwaEHnSPfq1maptatI=;
        b=A+tA64YsmtrpnARjnLrojpj6VKaIt3miTDZpyzVHeAU+9yDHIrbblzWOqMXMaXx2aq
         plIfgXvZBV6tSDTcPFam3WbmULc+6m+3xydivclnO6m23cuhLlnnj8VIWdTqlY5lu36Q
         BRsdKQ47yYSV7HVAhhPzJ0EvbWRsOXOuwgbzfZnAM16ZYNImIBSltmIjTNXfeWPFppKO
         DXImj8KiSC9n0QQq+pbDaDagCvY5Ru/Bul4eG7MdQjlliAXxJL2g5Hm+2zB0Ks0VhOJi
         4rAnXt+uo8uzk/+c/5qpdjoTsiIwWmAHpC5fgJwaRpYjO98bUuyCAxhd9bPD5f9yg+VF
         iVOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ofe0MljtTCLfB3SDOVRniEw6gPwaEHnSPfq1maptatI=;
        b=R4tgDiUQK3qYrI7QIhZjtiw99GzcCEWcOm5TZLlJYlm/MO1okADBkHOHZf93Im701Y
         +q3o3jn1gYSRinHJtHUXIfE6yNpq4cFaYqV56Bk9ax0DxQLoXacZOn+q1uffx9f7jP9Z
         FXyuIgZvzk7XLBX9g/YyGHJqZglapEjb9H4+mGmznyM65znomAkM/LXouw3aTBT7aj1P
         FVBSPRWxIgyzTXw6o/GYERvu7MCcyWTByvVjlrY2nXiVZjKc/554nSfPKtxe4Mc9sfZe
         vsl/fYfa3YhT1+WmjvRFMh1SOMFfAHJWWjSHKuZH36LS6wEJaPifEZICPZoe4R1p/Kux
         KSsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3JZQNsVyZkNvNyB78bl1D+rMeWTLBHt8eiYFej1dt4hKTVIr7H
	H3mft3L66ohJXOU1lJHyFqk=
X-Google-Smtp-Source: AMsMyM6id9PQVSbqrL8qkm9MOQ1DD2e/dJeVwr1pNOZLm9Nu6H7XJyVYvP0uPhYS1e3fCyjh1hq2Ag==
X-Received: by 2002:a17:902:ef51:b0:180:7922:ce40 with SMTP id e17-20020a170902ef5100b001807922ce40mr2415054plx.8.1665177445144;
        Fri, 07 Oct 2022 14:17:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:780e:b0:202:c046:4732 with SMTP id
 w14-20020a17090a780e00b00202c0464732ls6901765pjk.1.-pod-canary-gmail; Fri, 07
 Oct 2022 14:17:24 -0700 (PDT)
X-Received: by 2002:a17:90a:cf82:b0:20b:3525:81ec with SMTP id i2-20020a17090acf8200b0020b352581ecmr6648649pju.42.1665177444424;
        Fri, 07 Oct 2022 14:17:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665177444; cv=none;
        d=google.com; s=arc-20160816;
        b=iBy7Q26zvyM6qa9U4pWfmJbogGccBOF8cY2nH/uYXyWTlUaig0x9Cw4V34m7t0lag0
         pjPOD7F1s4xF1dqhN045fcacpgOHMvI4yGLrjilHYi9tuJuHBmqSZfQ5enear9Qm4Krw
         o5uTWSKRVTfArZ/E/Yrns17dIQkNzugiIpR3fagMLsMgmwixNhF9uiS2offAHVhIf77i
         eOvU0cDbYKTAyTWpSDYZyCBCOsIY5bc71njQG0+hRoxhedZPKXtWSbAb/y9GGboA4WaY
         7cp8srXhm7MpObK9h1WRSoteKWB+huFiu42L7OxASiUaN0WJ85O2X9227DE6LoonO75f
         CM8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jrgO24KhOXFKRtWvS3yAZTQnYVG6qYfMW9r+ZvxA0VU=;
        b=abcqoQS+q8mKXNz8ovCr4LyPcz2zq9/mXgLH8wSt0OSvlo6zQ9hto6E1YGKctUm3BO
         STSMoIReUMCuzp2dk2kdmmFnlu5gnNVBMKO3gS/7q6Xf4lSLzbeyX4U+v1ziWrd71ejE
         yxcDjeKdO4UKsJXXBACW8uKD3rVuWbCpmZ3lxM4/enx+g5sz+x88xUvG8WHWs7Nxl+rX
         x+C1geLWH3+HROTLk8MVV1njGoHjlnEVV5J3Hpne1ySN1thW1TTCt5ZHsyvhKSM3dv8C
         oK0OtnDbzkUqhj6lPtjDxd3qMfxREfXd3uSIg8K1sl2TxLPLu6I8Tx0EJFB56kKBI0oC
         efQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WvIpI0oG;
       spf=pass (google.com: domain of djwong@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u17-20020a17090341d100b0016d3382bc9asi115108ple.0.2022.10.07.14.17.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 14:17:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of djwong@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BB3E461747;
	Fri,  7 Oct 2022 21:17:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 08267C433C1;
	Fri,  7 Oct 2022 21:17:23 +0000 (UTC)
Date: Fri, 7 Oct 2022 14:17:22 -0700
From: "Darrick J. Wong" <djwong@kernel.org>
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
Message-ID: <Y0CXYjV8qMpJxxBa@magnolia>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221007180107.216067-3-Jason@zx2c4.com>
X-Original-Sender: djwong@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WvIpI0oG;       spf=pass
 (google.com: domain of djwong@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=djwong@kernel.org;       dmarc=pass (p=NONE
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

On Fri, Oct 07, 2022 at 12:01:03PM -0600, Jason A. Donenfeld wrote:
> Rather than incurring a division or requesting too many random bytes for
> the given range, use the prandom_u32_max() function, which only takes
> the minimum required bytes from the RNG and avoids divisions.
>=20
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: KP Singh <kpsingh@kernel.org>
> Reviewed-by: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com>=
 # for drbd
> Reviewed-by: Jan Kara <jack@suse.cz> # for ext2, ext4, and sbitmap
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---

<snip, skip to the xfs part>

> diff --git a/fs/xfs/libxfs/xfs_alloc.c b/fs/xfs/libxfs/xfs_alloc.c
> index e2bdf089c0a3..6261599bb389 100644
> --- a/fs/xfs/libxfs/xfs_alloc.c
> +++ b/fs/xfs/libxfs/xfs_alloc.c
> @@ -1520,7 +1520,7 @@ xfs_alloc_ag_vextent_lastblock(
> =20
>  #ifdef DEBUG
>  	/* Randomly don't execute the first algorithm. */
> -	if (prandom_u32() & 1)
> +	if (prandom_u32_max(2))

I wonder if these usecases (picking 0 or 1 randomly) ought to have a
trivial wrapper to make it more obvious that we want boolean semantics:

static inline bool prandom_bool(void)
{
	return prandom_u32_max(2);
}

	if (prandom_bool())
		use_crazy_algorithm(...);

But this translation change looks correct to me, so for the XFS parts:
Acked-by: Darrick J. Wong <djwong@kernel.org>

--D


>  		return 0;
>  #endif
> =20
> diff --git a/fs/xfs/libxfs/xfs_ialloc.c b/fs/xfs/libxfs/xfs_ialloc.c
> index 6cdfd64bc56b..7838b31126e2 100644
> --- a/fs/xfs/libxfs/xfs_ialloc.c
> +++ b/fs/xfs/libxfs/xfs_ialloc.c
> @@ -636,7 +636,7 @@ xfs_ialloc_ag_alloc(
>  	/* randomly do sparse inode allocations */
>  	if (xfs_has_sparseinodes(tp->t_mountp) &&
>  	    igeo->ialloc_min_blks < igeo->ialloc_blks)
> -		do_sparse =3D prandom_u32() & 1;
> +		do_sparse =3D prandom_u32_max(2);
>  #endif
> =20
>  	/*
> diff --git a/include/linux/nodemask.h b/include/linux/nodemask.h
> index 4b71a96190a8..66ee9b4b7925 100644
> --- a/include/linux/nodemask.h
> +++ b/include/linux/nodemask.h
> @@ -509,7 +509,7 @@ static inline int node_random(const nodemask_t *maskp=
)
>  	w =3D nodes_weight(*maskp);
>  	if (w)
>  		bit =3D bitmap_ord_to_pos(maskp->bits,
> -			get_random_int() % w, MAX_NUMNODES);
> +			prandom_u32_max(w), MAX_NUMNODES);
>  	return bit;
>  #else
>  	return 0;
> diff --git a/lib/cmdline_kunit.c b/lib/cmdline_kunit.c
> index e6a31c927b06..a72a2c16066e 100644
> --- a/lib/cmdline_kunit.c
> +++ b/lib/cmdline_kunit.c
> @@ -76,7 +76,7 @@ static void cmdline_test_lead_int(struct kunit *test)
>  		int rc =3D cmdline_test_values[i];
>  		int offset;
> =20
> -		sprintf(in, "%u%s", prandom_u32_max(256), str);
> +		sprintf(in, "%u%s", get_random_int() % 256, str);
>  		/* Only first '-' after the number will advance the pointer */
>  		offset =3D strlen(in) - strlen(str) + !!(rc =3D=3D 2);
>  		cmdline_do_one_test(test, in, rc, offset);
> @@ -94,7 +94,7 @@ static void cmdline_test_tail_int(struct kunit *test)
>  		int rc =3D strcmp(str, "") ? (strcmp(str, "-") ? 0 : 1) : 1;
>  		int offset;
> =20
> -		sprintf(in, "%s%u", str, prandom_u32_max(256));
> +		sprintf(in, "%s%u", str, get_random_int() % 256);
>  		/*
>  		 * Only first and leading '-' not followed by integer
>  		 * will advance the pointer.
> diff --git a/lib/kobject.c b/lib/kobject.c
> index 5f0e71ab292c..a0b2dbfcfa23 100644
> --- a/lib/kobject.c
> +++ b/lib/kobject.c
> @@ -694,7 +694,7 @@ static void kobject_release(struct kref *kref)
>  {
>  	struct kobject *kobj =3D container_of(kref, struct kobject, kref);
>  #ifdef CONFIG_DEBUG_KOBJECT_RELEASE
> -	unsigned long delay =3D HZ + HZ * (get_random_int() & 0x3);
> +	unsigned long delay =3D HZ + HZ * prandom_u32_max(4);
>  	pr_info("kobject: '%s' (%p): %s, parent %p (delayed %ld)\n",
>  		 kobject_name(kobj), kobj, __func__, kobj->parent, delay);
>  	INIT_DELAYED_WORK(&kobj->release, kobject_delayed_cleanup);
> diff --git a/lib/reed_solomon/test_rslib.c b/lib/reed_solomon/test_rslib.=
c
> index 6faf9c9a6215..4d241bdc88aa 100644
> --- a/lib/reed_solomon/test_rslib.c
> +++ b/lib/reed_solomon/test_rslib.c
> @@ -199,7 +199,7 @@ static int get_rcw_we(struct rs_control *rs, struct w=
space *ws,
> =20
>  		derrlocs[i] =3D errloc;
> =20
> -		if (ewsc && (prandom_u32() & 1)) {
> +		if (ewsc && prandom_u32_max(2)) {
>  			/* Erasure with the symbol intact */
>  			errlocs[errloc] =3D 2;
>  		} else {
> diff --git a/lib/sbitmap.c b/lib/sbitmap.c
> index c4f04edf3ee9..ef0661504561 100644
> --- a/lib/sbitmap.c
> +++ b/lib/sbitmap.c
> @@ -21,7 +21,7 @@ static int init_alloc_hint(struct sbitmap *sb, gfp_t fl=
ags)
>  		int i;
> =20
>  		for_each_possible_cpu(i)
> -			*per_cpu_ptr(sb->alloc_hint, i) =3D prandom_u32() % depth;
> +			*per_cpu_ptr(sb->alloc_hint, i) =3D prandom_u32_max(depth);
>  	}
>  	return 0;
>  }
> diff --git a/lib/test_hexdump.c b/lib/test_hexdump.c
> index 0927f44cd478..41a0321f641a 100644
> --- a/lib/test_hexdump.c
> +++ b/lib/test_hexdump.c
> @@ -208,7 +208,7 @@ static void __init test_hexdump_overflow(size_t bufle=
n, size_t len,
>  static void __init test_hexdump_overflow_set(size_t buflen, bool ascii)
>  {
>  	unsigned int i =3D 0;
> -	int rs =3D (prandom_u32_max(2) + 1) * 16;
> +	int rs =3D prandom_u32_max(2) + 1 * 16;
> =20
>  	do {
>  		int gs =3D 1 << i;
> diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
> index 4f2f2d1bac56..56ffaa8dd3f6 100644
> --- a/lib/test_vmalloc.c
> +++ b/lib/test_vmalloc.c
> @@ -151,9 +151,7 @@ static int random_size_alloc_test(void)
>  	int i;
> =20
>  	for (i =3D 0; i < test_loop_count; i++) {
> -		n =3D prandom_u32();
> -		n =3D (n % 100) + 1;
> -
> +		n =3D prandom_u32_max(n % 100) + 1;
>  		p =3D vmalloc(n * PAGE_SIZE);
> =20
>  		if (!p)
> @@ -293,16 +291,12 @@ pcpu_alloc_test(void)
>  		return -1;
> =20
>  	for (i =3D 0; i < 35000; i++) {
> -		unsigned int r;
> -
> -		r =3D prandom_u32();
> -		size =3D (r % (PAGE_SIZE / 4)) + 1;
> +		size =3D prandom_u32_max(PAGE_SIZE / 4) + 1;
> =20
>  		/*
>  		 * Maximum PAGE_SIZE
>  		 */
> -		r =3D prandom_u32();
> -		align =3D 1 << ((r % 11) + 1);
> +		align =3D 1 << (prandom_u32_max(11) + 1);
> =20
>  		pcpu[i] =3D __alloc_percpu(size, align);
>  		if (!pcpu[i])
> @@ -393,14 +387,11 @@ static struct test_driver {
> =20
>  static void shuffle_array(int *arr, int n)
>  {
> -	unsigned int rnd;
>  	int i, j;
> =20
>  	for (i =3D n - 1; i > 0; i--)  {
> -		rnd =3D prandom_u32();
> -
>  		/* Cut the range. */
> -		j =3D rnd % i;
> +		j =3D prandom_u32_max(i);
> =20
>  		/* Swap indexes. */
>  		swap(arr[i], arr[j]);
> diff --git a/net/core/pktgen.c b/net/core/pktgen.c
> index a13ee452429e..5ca4f953034c 100644
> --- a/net/core/pktgen.c
> +++ b/net/core/pktgen.c
> @@ -2469,11 +2469,11 @@ static void mod_cur_headers(struct pktgen_dev *pk=
t_dev)
>  	}
> =20
>  	if ((pkt_dev->flags & F_VID_RND) && (pkt_dev->vlan_id !=3D 0xffff)) {
> -		pkt_dev->vlan_id =3D prandom_u32() & (4096 - 1);
> +		pkt_dev->vlan_id =3D prandom_u32_max(4096);
>  	}
> =20
>  	if ((pkt_dev->flags & F_SVID_RND) && (pkt_dev->svlan_id !=3D 0xffff)) {
> -		pkt_dev->svlan_id =3D prandom_u32() & (4096 - 1);
> +		pkt_dev->svlan_id =3D prandom_u32_max(4096);
>  	}
> =20
>  	if (pkt_dev->udp_src_min < pkt_dev->udp_src_max) {
> diff --git a/net/ipv4/inet_hashtables.c b/net/ipv4/inet_hashtables.c
> index b9d995b5ce24..9dc070f2018e 100644
> --- a/net/ipv4/inet_hashtables.c
> +++ b/net/ipv4/inet_hashtables.c
> @@ -794,7 +794,7 @@ int __inet_hash_connect(struct inet_timewait_death_ro=
w *death_row,
>  	 * on low contention the randomness is maximal and on high contention
>  	 * it may be inexistent.
>  	 */
> -	i =3D max_t(int, i, (prandom_u32() & 7) * 2);
> +	i =3D max_t(int, i, prandom_u32_max(8) * 2);
>  	WRITE_ONCE(table_perturb[index], READ_ONCE(table_perturb[index]) + i + =
2);
> =20
>  	/* Head lock still held and bh's disabled */
> diff --git a/net/sunrpc/cache.c b/net/sunrpc/cache.c
> index c3c693b51c94..f075a9fb5ccc 100644
> --- a/net/sunrpc/cache.c
> +++ b/net/sunrpc/cache.c
> @@ -677,7 +677,7 @@ static void cache_limit_defers(void)
> =20
>  	/* Consider removing either the first or the last */
>  	if (cache_defer_cnt > DFR_MAX) {
> -		if (prandom_u32() & 1)
> +		if (prandom_u32_max(2))
>  			discard =3D list_entry(cache_defer_list.next,
>  					     struct cache_deferred_req, recent);
>  		else
> diff --git a/net/sunrpc/xprtsock.c b/net/sunrpc/xprtsock.c
> index e976007f4fd0..c2caee703d2c 100644
> --- a/net/sunrpc/xprtsock.c
> +++ b/net/sunrpc/xprtsock.c
> @@ -1619,7 +1619,7 @@ static int xs_get_random_port(void)
>  	if (max < min)
>  		return -EADDRINUSE;
>  	range =3D max - min + 1;
> -	rand =3D (unsigned short) prandom_u32() % range;
> +	rand =3D (unsigned short) prandom_u32_max(range);
>  	return rand + min;
>  }
> =20
> --=20
> 2.37.3
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0CXYjV8qMpJxxBa%40magnolia.
