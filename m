Return-Path: <kasan-dev+bncBCC3ZNHOZYKRBPMHWWNAMGQEP7TBNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5709A600E56
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 13:59:59 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id h8-20020a056e021b8800b002f9c2e31750sf8797058ili.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 04:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666007998; cv=pass;
        d=google.com; s=arc-20160816;
        b=wrELGTpKhMnVd1gWPz5RssVHh+1m/wmnXrCxHUd2JSINxWo8hSNKPTZAxW3iUWWkxk
         VPDGviKEtAGBkAeYevpTuRAC7j+7W+bzc0VbEhhM94iSnnfvseAKHqfxUuBOfr0jdasP
         31745rsM+aBdu4MR1DKy28kqnw7GzEq4cCgGRjjocgAN46+IWTqQh6IA++A5zHSYznoC
         vcnjyER2Iytulcmi/qRmBn/hgNjlIG4rj+tCv35AfRSxNzfl38wedaY8rdf0hfWluYu1
         ofHvR87RqKX8Pw+5vGM7RyC8W1kaEEVBnvZAofGznANayE8kST4E7yUq1wo24oCLL7+J
         uTxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:dkim-signature;
        bh=qriqVPhTeM7vf8Ee52OW/IhnUfirIgkSL3P+HF3w14o=;
        b=Qm2JB1kSlufYCFk4aTcemcKdqwXgRB/NQePKGXwc3AZStqS52EJwZUJs1f68oH4o4H
         ypyHwv/prBSulrO2A6oHVhhnEmNrtDXvkKfOwKThY2VmzqjfDuAOATZDticH5oP2KHor
         x144e6ZY+Psuef2/fAoc+6AY92TRvej+s99/6Y/p/RxtanjgUCUmJrgPa7yi0tcmfwbj
         EhJNme89QD7Cx+pTTF6WfMcjTRPV+iAIpLqsvkZyKor8DVaQKaRmEZ+4yqQEudAmyz9h
         BgaVkuXEwabiyE1jg1c91sXCSLPEyXNmrAiej5WOO8T3R8G6hSrVXPANRt3U9W3FkqSc
         sEXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liulongfang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liulongfang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qriqVPhTeM7vf8Ee52OW/IhnUfirIgkSL3P+HF3w14o=;
        b=TjX61fAVCiWXxTdeDbLcacfVCbXiamfVgzovgqRQ0jq0up7WPWW6R1iKfDzMvOaFg6
         HZajYa8IMnxer4P28toz5IH5KQhDhuB3erl+GUe6Gdx/ddyvLtea4H5ZGrXGEW/y4fur
         bzIC5QWWA/L/anlbRbADPpzkuvH3ZzhDyUyWPVHf2q7bae80AWBmNY3pptWmP33EL18k
         Y9L3kaAwGy2SbWruoo8Asc3js5T8HU3EmyAf7O3nulUDA5bCtO6YAEwLS27O++kQMAcw
         SFv3ARPOnqnZa+8a6nymjvEaGzAdGVbyy2CTughDiq6gQutWe2f1+76r7JpFjAV2sw+g
         R4tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qriqVPhTeM7vf8Ee52OW/IhnUfirIgkSL3P+HF3w14o=;
        b=eIS1dd0e7df664xPAUxLDPhkcs8MSR+fhPudFpgdVrBLllXoMVn3S6Cjk94AqGOTYI
         8uQ3L7PtgdFLBfi0/zt3qZyqX/p58oAKLuTxz3ZIo7U49ZjqbsPC5WbfKOhwDgciSepP
         N3ANnYzlhqwYltSw4s6zgE0B0Vdzwf90mRyxjmduOVk2J7NMFUvmYgsso+IotWiPJtm3
         PTha0GcXbrUq+JlqK7syMBJmVfH1UdmNuEaow4OvZWCRICPRjRPh6Mb7COjqZ3n4h/Nj
         z25ZdhLlXILgFBReSben7hucgIStVWwLz4yXrbp2YPFw9lAmCkORCw9bPRm66lkYMm7I
         qHYQ==
X-Gm-Message-State: ACrzQf0Uz5huSzIIvS0tigTJzy/2/Qp8L50PgmgaTNgyxJeQGlW5YlOb
	xUR97nJLk2UZX2qlpoF2zvU=
X-Google-Smtp-Source: AMsMyM6vuDhBuFu/CWyneu717j5OahhZJSKFa0zjXCrgTkwpkUFsi1tvKtDHvXnelphyoIl3a3KKig==
X-Received: by 2002:a05:6e02:190a:b0:2fc:55a4:c64a with SMTP id w10-20020a056e02190a00b002fc55a4c64amr4558323ilu.132.1666007997867;
        Mon, 17 Oct 2022 04:59:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:85ad:0:b0:363:bee0:a7d0 with SMTP id d42-20020a0285ad000000b00363bee0a7d0ls2617942jai.7.-pod-prod-gmail;
 Mon, 17 Oct 2022 04:59:57 -0700 (PDT)
X-Received: by 2002:a05:6638:31c2:b0:35a:c5b1:b567 with SMTP id n2-20020a05663831c200b0035ac5b1b567mr4756658jav.58.1666007997430;
        Mon, 17 Oct 2022 04:59:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666007997; cv=none;
        d=google.com; s=arc-20160816;
        b=zAFamG3MapNouqOXTpnStmiKllI4vL7DMkMUoElN+R08LrBOMefW5/RoCTScqjdBz1
         7vKjOFKBWwM9wkxA5JCd3/LyrkqpCDuy6S/RdhRWIcOORd/Z5WRGzuwv3Ae4fk+3plWa
         7GhCGz5FcVrepbEAStR6Kz0Cn/rngXsIAMelo7mKEuBy3GdniFzYB/Yli3HMxPgXe/uE
         1TS8z++XY0sxpSs6dwKlmEKkYPNRA4WUoxuGw8rBl7QIt5WPwcCHNk/ObYuy03tu+mwv
         FjP6/vaotFVHKz4hmS2ve5+RarvbI+Ntj8ywbg6c51qZl0V6hTERlRVl9ILBUh4D3+fJ
         49SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject;
        bh=rLsUWuG673r5ithdF00cJV0y6ETj5LEmPPhl44cZhb8=;
        b=BzDppzVC+XyvB7GGIx0g+J46Dj3iBg0qh+mlckYl6BrlycmQDqZov68LcZK0g/DKKz
         McwffBkjApsofsVza6FcewGJ12jMt4dSlhhQMIZQPcufG8GV8FdNeiRnoPT1EvcFh01d
         9g+4RBPGL3sgoZ2pGrhBDY1r5ARQvdavh1xLfcDGnGSrZ5Z4NJDG4Itai534W5WRHC16
         LTmv20bzhPwjozDNWkZTVolTtBPOAFiu4Ew1g4aygbFc1Mgc4UWpPpnWobA+UH0+CSGi
         RH51Ye0ucy0IhnMfuZYfmC2TRZIMNFWSGtA+F9TYN+BCRcmHrEegFvTw5nk1t7QLxnKj
         1+ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liulongfang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liulongfang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id r13-20020a5e950d000000b00688fefa6d1dsi429123ioj.2.2022.10.17.04.59.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Oct 2022 04:59:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of liulongfang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4Mrb7T71GfzpW32;
	Mon, 17 Oct 2022 19:56:37 +0800 (CST)
Received: from kwepemm600005.china.huawei.com (7.193.23.191) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 17 Oct 2022 19:59:34 +0800
Received: from [10.67.103.158] (10.67.103.158) by
 kwepemm600005.china.huawei.com (7.193.23.191) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 17 Oct 2022 19:59:31 +0800
Subject: Re: [PATCH v6 0/7] treewide cleanup of random integer usage
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, <linux-kernel@vger.kernel.org>,
	<patches@lists.linux.dev>
CC: Andreas Noever <andreas.noever@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, "Catalin
 Marinas" <catalin.marinas@arm.com>, =?UTF-8?Q?Christoph_B=c3=b6hmwalder?=
	<christoph.boehmwalder@linbit.com>, Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>, Daniel Borkmann
	<daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, Dave Hansen
	<dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>,
	"Eric Dumazet" <edumazet@google.com>, Florian Westphal <fw@strlen.de>, "Greg
 Kroah-Hartman" <gregkh@linuxfoundation.org>, "H . Peter Anvin"
	<hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>, Helge Deller
	<deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen
	<chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>, Jakub Kicinski
	<kuba@kernel.org>, "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara
	<jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe
	<axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet
	<corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh
	<kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>, Marco Elver
	<elver@google.com>, Mauro Carvalho Chehab <mchehab@kernel.org>, "Michael
 Ellerman" <mpe@ellerman.id.au>, Pablo Neira Ayuso <pablo@netfilter.org>,
	"Paolo Abeni" <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>,
	"Richard Weinberger" <richard@nod.at>, Russell King <linux@armlinux.org.uk>,
	"Theodore Ts'o" <tytso@mit.edu>, Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>, "Thomas Gleixner" <tglx@linutronix.de>, Thomas
 Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, Vignesh
 Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, Will Deacon
	<will@kernel.org>, Yury Norov <yury.norov@gmail.com>,
	<dri-devel@lists.freedesktop.org>, <kasan-dev@googlegroups.com>,
	<kernel-janitors@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-block@vger.kernel.org>, <linux-crypto@vger.kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-fsdevel@vger.kernel.org>,
	<linux-media@vger.kernel.org>, <linux-mips@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-mmc@vger.kernel.org>,
	<linux-mtd@lists.infradead.org>, <linux-nvme@lists.infradead.org>,
	<linux-parisc@vger.kernel.org>, <linux-rdma@vger.kernel.org>,
	<linux-s390@vger.kernel.org>, <linux-um@lists.infradead.org>,
	<linux-usb@vger.kernel.org>, <linux-wireless@vger.kernel.org>,
	<linuxppc-dev@lists.ozlabs.org>, <loongarch@lists.linux.dev>,
	<netdev@vger.kernel.org>, <sparclinux@vger.kernel.org>, <x86@kernel.org>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
From: "'liulongfang' via kasan-dev" <kasan-dev@googlegroups.com>
Message-ID: <8dad6a2c-9ef6-086e-0fb0-cd9115d4faca@huawei.com>
Date: Mon, 17 Oct 2022 19:59:30 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20221010230613.1076905-1-Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.67.103.158]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemm600005.china.huawei.com (7.193.23.191)
X-CFilter-Loop: Reflected
X-Original-Sender: liulongfang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liulongfang@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liulongfang@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: liulongfang <liulongfang@huawei.com>
Reply-To: liulongfang <liulongfang@huawei.com>
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

On 2022/10/11 7:06, Jason A. Donenfeld Wrote:
> Changes v5->v6:
> - Added a few missing conversions that weren't in my older tree, so now
>   this should be ready to go, as well as a couple nits people had from
>   v5. Barring something large and unforeseen, this is the "final
>   version", as this is ready to ship. Thanks to everyone who reviewed
>   this.
>=20
> Hi folks,
>=20
> This is a five part treewide cleanup of random integer handling. The
> rules for random integers are:
>=20
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
>=20
> These rules ought to be applied uniformly, so that we can clean up the
> deprecated functions, and earn the benefits of using the modern
> functions. In particular, in addition to the boring substitutions, this
> patchset accomplishes a few nice effects:
>=20
> - By using prandom_u32_max() with an upper-bound that the compiler can
>   prove at compile-time is =E2=89=A465536 or =E2=89=A4256, internally get=
_random_u16()
>   or get_random_u8() is used, which wastes fewer batched random bytes,
>   and hence has higher throughput.
>=20
> - By using prandom_u32_max() instead of %, when the upper-bound is not a
>   constant, division is still avoided, because prandom_u32_max() uses
>   a faster multiplication-based trick instead.
>=20
> - By using get_random_u16() or get_random_u8() in cases where the return
>   value is intended to indeed be a u16 or a u8, we waste fewer batched
>   random bytes, and hence have higher throughput.
>=20
> So, based on those rules and benefits from following them, this patchset
> breaks down into the following five steps:
>=20
> 1) Replace `prandom_u32() % max` and variants thereof with
>    prandom_u32_max(max).
>=20
>    * Part 1 is done with Coccinelle. Part 2 is done by hand.
>=20
> 2) Replace `(type)get_random_u32()` and variants thereof with
>    get_random_u16() or get_random_u8(). I took the pains to actually
>    look and see what every lvalue type was across the entire tree.
>=20
>    * Part 1 is done with Coccinelle. Part 2 is done by hand.
>=20
> 3) Replace remaining deprecated uses of prandom_u32() and
>    get_random_int() with get_random_u32().=20
>=20
>    * A boring search and replace operation.
>=20
> 4) Replace remaining deprecated uses of prandom_bytes() with
>    get_random_bytes().
>=20
>    * A boring search and replace operation.
>=20
> 5) Remove the deprecated and now-unused prandom_u32() and
>    prandom_bytes() inline wrapper functions.
>=20
>    * Just deleting code and updating comments.
>=20
> I'll be sending this toward the end of the 6.1 merge window via the
> random.git tree.
>=20
> Please take a look! The number of lines touched is quite small, so this
> should be reviewable, and as much as is possible has been pushed into
> Coccinelle scripts.
>=20
> Thanks,
> Jason
>=20
> Cc: Andreas Noever <andreas.noever@gmail.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com>
> Cc: Christoph Hellwig <hch@lst.de>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Daniel Borkmann <daniel@iogearbox.net>
> Cc: Dave Airlie <airlied@redhat.com>
> Cc: Dave Hansen <dave.hansen@linux.intel.com>
> Cc: David S. Miller <davem@davemloft.net>
> Cc: Eric Dumazet <edumazet@google.com>
> Cc: Florian Westphal <fw@strlen.de>
> Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
> Cc: H. Peter Anvin <hpa@zytor.com>
> Cc: Heiko Carstens <hca@linux.ibm.com>
> Cc: Helge Deller <deller@gmx.de>
> Cc: Herbert Xu <herbert@gondor.apana.org.au>
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: Hugh Dickins <hughd@google.com>
> Cc: Jakub Kicinski <kuba@kernel.org>
> Cc: James E.J. Bottomley <jejb@linux.ibm.com>
> Cc: Jan Kara <jack@suse.com>
> Cc: Jason Gunthorpe <jgg@ziepe.ca>
> Cc: Jens Axboe <axboe@kernel.dk>
> Cc: Johannes Berg <johannes@sipsolutions.net>
> Cc: Jonathan Corbet <corbet@lwn.net>
> Cc: Jozsef Kadlecsik <kadlec@netfilter.org>
> Cc: KP Singh <kpsingh@kernel.org>
> Cc: Kees Cook <keescook@chromium.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Mauro Carvalho Chehab <mchehab@kernel.org>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Pablo Neira Ayuso <pablo@netfilter.org>
> Cc: Paolo Abeni <pabeni@redhat.com>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Richard Weinberger <richard@nod.at>
> Cc: Russell King <linux@armlinux.org.uk>
> Cc: Theodore Ts'o <tytso@mit.edu>
> Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Thomas Graf <tgraf@suug.ch>
> Cc: Ulf Hansson <ulf.hansson@linaro.org>
> Cc: Vignesh Raghavendra <vigneshr@ti.com>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Will Deacon <will@kernel.org>
> Cc: Yury Norov <yury.norov@gmail.com>
> Cc: dri-devel@lists.freedesktop.org
> Cc: kasan-dev@googlegroups.com
> Cc: kernel-janitors@vger.kernel.org
> Cc: linux-arm-kernel@lists.infradead.org
> Cc: linux-block@vger.kernel.org
> Cc: linux-crypto@vger.kernel.org
> Cc: linux-doc@vger.kernel.org
> Cc: linux-fsdevel@vger.kernel.org
> Cc: linux-media@vger.kernel.org
> Cc: linux-mips@vger.kernel.org
> Cc: linux-mm@kvack.org
> Cc: linux-mmc@vger.kernel.org
> Cc: linux-mtd@lists.infradead.org
> Cc: linux-nvme@lists.infradead.org
> Cc: linux-parisc@vger.kernel.org
> Cc: linux-rdma@vger.kernel.org
> Cc: linux-s390@vger.kernel.org
> Cc: linux-um@lists.infradead.org
> Cc: linux-usb@vger.kernel.org
> Cc: linux-wireless@vger.kernel.org
> Cc: linuxppc-dev@lists.ozlabs.org
> Cc: loongarch@lists.linux.dev
> Cc: netdev@vger.kernel.org
> Cc: sparclinux@vger.kernel.org
> Cc: x86@kernel.org
>=20
> Jason A. Donenfeld (7):
>   treewide: use prandom_u32_max() when possible, part 1
>   treewide: use prandom_u32_max() when possible, part 2
>   treewide: use get_random_{u8,u16}() when possible, part 1
>   treewide: use get_random_{u8,u16}() when possible, part 2
>   treewide: use get_random_u32() when possible
>   treewide: use get_random_bytes() when possible
>   prandom: remove unused functions
>=20
>  Documentation/networking/filter.rst           |  2 +-
>  arch/arm/kernel/process.c                     |  2 +-
>  arch/arm/kernel/signal.c                      |  2 +-
>  arch/arm64/kernel/process.c                   |  2 +-
>  arch/arm64/kernel/syscall.c                   |  2 +-
>  arch/loongarch/kernel/process.c               |  2 +-
>  arch/loongarch/kernel/vdso.c                  |  2 +-
>  arch/mips/kernel/process.c                    |  2 +-
>  arch/mips/kernel/vdso.c                       |  2 +-
>  arch/parisc/kernel/process.c                  |  2 +-
>  arch/parisc/kernel/sys_parisc.c               |  4 +-
>  arch/parisc/kernel/vdso.c                     |  2 +-
>  arch/powerpc/crypto/crc-vpmsum_test.c         |  2 +-
>  arch/powerpc/kernel/process.c                 |  2 +-
>  arch/s390/kernel/process.c                    |  4 +-
>  arch/s390/kernel/vdso.c                       |  2 +-
>  arch/s390/mm/mmap.c                           |  2 +-
>  arch/sparc/vdso/vma.c                         |  2 +-
>  arch/um/kernel/process.c                      |  2 +-
>  arch/x86/entry/vdso/vma.c                     |  2 +-
>  arch/x86/kernel/cpu/amd.c                     |  2 +-
>  arch/x86/kernel/module.c                      |  2 +-
>  arch/x86/kernel/process.c                     |  2 +-
>  arch/x86/mm/pat/cpa-test.c                    |  4 +-
>  block/blk-crypto-fallback.c                   |  2 +-
>  crypto/async_tx/raid6test.c                   |  2 +-
>  crypto/testmgr.c                              | 94 +++++++++----------
>  drivers/block/drbd/drbd_receiver.c            |  4 +-
>  drivers/char/random.c                         | 11 +--
>  drivers/dma/dmatest.c                         |  2 +-
>  .../gpu/drm/i915/gem/i915_gem_execbuffer.c    |  2 +-
>  drivers/gpu/drm/i915/i915_gem_gtt.c           |  6 +-
>  .../gpu/drm/i915/selftests/i915_selftest.c    |  2 +-
>  drivers/gpu/drm/tests/drm_buddy_test.c        |  2 +-
>  drivers/gpu/drm/tests/drm_mm_test.c           |  2 +-
>  drivers/infiniband/core/cma.c                 |  2 +-
>  drivers/infiniband/hw/cxgb4/cm.c              |  4 +-
>  drivers/infiniband/hw/cxgb4/id_table.c        |  4 +-
>  drivers/infiniband/hw/hfi1/tid_rdma.c         |  2 +-
>  drivers/infiniband/hw/hns/hns_roce_ah.c       |  5 +-
>  drivers/infiniband/hw/mlx4/mad.c              |  2 +-
>  drivers/infiniband/ulp/ipoib/ipoib_cm.c       |  2 +-
>  drivers/infiniband/ulp/rtrs/rtrs-clt.c        |  3 +-
>  drivers/md/bcache/request.c                   |  2 +-
>  drivers/md/raid5-cache.c                      |  2 +-
>  drivers/media/common/v4l2-tpg/v4l2-tpg-core.c |  2 +-
>  .../media/test-drivers/vivid/vivid-radio-rx.c |  4 +-
>  .../test-drivers/vivid/vivid-touch-cap.c      |  6 +-
>  drivers/misc/habanalabs/gaudi2/gaudi2.c       |  2 +-
>  drivers/mmc/core/core.c                       |  4 +-
>  drivers/mmc/host/dw_mmc.c                     |  2 +-
>  drivers/mtd/nand/raw/nandsim.c                |  8 +-
>  drivers/mtd/tests/mtd_nandecctest.c           | 12 +--
>  drivers/mtd/tests/speedtest.c                 |  2 +-
>  drivers/mtd/tests/stresstest.c                | 19 +---
>  drivers/mtd/ubi/debug.c                       |  2 +-
>  drivers/mtd/ubi/debug.h                       |  6 +-
>  drivers/net/bonding/bond_main.c               |  2 +-
>  drivers/net/ethernet/broadcom/bnxt/bnxt.c     |  2 +-
>  drivers/net/ethernet/broadcom/cnic.c          |  5 +-
>  .../chelsio/inline_crypto/chtls/chtls_cm.c    |  4 +-
>  .../chelsio/inline_crypto/chtls/chtls_io.c    |  4 +-
>  drivers/net/ethernet/rocker/rocker_main.c     |  8 +-
>  drivers/net/hamradio/baycom_epp.c             |  2 +-
>  drivers/net/hamradio/hdlcdrv.c                |  2 +-
>  drivers/net/hamradio/yam.c                    |  2 +-
>  drivers/net/phy/at803x.c                      |  2 +-
>  drivers/net/wireguard/selftest/allowedips.c   | 16 ++--
>  .../broadcom/brcm80211/brcmfmac/p2p.c         |  2 +-
>  .../broadcom/brcm80211/brcmfmac/pno.c         |  2 +-
>  .../net/wireless/intel/iwlwifi/mvm/mac-ctxt.c |  2 +-
>  .../net/wireless/marvell/mwifiex/cfg80211.c   |  4 +-
>  .../wireless/microchip/wilc1000/cfg80211.c    |  2 +-
>  .../net/wireless/quantenna/qtnfmac/cfg80211.c |  2 +-
>  drivers/net/wireless/st/cw1200/wsm.c          |  2 +-
>  drivers/net/wireless/ti/wlcore/main.c         |  2 +-
>  drivers/nvme/common/auth.c                    |  2 +-
>  drivers/scsi/cxgbi/cxgb4i/cxgb4i.c            |  4 +-
>  drivers/scsi/fcoe/fcoe_ctlr.c                 |  4 +-
>  drivers/scsi/lpfc/lpfc_hbadisc.c              |  6 +-
>  drivers/scsi/qedi/qedi_main.c                 |  2 +-
>  drivers/target/iscsi/cxgbit/cxgbit_cm.c       |  2 +-
>  drivers/thunderbolt/xdomain.c                 |  2 +-
>  drivers/video/fbdev/uvesafb.c                 |  2 +-
>  fs/ceph/inode.c                               |  2 +-
>  fs/ceph/mdsmap.c                              |  2 +-
>  fs/exfat/inode.c                              |  2 +-
>  fs/ext2/ialloc.c                              |  3 +-
>  fs/ext4/ialloc.c                              |  7 +-
>  fs/ext4/ioctl.c                               |  4 +-
>  fs/ext4/mmp.c                                 |  2 +-
>  fs/ext4/super.c                               |  7 +-
>  fs/f2fs/gc.c                                  |  2 +-
>  fs/f2fs/namei.c                               |  2 +-
>  fs/f2fs/segment.c                             |  8 +-
>  fs/fat/inode.c                                |  2 +-
>  fs/nfsd/nfs4state.c                           |  4 +-
>  fs/ntfs3/fslog.c                              |  6 +-
>  fs/ubifs/debug.c                              | 10 +-
>  fs/ubifs/journal.c                            |  2 +-
>  fs/ubifs/lpt_commit.c                         | 14 +--
>  fs/ubifs/tnc_commit.c                         |  2 +-
>  fs/xfs/libxfs/xfs_alloc.c                     |  2 +-
>  fs/xfs/libxfs/xfs_ialloc.c                    |  4 +-
>  fs/xfs/xfs_error.c                            |  2 +-
>  fs/xfs/xfs_icache.c                           |  2 +-
>  fs/xfs/xfs_log.c                              |  2 +-
>  include/linux/nodemask.h                      |  2 +-
>  include/linux/prandom.h                       | 12 ---
>  include/linux/random.h                        |  5 -
>  include/net/netfilter/nf_queue.h              |  2 +-
>  include/net/red.h                             |  2 +-
>  include/net/sock.h                            |  2 +-
>  kernel/bpf/bloom_filter.c                     |  2 +-
>  kernel/bpf/core.c                             |  6 +-
>  kernel/bpf/hashtab.c                          |  2 +-
>  kernel/bpf/verifier.c                         |  2 +-
>  kernel/kcsan/selftest.c                       |  4 +-
>  kernel/locking/test-ww_mutex.c                |  4 +-
>  kernel/time/clocksource.c                     |  2 +-
>  lib/cmdline_kunit.c                           |  4 +-
>  lib/fault-inject.c                            |  2 +-
>  lib/find_bit_benchmark.c                      |  4 +-
>  lib/kobject.c                                 |  2 +-
>  lib/random32.c                                |  4 +-
>  lib/reed_solomon/test_rslib.c                 | 12 +--
>  lib/sbitmap.c                                 |  4 +-
>  lib/test-string_helpers.c                     |  2 +-
>  lib/test_fprobe.c                             |  2 +-
>  lib/test_hexdump.c                            | 10 +-
>  lib/test_kasan.c                              |  6 +-
>  lib/test_kprobes.c                            |  2 +-
>  lib/test_list_sort.c                          |  2 +-
>  lib/test_min_heap.c                           |  6 +-
>  lib/test_objagg.c                             |  2 +-
>  lib/test_rhashtable.c                         |  6 +-
>  lib/test_vmalloc.c                            | 19 +---
>  lib/uuid.c                                    |  2 +-
>  mm/migrate.c                                  |  2 +-
>  mm/shmem.c                                    |  2 +-
>  mm/slab.c                                     |  2 +-
>  mm/slub.c                                     |  2 +-
>  net/802/garp.c                                |  2 +-
>  net/802/mrp.c                                 |  2 +-
>  net/ceph/mon_client.c                         |  2 +-
>  net/ceph/osd_client.c                         |  2 +-
>  net/core/neighbour.c                          |  2 +-
>  net/core/pktgen.c                             | 47 +++++-----
>  net/core/stream.c                             |  2 +-
>  net/dccp/ipv4.c                               |  4 +-
>  net/ipv4/datagram.c                           |  2 +-
>  net/ipv4/igmp.c                               |  6 +-
>  net/ipv4/inet_connection_sock.c               |  2 +-
>  net/ipv4/inet_hashtables.c                    |  2 +-
>  net/ipv4/ip_output.c                          |  2 +-
>  net/ipv4/route.c                              |  4 +-
>  net/ipv4/tcp_cdg.c                            |  2 +-
>  net/ipv4/tcp_ipv4.c                           |  4 +-
>  net/ipv4/udp.c                                |  2 +-
>  net/ipv6/addrconf.c                           |  8 +-
>  net/ipv6/ip6_flowlabel.c                      |  2 +-
>  net/ipv6/mcast.c                              | 10 +-
>  net/ipv6/output_core.c                        |  2 +-
>  net/mac80211/rc80211_minstrel_ht.c            |  2 +-
>  net/mac80211/scan.c                           |  2 +-
>  net/netfilter/ipvs/ip_vs_conn.c               |  2 +-
>  net/netfilter/ipvs/ip_vs_twos.c               |  4 +-
>  net/netfilter/nf_nat_core.c                   |  4 +-
>  net/netfilter/xt_statistic.c                  |  2 +-
>  net/openvswitch/actions.c                     |  2 +-
>  net/packet/af_packet.c                        |  2 +-
>  net/rds/bind.c                                |  2 +-
>  net/sched/act_gact.c                          |  2 +-
>  net/sched/act_sample.c                        |  2 +-
>  net/sched/sch_cake.c                          |  8 +-
>  net/sched/sch_netem.c                         | 22 ++---
>  net/sched/sch_pie.c                           |  2 +-
>  net/sched/sch_sfb.c                           |  2 +-
>  net/sctp/socket.c                             |  4 +-
>  net/sunrpc/auth_gss/gss_krb5_wrap.c           |  4 +-
>  net/sunrpc/cache.c                            |  2 +-
>  net/sunrpc/xprt.c                             |  2 +-
>  net/sunrpc/xprtsock.c                         |  2 +-
>  net/tipc/socket.c                             |  2 +-
>  net/unix/af_unix.c                            |  2 +-
>  net/xfrm/xfrm_state.c                         |  2 +-
>  186 files changed, 379 insertions(+), 422 deletions(-)
>=20

Hi, Jason:

There is a lot of code using "prandom_u32 % 4" in crypto's kernel self-test=
 file testmgr.c,
can you modify it together?

Thanks,
Longfang.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8dad6a2c-9ef6-086e-0fb0-cd9115d4faca%40huawei.com.
