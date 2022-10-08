Return-Path: <kasan-dev+bncBC4Y5GGK74JBBSG5Q6NAMGQE3BATDSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D6AFD5F8780
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 23:42:33 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id jn13-20020ad45ded000000b004b1d055fbc7sf4635911qvb.2
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 14:42:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665265352; cv=pass;
        d=google.com; s=arc-20160816;
        b=kjPh3kV+GJhdY4SJL7tQjRdenRy6n0bBMbEYxrlJ1xy7GU+1n30NCG+b53WAoROIVm
         yainqzVKb2330boLrzFVhDOrBiLxItx6e8H+hEdmLaa4EpSGE1k4pGONJcafptHwfCr7
         Ms/AlRohWP6117/XlzTKdUpDjTwLoPEDQEdhRPLTUxg+l48FXcb8Su6owHCmlMvhvrqJ
         f1FYkb6oj1HMzomqnHA255e84Rcdf2cT/mWF+SUtene0y/PQ8WY/kdsXtVbbqNmqqBQ2
         IG2u8Itvkm/Ll6Eps1pzwsWcoouVkU7gr2qnVImCy/0gqc6bPfAhhgHs/S4yqswSgZ9o
         k7jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=lrVpNUHj/7jbfOaj5w5GV0mjqZlDCy+4LJywYuzFRMc=;
        b=W+rGtqORtr6LcOQYLeIyPJBkjSHkCKHZvo/Tvntx4LSyLsFEeuuR1awXh/ZhkRlbZZ
         oBExdsgAadQWEqBBUP842sol1zq0g4241LQPXIA/jgA+owrfuPc6Ul5cHBqZRhsoK78O
         00s0Roc/CyY9/9eez4d/VSxHeNHtTFEQt+5qm4fHW5fMbfs96yzzHa4gnLFdGhh6uzoH
         97h/AabRdMJIMrg35Ir15y2JEXHKFLmE7TIRyr01gD2JtMWxIZkH+VryZLKsV8jvfLYb
         F3I6twS5rHl6in1YvtkW5k3ql0O2kaHM2+mDZ0giAbmOicLRPhXqUKGoEF9ygQqpWARz
         lZpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EumsjgKw;
       spf=pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=yury.norov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lrVpNUHj/7jbfOaj5w5GV0mjqZlDCy+4LJywYuzFRMc=;
        b=MivXg/hrvBeZZ8t0pM2hWAqLAEPg151Vi4ZpZ58fkUSj2lJqlj8v11yrrajkxzTN7r
         tWVJQMh9yfuQn/sOjfLQV3TEWypiAHhmH1SDdVJIU5m7CEjPSU5BhxO2ZnRpmn/S2ppJ
         LP2NdxKBEA2qLp75dOXxT2buX46cun9HLBCKnSxb4zXEy3IRvsVK9gCUJb5tY35Nj5vR
         Rb2Tz/q2y6YivDpdrv+A5t3qr88cLndY9RMFeE1nJACbcLe7HGujueEcpX6d5JL2/uvW
         zKllUMwvK1KtKF/qcaY2I2YvWljiYaZbnvnjWQhmryxLqtY67IDqbLtQHcYI3Ot3utAu
         xV+Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lrVpNUHj/7jbfOaj5w5GV0mjqZlDCy+4LJywYuzFRMc=;
        b=QMtjrQ9DCSRgPSezrDDHjwwcXhIk1I1VgzDX6IZQscQgKrN0EdKAl8SsLKKFPCeSlY
         t6F3IcrPVMAqxh7NvGQic3eUGDVSm5BLwseZmjYtQ/8uDSqg8P1C37dPD47UBftW3RUI
         VqEtzN+Sj4r3Goo900V0kuXf45rJaGAtHqJ8Sfohw86abixs2dKg+KgWOFuyDSJTgpa+
         7GTKKZ2dtCp9f836kbq7o9HkVQSJ8mInlJpwLuNB0QUxjFd4v2WquYYWfi9fqVYxhKbr
         JUkIt+WkcRND6VyffZyYvPHmYyKck3jdRwa5YWW74MUbEtlgyVTQWnTnjHT/T63Ndzp2
         9fDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lrVpNUHj/7jbfOaj5w5GV0mjqZlDCy+4LJywYuzFRMc=;
        b=8Npsms0CBm1zLW4Qj46tPcWabBTmsLLsa8LEGwGOP7oAOcqW/QFKsJA31WDTgy1f6v
         dNHkqEayOU/YFzeeqnAK4ETylZ9ygU05ITwj9x6mkEN8zVfVGVGW2+qul5ZccWRX4l5t
         5sC6CVhjQUT+ULaCIKNW9v34exwOV2m87fnZVsu+4L7bvRZO8beNt5Xo/TioevjMGv+2
         MnBLEHn11grnm4s29rPI/nGT/WUZ0+4jnUFmk9Cnq9zqhqvCH19JtDI9hXDNmEjem0rS
         H/dZCDwhl+2IzKY0W23ZQUFOn8oGbQ6CyjwL7JWr9sEDa+3/BQQLwOydXM0tK+NgjsAk
         sePA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0TM9YLWHPA6N6Ubcqcun48l9Bz7IDbilIRlTMMqi+dk5EXg/Kf
	5y5MgDPKRUl+Rtn9RxInLBc=
X-Google-Smtp-Source: AMsMyM71NVwdufc85K2RkopBm1gan75VDW9OAZp3MjgpAtkNwli6H6aYv2bN68UzfFa1LjZXkVtv1A==
X-Received: by 2002:ad4:4eed:0:b0:4b1:89ce:2c6b with SMTP id dv13-20020ad44eed000000b004b189ce2c6bmr9581134qvb.91.1665265352604;
        Sat, 08 Oct 2022 14:42:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8d83:0:b0:4aa:5803:b529 with SMTP id t3-20020a0c8d83000000b004aa5803b529ls3997282qvb.5.-pod-prod-gmail;
 Sat, 08 Oct 2022 14:42:32 -0700 (PDT)
X-Received: by 2002:a0c:a79a:0:b0:4b1:ca99:177 with SMTP id v26-20020a0ca79a000000b004b1ca990177mr9265213qva.34.1665265352040;
        Sat, 08 Oct 2022 14:42:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665265352; cv=none;
        d=google.com; s=arc-20160816;
        b=DFxe960NT8rBfGo39+2MwpS8i6+7jeenOfTQv/t2o7obQVH41b53LxZv5eNFrwQdf3
         A26x4NffWdfMJ4URZPqPV6tcKoKbqx26kTbzN0m5AQUeo7gbw7NDbby64HPBFmbRiOCy
         gDYap17z2Mfh5nF+t95FHmKiFUNNh7hFBq0BQSHYQ+2TjaqtI02Pq3Bu+/ZBu+E485PT
         K47IzDXiFvvPNqlPHFN7IvHbdRHGMEsxJ8Klh663dAoQ7Lx3zO96DCwWLbauJdWDu1kO
         DSjLQgdg2FSV55/og4qluumG51YUOTXMIB1x3lNxP4m0mwJ6DhBAZhHRJltLW1S6d9Hj
         +Fug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=XB90Z1qj3kPK5TTwJuNvzg1Gu7i5Rnz3wWrq9Xc3CzQ=;
        b=htm5AXJP13+/Ise6WZitPStmxrkgNAeSi3z9BNYvDAL4kvzA2ikj2MMnlXx2IM5MGu
         Ol/9dH0JcMNkqgfHnL7TVO+QoR30irFi2nqkh//1wRnM62hbbL69R0wpW3GwolpctDbk
         FhD5jMW7+9oE1STIoARPNFoKgBVFhzjetAvJ9AKE3xSyQCT0ePapDjFegz2dXbh/pgwX
         gd3O/7HGgUYWJockOy2grFuje8UPbwbq1daayzHNs4MHAPyw86VQUsQ0ijCYlDFicW0t
         c168xMrF4HZjOQghrzzD059C4E1J17yirLaSOQ/Su3SH+nR/SCpEXiH7MSJAUiMtdbdN
         nHWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EumsjgKw;
       spf=pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=yury.norov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id u29-20020a05620a085d00b006e9e77d2267si151118qku.5.2022.10.08.14.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Oct 2022 14:42:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id i3so4847924qkl.3
        for <kasan-dev@googlegroups.com>; Sat, 08 Oct 2022 14:42:32 -0700 (PDT)
X-Received: by 2002:a05:620a:46a4:b0:6ce:c4af:5a54 with SMTP id bq36-20020a05620a46a400b006cec4af5a54mr8239989qkb.377.1665265351668;
        Sat, 08 Oct 2022 14:42:31 -0700 (PDT)
Received: from localhost ([2601:4c1:c100:2270:4fea:6b67:9485:addd])
        by smtp.gmail.com with ESMTPSA id j1-20020a05620a410100b006cfaee39ccesm5821626qko.114.2022.10.08.14.42.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Oct 2022 14:42:31 -0700 (PDT)
Date: Sat, 8 Oct 2022 14:42:30 -0700
From: Yury Norov <yury.norov@gmail.com>
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
	dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
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
Message-ID: <Y0HuxsLysThhsaTl@yury-laptop>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
X-Original-Sender: yury.norov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=EumsjgKw;       spf=pass
 (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::72f
 as permitted sender) smtp.mailfrom=yury.norov@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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
> I was thinking of taking this through my random.git tree (on which this
> series is currently based) and submitting it near the end of the merge
> window, or waiting for the very end of the 6.1 cycle when there will be
> the fewest new patches brewing. If somebody with some treewide-cleanup
> experience might share some wisdom about what the best timing usually
> winds up being, I'm all ears.
>=20
> Please take a look! The number of lines touched is quite small, so this
> should be reviewable, and as much as is possible has been pushed into
> Coccinelle scripts.

For the series:
Reviewed-by: Yury Norov <yury.norov@gmail.com>

Although, looking at it, I have a feeling that kernel needs to drop all
fixed-size random APIs like get_random_uXX() or get_random_int(), because
people will continue using the 'get_random_int() % num' carelessly.

Thanks,
Yury

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0HuxsLysThhsaTl%40yury-laptop.
