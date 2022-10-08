Return-Path: <kasan-dev+bncBCLI747UVAFRBX5BQSNAMGQEHWQTQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B31B85F8340
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 07:55:44 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id bt23-20020a056512261700b004a1d87bd3e9sf1985204lfb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 22:55:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665208544; cv=pass;
        d=google.com; s=arc-20160816;
        b=eWOVtfwh9+XT/v+Zgk1+xMFzADtacWUtuTjaGIPWdh3qRiNZfw5a7+72g0z+xTn8rM
         P/foO+fIt5ZE/qfNnsSyk8/cfD0OeqZUHnnPd+2YWuhnK/irEJ6wGy3VQTtewovPQscP
         sSOegl7n1BH1jinophWx8vYj6Qbar1srmqjwL1UTwJ60zqyQqnAs0ZwARfvV6q72v0aG
         4oYS3Fg8jL22F3PzstQ3KwBvVERu+JI7M1uoTW24KJ9orUv/0EVdyyVIODGeoO/Ayp4D
         CysrCs2rGSdhtGeEbQO78+CFhkzRL4RTU2i3zUWXHsLH2NhaA6mqUVLEWKX2D0GD/J8b
         +Xhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=AeX9rLO4ynq2/Vn+0mQRlJLD9OegF24iVT+KwwLKC9M=;
        b=Iww6Ozxo6sf60mQVdP/iMu41nqIZ5YcfnUVHBDAD6t3/Ye3P0EaboU48W1r4gOTUKF
         UT/YBQDKQ9NSpAIOHOCMRSNj4+e+6xwIo75ndZm/XlFeYwwA2+UapveMdOvzsZ3t3/bs
         KhuYOMses0cdr98/set1LsJgVRQzOi4goD3A3qGE6IaGwnVnsbC8YLYUmv7dC1MDaOQN
         CapHKd5hWnAbqKYhgRof/HYqUphyvtAmHrtSndAPNGIst0bthi/RmCEEY23poiYeJLRl
         tZSHN6cT50cvrEtpfcg7GbcUy6BDvy0N+dJNU+RKJoVA3Qub9GkwKdC6JmZ+8a8aLDDZ
         1C7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=NOmHV9jd;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AeX9rLO4ynq2/Vn+0mQRlJLD9OegF24iVT+KwwLKC9M=;
        b=iZK0GPKfzadF/lJ0evgUX6BlqY7p4Tsfb/AqeLBZhWP1c94artlcDrJFSMqAJSo4Zq
         l9pawJ/wlZssOhs5xi+h4/QFj8KUicsQT8RpkLhsSU7+cm+cOIwCPTdaEUw3C1EkLs7D
         XzyKMH0T0Ft3LhMfPSLh3cz6haueT+JzPZ2+MC0TVsZ8t40jU1Y9l8fhS31wHQl/KrMQ
         Bfrdes72cu7lmxqG0t8VLnROUqt9oa+fgdwbWvIpDy7QktOSoYXyi2hCFPcVarZHqNX9
         E2nVGrkOibqzDQFq8uxOifQ04ccYc9J5wukcCzdgCYTjQTVuoS+emYtBC1g2cxp8N3fi
         8NOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AeX9rLO4ynq2/Vn+0mQRlJLD9OegF24iVT+KwwLKC9M=;
        b=FjxYK6IPvpX1PqGD0na8T5r+FesInPSFIrm6lcJK8Adh8SkcmDS1YBsWCmZkmHY5eM
         QluyLhOmfRzQb6Pdbl0Kn9ndOe4TvyDfdSbYpPoaVkaDLv8FC+BQk8hf6BTiu/xyvdpc
         fVa/7bc/il9g4W2nlhar6nM8Q07tWmYsjVfHkg5WihmKRAjKXGsO1V7/fckdKjICbKXO
         a3tFJFtXoU1ZfkcmZQBscuuAgPIbiiGav9mDAZEiXxSgZHu1KlvotK0qnaM3nKl7WcER
         17HYwbhvsPBp3YUWFM32m1V54MerFYu19s609+tPo3Yn3zC2dM1i9pmFTDTwkNENYgAc
         +jEg==
X-Gm-Message-State: ACrzQf0agJxQCgSglPupLGDTaijw6Ho60XXAKBZ2mNVDV47prEoPgN6n
	kLyyNCT0SUsLLNVKO0Ghn2Y=
X-Google-Smtp-Source: AMsMyM56GQYIJXO6l9TRUHDznXQhGWDMuWmsVp2z8Bp84FmEjmCspptR7HTdpWwgRBOAuHQLSHzKmQ==
X-Received: by 2002:a2e:be29:0:b0:26d:9825:abf8 with SMTP id z41-20020a2ebe29000000b0026d9825abf8mr2970948ljq.126.1665208544031;
        Fri, 07 Oct 2022 22:55:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3607:b0:48b:2227:7787 with SMTP id
 f7-20020a056512360700b0048b22277787ls2439262lfs.3.-pod-prod-gmail; Fri, 07
 Oct 2022 22:55:42 -0700 (PDT)
X-Received: by 2002:a05:6512:1154:b0:4a2:593c:9aa with SMTP id m20-20020a056512115400b004a2593c09aamr2848676lfg.96.1665208542341;
        Fri, 07 Oct 2022 22:55:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665208542; cv=none;
        d=google.com; s=arc-20160816;
        b=WfasWLNgdASuTA7u2+Xw0XApBvnLkgAbejbIXfhjL+dz6VYpQ9j8Q1ocIXJYfoY3Jt
         erzBkMNZYOqy2pKz98dwoRAjraHIDYv50xqFHUBVQl8zLxUxHsizRya6ymdPv6yiPPKN
         +Qvlmw97Kwog1MZT103Lvr/I0+E//Z8GhcbPq3RzSiizYkmM93xfXWADIkKUOapsv3Rt
         qvUn/cwQrkcQeMwM7wQuZeXNBL48bKeDM83fvanhkkyWLE01oAyTXtQgw4B4kPfS1ok+
         fGpAVsigqW9irG4Cr8XSfjGKRC/Xwm02JuCXBZrnYzvywL+Km0Az3Hck7vWUT+om3Kmr
         jk/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BFPsIDNo09sboNU1ww0bqjgGWYL2QJJRYRi+vjueqjc=;
        b=llkoTYXJlAj7VSjnGrq1agergBqpol0PZki1SnQqotx5M1Q9YzxZ8/GjnRvGeNo2nU
         a6gkvQWSnetrTXGqImahnXtGP7ECdN3sDwqqldgBQe2xEvoU59xU/pKVQFxJXGQ6MTe5
         SdW8Xp8qw2JyHjKuAwzZZ60TH1OeMJmMNUPAD9Nygmt+wMkwydLquTIBhvCv+/lM51YG
         jslnN3lpkREsQ3p+Pjip5oTmAwUxo/W4pe6aZunlDwJlXLXbOwjkrEjStR5G9AttfmoX
         rG0jUrV4mGF07VKWG8LjVhrPUvVfuC2uNgsT4RzFCm66iR6VYGVEbjLsQMSPhZWN+Qyp
         rCPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=NOmHV9jd;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id t12-20020a056512068c00b0048b38f379d7si154133lfe.0.2022.10.07.22.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 22:55:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8915AB81E4F;
	Sat,  8 Oct 2022 05:55:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 49061C4347C;
	Sat,  8 Oct 2022 05:55:34 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id a2c4a44c (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 05:55:32 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>,
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org,
	linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev,
	netdev@vger.kernel.org,
	sparclinux@vger.kernel.org,
	x86@kernel.org,
	=?UTF-8?q?Toke=20H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>
Subject: [PATCH v5 3/7] treewide: use get_random_{u8,u16}() when possible, part 1
Date: Fri,  7 Oct 2022 23:53:55 -0600
Message-Id: <20221008055359.286426-4-Jason@zx2c4.com>
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=NOmHV9jd;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
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

Rather than truncate a 32-bit value to a 16-bit value or an 8-bit value,
simply use the get_random_{u8,u16}() functions, which are faster than
wasting the additional bytes from a 32-bit value. This was done
mechanically with this coccinelle script:

@@
expression E;
identifier get_random_u32 =3D~ "get_random_int|prandom_u32|get_random_u32";
typedef u16;
typedef u8;
@@
(
- (get_random_u32() & 0xffff)
+ get_random_u16()
|
- (get_random_u32() & 0xff)
+ get_random_u8()
|
- (get_random_u32() % 65536)
+ get_random_u16()
|
- (get_random_u32() % 256)
+ get_random_u8()
|
- (get_random_u32() >> 16)
+ get_random_u16()
|
- (get_random_u32() >> 24)
+ get_random_u8()
|
- (u16)get_random_u32()
+ get_random_u16()
|
- (u8)get_random_u32()
+ get_random_u8()
|
- prandom_u32_max(65536)
+ get_random_u16()
|
- prandom_u32_max(256)
+ get_random_u8()
|
- E->inet_id =3D get_random_u32()
+ E->inet_id =3D get_random_u16()
)

@@
identifier get_random_u32 =3D~ "get_random_int|prandom_u32|get_random_u32";
typedef u16;
identifier v;
@@
- u16 v =3D get_random_u32();
+ u16 v =3D get_random_u16();

@@
identifier get_random_u32 =3D~ "get_random_int|prandom_u32|get_random_u32";
typedef u8;
identifier v;
@@
- u8 v =3D get_random_u32();
+ u8 v =3D get_random_u8();

// Find a potential literal
@literal_mask@
expression LITERAL;
type T;
identifier get_random_u32 =3D~ "get_random_int|prandom_u32|get_random_u32";
position p;
@@

        ((T)get_random_u32()@p & (LITERAL))

// Examine limits
@script:python add_one@
literal << literal_mask.LITERAL;
RESULT;
@@

value =3D None
if literal.startswith('0x'):
        value =3D int(literal, 16)
elif literal[0] in '123456789':
        value =3D int(literal, 10)
if value is None:
        print("I don't know how to handle %s" % (literal))
        cocci.include_match(False)
elif value < 256:
        coccinelle.RESULT =3D cocci.make_ident("get_random_u8")
elif value < 65536:
        coccinelle.RESULT =3D cocci.make_ident("get_random_u16")
else:
        print("Skipping large mask of %s" % (literal))
        cocci.include_match(False)

// Replace the literal mask with the calculated result.
@plus_one@
expression literal_mask.LITERAL;
position literal_mask.p;
identifier add_one.RESULT;
identifier FUNC;
@@

-       (FUNC()@p & (LITERAL))
+       (RESULT() & LITERAL)

Reviewed-by: Kees Cook <keescook@chromium.org>
Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cake
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 arch/arm/kernel/signal.c                                  | 2 +-
 arch/arm64/kernel/syscall.c                               | 2 +-
 crypto/testmgr.c                                          | 8 ++++----
 drivers/media/common/v4l2-tpg/v4l2-tpg-core.c             | 2 +-
 drivers/media/test-drivers/vivid/vivid-radio-rx.c         | 4 ++--
 .../net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c   | 2 +-
 drivers/net/hamradio/baycom_epp.c                         | 2 +-
 drivers/net/hamradio/hdlcdrv.c                            | 2 +-
 drivers/net/hamradio/yam.c                                | 2 +-
 drivers/net/wireguard/selftest/allowedips.c               | 4 ++--
 drivers/net/wireless/st/cw1200/wsm.c                      | 2 +-
 drivers/scsi/lpfc/lpfc_hbadisc.c                          | 6 +++---
 lib/cmdline_kunit.c                                       | 4 ++--
 net/dccp/ipv4.c                                           | 4 ++--
 net/ipv4/datagram.c                                       | 2 +-
 net/ipv4/tcp_ipv4.c                                       | 4 ++--
 net/mac80211/scan.c                                       | 2 +-
 net/sched/sch_cake.c                                      | 6 +++---
 net/sctp/socket.c                                         | 2 +-
 19 files changed, 31 insertions(+), 31 deletions(-)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index ea128e32e8ca..e07f359254c3 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -655,7 +655,7 @@ struct page *get_signal_page(void)
 		 PAGE_SIZE / sizeof(u32));
=20
 	/* Give the signal return code some randomness */
-	offset =3D 0x200 + (get_random_int() & 0x7fc);
+	offset =3D 0x200 + (get_random_u16() & 0x7fc);
 	signal_return_offset =3D offset;
=20
 	/* Copy signal return handlers into the page */
diff --git a/arch/arm64/kernel/syscall.c b/arch/arm64/kernel/syscall.c
index 733451fe7e41..d72e8f23422d 100644
--- a/arch/arm64/kernel/syscall.c
+++ b/arch/arm64/kernel/syscall.c
@@ -67,7 +67,7 @@ static void invoke_syscall(struct pt_regs *regs, unsigned=
 int scno,
 	 *
 	 * The resulting 5 bits of entropy is seen in SP[8:4].
 	 */
-	choose_random_kstack_offset(get_random_int() & 0x1FF);
+	choose_random_kstack_offset(get_random_u16() & 0x1FF);
 }
=20
 static inline bool has_syscall_work(unsigned long flags)
diff --git a/crypto/testmgr.c b/crypto/testmgr.c
index be45217acde4..981c637fa2ed 100644
--- a/crypto/testmgr.c
+++ b/crypto/testmgr.c
@@ -927,7 +927,7 @@ static void generate_random_bytes(u8 *buf, size_t count=
)
 			b =3D 0xff;
 			break;
 		default:
-			b =3D (u8)prandom_u32();
+			b =3D get_random_u8();
 			break;
 		}
 		memset(buf, b, count);
@@ -935,8 +935,8 @@ static void generate_random_bytes(u8 *buf, size_t count=
)
 		break;
 	case 2:
 		/* Ascending or descending bytes, plus optional mutations */
-		increment =3D (u8)prandom_u32();
-		b =3D (u8)prandom_u32();
+		increment =3D get_random_u8();
+		b =3D get_random_u8();
 		for (i =3D 0; i < count; i++, b +=3D increment)
 			buf[i] =3D b;
 		mutate_buffer(buf, count);
@@ -944,7 +944,7 @@ static void generate_random_bytes(u8 *buf, size_t count=
)
 	default:
 		/* Fully random bytes */
 		for (i =3D 0; i < count; i++)
-			buf[i] =3D (u8)prandom_u32();
+			buf[i] =3D get_random_u8();
 	}
 }
=20
diff --git a/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c b/drivers/media/=
common/v4l2-tpg/v4l2-tpg-core.c
index 9b7bcdce6e44..303d02b1d71c 100644
--- a/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
+++ b/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
@@ -870,7 +870,7 @@ static void precalculate_color(struct tpg_data *tpg, in=
t k)
 		g =3D tpg_colors[col].g;
 		b =3D tpg_colors[col].b;
 	} else if (tpg->pattern =3D=3D TPG_PAT_NOISE) {
-		r =3D g =3D b =3D prandom_u32_max(256);
+		r =3D g =3D b =3D get_random_u8();
 	} else if (k =3D=3D TPG_COLOR_RANDOM) {
 		r =3D g =3D b =3D tpg->qual_offset + prandom_u32_max(196);
 	} else if (k >=3D TPG_COLOR_RAMP) {
diff --git a/drivers/media/test-drivers/vivid/vivid-radio-rx.c b/drivers/me=
dia/test-drivers/vivid/vivid-radio-rx.c
index 232cab508f48..8bd09589fb15 100644
--- a/drivers/media/test-drivers/vivid/vivid-radio-rx.c
+++ b/drivers/media/test-drivers/vivid/vivid-radio-rx.c
@@ -104,8 +104,8 @@ ssize_t vivid_radio_rx_read(struct file *file, char __u=
ser *buf,
 				break;
 			case 2:
 				rds.block |=3D V4L2_RDS_BLOCK_ERROR;
-				rds.lsb =3D prandom_u32_max(256);
-				rds.msb =3D prandom_u32_max(256);
+				rds.lsb =3D get_random_u8();
+				rds.msb =3D get_random_u8();
 				break;
 			case 3: /* Skip block altogether */
 				if (i)
diff --git a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c b/=
drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
index ddfe9208529a..ac452a0111a9 100644
--- a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
+++ b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
@@ -1467,7 +1467,7 @@ static void make_established(struct sock *sk, u32 snd=
_isn, unsigned int opt)
 	tp->write_seq =3D snd_isn;
 	tp->snd_nxt =3D snd_isn;
 	tp->snd_una =3D snd_isn;
-	inet_sk(sk)->inet_id =3D prandom_u32();
+	inet_sk(sk)->inet_id =3D get_random_u16();
 	assign_rxopt(sk, opt);
=20
 	if (tp->rcv_wnd > (RCV_BUFSIZ_M << 10))
diff --git a/drivers/net/hamradio/baycom_epp.c b/drivers/net/hamradio/bayco=
m_epp.c
index 7df78a721b04..791b4a53d69f 100644
--- a/drivers/net/hamradio/baycom_epp.c
+++ b/drivers/net/hamradio/baycom_epp.c
@@ -438,7 +438,7 @@ static int transmit(struct baycom_state *bc, int cnt, u=
nsigned char stat)
 			if ((--bc->hdlctx.slotcnt) > 0)
 				return 0;
 			bc->hdlctx.slotcnt =3D bc->ch_params.slottime;
-			if (prandom_u32_max(256) > bc->ch_params.ppersist)
+			if (get_random_u8() > bc->ch_params.ppersist)
 				return 0;
 		}
 	}
diff --git a/drivers/net/hamradio/hdlcdrv.c b/drivers/net/hamradio/hdlcdrv.=
c
index 360d041a62c4..6c6f11d3d0aa 100644
--- a/drivers/net/hamradio/hdlcdrv.c
+++ b/drivers/net/hamradio/hdlcdrv.c
@@ -377,7 +377,7 @@ void hdlcdrv_arbitrate(struct net_device *dev, struct h=
dlcdrv_state *s)
 	if ((--s->hdlctx.slotcnt) > 0)
 		return;
 	s->hdlctx.slotcnt =3D s->ch_params.slottime;
-	if (prandom_u32_max(256) > s->ch_params.ppersist)
+	if (get_random_u8() > s->ch_params.ppersist)
 		return;
 	start_tx(dev, s);
 }
diff --git a/drivers/net/hamradio/yam.c b/drivers/net/hamradio/yam.c
index 97a6cc5c7ae8..2ed2f836f09a 100644
--- a/drivers/net/hamradio/yam.c
+++ b/drivers/net/hamradio/yam.c
@@ -626,7 +626,7 @@ static void yam_arbitrate(struct net_device *dev)
 	yp->slotcnt =3D yp->slot / 10;
=20
 	/* is random > persist ? */
-	if (prandom_u32_max(256) > yp->pers)
+	if (get_random_u8() > yp->pers)
 		return;
=20
 	yam_start_tx(dev, yp);
diff --git a/drivers/net/wireguard/selftest/allowedips.c b/drivers/net/wire=
guard/selftest/allowedips.c
index 41db10f9be49..dd897c0740a2 100644
--- a/drivers/net/wireguard/selftest/allowedips.c
+++ b/drivers/net/wireguard/selftest/allowedips.c
@@ -310,7 +310,7 @@ static __init bool randomized_test(void)
 			for (k =3D 0; k < 4; ++k)
 				mutated[k] =3D (mutated[k] & mutate_mask[k]) |
 					     (~mutate_mask[k] &
-					      prandom_u32_max(256));
+					      get_random_u8());
 			cidr =3D prandom_u32_max(32) + 1;
 			peer =3D peers[prandom_u32_max(NUM_PEERS)];
 			if (wg_allowedips_insert_v4(&t,
@@ -354,7 +354,7 @@ static __init bool randomized_test(void)
 			for (k =3D 0; k < 4; ++k)
 				mutated[k] =3D (mutated[k] & mutate_mask[k]) |
 					     (~mutate_mask[k] &
-					      prandom_u32_max(256));
+					      get_random_u8());
 			cidr =3D prandom_u32_max(128) + 1;
 			peer =3D peers[prandom_u32_max(NUM_PEERS)];
 			if (wg_allowedips_insert_v6(&t,
diff --git a/drivers/net/wireless/st/cw1200/wsm.c b/drivers/net/wireless/st=
/cw1200/wsm.c
index 5a3e7a626702..4a9e4b5d3547 100644
--- a/drivers/net/wireless/st/cw1200/wsm.c
+++ b/drivers/net/wireless/st/cw1200/wsm.c
@@ -1594,7 +1594,7 @@ static int cw1200_get_prio_queue(struct cw1200_common=
 *priv,
 		edca =3D &priv->edca.params[i];
 		score =3D ((edca->aifns + edca->cwmin) << 16) +
 			((edca->cwmax - edca->cwmin) *
-			 (get_random_int() & 0xFFFF));
+			 get_random_u16());
 		if (score < best && (winner < 0 || i !=3D 3)) {
 			best =3D score;
 			winner =3D i;
diff --git a/drivers/scsi/lpfc/lpfc_hbadisc.c b/drivers/scsi/lpfc/lpfc_hbad=
isc.c
index 2645def612e6..26d1779cb570 100644
--- a/drivers/scsi/lpfc/lpfc_hbadisc.c
+++ b/drivers/scsi/lpfc/lpfc_hbadisc.c
@@ -2150,8 +2150,8 @@ lpfc_check_pending_fcoe_event(struct lpfc_hba *phba, =
uint8_t unreg_fcf)
  * This function makes an running random selection decision on FCF record =
to
  * use through a sequence of @fcf_cnt eligible FCF records with equal
  * probability. To perform integer manunipulation of random numbers with
- * size unit32_t, the lower 16 bits of the 32-bit random number returned
- * from prandom_u32() are taken as the random random number generated.
+ * size unit32_t, a 16-bit random number returned from get_random_u16() is
+ * taken as the random random number generated.
  *
  * Returns true when outcome is for the newly read FCF record should be
  * chosen; otherwise, return false when outcome is for keeping the previou=
sly
@@ -2163,7 +2163,7 @@ lpfc_sli4_new_fcf_random_select(struct lpfc_hba *phba=
, uint32_t fcf_cnt)
 	uint32_t rand_num;
=20
 	/* Get 16-bit uniform random number */
-	rand_num =3D 0xFFFF & prandom_u32();
+	rand_num =3D get_random_u16();
=20
 	/* Decision with probability 1/fcf_cnt */
 	if ((fcf_cnt * rand_num) < 0xFFFF)
diff --git a/lib/cmdline_kunit.c b/lib/cmdline_kunit.c
index a72a2c16066e..d4572dbc9145 100644
--- a/lib/cmdline_kunit.c
+++ b/lib/cmdline_kunit.c
@@ -76,7 +76,7 @@ static void cmdline_test_lead_int(struct kunit *test)
 		int rc =3D cmdline_test_values[i];
 		int offset;
=20
-		sprintf(in, "%u%s", get_random_int() % 256, str);
+		sprintf(in, "%u%s", get_random_u8(), str);
 		/* Only first '-' after the number will advance the pointer */
 		offset =3D strlen(in) - strlen(str) + !!(rc =3D=3D 2);
 		cmdline_do_one_test(test, in, rc, offset);
@@ -94,7 +94,7 @@ static void cmdline_test_tail_int(struct kunit *test)
 		int rc =3D strcmp(str, "") ? (strcmp(str, "-") ? 0 : 1) : 1;
 		int offset;
=20
-		sprintf(in, "%s%u", str, get_random_int() % 256);
+		sprintf(in, "%s%u", str, get_random_u8());
 		/*
 		 * Only first and leading '-' not followed by integer
 		 * will advance the pointer.
diff --git a/net/dccp/ipv4.c b/net/dccp/ipv4.c
index da6e3b20cd75..301799e7fa56 100644
--- a/net/dccp/ipv4.c
+++ b/net/dccp/ipv4.c
@@ -123,7 +123,7 @@ int dccp_v4_connect(struct sock *sk, struct sockaddr *u=
addr, int addr_len)
 						    inet->inet_daddr,
 						    inet->inet_sport,
 						    inet->inet_dport);
-	inet->inet_id =3D prandom_u32();
+	inet->inet_id =3D get_random_u16();
=20
 	err =3D dccp_connect(sk);
 	rt =3D NULL;
@@ -422,7 +422,7 @@ struct sock *dccp_v4_request_recv_sock(const struct soc=
k *sk,
 	RCU_INIT_POINTER(newinet->inet_opt, rcu_dereference(ireq->ireq_opt));
 	newinet->mc_index  =3D inet_iif(skb);
 	newinet->mc_ttl	   =3D ip_hdr(skb)->ttl;
-	newinet->inet_id   =3D prandom_u32();
+	newinet->inet_id   =3D get_random_u16();
=20
 	if (dst =3D=3D NULL && (dst =3D inet_csk_route_child_sock(sk, newsk, req)=
) =3D=3D NULL)
 		goto put_and_exit;
diff --git a/net/ipv4/datagram.c b/net/ipv4/datagram.c
index ffd57523331f..fefc5d855a66 100644
--- a/net/ipv4/datagram.c
+++ b/net/ipv4/datagram.c
@@ -71,7 +71,7 @@ int __ip4_datagram_connect(struct sock *sk, struct sockad=
dr *uaddr, int addr_len
 	reuseport_has_conns(sk, true);
 	sk->sk_state =3D TCP_ESTABLISHED;
 	sk_set_txhash(sk);
-	inet->inet_id =3D prandom_u32();
+	inet->inet_id =3D get_random_u16();
=20
 	sk_dst_set(sk, &rt->dst);
 	err =3D 0;
diff --git a/net/ipv4/tcp_ipv4.c b/net/ipv4/tcp_ipv4.c
index 5b019ba2b9d2..747752980983 100644
--- a/net/ipv4/tcp_ipv4.c
+++ b/net/ipv4/tcp_ipv4.c
@@ -303,7 +303,7 @@ int tcp_v4_connect(struct sock *sk, struct sockaddr *ua=
ddr, int addr_len)
 						 inet->inet_daddr);
 	}
=20
-	inet->inet_id =3D prandom_u32();
+	inet->inet_id =3D get_random_u16();
=20
 	if (tcp_fastopen_defer_connect(sk, &err))
 		return err;
@@ -1523,7 +1523,7 @@ struct sock *tcp_v4_syn_recv_sock(const struct sock *=
sk, struct sk_buff *skb,
 	inet_csk(newsk)->icsk_ext_hdr_len =3D 0;
 	if (inet_opt)
 		inet_csk(newsk)->icsk_ext_hdr_len =3D inet_opt->opt.optlen;
-	newinet->inet_id =3D prandom_u32();
+	newinet->inet_id =3D get_random_u16();
=20
 	/* Set ToS of the new socket based upon the value of incoming SYN.
 	 * ECT bits are set later in tcp_init_transfer().
diff --git a/net/mac80211/scan.c b/net/mac80211/scan.c
index c4f2aeb31da3..6cab549cc421 100644
--- a/net/mac80211/scan.c
+++ b/net/mac80211/scan.c
@@ -641,7 +641,7 @@ static void ieee80211_send_scan_probe_req(struct ieee80=
211_sub_if_data *sdata,
 		if (flags & IEEE80211_PROBE_FLAG_RANDOM_SN) {
 			struct ieee80211_hdr *hdr =3D (void *)skb->data;
 			struct ieee80211_tx_info *info =3D IEEE80211_SKB_CB(skb);
-			u16 sn =3D get_random_u32();
+			u16 sn =3D get_random_u16();
=20
 			info->control.flags |=3D IEEE80211_TX_CTRL_NO_SEQNO;
 			hdr->seq_ctrl =3D
diff --git a/net/sched/sch_cake.c b/net/sched/sch_cake.c
index a43a58a73d09..637ef1757931 100644
--- a/net/sched/sch_cake.c
+++ b/net/sched/sch_cake.c
@@ -2092,11 +2092,11 @@ static struct sk_buff *cake_dequeue(struct Qdisc *s=
ch)
=20
 		WARN_ON(host_load > CAKE_QUEUES);
=20
-		/* The shifted prandom_u32() is a way to apply dithering to
-		 * avoid accumulating roundoff errors
+		/* The get_random_u16() is a way to apply dithering to avoid
+		 * accumulating roundoff errors
 		 */
 		flow->deficit +=3D (b->flow_quantum * quantum_div[host_load] +
-				  (prandom_u32() >> 16)) >> 16;
+				  get_random_u16()) >> 16;
 		list_move_tail(&flow->flowchain, &b->old_flows);
=20
 		goto retry;
diff --git a/net/sctp/socket.c b/net/sctp/socket.c
index 1e354ba44960..83628c347744 100644
--- a/net/sctp/socket.c
+++ b/net/sctp/socket.c
@@ -9448,7 +9448,7 @@ void sctp_copy_sock(struct sock *newsk, struct sock *=
sk,
 	newinet->inet_rcv_saddr =3D inet->inet_rcv_saddr;
 	newinet->inet_dport =3D htons(asoc->peer.port);
 	newinet->pmtudisc =3D inet->pmtudisc;
-	newinet->inet_id =3D prandom_u32();
+	newinet->inet_id =3D get_random_u16();
=20
 	newinet->uc_ttl =3D inet->uc_ttl;
 	newinet->mc_loop =3D 1;
--=20
2.37.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221008055359.286426-4-Jason%40zx2c4.com.
