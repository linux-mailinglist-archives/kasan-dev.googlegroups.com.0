Return-Path: <kasan-dev+bncBCLI747UVAFRBBWLSKNAMGQEEWTUQGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 22BDB5FA7EF
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 01:06:48 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id t15-20020a5d81cf000000b006bc1ca3ae00sf2621451iol.10
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 16:06:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665443206; cv=pass;
        d=google.com; s=arc-20160816;
        b=PJVM0pM0ChKZLpPSWFPXYTD0JSkXCzHaV9an5Lp8PlvOGjn1NVAU9Eg4UFqyWb6Qji
         iXiVkxai6EXv1eMa5vTlZb5T8r+tYdLAWprcxctlF6RQsHyELTY/yN8Y3iP3knhiNknl
         7pgAWzdm4iHgYoooHdY2zGbr2SyQLa8/XxTkkR0Oh1WqGPnTahqkLslnVN1s05qIHJYt
         7b9pRVkpSzKn4NnItGqLr0g3CC6bTH9OBJiYVBpq7HXkUNEWD3tuZEXYqIKlDmYyCV0W
         fzXkbYQ1zJEiwcW6zBSjnGzl0LZKq8qgPskBkHXD0OUwRn0c+HM/rm0jZGrt1hH4LWVw
         LTlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4hpZyOdXcompRSk0acsvVrkgjSgNHQcN1BJMrNsqk28=;
        b=JbIAWQ6tvuNPCGFD0IYjWhX18iQX6oP7ZsG25XMnph+joTUhVSIvH4F6bI/x7wT3+m
         mThRqZ1e3CetSG5cOjy2m0GFiCjqFzRAur0VMjkwwkxhA+9l0aYSP3KrEqQM2RlhhzSa
         aJXFAlqpYRfSyav0pf1ohDJ2BYkfzha9bi0LhvLTX90v26sVGvtkn9d2fIWqHm3KIqCI
         OwHvfl03iYLqkssNIjkcSwPVfEAz4I88ok2dz0WPsedvucdaou+f0Leby39A4tjdBvnV
         3SGgVJ9aUeqSsj4gFrmhJNbPoWGS0hO4n1XDmVukuSi2XmPBlgwktbqBV2KpE24Mnj/m
         CHuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=LJrnNFvf;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=4hpZyOdXcompRSk0acsvVrkgjSgNHQcN1BJMrNsqk28=;
        b=tRx7piLnTsXTvyrvjNCV0rQyRsgJKWpG4SixwoSXWiAUc7FPjnIiTGtDaErBAkxmBD
         vy5ZH6q393cqGnWPnRv1VmyiK82CVTOf+q/sulyNOdDJBmSqbw9rOalYGNHeh+vzG6zw
         nEBRw6exTgMsImj1MhJImQjdZaf10GtUzfLKDuPndJno/lnFLO0cjlBVtjziAOtipTWd
         Oqy85x43QwaV44ojJvvAWqrT1qbljrnI1AsshyoDWfNALohQioPwdEzUPHSWAMvHtoqt
         yutcfgbFUwoYL4q2tGc7y//WTSofuO0he6kP2ztzTLV7/wbmWbW6F6wVIFrPDgpaLSnX
         b0UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4hpZyOdXcompRSk0acsvVrkgjSgNHQcN1BJMrNsqk28=;
        b=8SBIjw/5jp3v1eEhcJaAcef+PCeaShkxBVu+323TNXyXwxUX+ndKYmhkcx0uaE0Pz2
         0z/kp9+ubMj59a8gpWYjfCxiz8KLWQGic3+K/0CpGRfdBlxfbY216pui4anep64JEIxI
         K2ZBtw9d4t60Ihv9oLpmcVEKn18LFIVGKG0OrOSadOqJOMx9LwvhpCXFZQEZmKLbdZK0
         mKwpbtMUgHx/u8DX0ICOBAMVeh90D0arD5gniSwDoqnaNPMVjT/vKRQ5wYnM9c/9MjPx
         rioYKgzhR3bmBej9CTNI0ITzMgbZDblQyQNMfa2QsLwmDLBP36tjSTT5z21XSc/r1sea
         igLQ==
X-Gm-Message-State: ACrzQf2gWqaJxaYySUmslTlA3XSAsUi0AehoOPtQ/emTlts3zuBe6PjI
	eL6h/TVdWEGSc6lUjdbkJKI=
X-Google-Smtp-Source: AMsMyM4CP0jWmJmMuYWitoJxKW09RJTIlAHWDe3KLy9oGX+sKR1N53YZJRULCI+Cp9f+2eer305kZQ==
X-Received: by 2002:a05:6638:3286:b0:349:fd14:7af6 with SMTP id f6-20020a056638328600b00349fd147af6mr11103926jav.48.1665443206676;
        Mon, 10 Oct 2022 16:06:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a82:0:b0:35a:328c:6cc0 with SMTP id w124-20020a022a82000000b0035a328c6cc0ls2782633jaw.2.-pod-prod-gmail;
 Mon, 10 Oct 2022 16:06:46 -0700 (PDT)
X-Received: by 2002:a05:6638:1385:b0:35a:723c:2fb3 with SMTP id w5-20020a056638138500b0035a723c2fb3mr10401248jad.222.1665443206252;
        Mon, 10 Oct 2022 16:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665443206; cv=none;
        d=google.com; s=arc-20160816;
        b=HHDMrvrL5HhxZkNpt5pcMT/hkPoTja3pfnyBSstXD52JGUHMwD6mnQyJ6111ZIdMZZ
         xq3vlGjjcJD13QxZFG0BrRMjfjT5YTmbUfML/18xJhIdao+FGpgTFus3S2buhsod4Ikm
         +6l+f9CWytCtE61lHUb9wLYilt9JXKFXxsWwalEt32gSEDTc8VORLKBPeOGC1EyG/8Bm
         /58t2CgasKSZo0MUWZ4zgvzyMuO3oRxxwkvxUPNxBK6EO9pf9rxKZgw84jvpLMvZ5oak
         PbYHuQoc2Z0WSvmsRWk7QxHDCctLg723UxLJhDmrLFG9IfoNRh10QlSTe7yWpWCeK9Z9
         Go5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=KqVWEHtrBC2bSt6YfoMbVT2SYWISgaw7tOKuJ16fz7w=;
        b=kW/huIyuyjNXxtQwgSGcn3amlLGjLTixO3oKrRr0JN5ZNz+BTSudP+oChOY/hUX3pr
         rgWZggT+cPae2IyFa5c/pF5XK10O4XEyKdHz2Va6gN6gQNM8R5Q0NC43eGSC7dcrG9wS
         sCQQtS9xOqKQF1mvuYMGhdKE5h6gBBWHLwf1ZVq0u8zc+yokcXL4gFH4KnzE2nQ5D7fI
         ArVdiuE7iDIMGoSexFc67eUDIO4ifC3nb03ZJO0CvKED0arQV5z15b1u9Vg6ThrIQteI
         gRPkor3qBzvNpPsb/TjqEXYEqde9+sRdxBtY9tvDdi6Lge7ZZqs4j/4Fh2HwE3Vt/j2n
         VsYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=LJrnNFvf;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id k1-20020a92c241000000b002fa33282e2asi331029ilo.5.2022.10.10.16.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 16:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B405460FDD;
	Mon, 10 Oct 2022 23:06:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F2675C433D6;
	Mon, 10 Oct 2022 23:06:38 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id d37e5149 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 10 Oct 2022 23:06:36 +0000 (UTC)
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
	x86@kernel.org
Subject: [PATCH v6 0/7] treewide cleanup of random integer usage
Date: Mon, 10 Oct 2022 17:06:06 -0600
Message-Id: <20221010230613.1076905-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=LJrnNFvf;       spf=pass
 (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
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

Changes v5->v6:
- Added a few missing conversions that weren't in my older tree, so now
  this should be ready to go, as well as a couple nits people had from
  v5. Barring something large and unforeseen, this is the "final
  version", as this is ready to ship. Thanks to everyone who reviewed
  this.

Hi folks,

This is a five part treewide cleanup of random integer handling. The
rules for random integers are:

- If you want a secure or an insecure random u64, use get_random_u64().
- If you want a secure or an insecure random u32, use get_random_u32().
  * The old function prandom_u32() has been deprecated for a while now
    and is just a wrapper around get_random_u32(). Same for
    get_random_int().
- If you want a secure or an insecure random u16, use get_random_u16().
- If you want a secure or an insecure random u8, use get_random_u8().
- If you want secure or insecure random bytes, use get_random_bytes().
  * The old function prandom_bytes() has been deprecated for a while now
    and has long been a wrapper around get_random_bytes().
- If you want a non-uniform random u32, u16, or u8 bounded by a certain
  open interval maximum, use prandom_u32_max().
  * I say "non-uniform", because it doesn't do any rejection sampling or
    divisions. Hence, it stays within the prandom_* namespace.

These rules ought to be applied uniformly, so that we can clean up the
deprecated functions, and earn the benefits of using the modern
functions. In particular, in addition to the boring substitutions, this
patchset accomplishes a few nice effects:

- By using prandom_u32_max() with an upper-bound that the compiler can
  prove at compile-time is =E2=89=A465536 or =E2=89=A4256, internally get_r=
andom_u16()
  or get_random_u8() is used, which wastes fewer batched random bytes,
  and hence has higher throughput.

- By using prandom_u32_max() instead of %, when the upper-bound is not a
  constant, division is still avoided, because prandom_u32_max() uses
  a faster multiplication-based trick instead.

- By using get_random_u16() or get_random_u8() in cases where the return
  value is intended to indeed be a u16 or a u8, we waste fewer batched
  random bytes, and hence have higher throughput.

So, based on those rules and benefits from following them, this patchset
breaks down into the following five steps:

1) Replace `prandom_u32() % max` and variants thereof with
   prandom_u32_max(max).

   * Part 1 is done with Coccinelle. Part 2 is done by hand.

2) Replace `(type)get_random_u32()` and variants thereof with
   get_random_u16() or get_random_u8(). I took the pains to actually
   look and see what every lvalue type was across the entire tree.

   * Part 1 is done with Coccinelle. Part 2 is done by hand.

3) Replace remaining deprecated uses of prandom_u32() and
   get_random_int() with get_random_u32().=20

   * A boring search and replace operation.

4) Replace remaining deprecated uses of prandom_bytes() with
   get_random_bytes().

   * A boring search and replace operation.

5) Remove the deprecated and now-unused prandom_u32() and
   prandom_bytes() inline wrapper functions.

   * Just deleting code and updating comments.

I'll be sending this toward the end of the 6.1 merge window via the
random.git tree.

Please take a look! The number of lines touched is quite small, so this
should be reviewable, and as much as is possible has been pushed into
Coccinelle scripts.

Thanks,
Jason

Cc: Andreas Noever <andreas.noever@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com>
Cc: Christoph Hellwig <hch@lst.de>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Daniel Borkmann <daniel@iogearbox.net>
Cc: Dave Airlie <airlied@redhat.com>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: David S. Miller <davem@davemloft.net>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Florian Westphal <fw@strlen.de>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
Cc: H. Peter Anvin <hpa@zytor.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Helge Deller <deller@gmx.de>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: Huacai Chen <chenhuacai@kernel.org>
Cc: Hugh Dickins <hughd@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: James E.J. Bottomley <jejb@linux.ibm.com>
Cc: Jan Kara <jack@suse.com>
Cc: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Johannes Berg <johannes@sipsolutions.net>
Cc: Jonathan Corbet <corbet@lwn.net>
Cc: Jozsef Kadlecsik <kadlec@netfilter.org>
Cc: KP Singh <kpsingh@kernel.org>
Cc: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>
Cc: Mauro Carvalho Chehab <mchehab@kernel.org>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Pablo Neira Ayuso <pablo@netfilter.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Richard Weinberger <richard@nod.at>
Cc: Russell King <linux@armlinux.org.uk>
Cc: Theodore Ts'o <tytso@mit.edu>
Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Thomas Graf <tgraf@suug.ch>
Cc: Ulf Hansson <ulf.hansson@linaro.org>
Cc: Vignesh Raghavendra <vigneshr@ti.com>
Cc: WANG Xuerui <kernel@xen0n.name>
Cc: Will Deacon <will@kernel.org>
Cc: Yury Norov <yury.norov@gmail.com>
Cc: dri-devel@lists.freedesktop.org
Cc: kasan-dev@googlegroups.com
Cc: kernel-janitors@vger.kernel.org
Cc: linux-arm-kernel@lists.infradead.org
Cc: linux-block@vger.kernel.org
Cc: linux-crypto@vger.kernel.org
Cc: linux-doc@vger.kernel.org
Cc: linux-fsdevel@vger.kernel.org
Cc: linux-media@vger.kernel.org
Cc: linux-mips@vger.kernel.org
Cc: linux-mm@kvack.org
Cc: linux-mmc@vger.kernel.org
Cc: linux-mtd@lists.infradead.org
Cc: linux-nvme@lists.infradead.org
Cc: linux-parisc@vger.kernel.org
Cc: linux-rdma@vger.kernel.org
Cc: linux-s390@vger.kernel.org
Cc: linux-um@lists.infradead.org
Cc: linux-usb@vger.kernel.org
Cc: linux-wireless@vger.kernel.org
Cc: linuxppc-dev@lists.ozlabs.org
Cc: loongarch@lists.linux.dev
Cc: netdev@vger.kernel.org
Cc: sparclinux@vger.kernel.org
Cc: x86@kernel.org

Jason A. Donenfeld (7):
  treewide: use prandom_u32_max() when possible, part 1
  treewide: use prandom_u32_max() when possible, part 2
  treewide: use get_random_{u8,u16}() when possible, part 1
  treewide: use get_random_{u8,u16}() when possible, part 2
  treewide: use get_random_u32() when possible
  treewide: use get_random_bytes() when possible
  prandom: remove unused functions

 Documentation/networking/filter.rst           |  2 +-
 arch/arm/kernel/process.c                     |  2 +-
 arch/arm/kernel/signal.c                      |  2 +-
 arch/arm64/kernel/process.c                   |  2 +-
 arch/arm64/kernel/syscall.c                   |  2 +-
 arch/loongarch/kernel/process.c               |  2 +-
 arch/loongarch/kernel/vdso.c                  |  2 +-
 arch/mips/kernel/process.c                    |  2 +-
 arch/mips/kernel/vdso.c                       |  2 +-
 arch/parisc/kernel/process.c                  |  2 +-
 arch/parisc/kernel/sys_parisc.c               |  4 +-
 arch/parisc/kernel/vdso.c                     |  2 +-
 arch/powerpc/crypto/crc-vpmsum_test.c         |  2 +-
 arch/powerpc/kernel/process.c                 |  2 +-
 arch/s390/kernel/process.c                    |  4 +-
 arch/s390/kernel/vdso.c                       |  2 +-
 arch/s390/mm/mmap.c                           |  2 +-
 arch/sparc/vdso/vma.c                         |  2 +-
 arch/um/kernel/process.c                      |  2 +-
 arch/x86/entry/vdso/vma.c                     |  2 +-
 arch/x86/kernel/cpu/amd.c                     |  2 +-
 arch/x86/kernel/module.c                      |  2 +-
 arch/x86/kernel/process.c                     |  2 +-
 arch/x86/mm/pat/cpa-test.c                    |  4 +-
 block/blk-crypto-fallback.c                   |  2 +-
 crypto/async_tx/raid6test.c                   |  2 +-
 crypto/testmgr.c                              | 94 +++++++++----------
 drivers/block/drbd/drbd_receiver.c            |  4 +-
 drivers/char/random.c                         | 11 +--
 drivers/dma/dmatest.c                         |  2 +-
 .../gpu/drm/i915/gem/i915_gem_execbuffer.c    |  2 +-
 drivers/gpu/drm/i915/i915_gem_gtt.c           |  6 +-
 .../gpu/drm/i915/selftests/i915_selftest.c    |  2 +-
 drivers/gpu/drm/tests/drm_buddy_test.c        |  2 +-
 drivers/gpu/drm/tests/drm_mm_test.c           |  2 +-
 drivers/infiniband/core/cma.c                 |  2 +-
 drivers/infiniband/hw/cxgb4/cm.c              |  4 +-
 drivers/infiniband/hw/cxgb4/id_table.c        |  4 +-
 drivers/infiniband/hw/hfi1/tid_rdma.c         |  2 +-
 drivers/infiniband/hw/hns/hns_roce_ah.c       |  5 +-
 drivers/infiniband/hw/mlx4/mad.c              |  2 +-
 drivers/infiniband/ulp/ipoib/ipoib_cm.c       |  2 +-
 drivers/infiniband/ulp/rtrs/rtrs-clt.c        |  3 +-
 drivers/md/bcache/request.c                   |  2 +-
 drivers/md/raid5-cache.c                      |  2 +-
 drivers/media/common/v4l2-tpg/v4l2-tpg-core.c |  2 +-
 .../media/test-drivers/vivid/vivid-radio-rx.c |  4 +-
 .../test-drivers/vivid/vivid-touch-cap.c      |  6 +-
 drivers/misc/habanalabs/gaudi2/gaudi2.c       |  2 +-
 drivers/mmc/core/core.c                       |  4 +-
 drivers/mmc/host/dw_mmc.c                     |  2 +-
 drivers/mtd/nand/raw/nandsim.c                |  8 +-
 drivers/mtd/tests/mtd_nandecctest.c           | 12 +--
 drivers/mtd/tests/speedtest.c                 |  2 +-
 drivers/mtd/tests/stresstest.c                | 19 +---
 drivers/mtd/ubi/debug.c                       |  2 +-
 drivers/mtd/ubi/debug.h                       |  6 +-
 drivers/net/bonding/bond_main.c               |  2 +-
 drivers/net/ethernet/broadcom/bnxt/bnxt.c     |  2 +-
 drivers/net/ethernet/broadcom/cnic.c          |  5 +-
 .../chelsio/inline_crypto/chtls/chtls_cm.c    |  4 +-
 .../chelsio/inline_crypto/chtls/chtls_io.c    |  4 +-
 drivers/net/ethernet/rocker/rocker_main.c     |  8 +-
 drivers/net/hamradio/baycom_epp.c             |  2 +-
 drivers/net/hamradio/hdlcdrv.c                |  2 +-
 drivers/net/hamradio/yam.c                    |  2 +-
 drivers/net/phy/at803x.c                      |  2 +-
 drivers/net/wireguard/selftest/allowedips.c   | 16 ++--
 .../broadcom/brcm80211/brcmfmac/p2p.c         |  2 +-
 .../broadcom/brcm80211/brcmfmac/pno.c         |  2 +-
 .../net/wireless/intel/iwlwifi/mvm/mac-ctxt.c |  2 +-
 .../net/wireless/marvell/mwifiex/cfg80211.c   |  4 +-
 .../wireless/microchip/wilc1000/cfg80211.c    |  2 +-
 .../net/wireless/quantenna/qtnfmac/cfg80211.c |  2 +-
 drivers/net/wireless/st/cw1200/wsm.c          |  2 +-
 drivers/net/wireless/ti/wlcore/main.c         |  2 +-
 drivers/nvme/common/auth.c                    |  2 +-
 drivers/scsi/cxgbi/cxgb4i/cxgb4i.c            |  4 +-
 drivers/scsi/fcoe/fcoe_ctlr.c                 |  4 +-
 drivers/scsi/lpfc/lpfc_hbadisc.c              |  6 +-
 drivers/scsi/qedi/qedi_main.c                 |  2 +-
 drivers/target/iscsi/cxgbit/cxgbit_cm.c       |  2 +-
 drivers/thunderbolt/xdomain.c                 |  2 +-
 drivers/video/fbdev/uvesafb.c                 |  2 +-
 fs/ceph/inode.c                               |  2 +-
 fs/ceph/mdsmap.c                              |  2 +-
 fs/exfat/inode.c                              |  2 +-
 fs/ext2/ialloc.c                              |  3 +-
 fs/ext4/ialloc.c                              |  7 +-
 fs/ext4/ioctl.c                               |  4 +-
 fs/ext4/mmp.c                                 |  2 +-
 fs/ext4/super.c                               |  7 +-
 fs/f2fs/gc.c                                  |  2 +-
 fs/f2fs/namei.c                               |  2 +-
 fs/f2fs/segment.c                             |  8 +-
 fs/fat/inode.c                                |  2 +-
 fs/nfsd/nfs4state.c                           |  4 +-
 fs/ntfs3/fslog.c                              |  6 +-
 fs/ubifs/debug.c                              | 10 +-
 fs/ubifs/journal.c                            |  2 +-
 fs/ubifs/lpt_commit.c                         | 14 +--
 fs/ubifs/tnc_commit.c                         |  2 +-
 fs/xfs/libxfs/xfs_alloc.c                     |  2 +-
 fs/xfs/libxfs/xfs_ialloc.c                    |  4 +-
 fs/xfs/xfs_error.c                            |  2 +-
 fs/xfs/xfs_icache.c                           |  2 +-
 fs/xfs/xfs_log.c                              |  2 +-
 include/linux/nodemask.h                      |  2 +-
 include/linux/prandom.h                       | 12 ---
 include/linux/random.h                        |  5 -
 include/net/netfilter/nf_queue.h              |  2 +-
 include/net/red.h                             |  2 +-
 include/net/sock.h                            |  2 +-
 kernel/bpf/bloom_filter.c                     |  2 +-
 kernel/bpf/core.c                             |  6 +-
 kernel/bpf/hashtab.c                          |  2 +-
 kernel/bpf/verifier.c                         |  2 +-
 kernel/kcsan/selftest.c                       |  4 +-
 kernel/locking/test-ww_mutex.c                |  4 +-
 kernel/time/clocksource.c                     |  2 +-
 lib/cmdline_kunit.c                           |  4 +-
 lib/fault-inject.c                            |  2 +-
 lib/find_bit_benchmark.c                      |  4 +-
 lib/kobject.c                                 |  2 +-
 lib/random32.c                                |  4 +-
 lib/reed_solomon/test_rslib.c                 | 12 +--
 lib/sbitmap.c                                 |  4 +-
 lib/test-string_helpers.c                     |  2 +-
 lib/test_fprobe.c                             |  2 +-
 lib/test_hexdump.c                            | 10 +-
 lib/test_kasan.c                              |  6 +-
 lib/test_kprobes.c                            |  2 +-
 lib/test_list_sort.c                          |  2 +-
 lib/test_min_heap.c                           |  6 +-
 lib/test_objagg.c                             |  2 +-
 lib/test_rhashtable.c                         |  6 +-
 lib/test_vmalloc.c                            | 19 +---
 lib/uuid.c                                    |  2 +-
 mm/migrate.c                                  |  2 +-
 mm/shmem.c                                    |  2 +-
 mm/slab.c                                     |  2 +-
 mm/slub.c                                     |  2 +-
 net/802/garp.c                                |  2 +-
 net/802/mrp.c                                 |  2 +-
 net/ceph/mon_client.c                         |  2 +-
 net/ceph/osd_client.c                         |  2 +-
 net/core/neighbour.c                          |  2 +-
 net/core/pktgen.c                             | 47 +++++-----
 net/core/stream.c                             |  2 +-
 net/dccp/ipv4.c                               |  4 +-
 net/ipv4/datagram.c                           |  2 +-
 net/ipv4/igmp.c                               |  6 +-
 net/ipv4/inet_connection_sock.c               |  2 +-
 net/ipv4/inet_hashtables.c                    |  2 +-
 net/ipv4/ip_output.c                          |  2 +-
 net/ipv4/route.c                              |  4 +-
 net/ipv4/tcp_cdg.c                            |  2 +-
 net/ipv4/tcp_ipv4.c                           |  4 +-
 net/ipv4/udp.c                                |  2 +-
 net/ipv6/addrconf.c                           |  8 +-
 net/ipv6/ip6_flowlabel.c                      |  2 +-
 net/ipv6/mcast.c                              | 10 +-
 net/ipv6/output_core.c                        |  2 +-
 net/mac80211/rc80211_minstrel_ht.c            |  2 +-
 net/mac80211/scan.c                           |  2 +-
 net/netfilter/ipvs/ip_vs_conn.c               |  2 +-
 net/netfilter/ipvs/ip_vs_twos.c               |  4 +-
 net/netfilter/nf_nat_core.c                   |  4 +-
 net/netfilter/xt_statistic.c                  |  2 +-
 net/openvswitch/actions.c                     |  2 +-
 net/packet/af_packet.c                        |  2 +-
 net/rds/bind.c                                |  2 +-
 net/sched/act_gact.c                          |  2 +-
 net/sched/act_sample.c                        |  2 +-
 net/sched/sch_cake.c                          |  8 +-
 net/sched/sch_netem.c                         | 22 ++---
 net/sched/sch_pie.c                           |  2 +-
 net/sched/sch_sfb.c                           |  2 +-
 net/sctp/socket.c                             |  4 +-
 net/sunrpc/auth_gss/gss_krb5_wrap.c           |  4 +-
 net/sunrpc/cache.c                            |  2 +-
 net/sunrpc/xprt.c                             |  2 +-
 net/sunrpc/xprtsock.c                         |  2 +-
 net/tipc/socket.c                             |  2 +-
 net/unix/af_unix.c                            |  2 +-
 net/xfrm/xfrm_state.c                         |  2 +-
 186 files changed, 379 insertions(+), 422 deletions(-)

--=20
2.37.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221010230613.1076905-1-Jason%40zx2c4.com.
