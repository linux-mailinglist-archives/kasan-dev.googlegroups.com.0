Return-Path: <kasan-dev+bncBCLI747UVAFRB66SQGNAMGQEKQ3EN3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 602775F7CA3
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 20:01:33 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id k2-20020a05620a414200b006ceec443c8bsf4319072qko.14
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 11:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665165691; cv=pass;
        d=google.com; s=arc-20160816;
        b=FowGvf6oYnp/AfLbDgsJiwm3/hL0wXy8+KeIyQPnyw/Sg5lPKqKK88tP+X59beHhQc
         JLY4cyInB7d3A+USuiit/FQVST8NY9gyhn2lpeH1bR0sAmhyHd9dwjR6K2Kfti99R4OQ
         Nr/GyVGN2vzdgD+hR8DV5XZFBh1d0xUvVrMo/dXOKpWs7nioT2vhdyzhR7G1Kti25Ulf
         HhYkaWD6ozLoRUyBhEaCg2Tig1MPTA1BZCNJNvNcFfa1gdi69NnkbXYgoVF9THmwP28s
         dQqElR8CpqJGwr/f+5Y6ibyE572/dUtCVqTz7o26Ry9jAeHEDnjtbQ3FuxY16DS7Q7au
         8daA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fEjXRg+rxqqPre5VFQx2u9oIdBqrcJSfFBDnrhuzX/8=;
        b=lx9W/8DEfj+1WbNLfoG/lvzdo334OeseqY8t+KGXaHtwbzGENta3mbbdzaZZg7fRjQ
         lUiyBGSXuNO3DSWlTtoTObxHSijPZ9ot05dakxUgi1WRZBO9dmDRpo07RnL+qe/u9AUA
         6tb3pDx1qdKuCgNqHuDYl3UVG4dIqxzda7LnLpLoyv1EPEiSglzzXUeU/5tZdIkmXQLv
         pJKW2HZneC4K0ci+sugDjf8cxi0hyhjzSHEVlPO1ZjMIdayMenT3E8FrlCkkCNxTodW2
         rLb0JhHN8UHKN4BPBKy0sUS6EitiSAED7LaUYrlPt9+59yIflsxiKqlbtIyBJm0GZMgh
         PUnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="PzPvv0/s";
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=fEjXRg+rxqqPre5VFQx2u9oIdBqrcJSfFBDnrhuzX/8=;
        b=HMPKBNUXAG0i3BaoP+yen4A7uqW58z56j08qU/qdhh4ofvUA84OKisIZaVTDoaN3oA
         TJ9iTmp+Dzs5YEjrAtZSaQrTQHXAitmwBRsvP+VAnU5xggn2LCYV+AcwhfGJsP3iP+2J
         roF6FsjXB2teBEYBgYnffX8mtV7jB6IUSVbTqAGhw8y0vbuJSFJX1AhQwpvWyKt6Q6y3
         3nxUJDWyHqiyns5YhnCTB9fcAW5ziezmWkpL8g0WYhNZoj/7fNxZeQxEpi2KtitUKId6
         glO6ijCG8io/7JCS2yKCQCC6waNk6GKG09Rs0jS4nu31t9JJUR36k3dbsGGFbYuhHNxo
         Fe1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fEjXRg+rxqqPre5VFQx2u9oIdBqrcJSfFBDnrhuzX/8=;
        b=MqD1EZP4XpLo/7LshmBacn6ldEk+Djytat4edLl6tnLZx5TpGs2Zfi1vJWWUVG5D3v
         KPrRB1fcmMwr/b5BejwIOnpcAXrbQH2UPwlnX1b2bXS96I2SMea3sJBSqh8xooRbt6SW
         uaqlxQZ5OBSwet09FiWITUQpZLS34A+phaS7j42tIylr7he6utWeZnSGvEJuRSeeNB5B
         niP5cYLgaoQfKLjDL7kISjq15AQQ0QeSJk7TTf8O483wd6wD+iKWVY5lrtYoCMzjwTmk
         z4pvcET6+ugFfWfws2ja4Q47lruj4fQj4+v2axKDROHDQrL61dTfnhclQjuOh8cWWNCK
         87tw==
X-Gm-Message-State: ACrzQf0pK/jDm9GzUUwGy37MLQyZX6nGTTLheXAgqi7Ssn8AE3c67WXH
	twmkXFslPqKjxaeDVd5lAyk=
X-Google-Smtp-Source: AMsMyM5hLV1p7K77LGd5XgunerdUjRWInXdXms5H2bUpYNDrR/7qZBkZre9NNdz0zmlEpg04n7HHVA==
X-Received: by 2002:a05:620a:4505:b0:6cf:9668:f274 with SMTP id t5-20020a05620a450500b006cf9668f274mr4516356qkp.603.1665165691123;
        Fri, 07 Oct 2022 11:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5298:0:b0:35c:f240:4bfd with SMTP id s24-20020ac85298000000b0035cf2404bfdls3395050qtn.4.-pod-prod-gmail;
 Fri, 07 Oct 2022 11:01:30 -0700 (PDT)
X-Received: by 2002:a05:622a:145:b0:35d:43f7:cb21 with SMTP id v5-20020a05622a014500b0035d43f7cb21mr5147018qtw.202.1665165690499;
        Fri, 07 Oct 2022 11:01:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665165690; cv=none;
        d=google.com; s=arc-20160816;
        b=If/EfhaHKUjT/QO9v2Wc+S1hfJRuw5jZbeg3Q6htSSBZ783uNPEGGVPk4cYTdtCjgR
         RmKvWvHct8WKkbMQ1oc5ZBwczZ/uLvwtrY67L2xB81Thr8KHvqAJ9v5t1LQ96kI9G0y7
         dFWSxUl5GUgHBZBRikeM+tT7k6m17ucc45i975UH86WIUW0xg1aZ4/FP3AV46fxS5UYx
         P2lv1u5gGTOSh6BpOue50wBb44za+MlXgQCUjd7lscGddJp6DT4HuOQAEIRSKa76+0Sc
         l/65nHcXTLudKTfpR+3Ru9ecdywQRWoNMGqF6AOBl71ALbPCvxZ9Chwyp1uW2Z4oG7no
         8uaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BojkAi/8g8zu4lZz0PvCkndQfyCzqdQaTWLu1pNCOPk=;
        b=qAyo5B/IhWuJZ61IRjDXBPSY5W2ScEF3WkVXitH26B1EXxGuD8fJa4Ya/EHIz4NKG3
         Pu6i6z6pzK//yO/5wjxZ2dK70Kpu3WyiWzvu3kEF145KIBkEpahGqphGk6xaZ85PiK5m
         FO/iWiy+SyNkTLwM1GZgU00Z2sLkZ7hojZFojKrTQl9o4mHpS294+Z0+06vJQjFD/3aU
         1QprPH7h0pT/x68oXWlM7TJ8BkAlDZBrXyP2MIvh2jbzGcn5qb76/37p1i/jJWMKmNwB
         QmFpNYQvH02IVI/B4Aet6KgJJBRe33LU5DPrgct++4DvagQUSTg94jF2Fn9SvJlENwLm
         gd2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="PzPvv0/s";
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y22-20020a05620a25d600b006cec0e4b3f0si126782qko.1.2022.10.07.11.01.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 11:01:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D53D961747;
	Fri,  7 Oct 2022 18:01:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3E596C433C1;
	Fri,  7 Oct 2022 18:01:23 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 6b781aa4 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Fri, 7 Oct 2022 18:01:21 +0000 (UTC)
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
Subject: [PATCH v4 0/6] treewide cleanup of random integer usage
Date: Fri,  7 Oct 2022 12:01:01 -0600
Message-Id: <20221007180107.216067-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b="PzPvv0/s";       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
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

Changes v3->v4:
- Split coccinelle mechanical step from non-mechanical step.
- Handle `get_random_int() & ~PAGE_MASK` -> `prandom_u32_max(PAGE_SIZE)`.

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
breaks down into the following five steps, which were done mostly
manually, but the first step was split into two patches, the first of
which is cocinelle-able:

1) Replace `prandom_u32() % max` and variants thereof with
   prandom_u32_max(max).

2) Replace `(type)get_random_u32()` and variants thereof with
   get_random_u16() or get_random_u8(). I took the pains to actually
   look and see what every lvalue type was across the entire tree.

3) Replace remaining deprecated uses of prandom_u32() and
   get_random_int() with get_random_u32().=20

4) Replace remaining deprecated uses of prandom_bytes() with
   get_random_bytes().

5) Remove the deprecated and now-unused prandom_u32() and
   prandom_bytes() inline wrapper functions.

I was thinking of taking this through my random.git tree (on which this
series is currently based) and submitting it near the end of the merge
window, or waiting for the very end of the 6.1 cycle when there will be
the fewest new patches brewing. If somebody with some treewide-cleanup
experience might share some wisdom about what the best timing usually
winds up being, I'm all ears.

Please take a look! At "379 insertions(+), 422 deletions(-)", this
should be a somewhat small patchset to review, despite it having the
scary "treewide" moniker on it.

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

Jason A. Donenfeld (6):
  treewide: use prandom_u32_max() when possible, mechanically
  treewide: use prandom_u32_max() when possible
  treewide: use get_random_{u8,u16}() when possible
  treewide: use get_random_u32() when possible
  treewide: use get_random_bytes when possible
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
 drivers/gpu/drm/selftests/test-drm_buddy.c    |  2 +-
 drivers/gpu/drm/selftests/test-drm_mm.c       |  2 +-
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
kasan-dev/20221007180107.216067-1-Jason%40zx2c4.com.
