Return-Path: <kasan-dev+bncBCF5XGNWYQBRBXMFRGNAMGQEIIPHHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F3BE5F8930
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 05:41:19 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id bj40-20020a05620a192800b006e20308f39csf6850138qkb.10
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 20:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665286877; cv=pass;
        d=google.com; s=arc-20160816;
        b=sLixieyqQ28GfwLzvEwL6/WVjctRYK1b8MqOdOVD+AOs1WAld76Pdc8DnzEJlarDKv
         5CVey+Ml+WIuEf8hbr0Bw/tSx493cvHTa7LTA5okcDPgHJsO5E8uAuI7K2jOKWFsNVCX
         rMNk+oKjjAvM4KoefZ33GVWkYIdtzSJ5NlfFOD02mXnUY/5Mla7XjVgO0ZOU18h7soz3
         SyTI3w5vnnIRtA32axgbf1gSTSpgqju/uX7FsOvIKuGkGGj858njhhSX6hsCJewA/mk+
         0cAMrEpJ9ABn9AG1NfyiUuyaRY65YrK/UrChIVRee8UlR1o730oAAyxMsqGDzNwd7bL5
         Y2Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9h34dZ2tqXis/KILTId6z/NtbNEc/QoX7qHE5g8CXE8=;
        b=mKLZh6Upm+hQnxi6RXTzIZdn+4mo5zYFMY4ZBBh7GV+lLZMwCNfDYGLkOKobj4avum
         EdX1ev21PCYpCLQA9jb12P9YyvVqEVHdVYlfJc87tsZ+lN0hoy3TyLYfwIu4mxLVCvge
         jBrv7RYww+caNb8i6d3FQwItUXTTe016vgcNQ65GMcFiy54PKW3UxNDRBJ2Mh1mWBt+U
         AoWHLPM4zIdAAmgBBYtTxGUdpXoBEK2YQckzhnkuOdvEIMbWPV5s0Y50JdflLCJANsCJ
         Q3DvY6V81xTm7wyNN2zRCC8mX/VGHwDer1IfC7xTGxKejQuxIDccJyiapJx21+h2bs04
         kHMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ZhbF7auk;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9h34dZ2tqXis/KILTId6z/NtbNEc/QoX7qHE5g8CXE8=;
        b=HXAUOMtp7c0GFymb7l1KPGzgAeSL7QH3E28XgYvvTFi4cqbc8BXCSze8j16vAHVZr0
         XKIpvJfUL5VTw9HQjd0tOO+iZTSNdpE77saXLrhijFf1f3iGSEzGQ9dhPgZa+iacgJ+9
         Qid5qYGwFkYhT7p5iPDPJjAV6gpt4yNZAIZ1pzeK72MsfRUPql92kkE4pDFf2ITX5+Vw
         xz3HuvsaeSYp4flxFZyUblHEZ69vvqytvZQKEZeH3TH2y3EqAwNqQCb8m096Mk8+Izbz
         dcYAYX0PGZjtlOXpcpWB6n0Hq8GiyNulj6hVoR6/baJHuH6NUvg70se4hvg08uV/+Bhi
         lsSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9h34dZ2tqXis/KILTId6z/NtbNEc/QoX7qHE5g8CXE8=;
        b=2Gq0NqbrtR4Ryu8Aj4EIWvRFuE0r6oh0PTmd/jOMI8S0NCarUFtGPFVPMmy9pZHgLB
         zOfsh4/XmYLlImOhvANWCmp2HI/qVC4vvvIDVvLsRBqz3oSZhLEvEMzC3WjbBLTlheL2
         7eq7S2w4phjhUtYGr9xdrGYpBp6ec1JCym2r9DluQSqqmortKYeMw4KEm6T4u+IrG6CD
         B/C1/TtJ+XZGPEg6f7A04X+Et4X5AVzkaMaGbYlr1/4qB/eOMnsJag+78jAtRjI1UYDr
         XlJUh3GBLyH/49YucKz27ZALS8Af3ftrbAHcn15pp7Kv1zeTT9H6tXHJ9XxPRt7aLBh/
         Q+Bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3rCC0b2GNBYTEnnoKljXr3jUowh2wflLYpKH/7fhx2loW54POD
	CO1JaD/g4OPu7N5qL+/XV+I=
X-Google-Smtp-Source: AMsMyM4qqMbVSNvbvSQdzi6wK1qH/+Yu5m+aEStvNaMOk2tKc9uF4dYy8dpNSIHNi8957b6jUxzXeA==
X-Received: by 2002:a0c:b294:0:b0:4b1:a396:d1cc with SMTP id r20-20020a0cb294000000b004b1a396d1ccmr10006150qve.107.1665286877790;
        Sat, 08 Oct 2022 20:41:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f50a:0:b0:6cf:8490:ef39 with SMTP id l10-20020a37f50a000000b006cf8490ef39ls5252889qkk.7.-pod-prod-gmail;
 Sat, 08 Oct 2022 20:41:17 -0700 (PDT)
X-Received: by 2002:a05:620a:678:b0:6ec:52ba:80a6 with SMTP id a24-20020a05620a067800b006ec52ba80a6mr1933800qkh.419.1665286877302;
        Sat, 08 Oct 2022 20:41:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665286877; cv=none;
        d=google.com; s=arc-20160816;
        b=XeUL+0ey/VrHrNhoAuVGOb5/watxyVvOSAMoKcuF71yYum5UaVk8ipslULwnUCnaZ0
         rGd0/VH3bHLHw4UZbBeUmWJ4L4DF2pIn5A2TgP2ShaT9QnNF5sP+UYuVSUtNhd4bmN0I
         hHOzrT1ugNhaticVWYkAnEzWEuoXvngnh+npuZmjOp4nWcYAOBI8NUMxoUgbgeS2bUy6
         2baN5a/FGazMIQW79mENtI57+y9s2a0A6E43tIJH4qW8gaOA4yIuyDaaCSBVAepd0Zzu
         x0kJKjJQjRZxnursD6uZEHb9sMXGj6O4jIv2M0XSSW8xit7g3bGyjoZkinvVB/2bWp+i
         5B4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Jc9wqi9hH7sDAuXmZMPHByefEvgO0MbR3+ZEqDB7Wuk=;
        b=jFZSafqUIcY8jr0uiOvFxITMLVYDyTy012iKzEm5Oo90SNvKwpbU2XC/ID2ni8vwuy
         sulCBaWgMrZ6syaL/6lFYnHaDmopA/W40u+b3/L/V0WoytBmu+fEJv75hAQ4rYRqeYQq
         ChZV4hGjfeDoIpoBB7DLlTl7XUmjwSiHHEO/JYuGAHOx3vM4HyU8+7IgzBzBAmuqPsRE
         DhP6DP4ePYJZpRzcjVbIIn+qU0NOh9J6iEuqX/E/ar/Wu/82ui4t3Dos7znkcarZqHIN
         oRga5m4peOV3P++6jzhuCUf/M517dGBls3m/lVvqQGSlR/QPPgyhRvyTmW4icNB+GpG0
         8a0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ZhbF7auk;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id fd10-20020a05622a4d0a00b0031ecf06e367si210046qtb.1.2022.10.08.20.41.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Oct 2022 20:41:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id s206so7810824pgs.3
        for <kasan-dev@googlegroups.com>; Sat, 08 Oct 2022 20:41:17 -0700 (PDT)
X-Received: by 2002:a63:1a45:0:b0:439:49b4:9672 with SMTP id a5-20020a631a45000000b0043949b49672mr11177300pgm.551.1665286876512;
        Sat, 08 Oct 2022 20:41:16 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h129-20020a625387000000b00561ed54aa53sm4353776pfb.97.2022.10.08.20.41.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Oct 2022 20:41:15 -0700 (PDT)
Date: Sat, 8 Oct 2022 20:41:14 -0700
From: Kees Cook <keescook@chromium.org>
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
	sparclinux@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v5 0/7] treewide cleanup of random integer usage
Message-ID: <202210082028.692DFA21@keescook>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ZhbF7auk;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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
> This is a five part treewide cleanup of random integer handling. The
> rules for random integers are:

Reviewing the delta between of my .cocci rules and your v5, everything
matches, except for get_random_int() conversions for files not in
your tree:

diff --git a/drivers/gpu/drm/tests/drm_buddy_test.c b/drivers/gpu/drm/tests/drm_buddy_test.c
index 7a2b2d6bc3fe..62f69589a72d 100644
--- a/drivers/gpu/drm/tests/drm_buddy_test.c
+++ b/drivers/gpu/drm/tests/drm_buddy_test.c
@@ -729,7 +729,7 @@ static void drm_test_buddy_alloc_limit(struct kunit *test)
 static int drm_buddy_init_test(struct kunit *test)
 {
 	while (!random_seed)
-		random_seed = get_random_int();
+		random_seed = get_random_u32();
 
 	return 0;
 }
diff --git a/drivers/gpu/drm/tests/drm_mm_test.c b/drivers/gpu/drm/tests/drm_mm_test.c
index 659d1af4dca7..c4b66eeae203 100644
--- a/drivers/gpu/drm/tests/drm_mm_test.c
+++ b/drivers/gpu/drm/tests/drm_mm_test.c
@@ -2212,7 +2212,7 @@ static void drm_test_mm_color_evict_range(struct kunit *test)
 static int drm_mm_init_test(struct kunit *test)
 {
 	while (!random_seed)
-		random_seed = get_random_int();
+		random_seed = get_random_u32();
 
 	return 0;
 }

So, I guess I mean to say that "prandom: remove unused functions" is
going to cause some pain. :) Perhaps don't push that to -next, and do a
final pass next merge window to catch any new stuff, and then send those
updates and the removal before -rc1 closes?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210082028.692DFA21%40keescook.
