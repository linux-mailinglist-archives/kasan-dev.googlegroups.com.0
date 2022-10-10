Return-Path: <kasan-dev+bncBCLI747UVAFRBAWMSKNAMGQEU7NEYBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id DCBF75FA82D
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 01:08:51 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id x21-20020a5d9455000000b006bc1172e639sf2800156ior.18
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 16:08:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665443330; cv=pass;
        d=google.com; s=arc-20160816;
        b=OS2JV0zSZaCe2th1MCfhlsVpU4AdDfHPeHUiHwJs6bveDcg43+8GlvKXLLwVRHHeRZ
         3vuH1lKWwXX7uMraSkDwwuSqrtFHT8l/fmi+t5Zj5a0mF9qLP+OmnydJCJDJHTINdoLv
         R8U96Uj7WB4+de5SarlCHkKm8oIvhvTHyi5nRVLCTjV27Rx6l+v2ZrVl/HaZOLvOKSqw
         232SjLBG4mUZiFjBwW1CKd6WEYtYKgqSC1huHvwLj4sd3mEFD6vtFVZf07Ws6r1aaV3T
         T7yC9I5ahrD12Y8vIURuDJbOqjHb9qkqzIq0jTh3mG1SDyE5WW1rPPj/gg78CcHkkKOd
         a7Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HD2GDpQvCpRpn2lovY2wQkukE9AJ3TiF3jR/0GBS6T4=;
        b=up31bDfu8TUI1cAGJTemXZ9eDv2TZFU0Nkdxrx74D+dgzT4uy8geRhtgN1IJ4ncm/o
         49E435Q0idBW45HQ2BFbJShx/6ZNhsPVXTR3rxsfAztKz6G0P4gmMwyxfOWP2qeSZEKU
         xcoQq1HWFXubTVxcJ3tJX9oZp+Mj6r6Glrrl/vdljwOqviJV/uID6p2oCeixf72ePMdI
         pwY11WBvIB1q2eW8gHkCKyyj9bsibT8FIPUQtrhfDNtZg/+sg+VwqHbzpxA3j+f9kQwX
         z2OiZMzWHSrEDn6iXnoY3a9jQ7MEw9N5nIExJkIr2NpdpW2duNtJiaI3kCO4g9RPlggb
         yaYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=PWVmhODf;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HD2GDpQvCpRpn2lovY2wQkukE9AJ3TiF3jR/0GBS6T4=;
        b=mOcULXWKlC7GOS4b4BnnzziVo1mLPMXCNtf9Qebx0GyILrqBrHG/tF6oZqdVzUNyNx
         KEaNy92gcv8sE7uxYoZ5TCseMX8LUpxmqVPXLP5giKeOvrAdcsVQLnenWxzOkdVTd9up
         szZKpt1GectlpRHuk6/nH6rg8f1T+qbOwfyeTfDd31YG1QVWuBHlgbjIFk1UxNL6rnoF
         2+EvHtf6DVYOR1mDHLPtQaExXxqo5zDJ3UUT9xG2Drk2hH7bZhkMZPvwp07YIDE+7f9i
         sG0Iut1htlTwEI2ZoiCpGTaOa+erElmm3Piihdt2b/mSj4yJ6gD2PPIPTx2ePLTsPbNm
         qjRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HD2GDpQvCpRpn2lovY2wQkukE9AJ3TiF3jR/0GBS6T4=;
        b=3dJtkshv8332bLPU9tZGRyJgjydXwwOjJi0fDIME4r+ie1DQGXerZ7tr0xCTuVti+4
         PVRUYL/PTLVOJlUyy98Y1SiCBps/+t3KZrCPZkshDNx1ICeS9IJgh3hejyrI6fGnlJ2h
         37w0EAdinVAXChAsa5MWJK9qXCCTXXb7YfTDl3qwKW7PVXD4NpTeQ6dLrZwXQN8y1iQo
         PaYc/ZsDK6CzSoWJuV17GltSOs9Vrci8vRiubRBBGrS1i+vHVAgqn9ZfnPyFnxZ3Ko58
         kCqDITibZFPFTaduWwwRgPlpj84RHFVVcSkQf8KW4yIJfaGuJ0pVSKuy2xP4e5kbDXOB
         heiQ==
X-Gm-Message-State: ACrzQf04gnNJuD4YEB2yvCGsvCVvVfwgAA4HPD3dUNnRwLfOd8rZ6Uv1
	RVAYGhNQUF0pLrH0HzeirW4=
X-Google-Smtp-Source: AMsMyM5B4XVJo0A9A7Tlg3yMYtvOh5o9F9NkxsHg++C8NuTyQ3QLPdR+eXYxVDg4swgpORCx7qFkYA==
X-Received: by 2002:a05:6e02:1d13:b0:2f9:e9bf:ec85 with SMTP id i19-20020a056e021d1300b002f9e9bfec85mr10270546ila.164.1665443330720;
        Mon, 10 Oct 2022 16:08:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:8507:0:b0:363:bee0:a7d0 with SMTP id g7-20020a028507000000b00363bee0a7d0ls626555jai.7.-pod-prod-gmail;
 Mon, 10 Oct 2022 16:08:50 -0700 (PDT)
X-Received: by 2002:a05:6638:1452:b0:363:d083:c7b8 with SMTP id l18-20020a056638145200b00363d083c7b8mr141505jad.83.1665443330274;
        Mon, 10 Oct 2022 16:08:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665443330; cv=none;
        d=google.com; s=arc-20160816;
        b=o1pp7yS98Oa9raswOzps4Anejp3mYrH5h8LYTjWNBY5qbuglfCgHH4zxx3ZLdxofRg
         nV+xl+tLAP5j2uf8i8vfzk7MZiz1zfzXmFHWGXfJhlvJaldwdrMt0HuIWBqVr/w2JQyo
         EuvnNEbupkXI7RD/paGBQgKCjdMuVC5vot/B5IuAL3KZlyyexMZd6j9ZnCVPCZub9XpD
         LOgwD2OgAYJ1RvjnZ1dLiGkuA3j9ghPacOvi3AY6GHLzVeIJLQ7wgXtI2t4kk/qUwAPA
         a1JA0nIBqWi23iSH3gjwOp1Zxztl34ogNPa52omejdLq2I5FRPvmvQTPUVYmtSj/LR09
         PPDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vIB8SkXJdq9zBFlYiq2VoiImKhyYI+n+MyCUYR8RA5M=;
        b=xvmdUW3Mq13ZRQF7JQWyQeZIMZ8Lu5nwyoJqthgnVTKYb6ra0/x9+WKLEkBf6dLuPm
         2Lp5Ev5bRW73TANz/2Ik+r55+kTFvClTYGTRHU97zEipsDgFfRCACyBC2h/G1j3JH4cC
         n6mwwG+M8JsCN602bhfMVIn15jSYyRjbuuPy8q9qRLo5QDnUSJaoV2rqL/j3Dtf/K8By
         Uwsfrljo8Cfj+H6sg3rg98fzrqHyRhCoXkDts3LtjJZK8FmN9s15bcnQReMxxsqil4lm
         6FahZqS+3G7rgIIVuSjoJ7jZ8ouX21Fe+ZoB/w/F3y0WF+QByFLfG25h7Wu6rmuMB2M/
         4j0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=PWVmhODf;
       spf=pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n15-20020a056638120f00b0035a25c888bcsi396434jas.2.2022.10.10.16.08.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 16:08:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EFB8261062;
	Mon, 10 Oct 2022 23:08:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 787B9C433D6;
	Mon, 10 Oct 2022 23:08:43 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 4caf0efb (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 10 Oct 2022 23:08:41 +0000 (UTC)
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
Subject: [PATCH v6 7/7] prandom: remove unused functions
Date: Mon, 10 Oct 2022 17:06:13 -0600
Message-Id: <20221010230613.1076905-8-Jason@zx2c4.com>
In-Reply-To: <20221010230613.1076905-1-Jason@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=PWVmhODf;       spf=pass
 (google.com: domain of srs0=yjjh=2l=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=YJjh=2L=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
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

With no callers left of prandom_u32() and prandom_bytes(), as well as
get_random_int(), remove these deprecated wrappers, in favor of
get_random_u32() and get_random_bytes().

Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Yury Norov <yury.norov@gmail.com>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 drivers/char/random.c   | 11 +++++------
 include/linux/prandom.h | 12 ------------
 include/linux/random.h  |  5 -----
 3 files changed, 5 insertions(+), 23 deletions(-)

diff --git a/drivers/char/random.c b/drivers/char/random.c
index 01acf235f263..2fe28eeb2f38 100644
--- a/drivers/char/random.c
+++ b/drivers/char/random.c
@@ -97,7 +97,7 @@ MODULE_PARM_DESC(ratelimit_disable, "Disable random ratelimit suppression");
  * Returns whether or not the input pool has been seeded and thus guaranteed
  * to supply cryptographically secure random numbers. This applies to: the
  * /dev/urandom device, the get_random_bytes function, and the get_random_{u8,
- * u16,u32,u64,int,long} family of functions.
+ * u16,u32,u64,long} family of functions.
  *
  * Returns: true if the input pool has been seeded.
  *          false if the input pool has not been seeded.
@@ -161,15 +161,14 @@ EXPORT_SYMBOL(wait_for_random_bytes);
  *	u16 get_random_u16()
  *	u32 get_random_u32()
  *	u64 get_random_u64()
- *	unsigned int get_random_int()
  *	unsigned long get_random_long()
  *
  * These interfaces will return the requested number of random bytes
  * into the given buffer or as a return value. This is equivalent to
- * a read from /dev/urandom. The u8, u16, u32, u64, int, and long
- * family of functions may be higher performance for one-off random
- * integers, because they do a bit of buffering and do not invoke
- * reseeding until the buffer is emptied.
+ * a read from /dev/urandom. The u8, u16, u32, u64, long family of
+ * functions may be higher performance for one-off random integers,
+ * because they do a bit of buffering and do not invoke reseeding
+ * until the buffer is emptied.
  *
  *********************************************************************/
 
diff --git a/include/linux/prandom.h b/include/linux/prandom.h
index 78db003bc290..e0a0759dd09c 100644
--- a/include/linux/prandom.h
+++ b/include/linux/prandom.h
@@ -12,18 +12,6 @@
 #include <linux/percpu.h>
 #include <linux/random.h>
 
-/* Deprecated: use get_random_u32 instead. */
-static inline u32 prandom_u32(void)
-{
-	return get_random_u32();
-}
-
-/* Deprecated: use get_random_bytes instead. */
-static inline void prandom_bytes(void *buf, size_t nbytes)
-{
-	return get_random_bytes(buf, nbytes);
-}
-
 struct rnd_state {
 	__u32 s1, s2, s3, s4;
 };
diff --git a/include/linux/random.h b/include/linux/random.h
index 08322f700cdc..147a5e0d0b8e 100644
--- a/include/linux/random.h
+++ b/include/linux/random.h
@@ -42,10 +42,6 @@ u8 get_random_u8(void);
 u16 get_random_u16(void);
 u32 get_random_u32(void);
 u64 get_random_u64(void);
-static inline unsigned int get_random_int(void)
-{
-	return get_random_u32();
-}
 static inline unsigned long get_random_long(void)
 {
 #if BITS_PER_LONG == 64
@@ -100,7 +96,6 @@ declare_get_random_var_wait(u8, u8)
 declare_get_random_var_wait(u16, u16)
 declare_get_random_var_wait(u32, u32)
 declare_get_random_var_wait(u64, u32)
-declare_get_random_var_wait(int, unsigned int)
 declare_get_random_var_wait(long, unsigned long)
 #undef declare_get_random_var
 
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221010230613.1076905-8-Jason%40zx2c4.com.
