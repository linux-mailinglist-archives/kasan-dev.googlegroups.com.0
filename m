Return-Path: <kasan-dev+bncBCLI747UVAFRBK6TQGNAMGQETNKLIDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 00FE55F7CC4
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 20:02:21 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-132ac95c2absf2973186fac.23
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 11:02:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665165739; cv=pass;
        d=google.com; s=arc-20160816;
        b=RYo45BosopL/yBJzOeY06jHYSR7Bto9xoobtVLEmMEJvnrqE8zBKIXoNaPHdVkl60O
         v429Q+VlE3CCc8qT8keitLk4ef0ILt/vjSXwJ5rgga6Ab1gmkdI+g/bEIoRE5jp1mfGm
         tYZ9UhDtRi7Paq8myhPcGIN8cffWrPvVcRIRvqUljPj8G8sfzkp+oEZBLGFmlGmgXodB
         L8l42GSWwiQIhE6z50iz9T13mLd5WjJnJhHD1icElewnBo8V6uLggdvdqDeENcqKHPAE
         UJraV+qmpQ+1GehZM/XwOhjQgdqkz385nii8dnpqY+pq1mLXNZYO/0VXYxviwffboWpz
         /+2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hspC1RysWtWG1QLHGMFD2YvHjqUoGQsPgqENlJ1UXEI=;
        b=YEEFTwvq52GO26SO7gDN0HJHyZ2mVDzfQTc4s4uri7tNVNTdddY6up2hvke29Gu86/
         LgwfvdroJNM9QWtpYu9NUfnznffdVEi3IpUylc6lFQXYJNrvlCVdTga9bnLrJ8fFjvmk
         QejGDdMQu5AdMvv11EYUu2eUlO2ISBf2UJtUqI25XjGI/PFRvVFht5c4yFIqplz9c3i1
         uCAlUpE3vGhkSlR8iEI/+PZf1P0yT5mxpu9yrqLcdEAoE7DFb0t6+ILQXHM6YTg5S7rB
         LS3v/ZKuru2t19UkhiUeZ94iwL9TfhX/RpOrZofmDgDdg13Kv2TF8shuJQBAcrQ4rhUJ
         ZF7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ZNjDptlw;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hspC1RysWtWG1QLHGMFD2YvHjqUoGQsPgqENlJ1UXEI=;
        b=BEEByZ1IRqP3RgoMt1BWWjE+XUeZwWDqhPjeXEbp4c82g/U+PqrRQDi2pfczqy1hx0
         TzpbJiTNfZs5fVf4LVroqYZ8ywGlB2TsfdHgLXmaH2+ZFzSVA8y3toMiyck+EfQRaLKz
         4Cu4EAaso8insz07qdiOceqSNQFC2qiww7orrF1tABYSDw/E2cu16yTlCmA9HCbT0dTo
         YbPoT1lDV26ogReZwXCikYsRWGp3fxRqtAibaHmBr2Kiqa6PfIm1VUdpIlaI9MeiKOxI
         G3T3hivvBeBI4ZtpFn1WOlIDWjt6CApKpyUzrJsShsqkVXHKfSu6GLVhiLGiCl+dJakQ
         oOfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=hspC1RysWtWG1QLHGMFD2YvHjqUoGQsPgqENlJ1UXEI=;
        b=DsI3IHG4qDJWjGIR9ZhC7RbeW/yqQQLVPCXXHgIpMQOjuVJRuR8To7r6+8DYvEBsVR
         nIYY3/L5VuAFq8fP+lSJfM/pItntl87Jh9DAiWpp8jFi9Ad/eS8fqXmFWMmK+at1z3yP
         WPp89dBJcyeAy0RQjjYB8oj8uLt9aaA69Nuqkv+COoDCB7iKmMPOuJ0+AGiJYD4bJotK
         MM8t1El522ccjDO6RhqHDlGMSOZw6UBm5h3zQsOA3M3HGeoiBZuQNgsgM/XY3FmvIjli
         JpM8XbW/TEuVq18LfpXw9umlZpfwnV34xpgehVzjkxpVcKC23taONfLlbxBkIW2woKdH
         URYg==
X-Gm-Message-State: ACrzQf1VfdeJth8Dqgd+kxISAP+TnFGiVrPsOli7LKxxSTR6gdzPpv0U
	TfUCK8MDv/HB8U6PMamwpYI=
X-Google-Smtp-Source: AMsMyM5eXy/bH/QTgSMtPS0ydBA253c0paY0R1/Kblg3bDCgOKrKOlvo05vDdCGtHLWmQhHx7I8gig==
X-Received: by 2002:a05:6870:14cc:b0:132:8901:7cb3 with SMTP id l12-20020a05687014cc00b0013289017cb3mr8734084oab.21.1665165739767;
        Fri, 07 Oct 2022 11:02:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e287:b0:132:302f:c297 with SMTP id
 v7-20020a056870e28700b00132302fc297ls1824132oad.1.-pod-prod-gmail; Fri, 07
 Oct 2022 11:02:19 -0700 (PDT)
X-Received: by 2002:a05:6870:d212:b0:125:f06d:1a92 with SMTP id g18-20020a056870d21200b00125f06d1a92mr3252297oac.242.1665165739161;
        Fri, 07 Oct 2022 11:02:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665165739; cv=none;
        d=google.com; s=arc-20160816;
        b=wEONZrBXAAewjFD/LqWq2hxsBIAJ1zUj2f5josQIfmic5r3waZpRYNTTq6hAshSoii
         FnupTKrbkZPYen4jQcf6WvW4CYUXdQsm1W3HQ6/Miils/VT6LuelHUV32Hy9pyQfnEiM
         XUMZWlDN1PsyW/W7YXZcZQOXIZl0QWy/pXvEX9YgBpasRTwtA2y9ySjuQcK6JdwtWFG/
         gY/RGG76/BhV5W1MI9nl+NXwIRm5gkKO8TlpN1N1MpiNttx9jP/92zlkZcROU3Twrhpc
         /NiTUS8y9FcuVfisR5LVlhdKebeb9NqyW8xFpq3SNb95yOuJAeS3WMh7Rl/roJEm/zi3
         nwCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wugUkH0LlLzYfPgynaJ//AEyTMustLSmvE+oyYjIDcM=;
        b=Qo1ISKWTQRu+lqO8EtOm6KT0o+THzCPs974c6T3oqvX5vnDQVPtWXucPI+XNL1Phn0
         25/gwZ3HvGOVTSwsOjPvDe3wTEIHC+6h66IHu74LJp7QUq81tjwv72z8PV9h+HGofvI4
         IKQX4J3pMnVK2KyZkJSigH2G4TKKMw99IDBOgn6NtXtgGZOmhNqIbtubS9PWtefxx1a2
         ItyOsIdMkI+9fVx0jhi+HnrGScDK+QZIiQx37FTy50pNX26K9BZHlM1hvqao3kUXr+ZQ
         6QU7Dl9/XysU6T+4R/lm/ev/iXIhijKv4xHKZY9h+z3QLxhY2Z3C23h9yOwTDNhZKa1n
         xNuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ZNjDptlw;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 66-20020aca0745000000b0035446541a0fsi41389oih.5.2022.10.07.11.02.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 11:02:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EF0C861A1B;
	Fri,  7 Oct 2022 18:02:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 63A14C4347C;
	Fri,  7 Oct 2022 18:02:12 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id b5c9a69b (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Fri, 7 Oct 2022 18:02:11 +0000 (UTC)
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
Subject: [PATCH v4 6/6] prandom: remove unused functions
Date: Fri,  7 Oct 2022 12:01:07 -0600
Message-Id: <20221007180107.216067-7-Jason@zx2c4.com>
In-Reply-To: <20221007180107.216067-1-Jason@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=ZNjDptlw;       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
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

Reviewed-by: Kees Cook <keescook@chromium.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221007180107.216067-7-Jason%40zx2c4.com.
