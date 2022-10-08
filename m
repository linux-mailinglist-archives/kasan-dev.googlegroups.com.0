Return-Path: <kasan-dev+bncBCLI747UVAFRBAFCQSNAMGQEIQMI3CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A1FD5F835A
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 07:56:18 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id w13-20020a05640234cd00b0045bd246f73bsf154996edc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 22:56:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665208577; cv=pass;
        d=google.com; s=arc-20160816;
        b=vqpX6+cazT7xrsHXjzQoKQLWjFyIzIDU/jue5OPlarJqKsvgDQ0maAqE5ljk5JVrm2
         Ekb21dhsm38P3ZZ5sdDr6db8STgidG7veKuvRTnq+cAA3K4PGnormlDKfJWYD2YENmk3
         g1opFfW6t5jQDeEdDs5yp21LxUtjAl+G0qQhNxFV/iMQ/NjnL94t76XdlLWVI6ZNB+Rl
         v/BL8EZJY4C0RisTleTHtbpeqyXkyUMbuUuhigjkGgJ9muSl813qVT23TdMinEMYbFGR
         1u9ZHYbz9RInrWXBNVl1C8aDluBx0YATBJg0w7xcZ7hSc7pKI0LS3f1oa+lJrHUJhzRB
         GYgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Kv8FcE1Z3xnzgm+6cBm0lywUjsy+I7JJjvPo5wAjub4=;
        b=FfHajBfhA0YldIbQwtLk9284eqPabIaAWlaTlA7qFYoXu/6aRJSbFD+lzDFVe0673i
         jitJnWB4zKK7n4af/FnnjzrZQIQDgfuZmlsF5+kD09Yggdf3IE4mEx4WbT9yx5ic10+m
         YkW7l8TCDAHqWy4s2+36GLNHZ9A/cFgcLBUOGMSNNkWuH2tNT3qMlNrv3Kb5bmkwUjdk
         mDLesVQfaJC6e88UmWcrrF6ZUKO4KGzqkSBOABjMr/E012z1lL2lEe8oMA5h5oF+U31i
         kNbn/Th5JvPcOFtyg/+yY0Qpc29RLKeQt21W0CbzeVNPh8P3Hqt7EYafsspA4jP9lBf8
         n4xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Ga77e3Gb;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Kv8FcE1Z3xnzgm+6cBm0lywUjsy+I7JJjvPo5wAjub4=;
        b=ZW/ioXH8juDVLF0tfkSGcyJ1H5pKUG5BVYMj6ga660E+CFI9LaZfrbmpsbwgmq58YH
         RrSrd8631N70/DhYqz9V7rK8lY4v+oqHkYjiAOwH7QP298FWbZMOC7yaAhdYGp/iMdzf
         WQlD/4+kl9PtVw+DwNJsmt5IV8j9G+pvscCdExhHbyPb2vrxyCVx4hP4B6ypx2gN0I7P
         tjEXCGBn2+TkEUYQSHA0Bf1i75tfGI1CQ+ArYlGcJLY0DlDUACYdI3p4hvlvib5BQcMw
         K9kA0aH+QNKP1FewYRXdykQ+wB9lYoXEsJDcwcO6Ok2DDDydIbjZbQQ01SLPLlGz1kJf
         6jGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Kv8FcE1Z3xnzgm+6cBm0lywUjsy+I7JJjvPo5wAjub4=;
        b=uNPfSALwVdao5cCSdZtCEGzZT11NkQ0k4PZKTVMAZScpHwKR/m1y3uCfPOKcfFNByZ
         Z99b8O+Htp/4O2w2QGQ90eH+Gx+uG7TLeiiY8rAfK8if/GQ1WtbRSUPw3yfwkmvLdgVn
         KOQO6HdzZMGe0bvJNbSvXthn5gPUdtJfHlS15riwKsEGUlKYKr3r/X7A3QxOSNbfvnqU
         OAQjc4DiWt3NGpwF9zQfIe/6ngvnSnbo6e/BOYfAoLhPCvmevPZ5L42F3iBzPEp2FTD6
         0d+IKlyfkZXyori/bJwFyuFbgkY9YY0zV436BbJY3W/h+J1gDGNMqEr73xT1E4jpdvLP
         dtSQ==
X-Gm-Message-State: ACrzQf3LbiXV8mVfinBxN6rmnNypGQxyOsXJfUWPk4zg123Pp06o/x8d
	jUATd55QtIq8bkFJHhVMv8k=
X-Google-Smtp-Source: AMsMyM6WpM6l4yX5euyTMP4kx6CVZwUv7VpYSLQiEjM79XvSd+RWSSGNUg4W9JQlnlkOz/2wv2qcUg==
X-Received: by 2002:a17:906:cc49:b0:78d:361a:561e with SMTP id mm9-20020a170906cc4900b0078d361a561emr6846676ejb.741.1665208576552;
        Fri, 07 Oct 2022 22:56:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f296:b0:783:b20:46a0 with SMTP id
 gu22-20020a170906f29600b007830b2046a0ls1955810ejb.6.-pod-prod-gmail; Fri, 07
 Oct 2022 22:56:15 -0700 (PDT)
X-Received: by 2002:a17:906:9b87:b0:733:1795:2855 with SMTP id dd7-20020a1709069b8700b0073317952855mr6830296ejc.156.1665208575189;
        Fri, 07 Oct 2022 22:56:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665208575; cv=none;
        d=google.com; s=arc-20160816;
        b=zyGk4UQ79whcj1dCKZgpMie3aGG5OAImXIrDKZa+EzX+THQViapHf9bPUsO6r2u3+j
         yPH2QLOd4iajyMg35SwkGYGuT0t/HJcUDAPc/NTivhpOM59034b8dan+nAPFr2COsRV3
         iu9kMKAFINZEdJ867cbjMauUL/Dg5t2uCygLH94fvqhSfhX96t9O34WfGlpgVsvc1IPG
         7xIoF9DMCtkzXS+O3Lace9R4x5YtgD5D0xG/aXKO69AsK+Hsu0y/5QSWJRmmoqyghKtf
         gdM0MhKhKP/AXThjGV+keRObMLQihuNLNaktqRQt3DAPSll7QyXLA8KqY1xviouioE82
         Hzhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wugUkH0LlLzYfPgynaJ//AEyTMustLSmvE+oyYjIDcM=;
        b=n0wNnzZtUJO4yqZXfOGK/UR5pYPXX9p+sTY+fcpHDO9Uw70qFNVhcKb/UsTFU7b1nP
         dhYEUSAXaMPhPyWuoRKl7eN65BQWva5ZxsuA2oApw4B21Dpb3J2ON4iizE/NqTLFqWzh
         yhy309X2jklZBCSNY8M/jR7DIxr+t+8YddDAHxE9nzON9n4WTPJmT2LMQbsqLABPD9xn
         ZQVTk488+8M3ig8dF7iNgTiRTwOLhUlGeaaq0MHPJ1jEvkHbF8BfUJBJwes7390NPh6Z
         WF60e59dsFJpsk1qm3G5va85XWspp6p1ju/eR/GMFY7+hOp0Wip0SSS8forDdpHu1xYE
         pSGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Ga77e3Gb;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id q23-20020aa7d457000000b0045bcf2bacbasi12473edr.2.2022.10.07.22.56.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 22:56:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E4552B81E4E;
	Sat,  8 Oct 2022 05:56:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 70FFEC433B5;
	Sat,  8 Oct 2022 05:56:07 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id aea478ca (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 05:56:05 +0000 (UTC)
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
Subject: [PATCH v5 7/7] prandom: remove unused functions
Date: Fri,  7 Oct 2022 23:53:59 -0600
Message-Id: <20221008055359.286426-8-Jason@zx2c4.com>
In-Reply-To: <20221008055359.286426-1-Jason@zx2c4.com>
References: <20221008055359.286426-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=Ga77e3Gb;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221008055359.286426-8-Jason%40zx2c4.com.
