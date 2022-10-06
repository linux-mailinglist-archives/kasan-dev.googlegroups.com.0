Return-Path: <kasan-dev+bncBCLI747UVAFRBTEQ7SMQMGQEBSCAAEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA9AD5F6C18
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 18:54:37 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id t24-20020a19dc18000000b004a20fbbbcfcsf833853lfg.6
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 09:54:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665075277; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tu+zMMY0Gr82ykUcQqjhdnKU6PFdSAiQNXlRz3hqQG4ElVvcnrKFFh4sn19hWjH9PU
         G2XZXCbMRXMBCdRmmpJlr8wcrRXg7Jf/+XFsjNB29eVk7oGOHvzzwu0tKU14eKNVOtiS
         fwlDVblj64ZLOL6PS3SdZuUPqvCf/uZHfOkGUMPazOeRAYfXpaOSLbLM96KZWVV8/JOQ
         kEHPAqXT+eRSXBR1WX+zjThSfAJehK651kShNW8M7NapNpmOi3D9RgdJHOy87hCPRXH5
         YNkLk7WPl68WxRMahgUKph0l7qje8TSTm7/6SgyijxX2zz6M66ymcmebO29u7Jzm70+9
         A3Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YVzw4mE5UlayUzaFSji19L66ULPm4//TlRxhjLlEK7U=;
        b=bJf70Z5HAnkBbYtb93joZ2wu51w6Ue/tlGiDGT3k/HVYrzxRlomy4m9DTehiepnD4r
         4dSh+rJGo8s8nmDbBq/iAyrTl1ghz7VgJ4n6vMWp6uusWK7Gm1jWaAEk0A8vy4J++dJ9
         n7rAanwHgYSFmCGvpcrd0CxFsyzOFLrlPe1N6i/WMa060i6xmuKij0Jl/6XVC3ZVbxz/
         EuTrNW8NOFogZdJQ/blaqICNeV32GZrCxU40BU6ieJQs9AyJwYeZaJqdNhaj0BnSi26q
         lAmMka7c+PSWViRUWDqevJd5seAq798F3KSKo32hD6hnoSlZAat7Q9pWMHyWMSQhkix5
         RRWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=FFz7TrE8;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YVzw4mE5UlayUzaFSji19L66ULPm4//TlRxhjLlEK7U=;
        b=b8x+fc2DYlh9F18338CAqeKwflQpl5FtBBpgalxufcA9HKSAMmsipxCYH+XykHlPBk
         NiIusFrMhhMeUi21t/DvQUfA/ErRmbUDELbiIO76oIB70g9lx4xOHJgMtO4OyaVAIHlm
         icI+qaI3/1uwAj0rCOWXoZg1tn0K7VwhPRbHqQ8c8URipV0GwyI86VElK+H57+i5otnl
         hA6qSe9Sa2T6WRtI0TOeHsEcbGmsGQLB1SkUs5qkyMHPyvroEyjMgtzEv+wNFeL/5HDw
         a0H7xcxXqnnVrlsCx28axoM0s81N9B8HKo0MjgiUxdtIywAz5xZyoIIy4771WErilw5+
         70fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YVzw4mE5UlayUzaFSji19L66ULPm4//TlRxhjLlEK7U=;
        b=o/GhjOlp0ItDwaJdDqEAZxl7AGEGiARjV/4EUG2xxGnR8veqVF0l5d1YtN0ULg2r8E
         A3FMfsxKdR5O4IdRGo2v1Vz78poKrh6ii2DEilOqZs2Fep+5QCxVJ/CEyTr+2CKl2K3q
         aFT8H4+P6oXwp3JxJxjKk8JAQpI53tLuQCoabc7i7MQZhVz36PpTMTIum77EglGInJyI
         8r1QYOBJ4ABRwK2s2CRWMGrvwtQCAscINPXStvu3pFBb2PiwZUSAZ8OBOpFZQnv3SvJ6
         8/mcpDsUsDFbGEtwpgfsqiv9UhxEDOmPDtMIlYq5y5Ww4M3TzJtwQpyUuuG35MsQnWKN
         If6Q==
X-Gm-Message-State: ACrzQf1turwZiFe6hpy+IAlbGF6tsUSHJ+YhFJN9uHXFDD3rabE5SAZ5
	qqPIED67qg+dcJcosqOTwoc=
X-Google-Smtp-Source: AMsMyM6Stu4VZ1ogQX1Ov6ovXdeT+cxWwApXo2bedbZuooWv2jV3eCznRqPr6kbqoYDpn9qyO9vYRA==
X-Received: by 2002:a05:651c:98f:b0:26d:ff18:97c6 with SMTP id b15-20020a05651c098f00b0026dff1897c6mr214401ljq.375.1665075277195;
        Thu, 06 Oct 2022 09:54:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8607:0:b0:26d:b66d:2004 with SMTP id a7-20020a2e8607000000b0026db66d2004ls518412lji.9.-pod-prod-gmail;
 Thu, 06 Oct 2022 09:54:36 -0700 (PDT)
X-Received: by 2002:a2e:7804:0:b0:26c:463c:493c with SMTP id t4-20020a2e7804000000b0026c463c493cmr209100ljc.521.1665075276005;
        Thu, 06 Oct 2022 09:54:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665075276; cv=none;
        d=google.com; s=arc-20160816;
        b=TIt0TQBigCKwlXiOXSgmnGlQOqoiJVz1Lj7GZbI0bfG96xOsyHVqIGHyWpYcU2ZAba
         ea9QXcGOmXIlnVNsZnSflWebAtbMuBHZvskXO1YUXFjLMlQWJYKqTWcafQ2in4wWRClO
         QCIHSNnHZ3SygvDFQhU8iOqH4JHQCIa5DIhQxTPryZFLVtrvupkXAxPwXBhcWe4sEupt
         I3nHkljYnA9pIVqa4hyaaCfNa5PxVX0O77PPehdFpX49W2gPTwEzvYULDCUl3Q5+3d0U
         Jm+QezBMU3fv6yEHdzKDwAIDGjqCde6tQQsn8815GoZbnFGmzFMExtYQF4hScQ85f/qi
         g8Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wugUkH0LlLzYfPgynaJ//AEyTMustLSmvE+oyYjIDcM=;
        b=vM126BtI49i91XcwiN/2C6PJGl6c2sUDjdwJgQXzMOfs8OPX05o/Jcquo9W2jO2dRq
         gJmwWJAYRcIoRKU52VKw4LC7XgzOE4+orxx2P1G8LamCu/iaeNpZwTQPkx7OfivrErXF
         AzqGM2B7/GMx9tHb+cBHGATRi1gTBKXmorbMSOH9HLK/tCx4nR6eplGocliWm7FACyxb
         JtzB076M3sJATBUGi5193h/unwsFsQDr67CCC++EvfO3BjVCl10pP59sRGqjBwdzKi0c
         Wevb7hb9o++uU0vl7ISYROBlKh6MvcUx3OAeCTxuaahmPkZbhlW53pFhIemIeboQ5ZSE
         L8Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=FFz7TrE8;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id k21-20020a2ea275000000b0026de0d11d91si426321ljm.3.2022.10.06.09.54.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 09:54:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 78085B8211F;
	Thu,  6 Oct 2022 16:54:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40F56C433B5;
	Thu,  6 Oct 2022 16:54:28 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 0c028fd9 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 16:54:26 +0000 (UTC)
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
Subject: [PATCH v3 5/5] prandom: remove unused functions
Date: Thu,  6 Oct 2022 10:53:46 -0600
Message-Id: <20221006165346.73159-6-Jason@zx2c4.com>
In-Reply-To: <20221006165346.73159-1-Jason@zx2c4.com>
References: <20221006165346.73159-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=FFz7TrE8;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221006165346.73159-6-Jason%40zx2c4.com.
