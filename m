Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBAMNW64AMGQEDD5XH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E2FDC99DB87
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:33:54 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6c5984bc3fdsf62497396d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:33:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956034; cv=pass;
        d=google.com; s=arc-20240605;
        b=JLd3WGlJMJVn5sKRR6MmOrmVY+8twcoyv4ozGCUGEYF20knE0ty4EoyIz6kAeOY0gb
         iyNHNjhtPO9WuQdVG5GJCVKhk5uduotBJ4CgrnsUHozphqoc7L/B6GksCPzM08NK1MkE
         ZvcW5RrrN1rTht8crx67P3zp0h3h0fcVh2OYzLicwDcYhQuPrc7UYn+QWPIuPxg8EHpB
         ha0URYQvx0Qo2S9Gi/zPCBJpQo2gKN0X+DTbZWEjviu52xodZWp/1/9w4T8F/cW8hsjw
         hjMkiWnH/Lg+w0VBbZZ/qSSzf9QmRmZOcrFiN3LsVcVJP3CZrOT81OHaU4JL30rZEX9n
         /NaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cF/fbCxY7f5gmDZSGLv+LM+lQB9k7Qr7x5f3YzTniPk=;
        fh=2PmFNF0IJmP7tHs4csm+d9koQbSxEMBdZJa3++oJGsU=;
        b=k1rSzCMdhIW7WY/v5kE5Idtu/sPfHJAdalQyeqC69nXJBr8yWrbdHO/k7Pe9dnw9vG
         uBDcM+9FARfSnAACkXqP+jeGnXR284jM8VXJgnpmynfiyO80IYWuRBan01BDX2ClFDqi
         MerimMfzJxuXDyXKqSEPG0PMawL3RGtWBdK8RPToL4slI8Cfi7YnjcI+UN98r016s8aH
         nkQgtpp9G5YQPOP0ASdxlWZdL4s47hpI8jFAHixDU0y8bzgwTlTfdDaUGrmXmEVERaR+
         M4xALqqNifgEX2U6/jk2v2TbJcPD1CoSqcbiMLkR23tNXsaCfw5UcC1p97V1EtuecXiZ
         t5kQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lEkRBe6M;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956033; x=1729560833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cF/fbCxY7f5gmDZSGLv+LM+lQB9k7Qr7x5f3YzTniPk=;
        b=HpoXcxbNCIOe6s86X0hboP5cobhnDxzVPal1vhY61qiQeYq6oWG5EfFcQT6m2ptSyg
         Yg4z6GBVvgjkJVHQZvXxqdQE28zeT4y2BfCB4+aRpqBplidp90jaehH/jbQ4KXN65zKt
         ZKxc2OqMSxYUNOPrev2bXzlcYEUPsiK/1yrzdZFa5+P4nB8uk2zhkJtOo9M6FJjCtiOr
         BrrOzOCZMuClYGEnPNsvkd95UCpVflDOJLVXTSn0Vc46urIKoWnlnjdheudTf5N9ZNGM
         FzewEUBahKriDH2o5DLLpRNnrvCi5B18ywkrXlpjj7w4zZQew8n5vKk+bMIDFkdiLWRy
         C4jg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956033; x=1729560833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cF/fbCxY7f5gmDZSGLv+LM+lQB9k7Qr7x5f3YzTniPk=;
        b=ckC8srANCWxoKj0+ODzhaaWil26xNjiEWmSwquWpudAGzEMAtGcNJZsLdx4SUd+Tcs
         1qXQjPX6BCNZeWoPfJTRnWgE70QeYG3O2JavOcupAd43PNaR9aVNY/ib6d1ECiGs4v7k
         njCi6vaW88Dsn5H3P9va4sM1DXsAr6g5J/kN5HfytrJKgasTioMLmXOl4SEPAdKxHRSq
         8X0r6sltfgIX+EW/rkQr69C4I4luPSlhKKJCQJ0YVxxJyuMjbh0gne1emuatHPKHlTNP
         J9qEs419um4lzv7JxjCJ/lVXa0gzrW3dgW4IiVd2yeaAX7cCf3CfP7Fvm26qbwSgbRXZ
         hi9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956033; x=1729560833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cF/fbCxY7f5gmDZSGLv+LM+lQB9k7Qr7x5f3YzTniPk=;
        b=KUjQven694BjZIaERKmM5374EnBqjhQ7Mo8cgqx6mvySodLVOJA7pn93RCVTggEM48
         2NrHDbcfTWydnCUYilDszYUmP5pXaLh2uk9so3zzxmsUqXGP4c/BaxrsJFcslDNWGE+X
         Wq8LA2UxDbNFGzs2GjhRn7xcLTmyzXnH1efW1Gg0pWfT7ot2uEa6gbwyGX3bmoSmtJZe
         d9fmO2SdugUIiY29b1Sg3QwkwvJkkkjraKeldfqv9DBi5XXzecYqRbWeToPKWwzLzw8l
         VjawP/hTtLCgTOVvX+FaKQ6qBZU/8pp6Z0Mj1I2YSpKn/34QPvMFaRCa2R7iQcQ3Nl0W
         DvHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXa+eoMpbs63DMiYHK5Za0ITobpuVTVV7K0y4prrSV2OELLqUFSAKI0La5ozIjKAdXPY2Xlrg==@lfdr.de
X-Gm-Message-State: AOJu0YyypbGOJ7/Z4Pr/MX/p/T8U1PGukZ4tXUeK8+Gijki3P9BxN8uy
	pD01NFSSmCmubkn2evy1dyrY659vGOkR+s9PzFNx300X87Myfh+3
X-Google-Smtp-Source: AGHT+IHaTs8F01h8b6Aukc8rMuKwxsxq+71DbpnwOrmQVRwC6zpJXkucIrl2KLbXS7f/Lqj/rPUNLQ==
X-Received: by 2002:ad4:5192:0:b0:6cb:f345:8bcf with SMTP id 6a1803df08f44-6cbf3458de4mr190472956d6.46.1728956033584;
        Mon, 14 Oct 2024 18:33:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:21e4:b0:6b0:8881:bc19 with SMTP id
 6a1803df08f44-6cbe565a703ls87274186d6.1.-pod-prod-08-us; Mon, 14 Oct 2024
 18:33:53 -0700 (PDT)
X-Received: by 2002:a05:6214:4686:b0:6cb:ef34:9c00 with SMTP id 6a1803df08f44-6cbeffa5549mr236418236d6.12.1728956032863;
        Mon, 14 Oct 2024 18:33:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956032; cv=none;
        d=google.com; s=arc-20240605;
        b=ZuHvgg8ZvlOaLwifG+gSknBsh4ck4eyqE+mZhoFjCqa+jkBzJtq0R+wePDMjhgLoSL
         NXPGPDz07Y4nmtzQQg2pynW9pPOp2jbcYtNDlZbJ85F29yTGOkhqlxtt6hDX+1XUEZqx
         AmAW0DJDN3Ad/OIiKX9pj0stVKzSs2LLVqsbUMKlgAyl3GQ7TE+caZlgvBBdpKwxRC1j
         soNaOdAQE6l/WRZvUJ9o2bXTY+Qs+fsumEGhGC2VAr9i9+eYCkA1TiQ9/Faz30H2or0H
         zo6mGwKh8rtNwGxFhLp1/WHiAS/Ph5IX7z5WjxGGAeISqerMow2PJry/t6Xsi1Fuj93X
         RjyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L3z8aqN2PapGEchw6ngaiDWNeD417V3WkhQBwYXWFqM=;
        fh=GWwm9TH0AMn0HBdoEp0DKgUJ2rhRGutJ69y3RzmZHpM=;
        b=HndOrhL2zHcvFeaXOawOrFE5WTNJzn2KkQzf2dEP4VnsEB0Eu+DGxhevHp3N2zaWNZ
         SM+NCno944DqUgNcTS6y7h872AWBxfJYk62TpHIuCqVUzrfDpzfE0iQQz3kvDYpU37FT
         XYJ/bJYNxblwIfK2ZnokDCtaVeb8Rvf1uZdydNcj4HIU3joDGGWNPJn7u0DpRiOfs5EQ
         DbzDkbJtGPW1uhE4Qwu1F9m7jOGp3yCMY7CrprTmKth2ulaZ3IcRbBlriYcO6Th+j10U
         EgRXDHvXvE1MJEGkmfl9tEzfoXe0qecrgVLCqaj7NW9gl7fMsh3IRl8K3GemjuUdnjRX
         ODoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lEkRBe6M;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cc22954651si134546d6.2.2024.10.14.18.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:33:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-71e70c32cd7so717401b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:33:52 -0700 (PDT)
X-Received: by 2002:a05:6a00:9a1:b0:71d:f215:1d96 with SMTP id d2e1a72fcca58-71e37e287e7mr22675408b3a.6.1728956031701;
        Mon, 14 Oct 2024 18:33:51 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.33.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:33:51 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 01/13] mm/kfence: Add a new kunit test test_use_after_free_read_nofault()
Date: Tue, 15 Oct 2024 07:03:24 +0530
Message-ID: <c987f2cb5d19e400ba3f1167e730a00bc16b7ca8.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lEkRBe6M;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

From: Nirjhar Roy <nirjhar@linux.ibm.com>

Faults from copy_from_kernel_nofault() needs to be handled by fixup
table and should not be handled by kfence. Otherwise while reading
/proc/kcore which uses copy_from_kernel_nofault(), kfence can generate
false negatives. This can happen when /proc/kcore ends up reading an
unmapped address from kfence pool.

Let's add a testcase to cover this case.

Co-developed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Signed-off-by: Nirjhar Roy <nirjhar@linux.ibm.com>
Cc: kasan-dev@googlegroups.com
Cc: Alexander Potapenko <glider@google.com>
Cc: linux-mm@kvack.org
---
 mm/kfence/kfence_test.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00fd17285285..f65fb182466d 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -383,6 +383,22 @@ static void test_use_after_free_read(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+static void test_use_after_free_read_nofault(struct kunit *test)
+{
+	const size_t size = 32;
+	char *addr;
+	char dst;
+	int ret;
+
+	setup_test_cache(test, size, 0, NULL);
+	addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	test_free(addr);
+	/* Use after free with *_nofault() */
+	ret = copy_from_kernel_nofault(&dst, addr, 1);
+	KUNIT_EXPECT_EQ(test, ret, -EFAULT);
+	KUNIT_EXPECT_FALSE(test, report_available());
+}
+
 static void test_double_free(struct kunit *test)
 {
 	const size_t size = 32;
@@ -780,6 +796,7 @@ static struct kunit_case kfence_test_cases[] = {
 	KFENCE_KUNIT_CASE(test_out_of_bounds_read),
 	KFENCE_KUNIT_CASE(test_out_of_bounds_write),
 	KFENCE_KUNIT_CASE(test_use_after_free_read),
+	KFENCE_KUNIT_CASE(test_use_after_free_read_nofault),
 	KFENCE_KUNIT_CASE(test_double_free),
 	KFENCE_KUNIT_CASE(test_invalid_addr_free),
 	KFENCE_KUNIT_CASE(test_corruption),
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c987f2cb5d19e400ba3f1167e730a00bc16b7ca8.1728954719.git.ritesh.list%40gmail.com.
