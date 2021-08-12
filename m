Return-Path: <kasan-dev+bncBAABBAHM2SEAMGQEZFS5NBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DC903EA6DC
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:53:53 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id v18-20020adfe2920000b029013bbfb19640sf1904299wri.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780032; cv=pass;
        d=google.com; s=arc-20160816;
        b=XickMQn8RBLqoAyFiEoV+3wvwRqaOCTxvFlK5aFk0pIdupB5kcXUIEmBx/A6jfS6Xg
         nejC6EeIJSmRUbx4eD6Dpz7yuY9EcN0+AO+QvCWeu531mPUOcldNPhuVKObqV81g7Cw6
         x/mYG+ZQWgp4zFQcWvKxIOkJ/GcI7DX47z45xzMJET+554J+H1kTD/lncrJx2P8WJ5bK
         hzwVmwdwqASPXgVve0dcC389/jY9DJAvKE7gMt4goS2aChWanhrXd7WklchB6jHk6cpK
         1ImYvSaArQcZ2EfPdf2YH38My5m5LoafO7A3z2wIO+UllzehmEgXE1XEvTYeHzG4ewHd
         /Uhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/cFYsaO4g6FnwXv0RMydRD/mD37yqFmi+GGVlfNV8Tw=;
        b=BVWBfadPLLJs1cXDS7EZfy+2uil9bQPbdbw1Fxs8QHTahMjSWn9Q+yL925XYd95+oQ
         RNUGoKUhv6z0OADs7VOwgK4hgWKJqOS0JaPE88es2/ns6Siec+rZNWuuED/lnHJaps19
         Zs41G+TXxLypQxWBTkUYYxh/SitdCDZzLor4J6qAs03/C90Pa76XHisRY6x5Zvirc5sR
         ltYull97+QBeQgSlcg587Pqn/zu+UJBrTT0tJXiMydvZ8WUIGKhSDCY80uh3PGu5aJDa
         jiS08UOCrYi5wKcTlRn3QaH/YiC1ZUq2CY1/w+M2OwGWi9JivLyw5iFRCGWlY4Vb5+LS
         o0Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JwmPAbtU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/cFYsaO4g6FnwXv0RMydRD/mD37yqFmi+GGVlfNV8Tw=;
        b=eiG4Wo2i/Z7ElBpg4tOVKCTlDYwfsF6RuES3h3FKEftmhXnLwPGng9IfdgNuY4AjVB
         RbBH/wgb4uV06OeaL0cn0R/uP3z9WtcIlyVhFu9ZayC97/mu03BjAz/SYcMtYSDnc9+o
         6624jo4Nm0YK4K5+8AVl+RopCY5AN4ORvpGhsy0VXG0/2RiZFqHKYcX8OPD/+E5umF45
         pfeMNTvZjPAs4XAVfOLP+NfO9p9bQzbC4LPi4nUTYO014UInE0UzS7VhjPKpwfPzV4r2
         MKX1o0q6vJfPFSVclBo4oWMU+9sbDAvBC2lZ0udY2ilPcZe9dC38equ2QNM41PiFpyHA
         L2fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/cFYsaO4g6FnwXv0RMydRD/mD37yqFmi+GGVlfNV8Tw=;
        b=crT6Fjz1EB7nfOkViy8pPwRSUMD0QGEZdVRejss43MccI3AnS/Pa9mlZI2rzpxCWjl
         YdBuqlUSEaIUYgE3xY3ZeXEuxFIk6Re5IqbOZYFDfLVfifU59JmR3MU/wuybtgIHqmmz
         T1F3o03Vz3k7pStN9nyk+8ywiWcp7cIsADo0t09sI52EAyZdBIf/oXarmBi6UuF/Fgan
         70y+3dtrEpTjK4T44cymHRHI7CMK5v5+vAM2Qvet9+mUXZQxlSqMdtt9z8mi90BCV/aw
         RuMDuT2UlK/o8k21xmqmo8x8zpMyHyQHkZUDPdQO/lmXvHTXbu9McF6ohmPBm4+i5QbP
         0Lvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532LyCjCG0Itj6E0xMWA2fTpFp42THwEVq1QwjHIjQdMekYiDU9w
	sTrTJC1usa1t8DUAlIueLjg=
X-Google-Smtp-Source: ABdhPJyHb5TwdzxpRn/gqRimCjgjupoZBoieqEP1TqJtbxrHaPMAA+BIvzUC6f+jRiUHjNAJiTaVqg==
X-Received: by 2002:a5d:518a:: with SMTP id k10mr4490157wrv.400.1628780032776;
        Thu, 12 Aug 2021 07:53:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:db90:: with SMTP id u16ls1387417wri.2.gmail; Thu, 12 Aug
 2021 07:53:52 -0700 (PDT)
X-Received: by 2002:a05:6000:18a4:: with SMTP id b4mr4632758wri.162.1628780032027;
        Thu, 12 Aug 2021 07:53:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780032; cv=none;
        d=google.com; s=arc-20160816;
        b=x7Ewxq503wsnhXwZmFiLIPu2DoZpbK8DPuz3aa3e2mm7kWzwUbn6krt3fST66BDmNc
         0KH0JLoHaY3Mn38kJVRgrYEph0MBPN2SC6AVzYM9RXnfLhlkMJfYbgbrKnjd0DaZYv+C
         /SpPJHFclE/XTTbie2a9wNUpa1+24dCPwfxtEUobnsYlUeLH0qlODB9bNpHG7MugS3gM
         CjTNqLhb/nrNf2UmyGjUTgXlu543MvNVeGmcMIUO+XyuUTEnuM+PGVVawd/46LZqbFdT
         WAbf3ckLJjE5fnzH0ufVVjIT2+xr2DdsjhuvB254w25JAzAZptz/2PEUiZaGWjf7B436
         GH+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hJvl0j61Zq+oSt6HYk9qiIcFyGt4nhGk7HpIREtRZqk=;
        b=icwS6re3bnT9CK53VorpHCJZUyMJwgNb57vE1xK86DtckvNwX9yI86ozyb9qCkG3kX
         JV2ZrxaFVCD/qSoBEknsL9T35y59DxP/bZ9zVsk1YPgOKN5SVfGPJaoRDQZpCvaZS66L
         RAuk0S576b5UqJucOoEQgFn4r3BNtXjyCd4r1i3LUt1YqwDzSPt6+gBm0oneaiPvNLff
         f81+2RZ6msT4e9ltS2dt6uCnkRV5OWUBo2fQo7ugcSzfGnnzJ+V32jPRbWLKTD+vUhIQ
         RFPsP3/W2+mYcTYgmdoLecNNfM1mj50lUJSJdwyNrYz3DdtAgSHsSJVT5Mg6OjH9Xr1t
         4Iwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JwmPAbtU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id m33si132333wms.0.2021.08.12.07.53.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:53:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 1/8] kasan: test: rework kmalloc_oob_right
Date: Thu, 12 Aug 2021 16:53:28 +0200
Message-Id: <474aa8b7b538c6737a4c6d0090350af2e1776bef.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JwmPAbtU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Rework kmalloc_oob_right() to do these bad access checks:

1. An unaligned access one byte past the requested kmalloc size
   (can only be detected by KASAN_GENERIC).
2. An aligned access into the first out-of-bounds granule that falls
   within the aligned kmalloc object.
3. Out-of-bounds access past the aligned kmalloc object.

Test #3 deliberately uses a read access to avoid corrupting memory.
Otherwise, this test might lead to crashes with the HW_TAGS mode, as it
neither uses quarantine nor redzones.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 20 ++++++++++++++++++--
 1 file changed, 18 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8f7b0b2f6e11..1bc3cdd2957f 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -122,12 +122,28 @@ static void kasan_test_exit(struct kunit *test)
 static void kmalloc_oob_right(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 123;
+	size_t size = 128 - KASAN_GRANULE_SIZE - 5;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 'x');
+	/*
+	 * An unaligned access past the requested kmalloc size.
+	 * Only generic KASAN can precisely detect these.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
+
+	/*
+	 * An aligned access into the first out-of-bounds granule that falls
+	 * within the aligned kmalloc object.
+	 */
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
+
+	/* Out-of-bounds access past the aligned kmalloc object. */
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
+					ptr[size + KASAN_GRANULE_SIZE + 5]);
+
 	kfree(ptr);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/474aa8b7b538c6737a4c6d0090350af2e1776bef.1628779805.git.andreyknvl%40gmail.com.
