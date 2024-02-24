Return-Path: <kasan-dev+bncBAABBX4V46XAMGQECA4RKJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id EFEE0862459
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 11:54:24 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-337a9795c5csf1061644f8f.2
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 02:54:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708772064; cv=pass;
        d=google.com; s=arc-20160816;
        b=YeF9ReZBe6nVYHj8GddImJifE+6W9Dav8ZEO9eyxl7i7xiivkEbA0+NG6PW/42yuSK
         /XOBC3eovQ4bFNmPhaWlIEoYGA+T4rvDWYk9JuO2hHxy6+FFkbPR26GgWOdNqg1ZsfJZ
         +9RZfl1vsU5fxIXS5LBQKrYhU2hOOKQl3Egb82F9ygRRh6/gZq45Pm4rDS2QloS/Z3Xo
         lmXefLqNmstkMgn0/2dkSp4ytQXH/VqimczI5TzCsUFFJER/2/b5SFoOGJcxLvoZecvU
         fSzn+qB0uye/XqWXzzyZzoCnuebsZHU0e+mv5biZ5CZLEZB/AVBDhB0ps6wk40A2dglm
         5aqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=wXfjXuQAOMfBh/EUUiUpp6VfLyTo2h6N/PI9vHJrbyM=;
        fh=30FyhG/QWT5qeRVzR1F8f6UiB/pW4i2BqCPLQnC+Esc=;
        b=WBDNvTRwBcoGIhjQc3iiX9ocJG10Yi5myi/EAprQgP20bkYZ5CQmfcNoMuwaL9kCFa
         2fVVfIEL93mPrOHeJ9buZE4lCQuKSVmTXDEypxoPDU6YwdQ1zgMk3rCRwDbl3wSt3mZC
         G1q74frs4cNGAcU+oIAhtkfJ5T9xEykYUtkzI9i00m74iReVYTs0K/3VIBH/1G3XOZLE
         6gDAodXdjZRfyYhJkbPKgbMmiWP5WovBpqiejRuruDZGf+I/g8qfroFmJcxxc+28JCI0
         4sgQDxOERz2oUZkM+rJh0t+BhbpnSNEWZbp1hbdSYRcZXG2CCzkkgtU0G7Lx0qce6hgs
         vADg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="Scx8/Edg";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708772064; x=1709376864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wXfjXuQAOMfBh/EUUiUpp6VfLyTo2h6N/PI9vHJrbyM=;
        b=WJMnJrh33FUcZKeddxSqJz9Wp8hu3tvaprQsmSNd6OCzfU0ZFK7YM4yYcSByZFe/I8
         BSNAyQ7lJM0uam/70ssDlz2hvr/FP04UP8uLfo/CI+3LGOldbMh6T52FybZak/vzsLDx
         QRsRDHmgPQs9XHdPh4adSDSi4sW4vPcWsbb64ZAZlpt/ZfW7CkBAUR2PVWlWLf26f//W
         fqKPDAAXpFkTYU54Eax7SA7Agt9SMc2tTgemV6LQejA7UotM4noVC2UpeaiLTAZTVtvZ
         vyt3iNnc1YlW7JywW9eM8lKPSAtE5K2vuw3dK/Cwi3hiNyIRq6dTf9qYFGkoeCKTzPpH
         pq0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708772064; x=1709376864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wXfjXuQAOMfBh/EUUiUpp6VfLyTo2h6N/PI9vHJrbyM=;
        b=Q5+QgSY8eKpLcd9GP+g+HP2mZrHFj0qn/bfHZPx/vMa7XJE0ypn1um++v2bypf0RII
         p37T8cknYnIAosBY8yGABxyJtgI0hedrkooW8FCvK0gfoJdwn8fRFem+T/Ub/E63YxR6
         wkOwc41X5ZO+UbOkeW9jzQ+5zCUfK92WpFHE8y30vsnSp1nQTN/Yc3Hfwdr8JY91fvRB
         yzv57AMINOvyN2oanbA/L1Nz25x3JAcA6L6MZEqjN8O/yNycl6GM3hLicqhBl3GfzRk1
         D82Lb9b+xQ2wBUtXHXFL/hCon+wD5+wy19pcq76Oj/IjUFYwYtsBznCmmNcDUN0L2k99
         i1+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxlM8VoXZqI4osmLjlxPxLjlAcNtmwWPQu41aFH3+Vv6jGc1rUfiPAGMnHAEiJIAVGhjSLiOKO1BXfanDSnulwLtQZ79blVA==
X-Gm-Message-State: AOJu0Yy20I6LDKwSKzvF3Y5m48Fw/lDBe29Hj89n59vXxsJlVE2K+KAh
	GvvkKwp6/LJng7B8bep8OCtQpHG0j4n1o9kAN4AxfIsJbvGVdgOg
X-Google-Smtp-Source: AGHT+IG981JRk1Oni3D1VCn3HgpBbM/sS/xTdWHih02oWWXfvBw5PqJDsZZs8lfIC3VrEZMaJ8tpXg==
X-Received: by 2002:a05:600c:5114:b0:412:919f:142 with SMTP id o20-20020a05600c511400b00412919f0142mr1468677wms.31.1708772063960;
        Sat, 24 Feb 2024 02:54:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3aca:b0:412:7a0c:8423 with SMTP id
 d10-20020a05600c3aca00b004127a0c8423ls698970wms.2.-pod-prod-02-eu; Sat, 24
 Feb 2024 02:54:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVu8XcuZPDbTCaakj7mZto+SWEoQadTTKLUcM9o2AiW04y+e1Z8a0IJ+DXYjmF/nwcHiEHlmsOkCNgttug+39iUm/7X8E+Kzitq7w==
X-Received: by 2002:a05:600c:1d87:b0:412:9867:2c09 with SMTP id p7-20020a05600c1d8700b0041298672c09mr1557355wms.4.1708772062560;
        Sat, 24 Feb 2024 02:54:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708772062; cv=none;
        d=google.com; s=arc-20160816;
        b=gEUvm0VBqNOPFq5g2770wk0DOe63Psmp8C8tiZHjCvWFkJ2PXhDNuKqWhKhhEFcT/T
         5cUZ4RFbW10eC9tXIsW37/1UYAbDFaEAgdu1gneD/zMm9XtQ3nHq18GbtmMg2uKPaSoJ
         ABduqSOaS8oQSZO8TJvS1HAzg7tWZiTmVwxte3FyCZklr06HFluliPBQpf5CIxCm9CDJ
         wbtPM75T4gdazT1tRaTPzkCmsZIakAb8fajlkXh/UNdSrnFa4X16V3wB1K2Do8u+NuGq
         wo4wA9D0TPry6vhgmxaO8x5iB8iF4Vp1Bi/xrQEWZJnBlEmx3RQfdwXT/iXNdsESxKsU
         i/Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uRexiL1hDopWJGrXPsILxKWh+xq4dfVumK602P+IOzs=;
        fh=uV27StYz1PuPNiZbuPO3IZ+o+DZj4i861k70n+rSjJc=;
        b=yy6esUhQPfOnPaWxKYnl4mrn7wsRBgumSY75007WxVuqpm5WvwOW+bOCrCrEF6QV/l
         NWyBf6uu2+o7K6BmQn9NO2LehUyIWjN3zZ97AuJrIJIzxH4/lj0wxymXunV0TNpqzqK0
         FCzihhb5/+61N6Du9+L1FN3fSQmvaD9MJ7Ga4lKO48jHdo55aHhpZurbTOwYkXRh5u5s
         7ddvCufGyas/lrKYJJ/s9s7OsR7s8ZmTIEcjlAk2QvWfS94wYIbkD6+0u9dn0hGz9ZXS
         OveJ0gPQDT10pCX+fJulJAKKFP0uE0YyDfSVN3wiS+hBXceqkDWV/Tno+EcbgGsUDqN3
         H/UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="Scx8/Edg";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [129.187.255.138])
        by gmr-mx.google.com with ESMTPS id c19-20020a7bc853000000b004128815c371si224299wml.1.2024.02.24.02.54.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Feb 2024 02:54:22 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) client-ip=129.187.255.138;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4ThkK95Rs3zyZG;
	Sat, 24 Feb 2024 11:54:21 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -0.382
X-Spam-Level: 
X-Spam-Status: No, score=-0.382 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DATE_TZ_0000=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001, LRZ_TO_SHORT=0.001,
	LRZ_URL_HTTP_SINGLE=0.001, LRZ_URL_PLAIN_SINGLE=0.001,
	LRZ_URL_SINGLE_UTF8=0.001, SORTED_RECIPS=2.499,
	T_SCC_BODY_TEXT_LINE=-0.01] autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id t3smiUimcLMl; Sat, 24 Feb 2024 11:54:21 +0100 (CET)
Received: from sienna.fritz.box (ppp-93-104-78-110.dynamic.mnet-online.de [93.104.78.110])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4ThkK821SYzyZF;
	Sat, 24 Feb 2024 11:54:20 +0100 (CET)
From: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: akpm@linux-foundation.org
Cc: andreyknvl@gmail.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	mark.rutland@arm.com,
	paul.heidekrueger@tum.de,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH] kasan: fix a2 allocation and remove explicit cast in atomic tests
Date: Sat, 24 Feb 2024 10:54:14 +0000
Message-Id: <20240224105414.211995-1-paul.heidekrueger@tum.de>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20240223161020.9b4184e1e74b35f906e0ec78@linux-foundation.org>
References: <20240223161020.9b4184e1e74b35f906e0ec78@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b="Scx8/Edg";       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

Address the additional feedback since "kasan: add atomic tests"
(4e76c8cc3378a20923965e3345f40f6b8ae0bdba) by removing an explicit cast
and fixing the size as well as the check of the allocation of `a2`.

CC: Marco Elver <elver@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueger=
@tum.de/T/#u
Fixes: 4e76c8cc3378a20923965e3345f40f6b8ae0bdba
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
---
@Andrew:=20
I wasn't sure whether you'd be squashing this patch into v1 or
if it'll end up as a separate commit. Hope this works either way!

Changes PATCH v2 -> PATCH v3:
* Fix the wrong variable being used when checking a2 after allocation
* Add Andrey's reviewed-by tag

Changes PATCH v1 -> PATCH v2:
* Make explicit cast implicit as per Mark's feedback
* Increase the size of the "a2" allocation as per Andrey's feedback
* Add tags=20

Changes PATCH RFC v2 -> PATCH v1:
* Remove casts to void*
* Remove i_safe variable
* Add atomic_long_* test cases
* Carry over comment from kasan_bitops_tags()

Changes PATCH RFC v1 -> PATCH RFC v2:
* Adjust size of allocations to make kasan_atomics() work with all KASan mo=
des
* Remove comments and move tests closer to the bitops tests
* For functions taking two addresses as an input, test each address in a se=
parate function call.
* Rename variables for clarity
* Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_store=
_release()

 mm/kasan/kasan_test.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 4ef2280c322c..7f0f87a2c3c4 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1152,7 +1152,7 @@ static void kasan_bitops_tags(struct kunit *test)
=20
 static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *s=
afe)
 {
-	int *i_unsafe =3D (int *)unsafe;
+	int *i_unsafe =3D unsafe;
=20
 	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
@@ -1218,8 +1218,8 @@ static void kasan_atomics(struct kunit *test)
 	 */
 	a1 =3D kzalloc(48, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
-	a2 =3D kzalloc(sizeof(int), GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+	a2 =3D kzalloc(sizeof(atomic_long_t), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a2);
=20
 	/* Use atomics to access the redzone. */
 	kasan_atomics_helper(test, a1 + 48, a2);
--=20
2.40.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240224105414.211995-1-paul.heidekrueger%40tum.de.
