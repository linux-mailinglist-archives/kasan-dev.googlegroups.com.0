Return-Path: <kasan-dev+bncBAABB6UO73WQKGQELBXQXPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 269CCED767
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 03:05:48 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id b24sf11813425pgi.5
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Nov 2019 18:05:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572833147; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/ChVRjNdYUtHIOR8D8jsC8PIajXzmhQXnujYSekwqYSz/U7Jk9xYzbIvSlPzNM8Or
         XzzTVgUOZcvND0QE8HpDKgH95Y+iTqbTHFxVg2ts+wNJllBTkjkiANOhym3gUdqEIVWt
         T1wnj7VDrHu/rnp9DY4iUFv4QY2MacxynseEoC62PYYbSYkYIS2VpgufiyCDtqd+jJPA
         71r4KowNQPPHvKjengpGd5kPkCt5ivi2fWbgSL0VDFTGDiF4CTr0T37QZ0YZkcbYnyUi
         WeIfJ0TATOr58TrhMIz5Fv0qzh/7nkj67tgxFfV44K/suQYPf6qSJ4PcPxucmwzUY3Su
         +8tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3QQF8Fmt5Jdf/77sImlONuqExi1PZHEWVvG/qg5fK/I=;
        b=KRawMEgGuG6+D3S+IuavUjiEfss1L8YGcsZzg9c/5k1Z+w8alPIXfCJxGx2gaytBSQ
         q2vVe+jgDLeDXLKXEX1ltVX0Hgi/AVzHarzcA6y4YjUC0zWD4lmXognHdrGjVvicnSDi
         sil4JqLEWtQIxvzqIFN3ifMpTh8omqyCSKBMSckGTrZ40QLxXp3XcWpCeJjxrbNc5Amu
         tLyrJarXJJWChs6GPhR8J0M469OqDIaSp3Pk+jV60e6FeVY04R0CYwlKcy7HtjwYV6lE
         z6eaygu7l4jgljE3E3zXraeILnDaRBM+rEuBP9yp9lBrMEhaRQNfyamZJoM3vkDOjuBg
         6ffQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3QQF8Fmt5Jdf/77sImlONuqExi1PZHEWVvG/qg5fK/I=;
        b=lZoIgOP3CIHc18cK/J9weiA5u36ylK91IDKoMymPIEuO9lgfPvLHt5vFJwWqP46Aee
         /YXdJ7MRCG+av7qoqQq8bU7LNwJq/RJefchMlR2JOlp4zHQ3bKRJtWVj9RW7eQIIUQRP
         GlonFE+VWn7z3vyXnjK9o5ITWC9koanJmm2fuIODACM4SyFA8PCANTFMVAQaT2cJd2xr
         tP+wwOC9oDfszWBmS0zjBEl1MGQqSMZEYhyGVneeWvJHES/BmnSehvZMcziT6GHZx9RV
         HkBKPrKM63eJnEkCnBkDeiFmNyECcs8keZrnQEFsfimX/oC0mLYZmbsJK3uXGMG2fPDN
         H7Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3QQF8Fmt5Jdf/77sImlONuqExi1PZHEWVvG/qg5fK/I=;
        b=c4jPmDsx2E8M429YRyh3lYXCOjBozjuCl1h6ikdsJh2rNzTJpBqcbxYcsVRCEykfZF
         gSMFeNqnItHSDI1TEW6ZXKHFG+cp/mJZiIGIWsK2UEw+KzUr8OA3WJdSz2wq1WyqC1Aq
         p0zB3JExD5693BCmQIvTIDrXeuKOV9B3ulGk1A0FV02JVwo64mEqo/cRhJ754HvpCFcf
         mtllgX7flQPf4DVi+Fp0YOO9AAhMHQfzJPEq3SgwLrXK5f5x1XJv1hP90thj69fEasoq
         WBi2gO8i0wK+z33ag6rDisQbVYWBwnuFZ0Y9vlLusJ584WZqPfGMYO9afwdAI9oc5Zai
         TMyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVak24GMzmN+Ti4S89IbVfLCQ/fS2lklrfOjYtwYTWK9RUA5fIc
	LAp5CLe5jTkNe5rsIMXedlE=
X-Google-Smtp-Source: APXvYqybZrgODEVceLjggKUvusqMUN5svEnLm36Srhe8mWJdPvyM1VaADnf+pJxntlJbj43+fKj4Rw==
X-Received: by 2002:a63:1703:: with SMTP id x3mr27867990pgl.263.1572833146854;
        Sun, 03 Nov 2019 18:05:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:52d1:: with SMTP id g200ls3114582pfb.3.gmail; Sun, 03
 Nov 2019 18:05:46 -0800 (PST)
X-Received: by 2002:a62:5c07:: with SMTP id q7mr27569886pfb.159.1572833146585;
        Sun, 03 Nov 2019 18:05:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572833146; cv=none;
        d=google.com; s=arc-20160816;
        b=jMbwkfPuXBGW7V1DofMzcMxHAJO9rOJrxd7Nkz9kxSew14APrwHuGBMGjQYb4B8K4U
         xsgRuzZqFGjkI20gnoYcZb05/8/HNZWxQtIfL3OZ5StkTxjell3LDzXRlCE6L6rsFji6
         3Znq4zND+khUdHM0Q+Qcb8fJKzeSnWm0tT13w71sOCNVZenOF8OijbVY+X1FiSJDu/V/
         jkRKvUBCZxOPpBv8aKpgMDA92iMv7boNXotZdGJi6lScym24lhrAWPn/2BBEXvBBjL+H
         UKHhu6om9ylkTIQr/Nan8jH1OtWO6VrT1NsVQVoni0QWAWYPErtqF6xZD/qUSFAQz9jH
         BUow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=NXUhWbaZQQgu25hdem8MHn0Xfn5xg3kHqkgFGT4qSAo=;
        b=rbL8mtYpJmp8+MKKcE44YGEXMzUKJIi0Cx/WX2j/pnTyMjUDMa/dKEI1ua2gAicZEE
         D35S7zoRHaWPzFLt+N60ZAF6atX0BsIXh4GJh82STBYoMbn+Zhx2VWCE+ZuR4iiHiuVY
         6FrHLCA9zFhbtXvsEy7+vScSJXYVf36E/N8E2Jx68SDo3BxMfV8mTK18zt+alFB3tcFR
         w74pvFKqK8u/ewgdAIhNkkp9K7mDNg6Wz2SscPPmPWM3YrRaRt1CtYeP+iuoOovtrP5w
         CBDAExWKA5StCrXedGcWxejTHafJC4FwwcX9gtS8aFf5N3pGxb8mmS0PU8+yHUXNs5Q8
         A5QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id s26si767335pgn.5.2019.11.03.18.05.46
        for <kasan-dev@googlegroups.com>;
        Sun, 03 Nov 2019 18:05:46 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 04af6f70713449ee9a2bbe13afb6df6a-20191104
X-UUID: 04af6f70713449ee9a2bbe13afb6df6a-20191104
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2092748576; Mon, 04 Nov 2019 10:05:42 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 4 Nov 2019 10:05:39 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 4 Nov 2019 10:05:39 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v3 2/2] kasan: add test for invalid size in memmove
Date: Mon, 4 Nov 2019 10:05:39 +0800
Message-ID: <20191104020539.28039-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: C7718962B9A4B5E4228DBC919FD5E100E8BDABB44BCDF8ABD45A72F8B85F7A0D2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Test negative size in memmove in order to verify whether it correctly
get KASAN report.

Casting negative numbers to size_t would indeed turn up as a large
size_t, so it will have out-of-bounds bug and be detected by KASAN.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/test_kasan.c | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..06942cf585cc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -283,6 +283,23 @@ static noinline void __init kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
 
+static noinline void __init kmalloc_memmove_invalid_size(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("invalid size in memmove\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr, (char *)ptr + 4, -2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_memmove_invalid_size();
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104020539.28039-1-walter-zh.wu%40mediatek.com.
