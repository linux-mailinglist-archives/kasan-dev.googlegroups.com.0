Return-Path: <kasan-dev+bncBDLKPY4HVQKBBW5X7GRAMGQEPQDHVCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A31F700BD0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 17:31:40 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-306281812d6sf3971352f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 08:31:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683905500; cv=pass;
        d=google.com; s=arc-20160816;
        b=CelqK++/BKXHVtWCG+LzMuXX21aKF/STR7hUbE/uwp3eZacF5T1X25R8XrOdXGteca
         TRYK6FqQr8CaYjPpeua18Pf+23kdBKnmG+HRbh9g5IomnSgL9srji8teH3wxJJlWNSi0
         zFFuW4GS1/hRT8muJQqF9lB0J75iJCewaMduCk7iYX7mtma+S3ZsG599RaJTzHvDhva3
         075HTlfO56W8hBmjrJag4jRT5HkVLiz22cU0OioYsWxY0DHhsHsgW4+HjDc0o2B8573W
         mqvNM9ul4WHIpa9erDBAIedC3DUGJTgYGQsGU/9iublLdJGoC+aMsLR0hu5kfh5QMLSA
         JwlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pBGg1wVXtvpDBJGUqcYYH63xU1bkwGKaHeBkWaROryE=;
        b=jPB6DWT6cZuo12R21DUTAHGTTLkzYCyeOWOgeD2XagxQfeQfDNxofLvxnjLTRKzMU3
         4Aaab/qrSvD3tnI0X1DsmF96tjIfZaC4gEVrzNGGxSl8/8gXOj/oeXNmEGeoebyEY7im
         xivwucN0qojKeQ/FInT9TVJe1DeraRE5qBsXjoKZPNYTOiQ75CB9wq6M5tHvaVyS6VRy
         +SPvn9KK5sZbALDBU6b1KAnxwp14Cvf7xRuajRMK1fXYSEfyzYEyEbcKZXU84yYqKhMI
         sgxChJXhu62AHR/V/7154i0gvNU3v8YDXrmphzioOm3dCpHXyXL6NtxNCy4I2inT3xx1
         zV8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683905500; x=1686497500;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pBGg1wVXtvpDBJGUqcYYH63xU1bkwGKaHeBkWaROryE=;
        b=plXpdfJECiUBep38QxDrIXc1JxVXzclO64X6aB7BW+MUnI5onBR2eBW8r/6WfWG5VI
         /yRrmh4icEj/6zPbetRV1jOh0prPHnRRfLhL1hXsrTcKBSBQX2xII4reXo2wmUPISpsj
         8Pf/eOXGEupvtKq64nurXgGx2y0TthPQSDt+1m9HEl0TvIrZlzNY4E0VaeSgSrf5Bngj
         nC3yGXw/3pim14UZmi35GAMRtUrzeQOmFRX7mjXHhYzelM8xIqa9gr9JvOKzuskMLpQn
         4K8ThJaHqlL7YEbZlmrTFOcrUlPmFRuCJkiIRFDKyOWtrogX34kK6kIq0EPRmKB0D7yU
         mkMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683905500; x=1686497500;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pBGg1wVXtvpDBJGUqcYYH63xU1bkwGKaHeBkWaROryE=;
        b=KZdMHyQKtPxxwsv81FVk5QgeHSAYH2Q72c0RaKFsSnNlt3QWoVNn8xqKHM/yADRnJ9
         mPRBQj+BX/+ANp04wGaT8dTPxQI8v7z0+QZQsMYAgaYjD8TBuaRscb7Wbqs3ma3uloN9
         QHmBqJjQt39OTDMhwxLG4DWGMBaeuYGzmKpRK+P1khk5JisBb2UBclQJx7BgyyR9pyNy
         1j93yMnCjFVaVH4lODZ029LpRzBgPSrXIggz7Lpja+a91nEnoqQlTZNW2I/47uha15Lz
         me2APgK84wDLaxuNJiCqfUV67JRFQwzSEx/jSXAPfWuMOjXfP3jGFO0MIYnmAzHDLqiv
         MoZQ==
X-Gm-Message-State: AC+VfDyUwu72ptlFNH17TXes2625cfnNa73UbtuL2lQVM1sfamnnsxjk
	xe7XJd6xI9yQ8cmuLyVItn4=
X-Google-Smtp-Source: ACHHUZ60eDLtQKlHWPxGLmVL72PTKjuDzNoHKNItiJaOt/6sEPFhuQkqOjTNtnOTK5nZKmriYk47Kg==
X-Received: by 2002:a5d:5259:0:b0:306:3da3:e4f9 with SMTP id k25-20020a5d5259000000b003063da3e4f9mr4071294wrc.10.1683905499905;
        Fri, 12 May 2023 08:31:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:45c4:b0:3f0:b128:14c0 with SMTP id
 s4-20020a05600c45c400b003f0b12814c0ls590810wmo.2.-pod-control-gmail; Fri, 12
 May 2023 08:31:38 -0700 (PDT)
X-Received: by 2002:a05:600c:2216:b0:3f4:2452:966e with SMTP id z22-20020a05600c221600b003f42452966emr12208032wml.0.1683905498482;
        Fri, 12 May 2023 08:31:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683905498; cv=none;
        d=google.com; s=arc-20160816;
        b=BXQrlHFa0dx32Ainyx5dLo3x4rhG3ma134ZT70WUqxa6CFQ9e8+yL286KiZI2h02AT
         GKGcTEZRM62s/ellAsflwABEjuIuOlaX2h4AjcRfN9pCS6kHSHHMUueCbRBAS0GOUDtv
         tIF44J/u9z75+LQeXgSwNH5/2/EN6oo+P1+lIoBwSXHAsCHmhSBSIf5eUj5q3OcomFly
         Dp6miwR63JjOY5NplItijxIaLaai2iYpYYQnxxota+3EnNokQ8rXraxL6X8c2BJ3CwDk
         1HbgecwYemBygGjTIvIy5kvAh2eMUpLkuwA0gx2T+qyKJdnlh/NCsqmjevCIXPtRtPqD
         NEWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=oqD/sXXrp6G3TfEDn3TjZvzN+ZlhV5TuSG4LBahWB2w=;
        b=OFLkjRpuM5PfFrclGYXc8EoSuShvvNaFvjKEiulBMQcjJGxZ0xfZdQCbAxZQASt2x8
         CsLc0KJn3i/3upBZR9gjN53U7Ugun76oz3kqOZ9kZm8OrAWGa3YWVAP8q8EHF6nNG1rx
         EJDoXzKgwZLD1nWV981/oy6+noQ6vo0oqbBOKpWLUGlc3jieqkyEf8zWF6/xVT/L1f0q
         NPtfMDr2p7S2z8QSPfRwFV2JWEG2zyDO/ux6W90c8Jvnin+0g4ESZXp/4FDqjKwJxorh
         wZgMV1qHPrJ1NS8eyenOovb/xUc4GCH2ua/ECIDe6GoT/YXg0JMcQyWLyLfl4BHvConl
         Snqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id bh24-20020a05600c3d1800b003f1951366f0si953587wmb.3.2023.05.12.08.31.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 08:31:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4QHt62161jz9shH;
	Fri, 12 May 2023 17:31:38 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id BlC2JZywGvGI; Fri, 12 May 2023 17:31:38 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4QHt602kq3z9shJ;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4D6978B790;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id AxLlpteNQTxU; Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [172.25.230.108])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 19CB88B78C;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (localhost [127.0.0.1])
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.16.1) with ESMTPS id 34CFVXsu027577
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Fri, 12 May 2023 17:31:33 +0200
Received: (from chleroy@localhost)
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.17.1/Submit) id 34CFVXIc027576;
	Fri, 12 May 2023 17:31:33 +0200
X-Authentication-Warning: PO20335.IDSI0.si.c-s.fr: chleroy set sender to christophe.leroy@csgroup.eu using -f
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        "Paul E. McKenney" <paulmck@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Nicholas Piggin <npiggin@gmail.com>, Chris Zankel <chris@zankel.net>,
        Max Filippov <jcmvbkbc@gmail.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
        linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
        kasan-dev@googlegroups.com, Rohan McLure <rmclure@linux.ibm.com>
Subject: [PATCH 3/3] xtensa: Remove 64 bits atomic builtins stubs
Date: Fri, 12 May 2023 17:31:19 +0200
Message-Id: <a6834980e58c5e2cdf25b3db061f34975de46437.1683892665.git.christophe.leroy@csgroup.eu>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <cover.1683892665.git.christophe.leroy@csgroup.eu>
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=ed25519-sha256; t=1683905477; l=2118; i=christophe.leroy@csgroup.eu; s=20211009; h=from:subject:message-id; bh=+zyncwZLQ3bafvCzHRcocRICLz4v7K33Eyqpmw+0Z2E=; b=JGBCBZPW/4L73BEPJbW1KwIUbjfFExLBpY/nshWqN/Q3w4BLyRscY1dA9vrUm3r816IXE7y6r XtQ6o6yaePVDp1dFY392FH1J8IjuLr2gpqzL4lLyIYMnnB99KMOjdi1
X-Developer-Key: i=christophe.leroy@csgroup.eu; a=ed25519; pk=HIzTzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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

The stubs were provided by commit 725aea873261 ("xtensa: enable KCSAN")
to make linker happy allthought they are not meant to be used at all.

KCSAN core has been fixed to not require them anymore on
32 bits architectures.

Then they can be removed.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
 arch/xtensa/lib/Makefile      |  2 --
 arch/xtensa/lib/kcsan-stubs.c | 54 -----------------------------------
 2 files changed, 56 deletions(-)
 delete mode 100644 arch/xtensa/lib/kcsan-stubs.c

diff --git a/arch/xtensa/lib/Makefile b/arch/xtensa/lib/Makefile
index 7ecef0519a27..23c22411d1d9 100644
--- a/arch/xtensa/lib/Makefile
+++ b/arch/xtensa/lib/Makefile
@@ -8,5 +8,3 @@ lib-y	+= memcopy.o memset.o checksum.o \
 	   divsi3.o udivsi3.o modsi3.o umodsi3.o mulsi3.o umulsidi3.o \
 	   usercopy.o strncpy_user.o strnlen_user.o
 lib-$(CONFIG_PCI) += pci-auto.o
-lib-$(CONFIG_KCSAN) += kcsan-stubs.o
-KCSAN_SANITIZE_kcsan-stubs.o := n
diff --git a/arch/xtensa/lib/kcsan-stubs.c b/arch/xtensa/lib/kcsan-stubs.c
deleted file mode 100644
index 2b08faa62b86..000000000000
--- a/arch/xtensa/lib/kcsan-stubs.c
+++ /dev/null
@@ -1,54 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-
-#include <linux/bug.h>
-#include <linux/types.h>
-
-void __atomic_store_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-u64 __atomic_load_8(const volatile void *p, int i)
-{
-	BUG();
-}
-
-u64 __atomic_exchange_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-bool __atomic_compare_exchange_8(volatile void *p1, void *p2, u64 v, bool b, int i1, int i2)
-{
-	BUG();
-}
-
-u64 __atomic_fetch_add_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-u64 __atomic_fetch_sub_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-u64 __atomic_fetch_and_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-u64 __atomic_fetch_or_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-u64 __atomic_fetch_xor_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-
-u64 __atomic_fetch_nand_8(volatile void *p, u64 v, int i)
-{
-	BUG();
-}
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6834980e58c5e2cdf25b3db061f34975de46437.1683892665.git.christophe.leroy%40csgroup.eu.
