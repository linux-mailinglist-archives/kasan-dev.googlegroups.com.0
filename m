Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBD5GV23QMGQEFG25ONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AD3C97C2F7
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:20 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a04bf03b1asf6580095ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714639; cv=pass;
        d=google.com; s=arc-20240605;
        b=EMNSp8E1w7mF82cfHLBNhrJCzw1f8NR+Ly+GGLxPrYFTAemUvVyo50G13FlcAiSlbb
         f+aluas1K/1X7B8/3v/zRXdltu8HOL0RJWWy2pf12JSZ1EbA/unBByw4wNLtJIgMx0Xx
         W3a/eaeeptwU00UH8QS186gWpx//wXeyfDKPsBHqmChebW3tGq4xGcWpyKbEOddZA+PZ
         WQHnTobneBFOZAmrt6QJh7a/bGtKiHilQm2pp9yAV4mHWCBFm9fy5HSSzhluSjKk0UH4
         IutYMMxwyCEn5iT1MXVXA7uwLOO1cJmtAVMiKhlK6VYh9EpSGVqrVa67GVLxzlxN+xfu
         PhWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Ko62QaogvxjcaEjE0nMfoA9oGnKPAJel6j8f1oyytNk=;
        fh=PZ38K1CyUExw3aVikIdnihGgW61/R2urwl/bezNryvM=;
        b=CuUUI/PMFVx6skc/2j+Q8HScfPlPYALYxAwu970HjZgMTf2AsAL3yAlnHiYdZgPMsn
         vaIokVvNKkR1oKP6gfot8tZwKBSfUpvHdsDdbtkC29xZ9INgKMJgQ0x0wEoxUCPKm/54
         PyuMRLLW3AwK2mQxBQBMbjYPyxVwWjMxbtMaRal37nQYf93vEQit1/W5Xvu7Omomi8lN
         1YH44vWk8+kz3WLGQXcWAYAfVmgnSsFZCS3bU+FxGjRG2IKf4ZPvatXSjA5KkRBHC4L6
         5HOf+htDpLTyDw2CyyziqF4pPaqaxLpoOjBagTtIesZ6uRFNwVrWs4RpNEnwSKnu413u
         AlIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DZYKY4T5;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714639; x=1727319439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ko62QaogvxjcaEjE0nMfoA9oGnKPAJel6j8f1oyytNk=;
        b=nOcP891xrWdBqmGIzLnbLZgtR9Bq8lcV6kOCcfkfErPoliWx+N6m7mbps1W6F0eYfT
         D6cZOxeYafK9VeXGp/PpSo5cehz+prNbNS9GBX/KOVjlwwq5B91k4wFUEIMmtEoaUh1/
         3bAsOfKOdvINefghq3jK3MFIUcITGCSy0cGksqvZWJR1iD2FDaIXhg7zz3NkofuQqMO5
         Eh2BHY6w6J9pd5vlWHj4yt9ve0MF3W2GMeHoGXN7fh9qk5RLiXNKyhiRd/Mh88Deam/M
         ilPar0pnAOl5O2SmC4fNZ935PvOw9eF9Uq583GXx7G7ZxAm1RfRYwjPGkzi0JIOGA3Qm
         Bcqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714639; x=1727319439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Ko62QaogvxjcaEjE0nMfoA9oGnKPAJel6j8f1oyytNk=;
        b=eg3n3BKrUoNFXkYBLa5MuStIiqt8rc95szmfFdWAY/RZr45aRAMl07IVJU8taXq2Yw
         AckK/M9dmZBsli3jIJwO5ucV11Z9d/AQO33A8/GkzW2KN11qc3M4I1k27UuKK7WDFJu8
         NFEensPwSlPLQkcIirr+d4xOlTgDvmwdfxkXKe3c6hHH3Fz5iTC/f7vywVmms6C9Dk88
         VUI8spQnfIA1LL0BqxZQgEpBCW08Jtz6owmvF4DUS7CRZbr2krbmMMZGcImoiCl4QDUF
         p+0D/5R+8mPe6/enhuXWGacaXFdWF3DGCRxbSnkNSXj1PeZ8KNB1rrxrBlrT8ieiuG9S
         ELgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714639; x=1727319439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ko62QaogvxjcaEjE0nMfoA9oGnKPAJel6j8f1oyytNk=;
        b=FJCq3hqtKkP3OOpHUacwPAJdvdAHZC+AdkOKtkDScz7L4oY0ScC8RGJEQUxrJ/DX98
         +Hoesx8tmuubZyQ6LLlWnG48n75XrMXS2e1wych0RoVvIwNW5Vp4466rJCI1wlIQpQns
         Z0jSkeCX06hyw+u5s+b/Vhn8wGKWvZifTQBFl95ktlUxZ8uppHceq/CTF8EGja9ZGPM9
         6OGzeJmpadZX7Ihc83uW6j2kKxnuK9wFL8jMChhmXiEcmkiG5oZVDM8kvR0HWo4r5URd
         FUkA8W4r5qSXsIDnRpR1uKP/Mil+rH3t8CxyCbCNa7YuYga2/CXML6qx2fZhsVS0Nzrp
         UNRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU77b5NH7SCW6yRt49XKscEM4JH6F3zPUXBgqGn7FE8Lu4Vf5AgoYt1LyTxZWvLSLudmVZhkA==@lfdr.de
X-Gm-Message-State: AOJu0Ywf6JpRyaHqvgnSzm6GeHKWQvJ+eFdQX18MxU5qTr/GXhZ+3BLZ
	H3MAyjw6QsVukiSBTYCyGSwW0LlZ44k6p/ZA/GDJ6LCKSmP5bhJt
X-Google-Smtp-Source: AGHT+IGIlmMwEle8lrJPUW28GkRPI6LExia0aHDzVpgYDMczZgJaf5NjTCPlVwIf4/zBII0ieGTnAg==
X-Received: by 2002:a05:6e02:1d85:b0:3a0:8dc8:4cd with SMTP id e9e14a558f8ab-3a08dc80569mr186358755ab.23.1726714639191;
        Wed, 18 Sep 2024 19:57:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:18cb:b0:3a0:8dfa:eac with SMTP id
 e9e14a558f8ab-3a0bf147bb0ls3855655ab.2.-pod-prod-01-us; Wed, 18 Sep 2024
 19:57:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdWKOuFAYrZ/gxT5noaatrnyf86Xnhq+oWaYQqvOK6Mv5DOtoaqJczFc3E/pbpflQfQf8oz8q9pjE=@googlegroups.com
X-Received: by 2002:a05:6602:608b:b0:82d:6a:4cae with SMTP id ca18e2360f4ac-831830edbd1mr809401339f.3.1726714638330;
        Wed, 18 Sep 2024 19:57:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714638; cv=none;
        d=google.com; s=arc-20240605;
        b=h/qnwjVOsjSgBKrf+Qsvm5OWryytRRBYwF7t1a6L1SmsYoqJTiaUieEnGaaE6JSa/Q
         1wkaWcZxabAb+JdHBHV177i4BgdpnRMRe3RwZgTMuIYYyvwVT/g+IUK2YA3HqhChti+I
         L90B6dmey1R8M0aLFX87xkeV2WjqkZgsYPGFYupnpUCHzeHp2Nhv/inwljG/kWqrvyqm
         8ljZRfVLo+YW0lB8gJM3BV/fUEMO2b70zaWvJ5lDU2i/UnMgzJqT8cS7renFGV9XsRu+
         Qpbc4u7dOQkeciaPwvVh0fwM41lKE4Pmsyr6uCLVia9jRgIeCfJ0+98Vf2+gBsXE58GL
         iRlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV6BxL5gMqFPtklTutfX47z8PwIuU3wFqvoyRitrLCw=;
        fh=Gr3QkJYjjj2oC6MchDeSfrCXvEsM0D4UChU+ehC3GDo=;
        b=PvkfIbzec0ylSn3dklpdKAzf5C5xd2ivsabft5hTBytRd2uspUvsYxSwAbDzUK484j
         VfNLMHnGYzPVXT67qaufi3AZBUR74bowAU909ttXAj/FW8nL9NUX7GnKgnPF2tnr9h9n
         nKTAa6/8//gTImMghluubXkZI09dGaomd2KVJnnBxR2Tzu574Gyu+IOa3BEe2fkLrgsS
         bTwWdpI8cBmXlJtee5+mi4WyRUqwhL+lAz81ZJ0jF5zWKqLRf0BLmwVrcyr5Ny3bCJGa
         g5D06DCR2PG9e1QtyIUDgJsYCLx3oKv+szvY19P9W5Ork2CLoKSV7iClVYUqaqN0hQYx
         BP4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DZYKY4T5;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d37ea2cd56si500497173.2.2024.09.18.19.57.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-206e614953aso4776115ad.1
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWaQ1pC4MVVAFnU+C1UfJ0I4AtnEswIrEU9pMUGXksGiD4WyIAoLTl+7o/PwwNXPMh3zY0cBIpmW5s=@googlegroups.com
X-Received: by 2002:a17:902:e545:b0:205:7db3:fdd1 with SMTP id d9443c01a7336-2076e3b7821mr382291845ad.36.1726714637877;
        Wed, 18 Sep 2024 19:57:17 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.57.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:57:17 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 11/13] book3s64/radix: Refactoring common kfence related functions
Date: Thu, 19 Sep 2024 08:26:09 +0530
Message-ID: <0711340e9050001020c284154064b3a4cf781045.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DZYKY4T5;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636
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

Both radix and hash on book3s requires to detect if kfence
early init is enabled or not. Hash needs to disable kfence
if early init is not enabled because with kfence the linear map is
mapped using PAGE_SIZE rather than 16M mapping.
We don't support multiple page sizes for slb entry used for kernel
linear map in book3s64.

This patch refactors out the common functions required to detect kfence
early init is enabled or not.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h        |  8 ++++++--
 arch/powerpc/mm/book3s64/pgtable.c       | 13 +++++++++++++
 arch/powerpc/mm/book3s64/radix_pgtable.c | 12 ------------
 arch/powerpc/mm/init-common.c            |  1 +
 4 files changed, 20 insertions(+), 14 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index fab124ada1c7..1f7cab58ab2c 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -15,7 +15,7 @@
 #define ARCH_FUNC_PREFIX "."
 #endif
 
-#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
 extern bool kfence_disabled;
 
 static inline void disable_kfence(void)
@@ -27,7 +27,11 @@ static inline bool arch_kfence_init_pool(void)
 {
 	return !kfence_disabled;
 }
-#endif
+
+static inline bool kfence_early_init_enabled(void)
+{
+	return IS_ENABLED(CONFIG_KFENCE) && kfence_early_init;
+}
 
 #ifdef CONFIG_PPC64
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
diff --git a/arch/powerpc/mm/book3s64/pgtable.c b/arch/powerpc/mm/book3s64/pgtable.c
index f4d8d3c40e5c..1563a8c28feb 100644
--- a/arch/powerpc/mm/book3s64/pgtable.c
+++ b/arch/powerpc/mm/book3s64/pgtable.c
@@ -37,6 +37,19 @@ EXPORT_SYMBOL(__pmd_frag_nr);
 unsigned long __pmd_frag_size_shift;
 EXPORT_SYMBOL(__pmd_frag_size_shift);
 
+#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
+static int __init parse_kfence_early_init(char *arg)
+{
+	int val;
+
+	if (get_option(&arg, &val))
+		kfence_early_init = !!val;
+	return 0;
+}
+early_param("kfence.sample_interval", parse_kfence_early_init);
+#endif
+
 #ifdef CONFIG_TRANSPARENT_HUGEPAGE
 /*
  * This is called when relaxing access to a hugepage. It's also called in the page
diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
index b0d927009af8..311e2112d782 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -363,18 +363,6 @@ static int __meminit create_physical_mapping(unsigned long start,
 }
 
 #ifdef CONFIG_KFENCE
-static bool __ro_after_init kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
-
-static int __init parse_kfence_early_init(char *arg)
-{
-	int val;
-
-	if (get_option(&arg, &val))
-		kfence_early_init = !!val;
-	return 0;
-}
-early_param("kfence.sample_interval", parse_kfence_early_init);
-
 static inline phys_addr_t alloc_kfence_pool(void)
 {
 	phys_addr_t kfence_pool;
diff --git a/arch/powerpc/mm/init-common.c b/arch/powerpc/mm/init-common.c
index 9b4a675eb8f8..85875820b113 100644
--- a/arch/powerpc/mm/init-common.c
+++ b/arch/powerpc/mm/init-common.c
@@ -33,6 +33,7 @@ bool disable_kuep = !IS_ENABLED(CONFIG_PPC_KUEP);
 bool disable_kuap = !IS_ENABLED(CONFIG_PPC_KUAP);
 #ifdef CONFIG_KFENCE
 bool __ro_after_init kfence_disabled;
+bool __ro_after_init kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
 #endif
 
 static int __init parse_nosmep(char *p)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0711340e9050001020c284154064b3a4cf781045.1726571179.git.ritesh.list%40gmail.com.
