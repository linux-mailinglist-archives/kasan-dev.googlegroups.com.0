Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBLMA52FQMGQEKURO3MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FE8243F66A
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Oct 2021 07:01:34 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id a18-20020a1cf012000000b0032ca3eb2ac3sf2838083wmb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 22:01:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635483694; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPrVNk3Uoh020e649k+hVBSDSrvoQhKNyBohVUqj0Hi2pKnp8fdFKEp7YQ4iMsMv/X
         ZpsOLFJ04nzkhgQAi+20UfZw4FD+cRtd7oH15FKU+9rpDRbvho/AEdINtTyx/xwfQpW/
         Ve/4iFNqWWgKqstIuAS0ZRjNgzmfpHbDhrwolo1T3kFvJE3H2b84C2ni7hYdjUlFt7Q1
         uRVLqv+EAGSSEGt2V6woxPXRXGEAZLQJb29rzLagG3XGvMEpCLsaq47hoH1abPYPD26D
         DFqNAJCP1NLZmEVvKmV8SVZaRSd8Byj/wvVPDE/ZrW1HqfVxmsx9ytSV098OY47xks4L
         l5eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b1394WuewwngUv3XLvrcxztH+fK33uvdwb5aLUM0Rxc=;
        b=o6Oca0DWSgN0pn1BYDRxKnOv3rIF18pEs4hxw9dLySHgxN833gImiSYaSKiOBIonRb
         F3vIaPmzCxBchIpV5D9d+ifDttllFwOms938Ff6AGlODnm0e0DvQy/oQGpvWMQRu/0oK
         y04bh1nI2dJ26MN8VguQ+hTrPYmZYeYhcPi+q+8x8A4v5tqv39Jiq1Gkqm5cqKUmxBjh
         t8WXApioiKlA70ZhGUdO7P5XbdhVpIfjKPrqkIWIUHNAraULxkc1ImskWtxujGeZ5Uy/
         BCRuVMIZH7qNd/P7fwjhvxjOSXXaSHi7KaCJBNEkerMQN9/JEii5OeQwlHr7yus5+UJN
         QMWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=v36YWjIp;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b1394WuewwngUv3XLvrcxztH+fK33uvdwb5aLUM0Rxc=;
        b=UCFN5PFrzLB5Tw6+8fql0EvIH9CNJMygxKFcEuaRJ6un/ovlK0XNFvQLaQsE3Dmhxh
         AQLDFXqY3rmp8v3RQMsgUHqKD+h5X9qcqFJaKHzjc8kRUxh0XOVKErcQKOkAPqsVlsWH
         zApbxoMzTHYeESKFLAXhSmsSG1XYxNGPnWszUGvfFbte6PvH/LhGrrKSaigjrZAD46zA
         wgyz6J8LkraLV6BfG0CXJ2L58EV2Gw1J4slNUysfO/42g7xskxvXcEuHjNmgFmgIUY+F
         32IRJqyy8L6tHqLO4jILo1gJhUCJgCqUPI8QH/yK7XRA5ze3gSM5CZjuuhLI45ZyL9YU
         tamQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b1394WuewwngUv3XLvrcxztH+fK33uvdwb5aLUM0Rxc=;
        b=ddF8L8gF8SwoddSOoiRQep3qQMzEtIVyTJ7T3U8L4qPD3IJ4o7FU4pzD2/C5w+qWOG
         RMSBoiTGhTHORv8NaeePLr4Q54I+SuS+m/x7lVScOuHeNA1EVQNxjwLbKwOi6fnjbR3f
         WnC4M43MHt2eQxJxoy5ymKZtWB92zoMDvGvMLlzHlF4ZiBIKHVRW0pqi4GikOVHjXHyj
         Lpzr2X5cFMevxRvlnOoXvvKIKArrLPOvoso+m1k/nl1klPU16DcUkBhPRBTa7R/grBbu
         dBqEdHoD1yCJk9+9WW7F30nd3xHYWowrEDgcvZ81UPMpEYigZUQll1e/mPG0m68RXjFP
         qR+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ogjo4BrEJUNtXZjVY2ysKIDUfEmXrwgNsj1KSUqKShTUWOi5C
	Rs9t67I1bbB7eYPcyRPsabQ=
X-Google-Smtp-Source: ABdhPJyvy0DolMFMCRfZNaq50Zbb1fIwRN0I4WR8TqPIpveG0RDrlTeuh5zm9ZC2TWmGIA+63abC/A==
X-Received: by 2002:a5d:4b41:: with SMTP id w1mr893821wrs.437.1635483693965;
        Thu, 28 Oct 2021 22:01:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b92:: with SMTP id o18ls5961092wra.0.gmail; Thu, 28 Oct
 2021 22:01:33 -0700 (PDT)
X-Received: by 2002:adf:ca09:: with SMTP id o9mr11135249wrh.303.1635483692979;
        Thu, 28 Oct 2021 22:01:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635483692; cv=none;
        d=google.com; s=arc-20160816;
        b=bhmxbtp3lumUnkLhJa+o+1esohnXogeZZkZDqiB05tbUkhQFR+GRANlo8aL4qgx15o
         MGJ4vOjtlAfLLOGZdA+uXdvNQNenkE5XYTB8Zix4FcimS2Xu99x3699rYkpyfUjAlSpU
         ivSuLMJp3zh/s8lDvkk9cFT0buUG3jbzuNV6Oi5mqcClLvpU35Q1PI/HKCqBgeQa1J3U
         Sby453mEUIcuITu9UIei59sJpqPyyZQlxoFucQ5mdsW/L3WpXGf2iW7Vzhju/iey40M6
         O5E3l0y1PPuaK8f12ANLbIEeLJ5bfh1zDWNXE+gBslfWDpE3z0LQ2QSdfyMwWkSR4s4t
         YWPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e3b9czu737yTY5HxipcQc4ldTFaXsWhzUIsobScJLNg=;
        b=Gs292vK6K9UN17rU6XRyoZFcNTfxC7q5/x5QDAVPE/rmT/uPpoEGOFvD+vUywHJxD2
         32Ai6VTZt26sZfNBpNPobseD11gwn5oddH3VERM4wS4mvuAKQl3RB+anrBKwyM0FEC5Z
         ofTN5lG4U/3JYXWJYa7JCvieA1MrybEI72cu9k3kRj4qdHCB/37J9hIlsCkXHxgO99Ui
         55qgjEX7xBscH/vX4Sie+xP+jgBBHUtjfSD+e1AqdQIjBGdPyuQDX9dGrWX1WEz/84/H
         Rn6hlby3Wvuj4BDYeUKhNaNi9rV1EjrSKtt+YBTp4sDXlTRiQnaWM/u2U6ic7DzdZW0+
         1ugw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=v36YWjIp;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id 201si69385wma.1.2021.10.28.22.01.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 22:01:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com [209.85.221.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 7CB7A3F19C
	for <kasan-dev@googlegroups.com>; Fri, 29 Oct 2021 05:01:32 +0000 (UTC)
Received: by mail-wr1-f70.google.com with SMTP id q17-20020adfcd91000000b0017bcb12ad4fso145932wrj.12
        for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 22:01:32 -0700 (PDT)
X-Received: by 2002:a05:6000:18c7:: with SMTP id w7mr11163972wrq.411.1635483692206;
        Thu, 28 Oct 2021 22:01:32 -0700 (PDT)
X-Received: by 2002:a05:6000:18c7:: with SMTP id w7mr11163947wrq.411.1635483692049;
        Thu, 28 Oct 2021 22:01:32 -0700 (PDT)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id g7sm6260959wrd.81.2021.10.28.22.01.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 22:01:31 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Nathan Chancellor <nathan@kernel.org>
Subject: [PATCH v2 2/2] riscv: Fix asan-stack clang build
Date: Fri, 29 Oct 2021 06:59:27 +0200
Message-Id: <20211029045927.72933-3-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20211029045927.72933-1-alexandre.ghiti@canonical.com>
References: <20211029045927.72933-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=v36YWjIp;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
Kconfig, it prevents asan-stack from getting disabled with clang even
when CONFIG_KASAN_STACK is disabled: fix this by defining the
corresponding config.

Reported-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/Kconfig             | 6 ++++++
 arch/riscv/include/asm/kasan.h | 3 +--
 arch/riscv/mm/kasan_init.c     | 3 +++
 3 files changed, 10 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index c3f3fd583e04..6d5b63bd4bd9 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -163,6 +163,12 @@ config PAGE_OFFSET
 	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
 	default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN_GENERIC
+	default 0xdfffffc800000000 if 64BIT
+	default 0xffffffff if 32BIT
+
 config ARCH_FLATMEM_ENABLE
 	def_bool !NUMA
 
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index a2b3d9cdbc86..b00f503ec124 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -30,8 +30,7 @@
 #define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
 #define KASAN_SHADOW_START	KERN_VIRT_START
 #define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
-#define KASAN_SHADOW_OFFSET	(KASAN_SHADOW_END - (1ULL << \
-					(64 - KASAN_SHADOW_SCALE_SHIFT)))
+#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
 void kasan_init(void);
 asmlinkage void kasan_early_init(void);
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 89a8376ce44e..54294f83513d 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
 	uintptr_t i;
 	pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
 
+	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
+		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+
 	for (i = 0; i < PTRS_PER_PTE; ++i)
 		set_pte(kasan_early_shadow_pte + i,
 			mk_pte(virt_to_page(kasan_early_shadow_page),
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211029045927.72933-3-alexandre.ghiti%40canonical.com.
