Return-Path: <kasan-dev+bncBDAOJ6534YNBBHFJZDCAMGQELJFJB4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E7DCB1B65A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-55b9da7cfc1sf1593673e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754403997; cv=pass;
        d=google.com; s=arc-20240605;
        b=UiX2QY/RFrl1ZSwU3JqjEwgk8Rdr+FX44s5oPdTQPsTjj54TKY0guvTgYRfccoNucA
         Aswuv/kdA8s75g9akic2a0Kw4hpAXsZ7dXrimYal7bgetC/bKtcGsHOBJNm8x/9OGVgP
         zGfo512EZ2mq3zXRyQ8LQdHCflZgrFXnCCVVVFPmmKMZYx8AmIR8sSaF8OP0GLnUHbuK
         7fGgqcRTI4i4klzXcX7LNvB72pbwWCQKUHH8T8OQfxs4k+HLSOvluDTqLoLVZqwPBOPg
         u6KRgRZxGeRp0jBh0Q49sXixeA8cTQ2Odqw1rLDKrPe26AaNsS5dGz+pOurq4Pcyvs7E
         qA4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=oDDpS8u1EE/pPUHMExXslqXzL3zdh0UKeaMcFw5BqtQ=;
        fh=yiy3dY3ba/4qk9l0lX/l1ii50gwTJ/EnsoOHxyCwgis=;
        b=Pq6mqcMLkd4q2ihRYevXJP7uPNK+m78QPD630eqVidfHwGPKFc+LkR9KR9Dvg7bOdA
         mXwUAPT5+hA9JzEc93iBeOO/86syjIumMflh6ri/oMFCeVnde+fISmbyUrp2pGSYQgCQ
         HaJdCk47xa52T/bjrp+jIaDUIkxcIIuacFKKUMI1nydRif3VKTEGwEDdXEMEdaYXQ0+I
         nur4vYYBR3S399CpeK9y+lWthTN0Ouwj7Hb0drkZZICEf42GS2ntNMHazi+sqHmRqsPs
         yS9KNkNSxPtjhgujPO9vnRksblbp4i5k571dPjGs90zopRZvUimfH9wyVqxQA+ETSRH2
         HxpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JNTxH04p;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754403997; x=1755008797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oDDpS8u1EE/pPUHMExXslqXzL3zdh0UKeaMcFw5BqtQ=;
        b=cHjWOcfChZu5zLFfLv9zECeK5UjCAPL6578csgJXO96IFmrzupUeDqP0DmZAPsSjGy
         M4qJzbICw633jlhEgpiItg8gEnkHAPz67KMm11Af+6AhBMsymX2BOARJsDi1mvXDA4iK
         8hp30XiTNXxwsn8KsDUxfkRiNng4EGGKitclN3ArktMNvtrBzHRIHoXIeesnwUxdWbBD
         lYpNGKBxWyai5m2tgppoJxx5fvPkHL3AyGbKZozbk96M5KafD9+/V1+WAkWeujitknt5
         /D/MMA+v7V/PzFXwpEq3MRhZ27MBYSB6DAjIOg4lb3NYvmkjfmKdeCv2swQO1ZippoaS
         4ZiA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754403997; x=1755008797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=oDDpS8u1EE/pPUHMExXslqXzL3zdh0UKeaMcFw5BqtQ=;
        b=Hu2IHY9LpslL/sFHFyx98X9G5gUPsPAKZZj+D/jkr4t4a3YhXbOJnRs7DNNAcxd5GG
         2gaseLQUf9v+V74U2sxwbKe8DfxW17zkFCSm5RN8Go8gi/pxlkC2e2/YhKkFp4zHYyM7
         AhRNB2g02z8HIfgrkMapQR5G+XfYtXeb83zpC2nAhjAUmAmjOk+Q0Itj5rtTpqs2sLKl
         92gPzH5AEhSQzooTkDruLw+LLKS7u2DU0J5dKOzY08YQxodMNAPaQ+hAyFLSyr27eeMA
         JhmXmGWzB398QuYiYX+qGFX5Ltyi73W7VntbOhUbAtp+bd0jpfPS2tmw6r3Sp2qYyXA7
         5NQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754403997; x=1755008797;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oDDpS8u1EE/pPUHMExXslqXzL3zdh0UKeaMcFw5BqtQ=;
        b=vLRnGiJEussH2zGry+PdK/CFQQ68yj2ecoHZ/otQzvD/Smvz/t+L9oUye1xyDChzwB
         hyEcgj3QymLOzQv8MyCo6T9N7E2Cmafoy83Qtxd7zDDPyQGw9PNnEZYWbr+A0B4f+tth
         Z24Lg/O6LVD0eYyuwNQZWsukbgPxRmvNjJKl7SDxr0c3UNTlHzUkxTNmes1Ynfqv//cU
         87z51t4N9Omt81MbPito/0P2DRFKaGIzugFRx4cPaynPoY/iAmznP0/TWW2brW1GGiMG
         V1Dd9aXVMR1iltwrbduFLZzTL9BfPORQx4PtvP83pYn+VDejJDb7lDV6crjn3n8jPrvH
         fXWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVhY8NOemPeVeFdozmjMulSsjh87tOXUS2T+p20wf+f6OJfo1hJbwKeGpDZD4KFvjl0PrEGQ==@lfdr.de
X-Gm-Message-State: AOJu0YyAHwnAelgbpLTjiquM1VLOPpBoeb0MS0jLBid5tH+zlE5O1CU1
	QsqidkctHLqACeRXv6OfHBxQJcPNCEMfkiuu0hmZ/r3gnrpL3VYwW8K+
X-Google-Smtp-Source: AGHT+IFgcspPA+b83OzafsqFF13hDCt3A4KPDULmnJKrlsRN8CVz8Npi3sJhV/DtpbV0m2Fo94fy3w==
X-Received: by 2002:a05:6512:1598:b0:55b:8435:2fb4 with SMTP id 2adb3069b0e04-55bab41c1c6mr1088109e87.27.1754403997065;
        Tue, 05 Aug 2025 07:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZezbQkQe6gbC89js4fwFCL40da28eCG0YM7OCq2hFBCzQ==
Received: by 2002:a05:6512:1349:b0:55a:4f5c:f12e with SMTP id
 2adb3069b0e04-55b87831984ls438060e87.0.-pod-prod-00-eu; Tue, 05 Aug 2025
 07:26:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/5LGeQHZQ1O2TgC7iI/rVNHQS7wPQJx5Tct6HRrccrOwtPQW0Vq7Z5ev7+GZcdqbMAbZDLKRUOpA=@googlegroups.com
X-Received: by 2002:a05:6512:104a:b0:55a:4c18:e53d with SMTP id 2adb3069b0e04-55bab452082mr1233521e87.23.1754403994136;
        Tue, 05 Aug 2025 07:26:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754403994; cv=none;
        d=google.com; s=arc-20240605;
        b=P3Q4q6FWyvmMfPSK8Z9t7EaU7w2p8Vem8Ica+yIu/BhW2m6w/1LJOd9kDCGaNQwIpd
         YGHzfWHLs/Aqy1vWAYXVwTSm1gRRPuHkpY6B4o6cgIAhjq4pWXYXQPUh3toap/c2X/y1
         /1PnMeBV5cxDA4NiNXgrKlZziF071+OR+ap1KUOS2vmyyn1WmSeAbBNrept+gBPQGDWd
         uJymCBI8Z/n5MDgdxSUeeTcGptBrRNW8aMFjaO85dkrtWp9Bux0NI4Iw0LuS3ovIoL/D
         bDvhBs5z7ECZ1Kp2IQr2UbcDa6E432W+EnY1fXVGweJ5elOG0TA//+ScIyNhb+aDnLtO
         AKRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=44Cef9kvp87sJdDYN0I0T3XW3v08YaC6etU0qwyWC00=;
        fh=FOQbxpPiuHnZG99VXDJzYehT7cHyKLOwrKFcVSLh+Dc=;
        b=hDvLqOSI3Rgv60DD/f6DILr5ykb9189koIYfsOMnQEQDxXRTt7e2j4/nuJbtGYlCe0
         M5ETETLqxNEZzviMNsRmdYqmLAfCT+TlqSihR3gcufgYGEJHKMzh4/F77rKYUuN01D44
         G3c2+DVM09PUXExzXvhgWT1nqpNs6ycJJxfHvg/zLmm1gcScWckZ6RRMFAnwZ1AkTRnN
         WW6sd6RaCGlRufOmtO9fcKZcrnf+ZRMCwDmuyuA7ZbB2Mq69pHeqJTqGAkS4Ggg6OSEQ
         VD5wmJRXKCWOE5ijnFeli9PPRqXexmh8viiF+Hs6glQ+D5lyfKoeaLd4vQV4FwHapQCS
         Rg3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JNTxH04p;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8870e498si334769e87.0.2025.08.05.07.26.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id 2adb3069b0e04-55b847a061dso6301787e87.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNTUQ+JwVeHFg2AQSsf/ECYK3RgyYNEI1ROx02evzxbUt4vZ+KV3mBDT3hLm2ZcXB82nlN4lK05nc=@googlegroups.com
X-Gm-Gg: ASbGncu2NuzAoor+3QEUW3ygziEqVZu/Nrp1Emgh7MMEkTVdRLhFWY3rYuzgZpELayu
	E1UNlbN8apeBaBq/Ia+cBe7YYJWlf/vJnOIWu7nt+H52kMruzShTm8yv0my3tU5aGs6Y5JTqKXa
	gvXIy6nGscAxbCbPxpCfCHeyUFWcyeZAoyG7/IArtsDMbakjGAJtuTzmk2e3hHwxCpxMqybmr4N
	KZ/gcEyNog/+wdnzlbBKE2uEVOIDQ6HNMCi6PseA5mBtzGpegJUdwGSrul0G755BPmEdEhz9mpT
	QEqeAj192C8H1iCbLpAS7nLwcVX/rVSkc072nhnF3q6zcOo9hA1wueNo1/xHmNkFZxLT5pJsAM7
	qB7tuzzajy6yh7BceXcyUJO+qdZiKlbGY1qucsqgdjQlpay7+hUaWYuRLGz6U/mSQYLAVnw==
X-Received: by 2002:a05:6512:4023:b0:55b:81de:3576 with SMTP id 2adb3069b0e04-55bab40c2d5mr1298432e87.24.1754403993514;
        Tue, 05 Aug 2025 07:26:33 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:33 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 2/9] kasan/powerpc: select ARCH_DEFER_KASAN and call kasan_init_generic
Date: Tue,  5 Aug 2025 19:26:15 +0500
Message-Id: <20250805142622.560992-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JNTxH04p;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

PowerPC with radix MMU is the primary architecture that needs deferred
KASAN initialization, as it requires complex shadow memory setup before
KASAN can be safely enabled.

Select ARCH_DEFER_KASAN for PPC_RADIX_MMU to enable the static key
mechanism for runtime KASAN control. Other PowerPC configurations
(like book3e and 32-bit) can enable KASAN early and will use
compile-time constants instead.

Remove the PowerPC-specific static key and kasan_arch_is_ready()
implementation in favor of the unified interface.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Fixes: 55d77bae7342 ("kasan: fix Oops due to missing calls to kasan_arch_is_ready()")
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/powerpc/Kconfig                   |  1 +
 arch/powerpc/include/asm/kasan.h       | 12 ------------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
 5 files changed, 4 insertions(+), 19 deletions(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 93402a1d9c9..11c8ef2d88e 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -122,6 +122,7 @@ config PPC
 	# Please keep this list sorted alphabetically.
 	#
 	select ARCH_32BIT_OFF_T if PPC32
+	select ARCH_DEFER_KASAN			if PPC_RADIX_MMU
 	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
 	select ARCH_DMA_DEFAULT_COHERENT	if !NOT_COHERENT_CACHE
 	select ARCH_ENABLE_MEMORY_HOTPLUG
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index b5bbb94c51f..957a57c1db5 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -53,18 +53,6 @@
 #endif
 
 #ifdef CONFIG_KASAN
-#ifdef CONFIG_PPC_BOOK3S_64
-DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	if (static_branch_likely(&powerpc_kasan_enabled_key))
-		return true;
-	return false;
-}
-
-#define kasan_arch_is_ready kasan_arch_is_ready
-#endif
 
 void kasan_early_init(void);
 void kasan_mmu_init(void);
diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 03666d790a5..1d083597464 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -165,7 +165,7 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_late_init(void)
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 60c78aac0f6..0d3a73d6d4b 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -127,7 +127,7 @@ void __init kasan_init(void)
 
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_late_init(void) { }
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 7d959544c07..dcafa641804 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -19,8 +19,6 @@
 #include <linux/memblock.h>
 #include <asm/pgalloc.h>
 
-DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
 static void __init kasan_init_phys_region(void *start, void *end)
 {
 	unsigned long k_start, k_end, k_cur;
@@ -92,11 +90,9 @@ void __init kasan_init(void)
 	 */
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
-	static_branch_inc(&powerpc_kasan_enabled_key);
-
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_early_init(void) { }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-3-snovitoll%40gmail.com.
