Return-Path: <kasan-dev+bncBDCPL7WX3MKBBY4M43BQMGQENGGVKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 61447B09740
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e05997f731sf27149385ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=QRtIZ69K01vd02AqyOz3J62x7fBAfnIQmd/KC/DTbe+FTF2SaRa1dIN6yRuWsRjopQ
         nRc4Yp1URYFbIrzqUlb0xfd8lhey3Q0vGw8dUpG/ytirc3ckJY+kUEpsY1yCBuh+CL/9
         YZy+zVDFLuyAQ2tIIhPoBzHk4RKxY85MwYUNYLL/izr049lTU220fqZd4r/kYfzlbP0j
         vA/VDo0VbUvWoMCQHyAVcjCauCx233c4TpaBoJi9TkjJrr9jECLaZ6V60Ybjia113AIP
         sJAjZdDqnY5TtwoKTratxP+EXFKwGL6F/2drBKBS90j+pzhT7OsFHBAXzO2suBfO3n8d
         iNUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+HZ+1efiLzD1HCfwS3/BHZ3qmozbEvaq6adV9M7mIBg=;
        fh=X14atD+y49cEeigz64CAwP09R5fx7fSlTX6KgPAWiW0=;
        b=dzIt4SePgyT+NuLN6chEOlY3UcMxGzad4O95bgPVjM1A7XSqCTSwzWT9BhmfpGC2Ug
         F07Am8Pcye5m6dnhfExhC86+XKoy+oO6tvH6KklCWJ+h2S+QGrR9tnO9iMdGKvC5t8ju
         fOqtSLXsn1ApNfMWeYkIwuQkR3xCERdzCl0zsxRPWwTJp2TDqknaY7OHcVBhEUwXxDsZ
         32892WAldZO4tjIKm+uTYr+Dne/FUw0EuQWSIi6Ts9GDjZebEJk/HQgrr6Tci4OFp7Pg
         GgteaAb0XNs+tOdtwfVKf03taGh3o3xur1bwrGWtSHBah8uDimfEIGJ+pY0yd7eZJdDn
         xw2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bCLGzgvX;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+HZ+1efiLzD1HCfwS3/BHZ3qmozbEvaq6adV9M7mIBg=;
        b=V2qpyFfBxkgxJT0PDUxynAtiuaaqb0SCenG4dt5vlh2o8Tbav3ci+dEYgXHLmZGsjt
         sAJ7aYpNWfmYBTSZ8BR3diLhyXNfvrmKmiXQGdsSHPdzhdaTMnO7Ar1Y0Lr3lI86uJhd
         t8dwZ2T5fzDgWGQ/GTCHcJudLiE6R+4aUb1lTueE1PCRvvbTrRqngMM5wkNn9+sdKhEM
         z81qZjE5BnQhh0vha30b/AXA1suq1zkkbpkhXh4YBoAvdC8U2Zk1xFqOn4nfDIH05Del
         8eqP+cJPZXZHDZV5edjhh7MpvRg+RXCYIuYr5xpnhW+cNHmlmcl7wPrYgQ+Z4p2lRpnN
         SgeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+HZ+1efiLzD1HCfwS3/BHZ3qmozbEvaq6adV9M7mIBg=;
        b=YiK2wau2tQFH3UxSB/krSi0JmtYzIHpZhYIuujR5vweVyD3GsbTqpMkT/rMaO95DNR
         u2s+aZTVr26g40Y+SvrB5IkZmsJtJYxy+Z/aO40W4qXKAodOvKCeHgMftVp9CCVYzWgt
         gG5EF14qHPNM62yCncxNrj6VjLHymRKtuNnrhdyxxUcXGCnH7NLARJ3v7aTjfai6uRD5
         MJpNOX9WMuExOOh/stRExKWbT7CrIjWUeC5vI4o8gcCKkK/kmRGLT1+rkZdncmim2ifc
         f8L1MGJ0lUGj0AcAierCLAE+YsATwFRaHE2X5dwYHNVH95b8UMrBoEkOVtyDNVdl1xEP
         xcPg==
X-Forwarded-Encrypted: i=2; AJvYcCX2FDbLy/i95hErg2yLSeb3ar1BbzwuI3fS4IxrBk31quGmQMekQcCWHyt8J9sYffkjkYdn9Q==@lfdr.de
X-Gm-Message-State: AOJu0YzvU55bvWeV9AzxbxY4yK8ac7SwhGoMacyAP9bVffQa/Q9p+rJo
	MZjjHmzUZPVUz6WbqGO/kPO3N+3j2zJmsrMzhe5qhNi9dQ2ee3TbpeHO
X-Google-Smtp-Source: AGHT+IE+tE5Gn1fQG3idVvDs5CCvLiEhO8G0emCjylYVZcZZLgBsVaxayb5egX9i+HXuQhkPwHFGzw==
X-Received: by 2002:a05:6e02:1749:b0:3dc:88ca:5ebd with SMTP id e9e14a558f8ab-3e282ed1c21mr98048405ab.20.1752794723514;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdDli72FDxJk/hynhLYKeyQ8f3QQQxDIc0UPevkBQMIqA==
Received: by 2002:a05:6e02:4811:b0:3df:1573:75e4 with SMTP id
 e9e14a558f8ab-3e28acf373fls14559615ab.2.-pod-prod-08-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj4tZyLoiO1h4jCq1Ik43T/tMOM8boMthJnraJDGDegPKQPsrLP1QDHuGKCXqRGEdfGHAqhNCn9aQ=@googlegroups.com
X-Received: by 2002:a5d:9559:0:b0:876:b8a0:6a16 with SMTP id ca18e2360f4ac-879c295b338mr959230839f.13.1752794722657;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=BbByglTySzlRGto2kPiVKpiAawsoeH3WlawD3OHr9gxj43wuPlHN4BB6j2/hlVskk3
         YGSbN0TBSIkP+1lYd4AE4YmfCKc4FW9Pti79c90CW3shNkbyTUsajARlBzk5cVjUr5HA
         Vb2YBSX05G7ik2Zv5dNhnKDQjZoaIK/tPV/9reyv3naaa0u8Yo5EckLFwlZk7Njh7eK+
         qWOB0VWXv0Xhe4WoAlQF2ZY/DjfFhVrqYiUE0iQNUTe/oK2zcv6/zh4AK3fVhLYvA1RV
         dlu+x5ZMHVkww8JEJFcb0z68Tvp26Vg6xCLjv4Oa+I2hqdC6tOaVpHgvbCN0eZ1O1hXW
         6xCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=p9nb4+HuUbLHT0nPoaXq8rPVIIkeznEeRR3Cry5eQV0=;
        fh=Md5d9WjXxCwS8bnxiefSYJ65aFtEyCK9tWCECJwP5OM=;
        b=BH8bojubBBkxKxWhpD7Nqpcpme6LLeLDuvtd9jk2gwbaM+tXzf0T7istwgS/ySYHHR
         1/ST4O0OzmgvIPvfudV49xJFlZWTpZUr0/uF+v8g9acyIjzA2N5NVuzyRLsrWVMyupb8
         ejWYZVW/CAvHbC4FEKb/WTueN6cvg415xTTB/GsjJ6/sjahb/rIPH44riCmwhHzldV1X
         1nSke8ISCCaSCGlXY0OBMhiRBYKU4o6RSr2dPiQgKK23Zf8175z3WgqQszVx6iC7EtMF
         zPg3FfnZkUJoJhNQtl7q9wxeh5JoIdj+E0YsGoyQJ6nfd6aUcZnd/D3RMbJ7CRpWAqfx
         a6Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bCLGzgvX;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5084c8b00casi7358173.4.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 50C9061401;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8A518C19424;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	Gerald Schaefer <gerald.schaefer@linux.ibm.com>,
	Gaosheng Cui <cuigaosheng1@huawei.com>,
	linux-s390@vger.kernel.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 07/13] s390: Handle KCOV __init vs inline mismatches
Date: Thu, 17 Jul 2025 16:25:12 -0700
Message-Id: <20250717232519.2984886-7-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2371; i=kees@kernel.org; h=from:subject; bh=w4dfSlEX1TBFugBqGp8JAUT2yBh6pSwtKD0mxGK1YQU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbdG/2KY8Xu85O2j+4nWyVw/mC3Emf3168P7KWTN/x p5rPzPPrKOUhUGMi0FWTJElyM49zsXjbXu4+1xFmDmsTCBDGLg4BWAiD+QZGT4bhW+wyPBOq197 8b3pj39iU253eKhfucT7+XV+gIb17DkM/738av/xuz8z5jvAWfzMWOHsI8UljCZsWs2/wlaI/f6 Yzg0A
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bCLGzgvX;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

When KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we have to
handle differences in how GCC's inline optimizations get resolved. For
s390 this exposed a place where the __init annotation was missing but
ended up being "accidentally correct". Fix this cases and force a couple
functions to be inline with __always_inline.

Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Gerald Schaefer <gerald.schaefer@linux.ibm.com>
Cc: Gaosheng Cui <cuigaosheng1@huawei.com>
Cc: <linux-s390@vger.kernel.org>
---
 arch/s390/hypfs/hypfs.h      | 2 +-
 arch/s390/hypfs/hypfs_diag.h | 2 +-
 arch/s390/mm/init.c          | 2 +-
 3 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/s390/hypfs/hypfs.h b/arch/s390/hypfs/hypfs.h
index 83ebf54cca6b..4dc2e068e0ff 100644
--- a/arch/s390/hypfs/hypfs.h
+++ b/arch/s390/hypfs/hypfs.h
@@ -48,7 +48,7 @@ void hypfs_sprp_exit(void);
 
 int __hypfs_fs_init(void);
 
-static inline int hypfs_fs_init(void)
+static __always_inline int hypfs_fs_init(void)
 {
 	if (IS_ENABLED(CONFIG_S390_HYPFS_FS))
 		return __hypfs_fs_init();
diff --git a/arch/s390/hypfs/hypfs_diag.h b/arch/s390/hypfs/hypfs_diag.h
index 7090eff27fef..b5218135b8fe 100644
--- a/arch/s390/hypfs/hypfs_diag.h
+++ b/arch/s390/hypfs/hypfs_diag.h
@@ -19,7 +19,7 @@ int diag204_store(void *buf, int pages);
 int __hypfs_diag_fs_init(void);
 void __hypfs_diag_fs_exit(void);
 
-static inline int hypfs_diag_fs_init(void)
+static __always_inline int hypfs_diag_fs_init(void)
 {
 	if (IS_ENABLED(CONFIG_S390_HYPFS_FS))
 		return __hypfs_diag_fs_init();
diff --git a/arch/s390/mm/init.c b/arch/s390/mm/init.c
index 074bf4fb4ce2..e4953453d254 100644
--- a/arch/s390/mm/init.c
+++ b/arch/s390/mm/init.c
@@ -142,7 +142,7 @@ bool force_dma_unencrypted(struct device *dev)
 }
 
 /* protected virtualization */
-static void pv_init(void)
+static void __init pv_init(void)
 {
 	if (!is_prot_virt_guest())
 		return;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-7-kees%40kernel.org.
