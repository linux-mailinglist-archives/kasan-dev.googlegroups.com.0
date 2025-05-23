Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDXYX7AQMGQE6XJHJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 114E9AC1B18
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:55 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-734f5e350d6sf385310a34.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975194; cv=pass;
        d=google.com; s=arc-20240605;
        b=ADaKlzV7TrwcxzMVI/DKVmNj2fBZgZKQqZTRZFN6Sf17NMw6K4kT5IWkdrKVWfDH2f
         biTJ229LWgQ7qAYJDqckURa/oMF1Umqqz1cu+Gijf7X66O1wg2tixZbo8uB2K+FA14Yy
         uFl+lw+c9A2Z8VrYoZZDRb3LcrhWUv6RddipG/xUYw7Ej2t92WFAvr8VJ+P+MHZXEhf2
         esz8Fr+SKJbLzdB6bm2nlYLrZFlO30NgwRT+jr69A0V/loeHiXKbRC3Myz0l97UAs4ge
         QdYfhWklXa6s3FmveIf2pLEU31DRMEpwh+dh/M0jsse2DCWNsdcsq8C9Z0RtUIuLYKRb
         OXpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=G6oQTzYSwvoRt8DRnZzrUQ3639pPF/vq/o+F6hcVXc8=;
        fh=zueCOAXbeKJcQPBJ1lmG7v0av8m+ejYIH8ijQPPn6Jg=;
        b=eNACh7tIB75JFfi40pAV97COGZUmRkm6eOu/jGhFZMK56O97gQSjb8brUJFFaBSLl/
         jTPbCEdDrFB8jDcFINgvJasHShlx2RIv7Xp+NLX2ojqBAwthRNVB1VpSps3Df2b1I99s
         Hvv7leF8A5v9CiC7DBRfm1XG+6aDXiFg82R6qHshvgspeG7b+0Um4CIQZYD8wZxFON8A
         erx5LPHnXIGFbeA0f763B6rNum7G1rBs3E37FyJT33ggevbXrWA111mLJUA1rOQOElOr
         Gxq9j0/FLytQharrGO/wQlk7UDFuo3RE31j6umIj7seax9TvQcKoKS69/YQVB97fhdRK
         sKlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J6TfYX4s;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975193; x=1748579993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G6oQTzYSwvoRt8DRnZzrUQ3639pPF/vq/o+F6hcVXc8=;
        b=MoBK96VqxD9EbLMie8ymIx+KGAQ7rCCyBDhEwFxySY/APSiuIIiEgTBueQiE9j+xjI
         XN21lLUiYGbT+0mWdSTb/ZIkXFvgMSKxcJJGmKDtqqI0v9VpQmotHXDkPu6WUaruSsow
         nF/uIH/b1wyACF0/gONyLaYMDNKL+DtnddKJQrcfdgN2YHYh1L8DAGyh9fJWwJRcJ6JB
         1N13YqRzyV2aqCi4Wz6Lw9lNFDZ2twcCU07IKubyySbPboT61+1gwlJBHHL/uHvwhmU3
         hy10n/9goYEcqRcC61k3JOaI/fqLoahZApBenJifJVvFstQtizbWHJ5WX4Smh9h3vtsv
         OQug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975194; x=1748579994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G6oQTzYSwvoRt8DRnZzrUQ3639pPF/vq/o+F6hcVXc8=;
        b=pfDrkPt72DI3yPGouU6va5o2qoglMRx938xJZ+/otBMlOxREeqnfiaABK1NOB8RPjL
         SNm/qmncAuQik8iigueWetkibATno/MDfWNB9+iT57/PV/IcYSTQ+zlygUSriajJYxiE
         lW+Tk3ZUtZ/PihlDn43tGSCjWPucDtE41Su/0WMeoJLAqCPnduNHZHe276APguXVyLCe
         3c6eS6R31J75IZUMGSkTSSC7cM943zz4mlSjPGaOpxw20hunLlfOMpnmewcYA+AjxOqp
         p0xImjYDd0U+c1YEFF6pWS16FetHX8zCUwHA5dVHlw/end8lwh0urC8mj+GECCx4bi+r
         bn0g==
X-Forwarded-Encrypted: i=2; AJvYcCWF2u+XHZHvXZGa/6cv5xlhXAKP3e5Bruifo5Dwndt1v5ehfccH7bZ4hxsmS2u9+YCc0cwjjA==@lfdr.de
X-Gm-Message-State: AOJu0YzTIpqoFKnvYWhg6VRgt/aF83yB0zM2hQ2UB5BdcaxVVcbPy1s8
	now9BWyesrbux/pgHmWBY/VTeLZScf/7jnQlWwA0eTS6+LXCnHzztWuq
X-Google-Smtp-Source: AGHT+IHQsgsbyKKOU3rAj4E/knfK8XGTtcPlyP6y0BYDSwmD+xFB3ctUd8XDAuLqjIWh32XS7eoO5w==
X-Received: by 2002:a05:6870:2a4c:b0:2d4:f2da:9bb8 with SMTP id 586e51a60fabf-2e83e12d012mr1401017fac.1.1747975182825;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHrRO0GAk0xwZ5BD9k5djs8nNhvS0QwVFPi4Zp66bhbXw==
Received: by 2002:a05:6871:7a8c:b0:2d5:17b7:9f8c with SMTP id
 586e51a60fabf-2e39ce5e175ls5656787fac.1.-pod-prod-00-us; Thu, 22 May 2025
 21:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0aylc7e9otcWIqOsF5LyHubaIFjloYRnm7m03A6QGZEs2gNHDCHcHb4KySHxQPaYzQ67k+jc4WLo=@googlegroups.com
X-Received: by 2002:a05:6830:8d4:b0:72b:80a3:e65e with SMTP id 46e09a7af769-7354c9b98a1mr1259471a34.8.1747975182086;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975182; cv=none;
        d=google.com; s=arc-20240605;
        b=PvjMBlAjj/w+mNiIw3R/6heJUgfxVeBJW0YfzKoa3fRHkX28GZBVzFatp0LcMfAvQ4
         w+aDFWVHDIuaofus73AinIbNYglboGuF4hYD8qY4RxkkEOmE31bqw7fXab27s5EyW87m
         f8xotgcY2CWCrksKtDE6VgwZmzf3DqcZ8myR9Jf0rM7kyKlISEPQNUdpZ5v4bEXcfNoK
         Ms+u9wf86GJODMD6ivKx6CEI58eeUpYiGTzN+EHC473dUpdELN/Y1jR4DMxVoskfwu7R
         6VsqRGDxh4h0LbR5oTg/hZs4yvxn6aBSlZ2xMAa/ddTjfQtWbSjAouQLBW/TcLxjXSP3
         //CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ofDLKsfVFwJjIEEjCE2W6mAUD2nSyNjNn/Z7c86fPtQ=;
        fh=oz88RTf0dButeGlmtWRfG6txWpwk4ivygM1gqmUTwaI=;
        b=CafouJf+XL884FY6aeIKn0wZwcUQ6esh9BZrsxKiqJ2PQDRLTxSN40DlX/39MUtWVP
         esFf2MeOZZ2mzy+4hPaZl6cxAZMzhydJHdw2kBcRx04lJo3LLlg/TWe5a0UCTiQWBgv4
         ntM2jSEhDWiRmOirdIjvQkLhSq2hbeGsZFOqNTByXN5ZM2X+hJgbdmqrlP+MCblVGud4
         fv7ZxckpyPCJTWFOq611QDePUw5tpHJj+5qCV7o2Q46tLRXxBh0B+4iOS9HY2jilXAAK
         9qFxfo0STeVotN7iEVARlIHd0fi5zFLa09iPe/yUkEor+b7qY/2UAL8JwdYBffWP/MEW
         +yhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J6TfYX4s;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-734f6b24065si780801a34.3.2025.05.22.21.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6FB0C4A966;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B2A2C4AF0D;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
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
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v2 07/14] s390: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:17 -0700
Message-Id: <20250523043935.2009972-7-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2325; i=kees@kernel.org; h=from:subject; bh=SyZieAtSFEV9PhSUW/pPII2GWOki6kjF+H9/UmF+VLY=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/W2hxYfnr9mkd3prUpF7sxH1j6p+qa4A+jPlbJO ZrHeJwyOkpZGMS4GGTFFFmC7NzjXDzetoe7z1WEmcPKBDKEgYtTACaynZfhn9Ljrme7X4ZanbzI enOKheqe3dPnMBjFOf2a8H5d36lL53Yz/BW9v3h2neSzt9ozGS8uNX7i59RwPPZXRVlAzeyrGhL 31/ACAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=J6TfYX4s;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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
index afa085e8186c..0f83c82af7a6 100644
--- a/arch/s390/mm/init.c
+++ b/arch/s390/mm/init.c
@@ -143,7 +143,7 @@ bool force_dma_unencrypted(struct device *dev)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-7-kees%40kernel.org.
