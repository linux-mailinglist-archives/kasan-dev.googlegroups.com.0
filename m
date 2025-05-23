Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD7YX7AQMGQEMNHBSJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id CB710AC1B09
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:44 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7caef20a528sf2245961085a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975183; cv=pass;
        d=google.com; s=arc-20240605;
        b=bJBBm+38PolyjNN5+NgKyVcqX6c2ik5w+1fcMMYXAG0q4upIs7U7uPx7xPYQ2+BXlG
         5G4MVMBZ+fB7/EywLuawmgMIrXKkEry7Z86IMHnTx0LscCm6fOXfMV4w80Mf4FrXc3N6
         1cMTJyUH3Jf+urQztsNA2cygBYsr+75n793H61Ov9msx8LI0DcGp/lR0E4crl7DYa0Ds
         Woq98fz2ZrxsNSG83PhlJEOA9r9YIn7h4fjjQoDDYXwdV8htLlFQGP61N7QhtRlvvjbE
         BJItMTG4uZDyIGRe9wRe/j/+Ao40U0GTxFG+AddeoVrdmZoL/nAEoJYYb5x6sDGLbJul
         UQng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=SkmdzHsp5e/exAZoSZHPd3P0WbWm9KC0lqDfhoMujc4=;
        fh=7JK5oxi5AW8quPqIi/PnATZL/NzEJtMT9Cd/XKJ83wg=;
        b=MXZM9gB6KI7yFW6bj1V/oCqGhEEqT6xn4jjli5lBP6f5848MfB+2FTtSw0IGHfHwDD
         NFprZDMwrvtKRNOvl7cvPzAl9v+gRlyl3LHel1O90Vl44E8pM/EnwBiNqzvzIMpzXuxw
         mMcSS+mElOfHRVqwPtdFmO2cTZ6WbAtfVi9/5SggBnAV5MLHAHOiip4MvBobQ+0WXoPP
         3gFMB7mvGpByyv6q6jA9BUJaHnxwGVzg8LrJlRedBNG9hX8bqii6SPIN7+IRB0/cI/zP
         qbT8m0LlHr/mMpXq+i88pFEsJw1heWhNQyH1pMUG7Xmvc2JLaF+9jUoXYqlO/beI+C8E
         +Bxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CHB1UIrX;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975183; x=1748579983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SkmdzHsp5e/exAZoSZHPd3P0WbWm9KC0lqDfhoMujc4=;
        b=sy950PTHeNjfEgnr72wZMNV86TMQSzQYBIgMFE4ZxJ6VPUv2+L1snBs5zUBGX0PbMq
         JF146DTGSeySWCcmczRyw/Mqqo/aMmCrM/RdaxfhJAo+RzoxEvaDbUgSmA1OUqfkCOrb
         aK1qSdgedRFBTS/EEw46pa7qBDXAe0OjgiIEh8T+SOunE+FXxC4iHY9HSWYIo95rQYTc
         7bCE392JemEKhvcgetXpuLoNas3FFZIajBiHCok6Q/tYJt+cvY8sMdkVXtFeiEV9drLP
         X7WCm9Fg2f0O+EMAUWLSQ2iVVwSwO5HuZH5PmRJ6XoXHE9ttZdPwpk5USDU4Vstbt614
         lhng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975183; x=1748579983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SkmdzHsp5e/exAZoSZHPd3P0WbWm9KC0lqDfhoMujc4=;
        b=m0ppqOdUvGZyM3TJYc/E+NufRbYD3xZL6LG0YaQCAah0SMjvQ2cdFIDvatpbVNi3Kc
         4PE1PDKEux7ext0q/NFJXhg3Oe0sJhu36TYqEFrNrsldX9AUVT+i61/6+zRRJjuqxArW
         h/l4BvPA/y4u8t4QheCY3caPVxvswsoHpXj7xEu768otckmTbQoS3M2pXIbK3M7b+j0M
         XS4vqQB4u5cnv653CRjYmiWegaGq7Ih0IcuIy4DOKTeAq0fPi4coZ2Sgf/lgq2iENIOy
         1aJcXRHpkciY+XbbCCE9XA6Ff8hRZru6k+s6Cl0cEw4F4/I19AyzRmCBYU5BMFgyrY+4
         kSGw==
X-Forwarded-Encrypted: i=2; AJvYcCUJmQ4cmCHZY0rP7L/vCDDAONIzY9nRTiRt99sDjMVAZsrUVIkN0X9PxqsnIeMdbQucLCKK/g==@lfdr.de
X-Gm-Message-State: AOJu0Ywn4g7+JHLZoNXMMvqGkY9TI4ytrSZ4UDQEpmsPy418Anf0J7t8
	y+H6ssrzDuXSDoIHnzpB36scNtgIpvM1bLvl83lbODY7kRbo9mekjzJT
X-Google-Smtp-Source: AGHT+IFfwZ5bS+vcJhtqGxwhHFOqpBcaxdqPBDmH6foMhwoz7J94YIp8fplG7XSqVqBXxBHypMXndQ==
X-Received: by 2002:a05:6214:20ec:b0:6f8:e52:ef81 with SMTP id 6a1803df08f44-6f8b2d2e23emr468417036d6.36.1747975183285;
        Thu, 22 May 2025 21:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFUbDAebanemp0xSK1ItK3/c0vm/yS8yMBNbHNNjtL3iA==
Received: by 2002:a05:6214:487:b0:6f5:4843:dd89 with SMTP id
 6a1803df08f44-6f8a376f7f7ls20085516d6.2.-pod-prod-04-us; Thu, 22 May 2025
 21:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLf7S7NX5nXeq4TPUtMomfMf/o78w78WsSaZQg11lgoZYrsJ4JSXTpZ1A/WAMVUWweL/1OIuHQrWA=@googlegroups.com
X-Received: by 2002:a05:6122:178e:b0:526:1ddc:6354 with SMTP id 71dfb90a1353d-52dbcaaeb20mr21137910e0c.0.1747975182313;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975182; cv=none;
        d=google.com; s=arc-20240605;
        b=HXfVzBmWZs3jXuPaTU1YC9tAcWdTT9qlaXto9voPUGm2U+bRyDvmYC67v30gcckkEc
         sM7wtyFwMR5bKw5FrS9zQtWQtzA/IgP4nsNYHSOY1/o4jKG7fAP5+y1V82SyAz/gR0Jq
         iUnQO5oJWxguSytdRNkAlzDm2E1dyNvIltTGn/xgAdFUuVDzl+5kfcx2RiSQKL2tF4AI
         auIG52eaV7FOELg+0aSIwNSbmDFqE/8hL5hWwYTyJslUnPTQOx6ShmPfvgH4nJywXzgx
         a2P/dAvR9qSayRbSuXUxCj2ijQJwnqU8+feqcmqqazZozMEl/QOqhafUyUV55bFu6/CR
         hmNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5WwsZAyhqCNKq8impC0uPdRnLe811mvhdI4uAc7GwKQ=;
        fh=qOFCaHtNK+0niXdSarmI+QdV7reyr7K5o7nVcgs1Vwo=;
        b=aFviqzDAsINZMH4mf0MMKwuvL+0ydXA1rLwmmVj4wWKny15VN3nRkLhehnHecY1rW6
         CP3A84hs+IZAi1KUlF831Wz60yA6kClXcaDrgdqSeBqybc11sUt+3/P7MJszxI5PRCWz
         xAz5RmOL2yDkUPnj1F87lCvTA6PO+YpHzQcROz5e0j753djo5efoDNJsZgM42iPlvgzr
         PNkJZjPT48SExCCfRnWbSX4hvVgTXRVkuijCKdxQWlA1To7Vdq8jR0YYdald0B2oUdxV
         r4UWTeGSCfsUXzXYn1Xd0+1GIQ/LEMbadDYLp0xjsMvbAtOV/IFgLz+ahS4zZOvyj0sq
         qY8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CHB1UIrX;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52dbab564fcsi717181e0c.5.2025.05.22.21.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 634464A959;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3E840C4CEED;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Naveen N Rao <naveen@kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
	"Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linuxppc-dev@lists.ozlabs.org,
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
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 08/14] powerpc: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:18 -0700
Message-Id: <20250523043935.2009972-8-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1981; i=kees@kernel.org; h=from:subject; bh=yaSxmxtYpasuc+rufEWrdAWe3aDh1VboHkgvW7Uuxmk=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3+dEGvzLNyc4frZMlegpp5xqfLf4qvOhQ6vClwWG c4+vkWro5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCJ6nYwMa39MVvl34OWuxWLC YitLL7uZs+fqxoq1bLk+uZ0hXWGaIMP/IouHmyfNuDCZ8fKpT88FFNw8Sr8vU98je2Fj6/LNOe9 62AA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CHB1UIrX;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
s390 this requires forcing a couple functions to be inline with
__always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Nicholas Piggin <npiggin@gmail.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Naveen N Rao <naveen@kernel.org>
Cc: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Cc: "Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: <linuxppc-dev@lists.ozlabs.org>
---
 arch/powerpc/mm/book3s64/hash_utils.c    | 2 +-
 arch/powerpc/mm/book3s64/radix_pgtable.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 5158aefe4873..93f1e1eb5ea6 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -409,7 +409,7 @@ static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
 
 static phys_addr_t kfence_pool;
 
-static inline void hash_kfence_alloc_pool(void)
+static __always_inline void hash_kfence_alloc_pool(void)
 {
 	if (!kfence_early_init_enabled())
 		goto err;
diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
index 9f764bc42b8c..3238e9ed46b5 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -363,7 +363,7 @@ static int __meminit create_physical_mapping(unsigned long start,
 }
 
 #ifdef CONFIG_KFENCE
-static inline phys_addr_t alloc_kfence_pool(void)
+static __always_inline phys_addr_t alloc_kfence_pool(void)
 {
 	phys_addr_t kfence_pool;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-8-kees%40kernel.org.
