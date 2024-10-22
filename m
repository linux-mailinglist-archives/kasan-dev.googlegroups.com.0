Return-Path: <kasan-dev+bncBCMIFTP47IJBB7MN3S4AMGQEUFOV2KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FA289A95CC
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:26 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5eb85572083sf3245651eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562365; cv=pass;
        d=google.com; s=arc-20240605;
        b=Yw9LQRLP+iLYMpHHV9H2G8mcKRoXv5dVJvNZnc/qel5BAS7/28r8RN2liHxLmQ0cDZ
         Mz/PWik0uhvH+sgh9e2ZvQmWKe/hatD1NdddqeCuj8+O4R7ljX2vPr5U6UezrXootp7H
         2vG90CMjjdqJx+lgh9e7TdMXBOLutFe/oMUaLv7er72W2+pHgNeSP41FMZA0K+aXSM2I
         frtpFmzYlQLsDk6tsxyQTwYjWdSEPRFiT2pq8S8GcLk7Lt8rfxyIFE72C9sjwFbRvoUC
         NrrZhRWbW2kJrXWEnvN//VtRoanxYG4gveqUtKnyk3oiiRnm+MX4hYOVnxVDEzcCp5Cf
         9r3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=40bddkVNVF20QNaQ3WAptd9t8/vyRXmP9Uc2a7h5bQQ=;
        fh=3PreGMAb0PjTA+ejFDvQPVVBcvugTn15xgpX80UUGms=;
        b=QHajRow9pUKq5FSIFEQczzaXx3QxjFctZsz374V+QSWfnEoJF7wTcY5t9yhCM4ULi8
         3Wx3QR9Fm0GTBjwm16yu0DUWHJ1juJPXoBrV215UcqAoTkmtg20H8RSBlQBB1Rj3PIKY
         a2HcU58CA4hgcPTM4F3ltuP0H0m/Ejw8vCz/HJWTQgxIC29dHAEQxuaXhbWY+WLOptTz
         9PNjJtM+PkUClZGS80T+6+cOr2DSjWpfndI+roHb0iPlh4ky8mjDkQYe/2SJAPeCjuVi
         9x037GkZSPIoQ8rBcTgQ4c5lj989R4f4BQIkDh0q6sk6tUkehpdP1NYnccwxlS2OVKvn
         wTXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=UNzi9Yoq;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562365; x=1730167165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=40bddkVNVF20QNaQ3WAptd9t8/vyRXmP9Uc2a7h5bQQ=;
        b=Nx9+i+JMGYF3V1t63Y5KOfE75tfjfqiHIGrzm9oOih9BpjxGax0o0FdLN/Q+nh6tmx
         xUI7Ryqrbuj9dYBiimx3O9UiGURtQLsUvwiMIRwdfsf3oxXNTTvTOcqoziJiMaDQpwcu
         reJdj2/QerXEx3koXFKYEnuae7CLXZy/zJqt27OGkEmBemoOizooXvvn2Yk5kXUCqwHn
         tU6rN1QsPPIeVl+uw0v/Jwj8TUW8Bpnpb4ilY9ywGYEToAQ29HzTKjaQZHro0fuCiVZF
         yIMoo4PE8p+QJY3EbTrxEtFo2nq95wo/krwXMIeqJEGklbmtqIB66GhMZwNYKRBSI6+J
         SGxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562365; x=1730167165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=40bddkVNVF20QNaQ3WAptd9t8/vyRXmP9Uc2a7h5bQQ=;
        b=XbK1rJIfv5hcgG7IgUB9guKFZVbgYC8tbRpoTOUTgjUMmeKn8nZkYV7nrZBrPyeBCs
         SstxW2jM05qVCxZ192vghwjN6eiUMC1lSX9JXjy7vPlnrF7HApG7OfzJzRVrod3ue3gw
         9B/NPxSBaBzebNG5r5jJV93+bp345VkLobPBxZMfJc/thbp1q+xy1Iw4QS51V52P2m0+
         PBKinXUNnpzw1a1ZZ1hIkv+FOwdxchb57xdo/BgO7TY9DLRlBAScE5XfVGmmzzW+vUpY
         IixE2PpsOjBGqvrqqv9kcBOKIZmCH77HIBqdmAK8MZ6N67TMAXHPcfMbSynelgvf7pIS
         pgYw==
X-Forwarded-Encrypted: i=2; AJvYcCUvgU7uPKmlIagUCizSoLWiKuQ0zHnMvcwjbazJtupqCHdUhlbqOrtSNxSJizmnQNLQD2FCLQ==@lfdr.de
X-Gm-Message-State: AOJu0YysDI+hrIMFT/zIyQlkfl21sMeb+8S0k/5khCcBN0QgDR6lhNId
	yZtQLROtSf16VQ01cTZPrwgZXs3pD8zYpJfkjHWv8ntkZD2Vc2Ab
X-Google-Smtp-Source: AGHT+IH227UwAxjZu5Vacib9002XC33IRQt70MMXPLMdKLbfsTt8upYghGOpyBIeeSo50MtQBwVW3g==
X-Received: by 2002:a05:6820:1846:b0:5e1:ea03:928f with SMTP id 006d021491bc7-5eb8b7b39e6mr10078283eaf.7.1729562365182;
        Mon, 21 Oct 2024 18:59:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cb88:0:b0:5e5:c4eb:d560 with SMTP id 006d021491bc7-5eb6bbb7049ls2536530eaf.2.-pod-prod-04-us;
 Mon, 21 Oct 2024 18:59:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVy+DsFs7f5VW2hi4ERYzB/E1+NJvwyU3sDxu1/EZTwt1z1jFInlTw5OzdaaDzUnksbkjkxvxgltFc=@googlegroups.com
X-Received: by 2002:a05:6820:c91:b0:5e7:caf5:ae03 with SMTP id 006d021491bc7-5eb8b3a4babmr9668703eaf.2.1729562364305;
        Mon, 21 Oct 2024 18:59:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562364; cv=none;
        d=google.com; s=arc-20240605;
        b=JVnVxpGmv7VTajFl7pIsmvRMhstfhMhf8HSuiaep5XaG/sqGguVDpKWH9wWTG7SW+5
         EMVVjfNp/Lcu3/0/OZL8MCMYlBkkipq2uB2kiimQ2i7uktGleb1uC+NqOsHgf8/6III6
         F2s2bLbr3ts55ngfw3zRPslzcFKeKieqNW+onwFJfEzcx7Qs9cHS6gfx32D5ACeAC8RF
         3blPeIN8msaiXv+PCl+VUidcDV3edDwA/dTTqyaSf+g7dBNrI2Ifz5bVti0wGi5tuwHG
         ISAEEXuho+ZxWkh3rJYcmKddilr3Cg8Dn641m2qSlB2Xc1nn0E9jzpvMjd09peRlXPe6
         fCEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y/iY9Y4RpcnWjc25xyItwxMbRygrVUaVLlWUhwxh2UQ=;
        fh=08qoo0sTk7H66Krs7BThkHnE0E5/Fr4xAG0LyFh6vcE=;
        b=VuGCpYOqzFz6UvHKDQymd61DWBafLDp8h3hfJj+8+WhX6fUZENXMAyl8wLB8JjHtS2
         PgbWRu6qFdMZuEk69zr1nZZJTXGwGoinj6WXy1DlAsG0ZMWphchklPenupTTDtarGNpA
         qO/V5vO3nvtipfUHEszSWuUaghQr+JcOQ7k3rEXUitMaqRJnFH9BeCfJdRUYP0eFrIur
         424eaGn6CsHKc2ItuY2tfeloLq2J0gD1pL/v5odirRbxiC5YBg28pxq7EktQzcVfV2Tu
         Ex9Z+cWLcAe3IKgtqBkmki73YjcyCpVVNjaUkk9gBWXAG7GOSZwnWR+r5uC5UeDfH3qk
         F5BA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=UNzi9Yoq;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5ebb7a176e6si171766eaf.1.2024.10.21.18.59.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-71e4244fdc6so3571322b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWph32miuB/uzE0czIKhQjvzZkjhU2rgzpDQlkHjrsL4rz6nfuDdu9nDsXSgGxbvvbJhPzr+2tgrtc=@googlegroups.com
X-Received: by 2002:a05:6a00:9298:b0:71e:5de:ad6d with SMTP id d2e1a72fcca58-71ea323b91dmr19028480b3a.24.1729562363415;
        Mon, 21 Oct 2024 18:59:23 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:23 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 4/9] kasan: sw_tags: Support tag widths less than 8 bits
Date: Mon, 21 Oct 2024 18:57:12 -0700
Message-ID: <20241022015913.3524425-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=UNzi9Yoq;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
pointer tags. For consistency, move the arm64 MTE definition of
KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
RISC-V's equivalent extension is expected to support 7-bit hardware
memory tags.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v1)

 arch/arm64/include/asm/kasan.h   |  6 ++++--
 arch/arm64/include/asm/uaccess.h |  1 +
 include/linux/kasan-tags.h       | 13 ++++++++-----
 3 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index e1b57c13f8a4..4ab419df8b93 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,8 +6,10 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
-#include <asm/mte-kasan.h>
-#include <asm/pgtable-types.h>
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
+#endif
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 1aa4ecb73429..8f700a7dd2cd 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -22,6 +22,7 @@
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index 4f85f562512c..e07c896f95d3 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,13 +2,16 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
+#include <asm/kasan.h>
+
+#ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-#define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
-#define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
+#endif
+
+#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
+#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
-#else
+#ifndef KASAN_TAG_MIN
 #define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
 #endif
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-5-samuel.holland%40sifive.com.
