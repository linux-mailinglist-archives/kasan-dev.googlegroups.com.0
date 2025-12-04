Return-Path: <kasan-dev+bncBDP53XW3ZQCBB5FNY3EQMGQEB34FGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B46CACA3F48
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:09 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4776b0ada3dsf10999215e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857589; cv=pass;
        d=google.com; s=arc-20240605;
        b=VLUXPSu1Q6ZRaJs7AViQs1+qsa2JyWGiHfOe78E2UphdWZpx1ILbMrbuptJVHerXhp
         ztcQ2nFmb3VLDOdXLbde1G9HmA1mnXAT0sSf34rLt0IZxPXX6v7z37fCJBEjqcdY+nqV
         JPnVzNrt7cmg5zk0AL2FZiyIQ41legBLeSjHvwQfFB/n/sNE0dB76sp96scD9CyHfMx4
         pYt2ybo32LRpoLEh1LKPCq5a92/LtaWEbntzPHr68sEfO/leJ+eOF5KW33nKSgc8oMP4
         np7GZf4RUevggExLsUIJWK8s+zV4lr4AxJnYJAxnwltL6/ZNdgtmkpRdq3wK9VVHZDP+
         S6Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Sn/YWQbrUZpsh5TyRZnP6oPsD8C1fbfhK77gxiGIy+o=;
        fh=0HvyAEmJkn7+eAq9MaJknZ9KTP2SO33AovIZSL4F/N8=;
        b=XoatpEnmjR8punkabmkNZ0ySqm+x3DomxoNqBn+8CQrxUerJ9EBp8YUfBgGQlBq95i
         XxbiKOdtYt5EGAoJ3Zho/FxbQPhzUWDrvmwlqCeHcVobGhnFQAwoTPw5Ih02NkNPV691
         teblQpxmE3WdEICRDl++zXIk2aIKw1jMuZ8uMUSoewv6caZYSFk80J107kTGCpiOc5Eq
         OjTx499B+rk3FEGBBKlqnoatATb4eJdS3Lz07eiIog2BfobRzAc6TGHPMg+kzavVc6bN
         Xx+QoJpvSnF7IRR4djmuR0TzA6jBB4/BopbH62daIzVxPiPqhWCdVlSFe6zXjyyhbZKB
         h65A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gKkaigvs;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857589; x=1765462389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Sn/YWQbrUZpsh5TyRZnP6oPsD8C1fbfhK77gxiGIy+o=;
        b=bPhi7oCstqUsJWAGovEE7CHAfO2WxzlOOA+MauIbqpjy85eQHxzDjYI88vAtOJvTXe
         PfLotXP9Go4K1tsL8x/9n7sJJAYquC5KjDozWeWZOQE+pJqXmUTgKP9sataWJwtz68l8
         5yhCnD1UXmBEon2p6wEKkdcCTywLlTBD0e+/NvanqKbNRsgpJoyc1hWdfnUkyiRkibk1
         yhMv3/P62r04tsSbyXCuow4tJxsbq1LLEARAEmZS6VDBB1t8/3G7VGOMuslZvYqmEZ0R
         cCHvEXOKpZ1SNHw8XrBTYj1A0Ki61mIGG+vevSftuq14ACHx4FBHSwSlh6lVqDFJxifs
         JW6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857589; x=1765462389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Sn/YWQbrUZpsh5TyRZnP6oPsD8C1fbfhK77gxiGIy+o=;
        b=damqn1JsnijHtBie85PqGn1lWyr47YWf2UA4ecohg9efn9/QzhIplJENwcdjljDbDF
         P/4hO/cm3zKOC+cJcSs+2mmgrzRncIe31SniALbemAE2dvu6JP2Eg4GJEgya4kpSV6Ac
         MCR2cBvNo/EdR/NcfC+ZygdgYxOgLjayiUAsl/MYg5PE8jjlRvwh+P3RPhdLqUMbsj8t
         ncQLXBIZPaJ9PuYrhwdUWlnM0PXsMrSKroIHjq2pcqb911D8jZFok3+rW6EFlNe8B02w
         FCqf03MFc3AaS3P8L4fPl/OTaYuz1bVdju4TENdBp7GOM3e7mrfp9M6VN4/GtezDz9rD
         fFZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857589; x=1765462389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Sn/YWQbrUZpsh5TyRZnP6oPsD8C1fbfhK77gxiGIy+o=;
        b=wD1BCfg04QLwwuBvEXuJykNmUq7L8G+maUvERrudUkuGw8/kyImTSEcGYmG1FhinKO
         +gmVXV4Qs/3SGpSqxyVjiDfLEj9ibBzNFR21izKoxVMVPRKsMcEJKT2Im2yY5VJjUb/W
         IhEF3BF7YUN8r0zwFm5psTa6Fq8lX0CEVtMN1AC1lexfhzpJAhLEac3Wpw6YPRAjcuJu
         guN9oeYfNDAceDmfMpArpj9bnVmO4231lMmr8q1knxLukqafGqL9Hj87D7Er9/sM0BaS
         VAMz+nAkIk0diMHJnhJg+N1h6UCLryvEuib6J/sOioWgtQeoDlmcx+b38NAoVY6T803z
         5yug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUouLWqzQ6foRYXdM4SPnP4DtFF6g4AwVWr5dmKKh/0keIhRp7sNhBh5BZ1l/rPECTyKfHQZw==@lfdr.de
X-Gm-Message-State: AOJu0YyI7LXzQhuzHcmGCaxoTDiyUtwkwlIyvFNoQo3P+ShOc72yvmpH
	gULVK/fSxEh/G9Idjw90YaHFXd5qpVLGxsWpQ8BPOxeRYN8zkAlGTDGC
X-Google-Smtp-Source: AGHT+IGWej6PxRPv0XHqjC+ruA447L1zrvr1Kfcz8AiHDHkbTcw3t0bPy31hKVR81QRocBz0Kf/JeQ==
X-Received: by 2002:a05:600c:c093:b0:477:14ba:28da with SMTP id 5b1f17b1804b1-4792eb1675amr36912215e9.5.1764857588957;
        Thu, 04 Dec 2025 06:13:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bvYfgG+29TFKMgoBv8eJY1+ovlPKra7bP0DV5LxZk06A=="
Received: by 2002:a05:600c:c0dc:b0:477:2205:db97 with SMTP id
 5b1f17b1804b1-4792a73debfls6664385e9.0.-pod-prod-00-eu-canary; Thu, 04 Dec
 2025 06:13:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVppd2q7F0eJClntVT+0prDVlnAyWn7gl9sX5GoWNZUwVrzGlMAFClrfv1gBpq1acHJgEdrCzkC1ec=@googlegroups.com
X-Received: by 2002:a05:600c:470a:b0:45d:5c71:769d with SMTP id 5b1f17b1804b1-4792eb2452fmr31952535e9.8.1764857586061;
        Thu, 04 Dec 2025 06:13:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857586; cv=none;
        d=google.com; s=arc-20240605;
        b=MIVhyx1dCJ1kq8Sq8Z50Fe0Ab88+SWU+Bf8yNV9V5+SA0bnnzcdOK9gGj4itNEQtiv
         vdr/bhf0iE7TDAx2lARG/QER72QDxTx1KGXGZTEmvaVTAM2ZZc35b4GVVPcuhE2qLH3Z
         sPw3yHnCvAdqt859deZ6o3/xQVMWpInmmasDT+n9svSgKyMFNmqXUS+UNZ1vzR9FyPod
         LFaJSpXXayW67GYpjEgqpxYxi7a8zdtCGKODl5Ke7tmcon19GraIzBqc4Bds5J+nlERl
         qKPmjuAkj7vd4otyMcm8uW7IGSo9bt4hWgMUHyxtjrTTCaVyE4SFjO2im8T3e3lnRy3g
         yr+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eB/egNHg9loIhoHi7MhcNEE3/MaK1lWrTWkAXOToMjQ=;
        fh=4SVeRYtzMpPZ7tgcO7iFgxkwJPsZ1ZCiFxEawLhkwtg=;
        b=A1fphEK6uyLmPWknnufpBxSd9BOpkQy0WiCOQLQiUVgysibY7Lm0sd1Hs0vdv2fD2x
         3WNuSZJl4EipfdZ+qbV5QeMoO+ynTTVEI+CLXvwDeYPUMvqByHIGCgMUmn1F73znW0+q
         w4+QCxFfL9hBpWtSxrGFMAHvoaTUf5QvLD2MD7N2iDBKo6WbRtrXBppXFTVsMr6dsvW5
         y1y1H/krlSot01C50FLV87OaG7QZywzuTVCwb74qcP9d6JF9lRwA5nIXPogiUOwLiHD4
         SBygJcYvMv7fuCzXNN8rXryf6GY1yjdCcY5LnatHOn5KqrR15Wmrw7rqHfwwVtdF1j2u
         mY+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gKkaigvs;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d325b82si22434f8f.11.2025.12.04.06.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:06 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-42b32ff5d10so1398655f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUUAl1DlHI8V8b+oV26aJ/pWdEKSphV2Tqbs4Z9uKyPjm+xLSSLFfr4psfOSQWS8oi8KkhLuEQERZo=@googlegroups.com
X-Gm-Gg: ASbGncuoAMHzhXyV2DXHEPgYCHLczeYWJcMJqwmCm59EfBojGKX05MCur7Odt1AZXiH
	j6EqS5V0G8OTUdcACoCNwY/wfCNAomI9F9aMzPgxSXUzVzhJW/2XOuW+UJmRkuHZevd6B87KTAP
	IW2BsHqv/epwXt0GXeEBpWihqmbfW0l6GL00loXIQdkOBs0SbU8YczNv0T9zM5v1s3UMM3lDTVZ
	9WLXo2duN+CMParHFVyoLnmTbEP+B+zOw8zGMMhRttCswoX5UR/HIKlX7On0yXNNF7U2U5HIvCN
	VkI412yFEFDfSZ5XJ7C1ylduAPuw6kW8fQ8CvKo8kBocasKrxYkgNGrWHla09X2bvyVHWxb2T0l
	G4jfpY547EX7+iKwNk7XIus+n4QFyr+De6EfZwTpkw2aud8DH1YNoPTbyrMoPU+L6o2crFFakAM
	O3huwF8/5bSn6WMJTeuf7LFcn8EXhjLR2lkKzLUlo458yLgPjj9rpqEd9HcAe8zC/TTQ==
X-Received: by 2002:a5d:4942:0:b0:42b:2a41:f20 with SMTP id ffacd0b85a97d-42f7886d085mr2957881f8f.18.1764857585163;
        Thu, 04 Dec 2025 06:13:05 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:04 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com,
	Ethan Graham <ethangraham@google.com>
Subject: [PATCH 02/10] kfuzztest: add user-facing API and data structures
Date: Thu,  4 Dec 2025 15:12:41 +0100
Message-ID: <20251204141250.21114-3-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gKkaigvs;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Add the foundational user-facing components for the KFuzzTest framework.
This includes the main API header <linux/kfuzztest.h>, the Kconfig
option to enable the feature, and the required linker script changes
which introduce three new ELF sections in vmlinux.

Note that KFuzzTest is intended strictly for debug builds only, and
should never be enabled in a production build. The fact that it exposes
internal kernel functions and state directly to userspace may constitute
a serious security vulnerability if used for any reason other than
testing.

The header defines:
- The FUZZ_TEST() macro for creating test targets.
- The data structures required for the binary serialization format,
  which allows passing complex inputs from userspace.
- The metadata structures for test targets, constraints and annotations,
  which are placed in dedicated ELF sections (.kfuzztest_*) for
  discovery.

This patch only adds the public interface and build integration; no
runtime logic is included.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---
PR v3:
- Reorder definitions in kfuzztest.h for better flow and readability.
- Introduce __KFUZZTEST_CONSTRAINT macro in preparation for the
  introduction of the FUZZ_TEST_SIMPLE macro in the following patch,
  which uses it for manually emitting constraint metadata.
PR v1:
- Move KFuzzTest metadata definitions to generic vmlinux linkage so that
  the framework isn't bound to x86_64.
- Return -EFAULT when simple_write_to_buffer returns a value not equal
  to the input length in the main FUZZ_TEST macro.
- Enforce a maximum input size of 64KiB in the main FUZZ_TEST macro,
  returning -EINVAL when it isn't respected.
- Refactor KFUZZTEST_ANNOTATION_* macros.
- Taint the kernel with TAINT_TEST inside the FUZZ_TEST macro when a
  fuzz target is invoked for the first time.
---
---
 include/asm-generic/vmlinux.lds.h |  22 +-
 include/linux/kfuzztest.h         | 486 ++++++++++++++++++++++++++++++
 lib/Kconfig.debug                 |   1 +
 lib/kfuzztest/Kconfig             |  20 ++
 4 files changed, 528 insertions(+), 1 deletion(-)
 create mode 100644 include/linux/kfuzztest.h
 create mode 100644 lib/kfuzztest/Kconfig

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index ae2d2359b79e..9afe569d013b 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -373,7 +373,8 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 	TRACE_PRINTKS()							\
 	BPF_RAW_TP()							\
 	TRACEPOINT_STR()						\
-	KUNIT_TABLE()
+	KUNIT_TABLE()							\
+	KFUZZTEST_TABLE()
 
 /*
  * Data section helpers
@@ -966,6 +967,25 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 		BOUNDED_SECTION_POST_LABEL(.kunit_init_test_suites, \
 				__kunit_init_suites, _start, _end)
 
+#ifdef CONFIG_KFUZZTEST
+#define KFUZZTEST_TABLE()						\
+	. = ALIGN(PAGE_SIZE);						\
+	__kfuzztest_targets_start = .;					\
+	KEEP(*(.kfuzztest_target));					\
+	__kfuzztest_targets_end = .;					\
+	. = ALIGN(PAGE_SIZE);						\
+	__kfuzztest_constraints_start = .;				\
+	KEEP(*(.kfuzztest_constraint));					\
+	__kfuzztest_constraints_end = .;				\
+	. = ALIGN(PAGE_SIZE);						\
+	__kfuzztest_annotations_start = .;				\
+	KEEP(*(.kfuzztest_annotation));					\
+	__kfuzztest_annotations_end = .;
+
+#else /* CONFIG_KFUZZTEST */
+#define KFUZZTEST_TABLE()
+#endif /* CONFIG_KFUZZTEST */
+
 #ifdef CONFIG_BLK_DEV_INITRD
 #define INIT_RAM_FS							\
 	. = ALIGN(4);							\
diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
new file mode 100644
index 000000000000..1839fcfeabf5
--- /dev/null
+++ b/include/linux/kfuzztest.h
@@ -0,0 +1,486 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * The Kernel Fuzz Testing Framework (KFuzzTest) API for defining fuzz targets
+ * for internal kernel functions.
+ *
+ * For more information please see Documentation/dev-tools/kfuzztest.rst.
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_H
+#define KFUZZTEST_H
+
+#include <linux/fs.h>
+#include <linux/printk.h>
+#include <linux/types.h>
+
+#define KFUZZTEST_HEADER_MAGIC (0xBFACE)
+#define KFUZZTEST_V0 (0)
+#define KFUZZTEST_REGIONID_NULL U32_MAX
+#define KFUZZTEST_MAX_INPUT_SIZE (PAGE_SIZE * 16)
+/**
+ * The end of the input should be padded by at least this number of bytes as
+ * it is poisoned to detect out of bounds accesses at the end of the last
+ * region.
+ */
+#define KFUZZTEST_POISON_SIZE 0x8
+
+/**
+ * @brief The KFuzzTest Input Serialization Format
+ *
+ * KFuzzTest receives its input from userspace as a single binary blob. This
+ * format allows for the serialization of complex, pointer-rich C structures
+ * into a flat buffer that can be safely passed into the kernel. This format
+ * requires only a single copy from userspace into a kernel buffer, and no
+ * further kernel allocations. Pointers are patched internally using a "region"
+ * system where each region corresponds to some pointed-to data.
+ *
+ * Regions should be padded to respect alignment constraints of their underlying
+ * types, and should be followed by at least 8 bytes of padding. These padded
+ * regions are poisoned by KFuzzTest to ensure that KASAN catches OOB accesses.
+ *
+ * The format consists of a header and three main components:
+ * 1. An 8-byte header: Contains KFUZZTEST_MAGIC in the first 4 bytes, and the
+ *	version number in the subsequent 4 bytes. This ensures backwards
+ *	compatibility in the event of future format changes.
+ * 2. A reloc_region_array: Defines the memory layout of the target structure
+ *	by partitioning the payload into logical regions. Each logical region
+ *	should contain the byte representation of the type that it represents,
+ *	including any necessary padding. The region descriptors should be
+ *	ordered by offset ascending.
+ * 3. A reloc_table: Provides "linking" instructions that tell the kernel how
+ *	to patch pointer fields to point to the correct regions. By design,
+ *	the first region (index 0) is passed as input into a FUZZ_TEST.
+ * 4. A Payload: The raw binary data for the target structure and its associated
+ *	buffers. This should be aligned to the maximum alignment of all
+ *	regions to satisfy alignment requirements of the input types, but this
+ *	isn't checked by the parser.
+ *
+ * For a detailed specification of the binary layout see the full documentation
+ * at: Documentation/dev-tools/kfuzztest.rst
+ */
+
+/**
+ * struct reloc_region - single contiguous memory region in the payload
+ *
+ * @offset: The byte offset of this region from the start of the payload, which
+ *	should be aligned to the alignment requirements of the region's
+ *	underlying type.
+ * @size: The size of this region in bytes.
+ */
+struct reloc_region {
+	uint32_t offset;
+	uint32_t size;
+};
+
+/**
+ * struct reloc_region_array - array of regions in an input
+ *
+ * @num_regions: The total number of regions defined.
+ * @regions: A flexible array of `num_regions` region descriptors.
+ */
+struct reloc_region_array {
+	uint32_t num_regions;
+	struct reloc_region regions[];
+};
+
+/**
+ * struct reloc_entry - a single pointer to be patched in an input
+ *
+ * @region_id: The index of the region in the `reloc_region_array` that
+ *	contains the pointer.
+ * @region_offset: The start offset of the pointer inside of the region.
+ * @value: contains the index of the pointee region, or KFUZZTEST_REGIONID_NULL
+ *	if the pointer is NULL.
+ */
+struct reloc_entry {
+	uint32_t region_id;
+	uint32_t region_offset;
+	uint32_t value;
+};
+
+/**
+ * struct reloc_table - array of relocations required by an input
+ *
+ * @num_entries: the number of pointer relocations.
+ * @padding_size: the number of padded bytes between the last relocation in
+ *	entries, and the start of the payload data. This should be at least
+ *	8 bytes, as it is used for poisoning.
+ * @entries: array of relocations.
+ */
+struct reloc_table {
+	uint32_t num_entries;
+	uint32_t padding_size;
+	struct reloc_entry entries[];
+};
+
+/**
+ * kfuzztest_parse_and_relocate - validate and relocate a KFuzzTest input
+ *
+ * @input:      A buffer containing the serialized input for a fuzz target.
+ * @input_size: the size in bytes of the @input buffer.
+ * @arg_ret:    return pointer for the test case's input structure.
+ */
+int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret);
+
+enum kfuzztest_constraint_type {
+	EXPECT_EQ,
+	EXPECT_NE,
+	EXPECT_LT,
+	EXPECT_LE,
+	EXPECT_GT,
+	EXPECT_GE,
+	EXPECT_IN_RANGE,
+};
+
+/**
+ * struct kfuzztest_constraint - a metadata record for a domain constraint
+ *
+ * Domain constraints are rules about the input data that must be satisfied for
+ * a fuzz test to proceed. While they are enforced in the kernel with a runtime
+ * check, they are primarily intended as a discoverable contract for userspace
+ * fuzzers.
+ *
+ * Instances of this struct are generated by the KFUZZTEST_EXPECT_* macros
+ * and placed into the read-only ".kfuzztest_constraint" ELF section of the
+ * vmlinux binary. A fuzzer can parse this section to learn about the
+ * constraints and generate valid inputs more intelligently.
+ *
+ * For an example of how these constraints are used within a fuzz test, see the
+ * documentation for the FUZZ_TEST() macro.
+ *
+ * @input_type: The name of the input struct type, without the leading
+ *	"struct ".
+ * @field_name: The name of the field within the struct that this constraint
+ *	applies to.
+ * @value1: The primary value used in the comparison (e.g., the upper
+ *	bound for EXPECT_LE).
+ * @value2: The secondary value, used only for multi-value comparisons
+ *	(e.g., the upper bound for EXPECT_IN_RANGE).
+ * @type: The type of the constraint.
+ */
+struct kfuzztest_constraint {
+	const char *input_type;
+	const char *field_name;
+	uintptr_t value1;
+	uintptr_t value2;
+	enum kfuzztest_constraint_type type;
+} __aligned(64);
+
+
+#define __KFUZZTEST_CONSTRAINT(arg_type, field, val1, val2, tpe)				\
+	static struct kfuzztest_constraint __constraint_##arg_type##_##field				\
+		__section(".kfuzztest_constraint") __used = {						\
+			.input_type = "struct " #arg_type,						\
+			.field_name = #field,								\
+			.value1 = (uintptr_t)val1,							\
+			.value2 = (uintptr_t)val2,							\
+			.type = tpe,									\
+		}
+
+#define __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val1, val2, tpe, predicate)				\
+	do {													\
+		__KFUZZTEST_CONSTRAINT(arg_type, field, val1, val2, tpe);				\
+		if (!(predicate))										\
+			return;											\
+	} while (0)
+
+/**
+ * KFUZZTEST_EXPECT_EQ - constrain a field to be equal to a value
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable
+ * @val: a value of the same type as @arg_type.@field
+ */
+#define KFUZZTEST_EXPECT_EQ(arg_type, field, val)	\
+	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_EQ, arg->field == val)
+
+/**
+ * KFUZZTEST_EXPECT_NE - constrain a field to be not equal to a value
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable.
+ * @val: a value of the same type as @arg_type.@field.
+ */
+#define KFUZZTEST_EXPECT_NE(arg_type, field, val)	\
+	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_NE, arg->field != val)
+
+/**
+ * KFUZZTEST_EXPECT_LT - constrain a field to be less than a value
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable.
+ * @val: a value of the same type as @arg_type.@field.
+ */
+#define KFUZZTEST_EXPECT_LT(arg_type, field, val)	\
+	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LT, arg->field < val)
+
+/**
+ * KFUZZTEST_EXPECT_LE - constrain a field to be less than or equal to a value
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable.
+ * @val: a value of the same type as @arg_type.@field.
+ */
+#define KFUZZTEST_EXPECT_LE(arg_type, field, val)	\
+		__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LE, arg->field <= val)
+
+/**
+ * KFUZZTEST_EXPECT_GT - constrain a field to be greater than a value
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable.
+ * @val: a value of the same type as @arg_type.@field.
+ */
+#define KFUZZTEST_EXPECT_GT(arg_type, field, val)	\
+	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GT, arg->field > val)
+
+/**
+ * KFUZZTEST_EXPECT_GE - constrain a field to be greater than or equal to a value
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable.
+ * @val: a value of the same type as @arg_type.@field.
+ */
+#define KFUZZTEST_EXPECT_GE(arg_type, field, val)	\
+	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GE, arg->field >= val)
+
+/**
+ * KFUZZTEST_EXPECT_NOT_NULL - constrain a pointer field to be non-NULL
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: a pointer field.
+ */
+#define KFUZZTEST_EXPECT_NOT_NULL(arg_type, field) KFUZZTEST_EXPECT_NE(arg_type, field, NULL)
+
+/**
+ * KFUZZTEST_EXPECT_IN_RANGE - constrain a field to be within a range
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: some field that is comparable.
+ * @lower_bound: a lower bound of the same type as @arg_type.@field.
+ * @upper_bound: an upper bound of the same type as @arg_type.@field.
+ */
+#define KFUZZTEST_EXPECT_IN_RANGE(arg_type, field, lower_bound, upper_bound)		\
+	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, lower_bound, upper_bound,	\
+			EXPECT_IN_RANGE, arg->field >= lower_bound && arg->field <= upper_bound)
+
+/**
+ * Annotations express attributes about structure fields that can't be easily
+ * or safely verified at runtime. They are intended as hints to the fuzzing
+ * engine to help it generate more semantically correct and effective inputs.
+ * Unlike constraints, annotations do not add any runtime checks and do not
+ * cause a test to exit early.
+ *
+ * For example, a `char *` field could be a raw byte buffer or a C-style
+ * null-terminated string. A fuzzer that is aware of this distinction can avoid
+ * creating inputs that would cause trivial, uninteresting crashes from reading
+ * past the end of a non-null-terminated buffer.
+ */
+enum kfuzztest_annotation_attribute {
+	ATTRIBUTE_LEN,
+	ATTRIBUTE_STRING,
+	ATTRIBUTE_ARRAY,
+};
+
+/**
+ * struct kfuzztest_annotation - a metadata record for a fuzzer hint
+ *
+ * This struct captures a single hint about a field in the input structure.
+ * Instances are generated by the KFUZZTEST_ANNOTATE_* macros and are placed
+ * into the read-only ".kfuzztest_annotation" ELF section of the vmlinux binary.
+ *
+ * A userspace fuzzer can parse this section to understand the semantic
+ * relationships between fields (e.g., which field is a length for which
+ * buffer) and the expected format of the data (e.g., a null-terminated
+ * string). This allows the fuzzer to be much more intelligent during input
+ * generation and mutation.
+ *
+ * For an example of how annotations are used within a fuzz test, see the
+ * documentation for the FUZZ_TEST() macro.
+ *
+ * @input_type: The name of the input struct type.
+ * @field_name: The name of the field being annotated (e.g., the data
+ *	buffer field).
+ * @linked_field_name: For annotations that link two fields (like
+ *	ATTRIBUTE_LEN), this is the name of the related field (e.g., the
+ *	length field). For others, this may be unused.
+ * @attrib: The type of the annotation hint.
+ */
+struct kfuzztest_annotation {
+	const char *input_type;
+	const char *field_name;
+	const char *linked_field_name;
+	enum kfuzztest_annotation_attribute attrib;
+} __aligned(32);
+
+#define __KFUZZTEST_ANNOTATE(arg_type, field, linked_field, attribute)						\
+	static struct kfuzztest_annotation __annotation_##arg_type##_##field __section(".kfuzztest_annotation")	\
+		__used = {											\
+			.input_type = "struct " #arg_type,							\
+			.field_name = #field,									\
+			.linked_field_name = #linked_field,							\
+			.attrib = attribute,									\
+		}
+
+/**
+ * KFUZZTEST_ANNOTATE_STRING - annotate a char* field as a C string
+ *
+ * We define a C string as a sequence of non-zero characters followed by exactly
+ * one null terminator.
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: the name of the field to annotate.
+ */
+#define KFUZZTEST_ANNOTATE_STRING(arg_type, field) __KFUZZTEST_ANNOTATE(arg_type, field, NULL, ATTRIBUTE_STRING)
+
+/**
+ * KFUZZTEST_ANNOTATE_ARRAY - annotate a pointer as an array
+ *
+ * We define an array as a contiguous memory region containing zero or more
+ * elements of the same type.
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: the name of the field to annotate.
+ */
+#define KFUZZTEST_ANNOTATE_ARRAY(arg_type, field) __KFUZZTEST_ANNOTATE(arg_type, field, NULL, ATTRIBUTE_ARRAY)
+
+/**
+ * KFUZZTEST_ANNOTATE_LEN - annotate a field as the length of another
+ *
+ * This expresses the relationship `arg_type.field == len(linked_field)`, where
+ * `linked_field` is an array.
+ *
+ * @arg_type: name of the input structure, without the leading "struct ".
+ * @field: the name of the field to annotate.
+ * @linked_field: the name of an array field with length @field.
+ */
+#define KFUZZTEST_ANNOTATE_LEN(arg_type, field, linked_field) \
+	__KFUZZTEST_ANNOTATE(arg_type, field, linked_field, ATTRIBUTE_LEN)
+
+
+/*
+ * Dump some information on the parsed headers and payload. Can be useful for
+ * debugging inputs when writing an encoder for the KFuzzTest input format.
+ */
+__attribute__((unused)) static inline void kfuzztest_debug_header(struct reloc_region_array *regions,
+								  struct reloc_table *rt, void *payload_start,
+								  void *payload_end)
+{
+	uint32_t i;
+
+	pr_info("regions: { num_regions = %u } @ %px", regions->num_regions, regions);
+	for (i = 0; i < regions->num_regions; i++) {
+		pr_info("  region_%u: { start: 0x%x, size: 0x%x }", i, regions->regions[i].offset,
+			regions->regions[i].size);
+	}
+
+	pr_info("reloc_table: { num_entries = %u, padding = %u } @ offset 0x%tx", rt->num_entries, rt->padding_size,
+		(char *)rt - (char *)regions);
+	for (i = 0; i < rt->num_entries; i++) {
+		pr_info("  reloc_%u: { src: %u, offset: 0x%x, dst: %u }", i, rt->entries[i].region_id,
+			rt->entries[i].region_offset, rt->entries[i].value);
+	}
+
+	pr_info("payload: [0x%lx, 0x%tx)", (char *)payload_start - (char *)regions,
+		(char *)payload_end - (char *)regions);
+}
+
+/* Increments a global counter after a successful invocation. */
+void record_invocation(void);
+
+/* Common code for receiving inputs from userspace. */
+int kfuzztest_write_cb_common(struct file *filp, const char __user *buf, size_t len, loff_t *off, void **test_buffer);
+
+struct kfuzztest_target {
+	const char *name;
+	const char *arg_type_name;
+	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf, size_t len, loff_t *off);
+} __aligned(32);
+
+/**
+ * FUZZ_TEST - defines a KFuzzTest target
+ *
+ * @test_name: The unique identifier for the fuzz test, which is used to name
+ *	the debugfs entry, e.g., /sys/kernel/debug/kfuzztest/@test_name.
+ * @test_arg_type: The struct type that defines the inputs for the test. This
+ *	must be the full struct type (e.g., "struct my_inputs"), not a typedef.
+ *
+ * Context:
+ * This macro is the primary entry point for the KFuzzTest framework. It
+ * generates all the necessary boilerplate for a fuzz test, including:
+ *   - A static `struct kfuzztest_target` instance that is placed in a
+ *	dedicated ELF section for discovery by userspace tools.
+ *   - A `debugfs` write callback that handles receiving serialized data from
+ *	a fuzzer, parsing it, and "hydrating" it into a valid C struct.
+ *   - A function stub where the developer places the test logic.
+ *
+ * User-Provided Logic:
+ * The developer must provide the body of the fuzz test logic within the curly
+ * braces following the macro invocation. Within this scope, the framework
+ * provides the `arg` variable, which is a pointer of type `@test_arg_type *`
+ * to the fully hydrated input structure. All pointer fields within this struct
+ * have been relocated and are valid kernel pointers. This is the primary
+ * variable to use for accessing fuzzing inputs.
+ *
+ * Example Usage:
+ *
+ * // 1. The kernel function we want to fuzz.
+ * int process_data(const char *data, size_t len);
+ *
+ * // 2. Define a struct to hold all inputs for the function.
+ * struct process_data_inputs {
+ *	const char *data;
+ *	size_t len;
+ * };
+ *
+ * // 3. Define the fuzz test using the FUZZ_TEST macro.
+ * FUZZ_TEST(process_data_fuzzer, struct process_data_inputs)
+ * {
+ *	int ret;
+ *	// Use KFUZZTEST_EXPECT_* to enforce preconditions.
+ *	// The test will exit early if data is NULL.
+ *	KFUZZTEST_EXPECT_NOT_NULL(process_data_inputs, data);
+ *
+ *	// Use KFUZZTEST_ANNOTATE_* to provide hints to the fuzzer.
+ *	// This links the 'len' field to the 'data' buffer.
+ *	KFUZZTEST_ANNOTATE_LEN(process_data_inputs, len, data);
+ *
+ *	// Call the function under test using the 'arg' variable. OOB memory
+ *	// accesses will be caught by KASAN, but the user can also choose to
+ *	// validate the return value and log any failures.
+ *	ret = process_data(arg->data, arg->len);
+ * }
+ */
+#define FUZZ_TEST(test_name, test_arg_type)									\
+	static ssize_t kfuzztest_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len,	\
+						      loff_t *off);						\
+	static void kfuzztest_logic_##test_name(test_arg_type *arg);						\
+	static const struct kfuzztest_target __fuzz_test__##test_name __section(".kfuzztest_target") __used = {	\
+		.name = #test_name,										\
+		.arg_type_name = #test_arg_type,								\
+		.write_input_cb = kfuzztest_write_cb_##test_name,						\
+	};													\
+	static ssize_t kfuzztest_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len,	\
+						      loff_t *off)						\
+	{													\
+		test_arg_type *arg;										\
+		void *buffer;											\
+		int ret;											\
+		ret = kfuzztest_write_cb_common(filp, buf, len, off, &buffer);					\
+		if (ret < 0)											\
+			goto fail_early;									\
+		ret = kfuzztest_parse_and_relocate(buffer, len, (void **)&arg);					\
+		if (ret < 0)											\
+			goto fail_late;										\
+		kfuzztest_logic_##test_name(arg);								\
+		record_invocation();										\
+		ret = len;											\
+fail_late:													\
+		kfree(buffer);											\
+fail_early:													\
+		return ret;											\
+	}													\
+	static void kfuzztest_logic_##test_name(test_arg_type *arg)
+
+#endif /* KFUZZTEST_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index dc0e0c6ed075..49a1748b9f24 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1947,6 +1947,7 @@ endmenu
 menu "Kernel Testing and Coverage"
 
 source "lib/kunit/Kconfig"
+source "lib/kfuzztest/Kconfig"
 
 config NOTIFIER_ERROR_INJECTION
 	tristate "Notifier error injection"
diff --git a/lib/kfuzztest/Kconfig b/lib/kfuzztest/Kconfig
new file mode 100644
index 000000000000..f9fb5abf8d27
--- /dev/null
+++ b/lib/kfuzztest/Kconfig
@@ -0,0 +1,20 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+config KFUZZTEST
+	bool "KFuzzTest - enable support for internal fuzz targets"
+	depends on DEBUG_FS && DEBUG_KERNEL
+	help
+	  Enables support for the kernel fuzz testing framework (KFuzzTest), an
+	  interface for exposing internal kernel functions to a userspace fuzzing
+	  engine. KFuzzTest targets are exposed via a debugfs interface that
+	  accepts serialized userspace inputs, and is designed to make it easier
+	  to fuzz deeply nested kernel code that is hard to reach from the system
+	  call boundary. Using a simple macro-based API, developers can add a new
+	  fuzz target with minimal boilerplate code.
+
+	  It is strongly recommended to also enable CONFIG_KASAN for byte-accurate
+	  out-of-bounds detection, as KFuzzTest was designed with this in mind. It
+	  is also recommended to enable CONFIG_KCOV for coverage guided fuzzing.
+
+	  WARNING: This exposes internal kernel functions directly to userspace
+	  and must NEVER be enabled in production builds.
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-3-ethan.w.s.graham%40gmail.com.
