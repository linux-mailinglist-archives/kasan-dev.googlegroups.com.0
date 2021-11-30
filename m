Return-Path: <kasan-dev+bncBAABBV6BTKGQMGQEH7LRBGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B569464108
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:24 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id g38-20020a0565123ba600b004036147023bsf8593804lfv.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310104; cv=pass;
        d=google.com; s=arc-20160816;
        b=GUz/E3ZFgkuG+F30iFor9Fvm4D7n2Z0tmI9EiwFY7hAMlPZLztjK6hSpSL+7umSufQ
         uIXXCLStz4Sbio4cWfvIVlLOXKCxK2baFnFRKEOC6X72a9vdBQhb9aMrMRb41fdflJtf
         Ap000Uei/VXZdF4IDNZ6mZc8/BNCbGTQ9lm0qHjaYtaO8NKD6upT3cr//TmV+D2/5J7x
         C/+4PcEFDcYX7g26LqZq4NCL4dEiBvf+MBWLZU3uyivOhkLf986dhyQg0pkT336YJOla
         NKcizvayi+ZOQva4RBelOUBXQYT3YKZgZ8uArgPEo6DrusX1KGKd0zoxA6If8ZS0U8sU
         hg6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VD41E/jbgR87q1arW5IraxTNQtAgapf8CxaLOHdWrQA=;
        b=AK/X2uy5trc2OmpZlxijaigvaunaTkJwXtsiIXf9lSVC4LCNw2FH3mfPa2Hy1xCP98
         PIhbAcZ0JD88PkiUpAwUt7cVLt9CgEFvG8ktZE0sNoQXS2+mqTPg+4W5A5cVykQNkL58
         6EuypxjEWW1uIExHuATbdTA5cwGz4wjK8t+bVZg+n6pSUaz/SWN3YOFWGzPsnHVkFpwC
         r1x2bCrz0gFb32DxZaSPz3rU9a6EmO23See9crqEw9G4XCKGq2ZzG7L/Y4O1SQ5mslqv
         FVzNJtlQIECbv9heWKv9Wr7d4fZiFinElIQn55YsVMPVBOi/euAPv6wDfo9P0UtgcoQF
         Lwqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fjt3KF2A;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VD41E/jbgR87q1arW5IraxTNQtAgapf8CxaLOHdWrQA=;
        b=OIqht6hblCg61HaIjdP+A7kl14l/kQIVF5DwAF2VcVEr8/XeI5UVCXCgjpTd1QqziB
         bniR/ybSAKJesbQYQFpYj3ISOAk6YK0haiUSjHpdfOU0ukBAsh0RvFS8PjiJXRF05trm
         za6mQAmG3qcaIMM3jQgJLtEtB6q3aeVb/f/AiVQUdzoBIQM5Nkuqie+V/mV9itI6NkFX
         C5Z6f5ipPOeXdNXFUzI9ztVyeMf2IRLPqELofjZNeUy/2Z0AVi+ZASf/27jFnILnFOYO
         mdLlCh5NVA5YGniI5/XNkHKE0qp1dzPClqUJS6F9Q8r/diqnFTGjxVgAaTjnM+d6uf2P
         Waug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VD41E/jbgR87q1arW5IraxTNQtAgapf8CxaLOHdWrQA=;
        b=fR5m3DxCt9xlRbzdgPSGdXwuzWOmZx3PdVGotc/WoZy4afwM3pUTHQbKIVGNGElpM0
         246dMltc5A003a4JRLeQUAZnND61sa6uF3bIXALcXgHIzNWjRt0UNVb2h/9M5v8hYhOz
         /Kr80sKUMzMpdAW3L0BOds/zAU5/+MJyucAgEovQ4YG7V2itq/BYfHTRYixjuTFqNct/
         XNjXRO0Nt3xDIhNy5au6/bANbGTRuf/9dgJUfLD+NurR4+5n2+sj0vIlh/IgdXY07+ay
         lP5OpeBsZsiitu1Gtz+jM5eIOJu4iUG4WCnLTd8rkwc+5Mwxiw4b16Nu29h8Xw8cYTBp
         rwbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AHgiX6xBVXwcwJ8yUfgR+i5eLWoHD51qMFBwiemoqtFxe72w0
	kbkaBHODjikFMU4c4NscDpw=
X-Google-Smtp-Source: ABdhPJw2DHSQmtQjn1rUqe77dYxpyAWJ/RjuS+PpevFTijO9qLKgeqmYpp0QK91pW8EpH1L+KkyChQ==
X-Received: by 2002:a2e:b053:: with SMTP id d19mr1520330ljl.231.1638310103858;
        Tue, 30 Nov 2021 14:08:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8946:: with SMTP id b6ls13059ljk.7.gmail; Tue, 30 Nov
 2021 14:08:23 -0800 (PST)
X-Received: by 2002:a2e:8ec7:: with SMTP id e7mr1605415ljl.430.1638310102926;
        Tue, 30 Nov 2021 14:08:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310102; cv=none;
        d=google.com; s=arc-20160816;
        b=CcSrGfh+NTYULCWbuUDle0cHuPdL9KBHti9tA8xS0L0/nWBBMcOGLfPJdOKXjOmdI1
         8bXj8JWk7oEjnTVerItgYl50WiD77XX1Zk6JUWMItURzdM8Z9MgmFGLPllBt52qfMN+I
         ySA59vg9VvizU/iygcyYWesV2ugHGyGwsQNhJSQ42m9j22ZFoTV/jxWoFjckWU7qRiHs
         eUzXZ7UK/idebo+QLYcL7jH14JyeTp9WKNCfsTPpBtYmgYrcBIggQ/yiM4HvPeVyxWxX
         VMegqZvNH9+qcDOqnorZbzrPW+3Oj4BXnCiSqy2Zh0YMe+dSCWdSoppbSSg6vYLcAvpr
         U9iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xAlgAJIkgdSw/H62J4ONvMmg8WxewXYkqfQfZPdbW8s=;
        b=buLzAvN/Pz3Mp6q9Vp9R7h0QsQpiwhWO+GAoopjlR/HCTpbVR/dgcD4l4nsv5CZzJZ
         Sukkrgckm6UQxuzOlog2/1SuhZ92Mp937wjgPPl3M6XLv6DBUaIjejoPwCVUj6J8qqiY
         nU3LtdFB/WZrvyGdOKuIdmhlhqu3txjpXcH9SX+YjzGXC9c6Z6qYrEYWEKSzAdL6BaD6
         NJTz40X/Uk7GRyjjYoAfk0Yrs9L1eeMHbGq1i8nlvbDWzo9uek8rI8U+Rhv5o+VD0d8f
         uJrXE5cBAa8YfXQFhso2DPsMT3drBUh6tSSO9iqQcp6LxBhZq2Hl8akEGr3lpZNyAvcL
         gRug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fjt3KF2A;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id x65si1334147lff.10.2021.11.30.14.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 29/31] kasan, arm64: allow KASAN_VMALLOC with HW_TAGS
Date: Tue, 30 Nov 2021 23:08:20 +0100
Message-Id: <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Fjt3KF2A;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

vmalloc tagging support for HW_TAGS KASAN is now complete.

Allow enabling CONFIG_KASAN_VMALLOC.

Also adjust CONFIG_KASAN_VMALLOC description:

- Mention HW_TAGS support.
- Remove unneeded internal details: they have no place in Kconfig
  description and are already explained in the documentation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/Kconfig |  3 +--
 lib/Kconfig.kasan  | 20 ++++++++++----------
 2 files changed, 11 insertions(+), 12 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index c05d7a06276f..5981e5460c51 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -205,8 +205,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
-	select KASAN_VMALLOC if KASAN_GENERIC
-	select KASAN_VMALLOC if KASAN_SW_TAGS
+	select KASAN_VMALLOC
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 3f144a87f8a3..7834c35a7964 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -178,17 +178,17 @@ config KASAN_TAGS_IDENTIFY
 	  memory consumption.
 
 config KASAN_VMALLOC
-	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on (KASAN_GENERIC || KASAN_SW_TAGS) && HAVE_ARCH_KASAN_VMALLOC
+	bool "Check accesses to vmalloc allocations"
+	depends on HAVE_ARCH_KASAN_VMALLOC
 	help
-	  By default, the shadow region for vmalloc space is the read-only
-	  zero page. This means that KASAN cannot detect errors involving
-	  vmalloc space.
-
-	  Enabling this option will hook in to vmap/vmalloc and back those
-	  mappings with real shadow memory allocated on demand. This allows
-	  for KASAN to detect more sorts of errors (and to support vmapped
-	  stacks), but at the cost of higher memory usage.
+	  This mode makes KASAN check accesses to vmalloc allocations for
+	  validity.
+
+	  With software KASAN modes, checking is done for all types of vmalloc
+	  allocations. Enabling this option leads to higher memory usage.
+
+	  With hardware tag-based KASAN, only VM_ALLOC mappings are checked.
+	  There is no additional memory usage.
 
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl%40google.com.
