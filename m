Return-Path: <kasan-dev+bncBDI7FD5TRANRBTPGSO3AMGQEV5VQCAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 59DA1958EC9
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:49:35 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-7c6b192a39bsf4525315a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:49:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183373; cv=pass;
        d=google.com; s=arc-20240605;
        b=GarKksaEb1THNksnVnUT4rc7XcOV9F7CK4V5w0TWQsrfto0u1OuBOIFXXpMYfqINF4
         TP0m4Sbbk8DCiE/DJugbUlyi+pinOi7CO0vCg5Z+Qw4bUm7hRIAXvfzUzB3H5XEzIV3D
         qbdmHxXxVfzR0eDS38D8kvrH5gcRmk9n8FPMpGR0kNvpkMc5QzCHansxNrrhQDe+O/SA
         f853SxBD5cn1FvDvX7ZVyQMRN/qt0ROBevnG3bg9l6Jxn+i0lou/ISWH1X3+GkA7ma35
         Gwj3guSS7Ucj9whfE6uMsSp3aKn+vK27kj2G/TzlyWV+q+WhtSRpTEh0iCht5W6qaFRV
         /R7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=H8ZPX/NDmgAEndFLuClgLWG0QBf6GDrdQHvYorXwJRQ=;
        fh=vGwqn1XS3TNiTrrGuD+DhFncK5KrMPqCcr/f/60nMYY=;
        b=hHxjtN/FX90ExjNyOMOXrnRvNddktlrvtFk4KxxXpo01thJAXACSsZ8wJEuaAcd3/F
         0DOrTE658LS+dRH9DoqrCMR8zlpWeVXImxZiAhGYroZUvHCxem4NA0gjZh/Bmt54MvHV
         bj19hxJayRn+3cNXrFMl7h1z87a1yERJgxJGc4lkwxCIKSROCaYaUYGcsMoMM0QkYCNa
         lA2fAg/eWaMWoKscCRDh2Yiq2fVGB8+vXJ1sZ7pHkw6e6A9hzrNnmcVyytx8kLxh9vIr
         p0rS+bLBVy1XQq+BSiMMyA9HU2CWmmxOaCUZpWu4p3f8c9nsatmujVwcmDERUpv/7M3v
         k3Ow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dObMoR80;
       spf=pass (google.com: domain of 3s_pezgckcyissg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3S_PEZgcKCYIssg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183373; x=1724788173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=H8ZPX/NDmgAEndFLuClgLWG0QBf6GDrdQHvYorXwJRQ=;
        b=FtQhmCrm5a/80ir/LzJFcQIKA7KefU/XcB77ay+58vIvAQw+6wQE/BqtembI9HjLds
         Lcrnwv1QYZobBAPyaXKKratePifZtzDgN9SVJqYKs4YyjQwrEfaR7sZeOGmGxms0d189
         hSGWx9drduXFUx/8Y4k57LkbyiWjC+zIDD88qIY6UBmOQ6QD4qIxFNJ9VoeCe22eeAEX
         1b+AU/g+Uz48O7oVvvoNxCj/e95mZKVYbbJaPpoVq8lUi+X/Pal+9I2wJOlkAi6BOt+y
         NZU8CxtQzIGsEvtMZNcLxjbpSPHSVt6jrQKltH0fWY+Uio4kPdAlmJXPTyf1D9pDL5PX
         xBqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183373; x=1724788173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H8ZPX/NDmgAEndFLuClgLWG0QBf6GDrdQHvYorXwJRQ=;
        b=focrJoZFym2XbnJ50qAOLrH9rBB4JlDwsqhhHqmVAWlEeqC3nzzjUP9PTDGPGXXlPj
         sWCy5p1vI/ASLF37AzsrhbN7KBJM0ZaX7rLCfjMpqlOOFPJbchcWsQigy6JE7uM/UcTi
         eqxD8H7DNuUn+pDC/Yg7Nzw+1wlUt7tko3N40ftFoNOnYXOwxWg0sVfFkgYbh4T8XyXG
         TYoZ58iTDWF2t3l//qauF8ml+JF8dLbfVjxG+4v+SkL1HmkGfLFZRB2KRQE9TqybtUAJ
         uSX2wHveKaYTlfyOjqbm94pGYyQgRGoDwsAnTUQxxnmtmxPX42FA7FHYn8+2JdD3SqDu
         yD0Q==
X-Forwarded-Encrypted: i=2; AJvYcCX+jRXnfhD1XAoOQIDN+TP5tbrBW9+KL3q+GyS//augZpd77BtnGknrWMyD0u1qmXK1oG0dug==@lfdr.de
X-Gm-Message-State: AOJu0YwYNAimK3P2S0/LLo+YSHSLEEOvsakCPYbkP/1l8w1Mdu5yCG0b
	zyClnPSemZifNlMyRVsbv3zA/ijaNNiQeeerOHmYh5vFfkD2IGPS
X-Google-Smtp-Source: AGHT+IGO8wdUj/DAV8JH+G1X+MWrPapf4NfkDlGABFzvZU/Fb37LvsenA2gyNP30mfnJGseYKDrvRg==
X-Received: by 2002:a05:6a21:710a:b0:1bd:1df4:bd43 with SMTP id adf61e73a8af0-1cada1b71f8mr26221637.54.1724183373397;
        Tue, 20 Aug 2024 12:49:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6fa5:b0:2c9:6188:f3f with SMTP id
 98e67ed59e1d1-2d3c2f846bcls3298598a91.2.-pod-prod-02-us; Tue, 20 Aug 2024
 12:49:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNRrYdPwV+G5D7VbyR+P8f2dcvT2wC/DLEho5L3GVFy+mLKywIul067++gM1d4Qy0Q9GhZw3kf5Ko=@googlegroups.com
X-Received: by 2002:a17:90a:f60d:b0:2d3:c638:ec67 with SMTP id 98e67ed59e1d1-2d5e98c8067mr63459a91.0.1724183372208;
        Tue, 20 Aug 2024 12:49:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183372; cv=none;
        d=google.com; s=arc-20240605;
        b=LMsHj9fx0zErvUTEP5WPaP1YoJSdGLnTDV4gb0doCs/OD3vaXud9BheAAiMy5MzCeb
         vYnb53533DBZw8j5xFuV1m3cGPKskhq+l4ha5ieTP/DWDwNLFEuOJR39wCvwUBsqzqTd
         pEowZmeYqHxPjE/6tYjFXB9VfkOmsiLwb3gYruv5K3nEmdM/E/9htMRRFvZr0Ljt6LPn
         /Ufj1gu7l4LS4aZ0aJHtYH/qQZmC+BLqTNo7v99DJRw54WhXZnELg9A4SuxxarjMC8P8
         XmdlDkj1a0Jctn1/T/mlcupfp0oNkCGeKfYw3NVGbBMFqs8dAIZ5M1O8FjUpsEXXuCAw
         zf2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=IttCgeBRXfLGGSRTMWMVTYyC3qQ0hIHeZRv9TWbyvy4=;
        fh=+JFeIDedcnEtaS42ZNVJ8Dl2GWgqOBVvJU6t7rR3CnA=;
        b=SQlVu0uPymBKG7BIufObX1gx9Y5qe1ARASD/8S/xybOcQmRnV35ab8ZNT9tJH311Dp
         vbbFNP+QpMxI7gRq8tekmQv834BeNRPGfTsN4ONXXkrFotOhMVslJG90yDm+/Grs9UK2
         1imrV/fNTSSqV7c9529ek1pMeRlrPQJEVD4Uu+DxHqB1DSpYzkDyHvFv3b9x8KlazZmZ
         D4ZfpaCGbeq9AXY9cf6fcDq9Lwlv7U0RJl1/lXvROYYClpkWO+BJ0Gdg9o40tyDmbsMJ
         eFWYT1bdTNrH6hgL0S+hJTT2ClC/TSZhRmcqgc8pwYunuxrEWG+AFuvBGa1w4cuxPYcs
         AtKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dObMoR80;
       spf=pass (google.com: domain of 3s_pezgckcyissg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3S_PEZgcKCYIssg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d3c9fc2342si484272a91.0.2024.08.20.12.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:49:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3s_pezgckcyissg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-e11368fa2e3so9798720276.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:49:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUIDvkYf1NyRYb8VRns7Ee2Ut5RtP01BWQjvllBEVTs6hcc8n/Hnnilv61piHbWQaPKF/U3A+hdEfo=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a25:dc06:0:b0:e11:ade7:ba56 with SMTP id
 3f1490d57ef6-e16655a14famr5299276.7.1724183371261; Tue, 20 Aug 2024 12:49:31
 -0700 (PDT)
Date: Tue, 20 Aug 2024 19:48:59 +0000
In-Reply-To: <20240820194910.187826-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240820194910.187826-5-mmaurer@google.com>
Subject: [PATCH v4 4/4] kasan: rust: Add KASAN smoke test via UAF
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: andreyknvl@gmail.com, ojeda@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>
Cc: dvyukov@google.com, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	Matthew Maurer <mmaurer@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dObMoR80;       spf=pass
 (google.com: domain of 3s_pezgckcyissg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3S_PEZgcKCYIssg0xkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

Adds a smoke test to ensure that KASAN in Rust is actually detecting a
Rust-native UAF. There is significant room to expand this test suite,
but this will at least ensure that flags are having the intended effect.

The rename from kasan_test.c to kasan_test_c.c is in order to allow the
single kasan_test.ko test suite to contain both a .o file produced
by the C compiler and one produced by rustc.

Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 mm/kasan/Makefile                         |  7 ++++++-
 mm/kasan/kasan.h                          |  6 ++++++
 mm/kasan/{kasan_test.c => kasan_test_c.c} | 12 ++++++++++++
 mm/kasan/kasan_test_rust.rs               | 19 +++++++++++++++++++
 4 files changed, 43 insertions(+), 1 deletion(-)
 rename mm/kasan/{kasan_test.c => kasan_test_c.c} (99%)
 create mode 100644 mm/kasan/kasan_test_rust.rs

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 7634dd2a6128..13059d9ee13c 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -44,13 +44,18 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
 CFLAGS_KASAN_TEST += -fno-builtin
 endif
 
-CFLAGS_kasan_test.o := $(CFLAGS_KASAN_TEST)
+CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
+RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
 CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
 
 obj-y := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
 obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
+kasan_test-objs := kasan_test_c.o
+ifdef CONFIG_RUST
+	kasan_test-objs += kasan_test_rust.o
+endif
 
 obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_test.o
 obj-$(CONFIG_KASAN_MODULE_TEST) += kasan_test_module.o
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fb2b9ac0659a..f438a6cdc964 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -555,6 +555,12 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
 void kasan_kunit_test_suite_start(void);
 void kasan_kunit_test_suite_end(void);
 
+#ifdef CONFIG_RUST
+char kasan_test_rust_uaf(void);
+#else
+static inline char kasan_test_rust_uaf(void) { return '\0'; }
+#endif
+
 #else /* CONFIG_KASAN_KUNIT_TEST */
 
 static inline void kasan_kunit_test_suite_start(void) { }
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test_c.c
similarity index 99%
rename from mm/kasan/kasan_test.c
rename to mm/kasan/kasan_test_c.c
index 7b32be2a3cf0..dd3d2a1e3145 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1899,6 +1899,17 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * Check that Rust performing a use-after-free using `unsafe` is detected.
+ * This is a smoke test to make sure that Rust is being sanitized properly.
+ */
+static void rust_uaf(struct kunit *test)
+{
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_RUST);
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
+}
+
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -1971,6 +1982,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(rust_uaf),
 	{}
 };
 
diff --git a/mm/kasan/kasan_test_rust.rs b/mm/kasan/kasan_test_rust.rs
new file mode 100644
index 000000000000..7239303b232c
--- /dev/null
+++ b/mm/kasan/kasan_test_rust.rs
@@ -0,0 +1,19 @@
+// SPDX-License-Identifier: GPL-2.0
+
+//! Helper crate for KASAN testing
+//! Provides behavior to check the sanitization of Rust code.
+use kernel::prelude::*;
+use core::ptr::addr_of_mut;
+
+/// Trivial UAF - allocate a big vector, grab a pointer partway through,
+/// drop the vector, and touch it.
+#[no_mangle]
+pub extern "C" fn kasan_test_rust_uaf() -> u8 {
+    let mut v: Vec<u8> = Vec::new();
+    for _ in 0..4096 {
+        v.push(0x42, GFP_KERNEL).unwrap();
+    }
+    let ptr: *mut u8 = addr_of_mut!(v[2048]);
+    drop(v);
+    unsafe { *ptr }
+}
-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240820194910.187826-5-mmaurer%40google.com.
