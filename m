Return-Path: <kasan-dev+bncBDI7FD5TRANRBP7VR23AMGQETD2Q54Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id BBC509576A4
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 23:36:00 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-39d52097234sf12724945ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 14:36:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724103359; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xf2kgWUucuihVBsvAZBNTwtC9eMtL1683GeGFW7zxrUaHXcUW7jQYYO/5mwTTska7H
         /an8i+3r99DQyQdu34hIJ4fVSAC88AFm+/fBoOeRi9YWZk11a+bDTEYhsoatIDzPwE/C
         WP6YqZLqLaKbtOtgozDTiQuiS9Q9XxdcTrpguj9oFUimmMKMmkoQoiA8k4+zoweRyzAu
         smX4n65dtK9K2W/oXPPLxu+f6Vspkkx/ele6WfhAbZDiiEGyPmGjddTkdLrojM5L02Lc
         mnK34mO6MJtP4vpqGKInRxScLr5nkgt9Pj8Fp29/R4uafTnRHdR977PpDdDuCNOscTMH
         tB9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7ySRGIpkX7sy/DfHgZ5kVnpzjaPkqNKxqzu+/9UL2Rg=;
        fh=10ckFAXPyZSeWLPgi9cASOPxPERgPjxNpYDY0UxFMGc=;
        b=jtvBoiupbnvPcxxy1RfGylLqY7N8mlcS2/luPXBbTu5/he7qGC2A1zcZjhKsr4+kNP
         K5g569pJLJVku/ljcEj/HIZA2Rwh6UzFFEPhf+exXwcr3N60DiviBdKDgYzs7jm/Clou
         0BqekakbTTyisLxrOWudcihVxcg6nEHcz+5fTNvqMPRJXTyO8mCI5F5QRRL4hn4WsuTc
         72+5NF+r4ki+Ld3Vj0QlTDIfQNkEfsiqDBjmCP0/wyJCh4vd3VWhAW5mOrCC26FXro4+
         LVy0y9llde4NQd4L6TGjXjiH5jCpxMe36Dtqs/jOfBjGy9k8r6VgBsNdAQAMKssvcVvR
         NWXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=I8PzjWcr;
       spf=pass (google.com: domain of 3vrrdzgckcx8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3vrrDZgcKCX8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724103359; x=1724708159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7ySRGIpkX7sy/DfHgZ5kVnpzjaPkqNKxqzu+/9UL2Rg=;
        b=sUekjLawVg761NRf5hZLvYPqHll2/XvDDK2snk0eMZrYUIt1jUrOuQEXhOSM1fYyio
         MMtWPhcpCmgvtrhCK7PBAfogKipxMiVDwZ8SkO9OA6pogYBtE0wAdf0lwDytQCBI9476
         9qqvRp3VYWUok4HvOnJY4ea2LqsYwNLi6FZbZfNVbDb1/1+4Qgm88jFCDYC5AJB6XZdY
         4YsFTyvWZlF3a3AfNQrwhIhiZr2jbrSIGiPQl5R8nXkIrnm0EklcraFEHEkZ5UxKfFcz
         d/Ova8nfuL3sepBA/rh78yerbTgHCgrbLbgSS7w5avwdCIolQDXmY21Wd8md2/ETeipb
         4PNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724103359; x=1724708159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7ySRGIpkX7sy/DfHgZ5kVnpzjaPkqNKxqzu+/9UL2Rg=;
        b=rELhraslul7vFvXx30ubLyXZDeAKxPBGtq1rBhva9Zl3EGF/fXw4Du2OzJuqHe2WtH
         j9M/kBUj0P2mHxOi4Ql3MuSncFmp06fdRprfSa1BBsG0oIpp7uETJ/m68QOKSxrnTyqE
         TxWzHkFbTYOiace2RRoI0BYlY3tkFpZNraL0XKb+cCiNrLsio+Z5Hej+GpFEJ8F+ors6
         Mt3DLzn5xfuL50Fs7fLf2qZcWQxQgDHcdjvUz7c1xJqFwFfmFCZ/FtfLgXv4f7LGL4Oa
         LO3N72tmGtENfaUc1no7sPvGTTx0XAGPiwhyQ6UswEQGq0JiTfUDK4CVYyPJ1ehHsTLq
         c9gw==
X-Forwarded-Encrypted: i=2; AJvYcCXB4+3w1KJ1+JIRAHnUylbqpDT5XQSNVGGf9Wtjz1x7bm3MDjcMAe4Msb+HssyWIEkXJjgO0g==@lfdr.de
X-Gm-Message-State: AOJu0Yw2vC/R+ZB7JiHwfUz45LLb8Tj9nMgkPn4JWbP1JMAz3CUOEJhO
	Dzz01rPt+dVBLHisjFU128G12dj8g5wgSUIqyRmuWTEImXPJXhlr
X-Google-Smtp-Source: AGHT+IHwEaLQElAWLXMfY5se+At3+Y5BdgUOJ88skVe1UMW1bt6KS9p/cYqm4bpKr7azX3MOpA2zeA==
X-Received: by 2002:a05:6e02:b2c:b0:398:a2e0:18dc with SMTP id e9e14a558f8ab-39d26d6442emr155031185ab.17.1724103359594;
        Mon, 19 Aug 2024 14:35:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1aa3:b0:39d:4f2f:971f with SMTP id
 e9e14a558f8ab-39d4f2f97b5ls11014075ab.1.-pod-prod-09-us; Mon, 19 Aug 2024
 14:35:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUV7/QZDZNQ5j5Ln20ojc76GWEJrtuEqz8cIRchrEQAgGblfFW16IfV2depyg9o+99YFh2DG7+BzFE=@googlegroups.com
X-Received: by 2002:a05:6e02:164e:b0:39b:388c:3697 with SMTP id e9e14a558f8ab-39d26d8040bmr155931775ab.28.1724103358847;
        Mon, 19 Aug 2024 14:35:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724103358; cv=none;
        d=google.com; s=arc-20160816;
        b=HnW9yUMx87SOQh0/JSmfQDcZRIy+FPCP/+tR37HzMtDDSQ2GbrpQqQIBnKL0SBp/X+
         3Px5i2GhhMe6A7sLmyho4Ild9+mv/prvPvzO0iC14OuBLN83A825zIJAlHU4BwQDnwZi
         4M3OHWkYRLZim9x3kSeOhL4MowhpazL52sQM8A/0HhLPhnvN2k+wm7VfzJrjOvSLJZgK
         TjErMNC1BSZYuQ5wHLgz7VScWYPL/NBtzoJtHJYPEJosBZw1/I0qWUUiIWTY8Oz32g90
         gmWnGsIzU6i71hmrpb1lLodWgh7TT0B9ZH4nDZh9QcI0AdbrNFRPaeRtSi/otSM8WVxo
         pr3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DLZP/QF5cmnVPLPNbpw6BEPvqDqvHQJMieoIEn+0YgI=;
        fh=gCZoZSavTK0MLNF/LgYgJLtoJhjAJ5DDZ5jflFQTME0=;
        b=OFhUQFYr8Hs1oFGSVDB67TIMKs5NxiHS/SFh1/5A0Lb7XRObehVjgX5elQV7Ngr4Bz
         un/Gofx8L7mqXCr6l6wQ4BK2WbBeWwIKyJhmCR7bWR4esuzwMR7oq8Z4hFmCWnOENI/k
         6AVutOBZ1EaxWygN9BIspshqbQLdNOc6KXc1BQEKCr2kyTk7Y4aegVhBJ0rTAyGzfu9I
         c/iJuXkmxtdu0wd3IXA913byNMn+rDiAU22rjeeJMb1GNfDZ9Oln5WzmPySUFaA3lVTi
         x5qnHbbMvA6G7ckxzfKlrE7QJyGLZqJ9iff6W2ks7CJ8Cp56PRZnjklYI+i8dYEc2GUo
         ABEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=I8PzjWcr;
       spf=pass (google.com: domain of 3vrrdzgckcx8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3vrrDZgcKCX8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-39d1e9ac4bbsi3980235ab.2.2024.08.19.14.35.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2024 14:35:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vrrdzgckcx8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6ad660add0fso61814467b3.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2024 14:35:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtQjQdeLLCw9FZt5UiBDmeizUAytBkwpbLBs62ekZUlQ+SWL4lnScZ+YpC6GqvRS/8Q8TUx8oVztM=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:690c:4d82:b0:644:c4d6:add0 with SMTP
 id 00721157ae682-6bdcdcb9effmr348377b3.1.1724103358288; Mon, 19 Aug 2024
 14:35:58 -0700 (PDT)
Date: Mon, 19 Aug 2024 21:35:22 +0000
In-Reply-To: <20240819213534.4080408-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240819213534.4080408-5-mmaurer@google.com>
Subject: [PATCH v3 4/4] kasan: rust: Add KASAN smoke test via UAF
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>
Cc: aliceryhl@google.com, samitolvanen@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, glider@google.com, Matthew Maurer <mmaurer@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=I8PzjWcr;       spf=pass
 (google.com: domain of 3vrrdzgckcx8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3vrrDZgcKCX8ppdxuhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--mmaurer.bounces.google.com;
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

Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 mm/kasan/Makefile                         |  9 ++++++++-
 mm/kasan/kasan.h                          |  1 +
 mm/kasan/{kasan_test.c => kasan_test_c.c} | 11 +++++++++++
 mm/kasan/kasan_test_rust.rs               | 19 +++++++++++++++++++
 4 files changed, 39 insertions(+), 1 deletion(-)
 rename mm/kasan/{kasan_test.c => kasan_test_c.c} (99%)
 create mode 100644 mm/kasan/kasan_test_rust.rs

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 7634dd2a6128..d718b0f72009 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -44,7 +44,8 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
 CFLAGS_KASAN_TEST += -fno-builtin
 endif
 
-CFLAGS_kasan_test.o := $(CFLAGS_KASAN_TEST)
+CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
+RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
 CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
 
 obj-y := common.o report.o
@@ -54,3 +55,9 @@ obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o
 
 obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_test.o
 obj-$(CONFIG_KASAN_MODULE_TEST) += kasan_test_module.o
+
+kasan_test-objs := kasan_test_c.o
+
+ifdef CONFIG_RUST
+kasan_test-objs += kasan_test_rust.o
+endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fb2b9ac0659a..e5205746cc85 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -566,6 +566,7 @@ static inline void kasan_kunit_test_suite_end(void) { }
 
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
+char kasan_test_rust_uaf(void);
 
 #endif
 
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test_c.c
similarity index 99%
rename from mm/kasan/kasan_test.c
rename to mm/kasan/kasan_test_c.c
index 7b32be2a3cf0..3a81e85a083f 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1899,6 +1899,16 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * Check that Rust performing a use-after-free using `unsafe` is detected.
+ * This is a smoke test to make sure that Rust is being sanitized properly.
+ */
+static void rust_uaf(struct kunit *test)
+{
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
+}
+
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -1971,6 +1981,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240819213534.4080408-5-mmaurer%40google.com.
