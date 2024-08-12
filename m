Return-Path: <kasan-dev+bncBDI7FD5TRANRBWNV5K2QMGQEMBGS7SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id BAFF794FA46
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 01:29:31 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1fc596b86a6sf53873155ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 16:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723505370; cv=pass;
        d=google.com; s=arc-20160816;
        b=fpxYIEJiGzcwbfuV8RWuZlN06ft80tdS9RfrRnId/THY11TqHg4LdVEHP4qAnD6Rof
         hbBH3Rc2U8PLCaJ3vAKTnOCRJd8qARe19icaCgAtUlTZe2+GA6ZTE64W7PilgFikj6zp
         VsOrzxE9nSjgwFKCNAEN73KWKYLtlotvIiHzelA4gZcBd21NX6UrHu1dCQqRR6+DYPbn
         2/hKVpwgChSILp5wt7o7/eLEg4WbGd0Ijp5i2L5zlTN4nOARkh+kTvQ4SH0co+11RbxM
         NiSRKQ8/JvStQRIILWokVMUQfUe/3RfaPjsiPLZlhtdMqTmRv89OA0h8TulEZhBpQUcZ
         cJUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YlW97aB89EaOSo9b8fT4MPPsZLKT0XEIX/ar0BYGP4E=;
        fh=h5rZ102kUG4dqyCsIAgQqHgM6UOPQon/qmMiDHYLrd8=;
        b=Y79UL2xPQC9rr33JOYAbFAzJQt3cwv8vb0yYsGJEIMvPd+6qWAbDXZoSS5SQjYk1Pz
         cwpn36shRfhkUZfwXLBH6WRZ4heJadTeJi6Xmx6HCrtvIrnRt1sy5MdhrdkScHwNBxRJ
         0jAY68ICTnZRTSkFXsAKzi3sInFVTJkAt74DU6ebKNdmbQRjhWLOgMAym4v5ZEUpQjAY
         HspABbEztkeLRjFh/iqeUj6Hp6guYMRqNOxAD9btbuyOmvxWULe6hXBntdBCZgGPbvrP
         w11EsGATw5RX7kbpQ6urgRPriMNmnfJLc1n1pbizv4L6G9R8z071ti7FEF0+92agKY0k
         MDXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="b/IUmvBV";
       spf=pass (google.com: domain of 315q6zgckctqccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=315q6ZgcKCTQccQkhUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723505370; x=1724110170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YlW97aB89EaOSo9b8fT4MPPsZLKT0XEIX/ar0BYGP4E=;
        b=Qa/foUe0SKRurQjv4HWquXA0g+HFrlGdqj7sOgtFhmzNp4Uw+64s8AQ0Wa9tWf8wm2
         5RXOK2+RMHEk3m16LMdhOqOcKo1uTznOI+V2DOPq+Cyk5/0uN9rAhmo5GLo7/ue1t7j0
         LLauj9Bh/4ZWXVm9uxL7mhaveDszKJVMa/bQEJcG+s49BnKLN8VtRs/uTW1GxEOFgEmg
         Bf7wvQ5liE5RwMXCw74xisxrT6ZEuBjax2DZPSSs7WHsINjDoty5kCGm7B9l0G+Jc9Qg
         d4s88oHRGSBO7mTt8AE5iNvx6vT9V6dEeJa38fV8GWWFr06AmiYGWpr4/Dv8vnPPZaRM
         xlUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723505370; x=1724110170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YlW97aB89EaOSo9b8fT4MPPsZLKT0XEIX/ar0BYGP4E=;
        b=jKgSwIiEqJ157UUtLfWaA2gktebbz1JBSmwUVwvCMqdLFJQu+JI03pt66jdoFhgitI
         L5SoHTdz/cjbL1/P8Py5ZuhbGTP86JBgXjSrEM6H6nPAB+2mHhfaO17pOpBE625JcRNd
         WaVZKfrpPftZuiWHphSXTstdspg0neUwHIIvricSfbQVi4zzGPLuCQgellSFrv7UM9eT
         Qkp/6QEhY7YxWNtgPW8FXPr368Pyovd6CEooI+BWadrns/ypCFodO9rSY0mbOWM7485o
         FM7rVUCel2VvmLOS2bZkzGVC14P/RCeavM/8iVpk5oIRnyjJfH9hJ3Gj1u09hjpJ6YWx
         DCuQ==
X-Forwarded-Encrypted: i=2; AJvYcCUosx/xxbGC4m7e/sMZBoWl45lC/2uCzL06u12T4dr3V+c1f5MjAXfYkgDp7AzrAqhh008UF9hi1DMvs53zePPkkHbPF0VQOA==
X-Gm-Message-State: AOJu0YyJdVNXcBxUPYG5tr+qzD1gvSxOpx5SQ/anVqCNCwIyDGAOdUjm
	v3xozoV49d4as1XMgKqX/mgdnfsu5DZzSXkDyZRSOwsZ/baSxXKm
X-Google-Smtp-Source: AGHT+IHfOn5qQYIyNJYrxcPNOQ9caGVSVD7EXRHZE4clVv+dA/qoyTqBDZsFIJuixmN9x83IaptuOA==
X-Received: by 2002:a17:902:d50f:b0:1fd:9c2d:2f14 with SMTP id d9443c01a7336-201cbcdd6e4mr14950005ad.32.1723505369711;
        Mon, 12 Aug 2024 16:29:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:11c9:b0:1fb:2e1d:ad0d with SMTP id
 d9443c01a7336-200903efad2ls32589835ad.0.-pod-prod-00-us; Mon, 12 Aug 2024
 16:29:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzfgI91WNdq7J92WkYQ7I5OGUe/zneSsN7j1UizGhzA6pTNPEIsvcJiUD1ju7tjpJiBQd3ckJ4aVj1/HU4xTNJaDWKMGSvuNdbNw==
X-Received: by 2002:a17:902:d4c2:b0:1fd:6f24:efad with SMTP id d9443c01a7336-201cbc7255bmr20113115ad.26.1723505368485;
        Mon, 12 Aug 2024 16:29:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723505368; cv=none;
        d=google.com; s=arc-20160816;
        b=Udef6yKXG0fdNDdTD8oYTEC2+H/sV/n5nYOwNJ4z3e2JwKeU97PBS67EyQz18v+d3n
         3OxMUnsSt18M4v22rz+YyXrQBOSIpu/6jdk3RP4W3M1+eKSLLEGsn83DeA0mdnDQhJka
         cuLp+xRQDtQSV3fVFNx1U4PuN5WlbIOxpHhwm/cYyB20YnS+DlVdHMbkGDO+nYplM+Ob
         krP5Ed8HffMmAY7xFbwYW6vgfilaIOpWDbYPt8auLiF2E9Gk84GY8kXhnsXHyb9BgE9N
         PRQWhzgn3bwxsQVLKpVOjZGwrt4Mi+qGYwtd0JTDmoIANBjjrpM1oAuDPlAsTT8X59i+
         BEgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=upOwpMTeo+ntHO/NqVQFtbSuOi1aXqqXOiMSFMXzMsU=;
        fh=aE4DqogPl+KD8KhFiesNyFcQsXTP9uKf27oeZCkrwjM=;
        b=btoY54CpWzXdKe14J0ZSpiNgWmqRVDGNYKbgNlgOIFteMvFR+JIOoc0Z7yh6XTy+5y
         tBTk3OiUTx7MeusrCiZsREv26OWVNV10J9uzhuUQhQDOKiOdA1P+rksIK5ROmVCFCu1F
         0HvahBXTTsQKZ/D1JUdfYs/SNtcRGJzlJ6Pn/a14TNIEf1J5co5bVKot6wnzDI6VTJTP
         bt+t3ccsQgFWEGitpijTAkmTkZYm4sjnbKeQqg/QU3iKBG+BVNb3ZaHo8ZVQGDZOWn5k
         4SXVnm7SNDMm9xDTIOYlNSX1pviyrHOCjw98ddYrO7cHoA0BGDslSSgq4gletHnJKzEa
         P94w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="b/IUmvBV";
       spf=pass (google.com: domain of 315q6zgckctqccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=315q6ZgcKCTQccQkhUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-201cd18dcadsi205315ad.10.2024.08.12.16.29.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Aug 2024 16:29:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 315q6zgckctqccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-68f95e37bbfso120307737b3.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Aug 2024 16:29:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXk5eQBryJbwepkGT4gnm20YNYom+3yEdbR04hC7KMN/NKdyJNAYjTnTA3/Y2CbwXNffIADncAfmARaHAb56Y78YR0McogP1DO9xw==
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a25:5f09:0:b0:e0e:4a15:cc1e with SMTP id
 3f1490d57ef6-e113c80de33mr25468276.0.1723505367499; Mon, 12 Aug 2024 16:29:27
 -0700 (PDT)
Date: Mon, 12 Aug 2024 23:29:03 +0000
In-Reply-To: <20240812232910.2026387-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240812232910.2026387-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.76.ge559c4bf1a-goog
Message-ID: <20240812232910.2026387-4-mmaurer@google.com>
Subject: [PATCH v2 3/3] kasan: rust: Add KASAN smoke test via UAF
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>
Cc: aliceryhl@google.com, samitolvanen@google.com, 
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="b/IUmvBV";       spf=pass
 (google.com: domain of 315q6zgckctqccqkhuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=315q6ZgcKCTQccQkhUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--mmaurer.bounces.google.com;
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
 mm/kasan/{kasan_test.c => kasan_test_c.c} | 13 +++++++++++++
 mm/kasan/kasan_test_rust.rs               | 17 +++++++++++++++++
 3 files changed, 38 insertions(+), 1 deletion(-)
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
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test_c.c
similarity index 99%
rename from mm/kasan/kasan_test.c
rename to mm/kasan/kasan_test_c.c
index 7b32be2a3cf0..28821c90840e 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test_c.c
@@ -30,6 +30,7 @@
 #include <asm/page.h>
 
 #include "kasan.h"
+#include "kasan_test_rust.h"
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
@@ -1899,6 +1900,17 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * Check that Rust performing a uaf using `unsafe` is detected.
+ * This is an undirected smoke test to make sure that Rust is being sanitized
+ * appropriately.
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
@@ -1971,6 +1983,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(rust_uaf),
 	{}
 };
 
diff --git a/mm/kasan/kasan_test_rust.rs b/mm/kasan/kasan_test_rust.rs
new file mode 100644
index 000000000000..6f4b43ea488c
--- /dev/null
+++ b/mm/kasan/kasan_test_rust.rs
@@ -0,0 +1,17 @@
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
2.46.0.76.ge559c4bf1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812232910.2026387-4-mmaurer%40google.com.
