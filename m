Return-Path: <kasan-dev+bncBDEZDPVRZMARBF6VRTDAMGQEIQG6IQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 912EEB53CCF
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 22:01:30 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-7724ff1200esf979493b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 13:01:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757620889; cv=pass;
        d=google.com; s=arc-20240605;
        b=lqwIvKGYjc1QB4CKfojW8T0c2TAk8Yorw9MZQVXMPVjiNTl5aWEJuGXS1/t7okmKR9
         G6xlNNTaJCgYjC27j0cr0VovMnnFVAXgnIrkbUQeq53zuuoGiz59wPzhDyrKSqZAImNy
         7cbVKQ08GwYf315SysH8UvlLqcv3nUKWgFWg5lEO0xePWn8TWI0/yXEOmDIXc94PQvi/
         0uvsmkWNENT5UodHgHSCWa+7xuuVLdJ2aauhnvpJ4iL0wx18YUDDxccvdt6u+wGaIkWI
         jRkyxbnP0+fCktyUgnw8Yy//h45VOS157/lKCMZyPtY6HappAoZDnxHRJ3HCfR9Oyl6o
         TQbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=vjxZFQdC+I8xUxg4sIaS22LFlVBKGqEnFWZYN+T3LPI=;
        fh=fs9Nwz2L0g5FcPXTKVvfpVC43nk+szgWsayV25J4zK0=;
        b=EGTbrl/uabT5wris3On6hcvoDugwIuxZ7jpoYMSL7ApdwAebkOPDLnD1l0L+G3Bh0x
         wDfkObQ+3f2Kmpkc2yNeDabFlkaBk26LuCt4pTBgXQvl1OmAnblxSgGA+Wdj92hfegGo
         T0V3tGCTuAsOJfUp+t3Z8McOvnaE7luHIvL2CQxDXD6AmIiV0JNtdwjW6XNpNJb267YZ
         UPuUvnBEIfQaIQnpkR7BHpP7xNEvAQemHBeiyyWJneCqKvgoRT/E+/3Dh7bM8uqnlnei
         rTPeAZMfdHqUXYgXHOj9vxyXpxDmLkXBGsv01XPZEgSmXhQGTj0eWLJDrqkPHS0LMlsR
         kc1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ewFZ9qag;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757620889; x=1758225689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vjxZFQdC+I8xUxg4sIaS22LFlVBKGqEnFWZYN+T3LPI=;
        b=dBEMkx4VWoU3ZKmg25xsxF42R1/ge74cXvb7FjC6hyQyyJQ2V1U57w78RpB6GOwXTY
         PcqPzwRFaM47RQdG7xX0e1xyixAn1OPkZfrLheWLxvjYlcTxPYHA8pUFRa7nE8EU9fFj
         UKnuT13cYDzov2a2g+J2ZOUkEmKXThpP67VOBPOUJVAznF9EhpTrBBjKA9PKrw2Pj/xC
         jA6vQIE0Pp7uIuYyNNjNpuAwkJ+0heQS8LsjXcDA06PS0s5PN9+xMmKmPD1EVbP2RFT4
         4OmEFuDJLxORCUycORPeHzYHtlIfOHTFICpF0UdKfVS5NHhGk2e2Qk+BZgFQ/vGKRhiA
         rOiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757620889; x=1758225689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vjxZFQdC+I8xUxg4sIaS22LFlVBKGqEnFWZYN+T3LPI=;
        b=Iz6JqCkXmWpdwedjfpjwjDPJ8TOvpD+mMqPrGB8Vk0chtAprGG/3KZh1x4EguNWWCc
         bLNM4Is8TzknEEkG0iasdomc1r3S/NRBE96/j2uNGNjJ/VNlD2bCggQDQ0kGmj3d7wph
         WB4It1bthVvo5h25TfgSxtpbAM076kERZbgxHeTRJhk48yPLmHGXYrv8IPxwhsiZoYYg
         TvGRYhj3Y8gxezH53UTeGB/8lBFsab+YSv5OFOixWiraz3Rj3jTi97DZBe2w2LKrMo8s
         OSYuHvCsBFsV+4L7x1eLF65AGzNOD33afa5zdMurf2SQ8NWH1fYAQYajbSl575GsMxeX
         tCzw==
X-Forwarded-Encrypted: i=2; AJvYcCWlQ0LKO6vt5I2wAd9BZhiMWhFeJs9pKIpvbZT67Cj0rdfw4hyH/tn4PMqJ+XPuWCYdCTDg9Q==@lfdr.de
X-Gm-Message-State: AOJu0YxRFSaxobJbB9mOwLIJf34h+S6v8KodqgXRXqJaP4RLMTLMsA5P
	P7jKiRlXnnZ4gZNjsPSgFjt8VXMDuCfOCJ5C6gIDbGJviuiYw8XzuYrf
X-Google-Smtp-Source: AGHT+IFNdMbrPeg3vwEh24zIpd5FJfr+7CsQVPD0wjdGz02G3NPhNJyioBhYJ2VeJ8x+opGz+kETNQ==
X-Received: by 2002:a05:6a00:23d3:b0:772:38d0:4fee with SMTP id d2e1a72fcca58-776120913cemr572781b3a.12.1757620888255;
        Thu, 11 Sep 2025 13:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeMPkvjxyT9iO8Jo0u3axU029l7z0TmoA4jE6zaSMm+mg==
Received: by 2002:a05:6a00:b4c:b0:772:87ee:6e5c with SMTP id
 d2e1a72fcca58-77604e25b10ls1102596b3a.0.-pod-prod-09-us; Thu, 11 Sep 2025
 13:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQOXjJuGbPIqP3jl2OUsSS50MkuNASkrV3ZLceQ6AkRzjSaR3PQ2yM1SrLUqAVGmBL0tk0V2HkSx8=@googlegroups.com
X-Received: by 2002:a05:6a00:194b:b0:772:5271:d1ba with SMTP id d2e1a72fcca58-77612061e2emr662529b3a.7.1757620885755;
        Thu, 11 Sep 2025 13:01:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757620885; cv=none;
        d=google.com; s=arc-20240605;
        b=KfYt08zfPya5h3w7H43RCNXp86RVCiCpaoWaKLaCwM/327k7eGJnkMosv1LDu1LFFG
         rhroac6MobJxevRsRzyGB9krU6Qmrol5T9uBS/xGivHYh75LBmHZPipmpE0+ts5tqN7j
         8opeu9WMQOaWUYVCwunnp2V+Zpl/s9s+ZV4mwTx2+tC+8Ko/DoYc8OskRbrFHnFYGsHa
         o3lu8CGKEv0RvvIEcnCzwoibPMxgwjJ/PL7lBTK4PNBOdON46KPEL18GxoA1pKjGA7bE
         MSb8I0MtV2wGs2LJx81WC4Swk6YvUOWC6ba0lRDQNpEStZF5JjQUoqLGRKUGO1/5kSAt
         n1Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/U4YTn7fpmVQukBqbILryxn0c5nCuyfdigbDju2+Dzs=;
        fh=oO4b7IAYxhiiXhWty/Cra9qYmXRSX03jv+l0QdgpWPA=;
        b=FRbOJdupCb7hoxXK32mHPL9Equ/ST7k1wMB4Rwjz1iwh3FUrb0OnlSmjWZD9R1dmxu
         LRmpIXeSHIY2R+vzKR/EJufSph3jCpfASCuChCNcMnj0e2cua/LsTB34jKCfp61gdHba
         fxhuNZsZ6N/lL56Rwvi3wGfV0YVsT68y4PYLwvszZSo03IwEGRTc1bQ3Vo0CFUyo1Wi+
         JmWZ93hinOmaD0jnYy33bbE9b8eM8L/J42JMBLDztLPF5PkAyUDpBvhHcQ0KcPV7LIKb
         ITHs5OelzLIKRpifkBuh5dbdhoaMyEv5byOLMaiU5npmJZL2ESmBW/qsOYEJWH9R2YO5
         eYCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ewFZ9qag;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77607c67badsi82946b3a.6.2025.09.11.13.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 13:01:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C08EE601DC;
	Thu, 11 Sep 2025 20:01:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2AD03C4CEF0;
	Thu, 11 Sep 2025 20:01:24 +0000 (UTC)
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com
Cc: Dmitry Vyukov <dvyukov@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	Eric Biggers <ebiggers@kernel.org>,
	stable@vger.kernel.org
Subject: [PATCH v2] kmsan: Fix out-of-bounds access to shadow memory
Date: Thu, 11 Sep 2025 12:58:58 -0700
Message-ID: <20250911195858.394235-1-ebiggers@kernel.org>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ewFZ9qag;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

Running sha224_kunit on a KMSAN-enabled kernel results in a crash in
kmsan_internal_set_shadow_origin():

    BUG: unable to handle page fault for address: ffffbc3840291000
    #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page
    PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
    Oops: 0000 [#1] SMP NOPTI
    CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G                 N  6.17.0-rc3 #10 PREEMPT(voluntary)
    Tainted: [N]=TEST
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
    RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
    [...]
    Call Trace:
    <TASK>
    __msan_memset+0xee/0x1a0
    sha224_final+0x9e/0x350
    test_hash_buffer_overruns+0x46f/0x5f0
    ? kmsan_get_shadow_origin_ptr+0x46/0xa0
    ? __pfx_test_hash_buffer_overruns+0x10/0x10
    kunit_try_run_case+0x198/0xa00

This occurs when memset() is called on a buffer that is not 4-byte
aligned and extends to the end of a guard page, i.e. the next page is
unmapped.

The bug is that the loop at the end of
kmsan_internal_set_shadow_origin() accesses the wrong shadow memory
bytes when the address is not 4-byte aligned.  Since each 4 bytes are
associated with an origin, it rounds the address and size so that it can
access all the origins that contain the buffer.  However, when it checks
the corresponding shadow bytes for a particular origin, it incorrectly
uses the original unrounded shadow address.  This results in reads from
shadow memory beyond the end of the buffer's shadow memory, which
crashes when that memory is not mapped.

To fix this, correctly align the shadow address before accessing the 4
shadow bytes corresponding to each origin.

Fixes: 2ef3cec44c60 ("kmsan: do not wipe out origin when doing partial unpoisoning")
Cc: stable@vger.kernel.org
Signed-off-by: Eric Biggers <ebiggers@kernel.org>
---

v2: Added test case to kmsan_test.

 mm/kmsan/core.c       | 10 +++++++---
 mm/kmsan/kmsan_test.c | 16 ++++++++++++++++
 2 files changed, 23 insertions(+), 3 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 1ea711786c522..8bca7fece47f0 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -193,11 +193,12 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 
 void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 				      u32 origin, bool checked)
 {
 	u64 address = (u64)addr;
-	u32 *shadow_start, *origin_start;
+	void *shadow_start;
+	u32 *aligned_shadow, *origin_start;
 	size_t pad = 0;
 
 	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(addr, size));
 	shadow_start = kmsan_get_metadata(addr, KMSAN_META_SHADOW);
 	if (!shadow_start) {
@@ -212,13 +213,16 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 		}
 		return;
 	}
 	__memset(shadow_start, b, size);
 
-	if (!IS_ALIGNED(address, KMSAN_ORIGIN_SIZE)) {
+	if (IS_ALIGNED(address, KMSAN_ORIGIN_SIZE)) {
+		aligned_shadow = shadow_start;
+	} else {
 		pad = address % KMSAN_ORIGIN_SIZE;
 		address -= pad;
+		aligned_shadow = shadow_start - pad;
 		size += pad;
 	}
 	size = ALIGN(size, KMSAN_ORIGIN_SIZE);
 	origin_start =
 		(u32 *)kmsan_get_metadata((void *)address, KMSAN_META_ORIGIN);
@@ -228,11 +232,11 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 	 * and unconditionally overwrite the old origin slot.
 	 * If the new origin is zero, overwrite the old origin slot iff the
 	 * corresponding shadow slot is zero.
 	 */
 	for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++) {
-		if (origin || !shadow_start[i])
+		if (origin || !aligned_shadow[i])
 			origin_start[i] = origin;
 	}
 }
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr)
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index c6c5b2bbede0c..902ec48b1e3e6 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -554,10 +554,25 @@ static void test_memcpy_initialized_gap(struct kunit *test)
 
 DEFINE_TEST_MEMSETXX(16)
 DEFINE_TEST_MEMSETXX(32)
 DEFINE_TEST_MEMSETXX(64)
 
+/* Test case: ensure that KMSAN does not access shadow memory out of bounds. */
+static void test_memset_on_guarded_buffer(struct kunit *test)
+{
+	void *buf = vmalloc(PAGE_SIZE);
+
+	kunit_info(test,
+		   "memset() on ends of guarded buffer should not crash\n");
+
+	for (size_t size = 0; size <= 128; size++) {
+		memset(buf, 0xff, size);
+		memset(buf + PAGE_SIZE - size, 0xff, size);
+	}
+	vfree(buf);
+}
+
 static noinline void fibonacci(int *array, int size, int start)
 {
 	if (start < 2 || (start == size))
 		return;
 	array[start] = array[start - 1] + array[start - 2];
@@ -675,10 +690,11 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
 	KUNIT_CASE(test_memcpy_initialized_gap),
 	KUNIT_CASE(test_memset16),
 	KUNIT_CASE(test_memset32),
 	KUNIT_CASE(test_memset64),
+	KUNIT_CASE(test_memset_on_guarded_buffer),
 	KUNIT_CASE(test_long_origin_chain),
 	KUNIT_CASE(test_stackdepot_roundtrip),
 	KUNIT_CASE(test_unpoison_memory),
 	KUNIT_CASE(test_copy_from_kernel_nofault),
 	{},

base-commit: e59a039119c3ec241228adf12dca0dd4398104d0
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250911195858.394235-1-ebiggers%40kernel.org.
