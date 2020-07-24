Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF4O5L4AKGQEZMKRZZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F28622BE72
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:41 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id a14sf773491ybm.13
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574040; cv=pass;
        d=google.com; s=arc-20160816;
        b=JVza8fnVoYEBIMPIQrcjIaJysMy+hP4LtGYZHPji4Dels2/vtidV39BWDlVQbojf9g
         m/kfJx2cawtuLuhBApxuqrUfobQ8V7lac3AWtuHV6KNIMNlRCUbGDke18Ejqtk/+XJO/
         4unVegP5jZnCX8aBTnUzfBrrTWB+i920QP4Z4zoIOCWMfYfcD//cuQDxIRx6rnTBxYAx
         I4O8sGJbWwkOsCRNrTT+GlpDLKn4gCKhqd9Hec6DPy8rZ2c98hvAflP+c0uFdrw6ZKZn
         L2pZeaygCHScWQ5CXk9M8ouMtFg1S911HmNO60/jNS7i0GCOoqmuxkyPf1A6SHn0yll3
         jKMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iV01x7MWpfl2oSC+aQjqRGFINRDXiiTXv3zH5kGpdzM=;
        b=HSWhJ3/KVns5FLwTEdDW8MOymz8v/tOIPOtOVwrS0aPr8WBfyLmEeaQUPd+DcP/CdW
         Y9Q1cZWQg+Z3N0tbnmd6rbl7xUYnZg5cXG3rwrD1EbSZSrrErrITWM9aiwQjdY6xQylu
         2dNHrqYw1VKP3CZx1pFLy0HGw9gd9+1/tcefULOqCjpL9BoX6xUlhb33+Oi2G3DRDNd5
         CPt8f7VK/VzCmcCkS6mp75z/e5g8+l8pZhBrIJxkMHgx05FG/U+qiwLpWiGvMTy5il7C
         PNZOmNnBL45dXkiIZ9LZ1DSn4ZUKn+teZf+TmxFZxrQ+zHcyeALthyR8KqqNV+jOuJwB
         4Ifw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mmh2Mf3q;
       spf=pass (google.com: domain of 3f4caxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3F4caXwUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iV01x7MWpfl2oSC+aQjqRGFINRDXiiTXv3zH5kGpdzM=;
        b=TYRIaKTtjZwHR6RiZ2zhMOiCSehIoTA+5BhzQQ1HPWsrwvYLWzwJZ0hd+4GVLbMecf
         6rMYujXyQKVBoLreYw96UVR+xPsWms1uJAAEN5sUDwfLvZc9XgI5IpiUAlvRG5tUAc4F
         LPNUHbjiRSh1rOcsejAcyWKhkg9pR5yTneUqZMVufz7zn0VEbZbPi/45yMh3fu/Xpyf5
         HvZWwR146qNlCSZaNrtbOW6eaKYSM9VHZzgPZQM4rP7Yx3A4GCbkS4IB35Xie5B9WfGn
         n6iRonaVHSlLHFrksQ3vLVS6urjG4Qbq7AeKAHfcd4UA6vPiww2WycCdC/7RO6cp6eM0
         Mu2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iV01x7MWpfl2oSC+aQjqRGFINRDXiiTXv3zH5kGpdzM=;
        b=aSAZ7FwHdwNgCN2aDvaTXpSAMkje4LiJS1Uyt2Ka5x0rU4wiIwk8A80vIxn16zLhAl
         R5sEYLI+Sz4gbecWWJxkegd0txXPKCBW2albC5FGde5fwjLHMWLupLaGa6w/l+mMa4Ed
         y117+PE+YsKgKBPh/cD7sRUUql4S4/H0nxBIZgeVG6wWASI/iqH3fjW2ANfK2xGNwMrm
         wqK041h0+a6TBLQb5tyE7c0/4YlA+sZi2wYiD3urCTpuV9dFL4p0wZWxilvW5iStzPRj
         1WVeLkEP9O1YmndkTj7tCaUuMhW7j+P3qIDlkqmyb+KX1jtlgKgF6dUzdqtV2VTrth4K
         X7XQ==
X-Gm-Message-State: AOAM5323mP97hT65Pb5exBEt0VJdlXAUdiUzWroIDHyDO7sH2AhNaP4t
	4Rm0C3nY8a+8fCK5CNfL74M=
X-Google-Smtp-Source: ABdhPJye+NIrhsNteYoi13nJE7XWmo1V4l4wOeZrMLjmWvvZxM8/EcL3Xa31iYU69TTMvJDRKLn3pA==
X-Received: by 2002:a25:701:: with SMTP id 1mr12322189ybh.183.1595574039783;
        Fri, 24 Jul 2020 00:00:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:76cd:: with SMTP id r196ls856385ybc.8.gmail; Fri, 24 Jul
 2020 00:00:39 -0700 (PDT)
X-Received: by 2002:a25:af0d:: with SMTP id a13mr13138808ybh.163.1595574039402;
        Fri, 24 Jul 2020 00:00:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574039; cv=none;
        d=google.com; s=arc-20160816;
        b=bfYymrrx4m7XtgC4xpxF0S922I+DMVze2ttvUyMuw6vq63qzJII1VneT5zQPJURaMR
         yRgST6EfoXIz71ReX3ECCBIaTdIXJS+wKfrMFls2ssDqdpmQa/Tzn7X43XlXrCO5Il2k
         frHFwwwsE0q/y4xH9WSaLoss4gW98XnhQ+X59QE7lf/+lmMwUM6H//5qZAaBVGYd5pAN
         /zcXb/Z6ObnKe/Vz9jYOJeNp5qA+d9h0rYMEf7Tokkbi/BWEqOK0p/Kk1yzgwU65vsgB
         hQ+mfXJgJcpzrlBKg7I3slKBQbZNsWTYB1z2w8ehjFefj7ntB9824odrGuBve6NFz3DX
         gF6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=exjoV/J3QIlZtyiULDQJFxa/y5F8DBbC61V96IvJHj0=;
        b=UP8LOJgWYHoHFLH49oIaEJ9RMxeId+vSxUJ9/U3UuQa7K38WNK1OheUM4rOfKzcwrn
         baSjB07a1r+y3gn3bO93Sk00qzQgOB3+yNPLFMMoYE9f9e1P/xSzjePGDZsgYbhxFHFh
         7WN3Oe85tGAgaHY4DXHvTW996c+0Xo753LJwbjvX+m734Zd6EoY1WCy6leoRVMSui6nJ
         9M54xPP95Ot+JUhjqgWLW1sCMYeR/8bnHWkZa5RH8fohj/7Zmyb4fofJsSMF4EGYI7iv
         bh0U5JTqZD5Ez6xtD21mFlm7bvyC9PeDsrfjaRix2aHTAMedFmrGxmdeXctRD+l5Hl8k
         /AJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mmh2Mf3q;
       spf=pass (google.com: domain of 3f4caxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3F4caXwUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id i144si3489yba.4.2020.07.24.00.00.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f4caxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id u12so9493710ybj.0
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:39 -0700 (PDT)
X-Received: by 2002:a25:ca8d:: with SMTP id a135mr12598725ybg.459.1595574039087;
 Fri, 24 Jul 2020 00:00:39 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:07 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-8-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 7/8] asm-generic/bitops: Use instrument_read_write() where appropriate
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Mmh2Mf3q;       spf=pass
 (google.com: domain of 3f4caxwukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3F4caXwUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the new instrument_read_write() where appropriate.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/bitops/instrumented-atomic.h     | 6 +++---
 include/asm-generic/bitops/instrumented-lock.h       | 2 +-
 include/asm-generic/bitops/instrumented-non-atomic.h | 6 +++---
 3 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index fb2cb33a4013..81915dcd4b4e 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -67,7 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
 
@@ -80,7 +80,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
 
@@ -93,7 +93,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
 
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index b9bec468ae03..75ef606f7145 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -52,7 +52,7 @@ static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit_lock(nr, addr);
 }
 
diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
index 20f788a25ef9..f86234c7c10c 100644
--- a/include/asm-generic/bitops/instrumented-non-atomic.h
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -68,7 +68,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -82,7 +82,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -96,7 +96,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_change_bit(nr, addr);
 }
 
-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-8-elver%40google.com.
