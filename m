Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id D91642580A3
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id o18sf4643611ioa.21
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=SC8jObuEz0RGJayIBJHsgqyR1qltK3DVKBw4cPA0g6ajnxt2/Vo2xFWu+XgcigyxBd
         zm115jDq9RCJvztUs1iVitfXNC5VeIoIJk31bMHa/Qfwz6Y3Cfu+gqOzY5BTDCbOu8BO
         ptZCmJ/93pA2e6V94a+q/wxXDi+ZKazHAWD+5QDGz9tQclmYdzJVy6izSlaA9uTSRp6F
         CoYbxZr4af+BHHrTQAd9H0FpDHHekzQ6v7aOcoFENZZkSX+/KkUDTcpiA+0d5XEpuWZn
         ffaFtseO3QBBrxZ9fXfI3sbQTLobc29kLCOZwKlbC10g/gQ/5vsFZSbsM4Mrrjnuw7xD
         9sMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Yr7J+Xgr7VJ/vA58vp4MBVL3mYc6RZ2FHu0I5QjJi4Q=;
        b=iDTI6y6yBtpaNfwh0boYCHtKT1fECZBbYfcRFbcICSiLPLaPu7aX0N3lSg/A6W/Gmb
         srj7Rr/KLOzrhIg2MqbZTJlgpZC1M4S7oC7C2cMJ7jHdkhdvT1SnGPYWzX0s7IRiKEsE
         MJQYaWos6VLbS0Qog1GQyx8whKiSePJ4g6/MvWY9uTNuGmaeL6bXbG9sZVCTUqjr2Jnd
         kUvYns+iG6Ev1QlhowjjvQfGs15OEhCkWnVDLYZGxXmBVQGFK4owiFPQbg/guOkB8C9+
         lM0ysVMHWueCAbkW2+Ul010wEsWJZueQC91crYRD4mTKlgAAkNdNXGvVqM7OToB8kbDp
         1InA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=v1BNfe2a;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yr7J+Xgr7VJ/vA58vp4MBVL3mYc6RZ2FHu0I5QjJi4Q=;
        b=YkRV4CjirgbiIpRPf1lKItxH0GpTiY/ro/FuzPxH2hv/0iu2fCTBVOzvqBEMhFqMpJ
         x/PqBuIdAbHhyEt41+1IagjW8iuH4RsW/lSgpIpM5Ym9NnWz/Yg2QZUepsY+r2Wwp1Uj
         UYgU1/HXoOxW73KtHfHXq0JkygE3PX1dPYCpN0bIjvwSl44hMeRb44yv57wMnmya82qV
         OUt7JBh/g/15Zy09Pbhrr3Lr/psbGDIohFjXjb/dWHONQInQ9s/CLo6j6DG00l9cAwR5
         55Zavoklmu8H9BHNnAzZxDYuSY46aIDhfNtUQhCPimBVrY794IM1Ir91NxBqOTbKV3g9
         HtzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yr7J+Xgr7VJ/vA58vp4MBVL3mYc6RZ2FHu0I5QjJi4Q=;
        b=o/wcslitQO5EBzJ58Qw7bER4PXJOB6yhnbmSwHFapJCmkT+T0R9O4EH5nBdxoQIKQF
         /g9LKRuzLGPDsmLS4bIVdLhoSJ5zbaXx+AnnAtTBErzHEWOxZSx1AfiTU0CGv3GM/gGU
         F3lGJfMSFz0K+2kBbPvKPbPC2qSDDQBjQ5KYomRXnR986Ji1uExf3W/uN1iy9pmCcrcQ
         4Gc2Ls9JnaOlDgcKJgNi+XysU3nCK4GSJI87pOw6vG0l3CyeWB6lrWKGZLJodm3ZZTse
         wLudKKDKYwuHIhoLID2IC93dkSpa/ArwR4AAsiUpyW0T08Eko0b0HKWA04yE+ciLdkeU
         WX8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315HJvlBIlwgHStMqHbf5xoqw0h+f2hMxLkPZFPHrpHicZ+7SVh
	EC1DWFcBD5XIY59F5Iwkr0Q=
X-Google-Smtp-Source: ABdhPJy2H8hAgCpf69NUHJPfB0b8FGycZKM5zyBSofY6PAczhTssYnYsOwvvjMMc7lbbpTPpGQyiEQ==
X-Received: by 2002:a6b:c997:: with SMTP id z145mr2303718iof.136.1598897888815;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:2c90:: with SMTP id s138ls1222866ios.6.gmail; Mon, 31
 Aug 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a05:6602:2d8e:: with SMTP id k14mr2302932iow.62.1598897888450;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=UxgPyJxiwVWbca+zEU1a4TMhER5dE1G35D4Ox5vcScgAUO73opLFqncck+Eie8y4cB
         Nxit0M1B6pMjhLs57KiGtyc5Qx6KzJCwwoh/5ThLYywOeg8V5PmmNXkceH0rD0Y8K+1r
         1u7aGnbHP42vaQQl7q/LLvCWCVlpGPl5oqDuU9/C6vJeVSZSz3C22UC4MbFwvKZNGkG/
         fF0pwtK4JgRSs8/KNt4fITFoPL8W6+axeszXHUu3tzO1ijWO7WaYuLk3a4OK4Rv1FBR5
         ReAm33ZPLi77vsy4nAtU/Xtzcf8T/Izp/ZtUEzXJ3x8ujY3EjWcQWgAmD46IPPFlXnO1
         //TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=Gt8I1N1Co2s1yWekjwsZk184hmREF9ia7Qr9S4u9BQg=;
        b=nHgErENNmRQxlFmA2166t37n31ahfgli2NflgSpqTSjpNQpk5oFfu0JQaq/ylb9aMS
         ZCHJzH1PW897AJk7XLmAp8IAATramXLLKs4GCy54NqmFyXcv4ohGczTck7o3O1t4HEpZ
         jkCI8FMPyWOT3Y0Ice/6JcJ/j247J/XsgoHQDB5IrVUSfm8T/RmCCQiuwOLPOLFIwZ6Q
         Oo+uaM40xbtRy/ISsankFapXOfONWDhbxUYFTU4T/VbLmN8KaRECVk/cJeNOVvs+HIdb
         2rDue0QXgzlKKsI+WH7u0+pCTOH4ElqQ0dhNxj3FBwsM60Ph/xDIS/ofL8EomqaGV6io
         dmYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=v1BNfe2a;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z7si461763ilm.3.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C020221582;
	Mon, 31 Aug 2020 18:18:07 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 10/19] asm-generic/bitops: Use instrument_read_write() where appropriate
Date: Mon, 31 Aug 2020 11:17:56 -0700
Message-Id: <20200831181805.1833-10-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=v1BNfe2a;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Use the new instrument_read_write() where appropriate.

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/asm-generic/bitops/instrumented-atomic.h     | 6 +++---
 include/asm-generic/bitops/instrumented-lock.h       | 2 +-
 include/asm-generic/bitops/instrumented-non-atomic.h | 6 +++---
 3 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index fb2cb33..81915dc 100644
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
index b9bec46..75ef606 100644
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
index 20f788a..f86234c 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-10-paulmck%40kernel.org.
