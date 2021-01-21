Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDP7UWAAMGQEUS7YQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A7682FEB72
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 14:20:14 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 203sf2191478ybz.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 05:20:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611235213; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYxr0+Al9x/8CFCwlAEQ2oxDBjz7AcBbfbLOilk40EjA2t0Yh+tOG1O23T3bVK+aym
         AFsXl+wdzEh5C4BKUKPvJrWxrB0eNymMuOGhWrEm2vJ82YBhOBUP2uHGNy4G0RDODJ87
         id5vRSR+SJ4vDYZvbArIb3PbxlMKXsG8dxp4JaXtaEqiACEqsd4J/bmoswo35O6x5fUE
         EGqQg6KO9aaeLGiA9YQXHlI8rLcpAy/kQL2DzOxjD8MknyBdX7sEChXeI/np3c7Qaw0J
         rX2HMg431G3k+NAlvaGyGlLk3osyQfaT4p/jpabzav6jTgKmkHtrROFzTR4XwSt6j6+p
         0t+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b7KHTizYzQ2dQU1c55E1AaqvhDDTPd5xwg1K9Af+RWQ=;
        b=HgNlJHoL8TH8PFoV11YTuzrFXDGygz6tkCcu6LPOZJnNYpawpZlV24WaOITiv6J2tQ
         oP9H2auC8SC20BQtNWbTBTOl4E4S11VUi1whzBA78HeaaiFucoh3rZNganXTvKF5A5z0
         rt62tbLuf5oPPRQr2yUVdqJ2HBTA2F9ZrmYwI/50dfcHXwZJhwIrb4Db1ASi3pAnGNUP
         Ef4j7z9f8dKYWV7apXz5oBWPSAUqETzQYQebnO3gSr7oRydzgUVnrOURKdEIGIXVz7yL
         sbiHg0XcYKhbk2M49/lcEy1cM4SprayxI2/Ozj50g+K5pFRPcDple26WeBaCmwd/lUQH
         VieQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b7KHTizYzQ2dQU1c55E1AaqvhDDTPd5xwg1K9Af+RWQ=;
        b=Eh+EMSmCN0gn33VBgbaEJlj0uLn1CwOU18E0++n3lm2JP01mxUQKBgKSNdgFSc3CSn
         UBg31/7Sg09nZR2edAZA4V8PsvVxHl8JhSahWrwMTnxLOlvTF4Xfhmakqh0WNBgTXq5i
         MVZmwAk8RcGY1nzvgA/rljuUz7yoJms4Fe8AEMm6NnaGFkxnBKki7BlokLnSBKQqQH6y
         2VQXpqD0v5WWFLcfzBRBMEbTkOoEq7jyK5MzLO3/HfD8GfhAY0ItO0zyK4ELL2lMA8Uu
         94U6dccuIWE9VfDoMbP3LgVbE7EckiyOUO6uUdSgnqQ7iwD52NaYbUbUxG7DSS/cTnvq
         kr4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b7KHTizYzQ2dQU1c55E1AaqvhDDTPd5xwg1K9Af+RWQ=;
        b=Itt3LT66kbnMihx9nut+L7FxDbJy0k/rNlCsqRuaMhWMin8DzbGq1kThcs+35vl2ib
         R0VOGEAYZ+OM/vtZAs2G5JfbwCM6m+dgwX9Ry1ljvtnD6yLYGqZo1pMfx/jwz19ixi8x
         JXom8i74HxTXwHUavBevTuYPiji+KexYt64dbCnjZRZvL26SoZMa5L6RJKP08IpWcvXn
         jC88AKGFAUdIxiOMeMi3b+WhUZQUmM432tVC9vgaVofVFLIIwRpLd7BNs5SXDpWZNoPY
         ouVtZmxBgjJlWxsMLE2w4Za5EfUYz3onrqon5zbSdYvrcnZT30SuuK72pBy7soz86SZT
         +Yow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532k8PGU0Dl1c+1mK7/60fY90viGgDnesEe+soKCAaXgsXbQh/XF
	OrYXHt74YfZ7PVI3QyUhoVk=
X-Google-Smtp-Source: ABdhPJyH7AhQIf7MBpQvQOqOMAoqWuLgHc9dVs8UHFoq88HU5O1VyRmXinXXmimr1lrJW8cWKKRTYw==
X-Received: by 2002:a25:4296:: with SMTP id p144mr11652668yba.428.1611235213283;
        Thu, 21 Jan 2021 05:20:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:828e:: with SMTP id r14ls1245300ybk.7.gmail; Thu, 21 Jan
 2021 05:20:12 -0800 (PST)
X-Received: by 2002:a25:48c8:: with SMTP id v191mr19798152yba.311.1611235212868;
        Thu, 21 Jan 2021 05:20:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611235212; cv=none;
        d=google.com; s=arc-20160816;
        b=Yk6W+cEfPZankHnO9TNzcRuDeRHKUQi4f1DCg3LGK5h4AUHoVtKMWLDMXikQEecQbc
         Yciv9pM/UZoUWrI6HKC8hq1f1DWrTPFVIhohLK4dQj7ZXW+amWxdFpTiL4H06Xb5nsLq
         seT1cdRuyyX0ULDcgn+tDjM8oWy8gcrrfLoHrSrhouIgb6IfYpnFwSkCLGq/b1e54qr1
         HudfVTF5JqZJSlR65nWz8N2ntvEYQs/xp7hEletOzl9gmerrdPnGTEP1xi9iOsiMTPTO
         FTpfiFgoMCrcYeR41OSxC5dhlGwfj5XT0muboc25H4lmWVZ/oNAIaZpubSo1bJQST9LY
         d5VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=BhPXKmOD1KHe5U8Jyt2HCrxoIIzr0Wm67hTkulsknVE=;
        b=zAziehnQJ+YJXIuUrxtGjDEX1bA0UXjVIJDnLCz6vYyPBWmQZJsXwdnh6yJDbK35yI
         q2Vgdd1ZbjHbKISd6uSqJlcVBMNvQqYse0RoR1D9SRVYo9nz1HwSeuGtA7N64PTOPWsE
         lwBwlVljAqCmxIAy5ZP8QEwV8ztUtwUgrtDoP3UOiMv+4I4ayv7rPK0FyMyGzK1vEmWi
         eCawH2bMFKUU/7Waqh5oyQ3qF+mnZ1y8N/hPzTLKngwJKERbnk9S3KshN74w5pMeUfF+
         /YOYJvzRIqO1swDfWC8MzetgCA0davvf1CVY8cQG2RJvdS1XHPR/odQWFu5jlwBTXyYM
         Cy5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l15si406366ybf.1.2021.01.21.05.20.12
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 05:20:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 87CD0139F;
	Thu, 21 Jan 2021 05:20:12 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1E33A3F68F;
	Thu, 21 Jan 2021 05:20:11 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH v2 2/2] kasan: Add explicit preconditions to kasan_report()
Date: Thu, 21 Jan 2021 13:19:56 +0000
Message-Id: <20210121131956.23246-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121131956.23246-1-vincenzo.frascino@arm.com>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
the address passed as a parameter.

Add a comment to make sure that the preconditions to the function are
explicitly clarified.

Note: An invalid address (e.g. NULL) passed to the function when,
KASAN_HW_TAGS is enabled, leads to a kernel panic.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/kasan.h  | 2 +-
 mm/kasan/report.c | 7 +++++++
 2 files changed, 8 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..8c706e7652f2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 
 static inline bool addr_has_metadata(const void *addr)
 {
-	return true;
+	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index c0fb21797550..8b690091cb37 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -403,6 +403,13 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	end_report(&flags);
 }
 
+/**
+ * kasan_report - report kasan fault details
+ * @addr: valid address of the allocation where the tag fault was detected
+ * @size: size of the allocation where the tag fault was detected
+ * @is_write: the instruction that caused the fault was a read or write?
+ * @ip: pointer to the instruction that cause the fault
+ */
 bool kasan_report(unsigned long addr, size_t size, bool is_write,
 			unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121131956.23246-3-vincenzo.frascino%40arm.com.
