Return-Path: <kasan-dev+bncBDV2D5O34IDRBFFBRC6AMGQEZIW6DBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 92F66A0A150
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 07:32:54 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e5740c858besf23206276.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 22:32:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736577173; cv=pass;
        d=google.com; s=arc-20240605;
        b=b8LLbU+dD3nim55zDTUmhWT9cGKRvsZfK13t32N4HM0oOLV7cjq4PTlYoQ5VNxK9/D
         KiUuwDiFxifL1rOMAUL331xP69PsItrsiTDZMuF6fTRWCpmLnZy8h87Bq3QykRo6o3KO
         DZD4CrGWn0SmsURaKsnvqCdtE9MRn4H74DHX6K+ZV6D79q2Y6x/S68v3vnSmEWhAauu3
         TMbWPJ9BH/PWfT6X4s5KZr/mRh6OYQ0D7Od2UwWExNsENSA+FF8ERkdguXnvze2Klsqx
         5sieVodkN/VJdqPcUCIyURUCeDHpIxaLCYZMlZWyOeLJQ7RUEc7n7+h8ABpvjYOjPGFI
         O0Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=exSfvR9M4pncoZJZdw2HB7SWNpVa/K2pCtYS8j6Crgk=;
        fh=E0QDagaEmly+MMaH3EJsjyUhzIMZQyoocjuiwscaP1s=;
        b=dn0IMOE/n9QB6/X+immMXN+z7gxeymkuQNfuL1Tcn+OEVTAx4/N9nXB48W3WQkvRsI
         75fiwbM0ZKmGEzFqMiSUntBtany6SKNZr8zsfUBjheiPKwlFUtDIzCnMn1hXkG68w2Kj
         YP61pGoSYICRjSuOPpH9RSWdPS7COyNtbOvn6BbyPqtglzMGyFFgrwlLFHfy9xxA9jjw
         fMO7LFZhnjH/7x6WCDzQnJg1+EsX+ZMrGMqYFD1/NZ2HXtUmrI2LPgIMmOBZHqPIF6Dz
         Gt2o8P8Eo/Pwb2me02oJFj52Sl5ghoT5WXHJFVyo5v1SDDG3ItW3l6QtYd9BMJWUGqIo
         ANlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=lJzKKNO3;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736577173; x=1737181973; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=exSfvR9M4pncoZJZdw2HB7SWNpVa/K2pCtYS8j6Crgk=;
        b=VYeVd/QHDnF6BFn7rFlRtgLjZkZaSBP4Wd81BzYjd3Bzg8zo5QlpD2BzvUdFnj5a5G
         j4JXvbSf1xqug+me4ZSHH5zZaAJJTni6NRt8Wh+R7T141TnX1EHTq0iSNUc3UVoT3+ec
         Lz78qvJ/rzS/0iemY0uDewpWn1K5KcDVIPHvA1u7C9zWx1ZJB7ITAmpHiEe88eO7nlr2
         +TZvi/gChm+MGOM7jiPXEVuIPxdG+IpUv20Zu25uiuESHXz67tpx2uxlR9URGAHIn+26
         jPySkLxQPOYuMw8qLAE6LMhuYM7NRt/Gz+DT6GgVPsVknt1wtF40PuG6+y49NGkEGwG+
         I3rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736577173; x=1737181973;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=exSfvR9M4pncoZJZdw2HB7SWNpVa/K2pCtYS8j6Crgk=;
        b=GTLFWD4STgKFthkbFUG6AQIxGF+qLLiMF3Y++Fi9JkrqGLiC1UhlZNTwZ1zRuLFlYX
         2amrZCJ8e+nn470M9Ym0x9rcmDar9v5RMQACBZtuzeG0IrxKhDsfjINbTMbC3N949RkD
         M1lT/v4m90QsF9AOYlK4AC8XMXLYG4eJvnyXq+XTwSaXdcpJkaluP3FVbjPPlzBiTfwR
         O1dZVTZlzdVcXwBcKm9RguKwpkGQ6YdDJtiGxEALFCsEfSV8N6KFSM7QdJBc2cR1VFK7
         I+m30q//PUuvCejapT56PDKfdqlzNazytnGDvZrHDKKvnLmv4g+RMsPqcJ7T2BfVQHkP
         v6xw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiC2OllRkRt+Q6Npo/81hfRFry5eBb7iYDN2myJ14YoGRfMXoa9FpG5DMvjMXs6davShx7Zw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8DIiJaOnUOeNvKVkZigX/IozU/LcRq4s2aKTWh7vDwOz6BpKU
	yZwRsZNJXEexBoH+v9d86DysOIdQ03kQwr7fzVfvcghU5ORqSFqw
X-Google-Smtp-Source: AGHT+IFKsdBrXi+0CTFWNfd5Bg9I+KAdxs2vkvatGN2xoHlXOZppYgxPY67Lm+LCG8xn5hczGkNsBg==
X-Received: by 2002:a05:6902:12c9:b0:e57:3a14:a22d with SMTP id 3f1490d57ef6-e573a14a377mr790751276.2.1736577173052;
        Fri, 10 Jan 2025 22:32:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d3c2:0:b0:e48:8566:cded with SMTP id 3f1490d57ef6-e55007e118els2509200276.1.-pod-prod-04-us;
 Fri, 10 Jan 2025 22:32:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCViAcHq6zSwqlGWTi2jfpp5t31vr7oobixUWhmRLcx/JO2MhDPbsQmgQZK6hWlSV4x01/RK0z4De/4=@googlegroups.com
X-Received: by 2002:a05:690c:7402:b0:6e3:37a7:8a98 with SMTP id 00721157ae682-6f531248cb2mr116785667b3.14.1736577172312;
        Fri, 10 Jan 2025 22:32:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736577172; cv=none;
        d=google.com; s=arc-20240605;
        b=NMT/E+mHW9KOv4F2zLocKZTtbqkO4vPI54iiTQe4FdI9mkEI/6+EvvnNKRVDxwcTa7
         Ai/1je0Ma7ZwradZ7XiXiKM0L7VMr+oltN2FDNNv83TyDShBGxxyWynFsbASg8JJ/nYl
         nkRubPkmYDqYSTjy6En0V1CV2/CGSOAmiuUw/CLSxwpjSJSWWDokVBzuRoNef3LU6YFP
         xRWYMc1ghYFqzIVD/CpuBHhfnkCGuZLbXnS0046RXUKMHZJRMjODxYLuFJwEqFx5vPDf
         kpifHXn9xmfF++Fy8iTzKZJS0TPr9G5xXyi0SDbNXtCSWmTxJAjJSIxidqf61fJw86WV
         qekw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=05H5Z13o7TdLJt+1ogERo0k0wR5JRvboTE8J3zcgdyM=;
        fh=KsOcqHfT1GwBV7/jr63og3zjwYDCMB81OQwXx9STgts=;
        b=UgAk+yMVG8i+Y5aTVQUsJvXZycVdRyZ0/hWJoNJEG3XhXJH9o6UHlaUy6ri6uVT8f9
         3DtAJf1GUIhbjP97H9BugsUrqrc+MDP0HWXxfRl7fKhSV3eoR0azP5M7+95mvknbSNWR
         Kks2w2SxAl2U7UVNx4vy7/m5S1F7zIiRjTfHBTZp/xByFeonH/H7mdOLsrne18LKvmdR
         gAnWlX1NDQpKUhN6Z+NfLaCkTM9Pcx9Vp4RFH8Hy0WrGBWGDWOh3SyeBGcENKYg2M0R0
         64PkvOI1RWvteXP55UEsmMyGU/CgjQQ6KrKFMAxYJLkUFHxpGKzgxnBs/aGjGCsDkEJg
         nmSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=lJzKKNO3;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f546d05ce2si1002137b3.2.2025.01.10.22.32.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Jan 2025 22:32:52 -0800 (PST)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.2.24] (helo=bombadil.infradead.org)
	by bombadil.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tWV3C-00000000Hwc-0F1N;
	Sat, 11 Jan 2025 06:32:50 +0000
From: Randy Dunlap <rdunlap@infradead.org>
To: linux-mm@kvack.org
Cc: Randy Dunlap <rdunlap@infradead.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH] kasan: use correct kernel-doc format
Date: Fri, 10 Jan 2025 22:32:49 -0800
Message-ID: <20250111063249.910975-1-rdunlap@infradead.org>
X-Mailer: git-send-email 2.47.1
MIME-Version: 1.0
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=lJzKKNO3;
       spf=none (google.com: rdunlap@infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
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

Use the correct kernel-doc character following function parameters
or struct members (':' instead of '-') to eliminate kernel-doc
warnings.

kasan.h:509: warning: Function parameter or struct member 'addr' not described in 'kasan_poison'
kasan.h:509: warning: Function parameter or struct member 'size' not described in 'kasan_poison'
kasan.h:509: warning: Function parameter or struct member 'value' not described in 'kasan_poison'
kasan.h:509: warning: Function parameter or struct member 'init' not described in 'kasan_poison'
kasan.h:522: warning: Function parameter or struct member 'addr' not described in 'kasan_unpoison'
kasan.h:522: warning: Function parameter or struct member 'size' not described in 'kasan_unpoison'
kasan.h:522: warning: Function parameter or struct member 'init' not described in 'kasan_unpoison'
kasan.h:539: warning: Function parameter or struct member 'address' not described in 'kasan_poison_last_granule'
kasan.h:539: warning: Function parameter or struct member 'size' not described in 'kasan_poison_last_granule'

Signed-off-by: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
---
 mm/kasan/kasan.h |   18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

--- linux-next-20250108.orig/mm/kasan/kasan.h
+++ linux-next-20250108/mm/kasan/kasan.h
@@ -501,18 +501,18 @@ static inline bool kasan_byte_accessible
 
 /**
  * kasan_poison - mark the memory range as inaccessible
- * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size, must be aligned to KASAN_GRANULE_SIZE
- * @value - value that's written to metadata for the range
- * @init - whether to initialize the memory range (only for hardware tag-based)
+ * @addr: range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size: range size, must be aligned to KASAN_GRANULE_SIZE
+ * @value: value that's written to metadata for the range
+ * @init: whether to initialize the memory range (only for hardware tag-based)
  */
 void kasan_poison(const void *addr, size_t size, u8 value, bool init);
 
 /**
  * kasan_unpoison - mark the memory range as accessible
- * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size, can be unaligned
- * @init - whether to initialize the memory range (only for hardware tag-based)
+ * @addr: range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size: range size, can be unaligned
+ * @init: whether to initialize the memory range (only for hardware tag-based)
  *
  * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
  * marking the range.
@@ -530,8 +530,8 @@ bool kasan_byte_accessible(const void *a
 /**
  * kasan_poison_last_granule - mark the last granule of the memory range as
  * inaccessible
- * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size
+ * @address: range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size: range size
  *
  * This function is only available for the generic mode, as it's the only mode
  * that has partially poisoned memory granules.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250111063249.910975-1-rdunlap%40infradead.org.
