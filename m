Return-Path: <kasan-dev+bncBAABBOP3QOHAMGQENUTLIYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A3C547B5B6
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:03:37 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id l14-20020aa7cace000000b003f7f8e1cbbdsf8661231edt.20
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:03:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037817; cv=pass;
        d=google.com; s=arc-20160816;
        b=vUlXQhjy+c5eGKFJza762a6X+fLP48dTgOzH5Hyes7hAHPXO9Ac/YFr+Tn9h3A8H4g
         dfGER43SDxBh4odLlsgwb6R95YT4WJl6H8KlsykDUlcvt0BSdKLlfnXNonulWzXdnJzh
         H9qWcmGHv/g6MwyXBpZ9izhYaBLM5v2gyyhgh+rprjaW3fGnS0lkmzmJq9HlSNHmNkTp
         2XIQTrUQsn2Fg5dcGyFYSjrkNih+sMXxMHQZ4lRUgQq9hDirBwli0H39ymmo4U/a2IN3
         37+ubiXgR8Q8eld9bJWat7BiNACRtZQps8iU2z6lM7qbB7GTQ217/mfG3Cr4lKxYI+Ou
         AR7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GmITFIAmwG9QZfVMrDu15vxduJly0vnCRUN3qcPBfqA=;
        b=cmG23i46aJ+56jfgTURvuM1Ms2X1DHdpYww8zxmU+aYMeHxhWXZoP1PflsUF0plIqR
         WxBt1x51wB3qLfMECnhPS//cCyIetyhMIQ0G0+4e8E6HD/D2kgNykoqZjGKLIwgVYoN7
         a5oKI4HW9/o2QlVfKHBkzi+KmvwB7nT1E46M6MXaczsksvKDojY+3G5AUdUn3BBFjK7D
         +hW3ee2E0m35HvpqOzEO9BxbRxuZvOJsGHWCp2u54qW65S53IVcps82x280Gvb1q1zH4
         rWYIiU5dRU/TyE0F/afkuMI/VT9FmEWZzD9NrS3C5YMDvZWJvmYqz9svbfwoeMG5qVD6
         v0Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bj5IzRHJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GmITFIAmwG9QZfVMrDu15vxduJly0vnCRUN3qcPBfqA=;
        b=lsgGzT9OaRLxxDyen3uQW/1jm5wJg+RwrxgYmbRIhMYH00ejHuhWI0BDdt/ODlog7z
         ArVVGfu8LOKO2p03GWtApcCejwD5SJ2SUf73agtm2G7bgUypqaNPZDrDNEkjlpuYzG0F
         yWcvG2g01r/YC18z7tqWb/GruaXianFUsiZpzRASUzknRjzgAqVdttDYteNvbDl4dZ8j
         DWHJtbRiMy3gMWqsIk21JOW+pqSeiH9iQDqzDn6GA8V/RxcogzclcGSU5nZWB9fU0PZ6
         ozwIFaTVuFEH4dwP7wptYo/jc6hzMxkl76WEl8ycC11UQZBpUMFMJ5ir4E6Y4FdFMf9q
         0wDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GmITFIAmwG9QZfVMrDu15vxduJly0vnCRUN3qcPBfqA=;
        b=asF113DCvpuSfvvq69BVh+HrcAt1/gAv2YSGeZBIcIUCH0oMiCvCSb8FkxeHAyM/Ip
         mlwCR8ZTitQI74weOgly2TZkyRbZKWsOkQS3e1lgyLgRkDIie88f+pfUi8cF8PjS6+nh
         UnagsWnmqpJLx0tIIbRaPOUkqX8YemKrNOIxNxw4eW7oh6LPYKbUhgM8TTIY3K9zPbyA
         P9oZluQDG4NUbQZBHyOH5fe6chAPEJ1BwyLxdZW0pI0IGAuwENq9N9pWfTSlIiChnZF4
         G/FLxhYCg7oOodsRhxMvlEW0YgX1AiS6RYAamx3PFlpgpoaa+IQda4PvPE0YJ5l1wTmX
         6NJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cfteaCIyY0fUJTF1WOAjMB+2H9L/4TSzsaPDxD3qjZziKtREX
	154Q23FVUJ33pKKXmWf8l9w=
X-Google-Smtp-Source: ABdhPJxl6K2UFPl+Qip0OwCySv3N3i33pIR16LVaW8mJ8h0lUuefU3CPoBXWo1sTVT4EpqDzcFg1Jg==
X-Received: by 2002:a05:6402:5106:: with SMTP id m6mr137018edd.191.1640037817211;
        Mon, 20 Dec 2021 14:03:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40cf:: with SMTP id z15ls926137edb.2.gmail; Mon, 20
 Dec 2021 14:03:36 -0800 (PST)
X-Received: by 2002:a05:6402:40d3:: with SMTP id z19mr138030edb.185.1640037816519;
        Mon, 20 Dec 2021 14:03:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037816; cv=none;
        d=google.com; s=arc-20160816;
        b=cB+Z2/8fDvuXNyrMHfku/G4+j0DEmJL10EgFr9cWrACMa+4ECZ2tzp+1uOL/aK5tpg
         1phc5bLpCNMfIiq5TDU4Er1h5ipkU7ThU2YdKFfQgEp4Cr7BtKPYEFOH9UMkSUkRcrL+
         sq2XvmZxnCWlLWhg64CGrsCb3jmLWei7zHVPVt/detSVirpfz9l4UBey3VE9+zpkPOOG
         ui++H9923YUVri8IYoafn59BWcgj/WHd9DWLZvBJxFv97nFroplPLLR7tt2AdUnI+ecM
         /hZpHwTTGtDnqGPKtKP58c/HExBf4aBPVUG6eXk35GdWrcQZninwEPCFznx9aOK6x4W+
         a+Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XC1+Aytkcqzf1ileaTyJqJ/4yyuLy4mtp9hx3Zvq9co=;
        b=zZxj8fxR48/SzPqgRUFvZ0ePvxnzVs2d7dZ7VREu8o3AdKBARBS1qKJxTBvRTN9AoI
         MIC0TnKIuWJbDS9wL9aCHOj+UCl/nsCnUmhU8HwXIwTNWdjz85pYNsdF3RM6aXRtSpkB
         B+NFOToTwvR/AUM7lJusytiijNqi9/IGfTsyJbQX3DJEi7p4yrrBo4qYh2SAfB5g7bu6
         lZ4Cb08mg6WYElP3DOPwix1lERhjUklGpRsWO4kQhIQKGiAylPpsThPA4ALlSiTWklfR
         7QOeIjdLXvrxaQoiHOAei3V7JDs6u1iTtQJdHvHvlWT0bHwTOltvugy4hqbF8k28DUNp
         rOFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bj5IzRHJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id dk14si1184295edb.4.2021.12.20.14.03.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:03:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 36/39] kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
Date: Mon, 20 Dec 2021 23:03:30 +0100
Message-Id: <d391829df65888170df24e4577f7f0211db808c7.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bj5IzRHJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Allow enabling CONFIG_KASAN_VMALLOC with SW_TAGS and HW_TAGS KASAN
modes.

Also adjust CONFIG_KASAN_VMALLOC description:

- Mention HW_TAGS support.
- Remove unneeded internal details: they have no place in Kconfig
  description and are already explained in the documentation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 20 ++++++++++----------
 1 file changed, 10 insertions(+), 10 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 879757b6dd14..1f3e620188a2 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -178,17 +178,17 @@ config KASAN_TAGS_IDENTIFY
 	  memory consumption.
 
 config KASAN_VMALLOC
-	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d391829df65888170df24e4577f7f0211db808c7.1640036051.git.andreyknvl%40google.com.
