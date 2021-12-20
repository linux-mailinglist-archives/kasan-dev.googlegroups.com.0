Return-Path: <kasan-dev+bncBAABB6HZQOHAMGQEDEGD7CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DF0C47B58B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:25 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf229757wms.4
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037625; cv=pass;
        d=google.com; s=arc-20160816;
        b=LGjOoxjykKC2Se7B84EyllT3xCiF84ZeBHVbu7uDj9ldwWx/nj6ueT6ojnuPyl/l2B
         n46Cvdun3qCxx0p9Spe0KJVt3WNw+uOjgf13VYXgUAt2mXwtG3lvokTLoh4wxIvubHbn
         U6MLtMOthwpNgJgIkjrq1Ob3sTd+qSUGaVDmTCpjjtjdI72gBWzX41maJXaFf7TRbaah
         1ok+1OhGfuPgEEiuI/SYK/74B1tLiboTtEKtZtIMBaJcs5VRniuyEosoyVogGEIl1a+m
         xMJsdQFUuda8cx6+noBdWd0jWLBRToeoNS/btzID761gMSpkMGIRQeZg8sLgg9RaCH69
         KqSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uTVk4eCmpqlKmGT9esz6uKDMGPmFaSQ3Ph1wuN1YmlM=;
        b=uv4siRNwuCS1G57Z6EdHTo89tsHxh03u+mGJVSozL54e9C8S5WcQzvrdu1O3eMmfIa
         r6IxIOU5E44j1iEkbIOB3HdALDzeUW1UBYa3XNdFob/WmUH3n72JaZDDcYCEic/UtpAJ
         89w6U1D2lks8TPbUFCatxT360VLI5rPf/hHPKgj6i/wWIM5rqKhkm+FNGVlexdBMACdv
         r8MczYzg8EQDl7O5z1+LKGGcL43Am39oZb9YoIYKCMP5O8AmaNRn4BGRYguWPxuUT/JV
         dqUAFwLl1eR6TAgig+84qMFSMtMacOoHMZodzf/tV7f2mjDY8hlXA5raXf93uVndj4k/
         CdLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ipyTmvbV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uTVk4eCmpqlKmGT9esz6uKDMGPmFaSQ3Ph1wuN1YmlM=;
        b=UmYfNaR+P+l3YSeE11LHvDV5RoEvc1qTeo2y9hZmH8RQ/SDcz9qBuHIR//F7M+KOQO
         lDq3Etig+sUzX4CENXsTKv+WwzKP6Z6Bn0IUoeyVc5gtfxPZFE7OQ/aI7BIb6JN/L/2u
         dzAk3v36XeiYUZRkjQJNWhegr6UD69b+NT3BAThOmTWJqykaIQdTT7IsbgKF3W12Cw85
         GydVNeluTZQiOfiw8r8UehYjvxOhqpAo5wickMOXyrWS8/jVPu8rym5pM4uLoBsG6Sz5
         I7xIv2xaLUl1oFXaCjdkGefHprp6GKMCJ+oMp3L4DiPDev4DHZTbCAUgoKwepceh9+Qk
         U/EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uTVk4eCmpqlKmGT9esz6uKDMGPmFaSQ3Ph1wuN1YmlM=;
        b=xZHnZk2/LGR8yTGWd23adtsBRzbQeT5qDA3ghv535PYti3aT+IzSyZmqX5f8KH7rvi
         XHPGHhqqEgnCMQlzFzDnNdulL4jwVz7in0QsxYy+/4xAT8XoEoy7Ug3x3Daj4F6YmUgf
         ZY7RZ6//MhxcCDZacPlPwlNcqx4XWzapmKd/lz+nV6EEmdAt4fiTgsxWpCIOn1QqACJa
         /S+4MhZ3svRMTtlrdJweiY2cGJa4TWe9/Ubs/H7/oSdjAXFG9ap5d3wW35kDX36YVqp6
         DAZB+b7+sxJOJA/UFfm4zd4ykxYifaM0G50J3/wH2SNvbumyoVJVSebcrBlLPwgbFAQE
         BYLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531emYYhHyZCOv1xWPUbiFienXRerJTMvgnkqLgBGvW5Igt/kReo
	ZqShRvPRtkpIIoBBUbsbuNM=
X-Google-Smtp-Source: ABdhPJwUEE9rypPqzv1mOPAZ1/Xal3SXNCbW2wyTz5jJUBGZNIARpIGvXUY21O8I6EeKWMydgvPMpQ==
X-Received: by 2002:a05:6000:2c6:: with SMTP id o6mr113361wry.286.1640037624837;
        Mon, 20 Dec 2021 14:00:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1067981wrb.2.gmail; Mon, 20 Dec
 2021 14:00:24 -0800 (PST)
X-Received: by 2002:adf:ce84:: with SMTP id r4mr99533wrn.131.1640037624268;
        Mon, 20 Dec 2021 14:00:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037624; cv=none;
        d=google.com; s=arc-20160816;
        b=AsnRuiGKQyzh2Ga/pENmMOrOWfieEA3exi0Q/k2OJaa/35mTYB5Dw+Qt9IfiMIX7LF
         BB0IaiD8LW3VTqTfDzWWvGnQuHgSS2cUL7dGQouCB5znaIdJPwn2IU0v9wTClRdUFzti
         RN/X/mylmCCnWSWIRosAViBmEGiEqlQlZxZ8zwDdaMXbZOWYp40T4Sj2fb15bPFeJvi7
         YrJTn3pG//LJsPL0sgxJRdN/dyViK9OOvWS173HRx9LE3x76tGHIHngKLCjGW4ZwILQN
         w1f+qugNQW11xgEj0tS+sPUsAB1Ok51WN//ES6VauxYBo7XOYOPvtmsqBDiaikO1y3+w
         NMnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ei8kdZ5sQSvooSj5JSSxP/TjdwvJrbBJ/NUBpnrkl04=;
        b=RuAvwbT7IbTnDrb+ezcmqaY7A7vtAfsMPDAg76mMkgsG3YhGZLmTygt4pYsVKzUIOb
         OGjApBqFM3VCL2UaDCoCFZmQg6TVEjKLsbg/RAomluSBl7enCQIavP8SKNpFfW6ZRsFV
         7wKKRvH7f4pPTcbbvgvHuVrmZ+l1bw4GE1N5OJ1HE4im8vKhUEwg+28Iz7jcBeDfpS8h
         YpAXXBtG+Rc/J9LKCatJ/RE1n9YWnrv5U3r1CW4V8X4ipl/3wT8n1kzp4glmoThoz8Wf
         Z5lpQYAOfAdCVYqDR6Sl0F85rMj7+26IAogHK/qk0WAqYL+JKVp1v44qwczOLv8//3H+
         bAwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ipyTmvbV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id i12si34484wml.2.2021.12.20.14.00.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 20/39] kasan: add wrappers for vmalloc hooks
Date: Mon, 20 Dec 2021 22:59:35 +0100
Message-Id: <f69174e2f6196fb502afa5785612e3a30e6a71c7.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ipyTmvbV;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add wrappers around functions that [un]poison memory for vmalloc
allocations. These functions will be used by HW_TAGS KASAN and
therefore need to be disabled when kasan=off command line argument
is provided.

This patch does no functional changes for software KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 +++++++++++++++--
 mm/kasan/shadow.c     |  5 ++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 46a63374c86f..da320069e7cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,8 +424,21 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_unpoison_vmalloc(const void *start,
+						   unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmalloc(start, size);
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_poison_vmalloc(const void *start,
+						 unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_poison_vmalloc(start, size);
+}
 
 #else /* CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index bf7ab62fbfb9..39d0b32ebf70 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
@@ -488,7 +487,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f69174e2f6196fb502afa5785612e3a30e6a71c7.1640036051.git.andreyknvl%40google.com.
