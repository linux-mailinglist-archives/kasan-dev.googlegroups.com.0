Return-Path: <kasan-dev+bncBAABBJF372IAMGQE3O7CN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id F27DC4CAA8B
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:39:00 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id bg23-20020a05651c0b9700b00247b65e75bcsf368871ljb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:39:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239140; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yysmazr9byrduJoMR2TWdDonUyQQ2OcgPoxGj92LKmlpEWKfSKb+e9qQRFyujR5aP8
         SwCMVefsahlAHuiVTh66Tw3rw/+/nS3c5cTFaqXCKjnxAEhEAQy2or8PkkO6CAfAEqQj
         oNOrHMjmPFU6fEjpWFLfeNZqBg7EJrfVHhXjLtQm2OhT6PbphJ4XXMIC72WQ0DcyCdgy
         MNgRitAp8LxXqr/b3D5Fn06xPdbYW6Y9S4WqQOTlPXdG3QCTg1UwqeB0mwxUSrj65wkW
         F+OVK/bPBIk8cjQ7WvFE11U7NRddNLDIujwBSu3otAR18pDPKa7qdL0GrIV0Sc05gn+b
         hjBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tPxxSXJmS1pCFJnCNg+k92ftgl8iS4npcOSa/Dt/6JA=;
        b=XmKPkHw3E+fl8eCu0VrsAKr/5SLRNUq/681HSNVmoXM7L6rdpLovSAnzqAx/B26JDj
         lxvtE11K2ry1V/ysFBA/Fw1qnRkEbPVQyKEkqoc6nTClii49Iz5yJWzr8fnhSHr2OCs1
         gNhc+0myyxtOn/Dekgpl7yeUQY4H1YYP9yZ32h5umtk8AJqudF6eNwfSC4XeBFbKd1K/
         wRTJafm2j7tMAOhidl6jm3Rzxl5jzasj1Pb0mmrHHpBFFAZBWoaPc+WxxF6iFA2SRAx7
         qbItLOX+3aKFMeScm3fPSE8xlg9oPKnRqsFe484KuN/R8KowE33zBqiIHkemAJDoi+zy
         LKIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bWJzl9fx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tPxxSXJmS1pCFJnCNg+k92ftgl8iS4npcOSa/Dt/6JA=;
        b=d8QU0fN8Ae1UnI6KuXGro7eRbN4kNgF6oGqwOi7BhPDMaAQYjSyQdK4DQeyxyBEms5
         KrUfRWfCUd1PF7dKVrXArBRaqM8NhGjzTCK9nJ1+ax57Ggfgc+5+ki6fSYq7BxT+itda
         iueXT2k/8PaAvKymhVe8FOI+JZcbcW8zr9cV7BUntS8sCFQvm5JWXsc/oMh0cgJvcf25
         KzHoCJOH8iS4dOzwhOPf6oYU4YtKSAoqdFL2w6h9CS7zvtPM6Mzppf7+fXb2mvlfUPZx
         BqQOdFFitaXjFYRTPLeWthmLZEffxLws62U8YTdnPUXnH8E9pTNMKK6nGZVJFrJun5B6
         nsbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tPxxSXJmS1pCFJnCNg+k92ftgl8iS4npcOSa/Dt/6JA=;
        b=a6VvEXcmPZgZ994UTz7lRqFOk3EaQJ008YU6UbaYBA/R0X+FHkz8NTCHUUTem/mzjx
         e0aMv4oQWtcEFTV3B5W+Pu4iWmIEHg7hperO3EA2tLGPXC1Rfw5sxKRByw7f+wdWkSZt
         JooXu8I1QcWgIFVefGN06HFXfidOtnBFm5Lz2MPkJ7Dp5mkY9ib+KVgUtrHy0Qv+t3P+
         L2Xjfwu8YaXArG14xYWSjO5Glgo3alyJXpJ4k0A8HpDn9tDSRVDp/hTecajx4XlmosPI
         c/FYx4Lby1biQjYLchdgZvUH75FJYHUXG97PHbDKLRgVa7iDfTJvawrS00/4azG5xAOe
         nMLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308D23AQ0zOh2jX5tUE7RSQF8m1Q0kMO9lHa5hoCEgP4tV61e3c
	7W3DqFYSZKwvPEdgrN3wGFE=
X-Google-Smtp-Source: ABdhPJx6xAH0hW9ATAZxBqjbiefu+b6ezulWHG7vmO8W8s0jIeIMI2AOF33yNN52mbLSEcCYuS7zdA==
X-Received: by 2002:a05:651c:17a6:b0:245:f359:4464 with SMTP id bn38-20020a05651c17a600b00245f3594464mr20598663ljb.478.1646239140562;
        Wed, 02 Mar 2022 08:39:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211b:b0:246:3700:8bf with SMTP id
 a27-20020a05651c211b00b00246370008bfls3651662ljq.9.gmail; Wed, 02 Mar 2022
 08:38:59 -0800 (PST)
X-Received: by 2002:a2e:3a17:0:b0:246:387c:46ab with SMTP id h23-20020a2e3a17000000b00246387c46abmr20720526lja.77.1646239139620;
        Wed, 02 Mar 2022 08:38:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239139; cv=none;
        d=google.com; s=arc-20160816;
        b=ufPJCP4m2cymRkGXCZSFcvhf5R8Pq0vAg5itBvbQjbMLGztjRdcg71I7xIYrGKiHTv
         HlR8VemIU5IzlN+NUBwFS/JiN+GKzk8MolbelnmSpEP8lfbraG9rBeBCKf0A0G9YO9Xn
         n+eVIjYiEqJIg1cSXE+ysznH4UGGlDg8/Yj3kF6mbV+px344+3grfPtfeyHhdHBlLuOZ
         8c9xVTesFlc5I8I0VUMRpzFYM/6WK9d2cVmETQ2QPN9jtpQah2W1Fewg+fSf7lYvFqXc
         HgSENQMpqEBiiAUbPhHhrCyxFEHuYK/RfxF/efCIccjhe5NeQErcCRK266Q7KCQL7T5L
         cINA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QsCdzSP/k33pOndnGnQGapEj7FynIvIpYn3S3i9tIEc=;
        b=PyzosJsI7sxC9FtYBF3FOHdmuJ5VHaKg94lzqMS9VE4o32/QxIbiPH51G3WarpLGee
         qNz110hUN6NqjA14qoQqYOSzhRO91KDpOgEwxQQK+QdijNhaGpioVEhiBEf6OQyDjACh
         fx8Ske0UvpGpuSu6gidkZap9SLSfculci447Jrh8tPbg1Gnbiywg28cP8dBWm7doD4EV
         uOgejCTJ/Goq440dgrrXNz4LHi3m29dj0i9jQM+ap1e7X6yNsIfVCGQYCAPm67hj9bcw
         rCQKjHo+NJFVNQhZ7JjjboKBaYVmh2f0OmnA8NZkbUtoVlJ+dPJvcQ/gUoQkFj71ulsG
         J74Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bWJzl9fx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id w24-20020a2e9598000000b002463b72fb7esi1065769ljh.5.2022.03.02.08.38.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:38:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 15/22] kasan: call print_report from kasan_report_invalid_free
Date: Wed,  2 Mar 2022 17:36:35 +0100
Message-Id: <9ea6f0604c5d2e1fb28d93dc6c44232c1f8017fe.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bWJzl9fx;       spf=pass
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

Call print_report() in kasan_report_invalid_free() instead of calling
printing functions directly. Compared to the existing implementation
of kasan_report_invalid_free(), print_report() makes sure that the
buggy address has metadata before printing it.

The change requires adding a report type field into kasan_access_info
and using it accordingly.

kasan_report_async() is left as is, as using print_report() will only
complicate the code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  6 ++++++
 mm/kasan/report.c | 42 ++++++++++++++++++++++++++----------------
 2 files changed, 32 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 40b863e289ec..8c9a855152c2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -127,7 +127,13 @@ static inline bool kasan_sync_fault_possible(void)
 #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
 #define META_ROWS_AROUND_ADDR 2
 
+enum kasan_report_type {
+	KASAN_REPORT_ACCESS,
+	KASAN_REPORT_INVALID_FREE,
+};
+
 struct kasan_access_info {
+	enum kasan_report_type type;
 	void *access_addr;
 	void *first_bad_addr;
 	size_t access_size;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 56d5ba235542..73348f83b813 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -86,6 +86,12 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
 
 static void print_error_description(struct kasan_access_info *info)
 {
+	if (info->type == KASAN_REPORT_INVALID_FREE) {
+		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
+		       (void *)info->ip);
+		return;
+	}
+
 	pr_err("BUG: KASAN: %s in %pS\n",
 		kasan_get_bug_type(info), (void *)info->ip);
 	if (info->access_size)
@@ -386,22 +392,6 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
-void kasan_report_invalid_free(void *object, unsigned long ip)
-{
-	unsigned long flags;
-	u8 tag = get_tag(object);
-
-	object = kasan_reset_tag(object);
-
-	start_report(&flags, true);
-	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
-	kasan_print_tags(tag, object);
-	pr_err("\n");
-	print_address_description(object, tag);
-	print_memory_metadata(object);
-	end_report(&flags, object);
-}
-
 #ifdef CONFIG_KASAN_HW_TAGS
 void kasan_report_async(void)
 {
@@ -435,6 +425,25 @@ static void print_report(struct kasan_access_info *info)
 	}
 }
 
+void kasan_report_invalid_free(void *ptr, unsigned long ip)
+{
+	unsigned long flags;
+	struct kasan_access_info info;
+
+	start_report(&flags, true);
+
+	info.type = KASAN_REPORT_INVALID_FREE;
+	info.access_addr = ptr;
+	info.first_bad_addr = kasan_reset_tag(ptr);
+	info.access_size = 0;
+	info.is_write = false;
+	info.ip = ip;
+
+	print_report(&info);
+
+	end_report(&flags, ptr);
+}
+
 bool kasan_report(unsigned long addr, size_t size, bool is_write,
 			unsigned long ip)
 {
@@ -451,6 +460,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	start_report(&irq_flags, true);
 
+	info.type = KASAN_REPORT_ACCESS;
 	info.access_addr = ptr;
 	info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
 	info.access_size = size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9ea6f0604c5d2e1fb28d93dc6c44232c1f8017fe.1646237226.git.andreyknvl%40google.com.
