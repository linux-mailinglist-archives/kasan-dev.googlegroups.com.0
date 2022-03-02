Return-Path: <kasan-dev+bncBAABBJN372IAMGQEHR6Y2PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BD684CAA8D
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:39:02 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id a5-20020a2eb545000000b002462b5eddb3sf662207ljn.14
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239141; cv=pass;
        d=google.com; s=arc-20160816;
        b=gwzsDguQL7q9lk8ApsNhDi+PKqfVaA+5pluBsH4Mo3PxxSgQ9QLiKNZmv5DaW1Twha
         zYiHq4tPbOC4LnAXJSLOABXbqqCSySakQM+QL0IkJjwxXXSW0zeytU07aCGvhgmuwEQS
         T1nb4gU7bHJLCB6HaH1TShNbnj8DwFq0Xq873M89YRwM4NtlNQ50fV6PulG1NUd2l9qY
         3EnuE3PJ/9aZBvQt5pr0y0XPfacdr6RDcI5ewz2Q3e3wvc1YjbMV67FwFeaKUKG672HT
         Z2cn3dH9HPVLBr9xlrBP0BstKesMjlOxkfPWEpU8uQCQNZiclhXCtaTDkzC6CxEqm8yO
         e/AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yhTq9FVvQyTb+jg8swYrO6gcLS+/Yes04OX1G2GYvoE=;
        b=PrI95Gz6dDb08XJqbx6+x4h8nao1ZbKHxC8XgwUfAN9szZ+zQ6WEUpLJK/r2NbhLOm
         sSSqDFzCV6ZvrNs/VNspceCI9GkE5Pf1lG0+3QG3HoE9T79cbILoK1QmoBksLQ7DaJLC
         W0rtAJwZMCzTdrHd1GUFrlsnds1DCWzLxM7s9xrEzSsFAn/YIgDZzFxELVyQyrZZ703l
         8yKr/Vmh7SRPLgr+ksMrdrw/4DJjZgyOIec4EvxD7Tuddr7lHs3hNGYAhwvP2MHzEISu
         z971epgowpOq901CdRWC4r27t/pWdE1BJLrdm2hZJu+IShPY8/LpPYN7myS0kpqW4xvZ
         z5qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=G2aWvWA0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yhTq9FVvQyTb+jg8swYrO6gcLS+/Yes04OX1G2GYvoE=;
        b=qRaK2VqB/hsbfw2hYCV+i3LmlmNR4TZXTR1FCeJmYR6bpnLKmOrlCKfic/OO8Af7JH
         /+wW0uf05Q94+hZIbthhY+hvtqqn/sAAA8n3ZLQb1EbD1FzADEanuK1OyOZvGudmc8m3
         mlQ3EFo0L5SRm7br/sqgwwXcCH65FBvgecQ0gOZfG6wQfIfFGFT2lm24Cm4N4MwiVFv9
         odHNhPR26AqPZFMbtk38PJ8sBeR1T9czNxA8JER0zKdu0/2J7e5SLBMYSeRwTSQcBrlf
         IgzDmi2GsBcM0c2yTlh07IZ+XaqTS3kYnLM08fqOhfNEqlWJnGIlAF+3bgIz99ss8myH
         yr1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yhTq9FVvQyTb+jg8swYrO6gcLS+/Yes04OX1G2GYvoE=;
        b=z8WURE6kzTZNA83D7ZKAryZz5frV4M2fYsSpsCccDdUs+brYjweBTmdj+HoVw4VKSQ
         Un2ujcKZeTTJg0am6h5GJTNs5AAVU4RINapAo5TxgqK2LksCzef2efCpYV10+enp41GS
         3SvJx6jEIDWMSrVt13DTZHa2X56QuROHgBmwrZbou2C4XcZG8OMb0OY1itbgrh+ynlED
         PssWq+P9+SeVWLtjBTMDEDFqGHhpPSWt9bJpoqjch/YxYmh4PFrtDxLSFBOXa42jlJ9Y
         8r1BgwLKCF1XZK4amrZqP/kZcDg4biIvsGxjJXpVmEyrJCTNYkWxuSRKa9JMy4enU1rQ
         x+3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HwXN77JSdW9HmVuUUvfAbVDFWbzlDQYE2Ml60IzF/niwGR2+C
	zoO4w/AhikwNMgk2u79uQ10=
X-Google-Smtp-Source: ABdhPJyvVF6CN85POpYhvRvCp2YwdiopE3gAY7Ahx1OD7T7n14/idgho2xxIADYmB3nJuVjmK9Qq+Q==
X-Received: by 2002:a05:6512:1193:b0:443:3bb8:d982 with SMTP id g19-20020a056512119300b004433bb8d982mr18796961lfr.61.1646239141744;
        Wed, 02 Mar 2022 08:39:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8d6:0:b0:247:b65e:7618 with SMTP id s22-20020a2eb8d6000000b00247b65e7618ls213954ljp.5.gmail;
 Wed, 02 Mar 2022 08:39:00 -0800 (PST)
X-Received: by 2002:a2e:b80f:0:b0:244:bd38:c4b3 with SMTP id u15-20020a2eb80f000000b00244bd38c4b3mr18164346ljo.207.1646239140890;
        Wed, 02 Mar 2022 08:39:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239140; cv=none;
        d=google.com; s=arc-20160816;
        b=NJD9UZIGfMQqWVeKbZGMISZLXzrOr0NGWz0OYQqqknWN7jf0eDwS1FhXJNDtWnaAEq
         ipGuO4PpA0Q5iNA0wMde1KfkQP6Dpp8woN+zKGEXo4YExvV4dd6gWhDfSrraUJGcyk78
         /NMpu+ogfs2cp4T+ACyScXSslnFpFaqrxtmfF/c2I8QdhuY63lvlZMYrNi0swenUeHa9
         86SMLDWazMH2J0AsebYrajHs8+t5XW8XocuJBzPRpUzTf9cc/fmeUq1/Mtnkkm0RZCQ0
         obJNpvmZzjX6E09rdEs3628t6aJRZVkr3dyLtTLcHS3JJqbVEJyGEGCeDLpwgjaa7/nO
         ORdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/qOrM9Ost/e3M5mYf3qg7gFNISCBGPyiXg0v046DQbk=;
        b=DhCX//W2rk+uO1259W/56oQL1W1fEuOIdllfNQ18wbsj864AgiM32T+JBXNDlW/p59
         jtWJ1w2N6FQ4+adnd5FBNF5MoktkHUk1oZCD2vRpWhgZcYR8iw8f2OeLurJZUHKlN58b
         ztaQ8SC5c6sgpiZCdawSvrK28H1bv29JOV4YhHBHhWSeFUei7nFgJN4hG+h2Qe4M9i6e
         NEyGapXjdo1fZ0iK11fmx+YYtStp57YFUIW26pCmLOM9X2uMa7ljQLZXXnM9ss8Yimi0
         uMLkYaWM2cpxFu0g78VpBwoAPw53BdFxKFaAP4TSujYIKkihZBc5tUiKCzOuwnfey1wF
         p28Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=G2aWvWA0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id s2-20020a2e81c2000000b002462ab45e78si1030609ljg.4.2022.03.02.08.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:39:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm 17/22] kasan: rename kasan_access_info to kasan_report_info
Date: Wed,  2 Mar 2022 17:36:37 +0100
Message-Id: <158a4219a5d356901d017352558c989533a0782c.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=G2aWvWA0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Rename kasan_access_info to kasan_report_info, as the latter name better
reflects the struct's purpose.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h          | 4 ++--
 mm/kasan/report.c         | 8 ++++----
 mm/kasan/report_generic.c | 6 +++---
 mm/kasan/report_tags.c    | 2 +-
 4 files changed, 10 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8c9a855152c2..9d2e128eb623 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -132,7 +132,7 @@ enum kasan_report_type {
 	KASAN_REPORT_INVALID_FREE,
 };
 
-struct kasan_access_info {
+struct kasan_report_info {
 	enum kasan_report_type type;
 	void *access_addr;
 	void *first_bad_addr;
@@ -276,7 +276,7 @@ static inline void kasan_print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
 void *kasan_find_first_bad_addr(void *addr, size_t size);
-const char *kasan_get_bug_type(struct kasan_access_info *info);
+const char *kasan_get_bug_type(struct kasan_report_info *info);
 void kasan_metadata_fetch_row(char *buffer, void *row);
 
 #if defined(CONFIG_KASAN_STACK)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 162fd2d6209e..7915af810815 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -84,7 +84,7 @@ static int __init kasan_set_multi_shot(char *str)
 }
 __setup("kasan_multi_shot", kasan_set_multi_shot);
 
-static void print_error_description(struct kasan_access_info *info)
+static void print_error_description(struct kasan_report_info *info)
 {
 	if (info->type == KASAN_REPORT_INVALID_FREE) {
 		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
@@ -392,7 +392,7 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
-static void print_report(struct kasan_access_info *info)
+static void print_report(struct kasan_report_info *info)
 {
 	void *tagged_addr = info->access_addr;
 	void *untagged_addr = kasan_reset_tag(tagged_addr);
@@ -414,7 +414,7 @@ static void print_report(struct kasan_access_info *info)
 void kasan_report_invalid_free(void *ptr, unsigned long ip)
 {
 	unsigned long flags;
-	struct kasan_access_info info;
+	struct kasan_report_info info;
 
 	start_report(&flags, true);
 
@@ -437,7 +437,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	void *ptr = (void *)addr;
 	unsigned long ua_flags = user_access_save();
 	unsigned long irq_flags;
-	struct kasan_access_info info;
+	struct kasan_report_info info;
 
 	if (unlikely(!report_enabled())) {
 		ret = false;
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 182239ca184c..efc5e79a103f 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -43,7 +43,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
-static const char *get_shadow_bug_type(struct kasan_access_info *info)
+static const char *get_shadow_bug_type(struct kasan_report_info *info)
 {
 	const char *bug_type = "unknown-crash";
 	u8 *shadow_addr;
@@ -95,7 +95,7 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
 	return bug_type;
 }
 
-static const char *get_wild_bug_type(struct kasan_access_info *info)
+static const char *get_wild_bug_type(struct kasan_report_info *info)
 {
 	const char *bug_type = "unknown-crash";
 
@@ -109,7 +109,7 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
 	return bug_type;
 }
 
-const char *kasan_get_bug_type(struct kasan_access_info *info)
+const char *kasan_get_bug_type(struct kasan_report_info *info)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 1b41de88c53e..e25d2166e813 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -7,7 +7,7 @@
 #include "kasan.h"
 #include "../slab.h"
 
-const char *kasan_get_bug_type(struct kasan_access_info *info)
+const char *kasan_get_bug_type(struct kasan_report_info *info)
 {
 #ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/158a4219a5d356901d017352558c989533a0782c.1646237226.git.andreyknvl%40google.com.
