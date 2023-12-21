Return-Path: <kasan-dev+bncBAABB3VUSKWAMGQET5M7ZLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 27CF481BF50
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:05:03 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-332ee20a40fsf733940f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:05:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189102; cv=pass;
        d=google.com; s=arc-20160816;
        b=AUcbZNZ3a0SuFTzR4lyBOqe81ICdqJUAfqV0nrEJOf4V/qJzg2196KBBAa73gcDh7c
         g9dPPqLytCcpZ082+Ph4v5EoohbFQeDBXVc9MqpuVVKgc+7ZJniZUSsanzrd4AmEBFsv
         zenj3T4VfkB4pbt5O2aSzleo8uhuGXoJPwL3gLMyW6PX92VbYC6R/HeUzphcXiM3AUg3
         ZKrngv+zAeZGnOw6jEMZRNkKANGscN9o3yVyVHmMQ/hnMwahtyIIsFWId0oliG9+UZKU
         h2ed+eauLEfGORqFDVTgBbd+iVog6mC0UiTH0Jfrvn5OPmswkv82GlkRHX8VF+mpQtx5
         UOLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VW6naNUEqZ/e0WJW0g5DqRKUTA4LlhGf4OrChGlOTR0=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=BG0vaM+UxK1y14rL06FFHbtB0MtpGw0o+4AKFgt4q9PiM/vQzWgM6l7nAnTUyT0CX3
         r0f2DDXFoP9sWbuTlMN2Un4JW4lVDbxWKc+ImPeQHtVpHJ96JGV3zgdVnlxMwt3ci5cB
         sXEDAPibjELI3DOoozC2xnJyStu6e6bE4fL6nh5MxtBihHZ0Hle6DToI6GYsaydhA6Zj
         GeY+sd+jDyQwg+Ez5aPMzF14iSpH9c3tRfCogLxEf/iVIAdJ9hvLZiPKU5Dl/fraVxZ2
         B5fY/2dFT7rDPpS0Obt7joIz0zdj22H1AWW+hM3y2e5JhQHZxn49BzE9irkzcdwfuxEP
         uK4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gsy7nZlb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189102; x=1703793902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VW6naNUEqZ/e0WJW0g5DqRKUTA4LlhGf4OrChGlOTR0=;
        b=E5cKevbWqCXsJGb17J0M4+rnI3/hMnY4Vd/1CgWv91lSzKj23rPbXF7rYW7x82Y4Ea
         cur6LFQPDEO8OwbJKmXx9D/z6ek+pWE6oXDks+Y5FWi0K13FTftYKQwzRdUDBDJj5VV1
         OeRZPxIe+jES5XcMrlBB5POdn4X/+fH6tvNhGgLEHo9ufviLcKjZfcl8q/iQoPSZlOwY
         ucGr3sKSIaCl1tG96DWplzSUzE2And9IQrFFWRjN29LfsNXwliHTAikGjk/8Ec1STDWe
         RL3VAYs5P/aL8N8/3PkBtYDODZPPv3KgHVe/z/Q1VF4OV56OS3AvkQ9r10FdbfryJIoe
         9Nhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189102; x=1703793902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VW6naNUEqZ/e0WJW0g5DqRKUTA4LlhGf4OrChGlOTR0=;
        b=RpWJXXtnfIohetO6W/xoUdE9l3BiaNrD1gr7OKu479VTQK8Eaxf8hnXL6wE2WYYrnk
         uQaBE7sROrwtrTBeJ7bGHWAWI5pbm+BAnG6ThOTmHNYbcarT55bC+pSN1zVrXvhW0o1M
         BFrUsr6oed123jVk2jHZMT9uZPEAa6aI37QLHhChS8PfdBAqlyQoexiOJBlhQwe8RxHf
         9FOYCcN87uYeYwPXLC1wgYH7A7FWHf0CmL4uOUS05Y8y/wzSDEmVmiTB8ARVKisLYQ0r
         SJWOXeJpPxtVdJyoef7WTQzsld9gaD25VPnQVLVDZaI0fsczNZv7AB2ZPDfcAsNnfgxG
         E99Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyP0fYGaCXK9rZNxSVvyRZLPMvqTLVGe8yZSUvvZc4SlKIKG3mC
	fkAXxIkAoAlCkHUGQn4Y3ps=
X-Google-Smtp-Source: AGHT+IE8W3dvojdU00CYQyRCzPEBOB3f86+PKea++vLc9ks25q0MkOQNhcS3A48P1XOkcP7Ev6Lvkg==
X-Received: by 2002:a7b:ca47:0:b0:40c:349e:176c with SMTP id m7-20020a7bca47000000b0040c349e176cmr144134wml.46.1703189102332;
        Thu, 21 Dec 2023 12:05:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:b0:40c:6935:2d19 with SMTP id
 i4-20020a05600c354400b0040c69352d19ls690941wmq.2.-pod-prod-07-eu; Thu, 21 Dec
 2023 12:05:01 -0800 (PST)
X-Received: by 2002:a5d:5711:0:b0:336:74c8:86c1 with SMTP id a17-20020a5d5711000000b0033674c886c1mr199972wrv.41.1703189100881;
        Thu, 21 Dec 2023 12:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189100; cv=none;
        d=google.com; s=arc-20160816;
        b=sUnAZXo/tw3FML9aiCSakjuvdlQy7IL8p1S+G+m3OrjLOqly2Z3WxCFTsSMQ6q46KD
         kXji9sUrY8B9PCxl9MK7y/im/wZzHZeYRmOPDWQM8gxH+ZIwRlScEYheI8+8tnc5le6C
         r5+dUgA0K0d0Lz8SLVblWVxAA7W+vTKS9oonk3p9K64qQxwD2jDVfuzi9YcyX5lOW9wS
         3Epj10HKIOazFDHpjh0/si9f32eMGzpNSwzS1QXdxwl3EiND8oG/8lqXbKZKv8u4VbBr
         ToBzybjPXj5M6aFGI5o+GzRfxa/ISUZvJiK9CIW14LyPGZvq/qbCZ8n1YweLsLJORrdi
         Cy5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KWohJbv99PLbGcicyqYuN0s/R1C+lxZK4GlvmO4roNU=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=uHEQy8NvnJrgWi30G7/mkvIer8eI2yRAN/HCYuICrQwxGVHXqpL5g2KpaPYl4B3203
         5rVXQpQmY26Xz9jGXURxb9SitUzARvQGxvejUKMrFrSYv/1FjQYbcdo7Rl1lR7gCSjWj
         LLGWGHmmHh4c4e1/9at3DbkXskfA4OSn7f3NH7NC+Ad3iInzQh5vL1a2lJ9fWvVoSbXi
         wp0Y2pJkzayu9NzbQrMnjqmgTpdJ1yjkTDf7ZXAqAHjNZAXTFbbkC4XMuE7UzJjwgRnC
         QrmixxXJKCSN9Tl222Wukl1NtLjgZz0cRPXdyBqQFTtqR0FMRzfUhNsxhMex93rLhHxU
         FgLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gsy7nZlb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [95.215.58.181])
        by gmr-mx.google.com with ESMTPS id d14-20020adfe84e000000b003367c517385si96151wrn.5.2023.12.21.12.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) client-ip=95.215.58.181;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 03/11] kasan: improve kasan_non_canonical_hook
Date: Thu, 21 Dec 2023 21:04:45 +0100
Message-Id: <af94ef3cb26f8c065048b3158d9f20f6102bfaaa.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Gsy7nZlb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as
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

Make kasan_non_canonical_hook to be more sure in its report (i.e. say
"probably" instead of "maybe") if the address belongs to the shadow memory
region for kernel addresses.

Also use the kasan_shadow_to_mem helper to calculate the original address.

Also improve the comments in kasan_non_canonical_hook.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  6 ++++++
 mm/kasan/report.c | 34 ++++++++++++++++++++--------------
 2 files changed, 26 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 69e4f5e58e33..0e209b823b2c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -307,6 +307,12 @@ struct kasan_stack_ring {
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+static __always_inline bool addr_in_shadow(const void *addr)
+{
+	return addr >= (void *)KASAN_SHADOW_START &&
+		addr < (void *)KASAN_SHADOW_END;
+}
+
 #ifndef kasan_shadow_to_mem
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index a938237f6882..4bc7ac9fb37d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -635,37 +635,43 @@ void kasan_report_async(void)
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 /*
- * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
- * canonical half of the address space) cause out-of-bounds shadow memory reads
- * before the actual access. For addresses in the low canonical half of the
- * address space, as well as most non-canonical addresses, that out-of-bounds
- * shadow memory access lands in the non-canonical part of the address space.
- * Help the user figure out what the original bogus pointer was.
+ * With compiler-based KASAN modes, accesses to bogus pointers (outside of the
+ * mapped kernel address space regions) cause faults when KASAN tries to check
+ * the shadow memory before the actual memory access. This results in cryptic
+ * GPF reports, which are hard for users to interpret. This hook helps users to
+ * figure out what the original bogus pointer was.
  */
 void kasan_non_canonical_hook(unsigned long addr)
 {
 	unsigned long orig_addr;
 	const char *bug_type;
 
+	/*
+	 * All addresses that came as a result of the memory-to-shadow mapping
+	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
+	 */
 	if (addr < KASAN_SHADOW_OFFSET)
 		return;
 
-	orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
+	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
+
 	/*
 	 * For faults near the shadow address for NULL, we can be fairly certain
 	 * that this is a KASAN shadow memory access.
-	 * For faults that correspond to shadow for low canonical addresses, we
-	 * can still be pretty sure - that shadow region is a fairly narrow
-	 * chunk of the non-canonical address space.
-	 * But faults that look like shadow for non-canonical addresses are a
-	 * really large chunk of the address space. In that case, we still
-	 * print the decoded address, but make it clear that this is not
-	 * necessarily what's actually going on.
+	 * For faults that correspond to the shadow for low or high canonical
+	 * addresses, we can still be pretty sure: these shadow regions are a
+	 * fairly narrow chunk of the address space.
+	 * But the shadow for non-canonical addresses is a really large chunk
+	 * of the address space. For this case, we still print the decoded
+	 * address, but make it clear that this is not necessarily what's
+	 * actually going on.
 	 */
 	if (orig_addr < PAGE_SIZE)
 		bug_type = "null-ptr-deref";
 	else if (orig_addr < TASK_SIZE)
 		bug_type = "probably user-memory-access";
+	else if (addr_in_shadow((void *)addr))
+		bug_type = "probably wild-memory-access";
 	else
 		bug_type = "maybe wild-memory-access";
 	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af94ef3cb26f8c065048b3158d9f20f6102bfaaa.1703188911.git.andreyknvl%40google.com.
