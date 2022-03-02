Return-Path: <kasan-dev+bncBAABBYN272IAMGQE3KSQS6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id CA10F4CAA7A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:37:53 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id p18-20020adfba92000000b001e8f7697cc7sf834276wrg.20
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:37:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239073; cv=pass;
        d=google.com; s=arc-20160816;
        b=VqK9a2wQz47I0Tthuc2kYpAnBjHnF7D4qVNxrFU4v38cc34Gq+YLJoHIQvoosKm40z
         obxmqvngw19xTbMtTiNv+/KUIrX3SxRnoYW/WUUf3BmDI1emZkISSIG1C8LzMm87/o/a
         TejW8gIE0vTdc8X+p3qgzNEIH70PlN8o9LRK4eKEzvT8ad1sLIp79ribc0XxOlP2eBEw
         dhmDd89sVL9XBghN/nut/lui3UNJn9ujEmg1yp8lND9kg8LWjgKqd6DaUGJ334BaCuV2
         D6Wd0dBECsC5OfwhnByYeC99rmKaksK4MA8qBIK4GnE8jwpt46yzFWferCX2Ioa1EdJB
         7L/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3HIvpUJMNQ3Rgu01j9g/JAulinTKJpZNbVKFlEYbc+A=;
        b=osFb3zHoaUQjM0Pt+WoV21VQY7UuzQaiJF7F/Iyq+WY2lN1956plXqzFoeRTUmtdL9
         xykkk+bHQlti3Kd198yR14LB5JXQMfb4z4TKNtYdZww87JlOOg7m9yHkztq5gte/Cm7c
         9W6uOyM3voOEGJEuAk0zdOphMqGGQi/LKKzK36wzqAYEM3Uct1wSnjbEGifBU8Vn2Mcf
         RKGmUObGbOj4P5sjjnXH0y9714CZfFmp+718mg0oj5vN9ZgMLJjDp67XcVm+0D9pAlMv
         dE0hAVvShBymTBMYKJvtMVaamSOLD2/+c0EFz0rHKltrIqNOf6Ae6+79gbbQ/rYpOZJ4
         PBnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=He6aO0Jg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3HIvpUJMNQ3Rgu01j9g/JAulinTKJpZNbVKFlEYbc+A=;
        b=iZia7IpYUqh5dMK0QtsZaAvgAY/mCi7y64E2Lxg69ZcYQiaZwdlBmwp4+MeRxb0051
         A+DzkRXN3Lou2UOLYQ7obAHDw6nNjD92YFMIQdHrr7J+XmQnq5ncgSPic5Jag/qnPglp
         Y2noQfbmFsgJhH+V+I0UWQqKAbppP3K1r9AHRQBwFwKQqkWBqJvSwBFsmpu+lDKnCno4
         4waGH0vEZbFxx1R0rmI6Za4zcv99eY47D+e+pk69vV8Jebsub2Mn3mrHRjUQAKoxJwcf
         JiI6WuMjVWck61jcuIrkLg7/v5VGx5h8uAG5RgjgAzELf/ep5ju/rQxPn4la6ig7fq1O
         jMwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3HIvpUJMNQ3Rgu01j9g/JAulinTKJpZNbVKFlEYbc+A=;
        b=bzFr1/kEuKqpwxuWQDKu2q2AmF+T/2UFEo6Gzoz4Png8PumrnH5/18mmEkv3bpUl0w
         lPKqM44K11m5IPb2cACYCaXrjrwKZM+caS+G+XBSVuvHfye72NtDRt0M9Dqmbgpb7Krv
         Pt5Z8UUSCUNMsN92ffqYD0LDDbapRacRit+XGab9a6PZCrrPUvId1oBE/hXBnlqEsKeB
         0utAMsG6epkXnQSidEBrTMzuDzaTMxfhyHqwZo+6qxcRiBUBDSiyghxRlO+GYrrGWai6
         6IQB7w0Rjo/gVrpT+QSC9oVvyIURlDh4oAvs8IuAp/cwDn2Q8Pi1i9UB1W9yQt6v7IeW
         0KGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532CpFu0MUqfvQfcENVUxaysZEHp8XpP7TLRymA+Hh6E2MocGGJO
	ZKCpIdNsLrNBQPIXwO3In4g=
X-Google-Smtp-Source: ABdhPJw6dBpcELmp2jZH77LFkTrii03izzv1Ef7QTxV4AeQ9//J5GpzEHuFOa0uIgH7symgxxJIVxQ==
X-Received: by 2002:a1c:7c18:0:b0:381:4fd6:fcec with SMTP id x24-20020a1c7c18000000b003814fd6fcecmr493948wmc.45.1646239073562;
        Wed, 02 Mar 2022 08:37:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6489:0:b0:1ef:d725:8751 with SMTP id o9-20020a5d6489000000b001efd7258751ls699197wri.3.gmail;
 Wed, 02 Mar 2022 08:37:52 -0800 (PST)
X-Received: by 2002:a5d:5982:0:b0:1f0:148d:3846 with SMTP id n2-20020a5d5982000000b001f0148d3846mr6264946wri.639.1646239072818;
        Wed, 02 Mar 2022 08:37:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239072; cv=none;
        d=google.com; s=arc-20160816;
        b=bh7sWdIJ16IYMDXAbS3SojjN9nzOAiDyLbCJ/1KH2n5yUlHk+mJ2E440fsoBGqGlhV
         DfUNWUX6pTnyt1fA6j0BLC12giY/A8PaAKA6pb8Q+MB2DF4ONLso/RZm/Av8ubGW/ESD
         o0cijc1Kv/wg+iEJb1vIBussmj4XqzY79AU1kgMck4mUdd9nH8A5sb3Guz883LSTewPF
         eQnn4x62Ih2/+O0cL4Y2bCZxYvMmZAEFwcrVbxQAb1V96WCdklAkY/+dXBv0kWJ9NfJT
         cFPRRy2+XlTi2WwV48tNtBBszqzRHE8lxVHIv3FsjFX6ciTAwODSNqDxyAy8Tk1uF4HZ
         q8+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RoJ6KhPXk7RwGdhLlSmay7OZIFNg6mxUpxpaIs64SPw=;
        b=JuLTj1Le4IE7FFuKAcGsb7euZPfDEBkyzEh+6J6JRDuXVvjpkT3YU/3EjUb22amSvL
         4YUH4YM4F3lqJtSThP4JlvxkmGcNZpuTyAKRyb8Zq5QW7C5DED56aZ31R/UAwbGJ0Ugo
         fKee+xwJbekREqVdKmTe8x/e8/JsqackZI82JVBYl2EZeCx2VRbz7mAo5Fko78YLAbza
         XDHkGDapciIqq/btGWsqNPFWzmdlQ3Di0UZHWZWOtyzR8h05tKaoM/wSB9VwqUsnkeKx
         nO8qUkglX6raErmMtfySzpdO2hV6B5wHCAKnt8uy2C9otZCePlf8uYVBFHrsoWiStHvF
         hhHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=He6aO0Jg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id t9-20020a5d42c9000000b001e9d3847897si871758wrr.8.2022.03.02.08.37.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:37:52 -0800 (PST)
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
Subject: [PATCH mm 07/22] kasan: simplify kasan_update_kunit_status and call sites
Date: Wed,  2 Mar 2022 17:36:27 +0100
Message-Id: <dac26d811ae31856c3d7666de0b108a3735d962d.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=He6aO0Jg;       spf=pass
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

- Rename kasan_update_kunit_status() to update_kunit_status()
  (the function is static).

- Move the IS_ENABLED(CONFIG_KUNIT) to the function's
  definition instead of duplicating it at call sites.

- Obtain and check current->kunit_test within the function.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 30 ++++++++++++++----------------
 1 file changed, 14 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 2d892ec050be..59db81211b8a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -357,24 +357,31 @@ static bool report_enabled(void)
 }
 
 #if IS_ENABLED(CONFIG_KUNIT)
-static void kasan_update_kunit_status(struct kunit *cur_test, bool sync)
+static void update_kunit_status(bool sync)
 {
+	struct kunit *test;
 	struct kunit_resource *resource;
 	struct kunit_kasan_status *status;
 
-	resource = kunit_find_named_resource(cur_test, "kasan_status");
+	test = current->kunit_test;
+	if (!test)
+		return;
 
+	resource = kunit_find_named_resource(test, "kasan_status");
 	if (!resource) {
-		kunit_set_failure(cur_test);
+		kunit_set_failure(test);
 		return;
 	}
 
 	status = (struct kunit_kasan_status *)resource->data;
 	WRITE_ONCE(status->report_found, true);
 	WRITE_ONCE(status->sync_fault, sync);
+
 	kunit_put_resource(resource);
 }
-#endif /* IS_ENABLED(CONFIG_KUNIT) */
+#else
+static void update_kunit_status(bool sync) { }
+#endif
 
 void kasan_report_invalid_free(void *object, unsigned long ip)
 {
@@ -383,10 +390,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 
 	object = kasan_reset_tag(object);
 
-#if IS_ENABLED(CONFIG_KUNIT)
-	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test, true);
-#endif /* IS_ENABLED(CONFIG_KUNIT) */
+	update_kunit_status(true);
 
 	start_report(&flags);
 	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
@@ -402,10 +406,7 @@ void kasan_report_async(void)
 {
 	unsigned long flags;
 
-#if IS_ENABLED(CONFIG_KUNIT)
-	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test, false);
-#endif /* IS_ENABLED(CONFIG_KUNIT) */
+	update_kunit_status(false);
 
 	start_report(&flags);
 	pr_err("BUG: KASAN: invalid-access\n");
@@ -424,10 +425,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	void *untagged_addr;
 	unsigned long flags;
 
-#if IS_ENABLED(CONFIG_KUNIT)
-	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test, true);
-#endif /* IS_ENABLED(CONFIG_KUNIT) */
+	update_kunit_status(true);
 
 	disable_trace_on_warning();
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dac26d811ae31856c3d7666de0b108a3735d962d.1646237226.git.andreyknvl%40google.com.
