Return-Path: <kasan-dev+bncBAABBYV272IAMGQEOME3C4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 762164CAA7C
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:37:55 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id hc39-20020a17090716a700b006ce88cf89dfsf1268184ejc.10
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:37:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239075; cv=pass;
        d=google.com; s=arc-20160816;
        b=rZ08DFNZ867YIxscoAU4oI4po2CB1Pm503qdeH9ZdO4Hvbu+R4yzIOYxM4jg1llkkX
         7PYgtSpJqIsI8+jXWAQKBnM8JmmfhYZaZ71FzthYin3xaudWpTK3uQIBTmzEfVvArHW9
         la1L7UkYSZFk94fCLxjnvnU7rXA3Nzdhqy1g5U2qZRNmLPUxxDF4JAwdEbwP210I0sqi
         qylu7CiMRivJBDS8YlbpKzKm8+fQSBhO0417bi5DFCJ+hxUm1cP9hYCU/zTmV9a0rNyo
         Wi83fIREeWUkGbUzRsESt8TYhEhbXmkQYsUP3Wstlu5f0HT153v1iSzBOxtlZy/zMfXi
         sa9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fCQHT7HjD1h8tdtXymFAjw6tSbGh86feLQ0FEYWtFIA=;
        b=fHdpSGK/S9NFziVaeXwJRZrAoRkr1K6zY3eE23gF61D6bFQc+87DjDfsffJ2h+clIm
         04Yn2Y4gA6XLnHzG226ZlJBx87+S82bEXTxvkUXbY6dJp+35PwdcKkyPO82ceoXhbbAN
         kcirPx+Uaeq+56BqBOpexDUZBGPKZXD97kZrJ4aJ711QBo+2rrDtkjrfOtOrV8n0GPnR
         ut8OIpfQ1bqvm4bA7pxqDr8XkdGoWogA1HXsnl4zxuHHzJCvps73oB8ko2Gvnj+4220c
         065bLyxpqiI+VkdZY5pbZwCFYL3QWl0Xe+LhCEn/69Gwfyue0Md3oudJPdjY30r4jFpW
         ad5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="ZVIurZ/9";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fCQHT7HjD1h8tdtXymFAjw6tSbGh86feLQ0FEYWtFIA=;
        b=RcojAE2RHdMXheNz4wDDMMtUV0JdyDPBDPfm3vEotREUSH7fYPGsIf5ihHrCiUF3mw
         OuE5p4tBZ04fWyYYwnRYCs7ftcsUomVT/okZ0m54LSrsjRgcDlTzsUzS0+Td4vM9KGzp
         ap94Rc/wHPRILB0v3lnrzSU0osUfUvnD4pR3p2jOu3Gxm93hjgZcwVt4VZCjceoG/KRU
         Fek7E3K10cPHTCzoQJWPMf0Vfj+5WthIdPNYah83JhP/264Pnymd2rOjZu3Z1KSAvtX5
         jSwH3hhsiIp0kiRcBXRw+Sy4sgOEwOJZBaNgcssh2109QLZffpK+FXA2iqFhVdHsOsiz
         e5Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fCQHT7HjD1h8tdtXymFAjw6tSbGh86feLQ0FEYWtFIA=;
        b=VoOzXtQxNqLjg3p7zVPXSpcmy2488/yi1kLIbh6I/y2oM1D4biwQ3istnDj4/nZTZj
         7V2Mucn8fnRCSWnQidVo317W9Ag6RXfeXarU9kQboaAStZF4bKTBZCJjMeOat4/jjb1G
         pNq865bIA6i/pUOeBztjsW/hWt8vB/HqqeqC9WpeNVaw3Z5OD5Xije4LjDLNRDCdbHHJ
         vrhnQihjTmb7CIuNQmZazj9hnYbZCUTRp1wdRtI40lOD5ZMMSs3CGBLpnrXOQ2qaOcGo
         mP0JSPKxcjR+XasSeR8E9HCuHHJ3yX+UQWDK5gTQs8DfWOg/2gX7AIejAtxk4iS+R/zf
         BY1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339VHaxAg3Qedo/L8ZjY2rWSIE+CWJs4NHU0GfC8dEX2ABUNQRb
	YGrKyb1/3xLymSU9HGKJGnU=
X-Google-Smtp-Source: ABdhPJwS/zbjpS8Qi9wZbzTr3tHQgHMgA2uybu0LSYCYMk4QiyFVMMp0auawUpnzcJstqUimCiMblA==
X-Received: by 2002:a17:906:8902:b0:6d8:85a6:c6b3 with SMTP id fr2-20020a170906890200b006d885a6c6b3mr4206893ejc.187.1646239075128;
        Wed, 02 Mar 2022 08:37:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d302:0:b0:40b:657:ac46 with SMTP id p2-20020aa7d302000000b0040b0657ac46ls2647132edq.3.gmail;
 Wed, 02 Mar 2022 08:37:54 -0800 (PST)
X-Received: by 2002:a05:6402:f2a:b0:415:a3b3:2019 with SMTP id i42-20020a0564020f2a00b00415a3b32019mr5179107eda.177.1646239074228;
        Wed, 02 Mar 2022 08:37:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239074; cv=none;
        d=google.com; s=arc-20160816;
        b=Jw9LuRWgpikq2JCG1n5E9UInF2amlCqD2MRBHpcOQmCfRXqd/XaMzBs3Ej5C7Ry9fn
         TgiVABLNEZZSBpopW3SDgtC2BLw+4RWH05LxphOoPCZ+XzzHmpGRQueFDWIRZoaYfcPo
         PZ9Jd0281okbUnzjezrtW06nSv0uVL9Ii7t8x34SuqeKZdDYdkLqL4J5C3qqs7gDU9JN
         rdeHXpULzE948m5O6Va03EUvg5FzlcuV9dhukt+LP64WfiI0ArY4VuT/9bqHRcTHVNxt
         lGiDCJ7HP5VnkEg+RMbNJVGFeRssJdyDoxjv75nGcM4ZxCoUaqV6QoZJhFsjlaq0lubK
         dFJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=swbTnyAsWMCMrpYXsiQkz6QMlKhIbhxptnYL52Z/im0=;
        b=zmGfqVGEVx82BfVMOm5PRFjlbinHTjMXnfuAXGqjUHtVTIbRXGvJpbekQPslumlU1E
         6yf290VSCEGZH4W2OuIYPZxoPlsbpECTM0O4hnb8z+CG4CH82SSmQsVt+4DE2FCKdHZW
         xNZMTt3Xa0JWKXZMHrLiOiFoctjFNG7ROIB1dEvvys8ovGHZnw7pm/VcGwymutG92/1d
         0SCFe3O2wVnR4bIXWNbxxTj2Z57Q/etmlCdv06cB2nwMu+qGd777Yfo99dCiRFHXzbJ2
         TUYRyTeTqe79TGiVcs1gLE4U5Ptud9/8e39/F798wA0Jys6tRZW2FcJ656MWoiaVvPOF
         vxlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="ZVIurZ/9";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id b88-20020a509f61000000b00413ed059da9si487560edf.4.2022.03.02.08.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:37:54 -0800 (PST)
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
Subject: [PATCH mm 09/22] kasan: move update_kunit_status to start_report
Date: Wed,  2 Mar 2022 17:36:29 +0100
Message-Id: <cae5c845a0b6f3c867014e53737cdac56b11edc7.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="ZVIurZ/9";       spf=pass
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

Instead of duplicating calls to update_kunit_status() in every error
report routine, call it once in start_report(). Pass the sync flag
as an additional argument to start_report().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 75 +++++++++++++++++++++--------------------------
 1 file changed, 34 insertions(+), 41 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 93543157d3e1..0b6c8a14f0ea 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -98,13 +98,40 @@ static void print_error_description(struct kasan_access_info *info)
 			info->access_addr, current->comm, task_pid_nr(current));
 }
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+static void update_kunit_status(bool sync)
+{
+	struct kunit *test;
+	struct kunit_resource *resource;
+	struct kunit_kasan_status *status;
+
+	test = current->kunit_test;
+	if (!test)
+		return;
+
+	resource = kunit_find_named_resource(test, "kasan_status");
+	if (!resource) {
+		kunit_set_failure(test);
+		return;
+	}
+
+	status = (struct kunit_kasan_status *)resource->data;
+	WRITE_ONCE(status->report_found, true);
+	WRITE_ONCE(status->sync_fault, sync);
+
+	kunit_put_resource(resource);
+}
+#else
+static void update_kunit_status(bool sync) { }
+#endif
+
 static DEFINE_SPINLOCK(report_lock);
 
-static void start_report(unsigned long *flags)
+static void start_report(unsigned long *flags, bool sync)
 {
-	/*
-	 * Make sure we don't end up in loop.
-	 */
+	/* Update status of the currently running KASAN test. */
+	update_kunit_status(sync);
+	/* Make sure we don't end up in loop. */
 	kasan_disable_current();
 	spin_lock_irqsave(&report_lock, *flags);
 	pr_err("==================================================================\n");
@@ -356,33 +383,6 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-static void update_kunit_status(bool sync)
-{
-	struct kunit *test;
-	struct kunit_resource *resource;
-	struct kunit_kasan_status *status;
-
-	test = current->kunit_test;
-	if (!test)
-		return;
-
-	resource = kunit_find_named_resource(test, "kasan_status");
-	if (!resource) {
-		kunit_set_failure(test);
-		return;
-	}
-
-	status = (struct kunit_kasan_status *)resource->data;
-	WRITE_ONCE(status->report_found, true);
-	WRITE_ONCE(status->sync_fault, sync);
-
-	kunit_put_resource(resource);
-}
-#else
-static void update_kunit_status(bool sync) { }
-#endif
-
 void kasan_report_invalid_free(void *object, unsigned long ip)
 {
 	unsigned long flags;
@@ -390,9 +390,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 
 	object = kasan_reset_tag(object);
 
-	update_kunit_status(true);
-
-	start_report(&flags);
+	start_report(&flags, true);
 	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
 	kasan_print_tags(tag, object);
 	pr_err("\n");
@@ -406,9 +404,7 @@ void kasan_report_async(void)
 {
 	unsigned long flags;
 
-	update_kunit_status(false);
-
-	start_report(&flags);
+	start_report(&flags, false);
 	pr_err("BUG: KASAN: invalid-access\n");
 	pr_err("Asynchronous mode enabled: no access details available\n");
 	pr_err("\n");
@@ -425,9 +421,8 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	void *untagged_addr;
 	unsigned long flags;
 
-	update_kunit_status(true);
-
 	disable_trace_on_warning();
+	start_report(&flags, true);
 
 	tagged_addr = (void *)addr;
 	untagged_addr = kasan_reset_tag(tagged_addr);
@@ -442,8 +437,6 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	info.is_write = is_write;
 	info.ip = ip;
 
-	start_report(&flags);
-
 	print_error_description(&info);
 	if (addr_has_metadata(untagged_addr))
 		kasan_print_tags(get_tag(tagged_addr), info.first_bad_addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cae5c845a0b6f3c867014e53737cdac56b11edc7.1646237226.git.andreyknvl%40google.com.
