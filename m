Return-Path: <kasan-dev+bncBAABBJN372IAMGQEHR6Y2PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C2F694CAA8C
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:39:01 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id x8-20020a2ea7c8000000b00246215e0fc3sf670423ljp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:39:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239141; cv=pass;
        d=google.com; s=arc-20160816;
        b=cXfQ9CYXIvqqsGD27pcWNQriLrvQoZz0uUx6aqgEw7vDlTifg4AKoiwMI+YwPLnNNW
         xOwtwdV0ZDG6/nPehowSM6UmbuARsWdq3oZ9bT2LdrcDwC7gT4SvJJ5fu/rwwdtXqBPQ
         1ZKUNWTZrRSGSpqWpnd7SqgrVDfUcstf0tlA/6nPwKBVqihl+Lf7exzapz/IwVDCSL5p
         jmM8Ia9wK6AR6X+QgEUNWPYUYbHArUBKq9F9IxOV+yhFWdOgjXsPcy1P++6fuJBajTiM
         +nEb+SNbIUYZ0diN4xkdZNNddYfENntU3TEDXmDQA/s+uw7nysmw/ZGvtmpS0qI91o4t
         zTTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ydNS+gkNLvXrhTcdhVdVku1kZu1yG30n6KvsEXZhnNA=;
        b=w83xgJ7HM1S2sF1oduNijE0Hvd0QMV8xlRuM6mt04Myz8LnqHOLqQiuntVXARAEgjx
         COxZZEzQhZ2/YHJ3pCuDBJvJatpd1UyvsPwcwWazpWEf6z4DWpU4sGcxAvF0TYUYsadA
         9qVBy5ThoPMO7VCvg/MvtPBG2d68/tjislrBq2o1MAp1p9Nu53Km5/+SF4mDIV398mO6
         TFoYEy+/+8h56s2olX+c5c6mPY6LBRicSSoDiW+RU80rL52F9EQ5PMxrJCbQthk6ez2r
         RvXykMenRgezac6AQ61/8FeGo6gB6sgIhfvdPISEsfeBMmJMXWOZTXfofmxuvCdtVRK6
         5WWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=akh6ZCXA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ydNS+gkNLvXrhTcdhVdVku1kZu1yG30n6KvsEXZhnNA=;
        b=s1FrYhzUPb1RBn0aYNxsNUfh80WWNxo1C5b3b8JeRe+inzxPFuu4hwk2r/eNLLHh5D
         QrgcyOJMxCFwDYLGUTY8U3fy5oogoaVQsnVJltFcOZA7npgOMf8VZaj3UD5iyDXaotnJ
         fDXvxu21ey26+oK/VHt0gAsYCumymwKsOKA1REvh1dt3GhD6C0cSfUuRQYBMrV72cLbe
         thbzj5KAhChCp0ydQeuCnkcDx4dbp7bhwAqQ3fkddvsrUdcLxzt4H7YXN67KnetEFBdb
         oEVgzFLv8lgfhZ18f0yKuUqGAzk7CaMh57gjeMlT6JzmfoQu+7j2qglL7MoWK2WpwpGq
         PRPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ydNS+gkNLvXrhTcdhVdVku1kZu1yG30n6KvsEXZhnNA=;
        b=ONlCV0WAzyxy6A9EGCHWpBaEMTpM8N2s8KcYktB8qGt2rH2Cy1Is8z9MUaFpe8SxN0
         jdovL1ejPk7jokcP/FycG8iUOb8h7ohz0Tyq7Dgbj5FcvY9Z8Rx8MuIx4QU6aU4/Pfr+
         /yVwkrqJ3pmZ4qcXs2/8RmfXJ8i4wvDv5H1b7ncv9g49ixaPJndsj05JP+lL/4YsbrJc
         +SH2tWAfVbtjuvn8cr5CKzyyEYCm4gVWT+v+7DtjdoEPfUsAajzCH7CHzWw6IOO56uSV
         IxOlUl6ToBra7ryAeEiiIPnkuy/Md+KnrhdWz6/9gC7rGVVJm4zMvIOhyltrSrdXH5Jq
         QMRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530srvSmT9YK4Fa64DD1s2HPDEvpKulbAGSpw9xCH8XlT2Fvbg8w
	QBWb/5OAS12qEheSbrK8qts=
X-Google-Smtp-Source: ABdhPJxRaB3xAcoWrN5Yboub7sqmLPIgWP4F8gxSqgNZ0RFKFgR3njUuwAiQlCON1hLD585C0YkJuQ==
X-Received: by 2002:a2e:8449:0:b0:246:440d:b2aa with SMTP id u9-20020a2e8449000000b00246440db2aamr20293469ljh.107.1646239141298;
        Wed, 02 Mar 2022 08:39:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc07:0:b0:247:b308:7b8c with SMTP id b7-20020a2ebc07000000b00247b3087b8cls404070ljf.0.gmail;
 Wed, 02 Mar 2022 08:39:00 -0800 (PST)
X-Received: by 2002:a2e:980a:0:b0:23a:22f8:83c0 with SMTP id a10-20020a2e980a000000b0023a22f883c0mr21012591ljj.158.1646239140367;
        Wed, 02 Mar 2022 08:39:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239140; cv=none;
        d=google.com; s=arc-20160816;
        b=mTWUJhDvOlZvw6YCoRdo9ynKzBodhn0hZqpCgpPT3B1si6Q/MDVrUqW7kmQmjzEwk/
         8hhtbDWlEKJ6qMfyU/ige59thTNbG1E+uwx4tBCS011mwr6hLCxDXIeFTrG8a+31MAFo
         3d8sjKJ/Q3IVTHq2/7S7HIURSnN+ZOa8hJPtnoyVOsCm6Z1W9zdJzWGzvWIxooBtt7hl
         QmTJS2YuEfoRqjBSZc9Frut0Tb10dFlJiSmB5JqBgrxtb07MXemSLintY3mL4fPEfaQF
         DSWz6Bxy0Gh4MkDm+8bWdt/TKvKZMaJ8y70JP4lhX7tOGz5XMrw0JDNUTlnBBngC7QVA
         Hnsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9LoFBOx+41NuRW+TN1sbV0xBqJ4TCv0zuyZEci6w9hM=;
        b=uqwz0jZ5hl6XXLElBfzrEKgvuMLrPdjlVZANs5ooG4PBJz8frkXw5Nr72jU9NADRnX
         HDWYkx7knxXUpkDmNx9uinHbBUwhNEQj4mgIaSwDzgkIwzNcFWRKX1bmNd6+g/UcIczv
         OYkIdogcqzV35I1LthBXdu+grUAT9dWZkRjbDAhDoBH8w1PwULK/slpVoheGEel6fpR7
         XB7HtLWfbuqgMShO+R7zgNwHZFcxkQhzNcjijPySklHLNwoeORA+n7AXe+G8Z6gU7Qgs
         6w82/IcQCZ3lJqXIjqXwsPyozzuRMj0ocqYMUo4HQu0j38rHupd2hYXhdcb8qC00/ytG
         mTUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=akh6ZCXA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id b14-20020a056512070e00b00443ab00ddd5si744004lfs.5.2022.03.02.08.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:39:00 -0800 (PST)
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
Subject: [PATCH mm 16/22] kasan: move and simplify kasan_report_async
Date: Wed,  2 Mar 2022 17:36:36 +0100
Message-Id: <52d942ef3ffd29bdfa225bbe8e327bc5bda7ab09.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=akh6ZCXA;       spf=pass
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

Place kasan_report_async() next to the other main reporting routines.
Also simplify printed information.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 28 ++++++++++++++--------------
 1 file changed, 14 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 73348f83b813..162fd2d6209e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -392,20 +392,6 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
-#ifdef CONFIG_KASAN_HW_TAGS
-void kasan_report_async(void)
-{
-	unsigned long flags;
-
-	start_report(&flags, false);
-	pr_err("BUG: KASAN: invalid-access\n");
-	pr_err("Asynchronous mode enabled: no access details available\n");
-	pr_err("\n");
-	dump_stack_lvl(KERN_ERR);
-	end_report(&flags, NULL);
-}
-#endif /* CONFIG_KASAN_HW_TAGS */
-
 static void print_report(struct kasan_access_info *info)
 {
 	void *tagged_addr = info->access_addr;
@@ -477,6 +463,20 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags, false);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous fault: no details available\n");
+	pr_err("\n");
+	dump_stack_lvl(KERN_ERR);
+	end_report(&flags, NULL);
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_KASAN_INLINE
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52d942ef3ffd29bdfa225bbe8e327bc5bda7ab09.1646237226.git.andreyknvl%40google.com.
