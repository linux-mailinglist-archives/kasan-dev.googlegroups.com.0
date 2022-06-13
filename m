Return-Path: <kasan-dev+bncBAABBINXT2KQMGQEDYDV3MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ECCF549EDC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:18:42 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id n2-20020a170906724200b006fed87ccbb8sf2189658ejk.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:18:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151522; cv=pass;
        d=google.com; s=arc-20160816;
        b=DxPwF35Ly7iezoByQ2lTMrjxdahveicBNwLTbkGfdaVG+5n1zDuvE/UZyFrGKoPamZ
         pwzia4wvo+WUCd9dw61LT/7/uJoqhDBB1odGT+8G28UUKNP0q3/3X+LOy5E6ipKxfK9G
         DCyWSlN2nYNNTpd/0lWeejl3qG0fYEsRyX8r/UgG8qw/uSPhUwV78el79KGsTCpqayek
         2vD++G6HDaW77K2RjIUde0u4FcQS85mvhryvX/l53k7LZy+3gv0oVdDHVwYpprVR2kd8
         tTZKDCcM0SZqSNxnqE8WhTc02lDalKsdm3ujfVSXtWre9X7YQjFHVSG/RuaEZmTd8E99
         FZOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=S1PBNSfrB9lNulD++JypiAFhD9o+LB1LRXUg2Ql/XO0=;
        b=DF7L3Ki3Wz9G0LqemAZV2aV7EBn6sclTn3gYDKzK1NRMNX0xAVIZAckxKBm0QuRIpF
         bHpb7jCqc3kYHXK+gosekoNx66vwgSAvhMCuK0G66yRj1E2Vj5xbYa+p8OxEIVRxkW6D
         85Qa41gjWu7aWjX2CWpOY3z/rtwiKccZrJn9kYoBjAqdN9xwejsEd34CZ4RP7y6k5RLK
         ojlcfwKGTtmqU8o7seiurX4efCkOM1cGLii+PlouKtuihzwgEHYGwtTmaljPWG8lbbdO
         iV6VqxybY+yKYTr/HqfwQ+Oa7ONtyMkK2alVNCl2kJVFUick8RaLNZYu8e7WWfw7+0mO
         KwPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kvRi5OcE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S1PBNSfrB9lNulD++JypiAFhD9o+LB1LRXUg2Ql/XO0=;
        b=DbYdEMk0ihnrgDcBs5jWZESRBhN2r6MiNsQxmtGjW3CxeUDiAh3B7VyZW8g0/xx0n2
         vLG+Y4uWMce6FNMomMDiFQRyQJqspnFgCnn3712V8ev2CKqASbj3qkaLdeDj0ce4W91H
         zhQxZzMyz2rDa6WsWdaOCSvxk0Jz4gSJuekd1+g6SKmobfWq6VVsQV7oNTiuUTAeRRLJ
         b3Ud90YcWgrcoC48VWrbsLMehIqVUymW1z4Udhm4BtYi37nXmLF2YsgW9SzT4/XTlijb
         /rGFqMYPD9zoC7iifwq/fiojZOOe9Q7q9RJc+R50QF8ubPi/VgN6eL3h2c/r7vyyWEjq
         7GhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S1PBNSfrB9lNulD++JypiAFhD9o+LB1LRXUg2Ql/XO0=;
        b=1qlNibPp1PxpUFCW2F10ljZDmUswtlorfUNvId6Vy5NVNPc0APAxRBaIseTHFEaHs2
         SVIVKyX6k6C6QUCVAzqkO9vmDlmplkmqF//r4+XFMOtDQzTHK/vkDa6FG9NhfiAhSZ1g
         E9oRgWg6xTX8BQxEcg8C/U8OHyxuWOHO0vNJLXURQTjXtX10/N4XNfz3NkEuNu3X6Lrb
         6bQcePIGF6hralQW03qbs8+VgE2QTQKfWZ5QqocqBPJtGMsUQ4beZM9nC+uxesZYrpq9
         oe3Ajt+3VEXC6yI7/NcCtvtv9uCnR7KGDMOrgeDrm0PuwUmjaI9rfYeUTQsJT6v6JZee
         89Rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531x4vfwo56sPrbKcDOznSc4Ugp8HnHEChKUdb0PykrgpavX68fe
	ETsFa8eb6w6+YSLkgKaGEuE=
X-Google-Smtp-Source: AGRyM1sqmmszwtEiEhAR4by6wxh1Qy24SJU6j4DaO0PwYx2Ari88eOrKiiFcG1RBve0Y7LoeieLr6Q==
X-Received: by 2002:a17:906:3bd9:b0:6ff:4b5:4a8f with SMTP id v25-20020a1709063bd900b006ff04b54a8fmr1320120ejf.139.1655151522005;
        Mon, 13 Jun 2022 13:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls144932ejs.6.gmail;
 Mon, 13 Jun 2022 13:18:41 -0700 (PDT)
X-Received: by 2002:a17:906:9d01:b0:711:dc5d:c8a5 with SMTP id fn1-20020a1709069d0100b00711dc5dc8a5mr1252578ejc.432.1655151521373;
        Mon, 13 Jun 2022 13:18:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151521; cv=none;
        d=google.com; s=arc-20160816;
        b=JLZ8HSifvMSI1np7hjUwqLpR0aMAM/LPLlPm5cSyhrNMQQQURNnBI4T7zO11TlQfmu
         6X9ztwTFYxzsfNTROCW6LnAD00J62SSiaCua08w0fRX4GK3rQ22G59BTd7sKr4hseqRD
         7vdqtMrwet4ABb45EBVY1zdOaHgiJS7suiKZqZwUuSW6znZbHe9Dm8WveGFd7PAC2b+B
         lhwLyD7SIkG0VLmKQcU4lBo38kdov7pjRrL04o7EZ+slQ7oV0kqB3T1jgAwiZdUnxPBm
         GHEn22mGIPXaYtFGPDriLNTaf3YE7jzW113KMo96kbvlhdXoesus7DvCej2Mz25ZpB91
         cWrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uV62cC5DfHg/D8q7E9RvYjkrSokJV1eiZxRUfsD9VoU=;
        b=vgsfyGd5vpSGEJjnRcOmzkOHfHDCqttSx+Mgx5C4VgtpYtaD+JBWiFan/hKizzsap4
         nLBnugyGqUF4spIihWVOkhxX5KHG7PAHjSklD0OQm5tS7/9z64aF4dPsSo6G4hydHBed
         Uf4dpuUCkwvbIkDIii/8Az4YnnQvcv+M9tV3omtII9g8v70g5rjHc0aTzIBx3CpqY5AB
         ezlUBa9+lqhVKgmOGPvHVJJe8ZlI9GnkNTYcURsznBfmhqXqTpEBQPP3UjjKjtEzxahW
         xJVc77UIE+YqpqgZvKsyECnypIPy3l7Y8HvVtQbF37OR1jH6xtasnjt+o8kVVIIcJqmJ
         LvKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kvRi5OcE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id j8-20020aa7c0c8000000b0042e15342b19si358419edp.3.2022.06.13.13.18.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:18:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 22/32] kasan: cosmetic changes in report.c
Date: Mon, 13 Jun 2022 22:14:13 +0200
Message-Id: <cd0cb4d93e15c5092de8a31ba8c1d6f719aa4c7f.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kvRi5OcE;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Do a few non-functional style fixes for the code in report.c.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 11 ++++-------
 1 file changed, 4 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7269b6249488..879f949dc395 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -194,25 +194,22 @@ static void print_error_description(struct kasan_report_info *info)
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 	pr_err("%s by task %u:\n", prefix, track->pid);
-	if (track->stack) {
+	if (track->stack)
 		stack_depot_print(track->stack);
-	} else {
+	else
 		pr_err("(stack is not available)\n");
-	}
 }
 
 struct page *kasan_addr_to_page(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) &&
-			(addr < high_memory))
+	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
 		return virt_to_head_page(addr);
 	return NULL;
 }
 
 struct slab *kasan_addr_to_slab(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) &&
-			(addr < high_memory))
+	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
 		return virt_to_slab(addr);
 	return NULL;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd0cb4d93e15c5092de8a31ba8c1d6f719aa4c7f.1655150842.git.andreyknvl%40google.com.
