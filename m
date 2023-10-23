Return-Path: <kasan-dev+bncBAABBJ553KUQMGQEFPLTBIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CCB5D7D3C66
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:26:17 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-507b9078aaasf3729240e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:26:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078377; cv=pass;
        d=google.com; s=arc-20160816;
        b=TaQTMP9FqMuVqcj43O4+If2HxknrsQdQIlgjz1ALbXPtynLwAZ8kp3vTcZoi2sfbfh
         8Gr+ECcNe2d14kvrwDLeBfvOVSCZ2cdDM8X4LR3TxkSfOaihuvtItvoZBTGFkjoplNmS
         N+R9HdbxIiEkK3k3sDJ7WROCtq/j7uj0EbRJiLO0nYbbUZgz7MqrRTp9alIOiod0cdIB
         qtLwg6qEDBtlZvwfbNxrqkHyS2BNFSyeO6kX9uGiHa3V7zUG2fZz37Bjiqn9Z3Caq8cA
         71eZaMQS4NUbfMZT4LY0MDQSsYAVN3XKEnHb3awsIxbAG7xorvVb6eI0STm7j3nhXK0f
         Oaog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XjTVu0QFgqYvofXDqaVFHYIjM3kADMJBkyhan2vwShk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=BliRhU4BzigqkbfRVGGAjlXgPGg00CmEPWrVFKBoZ6hn2gUTFWZNwMkz6p+tzOFxLE
         48hOpL/1FbmrbsG+ygIi7h7vqEBeeJLAJQq9K7FFEnW8LpRB2qfZhFrzAOpB3BmE6fP+
         KcGrpW5ZxaFdlKM5P+UebWkhXYTRhbbzRbdhVulf2ROMp10M6W/JKIoUaPDrJmATpOiN
         ML8NOepWMfTCtXALN8m3kHdWASpUampihR8lSlJKTd9MdopBO7oTIKHVFKkVLc/RrTjr
         SevVeTywZpY0hasFPdqMc4mdPKue2JQVXsJ1ZHsSsU2spsGrqydVm50Vl2zoUlfe53Pc
         d0Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ne3J1RXv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078377; x=1698683177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XjTVu0QFgqYvofXDqaVFHYIjM3kADMJBkyhan2vwShk=;
        b=XAcPScteKzxTX3typC/tXmNusdd5Gy1wYY5oFBUgh81rOqnXDiLcukxQ8+cIpyAtt3
         V/TRtqADjL7MZrhtYqSA859wdmKNDkYGOwtNRjVAHvqrwFzt4yhfORat4JKMIdB1xKn9
         pRj0wtvlXFioNeVjQRT1cws5yF+3wIcVGReAUAxO6/xarbXYYGaqAhkGjLSQW1bSJWpS
         CtCg8n8AfB0h9V6/zftF0EbDTIbxNzyBb9PzMChXCeM15KDqAYPZopUoL+fGqfNqMzWM
         mlbF1DdiZWVqGaDBeplIEzr+RQy0PkuQb/DdnNGsEWZrZtse4WCpFjrG879P0SCIyUi9
         zDZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078377; x=1698683177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XjTVu0QFgqYvofXDqaVFHYIjM3kADMJBkyhan2vwShk=;
        b=MFZ1rzBQXb1TbuPTZKkqMo3JEy1d0wRb80P3oXtbd+brSZ4Va8gs3e3OvsyiI84wh6
         D+MwOvqrUkjCxQEFnGGhFPxlnVb3Ob8MpAMq6xaWE4jBTeZpt0qErgxV4d89BQmxNUjj
         yzfWv0kj8MR62XsrDohQNn+QZ9rLIYBebNIv1KOKw8STnwm53V+pD573zTQD6zT7hADg
         F4x1X22ad7tcZJ9DnNQcUlPcZ1cAVHh17DFYOGpptTNEKuLN/Fcw3y9bjEV09KwbLPtl
         vPb4byo3FyvSym2Y4QvoQ/8GaOH6VeMpj0XNjXtoskHtTaIUxTC1FKfp667uQsx7m/Fq
         gPNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwyEIdm4TPU94XzYHCqPHUP/69L/sMO75NIDcFgYlCozTk6zLcG
	TSW0E6WHPdvwZvuoenOGHKg=
X-Google-Smtp-Source: AGHT+IEB4Tl+1C3hNgxTcXbkTheuj+zAYmvkxEr51CJiPISB1FNN1w7qEkWhRowcajQGcGCW8KF0iQ==
X-Received: by 2002:a05:6512:4029:b0:507:ce2f:8ef9 with SMTP id br41-20020a056512402900b00507ce2f8ef9mr8359374lfb.3.1698078375830;
        Mon, 23 Oct 2023 09:26:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3446:b0:507:9fe7:d87 with SMTP id
 j6-20020a056512344600b005079fe70d87ls1949165lfr.1.-pod-prod-08-eu; Mon, 23
 Oct 2023 09:26:14 -0700 (PDT)
X-Received: by 2002:ac2:4827:0:b0:507:9691:f854 with SMTP id 7-20020ac24827000000b005079691f854mr6940607lft.2.1698078374044;
        Mon, 23 Oct 2023 09:26:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078374; cv=none;
        d=google.com; s=arc-20160816;
        b=fbIM65INxyTlpzg2rw/Y56PxVz9yDk5z0y4vun0XYVxKGgBnoBciv6FBxyJbjj69Wi
         OpMmwAvf2TDj+A6YSkjB5HclfJvO1zrtky6J/1lAZ5ppkEdmHWuagQW0WvzWp5XvhdPt
         +SUK9VSdVoWpmhjjD1ZWeQmKaIASdOrqoEyXCnAfX2g0rnbaBMUdEm2i6NvCqaULUUcO
         Jt+Sp+XsqJELTB3ezIdDdL1Bco4qeUjyj+JGP/I7KdL4MNI5NbG84wzXO30RKbf1Jhpm
         a9SQEQ/SJ/vNs8OPt8WgEivn4MzC6c7j2O3mzsZwg6NlEb71WF29TFON3ll1eoiz176j
         4Nyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uhMrVBrzgAoT1gwViC8KxLkH9OMZhix/uhvoEc70W98=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=R/t7QaID+KJRNRNN5HyCspkeL5NG3XrW9G4H8FrNvl+mzr13uIN3L8RLJohYvRZofx
         YZKtVZ3h1K5EZ7Yy+urH1o7WR5b82DyOAqOqnKJsCid6ojQcvD3F5WJrvIwqPmbyBNbC
         0U2DMc+dbIlOQ5hpUHll+NlhDqvQN7WE5lVdrTQz5cEMXo0g+z20DNIkEy9HEXAJ4+Vc
         2Qi1FyvHLJgY3mGrh9Zgasl1U/SCybD9W6hVrVrC16+IXxBod0DC4Ll7uNFrvJfvXM2m
         gahwwbt8qfJbvLwtSKc4CfODD4lDZtNKYC6ClJ/NSPkcH0xlM9Hqt6ndjLaWLUh8d+Fg
         vr+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ne3J1RXv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-205.mta1.migadu.com (out-205.mta1.migadu.com. [2001:41d0:203:375::cd])
        by gmr-mx.google.com with ESMTPS id d29-20020a0565123d1d00b005008765a16fsi311635lfv.13.2023.10.23.09.26.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:26:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cd as permitted sender) client-ip=2001:41d0:203:375::cd;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 18/19] kasan: check object_size in kasan_complete_mode_report_info
Date: Mon, 23 Oct 2023 18:22:49 +0200
Message-Id: <97721c54e9ccacc494dbcfcd0cbd5f5aaab6973b.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ne3J1RXv;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::cd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Check the object size when looking up entries in the stack ring.

If the size of the object for which a report is being printed does not
match the size of the object for which a stack trace has been saved in
the stack ring, the saved stack trace is irrelevant.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Added missing "../slab.h" include for accessing a kmem_cache field.

Changes v1->v2:
- This is a new patch.
---
 mm/kasan/report_tags.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 78abdcde5da9..55154743f915 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -7,6 +7,7 @@
 #include <linux/atomic.h>
 
 #include "kasan.h"
+#include "../slab.h"
 
 extern struct kasan_stack_ring stack_ring;
 
@@ -58,7 +59,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 		entry = &stack_ring.entries[i % stack_ring.size];
 
 		if (kasan_reset_tag(entry->ptr) != info->object ||
-		    get_tag(entry->ptr) != get_tag(info->access_addr))
+		    get_tag(entry->ptr) != get_tag(info->access_addr) ||
+		    info->cache->object_size != entry->size)
 			continue;
 
 		if (entry->is_free) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/97721c54e9ccacc494dbcfcd0cbd5f5aaab6973b.1698077459.git.andreyknvl%40google.com.
