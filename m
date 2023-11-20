Return-Path: <kasan-dev+bncBAABB5NY52VAMGQEEXBDZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5530D7F1B8D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:50:47 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c8321310b6sf38715351fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:50:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502647; cv=pass;
        d=google.com; s=arc-20160816;
        b=CuPp895E0TGOR0GwRY5Yh+BMNrfq5AiSOvnJE8Mu3B52UelGo6/DcD4IW3zD8+IlD5
         GemMh45H9CqsJN9n9c44ZHRnV8NAWFyc+vUxIdavcBnyp5fJ/Hlb/wfjjY3JQGPi9kQX
         Z2tQn8qH1BBAS2QwZY8RX8HGhbBWxssb3v28UQXhQN4YFLRMrkHZ+5aFGNjA3Gyotazm
         BYQR4BrdJjaWgPyrTZYGTGjUsvvZqd9fscQVeF6Ei95vLxk7RHq740jdAq2IQG04DgTz
         rkzB8euAlqWj87/8yYpzMtvXpC/Z7EA8PL19qCiobO3advAWGczJT49vavBde/rUjeWV
         ocNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wlc1u/XUVq118CTLfcVsW9UxOjnfEAaLp4lXHsF+CEg=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=Vo9LOQtMG1gxq2tsc5t5ugvkp0+1y4HueJKiixz+Oco1zzON4lYbpqsNd0eDkIyJWO
         hX+pAobToglK1EXsiPAVy82VFbk4VcQkICFcMp9C/CXWN8UYeaRGGplolteIRo5i2dvd
         i4cSOM/f6LBmI4tThJFAwt0mgQ+UXpPzJp01Fzq1H3QTHR6by/PGKNWojOdZC66HtVpU
         KqMUKxUOO2tmwNpUOJBnRAGnTnZyODBygWX/pfH3SsH/TMzElDZ8uMXizzZk/PPT3Qa1
         xqz83wu9vd30545m3XXYZsHr1ot37RS2lThG00GaTMF06tZpalqMtCCa82WagHXWnTBx
         92RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lATFUJLN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502647; x=1701107447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wlc1u/XUVq118CTLfcVsW9UxOjnfEAaLp4lXHsF+CEg=;
        b=pSCFaajrASXFHm48gOIawUUqU+2cEvg1VUFBHhd8NVsTyapdwyZQ2IXldHiaIVDWCT
         0ohFmB1bFCIiMCs8oUA3GC62mw0xaTor+bHOL8BcUtuXVQkTMLFQp3HmWxU6WsvAl9ou
         UeWpdOf5N0BzpL4xXfnXkNla7PKoI6RUFt7QcNfaTGySIvnFtc7B0Wxc0nXVBQO6z9yP
         irb06BQhWAjMpQ7ADbFsACWeilUOFaQn8U38fTXW8WkluV0So/A61NSMxHvgSdfChNsh
         pqLOM+TCyMAySOfylnTEp+y2CGVMa8PkcHKGgeFVKEMIUBIs3zGIxngUlLd18uVvn1wH
         U16A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502647; x=1701107447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wlc1u/XUVq118CTLfcVsW9UxOjnfEAaLp4lXHsF+CEg=;
        b=ndzZfDGq3VyjtoRJ/G04Gw8MVxn8HQJCWLfh7/JX0Dn1w/GkXWpe0v7LQYbNq5tfbx
         QDk1RE2D6nG4xO0wF7jlG4vI3fui+UtupMjt3+B4LVREbg84YyuVAYpbR0WkMZ1qSJKg
         QYBJZtXdiKet5oZu3h1Go0KZCFgeI7SMyumyd+ZLy4IAraN/S292PeeI6WuXefelb+0D
         yEAGBwN5xsUkDp3gy2c5QAJ3GYJg9AfGfhLGPVaywbydm0wUcrRVUFiVzWWeQL3ZEicR
         0K6vHjTqZKEqLEq4LyJ4hlq2nJAMSrfZDhWMe5mXeqDa16ReHn1PsS+qATC/jvXLd8Kx
         L4rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxf6sbirf9pZ5CBQoAjmupHGBI8FHN1RQHaM0asz6qnmVpBpLrp
	ncznvnmRF9eaCzWfgWmWXFc=
X-Google-Smtp-Source: AGHT+IHVLD3AbzvNBzLSzeUKZzLapWmK7YFTVJVcRDuYmpitisYYLD+GsHgF+x7EX9HLWrO7e7B4Eg==
X-Received: by 2002:a2e:b0d8:0:b0:2b9:412a:111d with SMTP id g24-20020a2eb0d8000000b002b9412a111dmr5314323ljl.42.1700502646029;
        Mon, 20 Nov 2023 09:50:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1550:0:b0:2c8:752d:e073 with SMTP id 16-20020a2e1550000000b002c8752de073ls327301ljv.1.-pod-prod-09-eu;
 Mon, 20 Nov 2023 09:50:44 -0800 (PST)
X-Received: by 2002:ac2:5a48:0:b0:50a:6f95:3b50 with SMTP id r8-20020ac25a48000000b0050a6f953b50mr5515712lfn.16.1700502644361;
        Mon, 20 Nov 2023 09:50:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502644; cv=none;
        d=google.com; s=arc-20160816;
        b=xT5eSmX0X5cUcw8z23jKDvlB8AgczX4aE7gcUWhDtfkPbT24opt2s78Ex/TQJaFqdX
         KXA0woEM+YD1/2G330nfT2omKKvmt3iDanCA7ZxeqwvB3DL7J+B1/3eBy04XoOCJqCNC
         vHCLB67Z9yAx9J/0g7DpYuPAD98w2nhSv614Kqx9F02tqyOIT3Fu3LddPM26PoagnzVj
         16qa8kGBWfM0Um7odgaBVaHs2uRSHFoooApONrsvA7vC4hoU1IpdaLWemMDA8nxT4pSY
         IYdoQVMuYzPOD1hLgcZfBj5S34yugRDy3Hx+Cd6pxaRFGq9ak7S1Jq2ZU8sB9pLUFYCn
         AXCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uhMrVBrzgAoT1gwViC8KxLkH9OMZhix/uhvoEc70W98=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=pCq/uCeEnmHjqjyWbh9DPWFbhBqYuzeiGjdp88+b9NIZEtzwpv9um0ai7PQra33Acn
         lNDolzJhBqpGPkwHyizv/Cnau94WSydeDWScPvEdRpTD1hW/wXLDPvRKmRFI4K9QUfD/
         nwjXuVoAC8u+F7D1rKSPk9wNdUYhXIs+5s6oJZVN9XB1EUIPL8KU/d4nU/USnwVGjFda
         fmuC5c198oLIg1Dp8YuVCT/WTQTG/N2HEeVJp22T27oqixv5De7QLPdi6HFSPBfdrAw7
         jf8R/nQA3cB5UkL1cpW4IlDmDQsm/aSJNBQ0f5v3WoPhTDnd21jcBXnbahcA78ewjIQ9
         TcCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lATFUJLN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [95.215.58.179])
        by gmr-mx.google.com with ESMTPS id fb13-20020a056512124d00b0050a72e696casi322972lfb.6.2023.11.20.09.50.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:50:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.179 as permitted sender) client-ip=95.215.58.179;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 19/22] kasan: check object_size in kasan_complete_mode_report_info
Date: Mon, 20 Nov 2023 18:47:17 +0100
Message-Id: <68c6948175aadd7e7e7deea61725103d64a4528f.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lATFUJLN;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.179 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/68c6948175aadd7e7e7deea61725103d64a4528f.1700502145.git.andreyknvl%40google.com.
