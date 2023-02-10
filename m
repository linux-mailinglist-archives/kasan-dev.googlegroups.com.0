Return-Path: <kasan-dev+bncBAABBHHITKPQMGQEPRFEWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 235506928FF
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:16:13 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id z12-20020a2ebe0c000000b00292f8b0b433sf1854945ljq.12
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:16:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063772; cv=pass;
        d=google.com; s=arc-20160816;
        b=v8I5R7dckBRyUVYJYycGAuS2mKOXF/ofX17xkdSlGvsUGC3gtTVkaJoCyX1Y8tTHa1
         oo0VwLfLbQAS50NhaLOcPCCRPQtgcG3thWeCRyZevs6vEuHUSNnf+IRoPY0xAkNFjvfc
         zu410QGPqkgRkJwe9kxV1IynuR9Wtrux26zijG1KtU75+LneC0NFYJgk5EZ/7VOi5UgQ
         2ZXGv8fVdYd0uF6DiB25LIZAL03Wl5dN6nb35a3XEWKe9J9zqlJcHQvOnsusZlinTFTt
         DxyAgzuO28hyUzyOv/OaG4BOVlOqeuYSr+mTM1W08atSAdEG2g2fJedv0Km/TOmi3XMk
         npJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0wRKVoSYCSDRJPf0aC5K1cgN+Wriklv33637poO9vOU=;
        b=dhjFrzcBc5LsiUsZAdJhVKJH7jBREy58COYsuZOXK3mlcJ5LYH5CnOSI+4lFz1jrHI
         H9u+e2Yzw39R4LGHLAqcqSVjxkHhaoM+jDNC9SyB/ui1OTqaVZlTzMXnQokrZ8w4twIk
         JUGQSCFdEFj+sQiIsWoacnlE0RMWhsDV/CdzbSGavXLhUh4Qsbphj/7y4Ason4RhAE3v
         wPwtKioMpW49ZxS5ydAJI8IdiAStyGVNgcQHnqQKf/faFyK6rw3oc60W+G3CGsi87jAJ
         MUI37OahTJ3STQM7rdyFiv37vzKRHFX+Dqpo+wFjgBf2DNuhUdXyZ7g7ZF92ifHcxxNW
         OLPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Lpp+lB8h;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::6b as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0wRKVoSYCSDRJPf0aC5K1cgN+Wriklv33637poO9vOU=;
        b=G/G6AyxRQbxDNF1gMH3euK+M1OJKCwjHdk46MAz+7tGCyWaD8RT/sbv7Kk14Yrc0Vw
         OGy4aoh71to90IJU9Nz9MeJG4vWRYRbl9Ht9ZQuG3DVX0qW0d6K6brLidn6cR4DsgxSQ
         JiQMP8SYmL0Z5qOzmnvpQkg3zDjDnDa39QS1iCfVGb0HYZPSdY5NlSxuPNphXdPX3Vxp
         ikTNHaZGn4WV+M1qSschH3I3cJeYqlekEzXfFVMS3YpKnJVf4vkwRRO+p6ACXPdp2SB8
         FrlUirhiwA1pzyX5U6+LABlLHlXluF5IsNWKOGDmXfuP8l94ZFQ6e7MphxXOCOJ62oOf
         0D6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0wRKVoSYCSDRJPf0aC5K1cgN+Wriklv33637poO9vOU=;
        b=FNm3ok5h36ZrIsWJyvYVG7hRJa//GPYfBRbXrQEotge6GrCIfe/zJHTenX5NsJkjHN
         WQAG90DJyN7l+Ejzi3eEtEoIwfRra5mNBIFgpWCzwek+TtfoxApzpDzlxc2zKxPSxpKh
         4rDAkR+YhIEmlL1bz4Z/a7IxOSOC3PetOd+xiBlJRI0AX5X6+R5yCAlL6XSwQfULLtr9
         805KFGyY7ryTJkjF4Agd5himZh7dRc5dqxCSzwwIehwXHCabr+RB+DpjXI/S1nHXEX2x
         rX7F+o9Q4nw9w99sjO6p4oX6qiSnY/BAI5Z509n587P5SReeHRmDApUHYCoMwNRYkKMR
         Jz1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUX2+AchqO3kB0ZWmEwmsI6JLvIXnxrRd0FBGvXpO6UYmFBO5n8
	VgJTDzg5Z/f65Uwu0wiG2nXc2Q==
X-Google-Smtp-Source: AK7set/2amJ38wdrO1qV5KwjLvCcGyreX0qImddqCtk0TLWSSTLsoO967R8bMqy32W/McmU6UHY7kQ==
X-Received: by 2002:ac2:52ad:0:b0:4d8:5290:5ee8 with SMTP id r13-20020ac252ad000000b004d852905ee8mr2897792lfm.157.1676063772650;
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a907:0:b0:28b:86c7:a456 with SMTP id j7-20020a2ea907000000b0028b86c7a456ls1110713ljq.11.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:16:11 -0800 (PST)
X-Received: by 2002:a2e:7e12:0:b0:281:fc9:16f8 with SMTP id z18-20020a2e7e12000000b002810fc916f8mr4300082ljc.32.1676063771450;
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063771; cv=none;
        d=google.com; s=arc-20160816;
        b=iVT2zriY+bNis9LI5WcvUiclry8Ezf3khKUH+QnyPY8qWW++mxw5WeaRA4XiGTtjhX
         YIQX2rb8o8itX7aJKVxFpv6Xx6Z/ctWEILJ5WYr7af1vACMetnLd+WnNrgHDD1zhkq7l
         z/Nlj9ZikbmpylrUS0kTYDPNLSL7pouEbgxbURLAWD+AsVvemx1uCwLe3eA0NSL2hTBl
         t84Cf0KXYKktcIYVyQZA2VV+Ro/kRgcJvUJFnc2XFWPCO9I9vBl4K0JE/8MBgy4JPpge
         jtLFXQMe/giV9un8vKkktVEbhL5laDY0sD4YlEkqPLiY4i/TUkGpoclP4lZQ1IaQ/1Iy
         M5Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=z1gm2uHZDO3x8BSiOJ0jeaJz4iOmzsaE5lyAkDJqHg0=;
        b=G4rw/Uuo5Uh+e5Ge3tRIEmtDDPBIeOK2gthxEKPfQB5FYs3frd0P7HulvT4NFlbHTv
         nbj/9x6Mn9hA2ce3ixANLWGppJ/6oMwtqArCyTcXLesfcy5vByUOcyNGaVW5R2YjALfJ
         3pHFO1KEdo+jkv+QcUzaO545bNkkZMevcoWbrrLpiIQshD4+jhQGc5VCULO8Lxb9XH7a
         ZYNWEfz50NbdlGXUyWja6vYYomLbSnWN8KTlYbSSEKr5qmTvEBRrdPjY7zH3cSP17fe4
         P8DeJp/q8IBWCvbnQTCErxNsyJM0XxEUmwgvy2Y6Vf1aoAAGgcvpW3T8mmnzpx0EJiKB
         61jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Lpp+lB8h;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::6b as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-107.mta0.migadu.com (out-107.mta0.migadu.com. [2001:41d0:1004:224b::6b])
        by gmr-mx.google.com with ESMTPS id b30-20020a05651c0b1e00b0028d88cd79a3si265970ljr.8.2023.02.10.13.16.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::6b as permitted sender) client-ip=2001:41d0:1004:224b::6b;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 02/18] lib/stackdepot: use pr_fmt to define message format
Date: Fri, 10 Feb 2023 22:15:50 +0100
Message-Id: <3d09db0171a0e92ff3eb0ee74de74558bc9b56c4.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Lpp+lB8h;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::6b as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Use pr_fmt to define the format for printing stack depot messages instead
of duplicating the "Stack Depot" prefix in each message.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 4bfaf3bce619..83787e46a3ab 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -19,6 +19,8 @@
  * Based on code by Dmitry Chernenkov.
  */
 
+#define pr_fmt(fmt) "stackdepot: " fmt
+
 #include <linux/gfp.h>
 #include <linux/jhash.h>
 #include <linux/kernel.h>
@@ -98,7 +100,7 @@ static int __init is_stack_depot_disabled(char *str)
 
 	ret = kstrtobool(str, &stack_depot_disable);
 	if (!ret && stack_depot_disable) {
-		pr_info("Stack Depot is disabled\n");
+		pr_info("disabled\n");
 		stack_table = NULL;
 	}
 	return 0;
@@ -142,7 +144,7 @@ int __init stack_depot_early_init(void)
 						1UL << STACK_HASH_ORDER_MAX);
 
 	if (!stack_table) {
-		pr_err("Stack Depot hash table allocation failed, disabling\n");
+		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disable = true;
 		return -ENOMEM;
 	}
@@ -177,11 +179,11 @@ int stack_depot_init(void)
 		if (entries > 1UL << STACK_HASH_ORDER_MAX)
 			entries = 1UL << STACK_HASH_ORDER_MAX;
 
-		pr_info("Stack Depot allocating hash table of %lu entries with kvcalloc\n",
+		pr_info("allocating hash table of %lu entries with kvcalloc\n",
 				entries);
 		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
 		if (!stack_table) {
-			pr_err("Stack Depot hash table allocation failed, disabling\n");
+			pr_err("hash table allocation failed, disabling\n");
 			stack_depot_disable = true;
 			ret = -ENOMEM;
 		}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d09db0171a0e92ff3eb0ee74de74558bc9b56c4.1676063693.git.andreyknvl%40google.com.
