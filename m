Return-Path: <kasan-dev+bncBAABBW7ITKPQMGQEP7R4URY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id C12D969290D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:17:16 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id r17-20020a2eb891000000b00290658792cesf1854667ljp.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:17:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063836; cv=pass;
        d=google.com; s=arc-20160816;
        b=se1/tMOV5Q+BrDE+lbHFnn9yDtFwtaHk7RTl2mE17CYMi/ngVXnJVkL30JCWMDXhrG
         Q8vwr3o64MI2svaRooukkzv6PpGLXgNYrHn3gOeNDsTgArQ+2rtdil9X7HrhjW0dCx+0
         xGbsoQRXfN8lxUavDRPmtyLuB5XtvWnJTdhTjZCG61yvaJEkWKIbgSSetXHm4Qr9rGHo
         sWjcxnwLZbLHWRUPsV8/hrfY1M90Fp3KBv9n720fZRRKYjuyU+DA/btPiyA7NFyaJNyA
         3De6R0d76X4RCQ0H5IKHSPiBt1n+lehp9BwiD35W1MLsEPrG4hWcMx63nqwTfqJ23Br9
         EzLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LRuS3x25L76dWYFF+NcyhfZNRftHPbQHFf9c6v8BqUs=;
        b=yJ95ZzZc0uYMllFFcpfKosNoKkC0lFnoS/LhkTWNIG1oxpg/5IiVAnxeRs1rjuSvsH
         0SMgUnlxBvrqyBRUMXiW0ZxHPkmE0v3f9YgiSfV2cuDlCXikXgro3pGtk5Mp3HeG+AkF
         P+7WDNAhusRvhXN+heeA0sZe60fItvpzHRqE9SRNXuy2CeVHlMDiGYGNMUdSChUosKU/
         d3pxAEGII9HdMkPp/LJw4ABqF6QGtyKIlQGUhBGj063Pa3kGenlO89IHYPaiZ9QHRpda
         5enYtv/TFtnc+7snKASLNygCbVp/LqXdl0mpcOciZFlM4EkA9rBO33gB3vFy65oYGN0n
         0uIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="gCrR/J+B";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.49 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LRuS3x25L76dWYFF+NcyhfZNRftHPbQHFf9c6v8BqUs=;
        b=LgUSyUKEjOBqYO4N3etApZfklI4iTLZl5CuGUroHCxjHKWgpBsAP6cFh/soNfIhuCS
         bHJzqbj5/IWVoeAyDuT6GpJtj3dUzxExkLQ+mV0nqA311XL+e80HKnvOfXolmyJqgmyL
         moDNI1d7pGZVYH8KKC8vtZvaTz0YDxBluZW9JV9PaRpD3p4G5Kwzd+KjRwh2W1a58/6+
         5Olqp5Ur8Msrp1UQq0s13ayTsDWJ43JSmADb9KpF7MyULhQITHRe2Ynn5orOEG+/WVN9
         /a29YKzEX8UmjqYLXsSZFN8qEtp8PJs3B3YlOpGRxy3LRiy4U/3H92xESSyXtlZ3WzGZ
         aSQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LRuS3x25L76dWYFF+NcyhfZNRftHPbQHFf9c6v8BqUs=;
        b=vrONWk4TUaM0YoSdbgPN2/gNZ86QvpHiOAUZ8DhN0wtUwmXQ1shewg8hHAX8jTj7+a
         MIkzdb0QvwyizQCzFMoBqdWjV3dG6SaAXm8L2Bf6CxSLzdm+zxhlZdNv7lOMaP0p7cVG
         SAj8qW/gLPgevqPMryRJzPLmpkAVW3dSUkBlVEQYX+rrcSnp5HMLR14DnBYh7AhXsbxb
         BeTZ/VluQVo0IUa6hLgt6+MVjWN36/4Ye+/3/Eh0RKE2Qq5fdFvF7kCUWrwFZIiGu09T
         990AnKlAy5VrOvHl6GTpqW6On7dfOoMSlLHFpZov94jSZKsvUqXnnrp5rbolZUhqfOJL
         mGSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUYBJCfJeITmmD2huZXBghIhKZmBU+b6oqbUPNcPkpGzyoPN1fp
	AUOcvi4/+uXT20Jv/B9WeyA=
X-Google-Smtp-Source: AK7set85hLddpzinsQFgLuRYkkIWik0lDjZtu/lCai0QqqagfmaiaFF0ik65lby44Jn1Ek3LetJQ9Q==
X-Received: by 2002:a05:651c:38c:b0:290:637b:e410 with SMTP id e12-20020a05651c038c00b00290637be410mr3200316ljp.117.1676063836329;
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:239f:b0:4cf:ff9f:bbfd with SMTP id
 c31-20020a056512239f00b004cfff9fbbfdls4336554lfv.1.-pod-prod-gmail; Fri, 10
 Feb 2023 13:17:15 -0800 (PST)
X-Received: by 2002:a19:f00e:0:b0:4db:1b30:e634 with SMTP id p14-20020a19f00e000000b004db1b30e634mr2044028lfc.65.1676063835095;
        Fri, 10 Feb 2023 13:17:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063835; cv=none;
        d=google.com; s=arc-20160816;
        b=uj6B+R39kEK4sr2TD4D0WH5xCdtwO1YPe2WdGBFVrVbzJ494zgyJbGc2UE8Io92CdA
         VprnhrSPrvHP98qLdZ09c4k1Pp3L7/OrgPguSk9i/MowH8Ta8CwRXwdxlw45n2og1YGP
         b8k9HA3ZsLmd0WFYZAWL5lJmfpBfvfLz477e6qYJl3LIArU0W+In6aPLp6wIpnYhRQXf
         7gR98nY25fEXm9JBuYzMYUmSfvolxgD6d+qxGOZXrbWzObAraZApdOgNONxkGCjX4Roy
         tBORG0Pbfb+8aqaz8o1Vj0SHIaopWuM9o34EdCijA0o948n1X8boGywXfLo0XodRnRla
         CQ9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IMmtEbwX6SEFFs7KeDaMCDunDTh7JDSXGutwuFTHEE4=;
        b=r28DEL67ck6xr50hRILuIBlYeP6XdRzY5ZmliksXLsNdMNA8WNPJ1pCXEK7mc79TiE
         9hGTwKrThKB490aZxiBVhhoDy0LH0oFelUqyEIjBrDp9Tq7r9yYAH6ZdVZXFpbWkKxNy
         rHRfN3jgBSDeb5NFdO/JGxeZ01sk+jzsT+ldGzMvRfPlYqbW5wvUrCZEZNc4appY+Mih
         /9a4wG/UopYQqIwNAcON1I0gvOT9aF7p+U+aMOWeAUduUuTVSA3+LPtSKdtwxutkdDIl
         458DATaHzXbcYMVBsGcjpDMMutsjoLKo+sBJxW/9O+SQ8bAATNXfYt0HAex/yhQDPdn3
         R2Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="gCrR/J+B";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.49 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-49.mta1.migadu.com (out-49.mta1.migadu.com. [95.215.58.49])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b004cb0f0982f3si316525lfv.4.2023.02.10.13.17.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:17:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.49 as permitted sender) client-ip=95.215.58.49;
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
Subject: [PATCH v2 07/18] lib/stackdepot: reorder and annotate global variables
Date: Fri, 10 Feb 2023 22:15:55 +0100
Message-Id: <5606a6c70659065a25bee59cd10e57fc60bb4110.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="gCrR/J+B";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.49 as
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

Group stack depot global variables by their purpose:

1. Hash table-related variables,
2. Slab-related variables,

and add comments.

Also clean up comments for hash table-related constants.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 27 +++++++++++++++++----------
 1 file changed, 17 insertions(+), 10 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 3c713f70b0a3..de1afe3fb24d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -75,24 +75,31 @@ static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
 
-static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
-
-static int depot_index;
-static int next_slab_inited;
-static size_t depot_offset;
-static DEFINE_RAW_SPINLOCK(depot_lock);
-
-/* one hash table bucket entry per 16kB of memory */
+/* Use one hash table bucket per 16 KB of memory. */
 #define STACK_HASH_SCALE	14
-/* limited between 4k and 1M buckets */
+/* Limit the number of buckets between 4K and 1M. */
 #define STACK_HASH_ORDER_MIN	12
 #define STACK_HASH_ORDER_MAX	20
+/* Initial seed for jhash2. */
 #define STACK_HASH_SEED 0x9747b28c
 
+/* Hash table of pointers to stored stack traces. */
+static struct stack_record **stack_table;
+/* Fixed order of the number of table buckets. Used when KASAN is enabled. */
 static unsigned int stack_hash_order;
+/* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
-static struct stack_record **stack_table;
+/* Array of memory regions that store stack traces. */
+static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
+/* Currently used slab in stack_slabs. */
+static int depot_index;
+/* Offset to the unused space in the currently used slab. */
+static size_t depot_offset;
+/* Lock that protects the variables above. */
+static DEFINE_RAW_SPINLOCK(depot_lock);
+/* Whether the next slab is initialized. */
+static int next_slab_inited;
 
 static int __init disable_stack_depot(char *str)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5606a6c70659065a25bee59cd10e57fc60bb4110.1676063693.git.andreyknvl%40google.com.
