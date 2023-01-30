Return-Path: <kasan-dev+bncBAABBLO34CPAMGQE7FR2HNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E17BA681BC2
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:50:53 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id l5-20020a1ced05000000b003db300f2e1csf4905951wmh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:50:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111853; cv=pass;
        d=google.com; s=arc-20160816;
        b=QCotoPhIPV61jIfRxjNq3b2msaF0AMCbiejbFeinJ2J/TOpkqeCkjZ5fL5B4dkiApS
         du8SPysfdotTdryaVSXXjhV9ZzxGdLOV5w54RQPQjym2r83V55KPF0pZ15sSeO/9jFBK
         47ezTwAhu08flU2APP4f+nlZ9/9PdoghTUk3tEACWNzptg4+e9wSGE3HnwNL6BzMCMuK
         JYHyfD9+7hdBOxfdjdPc/v/3ei/+fqrZ931xLArsTQHWPSO0EcTWT9zdiW5Hhdu/4Hkm
         sVLMsi8TYJ2BLSMTolvc5bL1QDaUygk6hcaYBOgntfgjF4AeeMeqFC+BnkI/m9eR12vA
         kG0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nPGCkrLH266z39+ju1Nino57aCae9mggPWk9YhoIV/M=;
        b=gJIuEh3GJBpHfHK3lFt0mMtAs3rV1sl1AgnEzxoybq3dMZMHD8AyReynIempav9QGs
         kiY7LPoy2MBZJcmNxSNrbxIxOcOX0LxCYxdMwANWwOW4feSWoqlQwof27WccynnoPc8C
         6PvGuEIrNYhH3+DkQp57Mahc1DWkbgqKdYPpGH/kPY4GNRhFOrI7MlyJpTwodZW0DRoq
         LbD9MQXYkatLa5slTMpGvt+G38oWAKmyS0JvkPU9t37U9lNwtgXFG2T+YFIeRxn9rqgd
         BauO0Pk5QfkiXQmtI7OpmdPGz+ObY/s9ExYsAnzQgk8Xjt/PQUjrKDxvw23qnLFnhmOM
         acnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=X7HUu+4V;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.197 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nPGCkrLH266z39+ju1Nino57aCae9mggPWk9YhoIV/M=;
        b=J2OsQTVffbeCvs68UlC6j4mbwHAYrpNz8ge069aFtk9Uk41tqrGrG63S5cvQkoDJQo
         9OMDb7AhQ06YL0Y6redo3Q02Urm/Dbdo5pF89L6G6SihBbESrkFAh0yn9frICQ0Xwtqg
         Ec7NTR50TFcHdnBBvExuLFDAMHYKzGBKP/mCjIGtMOyE2zTaCl1mB/flUWqyJaGrRdd5
         Z9yhqH+P/FGS2dbWzB8GIO25wAxjbwQYOLuP/xmI6G4AxTkdRhbLA0t+W1KOWUlB16On
         eoOl0oemg9ObGKhdgUw3/Uf8PiJE3x1krUo7pGgev32tZWst7wLh4nJstfFZY+FoEnuf
         fOvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nPGCkrLH266z39+ju1Nino57aCae9mggPWk9YhoIV/M=;
        b=rFUclv5hAUHCoHRjw4S2ksPixv4xKUwbHIVvYMkoBjtSa8KXrU7/L5uxe9nhnU0q4A
         69DeqB8IYJQY8mnNz6zZlwEy4wvdFr9ee2di9+ach3XhTAqaUiKDhXoeRIIXgSN8W5eq
         pEAiEdNnEqaaDC254r7u72XTaqIByemfdIKBzNnd+s7dtRX18T5TkG18HZjKFxIhDT51
         KXJ1boTbwJHrWiWqJlU4nxXQzY5Gl/Uc+jkuxTSc+nDm3ffyV/lmQnLEDJ7ErDKV2g7D
         O+xp2lSjxvHFwiF8cTh1uDiS0LjHOy10ASScwsuk7QYvbuqMY/fXkDHVU2yrzslACfaj
         xTjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVc/Rqd4fRriYRgq2a5y4sSFDccc2osk1b5ryfakUmho26VrHr1
	Rbq6mWtmuDtyl8aHU73hBxk=
X-Google-Smtp-Source: AK7set/So9PWgG9h7+Jxgs+U1dkkKRgnSmeUcgjW+VexLDj05NCWqgTdYjb3jQ0GTelwUuY9DFoolw==
X-Received: by 2002:adf:a45e:0:b0:2bf:becf:7b92 with SMTP id e30-20020adfa45e000000b002bfbecf7b92mr557015wra.166.1675111853504;
        Mon, 30 Jan 2023 12:50:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ccf:b0:3dc:5674:6707 with SMTP id
 fk15-20020a05600c0ccf00b003dc56746707ls2555849wmb.2.-pod-canary-gmail; Mon,
 30 Jan 2023 12:50:52 -0800 (PST)
X-Received: by 2002:a05:600c:1e1f:b0:3db:2063:425d with SMTP id ay31-20020a05600c1e1f00b003db2063425dmr42755709wmb.2.1675111852608;
        Mon, 30 Jan 2023 12:50:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111852; cv=none;
        d=google.com; s=arc-20160816;
        b=Mxzb2pVwgfjCUxFLTKsEk2z0HGdeqoHrjgDr0K84QteVhSkZvLGjlYFr3pF/8AbpK0
         glzrWta4wHpBg9diy0GPfu6MuQuNwwSsIeCHE5j7RlW8Ki38xa7pzwux/h0x9MdgUrzA
         zLmVPVAAzrtc5YrO0LndVRsrW+T08HEVr2qdssvKpiIL7Os0+qo/MtGXeObsN/RcuYNQ
         b5RGMNQVaNN7hGqwUm48/nbDrJuANxDzYJP8dxbASya3bGTQ7zRrwkiBgmscuEQYuH1L
         5bz+lgW1nVijnipsBU/4YSeEWt34Lc4hfsWFwc4ReMgBmzWeENPUdWS/wU6dVc1isq4o
         TlsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OedhC/9cTS2mJq0ENA72OMR4Ifsg2rHWEhi+f8KNzJM=;
        b=j4fdz+cSIMKkH4+D9u5nCypFGCa/hSG4wVGWpNWQEo9P2BuwB9Mh3HqlCgtESTth98
         cPkuvsjwv9c6v0AE/aGfdksh0AipqIVpjnammQglJTHwAEdrm9jEHORdsGoPg868m/lE
         MeQBTwPKdZeW6g5ylQtyl/7KymzLjBC5yBEl44GYuduT1/OQBqHpNOP74t6WbmV3HMFa
         UvFUTozLC3FlNqh1fpHF26xrS2BcWV3zz9jqc166BsdmJXi9mnr+mgUmhElaiMKginA6
         qHZAP/UIvYRJDMl6hf1jeQA1JoSYEoBV9Ez4rzkvhlrnliIOMcTo9w3pgQ+8aqdizydf
         K4hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=X7HUu+4V;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.197 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-197.mta0.migadu.com (out-197.mta0.migadu.com. [91.218.175.197])
        by gmr-mx.google.com with ESMTPS id ay10-20020a05600c1e0a00b003dc537184cfsi328945wmb.1.2023.01.30.12.50.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:50:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.197 as permitted sender) client-ip=91.218.175.197;
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
Subject: [PATCH 08/18] lib/stackdepot: reorder and annotate global variables
Date: Mon, 30 Jan 2023 21:49:32 +0100
Message-Id: <4ed1d0828e837e15566a7cfa7688a47006e3f4b3.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=X7HUu+4V;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.197
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index cb098bc99286..89aee133303a 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4ed1d0828e837e15566a7cfa7688a47006e3f4b3.1675111415.git.andreyknvl%40google.com.
