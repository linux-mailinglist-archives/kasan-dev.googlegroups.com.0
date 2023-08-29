Return-Path: <kasan-dev+bncBAABBS6NXCTQMGQE2YIECNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FD9278CA55
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:11:40 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-31c7b8d0f0asf2940576f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:11:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329100; cv=pass;
        d=google.com; s=arc-20160816;
        b=aVGYetFIjW6jZYXk7DlJgE/3DygOjXT/9hHNHpoOnk/uxDMy9yKAjznVDf8cG8Nt/b
         pMutip444Nipx/tTdpCJO5yV1mfBzOKVBmDbUpQOMzAx+2/qlhnB3pwoumR/XVS5nkEC
         lf9BGznTNhjs8G2o7L0CnGjW+Ce/KVxfGZRww5Bkp+vON2Ex3WaiS8FXb7QJ0wFpa5yU
         d90uIwPX5Uo1POYC8bBw9+evVdvdu3f3HB2zVVO9PO7BhvWmiP+CBHXuXqEsrnCBlXjI
         q0j4l9suNVTEkkqMveBXySptCLgA45/o5e58I9jn2kmo86ftXmFtXFS13Q0cAa77HByW
         94sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eUCEWnXWJTQJv1kNOzYIi595b7mSAukIO1hXb4r2fxs=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=0ha122KDEr9aZJK8hTe/nhihshkBEZSSzWL+aeQTQCgZlZQanRGE+H5gTdfBTAAKtY
         dzyOF0lcrV8IDEn9RgN4x1Glf35rf3NB2/oRefWU2KNAC/JOFah1XeKcgXPkNl7RFDe7
         +1bPkHzA7OFvd5kLib6A119Uj5EEBg+GqdmQN8YcdODOH+WNX9+5tKudL6HSPZ6kpJEI
         3+5qJ9Wk7hJBc/H6+L4+IMq801mddLGCJXtFTGAnNkLTGmer0H6jZNNBAKGOH5TU4tf8
         54HhDdcdcgycstJP4CPAsVxUGX7CY0fze3PmP8yamsdGgcoxPk9Fx0mRRzrED/pcKAIc
         fz5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vWRwTzQB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329100; x=1693933900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eUCEWnXWJTQJv1kNOzYIi595b7mSAukIO1hXb4r2fxs=;
        b=REk3mBfOPyCpRY0uCXwulnLsZt/Je+moAXqLJDt2lHbd4WVGQe8i5KlrgZ5OyYtHJQ
         RYOiISXq1JNiYL3Z6Z22l4Jf1/zlDKKwqvOPdl5+oCymXJ/NEwyf/MCDZmDHtrKTk/42
         AQqR4B6TOdV4lqCnS1R9gZWokwoExbz5lQ64Hp8JdpFbeXEJtLUkEcnmj2qVY2cLfay+
         JFtVtft08vXbr4gFruXXNelKPpElMaea3bUif217OQ3ErwqfqGnqPrhFtIisfgaA6BBo
         e7izvjavFGyUueBJHziiiirogD7521I4jwDlBGtiLoDnlt7pNqrmGs5oUuIKQnVzjrR7
         j4eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329100; x=1693933900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eUCEWnXWJTQJv1kNOzYIi595b7mSAukIO1hXb4r2fxs=;
        b=Bz99nBqFgJmjBXiNkAN5iRPHL8iP7/5B/DSwQLlGmMgkMgr0I9N7qmpy8tLVLnDARD
         jkpxdFaYVkFHIhdVwxRCRZr6ZYedWD49TMDyEFacsDhTsGWliHAdvZrhj2JOjAKy6dXu
         6AFx1DHO87dWQ3nELTAraD1l55rWRwmw4ez+G94p+TQ6WYOlZ/9h5Bz5mtDJNB9upG2H
         W8N/8r1zZQqP8qQ5i+SGVgAtNFJUVwpb/XO2/S4Qpd0ACmiuD4WPS9V0P8dXuT8+JhfA
         kSXYbSc91+vdBQgeviDqd00DI44dgc/IA8oaxFh/ZVisArygUt8z5ebF/dRIDH6aKP5o
         eiFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwPzYAf+iAytDHJyYv2TK+SNrKFZJTOChcuTysDEMwywB8u4AyC
	5SESvNsmiDFSPKPtciZ6NYY=
X-Google-Smtp-Source: AGHT+IG6R2yuwcNrtIZ1Wjw6f710MrfWohMSSnz2HQb4d5azxQl/Zn+lkJ+y5qVIpzimV+TV0CIXaQ==
X-Received: by 2002:adf:ee41:0:b0:317:6220:ac13 with SMTP id w1-20020adfee41000000b003176220ac13mr21845307wro.32.1693329099891;
        Tue, 29 Aug 2023 10:11:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:53c2:0:b0:313:f4ee:a4c7 with SMTP id a2-20020a5d53c2000000b00313f4eea4c7ls2089359wrw.1.-pod-prod-05-eu;
 Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
X-Received: by 2002:a5d:5a9a:0:b0:31d:da10:e477 with SMTP id bp26-20020a5d5a9a000000b0031dda10e477mr729147wrb.8.1693329098642;
        Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329098; cv=none;
        d=google.com; s=arc-20160816;
        b=MqnVL5vH8VSG6KsBKpJnPlccvzSWK18H1djGiVWSgey6zyq7ACn8PzNrIOJ2/QfFix
         J/WkRvxc5S57IgN/FCd8RwBRltTC0JD4FkDxgHBBnc/rOuyZ57sVp0xOJfhp2gQxEZuZ
         XJSGM4hBme1Xjht9Oj1V4I9tDZBmpbIgkvu8GHAM41lli3F5XnTLmXIxZphM9MtxTH0D
         NcEHWeertvl1JM/2yv9XWSmFZ4lFkDKeZvH0GEMVPizj3MHKgSJISx0XXTOXOqsiZyZQ
         9XwOlrwJdrHDNIlxAEvQ/HEWdd6eLK/6ky4bUWRhBgdWQy5Pzac+H+bJuAhoD3RC8JH8
         Silw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=etRrGOIqY063bnkRK0UomaeBxyJpZf9uP5poWvb3gqc=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=MThH5Rus9L9Mya6b6Mm5NF/Bk9OnjDBAA/43m3wab2cqjifQye7dcyVcE+QFmETjNs
         T2XYrsBLDqjOt8ZVv1EnzgeYBDtFy/2BadSgkxCp2ai8ceJpiDAMa+5OGVCOSzpqrKK0
         xhhYBGrVPGBNowzwFxAj5xYJpofG1Cy4YaBK5pKlPjhku4xW/af7Ng6dmsIKd0gBsNXy
         3J3JZRo3rzokqh1glnMKYqMFyyavv4je9HotqiWlkkTjFgsNJCBuF/1PrP+q5hTrasDj
         Yc8S8fcIis6jCguNtfOYKUEDrA3EVgirQdxiqmaDAGbZeBt8jF8j2+ilAaBY2Qo/akxN
         6cKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vWRwTzQB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-245.mta1.migadu.com (out-245.mta1.migadu.com. [2001:41d0:203:375::f5])
        by gmr-mx.google.com with ESMTPS id bn12-20020a056000060c00b0031aef8a5defsi889423wrb.1.2023.08.29.10.11.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f5 as permitted sender) client-ip=2001:41d0:203:375::f5;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 05/15] stackdepot: use fixed-sized slots for stack records
Date: Tue, 29 Aug 2023 19:11:15 +0200
Message-Id: <89c2f64120a7dd6b2255a9a281603359a50cf6f7.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vWRwTzQB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::f5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Instead of storing stack records in stack depot pools one right after
another, use 32-frame-sized slots.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 14 ++++++++++----
 1 file changed, 10 insertions(+), 4 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2128108f2acb..93191ee70fc3 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -42,6 +42,7 @@
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
 	 (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)
+#define DEPOT_STACK_MAX_FRAMES 32
 
 /* Compact structure that stores a reference to a stack. */
 union handle_parts {
@@ -58,9 +59,12 @@ struct stack_record {
 	u32 hash;			/* Hash in the hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
-	unsigned long entries[];	/* Variable-sized array of frames */
+	unsigned long entries[DEPOT_STACK_MAX_FRAMES];	/* Frames */
 };
 
+#define DEPOT_STACK_RECORD_SIZE \
+		ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
+
 static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
@@ -258,9 +262,7 @@ static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
-	size_t required_size = struct_size(stack, entries, size);
-
-	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
+	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
 	/* Check if there is not enough space in the current pool. */
 	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
@@ -295,6 +297,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
+	/* Limit number of saved frames to DEPOT_STACK_MAX_FRAMES. */
+	if (size > DEPOT_STACK_MAX_FRAMES)
+		size = DEPOT_STACK_MAX_FRAMES;
+
 	/* Save the stack trace. */
 	stack = stack_pools[pool_index] + pool_offset;
 	stack->hash = hash;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89c2f64120a7dd6b2255a9a281603359a50cf6f7.1693328501.git.andreyknvl%40google.com.
