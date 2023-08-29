Return-Path: <kasan-dev+bncBAABBSWOXCTQMGQESV2D7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 94B7678CA76
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:13:47 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3fe1cdf2024sf31648255e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:13:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329227; cv=pass;
        d=google.com; s=arc-20160816;
        b=0vhP7uPy4CrrmhzEZ1H01l1XRLYRwyzKB9dFsv+34D5bk2u24flfAY0b3SOctsa4e2
         2jnYK5SsbIgUttvHs1Wi6RmsDnDMD5m0EBVOqLLbqQkcE5eB0uz0Dk0On8gtp9p62X9X
         bLm5HbijFd2JnJ8CvUcrFi8RFXxksWGWm52SzQPYkdUOmqBqZ8omrcxPGqZImpWrzY8n
         46Ukzo4/Yqcf14yKCC5lAzVhk1XrH+2d/HMCnrz/A6mg4B33QQ74Eny8uQpNTQZyc1ep
         Gy5KrwFloeSuKVxfjybN+cFo5NdXzVYejcKP40Hwg7+WnbU7vd7XnoXJFNueH6pOFn5x
         yXvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Y1K73HF0uFOS1vU6affsPQ1nYO+32HToNAoGRz+h/XI=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=SDSiNUHHUwJ8zXvkVNeHGKqOnrtktVTMTmReGFvkkVOZrH+iJENztDMU6lNQq/joWd
         AmJ6XXVg9iu2km7N6LVETHoN4fsnDum1tyQ95lW168YBfjHYr/JHNBdaXYqknlhSnYKL
         ob4lh6bX0Xw3CfvjRtOP4z3H+R/cPWApKT7iladMzaAcT6HCvwyZ+7emAq8icr5WOvNJ
         iwmlpVkeazuV3MdnpbUennjrPWSDlY3Acbf4vJWft6z6xh8h+exb0UtJAp4DQ4dkzTSk
         M1bDYesI3+ay5x7SIUpnOthDKStkU6SNPpRf/kPRs31r7fjTcZCq+0YTTEGriMgxPskQ
         hTVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GlaqijiJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329227; x=1693934027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y1K73HF0uFOS1vU6affsPQ1nYO+32HToNAoGRz+h/XI=;
        b=obj/3AhD1rBILqjXhU1nXwljY7/dvWUo07dXeio8cq/gd1N6tV7Nkx/HQe/E5bHlcC
         VVDC/1wnVaFNZWtevDNNBcZ34VoxF0Gubg1h1X8FeWj9/98o7pClrWn5Ncc8N6qM/jiK
         e/1tFwVgaLZS4BKkAWqXL8Q00BLZUBC2fWMPKauTv5OgrQVahxKEudVN80vDZWjsUfyk
         GRP4LuP/g/2FQnGMiXSh+F6Ocrf4sVGlyM07zhOEWSu+FuHpkvtMXW9nkIVeP0mrfcQ2
         J18aga56+sNXas1TsWR0+0BjESp2BrndlYg9xkQymPaWB2Nz6dLoYcw+JXO8aSe1Wlrz
         QYlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329227; x=1693934027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y1K73HF0uFOS1vU6affsPQ1nYO+32HToNAoGRz+h/XI=;
        b=K2eiibcUYbKf3O0n4j58Zy+PM641TvL93N/gbXM9XgoXj+LQc5NhBckeQHz0KXYj+3
         A/5OH7hAQf3yJmdxPfD2lDOtBjFgJNL9Yim4GuZQYocqJmNz5mKGJLCoYL9MUSWoDotU
         67vBQzFo943MLHfMhANEZRRqOsKqo9Sz7h0YUTq77+LDQvfOdIiKWrzTmV4yVgFH4guG
         TmCG4RjNfMu3IagImafqTQ7BJxBGnlF9m3sthNJt6o7frIj3iDteOzdBWH1l9Slj02h5
         9c3emDTmS9/OXkZ8Ao33B/wREu/8spzMX6PM9k7smbz+/Q/s7fm9VKEOKpEWYTUEmaeo
         L9JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxEGl9HCcWCa5PrI0yo7HO7CrIqrNmp5X6wgL6SS09aA6zErdeQ
	awSBtdc+KxaBt6avNfSFaY8=
X-Google-Smtp-Source: AGHT+IERYoSHQEW7xyU1/vjhPbtnd/czbPerwBQ+eCv2EKGoPqfmNQqxqqgvM4mQr9iqxd1sDUQFdA==
X-Received: by 2002:a05:600c:29a:b0:401:c8b9:4b8a with SMTP id 26-20020a05600c029a00b00401c8b94b8amr5564639wmk.29.1693329227029;
        Tue, 29 Aug 2023 10:13:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c44e:0:b0:3fe:e525:caf2 with SMTP id l14-20020a7bc44e000000b003fee525caf2ls60727wmi.0.-pod-prod-08-eu;
 Tue, 29 Aug 2023 10:13:45 -0700 (PDT)
X-Received: by 2002:a5d:574f:0:b0:317:634c:46e9 with SMTP id q15-20020a5d574f000000b00317634c46e9mr22313666wrw.43.1693329225605;
        Tue, 29 Aug 2023 10:13:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329225; cv=none;
        d=google.com; s=arc-20160816;
        b=swXKSMmLCWMHlVF3cRTy2Gc6hZPZm41mVVtzKLzSj7o9N3AqqSyB7nvMEggZDj/3/G
         cE2IVJ4TDveu2gfIYnQKaZfcHNIXg9k0NK/La1h1c09eT3gwashYE27VRjGlaXApLEf3
         PbSdR3Uxy3X2IHk12tYH+sZ14eqmjNwZ4rpdj7O7Xg954Xxdffa6EZ5UZVVShZrAYWKU
         KIsbYmNEPWwot72tMSOaOpYaUH+f92DdA4RQRj7tCPduBYqsfQLI1Ow+IhtDkVu5tydX
         paz7Z6v2JppZYAcEiWPyan2vfCGVRV46Z2EcpRh89zLAlaqCCGitPOQIEtIE5MGEC5Zg
         wh9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nl/mi/sJhm8d2IDMyyx9SK432XHk6oEEQ1PTooRDAe8=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=NI5mZDFnxWapbe0GXOmuD46oippH7VvOYd5Eyxw6MqrAFpdS94OP81/siLqANMDKdP
         Ei7o3q7OBl0U+Vdy/F0x8BLoIbSAHwX+9UmCd79e7rFoV82autMHorXSseoFmU4nz1Ey
         DIf+fjaPVBasZCnKX2gEof+wq39fFAOa6LMn3upmBl8HNTWbkO9g1HONwWwtegkZE6nt
         t3Hzxg5shtqvQCZYTgWxRpEJzefIGTACRSzK251ZcOOEOpnzO/R97LtAdpcy3l2mwiYD
         IWOHp3OU2NQUL8AtGNQr8Q/+oxtNwXzuMw7Rhj0GT8o7RNuCWbFQkWGCR6Y5gHtAUkUF
         ME3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GlaqijiJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-250.mta1.migadu.com (out-250.mta1.migadu.com. [2001:41d0:203:375::fa])
        by gmr-mx.google.com with ESMTPS id j22-20020adfd216000000b0031ac9fda4c5si946694wrh.8.2023.08.29.10.13.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:13:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fa as permitted sender) client-ip=2001:41d0:203:375::fa;
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
Subject: [PATCH 15/15] kasan: use stack_depot_evict for tag-based modes
Date: Tue, 29 Aug 2023 19:11:25 +0200
Message-Id: <f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=GlaqijiJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Evict stack traces from the stack depot for the tag-based KASAN modes
once they are evicted from the stack ring.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/tags.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 7dcfe341d48e..fa6b0f77a7dd 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -96,7 +96,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
 	unsigned long flags;
-	depot_stack_handle_t stack;
+	depot_stack_handle_t stack, old_stack;
 	u64 pos;
 	struct kasan_stack_ring_entry *entry;
 	void *old_ptr;
@@ -120,6 +120,8 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
 		goto next; /* Busy slot. */
 
+	old_stack = READ_ONCE(entry->stack);
+
 	WRITE_ONCE(entry->size, cache->object_size);
 	WRITE_ONCE(entry->pid, current->pid);
 	WRITE_ONCE(entry->stack, stack);
@@ -131,6 +133,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	smp_store_release(&entry->ptr, (s64)object);
 
 	read_unlock_irqrestore(&stack_ring.lock, flags);
+
+	if (old_stack)
+		stack_depot_evict(old_stack);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl%40google.com.
