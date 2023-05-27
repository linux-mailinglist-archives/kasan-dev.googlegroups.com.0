Return-Path: <kasan-dev+bncBCAP7WGUVIKBBMGEZCRQMGQEQ2J254I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B5CB8713575
	for <lists+kasan-dev@lfdr.de>; Sat, 27 May 2023 17:30:57 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-33b21c93c9dsf3192095ab.2
        for <lists+kasan-dev@lfdr.de>; Sat, 27 May 2023 08:30:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685201456; cv=pass;
        d=google.com; s=arc-20160816;
        b=ennPrf3sUUFCF7am2l5LmoTzv3LyE9GGMrPdfIZp4laW38xAJflYnjwCCtrs0wQvY5
         0wt6VTvSHih6CuEmwkM9cYbr4ELZ2jwrd11kbQtz8m0GKERinRfwy9OkV4FpVGN43ZgW
         siugQ8EsfoQ2hZkoGB+tDuoNsFv7nzvFClXBOvj9+NLfe6Zk5UYFw80CApm0njZwQ5jZ
         spzjMJcPafRBzjiPDhmXww6sn6g8o1NdIwu06uIyzeoIwdP26Jrc2v8/Es0T68T/+WNi
         frVhrzOTVINxOE4WmA/fgAMEiD8xQ7+NDKSR/PPHsVb3UGMpGOay5Zl18OfkivqqCFiS
         xXKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=whL/xw7yIQL2PNuja6OQ6dF38uGC03MOIm/14qr1EhM=;
        b=UusqOUcy3BdFGv2m9MLIxnmOdNZcrrdQddX+K6EeH664Ojafo3UGg5aQXumKBO1gfq
         /2EDCdR51iYYdl8cr3bEpEzIijhx1hW401+TWtShxMoIyioqtKkfiJY/8Pg6AnPXVoHk
         /h4n2sisQp3AJADTwN6kb013r7sbUwnBMwz3lXbICUO32Va/nATswfsZ+NmMVVlH9aQe
         lkTjfYyLai0tg8DHf5Gaq6G08+QX99Fqpj/TDaKERlB1/UMPeDPEgzSnWHl67XicXAqz
         1kd1FfLKvYq0w3PeVE4eE5NlOOKxI0GBSqEMu6tUXcBS3WSerro5EIteeHCBsgNoTvDp
         nHvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685201456; x=1687793456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=whL/xw7yIQL2PNuja6OQ6dF38uGC03MOIm/14qr1EhM=;
        b=YJ/TynvyTC354u1FRPd2gpJBK3i5cuXSmzN/HWGAtKEfy8ME+Rx74lqKeQMvFOWLFy
         VV9ngGfc5cuJXV7CgIemzNdR/R/3gZRKeW4zAc8bQxGQkIjnoXS+n94TVItI2FjM5Xzi
         /T7f9h0vaCZiGpAsuVjRZUMGcvKcvTqVkNix4e0HEt9uXDgOpfgfY5RpUNSL6tmsNbLM
         sOJsNT8RbBTSJp8V1FFIemByABHhE5zIXx8wE3bkPvJ57hz59bHNdD5WHZ+ym1knlj3f
         Su5f5251yCO8jiDFmi7qjhzWMFtcCdunRb1whcklNtgJuBI3pX+rgCUgTjOn3tVc5BEC
         +aXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685201456; x=1687793456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=whL/xw7yIQL2PNuja6OQ6dF38uGC03MOIm/14qr1EhM=;
        b=MuaF9Oiqq954AVnjTcqkfNQdoaBBHfmA9XEWnnTNiDdJMrB5thZsHSMFiJp7LrCHAu
         PYYf3F5rthRqBIk5Gx4S87oSIgKNWY61XB+ehEjRLAB+vMFyDFpQKwdYF00UydBxhKqO
         iCNe4ucx3YHCGIj1f56rE/p9HIk6VrXuwpnlX8C8OofDzoFVGt4dZ5pHMJTCkKDpcYgy
         dCtuagMumV+S0Op5Heup/famNf4Pq07kXgvA4vY4iSFv2kC636dk/cH2vEUl5vpFE0er
         UisqEdHNxClHSOQ34b8EsBlRfeoaui9peopKPVt2gYAuCNT3gvQTQCJPn6dPBGzQKxjj
         WYUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy20qnHTTsB2rhXi71P8wdiAYsrUIwe4Tyw9X2idzqmEiYQPcfn
	mTbllw0Hw7LkFmyOF8ZCKDw=
X-Google-Smtp-Source: ACHHUZ5Cd0xHDT1A3+VYNt6+uDrsHpfwZc3HNDbig+azXagRfMiqRHhhemIsl/W5gmA4HOwuQ7FEdg==
X-Received: by 2002:a92:d1d2:0:b0:331:a813:8b17 with SMTP id u18-20020a92d1d2000000b00331a8138b17mr489493ilg.3.1685201456451;
        Sat, 27 May 2023 08:30:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:505:b0:336:1c16:1cd2 with SMTP id
 d5-20020a056e02050500b003361c161cd2ls1235686ils.0.-pod-prod-03-us; Sat, 27
 May 2023 08:30:55 -0700 (PDT)
X-Received: by 2002:a92:c848:0:b0:33b:b94:2519 with SMTP id b8-20020a92c848000000b0033b0b942519mr2096346ilq.14.1685201455593;
        Sat, 27 May 2023 08:30:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685201455; cv=none;
        d=google.com; s=arc-20160816;
        b=PluS5ImfnvQ2KQXPFqVG+Ur4lkG5kfFvQGcshPHn+cNogE0dyiWLP7P4k3/c40q38h
         56qLLAhtNOyMvg1coA+HMYer1ZyQZAP1NHsF576JyKlZzFn+QdIitYFMxf5xh3PHr78t
         p/R2PWske/Ie6evRf3AqZQ5ou0u2mwvE1O3RU9VpTqpcrzDzMQ2DiPlQbOGmLd3+EBeU
         TfPcGyLf9QJDSf6Ngzglh8v6Si9QRSD6xlsX9iuANOfBHIjoSPDd3nCfhp9AEKke+jxt
         uGue+6P2kQcwX2agFr7tF8DiX8fLK5VDsddGDqOKchVTvWDtHspu0BDt4HsA+ZB06A7Z
         0mlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=sLVYHbXLr/f1aU52ldro7ocetcpgnwpOHlnDhJtPcLE=;
        b=hQCTX7wBtTx8n9UzM4QaMkoURB4nB0P6B8KbU/0b5CYwGr2MifKnITHMV0w4FNuktv
         zffaWS6+TasHo8K/GMYkWru+WhmJ/6/mhxpiuK+ivQz5ZvFvBJMk4K+sRHA+0lJ5dCtq
         3tJhXOUEGnRScrPEuw7720OJIaFBIoUUoywFLOCuZ/PuJXMZIz87YaTdLtIK+L+0CrHF
         TkbpE/JJ1ugXrobk7dT6pL5rHt0bgPw0dHmk6cby4gSzh4BW6muDS56S7FOMbYkKQth/
         oFEGqmJG7wLz97FyQsrkgpcoQoWzz2so+idTsxJuUdZzSNDo2qjlD8JVSgBe/auXft7M
         kXzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id g11-20020a056e021e0b00b0033a915e4e48si201650ila.4.2023.05.27.08.30.54
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 27 May 2023 08:30:55 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav314.sakura.ne.jp (fsav314.sakura.ne.jp [153.120.85.145])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34RFUZME078764;
	Sun, 28 May 2023 00:30:35 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav314.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav314.sakura.ne.jp);
 Sun, 28 May 2023 00:30:35 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav314.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34RFPWLC078150
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sun, 28 May 2023 00:25:32 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
Date: Sun, 28 May 2023 00:25:31 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.1
Subject: [PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from
 kasan/kmsan
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        "Huang, Ying" <ying.huang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
In-Reply-To: <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

syzbot is reporting lockdep warning in __stack_depot_save(), for
the caller of __stack_depot_save() (i.e. __kasan_record_aux_stack() in
this report) is responsible for masking __GFP_KSWAPD_RECLAIM flag in
order not to wake kswapd which in turn wakes kcompactd.

Since kasan/kmsan functions might be called with arbitrary locks held,
mask __GFP_KSWAPD_RECLAIM flag from all GFP_NOWAIT/GFP_ATOMIC allocations
in kasan/kmsan.

Note that kmsan_save_stack_with_flags() is changed to mask both
__GFP_DIRECT_RECLAIM flag and __GFP_KSWAPD_RECLAIM flag, for
wakeup_kswapd() from wake_all_kswapds() from __alloc_pages_slowpath()
calls wakeup_kcompactd() if __GFP_KSWAPD_RECLAIM flag is set and
__GFP_DIRECT_RECLAIM flag is not set.

Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>
Closes: https://syzkaller.appspot.com/bug?extid=ece2915262061d6e0ac1
Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
---
 mm/kasan/generic.c         | 4 ++--
 mm/kasan/tags.c            | 2 +-
 mm/kmsan/core.c            | 6 +++---
 mm/kmsan/instrumentation.c | 2 +-
 4 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index e5eef670735e..2c94f4943240 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -488,7 +488,7 @@ static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, can_alloc);
+	alloc_meta->aux_stack[0] = kasan_save_stack(0, can_alloc);
 }
 
 void kasan_record_aux_stack(void *addr)
@@ -518,7 +518,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	if (!free_meta)
 		return;
 
-	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
+	kasan_set_track(&free_meta->free_track, 0);
 	/* The object was freed and has free track set. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 67a222586846..7dcfe341d48e 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -140,5 +140,5 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 
 void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
-	save_stack_info(cache, object, GFP_NOWAIT, true);
+	save_stack_info(cache, object, 0, true);
 }
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 7d1e4aa30bae..3adb4c1d3b19 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -74,7 +74,7 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
 
 	/* Don't sleep. */
-	flags &= ~__GFP_DIRECT_RECLAIM;
+	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
 
 	handle = __stack_depot_save(entries, nr_entries, flags, true);
 	return stack_depot_set_extra_bits(handle, extra);
@@ -245,7 +245,7 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	extra_bits = kmsan_extra_bits(depth, uaf);
 
 	entries[0] = KMSAN_CHAIN_MAGIC_ORIGIN;
-	entries[1] = kmsan_save_stack_with_flags(GFP_ATOMIC, 0);
+	entries[1] = kmsan_save_stack_with_flags(__GFP_HIGH, 0);
 	entries[2] = id;
 	/*
 	 * @entries is a local var in non-instrumented code, so KMSAN does not
@@ -253,7 +253,7 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	 * positives when __stack_depot_save() passes it to instrumented code.
 	 */
 	kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
-	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC,
+	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH,
 				    true);
 	return stack_depot_set_extra_bits(handle, extra_bits);
 }
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index cf12e9616b24..cc3907a9c33a 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -282,7 +282,7 @@ void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
 
 	/* stack_depot_save() may allocate memory. */
 	kmsan_enter_runtime();
-	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC);
+	handle = stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH);
 	kmsan_leave_runtime();
 
 	kmsan_internal_set_shadow_origin(address, size, -1, handle,
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/656cb4f5-998b-c8d7-3c61-c2d37aa90f9a%40I-love.SAKURA.ne.jp.
