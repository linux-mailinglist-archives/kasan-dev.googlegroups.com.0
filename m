Return-Path: <kasan-dev+bncBAABBIUT72IAMGQEYNO3MLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 830E54CA8D8
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 16:13:39 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id cf41-20020a056512282900b00445c0a8069bsf24206lfb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 07:13:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646234019; cv=pass;
        d=google.com; s=arc-20160816;
        b=T5TwPT2H9H4WYLq8pQY8JEsk4YmgPt4e/YO7XhoVSDTTVeWNLOLFiOhQ2ebS7NNT2j
         9JAfdQiE2qUXruZ+x2zC9jh2/WqX7qJJfUdC+u7Rk2sH30pTBKXeVWmJjR/94yjCkSXq
         RpzeNPILadLmRqM1MnpjpCfrH+fLfVdqv9DBdwaAlMAS8fFOMzNdMcvq9yO3T1oVZX/X
         o/Y5XIl1AypnRhX/6IOBf/E+WiBmSRaGwdYzccWR6iici6n8goq4MPASb7lOWpnG4YgY
         iCXn6Y1qB79Ps/PykGq63eNaSFwVAuIjHvu1NajI2TFsQouyLHewgB+lqgtXYj4lglYA
         SZOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=RZx1tJObvW8oGBgm0JqSEBNlC/UYc/Vk/Gxix6UJsBo=;
        b=teS0oOMiszDfp4HHQH8dUvPYfsoAAFOoYxLolVvIGSu8gpR9B9PzuKdlne3XMRudmB
         TM9qKebm6MWv1bDx1cE1cWcSbcomSqUKkwQiPJq97V4BiEpqkBk56FBI/PcDxfTLaytl
         OgZVdrOa3w/irxPd9rrbme7iqv/QrMERnoFJyikW3OExl8/XEYfknZJuOE6OJD9PMdm6
         YecavMmhQ4OF4Et+4vpbqcnoTorQeIdk2xPFa9XwTpBirAKPFXQgoyt/AuGGVUKzi+GN
         pT8L36QxbNtOp/V/Eh0k66MrtDo6DHV8KTjik4M75mssHwWUZKiqWmBsZ5K4kM/bMLPY
         KlSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="pf//kUiq";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZx1tJObvW8oGBgm0JqSEBNlC/UYc/Vk/Gxix6UJsBo=;
        b=RnWs5+OxQHrfWEo3d9Y/XstgW85COXyeNWrjSKrdYT5CxRFKTQ6mR3rd0RstluG/W8
         0bnagpqwPq0KanY7rg3Whwu+mS+5lH4TrWRkAFlwKOQmNZ86Hepf0SE/GMlpguWgyXYJ
         3ZLm3xQrUpZXcT7V6XISSSXwFUUG3j+bGutmvMeUNRDVrdcZ6yqJNAZAYIRyXTY59B+8
         GrXq/I62lsHgdShIfcmjvNiXJllajUuqe7ZsRj22DeKChFN64Ucw3WQwFerH9ZJvL2NV
         hPviCrBBl18VU3vYFkeaA9ZJTCTzrwC4144YhwgyQQujvg8rHFkcifyxMvNAAleURvEO
         B03Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RZx1tJObvW8oGBgm0JqSEBNlC/UYc/Vk/Gxix6UJsBo=;
        b=r/ADwXtjTCIGKvkQIzim0Jn72oo2DQrxPrFX0Haf1pgAJzZwWz1eKuuRC2maQofF6P
         Ni2eMiCizV8EhCgfXGHMR31Ij4DBmIw2h12RGtINTB6FCl144fcsR3S53MunsRz3ic0C
         3YRDAp3k5S5x4CFSPqMa3Do7NyTAPsMaklkimtPaydpgAMUT9v5BwViBlLUdrPlCfiC2
         m6LCpFtCcWg0J1BnGoHlhdo7tQNQINJ4o20vox06S6WfkzGRmVbwQOU94LkMLIbAe8b0
         6BS1hJZDO/fDNtXUvW5dAK8jcWfuPSI0bCJxuQiWMyybUq/tz3JiACuvAj20r+OCT0Fs
         8yfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XtWR/P9skMrc9K18Aj2K8fpuHUQmuEtRSYlrQHTQ6AIOripb9
	cvNs4NDOCe2SZafZo9inp14=
X-Google-Smtp-Source: ABdhPJx39r++ZNfV3csm1ysEwnpCspBS273a/trtp7/FWr822uoqhJZlU9OtIIobqm5ia/zdU1cWOA==
X-Received: by 2002:ac2:554f:0:b0:442:ddc3:73e5 with SMTP id l15-20020ac2554f000000b00442ddc373e5mr18679091lfk.64.1646234018893;
        Wed, 02 Mar 2022 07:13:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:443:7b15:f451 with SMTP id
 bp35-20020a05651215a300b004437b15f451ls303076lfb.0.gmail; Wed, 02 Mar 2022
 07:13:38 -0800 (PST)
X-Received: by 2002:ac2:4150:0:b0:441:39dd:922b with SMTP id c16-20020ac24150000000b0044139dd922bmr18741096lfi.340.1646234018076;
        Wed, 02 Mar 2022 07:13:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646234018; cv=none;
        d=google.com; s=arc-20160816;
        b=hBxD2zV6p/cOCRxhkTUN48lx+fcsM9EVwgiBDeJYyj9jTiWMqldOtmVbPcFfJ4urMR
         6PdJzi1/vvS6tkHSd/Q14gaGFdk6TyOKiWeVz1kIaVB24XuY5BDgl+R9fNNJxA5v5eeB
         gj9TNWcJUouBRJ/SGKmvJ1q5/FBRphCP5ngYjvHkCwcys2hd7tz5WK1S7TJiAWJh4lMx
         H7ovue6Bm1DikQFsKEXwpy0vfLowZf+pebhJy9U8NiffVePD4lfiMiD+nHw0pRRwwQ0K
         zXhuQoEnhXiOfDiH8rMIYsXPzx57yI7dmpDr6D5uFTuXLH7SdrTTowzuKCckUQWtZUu+
         7m2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=yvhkHe8ffV7l7JQy8kWEX/L6d0v7GNlMNTEjcsXtnAI=;
        b=F94TeTzhFj9Fw9cJC0QNiHWskliZx3TBnd55+OZCDhn9/sn8Jcqg1yhhLbTyvb5mTE
         miTizYXCNEhL2ZZ8RHygdUbbQGq94G6JEr/ppggeJ6cH8Feose4ajJXGkcsqmAIVefAK
         JRwgJHbtfWzBRDK0dBlWG1MOQpHO8+k6RDKXjjL0uJuPBN8Q44yMfAeJtNVoWlEYs/IT
         sw2+mzELTPBTW3WexLaNzv5T9UsW28I6voEULRhR9z7hw8BWJHTmj64CGTDXRu9Vu49O
         HDvAW+lqxi5IbJNgZF01HgSgJZkJ287x/JqVhmecKcoNAkvrTm41RPQmfOFG///kRDNF
         J7KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="pf//kUiq";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id f2-20020a2e1f02000000b00244ddef9705si786978ljf.1.2022.03.02.07.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 07:13:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 1/2] fix for "kasan, vmalloc: only tag normal vmalloc allocations"
Date: Wed,  2 Mar 2022 16:13:30 +0100
Message-Id: <9230ca3d3e40ffca041c133a524191fd71969a8d.1646233925.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="pf//kUiq";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Pass KASAN_VMALLOC_PROT_NORMAL to kasan_unpoison_vmalloc() in the custom
KASAN instrumentation for Shadow Call Stack, as Shadow Call Stack mappings
are not executable and thus can be poisoned.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 kernel/scs.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/kernel/scs.c b/kernel/scs.c
index b83bc9251f99..1033a76a3284 100644
--- a/kernel/scs.c
+++ b/kernel/scs.c
@@ -32,7 +32,8 @@ static void *__scs_alloc(int node)
 	for (i = 0; i < NR_CACHED_SCS; i++) {
 		s = this_cpu_xchg(scs_cache[i], NULL);
 		if (s) {
-			kasan_unpoison_vmalloc(s, SCS_SIZE, KASAN_VMALLOC_NONE);
+			kasan_unpoison_vmalloc(s, SCS_SIZE,
+					       KASAN_VMALLOC_PROT_NORMAL);
 			memset(s, 0, SCS_SIZE);
 			return s;
 		}
@@ -78,7 +79,7 @@ void scs_free(void *s)
 		if (this_cpu_cmpxchg(scs_cache[i], 0, s) == NULL)
 			return;
 
-	kasan_unpoison_vmalloc(s, SCS_SIZE, KASAN_VMALLOC_NONE);
+	kasan_unpoison_vmalloc(s, SCS_SIZE, KASAN_VMALLOC_PROT_NORMAL);
 	vfree_atomic(s);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9230ca3d3e40ffca041c133a524191fd71969a8d.1646233925.git.andreyknvl%40google.com.
