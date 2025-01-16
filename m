Return-Path: <kasan-dev+bncBAABBHGMUK6AMGQEDU72Q4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B3BD8A1330C
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 07:24:29 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-436289a570esf3623855e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 22:24:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737008669; cv=pass;
        d=google.com; s=arc-20240605;
        b=MRmT14/fUplpDAuXRJdKSFnSmXsljfss1uT/1h17LQ29SL1CN3/pzrTxEtvm7Xr014
         OOsiK5Rko4aFQVgHAbShEuU5qZFIBY+r0brfCKHZmaTkWyt5ro0+IjOwAzFhQJgKkJNg
         XfCpNusG7YYari/n0rN7qlUC+UimASUJVebMXPgzC6qd2GU/JZ8lP3uLWItFkeWte4SV
         3HFLtzrUyaKZDFtGBFNjNSNAcwhP1iSlYKz3LTQFtFvCFpVHdYLPXiuTaQuiGbdA+TsA
         WWZQW96QLUbjnNY7FQbWehnvltJ6TxXifd+8fgmTwmvbQfAG71dVFIM/niuwM7DRpILY
         MUaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hXsCEKBOb50hIJWO1P5KSNPFBIdpfHLQ6HrkohKa+ng=;
        fh=x9UuzHlDRsZ8O9yqnbgjFnVxjz3j7nB/O3OMBaQ2Q48=;
        b=bwXyVfhiOsbU21EWtmGZTWh1Qomppx9aFz2PL5twidP1h+NHuM0Nq0fz/0qS7hxFg0
         KIKXFkTG/MSuHIDayoQzUqYUb9YeqJ9mWfAZDWHETezFynJ7k67EsxBUju+wyLqVPJRY
         cazYMXoFt+jLIapNI2N0XMTvlHFsv1sutNSX2LLn2jdJyiPf0lFjynkuLYp8y/tfrYko
         P0KLX7ZxSZfxewm8Qa1l/ZaDvCT9gFeuNhUUYctjC+lPaG7W+7dagghbxKKXQ18vcEtr
         DeuTQjt+H4AIBb2mpSPi4z1m9rxTqvhevmnIAwBItF6L9X9vK0gg1jAt5iBRcJuzA+M+
         o7WQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="DV0DSjZ/";
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737008669; x=1737613469; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hXsCEKBOb50hIJWO1P5KSNPFBIdpfHLQ6HrkohKa+ng=;
        b=fZMOuFR8ZUBZoVgurNdGsAtKu5gUyce+7lofBsKswCSfurB6rY46NKatJ01q4X1FAg
         CM4HR9OQiMiCUIXCFoUjo4mzr0tBs1GRxSkZuWgOVOiPyUGWwNr2eWPW3OwueeUhssKQ
         OxwHgs8d/2zFJ7pQ18ddKbKqc3u3yRKG8KfTPt4x9Lm7PaT/ttcWuhDzTIMXMc9+05KY
         GXqZOlaEsrnPEX6o+eWvOChHSd1Ab6DusNHSKv3yuY8peADpTx52bjbOJClS1oEGT4BS
         XXbjmHO0bvGrfT3F1bnnhHl5illT75nd6KQE3xWsORk0pL1Klci03CVjLdgxWGwrb/QJ
         kO+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737008669; x=1737613469;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hXsCEKBOb50hIJWO1P5KSNPFBIdpfHLQ6HrkohKa+ng=;
        b=f95PMABgcT9DQv8zwniCW+PCzef9w1iu93PK61aKudhYrN3Mk89A2ZRqNWX/OO7ulz
         3I4EO9evdjkzW4aLBZTCA5omIs/8cS+IKD7FSSXoUSvgA8Ga5OtJ3BTZk597Otwj1GMz
         Ls+Pcv+oz9ZlcIaDjayASEOwjdMpuLTf6ZgsH08VLtUMsEad9T6IYWoeqAVWGhiEQ2Bk
         G8s2qlAMFaSSUvJrxKYR+8UlbLUdWD4n3tqbrn5S/lec3NDtw1fvFtYRH5LQh5S05A9G
         +4NuxURULPq765+pe/lVyOfEj9eCP/nbPGXBtyAoeFtyUBuonl+l8RY2f5RP44eaUXX+
         ME4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2R2VHHwKLz+S7u8C0NLwPUJM+xk6PwEaAj3MB0C2neQkxr9BgUJHfoMjV3xa9ClYywchzog==@lfdr.de
X-Gm-Message-State: AOJu0YwPza2Cc+b1jzN2BjuHUGK54zlaPtWwHIEWd55Gz13LJVqaWpo6
	/LRbiL3tZRdagpwPar9hMT8HRTHEUaDF1tfvnrvkOad7oRHL/LxE
X-Google-Smtp-Source: AGHT+IH2nqR+K2DlWInPKYWVwV4ikS1FH/9Wqr6olN06UNXr+/oWWICLGIPRsKitSAK+lPFLZg1A8Q==
X-Received: by 2002:a05:6000:178b:b0:38a:88f8:aadd with SMTP id ffacd0b85a97d-38bdfeba01amr11345033f8f.53.1737008668537;
        Wed, 15 Jan 2025 22:24:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:293:b0:436:1e5a:fae0 with SMTP id
 5b1f17b1804b1-4388abb7718ls155685e9.1.-pod-prod-05-eu; Wed, 15 Jan 2025
 22:24:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWsoF2OFohslzdrmDCRG1OWxrprO+/m/VhTiTYjzsxDznRMD2CyyqKZWd+AVl7vgsDWckrfbV7tadE=@googlegroups.com
X-Received: by 2002:a5d:5986:0:b0:386:605:77e with SMTP id ffacd0b85a97d-38a873572a5mr29324971f8f.49.1737008666534;
        Wed, 15 Jan 2025 22:24:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737008666; cv=none;
        d=google.com; s=arc-20240605;
        b=JNaqrkO5TAmPRPQqfwTW7PQnxWFOfVPqFvWIhRmUJKRVUcvKJLGZ26VWd2xXR+XRqp
         eqexZIG7mK4GEuDC7uqdNZWhlR8n5I3yvcJYS7xwGfHJ5aWeltgXjfgbiRW9QUyRJjHV
         z1e8zRbu+TH81QZY+ZCOFYCT3J9DhR6WKNgTiIxzIav2GNh1DecEob5XN4Mo6BCtkiYJ
         H67WM3arRM8LZzY+I9vP1Zyv5dKLGptJKA8RwMJRb9c+JgAnTbGQ92sStrZlh1G9OHs8
         AKbwirqGeokXtAO/wAv+BtULdygSaDxPj7RsbzFr5qzW3UfTUofTHk+o79k88jLYg/V8
         2PdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3FneSeFdw2NxMz2mVRv2+KuvZR12hGarmr8kvBvl/8k=;
        fh=JFq/eZK8JHF6utRa265LQQsEKSEfbHrhjf2bY/xbzPQ=;
        b=YBzbD4MfkB5vhlz8Ye+hqlu/Ndoy3tTH3kHCXlcTvX0UsGI/pVdevLUuBkiNjA5xDQ
         BKhYROofFha9yQG79byvR/ZMwFGwh4nh5yxH6RKYADH6FVUu3/pJ7i3WuD18fBjPaDdg
         UbqKp/lq3kIEC4wwE3ktSeEg8uvqtEtlKt1yQrR5TQ9te6bXXccCPl2t6EVa+48TOBmK
         EGEwWgUSNOvESH69gY1CiUExLd0dPlFVGpifDdbkP4Mt448MS1pvO/mv+P6pjIduZ6N+
         0FbkVCyP342/UpJAFLEEIAHwlinMbDneWP97IvCgkmUd5rG184rZrYXcPFm62hqDjXkz
         bVEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="DV0DSjZ/";
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta0.migadu.com (out-181.mta0.migadu.com. [2001:41d0:1004:224b::b5])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38a8e49302fsi347842f8f.3.2025.01.15.22.24.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2025 22:24:26 -0800 (PST)
Received-SPF: pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) client-ip=2001:41d0:1004:224b::b5;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Thorsten Blum <thorsten.blum@linux.dev>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Thorsten Blum <thorsten.blum@linux.dev>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: sw_tags: Use str_on_off() helper in kasan_init_sw_tags()
Date: Thu, 16 Jan 2025 07:24:04 +0100
Message-ID: <20250116062403.2496-2-thorsten.blum@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: thorsten.blum@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="DV0DSjZ/";       spf=pass
 (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:1004:224b::b5
 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;       dmarc=pass
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

Remove hard-coded strings by using the str_on_off() helper function.

Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
---
 mm/kasan/sw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 220b5d4c6876..b9382b5b6a37 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -26,6 +26,7 @@
 #include <linux/slab.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
+#include <linux/string_choices.h>
 #include <linux/types.h>
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
@@ -45,7 +46,7 @@ void __init kasan_init_sw_tags(void)
 	kasan_init_tags();
 
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
-		kasan_stack_collection_enabled() ? "on" : "off");
+		str_on_off(kasan_stack_collection_enabled()));
 }
 
 /*
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250116062403.2496-2-thorsten.blum%40linux.dev.
