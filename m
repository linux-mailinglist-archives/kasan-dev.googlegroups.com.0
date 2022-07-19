Return-Path: <kasan-dev+bncBAABBMPO26LAMGQEGWBKJ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B84D4578EED
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:13:37 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id f9-20020a056402354900b0043a902b7452sf8766107edd.13
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:13:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189617; cv=pass;
        d=google.com; s=arc-20160816;
        b=LRBTwJh8UWAboZzrMH1wBnm0P2y/CQ1yMKLQPYznyVsqH25ab1lAVgeDyIZj9wCJie
         pR8twZ+LZ7O3AJ0KoLh/8F5WwNKl5pyGy0nqqCCzddlGZ2678DTKshHP+283hhHyZMQi
         uqbSeS1vfyVilrLT/Q0mdV2+p+QC3iOnajL6dcLeDxqYq6DmR/MynVA6P76PdmmbA/tn
         9VvmC2+wzSc0IA5QsPcBe3dDo0fLiL9A5fpT1B4cXMij3iHjbR1n35u+f97/6q4AyNtH
         PxuiJcXQ4jrONjbGBfiqNHxV+2DdbHT9eUJcfySwCVmKkwL+F91799o+C5p1wo7q4hwh
         Sp3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LleRd0USbvj8gqADG5GO6k8a5yipDBTu4JmE60Fp3eM=;
        b=u+RoE6qdW/c61mzECctjByz5Bb7RYpuVSc00NhABGgcPEowfGkTnL8vzt22IMGkNfS
         /FiQqR5dEFq8xnkzy8Lp2on7Fn/uEodIjQjde5opQOjt1nX6/1B2g5b6qKIeDYoel4DY
         +x2C5Z9d+p/Zuz8P1KiRIf4VxFN7NeipoCZ5qrRoVJgXCOcA4l4P2vzHp1tz3zje2q1x
         +Df2AusGA3RpfbB1+HvY7B2oCfq6dQafeffBM7jVso9SHUJXXUEYHwpMqRsGeobBVW6g
         2mncjCawnvbKjaR/f6z2z0RjMp+5v7gu9O8rW+HET4Khp6nX0AdHKjAibP1U+f4Z+rdw
         /keg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ez4NK3MJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LleRd0USbvj8gqADG5GO6k8a5yipDBTu4JmE60Fp3eM=;
        b=my6oN8dRZPEIep90N3CvYuSxKjdnQVOKCUeW8E7AY/BSVsI2a3RNy5KRbCbfYkzBQY
         LYS5Wn+JRSsf1gwwawxvuoRgcnXd4YOItGILSl2b7F3mQ7o4nny24OOKo9NgiosUWdku
         5iIfQBRb0Dgf2P93D3ZWoDDAOzc5JiWaK5kwyMKcOGpU41L12OBfQV2LHarIuFqx4xcx
         LFtQmVgft5MxE5LoOSVkAnwpxHvpbf14CeQ25h9+eX9E0NXpthWuIhSZyjVZyWOQv5ds
         UmacxVMDj5C59N+XhLFrd9f/PQ3EWsrKYMvB+o7zvsfaxy7YoBPMYDIrFfbE2QxVVcJh
         sO+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LleRd0USbvj8gqADG5GO6k8a5yipDBTu4JmE60Fp3eM=;
        b=mWZ8S9jwX8mVEt31FENJSYHlzhRn8p/hdqFe2PkoiQdxRhlwI0z93eyyJkt6V/UnRQ
         TRKuf3UN2Sbs+FIKYNrkGjKX8xypCkKwxdyq2u2XtU8bwbvzuwyVgnH+qfx5eTgIrVM2
         6zkXc50GxMib9jYz8P+YAmtulDfggFhlKeNr5XGh4itn/50YIUj/mDTSjP6/x9EaUwMv
         vNe6QaGKzJTHCrGe7aKIQA22BXm5MKTIv6oyxoS3NjUXDz2+hZoLOQ+KJwp+7f2Go5rg
         oSsT+u2msMjht2LuscjnPqRAPl9eO5QzlVtf/kdxwzKrGWaGjgI1ykl3fb3oECWQDCk6
         kZlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8ZvaJApas0R0oJBCv2Srn/P3njvTFVOPGG2BbNMQIEyr96bPqa
	rt307Dj6zEye7GBiPXGPmKQ=
X-Google-Smtp-Source: AGRyM1t/ItIwN/+jxe0pIJjQWJLvHx1EM6ssb7a3Qc6PBGGDnd7UJGqWmVyJwvJCvUMm3UX42tYfyA==
X-Received: by 2002:a05:6402:7da:b0:43a:6fe3:b7a9 with SMTP id u26-20020a05640207da00b0043a6fe3b7a9mr41166481edy.410.1658189617409;
        Mon, 18 Jul 2022 17:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:d0e:b0:43a:6e16:5059 with SMTP id
 eb14-20020a0564020d0e00b0043a6e165059ls78304edb.2.-pod-prod-gmail; Mon, 18
 Jul 2022 17:13:36 -0700 (PDT)
X-Received: by 2002:a05:6402:6c2:b0:43b:b89:3c31 with SMTP id n2-20020a05640206c200b0043b0b893c31mr40418002edy.239.1658189616667;
        Mon, 18 Jul 2022 17:13:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189616; cv=none;
        d=google.com; s=arc-20160816;
        b=Nb5xb3TslksqULEjHk49cLFlkDnbcM+XFcUKLsGL2B29lDVMM8EkUxFPalR9zmcc9Z
         teVaa8iHVrpTsALUYjSOZlLIKZtFmyrzhXUClTUru8JLwjrbYuh8p9Ws3Zg3xuGAT2L2
         yVkNbxsrws2QtYaQu0YX8rdTQGUcYhVditcldr9x+eQ0Yyfk/miJJl/PNBx8rbmCqpd2
         2cFlNxqPxfoxD2JCKiB49HflV5v6XgwMSMg1Uk24fyMly1RZx0tqG5XK7CfNKz9pH7jK
         T4cnROL0pvZeqdxT6yRHKYSBpdXaZJPvMUEhh2wyhCRZA7zWARk/ayACJaPlYOoPFaZ8
         J2Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ewIngwsCZaE/TDWKEzevD/ov9nRjvr0Ni51fNvRF6vM=;
        b=Z6vVezvH9cHApJQ2WVj9x0F2sPcZ7ZrUflSqpCL3e3ZZqcg0oCTOKLgg1uZU44S4qy
         e3Hq6Vyu2OCfbEiX21G5tJRAfGos6Jz8lhQZ4CtSQQEe5FHOivwbB/Lm/EWVpbGNRKtW
         oEZooPlVdDsG/N8nXKdfkzrUJ8P3yQlK57812Kqi+11wkADshk9NXtxrf1kMjm2cESj/
         ZwmfoT0B94OxGwokjtnavi4jp/IpQ8RGVcW06KkL6oRp1i/wEQocBTSZNU/dmETNLOZ4
         tVd4DRlK0Arqn1hxRkPBxvaw1f2R50RCwIr894psdqLjBzDITzlsPNuezOr/hqxC8+J4
         zz3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ez4NK3MJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id d2-20020aa7d682000000b0043780485814si397977edr.2.2022.07.18.17.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:13:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 21/33] kasan: cosmetic changes in report.c
Date: Tue, 19 Jul 2022 02:10:01 +0200
Message-Id: <7b5f4b94b922c1753190886d0b6984bc1c16828f.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ez4NK3MJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Do a few non-functional style fixes for the code in report.c.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 11 ++++-------
 1 file changed, 4 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5d225d7d9c4c..83f420a28c0b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -200,25 +200,22 @@ static void print_error_description(struct kasan_report_info *info)
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 	pr_err("%s by task %u:\n", prefix, track->pid);
-	if (track->stack) {
+	if (track->stack)
 		stack_depot_print(track->stack);
-	} else {
+	else
 		pr_err("(stack is not available)\n");
-	}
 }
 
 struct page *kasan_addr_to_page(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) &&
-			(addr < high_memory))
+	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
 		return virt_to_head_page(addr);
 	return NULL;
 }
 
 struct slab *kasan_addr_to_slab(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) &&
-			(addr < high_memory))
+	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
 		return virt_to_slab(addr);
 	return NULL;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7b5f4b94b922c1753190886d0b6984bc1c16828f.1658189199.git.andreyknvl%40google.com.
