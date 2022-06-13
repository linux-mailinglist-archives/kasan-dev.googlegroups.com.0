Return-Path: <kasan-dev+bncBAABBIVXT2KQMGQESCQZUYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 85502549EDD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:18:43 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id d37-20020a0565123d2500b0047c62294e85sf3509023lfv.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:18:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151523; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGoizbLA582vzFJ2Ph1qiVIf8zrVBz36Y2BCZfyCZgfQ2/b1rtBOHjrS3Q/EbRCeEK
         gwHcrfg9JviLawRvnsmiXLxrmxtDQIX2kKg8MK3Vsb/WKUeEySN6vGoAK/uhGw71VWbV
         XI0uzLyM9IxkT9cjFd4viOvOZCNQiu5Ym/9p/mrsiXZU2osllGbvxmHF1X+9Kokw1FVy
         FV8bJ4uEe1z+himLhiFATBUdKtKp0sDrcDI/ra2Yu4e/h05mKEKQaPK1Ysojw+CDelJE
         38Ua9ajx2jPuFiaTnzt9G31twiEj75k7zm0GoQ0+Gtve6Z2IJynoSnHnAvwRv9OHKu6G
         6KBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Yceo5XC0f2+pDirU1P5YhWm2IDtEzHwaSUc1FBDnaJA=;
        b=SgIqhgITuT2qllFJVG88U0sCp20ZOmgvj04zMk3hWmwaX/tRt4QzYw7a2gWPX29xtY
         nUPyQMr2seOCOUoePkBDhlyAqPNHyB0yc+rCcuLf/o3GlRncc+qK+oYUXjMWzhDqaOnI
         wM5pqyPpsD5fFGkdTYNU3wMznngPZn6ez6eTdiaA0HXOlDkbGRmQUKvUDtGpLarb+LNA
         CWdG75XbIV2RVFbpJkx4e0q9MgI1uO999f9RP5KW1pznuozvHAokRTEvhzEYvPjjamac
         BzlZC/8lJGYt1XGOB92iRve1BrzUZeKFgey9iGj0z9a4kge8z7AOrmXZN6FmVqzZT5i9
         BdOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ojnNMVl0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yceo5XC0f2+pDirU1P5YhWm2IDtEzHwaSUc1FBDnaJA=;
        b=WiA/cUuj2v67YfBgRKgTcsOkUNYWhYbWtnQDcccHztOwWR41wDeM/TIQmR84h8QtaZ
         WVVKIdy1M80kl66CKCnbxq/s6CjrSDuSnKrgxkVXzkfa1EtLXFN0XAwCuWVJOxvVpf4m
         Qc9Z12mGHKqfvHKO+M9/eKhILDQKAxDBbeWS3OISf34YylRwluMbEhDc4MM9V2iRS3gN
         lza0S9dYLWWhEXyxogNTtNW+/zCjpL1OisMt0wAp9L6RSeZjMqzf4gb1y6uQ9EBquR+u
         Py98hBOv2yBF6gYe/EogBfaeCW8TutBwAdFUcDnhVmuFj5jR4sFUdUbZ03ysK/BW5X8k
         g5Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yceo5XC0f2+pDirU1P5YhWm2IDtEzHwaSUc1FBDnaJA=;
        b=RBP+JUJkOCx/dBUwZlTxz31ya2WtVYmI9IgoKorXV0Lg0FQ1di4TZd2Hz2hCsdWJew
         dhTGb1e5nbCx3P2oUl11MAT/2RaWIyCxy2BVKCAvLNZRZMPBeuBeSEJ0BbCf51zKFvDZ
         kUPKAeed/1KEjenwsmdwvGOG1/JYN9cnAmlKqSBFQ4Sadb2M7AsPNRTnGmFW8a1YBHXH
         41k5U4EDVObjdd9c1+EpBE0B8ryPNBiKa8PqNC+gnNSvI4sYa5xJII33sHNMXSLXWwvP
         XbEY8eRw0090qow62KYCVxiZfvhHX+qviUlYNPqSQTej+RUEnU+kgEW/sBfTOTrYhm2K
         yD+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9yduYIPIvI0Ww5NbMKV5bNEN8kW55cycNqsAreTenz+Bkfq5Gf
	NTgzcXJA4D7GfCfuIFN5038=
X-Google-Smtp-Source: AGRyM1su3z11NXXFuLdaHXPUK80DhZ9V8A86IRLRVReh4OSA/TZ7yXW1Ol/xFNENUjkNh7qY9blGrQ==
X-Received: by 2002:ac2:410a:0:b0:47d:c967:e81f with SMTP id b10-20020ac2410a000000b0047dc967e81fmr976753lfi.116.1655151522963;
        Mon, 13 Jun 2022 13:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls186730lfb.1.gmail; Mon, 13 Jun 2022
 13:18:42 -0700 (PDT)
X-Received: by 2002:a05:6512:3d0:b0:478:9aca:4a06 with SMTP id w16-20020a05651203d000b004789aca4a06mr881231lfp.410.1655151522283;
        Mon, 13 Jun 2022 13:18:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151522; cv=none;
        d=google.com; s=arc-20160816;
        b=vuEGEUYoQDj7H9Bz3s4mATHLplRs/fA8uhEBAY1EtLKT4VG3D1JLNBcueLGCfa2vyv
         QwmjXPZU2CN88PpHj1IOdHHFlrPTozI48GTWM52DMmysdAt46I49kk4r5sYuKXDF3znG
         YAPfFrJ8KYAqS3C7kBCl8Mlh6Nh1wAC8k1Hkfgv+DHj3Pns2ilO9Yntsxlzwu7Ne/6a5
         hX66zlYm/EsHXbgIjzNw4uvyJJiwmPRhJ8vbDS4kHfHnbyqJ26mM8Vj80B5pliTeziUI
         BNv0qxRbeZbMnUhexoN2OlWADpAPR7SM/i2gX/kv7ENwAQust2qPE6pdJUZFwcDjuA4f
         CXjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Iixdi0aUzLucxsbCg6IG+LbS3JzcqWGK/WM+ZRzVqS4=;
        b=qalMq/zUme+LjYFiD6zdFa8VtzA9kQuJQliJlCY3HYSy/h0mGN7nk2R+eaUlid0ko4
         ABQUqMjbmoQjz0S+eqKa4t5ApPywnVaqL3IQqn+N0df996e0XmYEpHwjNQYEkOjqRgbH
         NG3K7JouHFqSFh0QyeoskThKta4iLbwseI7T4fTc7KMlTYY87yZPp5XRkuCUf82s/T3t
         dMe6CABV1MArOrMFhisNoxPlARVNSXZYvO8yerDAmv/AwFbAK8a+2/l80gYh2T64uWPa
         VHrx7vUuaGA+/GEKj/o38OBD4wxcBkrOcWwbMQn6VHJzuPHlYOO87tyVGOX799yPSgsb
         I+jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ojnNMVl0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id o13-20020ac24c4d000000b004786d36663asi286239lfk.9.2022.06.13.13.18.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:18:42 -0700 (PDT)
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
Subject: [PATCH 23/32] kasan: use kasan_addr_to_slab in print_address_description
Date: Mon, 13 Jun 2022 22:14:14 +0200
Message-Id: <b53ed1a8acef1f17a8c2f98050d8f43bbc42a806.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ojnNMVl0;       spf=pass
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

Use the kasan_addr_to_slab() helper in print_address_description()
instead of separately invoking PageSlab() and page_slab().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 879f949dc395..1dd6fc8a678f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -291,12 +291,12 @@ static inline bool init_task_stack_addr(const void *addr)
 static void print_address_description(void *addr, u8 tag)
 {
 	struct page *page = kasan_addr_to_page(addr);
+	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
 	pr_err("\n");
 
-	if (page && PageSlab(page)) {
-		struct slab *slab = page_slab(page);
+	if (slab) {
 		struct kmem_cache *cache = slab->slab_cache;
 		void *object = nearest_obj(cache, slab,	addr);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b53ed1a8acef1f17a8c2f98050d8f43bbc42a806.1655150842.git.andreyknvl%40google.com.
