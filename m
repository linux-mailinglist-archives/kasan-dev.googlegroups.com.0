Return-Path: <kasan-dev+bncBAABB56K3GMAMGQEXQMSVVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E8A55ADAAE
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:09:12 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id k13-20020a05651c0a0d00b00265d5dfe102sf3218762ljq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:09:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412152; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iz4fv/madjbICXT8Jic23IThOm1RWPPhmyDV5f8HgjX+niru/On5elR3mPYEqnj3NB
         Gah4Oce2lqEbUFciMpmxKUDffDGoVXRYnJfVjEqdeZ4qGW6Rkd/Itr6jzFhob8PcfuHt
         VXaD9ZHAU7OKl6A+WAJBLf/YTEN3Og1HUrmxQzIFchKHuwOon7Y2ng6L850k3/mBWxLb
         fnSJbpp1w0PHGt22MfxfKBiIYiJXS+EvihW4Dpu5ZlRk/45lS44xevZAhuSPFbE7NMXS
         2LkNaCHMkZjiReOhEzAoBk/Vyu1LTNOjKvn2eNvGu/wIYXWSwyj9OEMKkBV39iIJRGy8
         m3Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gQYVwsKNvRxoCZkbQ5OvLfb4DaDBZ5ORooJ3Hkj6XM4=;
        b=XIPVpRw7+Lmx2HtMR+NCZS9MG4qYgvuPm+vhqOILGTbqwf0qiTBi7mhZYc+Z1DqY8G
         gDEz04r2TCCWbZSwAIwIGAYwuLejPh7dmhTm6y09MVDMA+eI30T9xNiYmU3uutAwo3sJ
         5zktT7L7UOHmq7rFR7uHSNXg0KymrJ0lS5WN0qlCWKaSlHNNzCh//JAfnJli5SD1P9Xv
         +tsaXTwmlb4XwT7A7MMDWs3qIyfovb23XOIY8by7SXmlGJm7eLVoXIpupWwNWWXEB91c
         g0Ifdj6+Afnv2TWJax5LrpRw0COSeXv0kVbBrzclvG+87hIPAo9W6ETI32XlxrszEnaA
         kvog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t2jE6p9p;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=gQYVwsKNvRxoCZkbQ5OvLfb4DaDBZ5ORooJ3Hkj6XM4=;
        b=i2513nL80hRYhEmCarWAuVclg0VR41Evk637Tv8ChAZbenhLCW+g6c37BkpFfV6RQx
         BxBxyuG4xa/jLs2Jekpiz5q8KMKihKYyzJ8JBlNTC7W/Go9citzLibPoJ+etmK2uQEOr
         StQHak8ka9P3vrXCD5J+lkY91is+uxSeW0YnWxU0VjV2mpYonW60e0SPmuGc+igUpHSn
         UTNXD0cGH/Xhehopn3nTEARzgnu1FheteGmay2GWSJheMV+ZTasd31gDRQ4PsEt4UDT7
         /rDRjFobERO9z1KA5FEQhDA7vi9yE5/DEWC80Um41UowMeqYa9R1s9GUu5sX6q2/Vcd8
         QdLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=gQYVwsKNvRxoCZkbQ5OvLfb4DaDBZ5ORooJ3Hkj6XM4=;
        b=W4h+t7jCXkE2aFLXepJkzLSmyZtxVuqz7KhXI+u5uQ+T+ssLMic/fuy7oqw6KJo34z
         bsG886PUMDjScj11Ny346qz0qg9uWLPa8fcPcgIhvQxHJUpwje1Mv+YvEESJ1FxdxkKT
         GbuGyQWYAEJ3uzQKYF/IveD6F60fSrpDgwdAl0fi09OTu9qfHIPWkGqSSpUdS7TIzqti
         d22osUHHH0Ydz1HAVBixGjFauxI+9CckVvMP3qqSrKXPKPNzuHCsN/PcpRd8iExE1Eue
         GXJ6ieZOgt6of8eLs/jNYsGwobnlziF1f9q+cCEnxXOB6YHnKrBS2SiMXuI4S5wGEpiw
         wVrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3xW6pGDSkMCCfGBV7bjGXMdH4o4tqv4IoQAhNd23KBrDSkBBjq
	G7b0YN0OgPo2kBrlmFwfBZ8=
X-Google-Smtp-Source: AA6agR4s84J5emcLi+HsZNTtIw+JaQwQ0Ly92eOIX9res1VrUCAjuA7ZJH6AfmTbDOfuiKX65g2nGA==
X-Received: by 2002:a05:651c:b26:b0:267:18e2:2024 with SMTP id b38-20020a05651c0b2600b0026718e22024mr9999266ljr.409.1662412152093;
        Mon, 05 Sep 2022 14:09:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2016:b0:48b:2227:7787 with SMTP id
 a22-20020a056512201600b0048b22277787ls5359449lfb.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:09:11 -0700 (PDT)
X-Received: by 2002:a05:6512:3186:b0:48b:a14f:c78a with SMTP id i6-20020a056512318600b0048ba14fc78amr15881081lfe.28.1662412151275;
        Mon, 05 Sep 2022 14:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412151; cv=none;
        d=google.com; s=arc-20160816;
        b=OHqRxj/WUSGirWrncyCG8+A/TIde1RXp5tR8J0VLQjdA2DPKJKkw4AW6ndky81eL8f
         Okl8x6yMJ0pg2D6IsYolkiT+rk0fx70Td7wASTHAhu4DO6zAf0Db/RlaOm6SDu9pUsHd
         2S0wfq8do0IUrf1wVONjC+VeuWLV+S3M7nNE2FTE2XkvJSAYboNUpvI3poGrqh2gC4v5
         CtnLmurfxU3iiBvlBNVu4ultFeXp5aO9D8RCOC9nIQfTKirpMFzVHIkh1OS7zHze6YgD
         O7NsZTSJ80gOvdkmBD5UDLemrn8XycrBm2XAuhoIkmX9zVJcDiXPKyS40kteddY5RGXY
         vsSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Xrez/vnZo/oxjqNbdHGgKzELApXd1vkR10PWPCg0Dhs=;
        b=Uz+JCU9iKiGCW66F53NNjqPThm5hyEbCj4j4r7hL3r/EGkPuxj1KhuhorTelEp28gT
         Vitn46XeuKKWU2EgfGUFhuH38o7iAD8AMorf5nwgYoHhLFOGU7llQgh9vSKWvOUiQa3a
         lXlIy0ZZ+1iur1bs/Qk1zJxbeK85tPp2G9HgNmGXVG142BhysJBNldotxwVKQI/OY4PR
         8FiCQct9tUXCo4gd96ttP05Btmhhsn0ZXtgCgBjryKpbcwUeRDA2T5Pn36isEPuVsx8g
         bQH9LhKwEtQRl1wRPlbdfEKe7cqG+I6Ky/8IEPv5GzFM6vLiDa6fy0lfojX1+MiqTTvU
         3tnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t2jE6p9p;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id bd9-20020a05651c168900b0025e5351aa9bsi450436ljb.7.2022.09.05.14.09.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 21/34] kasan: cosmetic changes in report.c
Date: Mon,  5 Sep 2022 23:05:36 +0200
Message-Id: <b728eae71f3ea505a885449724de21cf3f476a7b.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=t2jE6p9p;       spf=pass
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

Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b728eae71f3ea505a885449724de21cf3f476a7b.1662411799.git.andreyknvl%40google.com.
