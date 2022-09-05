Return-Path: <kasan-dev+bncBAABBMWJ3GMAMGQECA5BGTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 88DCD5ADA87
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:05:55 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id gs35-20020a1709072d2300b00730e14fd76esf2647101ejc.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411955; cv=pass;
        d=google.com; s=arc-20160816;
        b=FDMn3ZpKO7wVfCYFW+XQdu67Kt22BIb5+sc20frXWeQIlnHViVutaWhI8W3c3YYkTL
         w2Pbo5YDurKEiOj+uOkum3/zaeq80tYgHerdJCo75+dJNr82VVAaCuSVC8hJLUAqtAUg
         LFDuXNk3z/eSJ622SFCUNKxb5k6ENtBFBbloH38FogurKLA84xPt1roRb8Q+EOl9tk1q
         2EfAUoFOQQL/hc32Ah01Tgn9rQXqJsLC9F3sMWTmyI3FxGjkgnYwN063YXRBcAe7WFpl
         QRNAoYIutXNymSJr+tbWbhWsn9mhJoixnxC6xscBmCN+0ry9vbut0fobuTy7yOct/39h
         lwSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=y/EK1UFJBfGoXFx/M0B2mEBwQB9ikEB2v008HCxivs8=;
        b=ZMJHHFcZDXyaMQs+LA7dT0o94lRNt2ToGA/w3LPsW77swi+gaE0j2wM4+QFKBqATSk
         uG9ruTdNj1STyO+dtCulwHx4Jb1cfk9vEVhmgPQP36qDsQTdOMbDcfLko58yOYZJ8TER
         hSqV2LnYFoDYoLe1FJUF6fcLiVgNZHZrVxjJVyZtkc5y9rDpa1gohrG5ant7IBB0cH1Z
         dWAAIWQPUcOwf2PxTMH990WB1xbo52XqhAG4P0DZs+mB74WmEjs/vOJiDU1KYUY/iTqg
         7Hftxj8kYcKAGVzo7wvElFLnb0A8t41rzJPrkrsMtCGupWaciH3aODb5fl5iLCIRG2P2
         KOxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RxlSmPaR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=y/EK1UFJBfGoXFx/M0B2mEBwQB9ikEB2v008HCxivs8=;
        b=LbeXQtlR6MuBFr+8sQJm+66jskYED/INKZfiTcJsqfYgmbkZO1QAUrVurl1q2CbSrt
         evvELpPdB2CqXjHauRulQrmpNO4Mo/k2MOgYa040cZpqznp3m/9j+qI4WGawn5AJZyRS
         5HcEYDKiJCUXtLh5eX99SNMUuMS8mNldqXIZQwsAcc27HkGH8T7OwC3f7F39qHGqBP+8
         GVnfWJIdHApVykfS6l9SfS8JjAmOkeoCoEoucUzjDijot9YpqutV9eiPjN4uM6jDXBYY
         aR3/Ny4y5aFBg1vXXakBcdVi8IsNR0bEpJGUKJhEXuMCZVAuYEq7UUpoQ2uFIiq4Z/gP
         G54A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=y/EK1UFJBfGoXFx/M0B2mEBwQB9ikEB2v008HCxivs8=;
        b=Hq6nSKOObGrofK49LZxd8eCluncD95Qww8uEMQE6c037y/sMB3M3lSwzrRqj0Wp73F
         72H1zMXMRz/lYlki5ZyD9XIP05AQO+BWUfaphXc4sCOOMG17N4YAk3HL5hHr7Ns5U2Gt
         XyEkirQk7zcXMnJvF9HitBElpxBJxS4A5RXf6qsVDav9pepI63OHeffEtr5lXg5Mk6ka
         krqiLRDZmkSnln/iY2O30j//qod4Xo6B0x6a3pGQj0kczGjvJowdJPGNviXm3CbG7XCX
         ZJ45FUVPSr0sE5eEN2NvOgSDWZCBoaLRjoh87qn5ymtiZwZyEKE8f8ae3m+tr9lyhKPR
         XvAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo19KuHdwl3+DkWTWwt3+ySgupvC46HB3s+Rn+USjvMV59FHOzE5
	9EFCpJAqhQ4nmqlfrSCRjSk=
X-Google-Smtp-Source: AA6agR7x7MbRRlgXU3aKYNZJJSuc6X3OKSsQ0Ai+B5ksaXYoMS21YqvDnUB6CaRd0uLkqp0jwl+5/w==
X-Received: by 2002:a05:6402:448b:b0:43b:5ec6:8863 with SMTP id er11-20020a056402448b00b0043b5ec68863mr44384223edb.377.1662411955103;
        Mon, 05 Sep 2022 14:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3994:b0:726:abf9:5f2e with SMTP id
 h20-20020a170906399400b00726abf95f2els3982604eje.9.-pod-prod-gmail; Mon, 05
 Sep 2022 14:05:54 -0700 (PDT)
X-Received: by 2002:a17:907:3e94:b0:741:9ed8:9962 with SMTP id hs20-20020a1709073e9400b007419ed89962mr25777477ejc.482.1662411954283;
        Mon, 05 Sep 2022 14:05:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411954; cv=none;
        d=google.com; s=arc-20160816;
        b=H5xtX64GG0aOcaajoJMKnOZvakYIU6TiV6ef7cDfjxUoTpF1WGBpLL0uxBs0nFoPCZ
         2SpixqJPIdsDfB7TLrMnWtcNYJypcxvjD5Ojz2mb4MuHOPB8qpog9OsMAuihzwZE2lLZ
         EsZShJcDWQ4lkXihOEtBNw/sCr05Yu4/PtR8+8uUDs8By2mmBz2KFM5sPlZpc6PXG+Yg
         j+/bakgeLuRKa+W/n8wCA7Q1w4yt7KtV5BFY4JSM/6XmoSpvuB3LwxsufnoZynikqXKc
         /idD3sBQiKgaUAFlqgw1Ajt3Kb5kvKu0CivorQxbS0/hRKNLoTUe2attFvTX4F43Xy5t
         n2+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VgD6aAPrK9DNDeYC6eoXfhD6gN4R30dJg8cA4lzePd8=;
        b=UEr4g0jxLKBs4rjdffChQmGmZYPSyXwD6fEr+JkJb/ZA2s6yuv0UXQ+8HRpn2gFskD
         OUc5q1Q7aXWZq1z08iovCTDw/pSdqT7bJTa4uUUN8s9SlrfLnq9zuo3D+P9u1osDYYBd
         UvueiPW6dj5riQ1oVASw4xamlW+IbwX1vDDAOeOGqq8Z+qi/yodW0lQ2fR0KHqBbXVY4
         IKKz3IjOb7rJxKhtR14DqDKfZXw33e/lVUtY/DbwTGPkUODD3/hIUpUYrz/trO6kE6rR
         bjvR2EzQHFRDkUOkk4VkSPLU/ViiWzZq3Cdqag8uOkjZOFaTowlzrT5vx63i696+YMuW
         ks0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RxlSmPaR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id s17-20020aa7c551000000b0044609bb9ed0si232325edr.1.2022.09.05.14.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:05:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v3 01/34] kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
Date: Mon,  5 Sep 2022 23:05:16 +0200
Message-Id: <c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RxlSmPaR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

__kasan_metadata_size() calculates the size of the redzone for objects
in a slab cache.

When accounting for presence of kasan_free_meta in the redzone, this
function only compares free_meta_offset with 0. But free_meta_offset could
also be equal to KASAN_NO_FREE_META, which indicates that kasan_free_meta
is not present at all.

Add a comparison with KASAN_NO_FREE_META into __kasan_metadata_size().

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This is a minor fix that only affects slub_debug runs, so it is probably
not worth backporting.
---
 mm/kasan/common.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f583855c8b..f6a6c7d0d8b8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -224,8 +224,9 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
 		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
-		(cache->kasan_info.free_meta_offset ?
-		sizeof(struct kasan_free_meta) : 0);
+		((cache->kasan_info.free_meta_offset &&
+		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
+		 sizeof(struct kasan_free_meta) : 0);
 }
 
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl%40google.com.
