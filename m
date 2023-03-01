Return-Path: <kasan-dev+bncBD52JJ7JXILRB3F37KPQMGQECJVFSJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B176A644D
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 01:35:58 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id bl12-20020a056602408c00b0074d073424aesf4132539iob.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 16:35:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677630957; cv=pass;
        d=google.com; s=arc-20160816;
        b=rybEuyVaL8L5m7WTwmWRUBJCL9Wj2z8clm0fxqZBajEbNgbNOaFXoAjYD+Z5k8zkPV
         U4t1yXaHbx/lPGRVnE5hA/YL+hijP5aeaA1XTCnrNt8BEgJtYyPtGJhkXTdD5RgBebsO
         Vj3eP4XWqQdFt/yl6jmUd2+s/jnwfsR+42c/5mJwta3yJA2JWiJdEJRPx8dMK+iEDBBO
         zBlqcF14vDna75JSN5zmB/gyfvI22EpSHN5v0ZkxCNO3y6j7mH7e21j4b6noAPTT5173
         vHNe3dccAUB0UqWwpReStwO/v8AjU7eHzarAyt7P77F0BAycKa8IEwUmgv065S2qLGYE
         v+rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=A7bFgb3ClbyX5UUjR0vRqWAPIQLr0n8I8q8Re1TacIM=;
        b=HG9LIkkRo5P1qUcbB7t16x8oDf+QeX5kryL1PV8yrA0xS+5YUhm76D4tPWHjfmJoKN
         mDYGoyh3J9NnJqI5KGJ9oNOXj7zvu5987OqJluQFHOaXRZXw9wgw0ju1alWacW0AF1pO
         IDGF0vxIvI+rWBVtDghfT0SxhgpVwTyZZY7AETGOA2b5odvQgo6z4rEgZzLgUtSuKDqS
         ZzHtuY4CQNXG/MznSKR6lv/qztgoA2eibm1+rcD3Kos6rk3tIuMDTSf/keP473vc0p0F
         q4hoyLvuv3eikiTKpL6fg2YAGlWc+5kVC99r/G86XX8uU6QZ7us+PIz4qBcZp8Wyj0Bh
         08NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="N/rvOCTs";
       spf=pass (google.com: domain of 37j3-ywmkcuk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=37J3-YwMKCUk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=A7bFgb3ClbyX5UUjR0vRqWAPIQLr0n8I8q8Re1TacIM=;
        b=iqILTOr/T1BZMbG6vgT4lRqstMlC+2oBoeRJ89kKETvE2AlFdfV+teWcyR1dLvD1v/
         aVjeX9lf1H6M5BvF0B8Oj+ncm+t7v9VFGhXZjitqd+3GgLwUTzkD7Yt5kgOEFy94va/u
         5Pwexmdj/FShPnrTUWi7yB104y4RO1ykXZrry7mCU13AZSk/JWerLAM4nCMTuSdmgCjB
         CDvqdV9lGNDtD9S8x2/d01dEFxlykTbN8kjg3OgQI6E2unWXeMzFX42vaYNqHpHzMzem
         Ik0BhAti8z2Hrmi8zaABacFuqkwNgf6uP75uW1yS54lL2XzmM9CGD/QF+TEyOqcRVcyI
         c6dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=A7bFgb3ClbyX5UUjR0vRqWAPIQLr0n8I8q8Re1TacIM=;
        b=aM/pJAv4rcETNBTRVYQg61zzN3A0qEuWPvGLYvmaMS4S8N6O0Gv3N+qKoZ9/lFQuz5
         +Kfpxd6akkfe0Pbkaze5RCbJq5r5XK7CCKWjVbBUC4srTkcPNXmOwPhXGZzSdCBGTBug
         sDX2xuBEeu+x7vhGcI5l9iPL4nHDz+0zk4X92BwKBUFEBZzjNdq+uRtynvnJALHXZhXU
         QfVg8bb+/ZQWLqJkWM8rqkfABKFm+Im6Dkf6fcSDMIGZAtlQfbEITKYryQKbi34DkuPu
         CwbWQgDqSvJ3pfSGAAbAg8lL75IZc8t9c/gLmObQl6qsH30pzjBdy4lM2aiEcLFq/i58
         jOdg==
X-Gm-Message-State: AO0yUKVIP8+W9zEU7R9jdG1Xi75gd8KMARSrggxCW+AoA6uhq+V9IH8E
	kqD8ruqbA5d8+jBk3+qyzbk=
X-Google-Smtp-Source: AK7set+KKZRJ+yfhSqosH0KjYhlVdJXs3ilmBLxVpCVQfkldT/wrVyStokBeo4QsFE4/U8BNieLYNQ==
X-Received: by 2002:a5e:c002:0:b0:745:33df:c498 with SMTP id u2-20020a5ec002000000b0074533dfc498mr2268702iol.3.1677630957084;
        Tue, 28 Feb 2023 16:35:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13c8:b0:315:7b96:e09b with SMTP id
 v8-20020a056e0213c800b003157b96e09bls6161248ilj.3.-pod-prod-gmail; Tue, 28
 Feb 2023 16:35:56 -0800 (PST)
X-Received: by 2002:a05:6e02:1a04:b0:317:427:e7ed with SMTP id s4-20020a056e021a0400b003170427e7edmr4796430ild.19.1677630956450;
        Tue, 28 Feb 2023 16:35:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677630956; cv=none;
        d=google.com; s=arc-20160816;
        b=N6twcEA7RvuN+i/EIb/rY9nrlCU0+62bdfzgJXf7k1FAGyr7+8AB79XdVlsFNMXgmZ
         PntYB/nscpyT3hbzwMOI1AWWs8nf8TrTZBm6oEMgkUJasbH2JfXkij0wOBqodHXjcVCk
         eEWHL2j+OcSkElvUV2h4ZLSefzicMSHhdlQnmQqhZ3JGlYj/1LD7JV+2zIgzI2+ZA7K+
         ATJd+6Smy3ZtCgGhyBIHfy2UdymTlhODiXpEpOHsgToZcRZeecHdMD+h/nnQCLzryNWI
         EjV8eXxiLUbRyhVDx1Kxm/WYfZdKoWLJj2WSPHUoxavJsNAo96PMEYw6+5ku7oO2zIV9
         t+bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=eey2bWIXShb0HJ2rZd6676jnb6hRL1sBGHfdZHZ/mnM=;
        b=vwUpQdwfyPsrRisKF8Y4+2jWhADamLZhkrtJqCaXouqheeOe5YMoY8A5BGJRycNGNf
         V8akwDWBBZhs/RQmSPdKzVLtH2Ex7+uPQVY7f6ORnsZxCqmILQ8VmQ9X8kcqajyAI0/1
         /RQz4TOaivy+b0WHUHFiMdj2ek3PT6WGUa9quwKwfifqW/wkfLRQYNmg2xIJk7CEWPuj
         +/Pmn0X6IbJH4z/vJyWbEhlZ2WflHjefb+WLRe2BTelh/Z2xjzWKtrmde+U9rEMkFfhH
         iKjPdJRPN+MGnRCNTL8OfNvCU3tSKHQwFm6Kdqx9KlkhiYG0u7iGwgxYO/V/X/pouPx0
         Zedw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="N/rvOCTs";
       spf=pass (google.com: domain of 37j3-ywmkcuk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=37J3-YwMKCUk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id j7-20020a056638148700b003e7ef26f13dsi966211jak.2.2023.02.28.16.35.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 16:35:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 37j3-ywmkcuk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-536c039f859so249211047b3.21
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 16:35:56 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:cb8e:e6d0:b612:8d4c])
 (user=pcc job=sendgmr) by 2002:a25:ec09:0:b0:aa3:f90f:369b with SMTP id
 j9-20020a25ec09000000b00aa3f90f369bmr193406ybh.6.1677630956042; Tue, 28 Feb
 2023 16:35:56 -0800 (PST)
Date: Tue, 28 Feb 2023 16:35:44 -0800
In-Reply-To: <20230301003545.282859-1-pcc@google.com>
Message-Id: <20230301003545.282859-2-pcc@google.com>
Mime-Version: 1.0
References: <20230301003545.282859-1-pcc@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Subject: [PATCH v3 1/2] Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="N/rvOCTs";       spf=pass
 (google.com: domain of 37j3-ywmkcuk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=37J3-YwMKCUk0nnrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

This reverts commit 487a32ec24be819e747af8c2ab0d5c515508086a.

The should_skip_kasan_poison() function reads the PG_skip_kasan_poison
flag from page->flags. However, this line of code in free_pages_prepare():

page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;

clears most of page->flags, including PG_skip_kasan_poison, before calling
should_skip_kasan_poison(), which meant that it would never return true
as a result of the page flag being set. Therefore, fix the code to call
should_skip_kasan_poison() before clearing the flags, as we were doing
before the reverted patch.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Fixes: 487a32ec24be ("kasan: drop skip_kasan_poison variable in free_pages_prepare")
Cc: <stable@vger.kernel.org> # 6.1
Link: https://linux-review.googlesource.com/id/Ic4f13affeebd20548758438bb9ed9ca40e312b79
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/page_alloc.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index ac1fc986af44..7136c36c5d01 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1398,6 +1398,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
+	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1470,7 +1471,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!should_skip_kasan_poison(page, fpi_flags)) {
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301003545.282859-2-pcc%40google.com.
