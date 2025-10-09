Return-Path: <kasan-dev+bncBDAOJ6534YNBBK5VT7DQMGQEYTTUQIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D4614BC9DE3
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 17:54:20 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-46e7a2c3773sf11536695e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 08:54:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760025260; cv=pass;
        d=google.com; s=arc-20240605;
        b=MM0OCrSgZ/56YuOOd1pfNQEyB4ubHsGOfJq7XQTayTHuIYTyzrjdgfIXWd4pdxoVTK
         bZI4mDdMy9ycI7JNcEVXnNVzOLRcuGgpe3o0KHqo/riQfXbZy3XERA8D3WKmmnIglwUf
         rBaTJvT2uAkzAKtn3GzamMjEPqFUAAuDAVYrt9Je9pXa5xjH3euscLtqVxKYMHfugnpX
         NbdaywTBARnYV0Z8Bzq3B8Q5gZ4+8OjCj0VJcnBSmulNIIFJI4Nu3kci82Coj3xns6hw
         IjUiXRDMHoATCk4ZF+GmlM2zAks0Hp/wTRLHvx8re7K6DyqXiic0hqcl5L4MVeGqDO65
         v2zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=zQYI11fNgaWAj/+UvFW3OhW3XB+dbZ+Z4ckPVx+q7uY=;
        fh=srUCSFlUvlXdBDpQr7oQpJJwrkvtGVyTrKf8hESZi9s=;
        b=ORDk6dE9XkHiSMMdTTKsE08KJHE0CHlQlMtEgMx30JNTj3ltVFj0Uhxn1gmspwXrfX
         qI282WYKMkrtnJ66p5ObHLEZubbkomK4WHomEaykM2qWtpOCGNnDTO2XwUwR1j3gavbd
         HpJhqNrvWlxIxq0KPQXfwzfLaG5hM4PVTsex4thYw1pBUD16nxcyt8Yl4dD1/LEY/SbG
         QTh+FkV3S6t1GtFUdcyovGzLGkG6AnYxwt+ntSwkt6adacIEKo8UMIqtEhNqY8DVXu2h
         oRwzYYaZrkzqOP5MHT3TKGguuWI28LFH2rftcQvByDKuy4KcasVW52wq11+uLIm7P2nz
         h7Jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IPEJY5if;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760025260; x=1760630060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zQYI11fNgaWAj/+UvFW3OhW3XB+dbZ+Z4ckPVx+q7uY=;
        b=lWZ6hIsLLTifU/cIjwzT9fV+TOBQpEFiLDy/AJBPwgBRtNdfz+/JDW64oLKdURoT33
         oZaKLdEwEmY9phQWOAPYbu2w1ASHXXVIlouksTsvbG6oXzKFtYJlBgD39AfdsTrFOxg1
         4ekx0gQpGBIDVa9Zcj2zCetUSinrdwIzeAhStRWCXTdEcCbaKQhL8NbSJdA1Vtnr+6um
         6zo6mVOMGL9A5e9OT6d+tqwvcwwxn0VSpDEZInGOjYH4d+Cw5xTZnMsgRm8iAw9tUl4X
         CzFSeRwc0H6bSv/ZN60Z+JsVDczP2dtDsrPy2+0SC2++I29FYSaoT01LVOt6B+jCITN9
         Aibw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760025260; x=1760630060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zQYI11fNgaWAj/+UvFW3OhW3XB+dbZ+Z4ckPVx+q7uY=;
        b=lM7yTpD38W7IUsXTlZhjNfIUO5uhBe6GNPp6bMhPy9zFntiDVVM+kJ5ibhhMrhnu+j
         S0sY5V4PoP5tqjYyvyu9cRvRf1OAY5H8/3oYriMVApA0AtsCfvYIlQi2nPC+Gy4wsELy
         nHtPS5JuTUJjWT/yvuxy4x+zRxYy10GprI8xIPhuHj9kGo/HCdxFqQi3N0DP1zUUOe1U
         GKALnbJqmSPdRVh0A7KkRzuFcc1Ehly0hDlvKX62o0fztbEWRXmrzevKmfG+YtreRPKi
         ZtX5QilU3/eE8g0+vO/fmvz/+AsYg0+hrZkojt2tOlbYu6xrJET/AGV8Au91mk5GWPxa
         oMMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760025260; x=1760630060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zQYI11fNgaWAj/+UvFW3OhW3XB+dbZ+Z4ckPVx+q7uY=;
        b=CsaNsvHX4gjzrLf3RD8+FiLXsPxPgluWjyLYiR6A3Nlq6/PMOFVAhd3bAlRuq9RJGL
         6V5S2OJ5mQsfUu8RgRutuEze9Tkm8xt4xdQV/Av8nHv5RXqUiatv0I6AO1JQTw42J8Gw
         kge9csw30+3an7T8hqsEbUXq0dQIipwy4hG/OOOhSfi7CBVTFQJ+JHr3VO0g6QgKkcHZ
         D5dSQNu2CKPSlC8p+yeP6Waix4FGCVxNbNV/ksuFIH68Vl+KaF1UFrrtLhTqgq/4vWEs
         Wzw01K1ZC4rxksEAzVRAKoYkVrH47R05BjeJh/omf4PbSGyLy2jKCn53g1qvSfDV5EWY
         SGbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQlAbeEu/5LaZ0n6NujbI9tS4NUexSoVgiLvMmW9HqxfMKwkpT28kiqlb0lfr/8dpYZ+PB5A==@lfdr.de
X-Gm-Message-State: AOJu0YxAgMe2eAsmovvyEQqqZvJpDLx3nRRY6z58F+mmKp57lfdDtcP6
	hKOuWdNAMDmO8sY9tD8PBs1jLMwmM3ILSg1k8wFfk1zhA3bRk07MIqvN
X-Google-Smtp-Source: AGHT+IEJB//hc9EwPRHKg7vaaOSPNoyzqSwKPTYRp/wpvxcimCPGS4k4bonRv3i0NW88NVhtgPphmA==
X-Received: by 2002:a05:600c:3543:b0:458:b8b0:6338 with SMTP id 5b1f17b1804b1-46fa9e98805mr61054775e9.6.1760025259997;
        Thu, 09 Oct 2025 08:54:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd59pUNQdN2cpD57bcMfngz+52WF2rXVZZrc7QxUXcB7RQ=="
Received: by 2002:a05:600c:1d27:b0:46f:ab97:d863 with SMTP id
 5b1f17b1804b1-46fab97db49ls12030185e9.1.-pod-prod-00-eu-canary; Thu, 09 Oct
 2025 08:54:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYtoqNziUWyBlFCKKqCl3HkMjKQGOEJQjp5qioa74ZVKBuPbfezBdBzzm/2K7OziicxH2we7Ll4X0=@googlegroups.com
X-Received: by 2002:a05:600c:5714:b0:46e:6a3f:6c6 with SMTP id 5b1f17b1804b1-46fa296e0e1mr63334925e9.6.1760025257471;
        Thu, 09 Oct 2025 08:54:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760025257; cv=none;
        d=google.com; s=arc-20240605;
        b=PPXQpStHpVknDCV0FDwx/0qEikHHGPf+kCX2BtulKsFcPbVjruMIrG61oPDZ/eBvaK
         vOwwBuMhK316JbTJTGWfyFeJ2gAziBghcG1nefFM9HqpPkH/OjZw2Xni1OneG73xD7zK
         EEyW7fB+IYdxdXr5do2pQ3Z6hiW01reRwna7rBJpdkskOnse20j9mWD+kzWpRkHvkATF
         +LlRXAf3/forEKsKkTV4IgP6pCrIziRdfoawspGa3/b9JKnW5PnOTh9oMKUhSUejh+6V
         AYSpmAicRnR8U2VXZBVZvrbpRbf52IBnk0dnEotZ6xoaHHwvwbbpzWx69qtr0epSZyj2
         PR4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7fCQnX2ZVKzE0uz1WnlkQnY2HwKIpXcbR9mszFR+OOY=;
        fh=rcLxYUH9xa4M53yYfx60yI6hdtUgFwxwuZBGY4hnHYA=;
        b=bKi2oKnwmpggRwIpON/l/UnbAI4GwLZrNZQ6teXrgzRtirMalx+fffRN06IJPdHOh7
         rS159CgtJ9iBDNdOBAa9/vVCu1KQ3oXEy5ZzDy2rbXpCUs2UqtNAL5KuxTYyX7EdvbPN
         NyzooJnyndHQofkk1IbEUUuLkuBsy161it3Ne0yCzF+bQC3UE8Ikh6Igg00SkSqBkCsG
         MAsDvCqiMiM1P2WvcVyhfLjibRT3znn/yFh2LWOD/L+eV8h8S0r+IkUv6guk2LLEuxkf
         EGBvKWspAPzPQSmxa87WkTEee2dAQ6ofOL8euu8axjqG8UhnRxhPvzCDwqS4z8Sn3KGU
         to6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IPEJY5if;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46fab36a004si2121575e9.0.2025.10.09.08.54.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 08:54:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-371e4858f74so13793851fa.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 08:54:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXy1bQR9/F40ee/MAfyAaNVfAqNgpyO928V3MsL+oLZJt+FsvZvjXLuFQ3YyJrULoiMYjbi6F0OO4g=@googlegroups.com
X-Gm-Gg: ASbGncuk71yY/+rzyrV27xJAF753sO+6wLKsisYwCj05BICUr2dJqLuT00wkX+CIPHy
	sczwzp774hUlvREUAbFqRDAhGjgu4SYFchTIcKr90ISuOOOT35OZZs35SW43RNEvRol6GjsK7tL
	1EdbZj7srlrL5uvyHogeQCthpNvK8In+N3xewRqlgloIxha5FJGpPsI9reMPEx9FAlFNyPIYGOa
	TsKMhr9gZdvM3AB5WAyeZWOEhZmGbMzoETqGIPWA+koxcZPOJCVQttcc+TSydyaSRFyxeDUgW3r
	scSikR2jGHln1ahKYETgISAgyW9dbL0VbSIkSe9vhx8tWXW+Q/p4vTG6bA+5+JwcTdMB88+39+n
	gQakfxIgZw9PM1I9aE5xMj0+Srqvobn3Q8LSgmg3FGognZChl50ZDh/nHLCrqcfwbqYZyImCgt4
	FqheFQXDBW
X-Received: by 2002:a05:651c:1509:b0:336:d0f8:5a7a with SMTP id 38308e7fff4ca-3760a2f9e1dmr20889251fa.6.1760025256534;
        Thu, 09 Oct 2025 08:54:16 -0700 (PDT)
Received: from fedora (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.googlemail.com with ESMTPSA id 38308e7fff4ca-375f3bcd2a8sm29499831fa.55.2025.10.09.08.54.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 08:54:16 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	bhe@redhat.com
Cc: christophe.leroy@csgroup.eu,
	ritesh.list@gmail.com,
	snovitoll@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 1/2] kasan: remove __kasan_save_free_info wrapper
Date: Thu,  9 Oct 2025 20:54:02 +0500
Message-ID: <20251009155403.1379150-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251009155403.1379150-1-snovitoll@gmail.com>
References: <20251009155403.1379150-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IPEJY5if;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

We don't need a kasan_enabled() check in
kasan_save_free_info() at all. Both the higher level paths
(kasan_slab_free and kasan_mempool_poison_object) already contain this
check. Therefore, remove the __wrapper.

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Fixes: 1e338f4d99e6 ("kasan: introduce ARCH_DEFER_KASAN and unify static key across modes")
---
 mm/kasan/generic.c | 2 +-
 mm/kasan/kasan.h   | 7 +------
 mm/kasan/tags.c    | 2 +-
 3 files changed, 3 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index b413c46b3e0..516b49accc4 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -573,7 +573,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_save_track(&alloc_meta->alloc_track, flags);
 }
 
-void __kasan_save_free_info(struct kmem_cache *cache, void *object)
+void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	struct kasan_free_meta *free_meta;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 07fa7375a84..fc9169a5476 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -399,12 +399,7 @@ void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack);
 void kasan_save_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 
-void __kasan_save_free_info(struct kmem_cache *cache, void *object);
-static inline void kasan_save_free_info(struct kmem_cache *cache, void *object)
-{
-	if (kasan_enabled())
-		__kasan_save_free_info(cache, object);
-}
+void kasan_save_free_info(struct kmem_cache *cache, void *object);
 
 #ifdef CONFIG_KASAN_GENERIC
 bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b9f31293622..d65d48b85f9 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -142,7 +142,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	save_stack_info(cache, object, flags, false);
 }
 
-void __kasan_save_free_info(struct kmem_cache *cache, void *object)
+void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	save_stack_info(cache, object, 0, true);
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009155403.1379150-2-snovitoll%40gmail.com.
