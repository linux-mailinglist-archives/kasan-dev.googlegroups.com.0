Return-Path: <kasan-dev+bncBDX4HWEMTEBRBI4CRX6QKGQEV6SASDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 878EC2A736C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:44 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id a1sf146221lfb.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534564; cv=pass;
        d=google.com; s=arc-20160816;
        b=tN4IE1wT+irCzmC6EYPo+ugKQkb3IlQI1ToE7wnVt+otj3namXmDZdIwxbaJhl5blM
         VkHV4m/j8voRu1uyHQGIsnQsv7Xydj0YSRE+qnt7PCkYcgnESGKVBwuAR3ndKx9OJ0e/
         Hrmvwlb+bfUYOMatmCNwc8CI/6PyGJg8wb8KfOBgj7CKw419pj4FgguFXm346yEN4PQa
         cXDL+orGk85C3sI7izV92HwYTKjfNLeIPHKlEYSkWoCjTrQpR3EpF5fXe/jnQ805UCy8
         M6lG2EX60lpF59TySJWM+lY/Qwe/+DpY0zpLa9YiG4AMdlWlYHuXgewfRRgyJcjXbxXg
         bDWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8wtYLe+nKpRBE+MDyfFXPBaBwq72GXt7RTyUXo3JPu4=;
        b=0iUJuNWA+/Xpsnenjgh9XHGv+4zPsDQFABdhOCkFZtA7wqFLo/82qVhH2TCmfMahVB
         kI0xr1UjmQ4qAaFw2jbXb0AGFhiV1lFq+Kp76GxiNxQioDMFbnoXlqygDuNDcGWTWar7
         QV85R+taOEZSFCpMLhR+Rf9fAcvuXOazSfhwPJQK2xQibhwVouwaxC+p3JFxuVQw4JGX
         i5qa9h/eHmeW/O0DPkOYurMDgqLCdAoDZ01eTlowDL7HGSfnAgNw798z1vEYydJgbROb
         p0/rb9pL9f9pdS9Tszq0sUaQimL1Z+QZAAK7JD9DEbBymxu+ecI59uijRcnFwS2Jz9pg
         Gh+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TKDRruDc;
       spf=pass (google.com: domain of 3ikgjxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IkGjXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8wtYLe+nKpRBE+MDyfFXPBaBwq72GXt7RTyUXo3JPu4=;
        b=VlKsO1xlaCbb6YYfobgfpLsy36pHgvklrKntSuz9HYZfYCWPWIEjcVzbxkokZyGyZa
         T92njEt4pZRjuYjaBTR8fUhVEtUdWqxm1APUoV82QwRmBt8zVaUAZttL5abPYfqSPWAZ
         cpZqX+M+2g1cczU1aoyvIUVYP+F4eJft2IFtZDfbmSVnUYYsvmLQztiu362xLFFxES4c
         UeYoE19o0wqiea0GQDLw+wshorOQ0go8Qg0mWxIiv+VflH0dbokhDxy4AUvCc+yFqy3W
         DjvUd/LwXd3DrKNopEVNhFYQQxgXUhXLKibhDNIbFrprrtlMZPOTZmE4NISXZIvYMnLA
         QruA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8wtYLe+nKpRBE+MDyfFXPBaBwq72GXt7RTyUXo3JPu4=;
        b=lOlFapo1fh1KDt7/iC9MpFmg9oC8ZYS4upBCcT3TXlonRK3PVnFygaJn70xd0u6FUO
         jhCNTYGi34P6ZfoEjrQPu4IcOhoN49EYSjlwONZDgmfw+SIK9404thRSHlaxQQBMXc6P
         tZUgJuEl7OQ8NeoQId0UPV2p1fqxyahcQBq/idhExrh7IGn+fNSBBvxbcZo43mOzNYnO
         wFcO75I+MQiWiaERC2N2PMwZm/aTAz3NbBhHRVfzmfgRNg4Iz4jN+xzCB+pHpfnW8ZNP
         TnKTmFdhfz/i/TMxAfMdlhh1EOHsmtoEaB84DEE8C0D0cC9DutYNxawICN+KqvYgZy+u
         AnJw==
X-Gm-Message-State: AOAM532DR+NX5/hL1GmHN1LV+P1d6ntbfCIpEpXFdFjCeO2BYOGzxNhH
	iPwjYlp81uC7ws0ZoVICGXw=
X-Google-Smtp-Source: ABdhPJzKtm4OGqSbp8L8wLvRyRdgPetq6Vfa+UYfnNU0R9l9Hxu2lF9S9VBjJ6RKsvuA/pYbTxgLfg==
X-Received: by 2002:a2e:85cd:: with SMTP id h13mr159189ljj.345.1604534564104;
        Wed, 04 Nov 2020 16:02:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2301554lff.1.gmail; Wed, 04 Nov
 2020 16:02:43 -0800 (PST)
X-Received: by 2002:ac2:418b:: with SMTP id z11mr70192lfh.371.1604534563214;
        Wed, 04 Nov 2020 16:02:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534563; cv=none;
        d=google.com; s=arc-20160816;
        b=qxdpvpGGB+Way7gsrDQCuyxh3vx82ndyVSwxJO/F5vZ/7sjY14GX8LyoPI0Brlazxa
         8nWwpzU89cz1up81Kc7xOwlieY1ptcOljsd6zrGA409XV+4L978zZ3a3xlwjVbRDmcBW
         uLc8fQf0FccAMfnNvrsJeDrqfxP5IDQvMiPSUmrpGOPvFsCnTdLqJknG/cj+ZG+oWHT3
         Am8Wbau7y0o9ksWAM3HD74WimZeAXcwBRBJj6q1MWgFMNHmFfiTaevni6ixTXTYG/x0d
         op3X+YaLs85DYQUtJRWy9VimoKdAqBdz+UcAlM3C0YBblULaHR4TYDqXmMhOzCjjR1/J
         njCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=vCuap+Z40WCfgwTrVBGRXx2rimwF3+Nybx2YvcmvQUo=;
        b=nkpbVHoVC701bDcrM6iEo/TEMGXZnKfebL7LW5B3xteChB2T3V0cTnyZMGUhgO0cOU
         QfhsfFpexYEpps0nvT4oGR5XYjaBQDILzZrVKyk6Tywt3gL73tjq24fkYGqd0XKSt01G
         uvGm+aIw5IdXw7hxZLvUYRFhunEAISKEl/ABREnTYZQpEyhx7BChqULeQ4zkK7Ud3kBO
         FhxMaCyYBRcHYxkmHkq2CUUsO6kmeWxbixJoY9qE3JZKDgSSZmZRKV6tdEcVnfPbQHqG
         BnGixrvnRI15qH67IacXagCc9yYK9nYl3Dd2PUDdobSZQp5E4HcaQvp0pfqPhXMAopiZ
         aFJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TKDRruDc;
       spf=pass (google.com: domain of 3ikgjxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IkGjXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id h4si83375ljl.1.2020.11.04.16.02.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ikgjxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v5so104877wrr.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4d0d:: with SMTP id
 z13mr477608wrt.23.1604534562699; Wed, 04 Nov 2020 16:02:42 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:13 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <4a32aecc6761e93d792cb2b78af86689025627bd.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 03/20] kasan: introduce set_alloc_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TKDRruDc;       spf=pass
 (google.com: domain of 3ikgjxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IkGjXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Add set_alloc_info() helper and move kasan_set_track() into it. This will
simplify the code for one of the upcoming changes.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
---
 mm/kasan/common.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8fd04415d8f4..a880e5a547ed 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -318,6 +318,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return __kasan_slab_free(cache, object, ip, true);
 }
 
+static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+}
+
 static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
@@ -345,7 +350,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
 }
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a32aecc6761e93d792cb2b78af86689025627bd.1604534322.git.andreyknvl%40google.com.
