Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3XIRKDQMGQE7DYXSXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A41A3BB7CF
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 09:27:44 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id t20-20020ac5c9140000b029025754123312sf1837077vkl.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 00:27:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625470062; cv=pass;
        d=google.com; s=arc-20160816;
        b=QAog7T6AVplEnnQdwUEcS68gbp3UfNNmz+TKE7EKyCyYAf1i+EmPsOIpJgpsqJ3u4j
         puObkBTguVIYTe182Mjn1Qb6Kna4zJ2gfZ6lyM5RA3CoLaLYDsLDKhhY5GpIBRPiPKMS
         aDxE+CDjOPzKiIlbtGJliQo7cdy5PzSmAqPL6KToCJChfOICYvrcpt4Y2hqHCWK1VJD6
         Y0bh9qAXBQPY//QaoR3ItsAsxa7DYcMVRYBiNXo+l/uR7R0X9je82R1Haxf09JdJcNe4
         nx0+vedSd0KABVG8lWp81GFhlfx0UVwwZ5zGGoijjsZpHxc4V9k8GVlsOKJ+gBW48h3A
         9ddw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=C2rTn2xZSnLvAbdJknvQMlBSmIrw6w3t/m9E180ArDQ=;
        b=KDku+14sq13CdiHio1vXi54BQkGNJX2IFUBRYc/YgUvTH4Qfs3lkyptQvFlTmzY1gB
         DM+lB3P9XcHIaddgaablfKTmHRBRIoimC8sA7iV6VGiIvEuxg/qsdyvXVjNv9tBTm4tF
         UXrEFYBcIdqRzvtliW8/OM0B2taTUTHP7F4E0VcFe36XUm5I5Guj1FzaIWJxPyerTHYn
         N+WTsro9SQ1//WI0U0htZlSzD1DyytHLsFQ70GKeTiO97x63JljzruAq3DnuKdt083P7
         VN3RCZDuq3FX4EEV5FTAJHiLDb5Vbhizoyi8DVxAlVyN8zi4rQHy6i5oHb8MVsXCGTrc
         RCRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qAMqrCJF;
       spf=pass (google.com: domain of 3bbtiyaukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3bbTiYAUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=C2rTn2xZSnLvAbdJknvQMlBSmIrw6w3t/m9E180ArDQ=;
        b=atDAKKztw9Sh5tdpNBQ8/dBC2TIvVg5tgdX0uUK1mlwnzpYeCutkjC+gV/59krMKBa
         bL+mCvHFYcd6uif1KS9Dg4L+w+BPHVUEjL/NTclgtsSI12akL+jcL8/FJfSvvQ28LA6k
         1BQSceP+qgwwuCqIdBSiMa8a0yZyXvYmxTqiODdtEuEep45QjTn+5lDggpAHJrEqYV6x
         HZnewCokHh6U6ab2DhW4z34QqjvfJzDo1WtukF4F46Dy9n7n6V1RrAw5AeDIeuCQheIe
         gQX/r3nJ113eaMas2mF87E574mHu/EXhvfmsOfeMlIbpuEQhKvF5h+2HPuPkRh9Nwu9q
         7JPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C2rTn2xZSnLvAbdJknvQMlBSmIrw6w3t/m9E180ArDQ=;
        b=ryDtI4am+gT/0WfHxQVR9O735blzJZAMMZb+eB78qBob+wMcL4F2E9LmZgTK1HKRnt
         BFOca5RXvgQz2w41NkLxaXUC0NSKtnaaO2pSgi28NBw9DzmqztL8BXualCSDV41qAvvm
         smoNMOsQvXF+HSNT1RyGaLo9RMiK2QXsNdHr5Sw4NPArE/8sbgsWONvPlRSisnB/RSX4
         tUbMd1vDlifjSl1qGp9vHFps5p3mrhXJs8FTr1VIxCyRNLqrzN67+F/aH0My16UVQoOm
         kS5UASZpr0QYtzuOnJ7cOyI35eB2eFNaegTo+zjySOUAk6XjcqIhtiizVXQ2CVDNtlXd
         m5sg==
X-Gm-Message-State: AOAM533AMsJN9KxVuIV5/FomIyRzj+a1ye9GuUaseAKfzfGKkgwH7rTs
	u1wS1ALFrJU7LV3IqbF7jwg=
X-Google-Smtp-Source: ABdhPJz1T86aTRfhKHTmn9B0NmLLK3v2p80yM34G736ag5AXM9K0igDHAaiDOBCMNDuV5MaPin+2Vg==
X-Received: by 2002:a67:441:: with SMTP id 62mr8569630vse.20.1625470062772;
        Mon, 05 Jul 2021 00:27:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e40c:: with SMTP id d12ls2417825vsf.9.gmail; Mon, 05 Jul
 2021 00:27:42 -0700 (PDT)
X-Received: by 2002:a67:16c1:: with SMTP id 184mr8127210vsw.14.1625470062268;
        Mon, 05 Jul 2021 00:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625470062; cv=none;
        d=google.com; s=arc-20160816;
        b=GPM2vmrAyCYw/U4chkeyriVWcJHOoB8yFm6tGBcY5SLuuzW0DLgKpeJRaQwYJNa2AL
         uEokQb2lsNparaZ72pgbkwzmYYeiKCwm47Ve6+0HxvpvlfKW3++GtiAMNOuaVRTPFuuL
         pOJ2oknX+3A20M0yI3q3QoV5VlN4vq7GR5iFHNUGyiWWF7DxtS5lpaYQnebdiNpPLUVB
         WDgNNkwMj+iLTQ0EEWIGgnWmDgp8mlSJOPKFGGspZ67md9FeSOaRPXhRwaBQt6LuD/Ey
         qLpY7sSLY3n/5LmAywzhwV4V9+0peD+ALcxhTHiUzTlFpr6yqqDpPsUlDBUbniNdA7SX
         xVxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=mDcwhPTUrel2btqXWeFaBd7hJh1LLe+zyIffNYoVAO4=;
        b=okguBbhCqlBqGU/1J+si+A5/ZsE3ADva4zQa59l75fizQjg4DN2ghhsQRUaoi5Tuqa
         589MZvAmA5+sv+/sbsIhRCVe8h5sYiTfvG5QCKHhomCngvs1AHxJFQeJ4KYSmc5VeMU1
         R8QH8f/c35+Hv3L3s174PttqqBWFYi+C5B2cZ0PrAlhuV+2stbPemT2Bq6h1hZ9zxnl+
         48D3rruL6WioHDrDnglizBjeH6Yb8WQaKAIte3Thcc0xrntm1MNKFFsQYZQMGI3fDc8P
         Wd/k+p1MuZQu+XN7Mnz7Pw2t5R1hd1PDeXRERh98D0Um0ZTUProh9HIEJs3CC+5nbVih
         wo+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qAMqrCJF;
       spf=pass (google.com: domain of 3bbtiyaukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3bbTiYAUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id d66si1425918vkg.3.2021.07.05.00.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 00:27:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bbtiyaukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id f10-20020a05620a15aab02903b3210e44dcso6853399qkk.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 00:27:42 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dddd:647c:7745:e5f7])
 (user=elver job=sendgmr) by 2002:a05:6214:d49:: with SMTP id
 9mr11847977qvr.30.1625470061873; Mon, 05 Jul 2021 00:27:41 -0700 (PDT)
Date: Mon,  5 Jul 2021 09:27:16 +0200
Message-Id: <20210705072716.2125074-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH] kasan: fix build by including kernel.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, pcc@google.com, 
	catalin.marinas@arm.com, vincenzo.frascino@arm.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, andreyknvl@gmail.com, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qAMqrCJF;       spf=pass
 (google.com: domain of 3bbtiyaukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3bbTiYAUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The <linux/kasan.h> header relies on _RET_IP_ being defined, and had
been receiving that definition via inclusion of bug.h which includes
kernel.h. However, since f39650de687e that is no longer the case and get
the following build error when building CONFIG_KASAN_HW_TAGS on arm64:

  In file included from arch/arm64/mm/kasan_init.c:10:
  ./include/linux/kasan.h: In function 'kasan_slab_free':
  ./include/linux/kasan.h:230:39: error: '_RET_IP_' undeclared (first use in this function)
    230 |   return __kasan_slab_free(s, object, _RET_IP_, init);

Fix it by including kernel.h from kasan.h.

Fixes: f39650de687e ("kernel.h: split out panic and oops helpers")
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kasan.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5310e217bd74..dd874a1ee862 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -3,6 +3,7 @@
 #define _LINUX_KASAN_H
 
 #include <linux/bug.h>
+#include <linux/kernel.h>
 #include <linux/static_key.h>
 #include <linux/types.h>
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705072716.2125074-1-elver%40google.com.
