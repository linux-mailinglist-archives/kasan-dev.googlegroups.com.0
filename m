Return-Path: <kasan-dev+bncBAABBU72SGWAMGQE2QVIC3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 682B881BDBE
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:00:52 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-336900e8b1bsf75563f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:00:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703181652; cv=pass;
        d=google.com; s=arc-20160816;
        b=OZ7w5iDJmI7quvN8LEaVrDc4tGbuHvoneQrPsE5OOM9YsBh/HZVfc3DZ/J57aW/kxN
         O4YJwm51v4h3U/JQXhCTbWb+e0Ehq8Rm58Y2PpDhVQgFukWLDiRKaOPG+VgUJ4AxDja0
         DO/5Nn6DGVvz/0B5EYU2RFvt+w6Clk+C+8nDuiB2eDjRYXCPLxwdzJDRP57J7ALf/tuT
         lXhvoHZ4dS3+uqFXuBq5aTcCgZ1XJY4NlN7zGzwhWGR+XK41x0ylvb/KH4bTmyEddqZa
         1RryoYiqrAaQnYvZosvVQLFJJsptWlVi1sl0AmLGoWU+ta8jUMiGMsi/hKgcKWGkdPdw
         yTNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Sbt2rSgAwt2f8BYJbWdMWIBR8FzGH6HVyz/3gbZN4gk=;
        fh=rrYYxR7rPrfZ9oPDzrWqTdscfrSKKogWCwrUGRk3Wag=;
        b=YKjgSrhiRD6ICBFzg3fqi7syZm67Ueyw/wr05VHGwqE5FgU0LWh2nhIHtgSBzixzqY
         iu9ipzbh9dgU1voWBP27vbwFFsQEEi29+amqDKKouGdmqlohOPIyQ6oEK6n3e6y/gyrt
         Jndhvy5AOWXPIIaMb7UA85eYt5+H6sVk8QqNt46HjZdeU8H/lGb5VriWsuOpgCJAYuHp
         5BX1tKkyzc0yYo5zm5CrGr06C13vtAswAEhW4oo6FLaHWGvfIr/tzSJ0zcUVhrl/Dzji
         2BYrM8XkzXJNCWIXF204884ZH/v0e09WUcdbiq3YE0mUvvqNN4ou1Jva8iOYYROxov9v
         q+Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ea6gr3dH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703181652; x=1703786452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sbt2rSgAwt2f8BYJbWdMWIBR8FzGH6HVyz/3gbZN4gk=;
        b=PvVCyF2apS88oX+Bdz154HaxdQJNHk3ArJh0YPMOcruC3KMJzxoWONHhQ/6khhM3kC
         9BNTwdprIi2rNPqNDprbI+BItl+NB9y3EGO8kRLfOiwUgM13HZZjj12eckx6z6YGpjNc
         c9b+1Py417Q37Me1Yh5U2NBlQ05GwcOQOBWvYY4vSj3WAWM3YQxARuPh7qsILH7YLHnb
         uCHxOY4QfVBnj4w/0X8C5PvwF5Q6pmL0RmqOWL73c9PHuacD+aKRx21GKOlr3qUdj7YX
         kpDD7+tLd5rk0x6LGWRdDp5F5nmSSzAebJiEdurXnjStMd4ceZmkmYKJ6Uzx3lOo5rts
         6pDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703181652; x=1703786452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sbt2rSgAwt2f8BYJbWdMWIBR8FzGH6HVyz/3gbZN4gk=;
        b=JSB+r5hj7l9E2FyakeBRC1vZP1iM4VaL7aNipeyxAwC1FmWPymkrtBLwXIBzYJwNba
         /gFR1FdwdL6JKmbddsa+WSwWU2IbJUjn9i9ElphpHwDa+F2skr0wK1DeYDKOO7k4znfh
         n084QAkVZB7oj5aOFAgZ8E2+cqosaUISr09lzivis8PsYz7/aNdQJ1ST2Z85XPfNd4yh
         m1kLwAYxNL5OdadCf+ELgLsr36U6RQWcBqlZ0+jDrTeTaF6P0a3ViNtFwjFRtc6scMPB
         1b8det218xIkJd+tlyStsCGgl2IhJ00S6PRrNZb6k7YSKPuC0tGrYd4yg3cjVvz/3ZPW
         8OTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxUv4TtRc5kKUWslYqZOXhMfcExtz1Dxl14oBQ8q5K0IKnKo43h
	3AartqHunyxS314N6f4l0Gk=
X-Google-Smtp-Source: AGHT+IHRdETU8RoY3NEEYP+uqY/wC2zoftWLD1YFpzQkcM5fgMVg0pgfauCKjan9GNzz/1qH4TKs1Q==
X-Received: by 2002:a05:600c:3007:b0:40d:22d3:e359 with SMTP id j7-20020a05600c300700b0040d22d3e359mr58738wmh.3.1703181651393;
        Thu, 21 Dec 2023 10:00:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:510b:b0:40c:3e7b:c687 with SMTP id
 o11-20020a05600c510b00b0040c3e7bc687ls8014wms.2.-pod-prod-06-eu; Thu, 21 Dec
 2023 10:00:50 -0800 (PST)
X-Received: by 2002:a05:600c:19cf:b0:40d:3159:9303 with SMTP id u15-20020a05600c19cf00b0040d31599303mr49962wmq.155.1703181649882;
        Thu, 21 Dec 2023 10:00:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703181649; cv=none;
        d=google.com; s=arc-20160816;
        b=aUb7jUWCz0sbRQWEty7+egzyFd8YYcQi3xwfNWyn0druODqMaLkpQaHqbOJcgY/OmJ
         yV829SdzLQHdsKY5tW0BouVRRHeqliDrpumShsdxR3+GgxoafpBv1Go3O8kM/t2EBslT
         vJ12ZBtYa54kj+fp3a944LQE+EYQtU47C5bLJF17miirmI+jcreoZBDLbSSs2lQCLUal
         UUc8IVOHki0oiIsXMpYqKTMKDLcIZdYNEA3+s8fLFIB8FOSNiONlytMS7gX1CCT/3/KO
         TagdnLt8wwoLLSJ43kYP2c8Oy/2DfNulnhxeGRciODkmgDBcsXeiBY4JNsL65IJPwl/O
         GW5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ztPTKR8sr9h6D18SGkQNBYXp/fqVZdKTe5VGqgvKvQk=;
        fh=rrYYxR7rPrfZ9oPDzrWqTdscfrSKKogWCwrUGRk3Wag=;
        b=e5QZEKmbICDdaZbKGR1eqrfv6QZcHJFxfFhy/ZfMAvF/+M2Y3ejVe0wPX4LWau+S9c
         wBRz91yodoIlZo2sNdH7cWvY7Qgu3e2H1OyFVny6kfAG0yQgRxxzmOg4ar/4Ro13mBss
         c9lG/k/HLsN/DIt3GYiHrZ1yYNBXqOvJ7Qf03gr7R7eehgnlPhMhznrJHHY1LQn/aF4l
         V7u/kC9a1DEyq5C/iddDJh2wVJ7LD6FjT4Gcugi6GFHSkXMvQTyPmNJuNuFY7yPK5QHH
         EhHBKJKX1oyUdlgnNbB4vnRbMA19v7zhBVBFxFA2OQ2yA70VIZRTJRa71ZvvGaywCEvR
         uFxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ea6gr3dH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta1.migadu.com (out-188.mta1.migadu.com. [2001:41d0:203:375::bc])
        by gmr-mx.google.com with ESMTPS id az15-20020a05600c600f00b0040b47a6405bsi355136wmb.1.2023.12.21.10.00.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 10:00:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bc as permitted sender) client-ip=2001:41d0:203:375::bc;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Nathan Chancellor <nathan@kernel.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: Mark unpoison_slab_object() as static
Date: Thu, 21 Dec 2023 19:00:42 +0100
Message-Id: <20231221180042.104694-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ea6gr3dH;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Nathan Chancellor <nathan@kernel.org>

With -Wmissing-prototypes enabled, there is a warning that
unpoison_slab_object() has no prototype, breaking the build with
CONFIG_WERROR=y:

  mm/kasan/common.c:271:6: error: no previous prototype for 'unpoison_slab_object' [-Werror=missing-prototypes]
    271 | void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
        |      ^~~~~~~~~~~~~~~~~~~~
  cc1: all warnings being treated as errors

Mark the function as static, as it is not used outside of this
translation unit, clearing up the warning.

Fixes: 3f38c3c5bc40 ("kasan: save alloc stack traces for mempool")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Mark as "static inline" instead of just "static".
---
 mm/kasan/common.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ebb1b23d6480..f4255e807b74 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -277,8 +277,8 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by kasan_poison_pages(). */
 }
 
-void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
-			  bool init)
+static inline void unpoison_slab_object(struct kmem_cache *cache, void *object,
+					gfp_t flags, bool init)
 {
 	/*
 	 * Unpoison the whole object. For kmalloc() allocations,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221180042.104694-1-andrey.konovalov%40linux.dev.
