Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGUH53AAMGQEDB6A6VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 94025AAE5B9
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:00:27 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43cf5196c25sf265605e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:00:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746633627; cv=pass;
        d=google.com; s=arc-20240605;
        b=WWYsHyOh2wAvkDeB0MZSiiWuiSKKAkcYnJ1fmZ4YMwAbxX/FGhp7i+d/Kjh37UCxsY
         1lSpeXDB53DRALlWj5dTAtjf5T/aV1snfbXXLmy26fqBDv325yrF8lAnbCfbFQnR75aL
         Epz6k2kwMVFd77UvJzd57BzgusAU2H3Lk4LyYFuOtUd9sdyfTAbfdOWXuaTvD+AgQf69
         GH5Jz751Mq0oTFtihCNqtkMEMtz8iIqfwMCUTx2+NLU1uBareJlLzc/WJxpJ5lWdt2dB
         WnzwlYpILmrAusHt1C1UMhtioeDfPrCET1k9MB9Kt14aV1R0ouyWDbw+cKLHemD6CS+m
         7/QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=cB1zZIg/SMom8NQYvrY4zQ1hzSGMCBeP9afkAhxGPOY=;
        fh=KpmHwMiaTGNwK1wqMTt+TCaUnx9AM3dzc12jXDbC7P4=;
        b=Kbu4nZfsADVQfkgvgMa/6z83o/GnFhOUuWdLOQpOtSCpm1V6xvXcHPdf4wvLOnCeeB
         nmMD9H3/fGBectx0GEm5q1mxJwDjAKmMfON3SibpJ3YF57D8H+0DOXiqJmq1PXLgoDzs
         YLA0UQY5MbZZDLlFVPTYytk7IaR+ddvGcOh96jv0t21N01w9Kgecozfmit/cwBcgOSQR
         XE+IxD8ZlBktK0fN8knA7EMvxGiHmCeTWrPfNNCEWytjIp2ODj8loLgOR5vRjeI92EM4
         nYuf5vcGLwvuXxNm+NrzVtoBbhKTq5b7UGxHXgdlzVEjZC6SLwB3KrGgO+HhNi+mJi7o
         n0GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xx2Zf3Bm;
       spf=pass (google.com: domain of 3mimbaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3mIMbaAYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746633627; x=1747238427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cB1zZIg/SMom8NQYvrY4zQ1hzSGMCBeP9afkAhxGPOY=;
        b=wYg9GHz7/6+AehdeUz2lfWx68PPXy85ASPu7VEJB08SJwKxpryRPYpZijuaRxWglo/
         hITkGc9IDx5/elicd62mdeS9waR4ze9glXCFjvaSW9RC9IWlFJfTiL5F2X56el4cmAHQ
         xSxd4cSWs2eT5mxmr32ISFQgMqyDmhNpTY86FtWJUGc1UhVNaN0JY3VYv+qjd5O8oHFn
         dmBSWji5Y4P6xP7qEkxuNv3AWCjT4UckzIxlyiDdY+bM7QXtxW3AiGDtgmGyoG1f17NQ
         F+FImS/aNqCNrbYrd6AHxLSSynmxOCVjPc6YFbKQ7wz8xFQueKfrIZNimbpBXFZjt4lM
         64ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746633627; x=1747238427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cB1zZIg/SMom8NQYvrY4zQ1hzSGMCBeP9afkAhxGPOY=;
        b=mdme6C3ue8CooaorB5xGpSv29OMvrLRGjWN5WvW6C+TLm4qTTHSL0gWGlyp+aUJrMj
         d9R3A6gyP3Z/soH7si1mRnyHkkOPkbBEaOzdiwkp+fL3evaSDG/VFae4sz2LypsDL87U
         92leu6zeDWDPhVBCbd5CRfRtupAASin4qD27zVQ27zjCVhipA+c3WI11TD6SFVmag9Mm
         PIjiX2iNObeIXYeS1nGv2MimeuSk1xNmMuPn8/REkfglmPaoqAmEKubQEPniawevQgr3
         DUIVROuZY+URdNgt34FmQ7ogdcglz4PwVUDO8VzMSwqHH1JeS+uM/25rzb6DXvPCcjHw
         hkFA==
X-Forwarded-Encrypted: i=2; AJvYcCWqMH2c4E+U7uMO/PZ1jNdxW9Rex1WbLWhTgTM0wHaOUpNAi7aMEiOfnocVt00exAbuLsnSxg==@lfdr.de
X-Gm-Message-State: AOJu0YxWiZASsrKb+bwYf0eu2zjp0TeHjI7Yzb+b/9AOXIAW4+y9m6RW
	/LJSPr3wwiHxPwJbkxfKE0CMlhZA4eoE4YmNza2/Lzeu3Vq7Hf9g
X-Google-Smtp-Source: AGHT+IEsjY6Z50fOCT/QiEWD0F0evlQk+VYmJaTRpSj9RS072eB9RzI7znyX0Cu4G1yP9+NLbQ7oeg==
X-Received: by 2002:a05:6000:420c:b0:3a0:acfd:d509 with SMTP id ffacd0b85a97d-3a0b4a3015fmr3367501f8f.59.1746633627118;
        Wed, 07 May 2025 09:00:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHXYzKrNgcJGAILh4bRtMJjHG4k2bKY2dV89W83s9edmQ==
Received: by 2002:a5d:5f90:0:b0:3a0:74cc:b8d3 with SMTP id ffacd0b85a97d-3a0b96ff9dels35286f8f.2.-pod-prod-08-eu;
 Wed, 07 May 2025 09:00:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVe+Cr8H5jQY8Nqm+LEWGAKsi2N7R8rz7Mu65rlozcYV0cRhwZoJOFA5ipJglZMXJls/NYVttr/rHM=@googlegroups.com
X-Received: by 2002:a5d:64c7:0:b0:3a0:8495:cb75 with SMTP id ffacd0b85a97d-3a0b49ae884mr3434602f8f.9.1746633624818;
        Wed, 07 May 2025 09:00:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746633624; cv=none;
        d=google.com; s=arc-20240605;
        b=LBnM+f0TksJYlJX1ofPt+fAHqcemr2a8WhMPRwUAfP8T1GI/TiuHbMYdp/9c64tjSj
         3j+f77T1a+u/cjp7RWc/qZG6STXPmvKf86JbXCX/YztYyO1j5ZRshSZrOpytJZbbzFSn
         rWU/IKHCQ/feX0LVUoGmORPtc3Lg0q17zkbZSjSuTxWQz38sMUDw2OqCcLS72u636J6M
         W9kexqlcRU5i2JZXFXPKjj5+dk+D4187hg3xY2nUuD7tF6g6IVHnOJJPNNA4COh9p88t
         vpXBo9ut2E2VXKckqlRlMXV/NuhNJVD5CgCYaYBmwEmLdiXVw4m5hEpQyMBx+q7NMD/1
         WrNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/HD+2FNI5wfvoRdutnU1OJmD0qGDP/bCL3lQrffpAd0=;
        fh=zs7ynxbYbI9hrYDifRrHbpg6nPzjqW2hC+L/wejkMwQ=;
        b=Dard3EfF9KVNUWeq77uQmor07Dfbn1npmEMyB1pVVXDo2CnL5AaxQgOLqmzpaGGWqr
         HC91yJHrO6xGcPrAQVDzo5yEeXCFsA9NFvyzXDx3PlngPkq4Ysi+mbzDg0PfWyyJjd/O
         /wmwAfuBNt/jFcQOFvdXZawHOY/uHSovdq/V4uO0MjmBi1h9UwnARsjXhqtASpMOx1UH
         UMkkAhPKalzu71DS2Vfcl6JwmNxEnP9L3Awa1nIFBknvr0EBe2xIypOxIHIq5I3dBwta
         p79mLj2NF+ko2IUGwTKeEIS2vYVly4G+JJPFaAihrri5YOVlk2QJRpQfgVUuJg0tgwXA
         mXqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xx2Zf3Bm;
       spf=pass (google.com: domain of 3mimbaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3mIMbaAYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a0a2ad91d8si151424f8f.0.2025.05.07.09.00.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:00:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mimbaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5fbf5bed97dso879530a12.1
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:00:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXs6HGnpSobqeJewuUOrOH1bjibtWCjFJdMJPzqdtJOu/x8Lp4/LE+mKlpcavDUh8pfpM4smV6X6tQ=@googlegroups.com
X-Received: from edbig14.prod.google.com ([2002:a05:6402:458e:b0:5fb:c088:893a])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:51cb:b0:5fb:a146:8600
 with SMTP id 4fb4d7f45d1cf-5fbe9f46c17mr3577975a12.25.1746633624482; Wed, 07
 May 2025 09:00:24 -0700 (PDT)
Date: Wed,  7 May 2025 18:00:11 +0200
In-Reply-To: <20250507160012.3311104-1-glider@google.com>
Mime-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250507160012.3311104-4-glider@google.com>
Subject: [PATCH 4/5] kmsan: enter the runtime around kmsan_internal_memmove_metadata()
 call
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, bvanassche@acm.org, 
	kent.overstreet@linux.dev, iii@linux.ibm.com, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xx2Zf3Bm;       spf=pass
 (google.com: domain of 3mimbaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3mIMbaAYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

kmsan_internal_memmove_metadata() transitively calls stack_depot_save()
(via kmsan_internal_chain_origin() and kmsan_save_stack_with_flags()),
which may allocate memory. Guard it with kmsan_enter_runtime() and
kmsan_leave_runtime() to avoid recursion.

This bug was spotted by CONFIG_WARN_CAPABILITY_ANALYSIS=y

Cc: Marco Elver <elver@google.com>
Cc: Bart Van Assche <bvanassche@acm.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/hooks.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 05f2faa540545..97de3d6194f07 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -275,8 +275,10 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 		 * Don't check anything, just copy the shadow of the copied
 		 * bytes.
 		 */
+		kmsan_enter_runtime();
 		kmsan_internal_memmove_metadata((void *)to, (void *)from,
 						to_copy - left);
+		kmsan_leave_runtime();
 	}
 	user_access_restore(ua_flags);
 }
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507160012.3311104-4-glider%40google.com.
