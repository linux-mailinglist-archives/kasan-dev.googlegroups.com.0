Return-Path: <kasan-dev+bncBAABBK567O2AMGQE4P2YHCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id EC78493969D
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2024 00:37:32 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-36832c7023bsf2688829f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 15:37:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721687852; cv=pass;
        d=google.com; s=arc-20160816;
        b=xDx8bolFPOIkVrJOhO9UvmHuq/88etezE7Qvp440PM81EUhjmgP5xEampQYpqgHA+v
         5TU9CF0njIhpzQuqHBFzZbGfHFwSQQSguw/Y3bA6DU24luux6i+TXonY8N5hT0jOrSio
         ANwXyvtpIqgY+so/HHfD5ea0TVVT3FVYBNoT2kNb5/zRIoA3FNrhz+ofyW5zAy5M2cpO
         jfV++yRQYPs8ejMJnZjORbRKHgWJstfByMuNSU5MAvzI674p4eZZlV4zrKO2P/iwe8Kw
         6ZbrfeFMLtJq+Dv0RfnsCIL5dbmkZEQaJMTHRjDdPsd+phyxOPMicw+E5eKzj0tyf7oB
         hBSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=W/TcV641GrTnTIcpEf0Oe7M/zK+ntfSiVO+iW1NoFTo=;
        fh=6YOhciw7t4eQsNjkKwUkbmR3+fXqT/bsqFYrMnSQ1lY=;
        b=esNhBEvwDym+6uGlT0flM6yKxawL+nBqlaLqZAjEYC6WQ1FFccM5vO13QMJin1YEY/
         TW9xa0yQU4jq65ypwjvSjwg4VcwJfD+aciZNbI72/yyLu5ofZFyJhajqkbTH93Qfs6jk
         TYtQLh1/JUHLcAp8q3rSf3tX+pTfIrDWanCyAYxt6qLDATi7k+nygsEuO4xcHSX1bZvH
         rbhuFS/RUX+BgZh19jz8ra94ubS2WmueuX87lXuQ9kyvdPpHKi4d8n/EKD0ipmZbxM8a
         v4bZXH1OtSiWv6XEdGJ5j7+wd7+PSA0TL0faIg0zqhhiAIN2yvwHytZ/Ts9r+agvKk8K
         cQ3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nbYbTP9Z;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721687852; x=1722292652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W/TcV641GrTnTIcpEf0Oe7M/zK+ntfSiVO+iW1NoFTo=;
        b=O+GlcobhZDv3I8iRMF1njfGYBVa2U+ysxYLmtoxaFAfd8bxbrVCt7c2yzU8FfBF67J
         5svASe1EajIeJdkpw32Z5PzJCLRDNOnscxJx5o0Uy7Wp+45A0h9McJ9UhLOXgSIeH/Xq
         WrFPZtOMIwvJj48nThkeXKJCALoMM3CpaziylV/6ZJxuTlJmBM9YmT9zpOOZIjVeLoql
         5+eN2SDTwwTcgWMmBxOTGpeghDLrUdjl7eLiPi8ZvPSSy54vKggiQ6R1QXa6yje8bG8m
         njMlEfKXx9R7JnKV0647lHUbZix5TV9A9tWdE6Ho3HEUt68aMDXiJ4fqdqsWmsMtKbuk
         Ma2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721687852; x=1722292652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W/TcV641GrTnTIcpEf0Oe7M/zK+ntfSiVO+iW1NoFTo=;
        b=gBi0Gw5yXURgB2/pDCKLKDuMk++Z077eNrGQfiPBU0VU/SdZtWP4J1icWdRINc3oTN
         3POoHgUyEuxQt60yiUmwQWYCyv2nh2VE//AWnctEp3I0ieHqrcMxWB1KnVAjmYiAC1ny
         LjBi8GpUC582n+K8sMPWT4brrvAOeZ/tYQ/miLGgCjh+ewU92Wgv35HYlCIsvC3GYpgL
         h1tFGwDPDnnKrPBJlucABFtmw77vGmw0kdjvSZccMix+ZSfwrMsDU9wNcHDg3f0RKRTN
         SGZGMd6eDc8gUCd+zSubBnCRto6dRp8eeLpM08RSYB4FXb0uzbtsOeZZBOtxDC6tU+Gd
         HKHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGQdszN6tsCY6piBAMb+ovipDmGDOhVaAJAFRbJCST1v/Ert0pHXnAUFAv3uV/O8/Se76U2aISnjP0Zeyu1RYd1Fb2m3ubUQ==
X-Gm-Message-State: AOJu0YwQwhMhEj4d7UAc+x9tC5sFfozWCF7B40TAQrHEBSjfJ+K1s68o
	3nrW16EtTbv7kILodFY3cU3Nfg/HTZl9DT9vvF8QmuHNfusVuKvv
X-Google-Smtp-Source: AGHT+IFFq0qBQlHZ3vqW3WThOyUZfY104hJNyq/VhI1atFg66hUn4J0K5m5Ptnm1yFDag4//MrKgew==
X-Received: by 2002:a5d:6a46:0:b0:368:334e:2d2a with SMTP id ffacd0b85a97d-369bae34a07mr5851241f8f.18.1721687851963;
        Mon, 22 Jul 2024 15:37:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:470e:b0:426:6982:f5de with SMTP id
 5b1f17b1804b1-427c83991cels23221925e9.1.-pod-prod-08-eu; Mon, 22 Jul 2024
 15:37:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbHVJUULeQa5sZey8AYzO2rOMep4LfJUCCZMG4V11Niu39rzwa8q8TCThNst3XyTq2f2gYa5xDWkRakW3rT1j6QUmRJIWdqYFQkg==
X-Received: by 2002:a05:600c:524b:b0:426:8884:2c58 with SMTP id 5b1f17b1804b1-427df7ba349mr49655355e9.4.1721687850398;
        Mon, 22 Jul 2024 15:37:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721687850; cv=none;
        d=google.com; s=arc-20160816;
        b=HdtXn/2EMlZSK8oQe3u/VoTleM99agLdqbWJWwFWoNqiVEgcJm5Cs0Qhdrbxz2DvBK
         7ZqGMYX01mm2xhxBXlIsJMA2Om/2nraxCd0X2+3I+8PUCNubkgtbOQFOOEAKAJsPDOXF
         nnA2veSwXN/RNeykb2UyfuQbBekj//ffrZnDxLUvAKBpfSwGzVZqDYoNvoI1vUbCBbzB
         qP6945Hq5O63OvgDCCQ7n3DqN3FVEfOGICrUbS706YxNgdIXCXiiiO1snN4Fd3oUQ9f6
         /q8am4+BN58tWsIrvT7Qn0obbsyGHmbKLrqZUY4JiliMPE+PP3Dd/q0GqyKm8cnRgmZK
         NBtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=r0s2bcH9kroSUN7wqiU+85l1vjvMcUHeZz27ffRte2E=;
        fh=si4CEiQuxnQSW/nkSZ+NLRjnAIUqQxd7bzQ989Jdo2M=;
        b=sy6r1Qmb9C6UHRJlbPhnvsfc0VJbRlsts5aYNXz4WjzLB3nwfvLfFDxN9nf9HDOysQ
         aTqHwpVLtvcRbGSAG97tr7MjecghEFcnrQ47gA1egaiUh88lXma7Zo3d/cf5h12EdTjh
         Qw6QfLlWB4WaLNYJFh37DJsE+9iasaUyfbICkH4ccr9TW2jL6a4LlHR4R43rinLTC1xK
         VEUiuchypbz9YS0qgp+p1ZWWExjvZXncf+pxQ51LVPYtSlefzmLTOow0bPLw48AFvQiK
         c4IyESV9KZSmTh6c/dyMbQriyZBCA8GdcHy9sb49qiQVVBS1H961suRpkO4SzsAuhocK
         O9zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nbYbTP9Z;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [2001:41d0:203:375::b9])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ef50b152si127505e9.1.2024.07.22.15.37.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Jul 2024 15:37:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) client-ip=2001:41d0:203:375::b9;
X-Envelope-To: dvyukov@google.com
X-Envelope-To: akpm@linux-foundation.org
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: nogikh@google.com
X-Envelope-To: elver@google.com
X-Envelope-To: glider@google.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: linux-mm@kvack.org
X-Envelope-To: yury.norov@gmail.com
X-Envelope-To: linux@rasmusvillemoes.dk
X-Envelope-To: linux-kernel@vger.kernel.org
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Yury Norov <yury.norov@gmail.com>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcov: don't instrument lib/find_bit.c
Date: Tue, 23 Jul 2024 00:37:26 +0200
Message-Id: <20240722223726.194658-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nbYbTP9Z;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Andrey Konovalov <andreyknvl@gmail.com>

This file produces large amounts of flaky coverage not useful for the
KCOV's intended use case (guiding the fuzzing process).

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

I noticed this while running one of the syzkaller's programs.

In one run of the program, the number of KCOV entries amounts to ~300k,
with the top ones:

 117285 /home/user/src/lib/find_bit.c:137 (discriminator 10)
 116752 /home/user/src/lib/find_bit.c:137 (discriminator 3)
   2455 /home/user/src/lib/vsprintf.c:2559
   2033 /home/user/src/fs/kernfs/dir.c:317
   1662 /home/user/src/fs/kernfs/kernfs-internal.h:72
   ...

In another run (that triggers exactly the same behavior in the kernel),
the amount of entries drops to ~110k:

   7141 /home/user/src/lib/find_bit.c:137 (discriminator 10)
   7110 /home/user/src/lib/find_bit.c:137 (discriminator 3)
   2455 /home/user/src/lib/vsprintf.c:2559
   2033 /home/user/src/fs/kernfs/dir.c:317
   1662 /home/user/src/fs/kernfs/kernfs-internal.h:72
    ...

With this patch applied, the amount of KCOV entries for the same program
remains somewhat stable at ~100k.
---
 lib/Makefile | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Makefile b/lib/Makefile
index 322bb127b4dc..0fde1c360f32 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -14,6 +14,7 @@ KCOV_INSTRUMENT_list_debug.o := n
 KCOV_INSTRUMENT_debugobjects.o := n
 KCOV_INSTRUMENT_dynamic_debug.o := n
 KCOV_INSTRUMENT_fault-inject.o := n
+KCOV_INSTRUMENT_find_bit.o := n
 
 # string.o implements standard library functions like memset/memcpy etc.
 # Use -ffreestanding to ensure that the compiler does not try to "optimize"
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240722223726.194658-1-andrey.konovalov%40linux.dev.
