Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3EASP6AKGQEG5MO4RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4653228C2FA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:33 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id h14sf6909434ljj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535533; cv=pass;
        d=google.com; s=arc-20160816;
        b=AVKMCge4qOl9aovf6LKAzKUHFNBNOgMo/Apqzms6aZ+e6+kTXCOvuMAtquO0YB6nzN
         o8QlckK3ARS6IizbSNwgj9ve8Iy4hjUmumfqnXddJ0yE6JH+v3w1u5PR+Ye+a91xdn9V
         Mxnyxn5ScduHngaqOqzo7sOU9HHdOdaad6oxx2rHdO28aC3fwFq/A5KXKsQLggKSST00
         UUk4t5pVtULgYTv8Qp6hrXqiCQTeQMCf+0OcEjOf2vptjsI/ZxDxsyYChPLvcagTvftg
         NjXaT0KwyC2zcxyHMfi2Q+gtfl3rw6CerD6Dxz+vuhF1743YcJsauYTZtZlQSvGk+XLk
         dtMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=U+Pyld000YW9CGjmn9LCx5/dUuiKnEplwOjgRDJb6wY=;
        b=b3p9i+T/Uy7SyPALVx3uaP4OHjtjM+wc5s9f2+jeIX6OM9rTdiE/lqJ2fNyFRclJBS
         mf5xvBEAcVCLIjY4KTcEECDbzKmxHw2lU6VM4m8Gdi0aeg7Jdrghi13rpo5YcpNAfqfD
         /uEMMOP2NJD9jqvVjLcSYSdhnpzagRe6ZUwqHLgYa8uz4HDjNd+LRVouIPux56+OZ+r0
         kscaKgpMkcOkfiG8K2kyJC7XXwjOTWXPdpI7TGB9bD/PJlG6RrqifZx47XJlZQ/HBU5n
         n8yKOUJzR5d4HUs8ysbf5TlltKg50Z3iuMd+iWmJW7pIF3GcWnpz+QaB1hJYtUdS/J8H
         zH9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vBaZz+YU;
       spf=pass (google.com: domain of 3a8cexwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3a8CEXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=U+Pyld000YW9CGjmn9LCx5/dUuiKnEplwOjgRDJb6wY=;
        b=sL5teJb5zcxC4xJN4HLoKLDRVvH/da9d7hc5V1XPnPRUP9DjDTUa64T9MDtUOab9xw
         jGbNyOaYspsAm92Qo3+rHyBLRw15i/FcWqRmf5xlQZePSTxwBDhmwfuw34KKA6VF2/xD
         2WRHxrlatQHNjTLhTstLZFR48wU4vWlcdZTnL7uDF/+9VQzxxf2qS6N8RhfmUa/SI+iF
         GalKxPw65nsLLIlOE5i029XL4EaMLhsvZxIfOpgplp8/lfL32pKlkKVIjGfI2zPwtF+q
         heoLRuFn8JF9LKRU8i+EHxDxZl910OcGLgY4dsYs3l2JlADvvEum7ismCud920pf6tYV
         2hSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U+Pyld000YW9CGjmn9LCx5/dUuiKnEplwOjgRDJb6wY=;
        b=PwymRzqiYGwRXChRAk9Dvj5bZbLAYAK6z+tS93QuDMvR0szMMwkLlXXZ4oY8JHWSF8
         i/VTsQB7EgdeWGZiLPOnTVFtGJdgqWNIGGdOyl7RN3KEx+0rgUqaq/v/Q+L9pyLRaXR8
         i65Wzx0vtSlTTLS1XbMO/akga9Tizdt8823sBv3wRyPKagUrgW5dYwxvkISnXRIM9/f2
         3LILnuP8bZYZ96P5+BO338OPK/CfeX+A3rZtb6CJanjuBOiYtrZfUnMD83C3XoaiyAnq
         Pu+pfxTlOX41z5r1lWp7zqTo9Pcqj/zWOETAexJAAx/w5eZoLsMitIWYPgRDOTg1FtoB
         8vGw==
X-Gm-Message-State: AOAM533jQVDyT6kKHS2zbDArlRVe+H8Ov4zc5cRPqWW5eyH59rg1a7oD
	0gbPKeizrJN51bz+lrwP4Kk=
X-Google-Smtp-Source: ABdhPJzbGf0gWMfnDIVQt1jVTfpBMfWT/vor2zX6IXEtEDAahA8PzGaMgWitBL1hqPxD5WFxKTKWUg==
X-Received: by 2002:a2e:6c0e:: with SMTP id h14mr535311ljc.117.1602535532850;
        Mon, 12 Oct 2020 13:45:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7313:: with SMTP id o19ls820520ljc.11.gmail; Mon, 12 Oct
 2020 13:45:31 -0700 (PDT)
X-Received: by 2002:a2e:6816:: with SMTP id c22mr12165928lja.200.1602535531758;
        Mon, 12 Oct 2020 13:45:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535531; cv=none;
        d=google.com; s=arc-20160816;
        b=xIK95f3PV7rc2yRkWlGcKC3m91qyQACv/txj3vrCoAl2wLexL+isc38fqqoV+sWtbz
         sXyUJOgR/wGl1SiANCXpKBJRqnMEOy0F4WcK4PFkhpHde8Ld3ghlbTzmcv2QD9dkTP6H
         wufBWTdY+rt9Fznsny0knWRpx+RM+mYKGtlW6Ns5FhoCzhpGKMj/YYTd62AS58TsvTmx
         G/451eiwQNkJS9gm22/iFgkUasoqsHwfGtHRWzKFdC2WdHNFBqNlqeEFrNCkpv9q579I
         jQEer4jYX82cx2QrsHZeZNX0Rqxof7gTB99PZdGOWtbHHAJjdSsleN4zmjLmO7gLxWfZ
         H/ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+lIiyQNbZ2iD7jyjbQzQvRa+OabJUbarW1CP8KW9GaM=;
        b=j6S+VAKEYiOxgTFEYjNSGU+o1vAtiHuC2b7A2jXjMKptjn6dg605sr27CSM4s6YAV9
         9ME6d6fjuiGMwLdfj/4ODc9XPY9RkaigKufm1bn1cVsFxN8rPhp6tsD+sc7ZQLOCYnGp
         HUBHYPzub2M+XtGIm7hpMn6dVHmdn2HSYqDu2iALAeVJhX7NiV0zsqSrpckAueAl405/
         QZQRr7ZzJ8D15BahiJroOAHy8hL2LZMGWywCvxnbJMr9G36rDEnIYvB43zEuhwghCXrW
         Msfn64WMjx2dBo8eqtrnkYk5sD5uaAIRLdEWbVpHMJvQnC8O8Br4rqPxmgkauAdodzF7
         /cvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vBaZz+YU;
       spf=pass (google.com: domain of 3a8cexwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3a8CEXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i16si162731ljj.3.2020.10.12.13.45.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a8cexwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 73so5439134wma.5
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:31 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9952:: with SMTP id
 b79mr2315293wme.144.1602535531176; Mon, 12 Oct 2020 13:45:31 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:22 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <1ad8692bc5cbe77ffa26052c2e827e1949f2ec84.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 16/40] kasan: only build init.c for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vBaZz+YU;       spf=pass
 (google.com: domain of 3a8cexwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3a8CEXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory, so only build init.c that
contains shadow initialization code for software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I8d68c47345afc1dbedadde738f34a874dcae5080
---
 mm/kasan/Makefile | 6 +++---
 mm/kasan/init.c   | 2 +-
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 370d970e5ab5..7cf685bb51bd 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -29,6 +29,6 @@ CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-obj-$(CONFIG_KASAN) := common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
+obj-$(CONFIG_KASAN) := common.o report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index dfddd6c39fe6..1a71eaa8c5f9 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains some kasan initialization code.
+ * This file contains KASAN shadow initialization code.
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ad8692bc5cbe77ffa26052c2e827e1949f2ec84.1602535397.git.andreyknvl%40google.com.
