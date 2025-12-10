Return-Path: <kasan-dev+bncBAABBW6343EQMGQEDN74K7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id CE4D8CB39F7
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:29:00 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-42e2e448d01sf5380247f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:29:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387740; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZHYyGVfeGQ9DDUGtEOohNaypIG82zQdj4pIojjhF1HqDKufZVLZdm7v+x1QSpNKHHt
         FOty334zf0GRGUuWSBhNgXscHIcl8xblk0u4E8kmOcJJcv2+TeHOaCqLOGyfaQI3VBjg
         VUZUaZB+gTlE0MJ3qH8KUZTdwG5NkMYiKB3ryZHOAdICQ5vKPxggZ4TJQCepoHDqlogq
         ltx31i9uFXyvRco1rF4az0NkKijopJQARtXOr9TnaOcogut81yqqPzMFC5ZbsHmlQRom
         hGmdht21mzrqlNqc53e3lUQJkgrv0uL99wrzp0tc0kJ4nsTmAWjq/xFfaVLxt3lGTqef
         l1WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=92ygMpm70aNHNw57PyxHSk4h/SUWqBb8mNnH/gURE4A=;
        fh=vgY1F0DqCLTkkVzm+qBmVwihT02T58WQAD77KgRCb8M=;
        b=WuCmRZGuSdOqEsFnqoCPYqcxOus1z3WncpMriXHuUhF432Fv+BSkp3FWIPbzXoy4lz
         yYvhwrcDvw744oa63x5oKCoymY+6gurpQsSCwlGLUrzxvEGyZe/I3Vpa9le5F+NHOeCH
         DpZm/inbWIyWgd39mi6uxQbuSQhOgi1uTbfGQHIKZAvXytWKm98GYgTnmQRQtCMNLmkd
         CRhE0rSdF7XzxlQR4hmvWmHYjLgohJcEr32c8m3/oQvIrtTTlkOaXCy4EX6eXuNeGckW
         IceZSLyRhtL8p/yOv17i9ANU1FhCQyEh185JtqBN5GJYNWTGKB4wO62NQ4LvZAEGlPo4
         icOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=QTYFtRRZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387740; x=1765992540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=92ygMpm70aNHNw57PyxHSk4h/SUWqBb8mNnH/gURE4A=;
        b=D6aQE9kp7h9QsPvSyW2xGIOlEfBswik1tfVHC91fi3QYOpcIvdiQ9Wu/S4oHe8Sht2
         TITShyPP0UAsS2pC8PEE9vujb7GDxNJle3rVrF7dy9QW9NKvD2oOzu1V40bgjRmuXAXk
         3X8BeGZihrRAo+ulslB8rVVlf+UyhHIBDvsOuo+T5pNeVAbK+KouMgfSwSEroDZ8Asm8
         s/GfM/uydvKRnEbHUwOm7P/oaO6hh8q23p+Fhz74zDO6WN8u1xtXOCIwQo4qDQyPxTmn
         4VQ2cGtBAWTXEy0PDsCTEKE3rZFAn65aSjNDYs0iCK/qC3bSazBigXM2gCvVW9j4sdSL
         8S6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387740; x=1765992540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=92ygMpm70aNHNw57PyxHSk4h/SUWqBb8mNnH/gURE4A=;
        b=GjdjHSRhsp7aDFzgbKjxPcKxpgNgYEflHrpBvTV7+/hsMWrDV/GGC9+Kli/bVKWbx2
         AHTqt0/2BPkzFC7yh/g1V5aqTaSuV181/2xgXrx7J/n5/e7Ymm8RFk23aLQfEXHXiMGF
         Giyppy3aM/+niHZBpid2cBMDaNMGDTFHZN7uGU+4DWtIeshkxbdEBz6GxrPbeI6Y3h4J
         4BxRpOpLn/nYP1/qJjVI3Ckhjz5cnFjqWDDJyvoABSQsFk7gVYt5+cQ4WMRsj+Tb8H5K
         cTPj8n65OYcjHyCvxMPnXQZ8GQLI50A0VnSChhP0v+WSnKtJCT2fZUBdzpHmykvl9gpS
         jnJA==
X-Forwarded-Encrypted: i=2; AJvYcCUp7s3dU1ONyDfsdSL9nF3b/CEtSN34z1EG9XKcu2dnfpp5Cng8zV8zS1Xjo0jRBnCBeXPTCw==@lfdr.de
X-Gm-Message-State: AOJu0YzgD82rUHI+smT9KGn80L+K5wUOgRT0siZOt2XnUWyvYzbMnVSn
	Z9ZluCZw4KGajNtntAvauYdTsYoYLxX0NSJW4mj9Brf+lWTK8DKhIyD0
X-Google-Smtp-Source: AGHT+IFS76mPXJGouj+3dOu7mKeUXzImD/9gO6a4X6mHhJXlN0rQrgad+yXMZ3Pqj4IF+UXkI/ldsQ==
X-Received: by 2002:a05:6000:2302:b0:42b:38b1:e32e with SMTP id ffacd0b85a97d-42fa3b08931mr3465278f8f.46.1765387739971;
        Wed, 10 Dec 2025 09:28:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYrcVg2sKz1mhUIbPvccqEkxM6df00ofH1SMmW+cfN/Hw=="
Received: by 2002:a05:6000:2309:b0:42b:2f75:338 with SMTP id
 ffacd0b85a97d-42fa8a540a5ls28716f8f.0.-pod-prod-07-eu; Wed, 10 Dec 2025
 09:28:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAeWVEYwgPT6K38jkQHd65aJTHCozRD7KilTjvYZ7YVkSYOOunrTqAiQvuNBrs9tubpiVG/kb6fFU=@googlegroups.com
X-Received: by 2002:a05:6000:40e1:b0:429:f0a4:22e with SMTP id ffacd0b85a97d-42fa3b125bdmr4143204f8f.54.1765387737928;
        Wed, 10 Dec 2025 09:28:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387737; cv=none;
        d=google.com; s=arc-20240605;
        b=ekTCwrpgJdQo5dtW/XKxZVJ9jjf+rEEf1k1+tfzoGMWgqPT1h/u7wKOZl7UcbdJOf8
         4hOqTlJzWFVG/WxgwI4iZZI7kEm0v9SKOSUc8FxBEk+nfuHIcHRuYWlB4Pw7jac1R6y/
         JPiZAJHOKDVGXKMQDKDGjNvuHmaEDllWqjCrwdp3iRaUqG/QIfXNDlqGCbuxEVf3mmi1
         iIOvVyqDu0aqY4vGIjjo0ftWCqhQ/UfiNywm/cR08Al9QaLNLY5MrVLQyvjfxDrdwP/n
         jYjqtL7X48BygPlhE04mF9MVc5xjk+ms8gDK+CN/Xcjzm6LMRlQrb+oK/zhv2q/4zQ0x
         9xcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=i82hVLnXXbAVfgARSkNfTSungiQEgJywgSx/RsX/wSc=;
        fh=n1p3O5YFTWprYVVYObOSg4BY7N6KlNSi+JgilNr1FE4=;
        b=eouYCArhfcvfz6qsjQnHcscDooNDmn/V3nIv1uruunKTD3/gnQGxyXadGudH/oQeys
         xi71yqFaUG9YXl37LpH1+EJ6xjRwLfMauwBrE8QtI960kNn3sYhtWGQ5npKYmHr15c5O
         UJB9dJorf94XkOv7QKZ0KtEnK+KmWD/oRN9+u4p8kijJerYGeAH0ms+hElqQBbhPbZw1
         0K/4sAd5hWqsRwZNdYCk5URtXNke4KjGJYjekuVwXHSuJQGalNQirbz327FxtZZhgsBb
         L4pL4+3wzKejGCig0cTzfqq3LhY+E32LKvi/tYmaVg+BK+IpeuY0v6RUsBKMWg7CEeI8
         ZDGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=QTYFtRRZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106120.protonmail.ch (mail-106120.protonmail.ch. [79.135.106.120])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42fa8b88d93si1568f8f.8.2025.12.10.09.28.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:28:57 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) client-ip=79.135.106.120;
Date: Wed, 10 Dec 2025 17:28:51 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: [PATCH v7 03/15] kasan: Fix inline mode for x86 tag-based mode
Message-ID: <b06ac8eb411157c7c60f6893cfdd8148b6dcc0d0.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: a7071320bc0417d682deed36d6eb1da05840a46c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=QTYFtRRZ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be pasted into each relevant
location along with KASAN related constants during compilation. If set
to one all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this, enabling inline mode in software tag-based KASAN
doesn't work on x86 as the kernel script doesn't zero out the parameter
and always sets up the outline mode.

Explicitly zero out hwasan-instrument-with-calls when enabling inline
mode in tag-based KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Changelog v7:
- Add Alexander's Reviewed-by tag.

Changelog v6:
- Add Andrey's Reviewed-by tag.

Changelog v3:
- Add this patch to the series.

 scripts/Makefile.kasan | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 0ba2aac3b8dc..e485814df3e9 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -76,8 +76,11 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
 		   -Zsanitizer-recover=kernel-hwaddress
 
+# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it to 0
+# when inline mode is enabled.
 ifdef CONFIG_KASAN_INLINE
 	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+	kasan_params += hwasan-instrument-with-calls=0
 else
 	kasan_params += hwasan-instrument-with-calls=1
 endif
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b06ac8eb411157c7c60f6893cfdd8148b6dcc0d0.1765386422.git.m.wieczorretman%40pm.me.
