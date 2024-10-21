Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZEE3G4AMGQE6TGI24I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 283209A676B
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 14:00:38 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-539e13b8143sf3185968e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 05:00:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729512037; cv=pass;
        d=google.com; s=arc-20240605;
        b=kK15JMF6IPhY2TRuaj916XoRhojXXRgFJN2xZXCFdT4j54YauYphTop/eqq/msHxZI
         /CZOCHsbrTrWRWYjUWt5a4YE72pqWmtWzpPm59IwhSAIo+MShrLVnf8AjGyDFmVTLe6t
         LoeTZ2aJ1GWiF2EwkJMy/4Z+qm1vyBWHtKiwwZt40JeM44IDYhdq1aUvHB2+MVjasTc6
         qvuQNY1rWfJnZGrRifJbXVryJuQOwRHjSwn6HtwmP/+PDDnlpJovBwqYnsj/weDH+edQ
         3bCEk0ky8LoF6vmvOx7D5G+NqXfpQClVD1eRFemgK3P0tlINDzMpMeIsF5LceWqQNqQK
         8P3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ynAYl3OPYY81DKxcBMFY8k4fZxBgfcX+bhboeWHsVqc=;
        fh=JITk3UG2c7/ena3QVcNOFijpvrVPjVA2vz0BDVNKtJk=;
        b=AijMQJO6NFqlZ2WNiQAhPe9sSjhyacr1SiTB4DQAcg/qndJvEv7Ad6+2z2anXrPGzc
         WAT9GQaASfpcS/avsT/IyGF5usz/3UgFqXYjFV4YAtshbspzRZYosS3NuiL+2KdPbN5p
         bi/DDEZuDDq0/mg6DB5t4GxjiwmdpSds4mzWOdpDR2bW6uDpmJP30MrhfBAs+HMOT5Vj
         AEZlAkrpobFuxWPGUS6y/y3vd9s2dfWaCArJdrezHHuMc4q+ne2HQXSQeh8zIbMC0I7w
         ISOXKrUk4wVnp59+A7tEGJqllyCl80UZd4kjLbS8mgrpQyxkWjowmlPEPrU1Rgj6DjHY
         6oKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Sz07bwjy;
       spf=pass (google.com: domain of 3yeiwzwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3YEIWZwUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729512037; x=1730116837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ynAYl3OPYY81DKxcBMFY8k4fZxBgfcX+bhboeWHsVqc=;
        b=URkf5xY08fgjOqExfBjH84Jng3u2xAy8tOkrbgcNxpXos8ibUoAUeihqsy0mW3fDVW
         yT/EJ2jn9XygD62VT8+dK35djOi4HCg3EHAjqt6JSFJIY5jfoG8ba0HBGpatyCYWud/o
         hvIBsK412SJu1XnEfYtiENZgGq5z4PQ2raI1AP4TWDh2cnko56QO4qaoFX6ww/A6E1fz
         qTUKOyb4WOgeAlpUwaQZfYzBX1KBMS58YMBJaCfPjDO1POKxhrCOocrCoPe6aPjTNh1G
         u6ZUkwj8m6l9fMBfmxUtYkb8jiOrZzRdxShgECCKMYDRdYBWtqUnfRs8EwOgd43+jCGk
         JXyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729512037; x=1730116837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ynAYl3OPYY81DKxcBMFY8k4fZxBgfcX+bhboeWHsVqc=;
        b=Pv5u7JLKG8aipNA3Moz+x1siR5iXBt0IkI2YUgXzqpmm5EnlYeKZhxvC4FHIMkDTV8
         04i2TEFKMAovCtfmgxTl7zTRI9xGX2dEKsBK2cp3ajIrkj6BSopA9muEPhAHlS9yoJhU
         sP8x144EzEzmteAV0TWvnW2AQe5dT3dJkUmlcbAe1mp75f3fL7BAtK7FosfvgFfewSge
         8xS3QFZNN5NhMuf2MfdZ7FrJlW2iCuHeLCDouZt+rABH7sG5Yjdwfo1p3KPXLE/srRYN
         s9T8yY/9xpo2NC5Makfl6suV2JvGwCtEIYQXHn20Iimo/kHOKu7qp11mPg3WbFLADL4k
         18cw==
X-Forwarded-Encrypted: i=2; AJvYcCXEiKpdoULOw4Akv0mx7zhFntELbqN4Pmy2V5XOLM9qhCMEiSCcM3n84T6wchJ0odCXedlfgQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywz1q/RtYvLDTkg3wNfL/j31BOtVtHWDcpSdWt1jTjG5w2LS2rg
	MoVFvSMbe9JvDNVkf00g61cGfncGDlznPAoSRxviJREgC5xZtu+t
X-Google-Smtp-Source: AGHT+IFU3tySGKeNg4LMZOCmrmmZ0VZ4mnYabcLrKb56WynagYTckjFoiT2eYT4camTzLpFFdrwIVQ==
X-Received: by 2002:a05:6512:3e25:b0:539:e12c:bba7 with SMTP id 2adb3069b0e04-53a154410d5mr4548871e87.12.1729512036979;
        Mon, 21 Oct 2024 05:00:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c8d:b0:539:fdc6:d682 with SMTP id
 2adb3069b0e04-53a0c6b04c8ls821592e87.2.-pod-prod-02-eu; Mon, 21 Oct 2024
 05:00:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoRUnzbKJ1CnVt6hp8iEA+MeLj50CoBwzLKmDr73P0dz7f3xExWpWUb3lXjX74N/4/B6DLQ1ucoKU=@googlegroups.com
X-Received: by 2002:a05:6512:b1a:b0:539:f2b9:560d with SMTP id 2adb3069b0e04-53a15512b16mr4662624e87.61.1729512033710;
        Mon, 21 Oct 2024 05:00:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729512033; cv=none;
        d=google.com; s=arc-20240605;
        b=dQ5w3a4dZfne8rs9/j+XvexH8LN0+xoCgG/nwly7WLf00OiuN1OcmYtZ6o5CIQxGgM
         EulG9MbF6/Agqp8s4QIbIfp8GS0Z/Izxr0FigUS5Vueh+9pUL3Sl3l/uhmIeRilNQGs6
         iVqr6gf8kFJea7yksnKeKW2YUSqBPqrGR7hqFXJsvRAWKAAkzY00jvHaHSpnzXvP992h
         ZcYIpyfmgPVSy8Y9UN3yEE+cJmnlqsBU4sRZOtb0ZetavXXxbqOGidWpKoE9DglaaEUI
         b/SwEe+MmNxZeo8drNLwBvZ0kzGGrz0k3yxflqamMYs+Xx4/9Pzzr2j2wLwYcc0g+Vuu
         tFLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+RPnI/3Gz1Y4IhHQKOjsXLrlBegzE9vzRcMrKpdABMo=;
        fh=+YEY654OywJNUKOVS26xkhhtHk0PoKVq3Wt5EOjK5Ak=;
        b=a7+l97bDyRj8Q6Yy7p/wHW1YC+/XLm50uJ7zu+D1ORZuftrVWr9KbjpVPdHE39S7iE
         pYYJpVqeNitjwi8gyrwNmUoiKpB9fvjjzl/GQriU/dljIM7mImQYCrFsZYpnhisd2jk3
         dv124h/3EuiuVHvo5eCNWs4+dexg63NyJFzrAQda0LwXwdasKDbJCoP/Feb8fjXdzOjm
         J/oXvIFcCMer9SVNnI+QoLjZWS8Rwa8xKeTOGVlJgZ8iXS10oM+PknO5/karrdyUuWiT
         kLWGO8mtxg8wZIN6cn7o7OIevb2zYtpI6i6IyGW1fasXwGZeizinW3ICBQZIp2IECwJ4
         RRJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Sz07bwjy;
       spf=pass (google.com: domain of 3yeiwzwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3YEIWZwUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53a223f4cb3si58402e87.12.2024.10.21.05.00.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 05:00:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yeiwzwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5c943824429so2634643a12.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 05:00:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUU2usVAePNLkW9UJtWwJ7/bg5Y6IP+tJDHb8jhvhHwu7kRm0fReJdDaARTdJTOT2Eeplla86wCW5o=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3103:a9bb:c02c:c514])
 (user=elver job=sendgmr) by 2002:a05:6402:3888:b0:5cb:7780:f516 with SMTP id
 4fb4d7f45d1cf-5cb7780f61fmr57a12.8.1729512032815; Mon, 21 Oct 2024 05:00:32
 -0700 (PDT)
Date: Mon, 21 Oct 2024 14:00:11 +0200
In-Reply-To: <20241021120013.3209481-1-elver@google.com>
Mime-Version: 1.0
References: <20241021120013.3209481-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.rc1.288.g06298d1525-goog
Message-ID: <20241021120013.3209481-2-elver@google.com>
Subject: [PATCH 2/2] Revert "kasan: Disable Software Tag-Based KASAN with GCC"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Will Deacon <will@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Sz07bwjy;       spf=pass
 (google.com: domain of 3yeiwzwukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3YEIWZwUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

This reverts commit 7aed6a2c51ffc97a126e0ea0c270fab7af97ae18.

Now that __no_sanitize_address attribute is fixed for KASAN_SW_TAGS with
GCC, allow re-enabling KASAN_SW_TAGS with GCC.

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Pinski <pinskia@gmail.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kasan | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 233ab2096924..98016e137b7f 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -22,11 +22,8 @@ config ARCH_DISABLE_KASAN_INLINE
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
-# GCC appears to ignore no_sanitize_address when -fsanitize=kernel-hwaddress
-# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=218854 (and
-# the linked LKML thread) for more details.
 config CC_HAS_KASAN_SW_TAGS
-	def_bool !CC_IS_GCC && $(cc-option, -fsanitize=kernel-hwaddress)
+	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
 
 # This option is only required for software KASAN modes.
 # Old GCC versions do not have proper support for no_sanitize_address.
@@ -101,7 +98,7 @@ config KASAN_SW_TAGS
 	help
 	  Enables Software Tag-Based KASAN.
 
-	  Requires Clang.
+	  Requires GCC 11+ or Clang.
 
 	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
 
-- 
2.47.0.rc1.288.g06298d1525-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241021120013.3209481-2-elver%40google.com.
