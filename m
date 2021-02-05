Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWUD62AAMGQEWTQIHSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 79A7E310ECB
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:23 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id h16sf5786148qta.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546522; cv=pass;
        d=google.com; s=arc-20160816;
        b=wYhXK7wiFcNHg1dR3Z5OyGhfxD1otS3AbmIkbz6W4r0g3VVd9C6x58ftIhyf5tP6Eq
         4scNEX7WW7aXfErxvTNzo1P334aVRByTIqi/0Csg+BdwbM4Je8/1ULx8sjF+rj4ZsOoA
         VgAT37Bapl7K+sIHCQ02F/cpCfSVQXI0hqYuNQ03B+l330vw+4T/myJPHDkFb/I3GDyi
         65QLKpqaOJ6JrOFkqMogJ7p38fckuDl8MR05J2JT8uRV1LNW7W2lQbTc66/TkG1lcg3P
         IU4bBXCE+lKJ5W3lOQuOu3XUmJPBsvdafxSHtoctPQqatW18grMAlM4zOlNjGzN8Rktj
         /9Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=o1k8w6Td/GOaB0HyYDPWK/rU0zCw+M4ZwNGAky1qGyg=;
        b=Lk/ioFtLLdnKRe1i1p7tvM1POC9w9XovIGp/LH6RlZ+xrHOETp5GsSF/KjBp2lx2hf
         SMlb9grJ+FMLTKUkqKdM3wv9BBCj9vf1gC3XLLtK3aYco1+XVb0aS1CXtLfmxRR678So
         Iqpfj56EON/G1ohXjx8kNeRtPl6UsgcTPtRCmJPK1awwf9orwgfubuex5sbPEBuOIXIa
         sjrlgqhvFt1hos8BwZ+Bl4jYd4zFggQflhrNSIx2B2Pd5KbcNg+gfQIwjfvuNhuKNBXS
         oYEdZfJ12KX7LT5dbeNbdgYDpquOWGAZws9mfwQjvcLYR0iTY/GguxIZU4BJGmnYtlEp
         p0Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G68KUqp3;
       spf=pass (google.com: domain of 32yedyaokcvo2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=32YEdYAoKCVo2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o1k8w6Td/GOaB0HyYDPWK/rU0zCw+M4ZwNGAky1qGyg=;
        b=UQNkoNms8EuIrR+py8uGu7Vs6JTOJTnkjqVyK/AvsEgH/lJ7/CsT/29z5WhRg287OR
         wyuo2c0re5cZRrEQ6HRXYUnVNTlKw1r1qCHnwz+3bfv3Wdq2RTL8Pv6pa/frrdV3X+HP
         GMAM/TV4xCeNsaFO6tv5ly3uL86nRjrthXQmcaAop3Bb6CTgb+lOB4IDLY+HcgH3gYA/
         L/4COdRCNFU/1k33MLr5D2aTwFem8VJxLnPS4rIwUjjkT3iGFhKewfU4I6D+TWQnqmwL
         xPIYkR1u/mm2HYdLhQ7ljDaKw466lZYBtZQ26wchiLKx9RGiIYNFhXMRijTsclZydhuW
         sabg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o1k8w6Td/GOaB0HyYDPWK/rU0zCw+M4ZwNGAky1qGyg=;
        b=Xy8RUCYH4CLUPrVC4C2L/zNSYAMOXnsvDp4/vkG53HuedESbnqixzwZpBXJxJZEQgT
         TWvEFR0Oc8cnobOFomsW3PmyBt1YvhV22vNFbDseEy8mzQvdwvQ0Daz350gHcrefUix+
         jvQsXejA3S8GARrUzB6d2tO2v+tKfQ/TbhKmeSA6ost79u+x1fIedWwyBggUvIfw+Mnl
         xfvalngjY8qxmuksuAb9S9Z1+Q2iQXSltQDfJNfFpxy7zneonNh2abqoLNSSy50aXv4v
         9AJuQ1C4JDjwc79VPrI+IODVH22NBL3G3Ykl8MnJcF1DJXV3yMXchcFTbghROKR3edba
         SMOQ==
X-Gm-Message-State: AOAM530ZGPVFe+1Pe7kK01i9/XaIx0lbzKjo0QINImQ+4rIGCUO68U1U
	E/JYj6ZUoZs3GoG/Us8a+ME=
X-Google-Smtp-Source: ABdhPJz475OBvPzqlp6OHUV7vaUVKkHJx6Fvvjj4us7lzu7UpS6Gjt1p4Ygi3FlHr1TvWfN9HAyLGA==
X-Received: by 2002:ad4:46cd:: with SMTP id g13mr5150415qvw.27.1612546522635;
        Fri, 05 Feb 2021 09:35:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e904:: with SMTP id x4ls5252925qkf.6.gmail; Fri, 05 Feb
 2021 09:35:22 -0800 (PST)
X-Received: by 2002:a37:c0a:: with SMTP id 10mr5517858qkm.52.1612546522294;
        Fri, 05 Feb 2021 09:35:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546522; cv=none;
        d=google.com; s=arc-20160816;
        b=GJeATpzTlmoh3+SHA1MU5hIbcECbT94BR0DwiD1Vgqh2MiHKvZvRTiikn+7tnp0Oc8
         lnkskWDNxX4o/NbZfg5H0snwLeBDo+ArTIL4jJ9SxK+EGZWtc9MBRJZ0SI2XlqzYd8Z7
         woRd23ZHOdNVh/Ofssvjx3QG7UsCgpsaAO3Evfbm70yh2d12yXAFUjRpBRQRY7VqOKnm
         DhK8S9x7zaFNJO2iZtVSpxgOCHP7twWtSamclYSemNvple+KR+uUqTgGDoQOcetOg4hx
         BsA+MedDYgv7PIR0AMpymSCOdxycqn4lBzA/xp8GpLsIdYqo6mwSM0gtZn2tKjRAUTPs
         p7hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qTEJ0ZFBO6HUy56kVKTkSwNvhkuevt789FDycYnAlaw=;
        b=XpXaUFG4Tdw1RQnuGlVG0IfYjQL2s5SLC2l08lyDlxQjLufBZBm4peqqg3btbHTMdO
         INECsmisqYvjp+VKhMLhjSrgKwtitLrM6oD9pG7RvpqH9l1UYTXMCJlONFJYmTikQH/o
         2Wkcczy7O8pE3S29uDeE0XR0vIwirjf4SeFLcj7DUc58G12/Sa0ASczxOtRMq81Z8yVW
         B1IBXF2PVeyU/RkJOXIzP6DOBOyJwTdE2/o2r6swKfs9Wr4Y2TUlVXJ2A2AQcGbeMrm7
         y200Q5Vw+XDhrQybhGRFIGaS1W64GokwKYxUcMQgxg347zUxy6aKpwcJ/cy+t+EpTO7U
         CofA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G68KUqp3;
       spf=pass (google.com: domain of 32yedyaokcvo2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=32YEdYAoKCVo2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id z14si726875qtv.0.2021.02.05.09.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 32yedyaokcvo2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v13so5529738qvm.10
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4f41:: with SMTP id
 eu1mr5346273qvb.34.1612546521952; Fri, 05 Feb 2021 09:35:21 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:47 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <00383ba88a47c3f8342d12263c24bdf95527b07d.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 13/13] kasan: clarify that only first bug is reported in HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G68KUqp3;       spf=pass
 (google.com: domain of 32yedyaokcvo2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=32YEdYAoKCVo2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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

Hwardware tag-based KASAN only reports the first found bug. After that MTE
tag checking gets disabled. Clarify this in comments and documentation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 8 ++++++--
 mm/kasan/hw_tags.c                | 2 +-
 2 files changed, 7 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e022b7506e37..1faabbe23e09 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -155,7 +155,7 @@ Boot parameters
 ~~~~~~~~~~~~~~~
 
 Hardware tag-based KASAN mode (see the section about various modes below) is
-intended for use in production as a security mitigation. Therefore it supports
+intended for use in production as a security mitigation. Therefore, it supports
 boot parameters that allow to disable KASAN competely or otherwise control
 particular KASAN features.
 
@@ -166,7 +166,8 @@ particular KASAN features.
   ``off``).
 
 - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``).
+  report or also panic the kernel (default: ``report``). Note, that tag
+  checking gets disabled after the first reported bug.
 
 For developers
 ~~~~~~~~~~~~~~
@@ -296,6 +297,9 @@ Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
 enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
 support MTE (but supports TBI).
 
+Hardware tag-based KASAN only reports the first found bug. After that MTE tag
+checking gets disabled.
+
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index e529428e7a11..6c9285c906b8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -48,7 +48,7 @@ EXPORT_SYMBOL(kasan_flag_enabled);
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
-/* Whether panic or disable tag checking on fault. */
+/* Whether to panic or print a report and disable tag checking on fault. */
 bool kasan_flag_panic __ro_after_init;
 
 /* kasan=off/on */
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00383ba88a47c3f8342d12263c24bdf95527b07d.1612546384.git.andreyknvl%40google.com.
