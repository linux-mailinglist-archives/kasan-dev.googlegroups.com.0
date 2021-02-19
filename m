Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR4JXSAQMGQERTCC4FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id C7B9F31F34C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 01:22:32 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id 9sf1682398uas.17
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 16:22:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613694152; cv=pass;
        d=google.com; s=arc-20160816;
        b=omslH99ti0XQaLCiR5ObZTRUTZdUV5Gn3AHON96XonAL3EsMgoP1qNGU/z2ET+IfpK
         Vn6gKTpylOrUg4fYEVHQQ9W4y6wE+mSVL+y008sZYMYPj2aopSfa4cvUbtPOLcU3A387
         8+FG0Hj0UM6RjkXqcvDH9obujFawgcKnI1FzVc8SWuxuqvmbbV9oWOedd8jSCp/PGgAP
         yq0+zZzLfS5SIArWmBLmgpqmS1BPnvCJF3Q1VJVN4+OqBpMxmaNFz9tuDz8aNNVP3b6L
         p6z4Uq+GNK6Q+MLPTQKLJEkdcEe6remuL3uWF0tGGgMUj8d1tyOQfPA4xxER+T99ysBt
         L4AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=pbA5goRDWkMbBJ1XRD28ZNo1FPpVA6tGoeDmP76OC4g=;
        b=NOj6JAFackAJ/8Rp7G/kCiKOH+jcnD0SinSDfX5Yo1MBVhciTnWjToqCoORpLuqk36
         YadOhwY6mRq8uBBrT24wh9cR94R2A6JaH4k4cCR9AKPYo2Dc1+mzxQZyGZSzQ4C827kV
         51MYQ/cUK+rVFyOCOHNKg9EB4h1BxOM0ubFgCAVF3uhNVk3QVucP72YsLSSIz9f76Yna
         0xnWA5eCTQok5CwJ04Q2/YBmHZrvOh5pjiv04kpQixyOF3F6tj2JxqzvS67Ldfz3hnZv
         ESFsHxGs1zmdaYY4Uz6ZBod609Nas9Z3P2gD6jWWwFwD40iDXRY44t9S+c2MNfdx1g29
         YD7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G7bAXsSf;
       spf=pass (google.com: domain of 3xwqvyaokczqyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3xwQvYAoKCZQyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbA5goRDWkMbBJ1XRD28ZNo1FPpVA6tGoeDmP76OC4g=;
        b=jip1mBsmioSrcVArOWSK3ivQlUNMJmHH6azDhjwRQfywPhq98tC3lc+y3yhBy133fp
         W+IPJGlR6fPqDtx2V6SAQcrK1SwSEf2oLTNhV27LfOc5shtwHlQxMrw8Vg9H3dAziE8m
         tBNYf2BJtZ+WCzJyy+HVbb+IxZuJcUUzpRAKKhKt0UcxDhrnOxvUtdUGzUaDqibseuGU
         /w69VAaddmeMRjBeHzZtYlTe5PVMMbO+JrhKyTai3D9tRlk4w9HTTEW64avTdngg4NXk
         02mFdIWhTP0ZYBD5HFUPj8MU4IwLyextL8XvrkFWeoSiHHZpHljy54FEn8hs39Jw6yDe
         aASw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pbA5goRDWkMbBJ1XRD28ZNo1FPpVA6tGoeDmP76OC4g=;
        b=uR9DDkCaHhZZQaAEdpwYfFzckSPawY+DzqHi9dbyd049TKN8zQdZRfl+SeLmye4HL0
         WU0A2ByudTFfMgf588+QeHI24aOs9vEtwPlvrbgVrDG8R4gEh3zVr3j8QI40+utpYpK+
         JcoTRWN4c/Uea0wdnVqqm4tHs0uS6+ZYyVQ0OQbx5VOyHwy+I2WNudyxH16NHB5Jmqv9
         Mc8kSvRe/M82dO1gBxynhfxJoTzbfue5H+l3hCPrqzuklVdbPZ5+jLt7u/Ti2iPjSe2/
         9EQzPBXK6tl0KRMHA0aN7oqlSelANJVRCSsU0PKAePdaf3G/K5jLOHiEn5u8DwicVVr+
         hdSQ==
X-Gm-Message-State: AOAM531e/0INHkzuw/txN6nRx6NCAaNqjeEWsZgeYomi3W45AvDomTW+
	oZ91ESqgVq9sV7k5Zcrt2Ro=
X-Google-Smtp-Source: ABdhPJwmcgz5RUYmCTK5T0HJ1Ga4X4zVdFZHQ4DPL0NUdmATv1FWdeKZ5MyuD2f5pS3Czn/en5v1sg==
X-Received: by 2002:ab0:338d:: with SMTP id y13mr5783953uap.64.1613694151895;
        Thu, 18 Feb 2021 16:22:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6612:: with SMTP id r18ls431712uam.3.gmail; Thu, 18 Feb
 2021 16:22:31 -0800 (PST)
X-Received: by 2002:ab0:2e85:: with SMTP id f5mr3546744uaa.66.1613694151509;
        Thu, 18 Feb 2021 16:22:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613694151; cv=none;
        d=google.com; s=arc-20160816;
        b=rZGSHdxeLitP7jCrkb4n4ksIcl1xnyJYV02rhIMMCcNZwjB/xCd6ILcfI3RRqE7hK3
         /w+ij63cEtc7Nhmc33LO47jZPCIqU4RXQcwfL9m1oLD1vSyC44MPT7DrV25SQWAMoHJt
         cLDsSDdbcNVvVzo/MA9ZkyXMgClOl3ntLRogg/MbenKPiRbXbKxjH6g/3A7FvnWrB4LZ
         a3REnMoqwE/Z0KrIhcWRDZpG1vmuwPcIVTiVtzennk6urZhOgngGa8BRBoxX+Cji2YHl
         rUpgB+rUphzckJivNYZhgq5AZHsmSJ1P+9oVm5kEA1az9MC2j3IEaz0n4wbYh5N4NbLe
         e2RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=U/iWzYWPjCN+XW1A2BqmtUjlIIZumhGvP/yo+EmOxYg=;
        b=qtyXN4H2ELPfoy+hYFHIf1G7Z3HL0G+SbkaFiPFLT2EkOt2iYht75Vf1In1NE0gxlF
         phapU6mHDsfyraSbC4pmsMSrWJcjpA3ADOmgYdbvOmzhDJKJNy31dY9tll5BbZpBUrlZ
         ddyeWqUhwjNyCGOP2q2OLR9Xi2yRpbXCrqB1prnkjpkC0wlr6yqC01xcrHnGcch3p3XV
         9SUs/0eetRb2pzTrkjeLurNcBdp7WvhNFh/yzgKxEr4Un6CdhyVhIVQF8gKm6H7CCm29
         WlzKDYoDtGqGaTFUG8vP9v+NwxrsJgLoSVtC7+3KwuA8pBjJlt5y+PQ99YstNheL3ox6
         9wxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G7bAXsSf;
       spf=pass (google.com: domain of 3xwqvyaokczqyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3xwQvYAoKCZQyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id n3si264663uad.0.2021.02.18.16.22.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 16:22:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xwqvyaokczqyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id r15so2460537qke.5
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 16:22:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:2d89:512e:587f:6e72])
 (user=andreyknvl job=sendgmr) by 2002:a0c:8b8a:: with SMTP id
 r10mr6826124qva.52.1613694151028; Thu, 18 Feb 2021 16:22:31 -0800 (PST)
Date: Fri, 19 Feb 2021 01:22:23 +0100
Message-Id: <c8e93571c18b3528aac5eb33ade213bf133d10ad.1613692950.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH v2 1/2] kasan: initialize shadow to TAG_INVALID for SW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G7bAXsSf;       spf=pass
 (google.com: domain of 3xwqvyaokczqyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3xwQvYAoKCZQyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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

Currently, KASAN_SW_TAGS uses 0xFF as the default tag value for
unallocated memory. The underlying idea is that since that memory
hasn't been allocated yet, it's only supposed to be dereferenced
through a pointer with the native 0xFF tag.

While this is a good idea in terms on consistency, practically it
doesn't bring any benefit. Since the 0xFF pointer tag is a match-all
tag, it doesn't matter what tag the accessed memory has. No accesses
through 0xFF-tagged pointers are considered buggy by KASAN.

This patch changes the default tag value for unallocated memory to 0xFE,
which is the tag KASAN uses for inaccessible memory. This doesn't affect
accesses through 0xFF-tagged pointer to this memory, but this allows
KASAN to detect wild and large out-of-bounds invalid memory accesses
through otherwise-tagged pointers.

This is a prepatory patch for the next one, which changes the tag-based
KASAN modes to not poison the boot memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 14f72ec96492..44c147dae7e3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -30,7 +30,8 @@ struct kunit_kasan_expectation {
 /* Software KASAN implementations use shadow memory. */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define KASAN_SHADOW_INIT 0xFF
+/* This matches KASAN_TAG_INVALID. */
+#define KASAN_SHADOW_INIT 0xFE
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
-- 
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c8e93571c18b3528aac5eb33ade213bf133d10ad.1613692950.git.andreyknvl%40google.com.
