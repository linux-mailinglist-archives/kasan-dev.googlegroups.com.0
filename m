Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL4RZP6AKGQEI3E5SSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F822296E3B
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 14:12:32 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id y8sf509859oie.22
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 05:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603455151; cv=pass;
        d=google.com; s=arc-20160816;
        b=VBonsPsxz7kHkXAehxP99UVCtF5CVwG6/aFYt7BKFrn+RrEPyur19T+BNReoEr0Q9H
         0H1ey59Qagd9slHUfIHKzIe7ReIzYFapui1of5cE9SaJoSJqOy6zYJj2Q421B74kZDn6
         GA5Y9pLwq9wUrae0Op3OprioqW1OqE90YgM9BUFkvB0GTavSLeGppvDhNWF6Kbs1EhdB
         Y9826M8ISbFm9UDY4ci/orLTHvyCX/Q37FRPAWr0+fNeizhIDdDQic8y+jkHIShtRyx7
         OZSsBp5Tg3p7gC48fU92B3gbxNHoVsOVr7CifvJxi3Lmka6P3tcpgiZLge9yYtwdlqMR
         w5RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=6kHoV2XS5VyZiAARUlVn+Uk7Vqwybgl8p46XH0HMLcw=;
        b=xDwmdwev90KeC0NmW9jgdOcU+Lqdl8Sk8QU8jVi+rCyywACW3SJxBnBmp9OVSSxpEd
         JumowKgKMStvmXz8elg10jHeg0rvx0/4vha8ylRj9d1beLpwNs98/jRQ1BURaDxKq7aT
         iorZbO3xELaX1Xnnr8gPdETt7xjlee32x21Yi05PrIORd0lJXfSgq5AgTPdTbYAtijQV
         j3XpVmW3aKsen3Qj3IfTZbQa9/vqDVP+cYALKjeCw/Xz8t+J6I9Bpt5wmHvIys4D3srw
         eK+2GqmRGUqlhRJBqkzWgmK0BTokvaSrVfgCa7SFnPwXaLJvtAQPlvrDyNbm5hbu7p1G
         3cDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aI9i0Aa5;
       spf=pass (google.com: domain of 3rsisxwukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rsiSXwUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6kHoV2XS5VyZiAARUlVn+Uk7Vqwybgl8p46XH0HMLcw=;
        b=bqmoGMNBTFUJQj3NX1lR8BemPl8j2bNKGQkfwZrpM2hFMDvIGiKqN4ki4sJWsKnThN
         ex2qHpuqLEJibRs79t0Dur7v9xBCArPgDdODGyULVfA8t8Z6SDI7pTT1HsETpmmWWVEY
         hd1PUg79rBmh79jR0lqFK4xeK63dJmMgOmn+RhoiZb1XTo5sB1GxLeMlaER7ytJEicg0
         +mL/j9GoUs5sIFrJ0RoGWf72Tm4jY76lod5BvqBXZgStNa948U8xp91VuijfLuSax1cn
         KFsYo+aNYELxljqA8pD057/IJJDjcfzpNVdI//hjQFFBe8bmlR0C4Q1L8zTrpcEEVX5M
         Z35g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6kHoV2XS5VyZiAARUlVn+Uk7Vqwybgl8p46XH0HMLcw=;
        b=AbECIDFGZjrstFQv4DPluOFJtS37hpqvV4kwURZMDAxv2/4qKNmV2ucM7xGIvOBNwi
         1xCfoNeUG5stHzJKnPINDa6N6EIloqrqvCmNCcnvvx3dXvLq04WQbBfpEroY+tSvBuIh
         QPDWVaoFrptO++M5NGE4rEFcHuzlOzIz1P+voH6mTPKUBpsa6HKP59m1ft9YaAMFdei9
         o1R8DVvpWgF0Xcz0yeBIwakMkMVDtiXO4ULikMuseRPHM2xndasT007aUQvvuNc1hF/+
         38jn2HgjcXlrsSesgBUpVO7Qgty0fUtCX4br4oXhsc5KPXI7k+6wpV7Mp1HkRlk0bUUA
         zq6A==
X-Gm-Message-State: AOAM530v1w4dig90FG5YksnCO3UGnmcjfqIj5Uuar7BfYfaQ8RPZf2H2
	bZE+nOwCZt/4jLdul1BYQL4=
X-Google-Smtp-Source: ABdhPJxoG37mLs1NVBdelqipynrSM+gKPo9Ah3YHfroBno/ocmBsdV9LYmwET31ILVlHao7Wfg+IyQ==
X-Received: by 2002:a05:6830:4af:: with SMTP id l15mr1238792otd.126.1603455151096;
        Fri, 23 Oct 2020 05:12:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4198:: with SMTP id 24ls280360oiy.10.gmail; Fri, 23 Oct
 2020 05:12:30 -0700 (PDT)
X-Received: by 2002:aca:6089:: with SMTP id u131mr1520848oib.16.1603455150689;
        Fri, 23 Oct 2020 05:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603455150; cv=none;
        d=google.com; s=arc-20160816;
        b=fIsr3gvVj7jxP56W760oP6MCsjclgtakM40AqtP0iu7u8mqWu700Qp1pkftB7ecHVn
         +UmvU9DAFXTSW26Dw8kPx9Ofkv1Da1sE9AWhJ1ckGoJKoSUzqSW0m1QRAZC9ezklEm0w
         HAqlz0gMAPIhFd27XhUIiHJczUZ8LndmW39nr4pA5DdawdY5mMUsA/4XPhLS0IDEGt9a
         1UiyBg/Djl/G3GmFFiMWMm7v7YPxSl6skhfBzwAzUoSGdbObfJn+S8wW8QDa1xcIGSyA
         C85NkB2QeS82umVq3oUfZeU+kqGSepafc+R29MZ/KHNi3HlI0WB6jz8YRXjux2Y4aMtA
         vKkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=ouYH/AbpkMNV6tkRrDvFrzxeHdaKqWEGX7QPqZMtewo=;
        b=kQUgzq+QfBdf1l/S1odqzAFlo8TB9oGPfhvaef9cpXAbZX/SaHUNuTPVbgXbjhTn40
         pqZqglQUCuMK8lA21RAdCnfVhhcsAyqC2wzyBM4aS8zO91LScC3imeRylxUqNYl5hORb
         MOvCvJI0Brwb5vgw7McuUQ8KzujmfNuEXWIKpcm+NryNNds/Y2NNEUInup9h0Xp3v+ZN
         22qbA1XtviWgl7IZXKLYCqTN3HC8UaaiptkBdkrg7VP7I8ScyM9wjrGJSsUr/t/MRZDQ
         0qmNpTLOQV5IEJVr3bKZRv8vgH+5TmkomjujyN4d4UIEV8nXB4OVTFNcbdC9ErV6oMpD
         AVhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aI9i0Aa5;
       spf=pass (google.com: domain of 3rsisxwukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rsiSXwUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id m127si36414oig.2.2020.10.23.05.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 05:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rsisxwukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id s1so800611qvq.13
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 05:12:30 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:8285:: with SMTP id i5mr1932002qva.54.1603455150074;
 Fri, 23 Oct 2020 05:12:30 -0700 (PDT)
Date: Fri, 23 Oct 2020 14:12:24 +0200
Message-Id: <20201023121224.3630272-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH] kcsan: Fix encoding masks and regain address bit
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aI9i0Aa5;       spf=pass
 (google.com: domain of 3rsisxwukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rsiSXwUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

The watchpoint encoding masks for size and address were off-by-one bit
each, with the size mask using 1 unnecessary bit and the address mask
missing 1 bit. However, due to the way the size is shifted into the
encoded watchpoint, we were effectively wasting and never using the
extra bit.

For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
bit, 14 bits for the size bits, and then 49 bits left for the address.
Prior to this fix we would end up with this usage:

	[ write<1> | size<14> | wasted<1> | address<48> ]

Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
size and address respectively. The added static_assert()s verify that
the masks are as expected. With the fixed version, we get the expected
usage:

	[ write<1> | size<14> |             address<49> ]

Functionally no change is expected, since that extra address bit is
insignificant for enabled architectures.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/encoding.h | 14 ++++++--------
 1 file changed, 6 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 64b3c0f2a685..fc5154dd2475 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -37,14 +37,12 @@
  */
 #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
 
-/*
- * Masks to set/retrieve the encoded data.
- */
-#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
-#define WATCHPOINT_SIZE_MASK                                                   \
-	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
-#define WATCHPOINT_ADDR_MASK                                                   \
-	GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
+/* Bitmasks for the encoded watchpoint access information. */
+#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
+#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
+#define WATCHPOINT_ADDR_MASK	GENMASK(BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS, 0)
+static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
+static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201023121224.3630272-1-elver%40google.com.
