Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFFNQ6AAMGQEPE7VMSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id B2E9F2F82FB
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:25 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id eb4sf8364703qvb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733204; cv=pass;
        d=google.com; s=arc-20160816;
        b=tNETE51xBaFPNoXfrIBroWEbjTYJOI+oPmZghQTtnS+tkqd7dXYMhZ85eZmwwPfnT3
         no2fJsla8kWmbnUB09opljPrK+hWDfhOOpeKL6yJfacrLdL9paS+alkLpzsf6Hth3uLS
         TG7Sl61TiRMb94a8wPS2jR99JTqToOB6PWLmgQs0JWv0kcMDpA9hA98sHNyZBmZj6uZ4
         NWcc71BvPTezGiNN7fg+PjbWG21RFFgcTFtf9tPXYJBTPs8Gdhr/hfX+lryagLrA9Q7K
         sG0JgQVLsScovI9WewRlu55VxZ6A1jkgZeRKP14YQ6dXe6bd85clVuxQTLb4aKgA4xyE
         cGhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=slLES2gGIF+/cslIJHsuOW21X1rprwgaAH8VV59bR3Y=;
        b=IiNJHBqmA3T0+IKs8QmwuZBRIhyEZzrkbKAwuFEuOSjiLFohnAonj3JbCRzjZiATVr
         5Y3tkTE4agQRpBNGNyMDBvtCElsoCuZ4P/o63mXpfphkuKEjW/KBa6c5EaJkTqEJMrsy
         UcOZEvudaoOi95iXtelvnjVwPt260gAkx+CpGyDxx+7Es3FIe4GQ5oelkrpEc2FtQlSR
         OydICrXMJV1Ugv/Nk4K+oBrMiP/WDax6Xldwmk4Ppn7t+kSXUsgoB2OIYR3xoVs1FCse
         J+Eb2NbZF6ifrWKKBg4mjCo/N9efbPJ0sqdtmVDVmuGLyRqhjbUCtOU/eoSnlKS2Ofsd
         B/OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vTETwvGi;
       spf=pass (google.com: domain of 3lnybyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3lNYBYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=slLES2gGIF+/cslIJHsuOW21X1rprwgaAH8VV59bR3Y=;
        b=mdBsbAFq7khCc1jn4pjCNwsEJgMBeJGPEZX792XvHE6jmLu2uuo3VxEPhv7fpk4zpI
         Ik6q+A5PPnYEtF31Rjv93wphZC2I+Ut3VGqTCWR+BJRYXhHVRV30cA3wsWusa/KbzvLs
         PDmtn3nypqeNQJYonqGpMSt1k1XfXZQwVcid3P/8/Alu55n49+nCcnGadEvWEuDakQz7
         fq2AlYN5U3SAuRpa/gcVmt7JKiD+TK26iTHCdnYiH/GjsAk5x4/v0jeGR+6GVnu3SRXs
         Ip8/QK5WHPGJz5abRIY/Kjy+9bhr8CN5yxISQu3kvjT9yvNQ1RJeym5cEFgjhPcR0s9X
         nE1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=slLES2gGIF+/cslIJHsuOW21X1rprwgaAH8VV59bR3Y=;
        b=VpaiOggO8daZI1O8dGfN7Z3sCwOBjihdKOIM/VMM/G+2boFQ3/NuOXkSiJ3lFOTtyp
         p1wgeRiYJ6Q08XFbBSPXgrdy18HBVXBxsVrQ1Tx+aPS+xpfUnscRaE2LTkouEbtOZuz0
         5k+Dq4M/ejgsNbjflpW9tzRzeSp6drpR/zJN9BYI60N1ffZt59tKxCt8t8MXUyeYc3E6
         XUftPoCub26c431LvjOu3RyBQwwj78nbeUhD4DlvnbQ9hVdvAuUXFAvyXtUolJFzkCAv
         DRnHqrpAoI5F7Xe/WyVciPnZZXZMJhtQ86dHsprM5fS+Ok2h5x7gQu1sxkNAKJbyMnQD
         Pr1g==
X-Gm-Message-State: AOAM531zajY00bshIAeKy1kV6JLuTTyfCcVz501+BmCVg0JlqEYO+liK
	Y9lusGEWYLeSDLWTPN1n3aQ=
X-Google-Smtp-Source: ABdhPJw5SaQULKednJ8deTR8kNCNvz14OROrWwpX5chbvDgmd+vAluegp8W37FUfzSZba2KonPAAnA==
X-Received: by 2002:a37:d2c2:: with SMTP id f185mr12893828qkj.213.1610733204840;
        Fri, 15 Jan 2021 09:53:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c001:: with SMTP id u1ls4975629qkk.1.gmail; Fri, 15 Jan
 2021 09:53:24 -0800 (PST)
X-Received: by 2002:a05:620a:2104:: with SMTP id l4mr12877288qkl.35.1610733204458;
        Fri, 15 Jan 2021 09:53:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733204; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRctxW0ZEl2JY3Jeb9OlotlvBB1c3nDKoXM93+13onfWkfW71myuCQZBUKXSbiWkBa
         4PnRQWUCBPp+vMODWvRCElw+dPpXMQOdbhFvuhTpdfc1cnH7BJC7ndHBkM0oZKe8UYbQ
         ZT+gcJ7R8cl7h3Ounj6fxrRJV7sfPKIy9d6cLUBl+MFG9LA7MORtmqMF4NVq+dx/vGz0
         g5LFJ4WihJmwLSLFFRCzkkixbMP5FGYTRSEGC0Ojjg5UNDAH+eZwFpgbEDJROhkMUpTR
         RWP3UZr/iGL4EYyYVpivyis9YFC+q/jC5kAcchyM0PhK4C9omgRvOr8lSB96I3mYud4R
         emYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ifrv61nnbwuahZCEiwjCwkZVX2MKhkqH/HoLspc9PnM=;
        b=03kvD+bUmnUj3S8Td9PfAkBj6gkCKDYs+wj5QYhg6+YFnDnPRIPL8AdX485TPtFbsK
         RzEmVRxSQNAo72ZgDwWzg/OZpv5AVAeArbEQkjpGwiqGwV/DUr8oLNVub4YMQpwLa2Ki
         HLsJ1lHeBjrP28SapevL/Bphc6gYLZTms42giFNI1CLhVxoBGvgEQMdA1vrAu4Ns5hm6
         xa4wCS1TcckO7W7+3XloM5xWIoWP7o6W6jjCad9b0kDphopnU+iq9lqOUMNqikzRTWA4
         MyM6VPr7zKg10W/CjesWa+gkdbjFbMRtkWeklSb4plkGi+4CmJvNg1IkALtQ7EBDBAW/
         xbJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vTETwvGi;
       spf=pass (google.com: domain of 3lnybyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3lNYBYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id i2si760564qkg.4.2021.01.15.09.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lnybyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id g9so7987636qtv.12
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4c44:: with SMTP id
 cs4mr13129570qvb.25.1610733204089; Fri, 15 Jan 2021 09:53:24 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:47 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <7d452ce4ae35bb1988d2c9244dfea56cf2cc9315.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 10/15] kasan: fix memory corruption in kasan_bitops_tags test
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
 header.i=@google.com header.s=20161025 header.b=vTETwvGi;       spf=pass
 (google.com: domain of 3lnybyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3lNYBYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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

Since the hardware tag-based KASAN mode might not have a redzone that
comes after an allocated object (when kasan.mode=prod is enabled), the
kasan_bitops_tags() test ends up corrupting the next object in memory.

Change the test so it always accesses the redzone that lies within the
allocated object's boundaries.

Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 0cda4a1ff394..a06e7946f581 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -749,13 +749,13 @@ static void kasan_bitops_tags(struct kunit *test)
 	/* This test is specifically crafted for tag-based modes. */
 	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
 
-	/* Allocation size will be rounded to up granule size, which is 16. */
-	bits = kzalloc(sizeof(*bits), GFP_KERNEL);
+	/* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
+	bits = kzalloc(48, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
-	/* Do the accesses past the 16 allocated bytes. */
-	kasan_bitops_modify(test, BITS_PER_LONG, &bits[1]);
-	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, &bits[1]);
+	/* Do the accesses past the 48 allocated bytes, but within the redone. */
+	kasan_bitops_modify(test, BITS_PER_LONG, (void *)bits + 48);
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, (void *)bits + 48);
 
 	kfree(bits);
 }
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7d452ce4ae35bb1988d2c9244dfea56cf2cc9315.1610733117.git.andreyknvl%40google.com.
