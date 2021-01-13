Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM547T7QKGQEWMSYP3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C20CC2F4FD0
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:11 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id l33sf1114440ede.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554931; cv=pass;
        d=google.com; s=arc-20160816;
        b=XuR3JwHQAUpQ+milwOGOEOLhok8Ld9kz2hjlo+7tXU4Qk2Kk84G/lCds9T4yejG+Qi
         AXVlSIpSMCrls1abdhwP5SWu/xAkT3360N6Wkk3ZkAqsIOKT1upwOdlq8RrCqCb+Rxlv
         s5D/fPjfeq8xKPUh1a9apBObLpmTrbLuOOLTahlztIQpaSCs8iTnPx4Z2rCjI/AOYYjr
         x6VERRNHvyrWm67aFri5zcn1DzLNYaW9Zkj+NTd5sKjghTOCQj4Q//jf3dy9y3Ka5cfC
         TyczdiBNTx65kcBaMGcd7h0fvcGnfveEDDctfD5Pj1GISnPFylOPGhN2I3N1gV+qYq86
         T0IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LuMgHkpKoY+2B7dZGtCRJjAPQ6fj8u4NlFHI6UJ/ucE=;
        b=yF4qPHFAOnnuBjxfWBLb2AoY3NbeXs4fWvEs/Z5Z2n/OW7fzPrHW10vPNl70iql2YM
         Sedr3huvc2lOA4mrACY8V7rZwtfTIkCFDxZHHkbaeWt4aSlpR6WLlkUFxVZCxY/kMpkJ
         mrciJncH83MD4BPsgGKrOSWWRTDl7jGRk6Z5aznCvOlaT96FQxh7ZkJXu3f/Tgs8qnQc
         99BxUFbK5KpcDy6wVOXuJBopZTD0hsYcsIgFirp1rfdHFp/XX8OcC2oGM1rX3vubi1Sk
         lpJRn13/uoyETshsno/BaDKwded2FZtKlwBjzJnGrHzdGfUtef0ei70OEDSI3ofboWmZ
         dXNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YLqNMyj7;
       spf=pass (google.com: domain of 3mr7_xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3MR7_XwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LuMgHkpKoY+2B7dZGtCRJjAPQ6fj8u4NlFHI6UJ/ucE=;
        b=Yw4f9P2mVW0DWYOHf85/ZseH+hu6C5IpThN7i0bzBFrnlTeHI98AmOW2tweAGFTlp8
         Op/H4s8ohscZrtxgISDiT3tgdFhCdIYEsP7w7zw1V0S1jIXPZUwxetaP/UphUwU/HLST
         XNxaJwuhRZDzHlC5b7G35sMZ3jUAqeexgZwa9BfEr4eZIp6SX6ciQsxIADH4NL6fDdF/
         2zgNBVEcWuzKTCjfoKoqA6M7HZFS5IhFiIj283QEIBGQctpYEj+J5EdnbvgRFzgQZQJ7
         1ew4jvl16ldu4/8HFHhjwyfiEidRWLLpsR88UEV6+TZ80Mw3CSEJ78Q0CoB/cuh6m60E
         ISlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LuMgHkpKoY+2B7dZGtCRJjAPQ6fj8u4NlFHI6UJ/ucE=;
        b=Kky1qpMB+jPVdvDn8S4/LpQdNfWR954up9/t+odeSd8b6mCkPmIiSZdS70mF9W6yZi
         eV0DEnOzgugPcYWoCeP/XyA3YMEI8JFhs9VNEb18rKcMJsPusZ08GgQ+Tin+PDB2KqYP
         5NnV/QHHlbdp47oEN/R+WIAjCrurgZbQoCOosl6aeCswCLkd1JPwhsj572lZubERYbxa
         JOTn0Qa5wQJLbfuImgu046RTGriESkfIQpHNDUkvjoBYJrvhEs9JShp0CJS2Y73DerXt
         ZhBeEY4o61R+tofUB8KbAG3ReY4Rnezu7if0seuWFtx9Tu1XTTBAdy+THEw8dtbj/N59
         EOIQ==
X-Gm-Message-State: AOAM530VOOjET69WkcjrIYliW8U7oNHiGOCD1fqp0a6Q9mPr2a9tRkHm
	MspLFadP2GkNjeY48uEbQ60=
X-Google-Smtp-Source: ABdhPJzpmaKnsoP088E/D6K0vlXuHL2Glovz6Sdv8HFGTZmVmoW5OdAW1kTsuf7ByGfxZahuIGGtWA==
X-Received: by 2002:aa7:dcc9:: with SMTP id w9mr2304721edu.22.1610554931506;
        Wed, 13 Jan 2021 08:22:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd15:: with SMTP id i21ls3181489eds.1.gmail; Wed, 13 Jan
 2021 08:22:10 -0800 (PST)
X-Received: by 2002:a05:6402:1692:: with SMTP id a18mr2320667edv.321.1610554930626;
        Wed, 13 Jan 2021 08:22:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554930; cv=none;
        d=google.com; s=arc-20160816;
        b=H3iMppsgp+HIT6cRcwYL/KWnGuUZZzkKB/kQaBFUA9m9S91yYI1mmMaJhOjB6/xc29
         3cz2Y4PKiuruwLs4992r4C4r7QpfTxv/+/C+3h6wT4Cx3InCKrTfY9RD21cpJBBVcMbD
         /scSug0bMMGtD7CV48pQ/fE7E8YnHtTqx8gan4lo9S1nGVt/01dwhwVZTmuKt6gfG67y
         f56xBqKFa4uxeicH9Lay6YDQHS6X1crNGTwsOoYzT/LjqcLhfGKJxYJCuTSILZGn+HP2
         M3yYRl4OUypL9va4dyjHfcsOdPXnuOChh/iyZHiFT4yQGuB6Ea2dEFTEW99JFhkixBBB
         0n8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=L1Lauf2F6M7nowmjOy2kFR6Fh9wMsHUDYRnyLelpHLk=;
        b=OQE9iGntsWgd7P20mqeQ1GSFd0Rp2bjopGQTYdHxz315Xiphrp5EA/nZLFkij6Db1Y
         bm393IE5hregRUQpebm3SgnsU7MWRG4asbXl/KMsiayEduDdkYKk0I5RJ1iN77H7A5TQ
         HFjRNX3uUVKB+6x/cz4zxvxFoYBz+FG1KzcAIDZT2V9NXsYt06U1QEsEgtmXZehU9gKn
         BVKjGunEHpbVbR0PSg15vz6SimQNmN0MUr9hIfMzmqt/ib7pmjW70u7EGIs+MPwL6t1H
         QmTDV9cDm2+POagtxXLDu31ZqFP/CbnyQsDFy42C8tbhZut4i89s3v83WpEqII2QbNTI
         ZIVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YLqNMyj7;
       spf=pass (google.com: domain of 3mr7_xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3MR7_XwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i3si134097edy.3.2021.01.13.08.22.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mr7_xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id x20so1029573wmc.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c044:: with SMTP id
 u4mr20900wmc.1.1610554929901; Wed, 13 Jan 2021 08:22:09 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:37 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <0dfffb5c0b13f1a150223863490638e8f462f635.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 10/14] kasan: fix memory corruption in kasan_bitops_tags test
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YLqNMyj7;       spf=pass
 (google.com: domain of 3mr7_xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3MR7_XwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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
index a1a35d75ee1e..63252d1fd58c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0dfffb5c0b13f1a150223863490638e8f462f635.1610554432.git.andreyknvl%40google.com.
