Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTFQ6D6QKGQEQKQ3DJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9466F2C156F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:09 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id a14sf6536839lfo.5
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162509; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOXsm0I5mBMtOSC/IJ6IsOcU7ZVqOSicoUWrIkqpSrvh9w6Hs4fVlJJhcc767/n90K
         9lVQ6n0o7rDs5jQfDAlLHuKNk7+hHAKRqRmI5IrD9kYQundlnUWaub3ErRvL1ICx8xf8
         GPWdsuJ5yhGpud6oRVoWdFjtDSDeg+tr62RJzR0ZE+MVzcDb6Rnb/mEq3eYHxhC8HP2p
         H0HemcmpWE73tP3Se/2+RscRfWvh8qe6WxA7c0/ASMZEybCDjrX9+CuHa+liN1JyJwPr
         wTjafCwbPIsSA+mOqo62bDJvrTLIU5bsGtiMXHIcZbhBsVPh/y+/0TE/lFiTVpo3n9YC
         +64Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vcty2juvcz1Iyeap1v3vama6Ap5oqe0gop1Itx/I5OQ=;
        b=sU8st0Hzm+1OsO33nvTjLKVSFBxadwQOr8QwCHKFzWLMxwAul6LGXMlBSZGGOYPA2Y
         +FFx0s/YSNIpv+9Mo2r6DpLYSIX7SnauDw2sA68eOpOh9sogLatrYsoyeRZXxovOAJvh
         PLZ4n8ut9W4p5BNU1LC65rNw4VZ1XOlB+NzpuyY6NN3MFHX02sbOHdLSBUm7+JeDVmVd
         TKMk47DDT8BnrQIWCuNyFIFCR7CmgCJVGb8votf3JMDXVFOmRZB+Ty1N3qOFdPMrF1Up
         8OW4zuCdNRqCnYcsrQzm4elkoYHdm6YiwBpu6h7YdNAEjRcNeunfnjB7SUbDCfLSa6XB
         baJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mg4G1Did;
       spf=pass (google.com: domain of 3sxi8xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Sxi8XwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vcty2juvcz1Iyeap1v3vama6Ap5oqe0gop1Itx/I5OQ=;
        b=fFjbJIBv4+WK8nwLiCogBXqFVNfMObi+Cp2/IKhiDCCt1+QYIxNp1kdGLozO0FYPiD
         vFID4s45e4ARN8lnDUUWj7Bj4T784olKpJnob730mwaTj/TaB1IKbmINY6l+F8LmRjPY
         U6Oxwrt97K4up9u0c6ydQo4GlgKzYo0nv4E8AlElkgbJmGyqHYocM4a1Lt6isfoyypFj
         N9PmTBsEF/G7OoHwmXfCeQnHq5yJ+08h8i047alKXuiLKWq42sPn3FRHWeUWUSZ/PbuX
         zAPBky04TFmiPdPa3B74f/ogGhfl9xGBi1DesWIOW5Qme+vnIAqJDWeMxaI+aQaP5rkp
         Ha+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vcty2juvcz1Iyeap1v3vama6Ap5oqe0gop1Itx/I5OQ=;
        b=lgzMl7/tZr+mT3ITygaHu2LJRDsflq/+4kZSyZMfdelClSIos724rCUrMASq1tlfzw
         igC7Tn0HPB4HvEjvI/99pinaqAQtnJ3JH0ECPtGIPEXUDfoAg2zUr5x8qHjWjTB/fWVW
         fbyZiYQC7C1qWFb/OkxQQwaoTsD0CGLDrlzeKMWa2KrjCgBnAGvXp2IGbm/0oVbSV5Sd
         0mK4EREuPEp36MTX2cv3wHNxgM4HX4wPKYjeKtwijqzzjXDRWjNLOy3ZDalfFvkIoAfc
         izBu9ZBdVcT+fhFHYRunppeBznThicU6TUxQAESvUg32fjBsvlxYhCIEBqN4jPZFlqj1
         F8Hg==
X-Gm-Message-State: AOAM531hXP86Gh1VI9pcpXAEiQzo3GXWppDmF2jUPtr99rtO0q1AS9fN
	u4RJm98G+W4WTs6mzP6pStI=
X-Google-Smtp-Source: ABdhPJxHAN5ang5kspK7IFdnvqWM7EyHQ0IqVdFkuBvM3N9xm53PLpkKwA/m8d2OYRASBP3WWczIqQ==
X-Received: by 2002:a2e:9848:: with SMTP id e8mr447433ljj.353.1606162509175;
        Mon, 23 Nov 2020 12:15:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls3996122lfg.3.gmail; Mon, 23
 Nov 2020 12:15:08 -0800 (PST)
X-Received: by 2002:a19:3f55:: with SMTP id m82mr363367lfa.344.1606162508228;
        Mon, 23 Nov 2020 12:15:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162508; cv=none;
        d=google.com; s=arc-20160816;
        b=XIymcGQZ2vfpsXFhxGdz4lqPrYXBUpy6CElKaQIBxvXBin8+PvVw9KWu/pULvZCabx
         7pkVV2lJ7XAgHsdpGEaWG2RBrX/GO6Tm8l+e3L2DAWxbLUMMaPpAOXHVvs83VlYtBiPC
         AQhwP/wpQgxSh7tN/mV9yVKCFhPcLARTFf2/Z/00XhoSyRdGoGFjFgU2OhOAM/hf/r2c
         AZTNVAm0ii2qHm3LC+5WUmRNPvzm4bIkdYAVxEHP17fZkyxPmLScD//9gcS6DjC3E73V
         bQqrYY6/AXu3bU7q9NOV3QRR/OHgPwtW3nnFypJmYv1AjFnzXg1S0IfaBRc28nq+01Ka
         x8jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=p36dbwqSBkDo+5S2cwk7w2vFpTiM3nymWvjDRmhBFUI=;
        b=mM0Ov9jRW5IxoEO5XLtb8itIIXPAKqJLBJ0WYOva/s8ZzaeoXQkFwUYMrLsMsnl2ku
         cUhSL5QIq5UsAqrFd9VeYimpuWtxe3WfuN4YiKgRF6M6weEqLJ4LwqjJ5pAXbVUWcvYe
         KpUrJCTHJp40GBZf3QABSrZhXPv2v0lRCn8h//pYZtVtt1ewKOB1Z4IYWhn+5kp9txZd
         i39mPshGz5hKDWCHVdBaxgZfFhcRgjBOoKSGRwASwN9D0h01vIVfxExZgANJvVV7NRnB
         eapJUaYq68STWQTbB9dMDJhil3wnLpjqVva6xABe34UHCXD+YFA71iCGSUkUqwBEBCZo
         KOtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mg4G1Did;
       spf=pass (google.com: domain of 3sxi8xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Sxi8XwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id h4si26755ljl.6.2020.11.23.12.15.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sxi8xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id n13so1518045wrs.10
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9d4c:: with SMTP id
 g73mr17209wme.127.1606162507547; Mon, 23 Nov 2020 12:15:07 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:36 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <93e78948704a42ea92f6248ff8a725613d721161.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 06/19] kasan: remove __kasan_unpoison_stack
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mg4G1Did;       spf=pass
 (google.com: domain of 3sxi8xwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Sxi8XwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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

There's no need for __kasan_unpoison_stack() helper, as it's only
currently used in a single place. Removing it also removes unneeded
arithmetic.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ie5ba549d445292fe629b4a96735e4034957bcc50
---
 mm/kasan/common.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7648a2452a01..fabd843eff3d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -65,18 +65,12 @@ void kasan_unpoison_range(const void *address, size_t size)
 }
 
 #if CONFIG_KASAN_STACK
-static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
-{
-	void *base = task_stack_page(task);
-	size_t size = sp - base;
-
-	unpoison_range(base, size);
-}
-
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
-	__kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
+	void *base = task_stack_page(task);
+
+	unpoison_range(base, THREAD_SIZE);
 }
 
 /* Unpoison the stack for the current task beyond a watermark sp value. */
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93e78948704a42ea92f6248ff8a725613d721161.1606162397.git.andreyknvl%40google.com.
