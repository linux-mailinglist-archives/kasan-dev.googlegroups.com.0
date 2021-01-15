Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3FHQ6AAMGQEQ3WQJZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B24C22F82A8
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:42:04 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id o17sf4456598wra.8
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:42:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610732524; cv=pass;
        d=google.com; s=arc-20160816;
        b=qMe2mV8/mn99pS97J+3Y9mF01dE7V5I9mbxlgfBjlz3tq18EgcQcCF0puHKSi0lYpa
         kfH7TH6KEJV8XnxW5XXiigpK2L5cQ01jzZusX8svWTjDfJ5ewT2JaLOJrlC4RsA7z5bu
         X8qPekeN4XkRdR4PriUUxphAGhwGjUMdu0Y0OS6MI6A/KQ7ZPTvH0FK0sIY/C0ERGcXc
         QFVY3AkI8DfT4J++K/TQqHUEEYZt2+86teJzxqPJQSuf5hlTw5Z+9oyDhPElyZemtsGA
         Xxowr9BPPqgiFfvxuagjV9o0dmBoqvM/opxOjIz1vpOffkgo/N1gQvomDsC1iF0C4xe1
         ijPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LlIaZVrpUvaFyWb/8QmRXhEe1K5IezrQu+duYkemWM8=;
        b=B8biQ+wHZN/5s2FU1Uj2w2TyGypUxxrNktQiOmS8At76jaF3fzKi1DD7wXVUzxMFHR
         +2Ipp3i36YKOsApk/Nl1eTDmdLhV0OVGdRzesK5p5szqQCe5j3EtqRatAfEkAA16wi8L
         TTWGPAM/uRYRdmPPnV5wO9BJNHrELSVfUorCRedbfznzwRZht9VNyL1qpzVgeyiFF6Ln
         7bjXgg8wRoBgfPEqK8qgCN6D5DT3vCmCG9kyBU7tMMXWQPgOrbYQIa/TSCcgZGvIjDpc
         asWUs3YSGwwXOShRYFyrmZVzLyikrfIXub5RbibfftHQZuMiM3BO+fgI7XNLnuFVtsWL
         eSQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hd2IN4XM;
       spf=pass (google.com: domain of 36tmbyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36tMBYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LlIaZVrpUvaFyWb/8QmRXhEe1K5IezrQu+duYkemWM8=;
        b=bYw3VB42SX8ekMaNvTY5qor4jf2Rb1tlLxwmow3FYUcAN2dhEif2cd+DrQVIC7Vkoq
         UUINVSgRTlLmhfl5JTALm3jaGr1+oB+y2SC2IdDIaYUzJRdZ15Etn6xeOC4d1bLeJrBH
         Iayuaj5f3e19pLQWZE3V9yB5k4xsBv0gJ4URtVQR5VoGlNom4+zFbV84y+tYUeUbntSX
         E3aezkJxFm/FfPF7dfumerKvWhzLbGfpssgDv6QIv3mYJl6yRTH9L9/ATgUBNkV9ayys
         lsWJL/hp4AMMJu7rfHtDR1l19b4m7MBCU2C08ZnAiBqcfYZK1u6DbiPQrEPcAyc6Vhx8
         WM7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LlIaZVrpUvaFyWb/8QmRXhEe1K5IezrQu+duYkemWM8=;
        b=PUCsUI8AHYRHL2LZemUKR/4JJClFPumPrnF7gyjArym7YPt3x0PICex7MOuBZs8/GK
         djsrAVOzmzBLOujMwuMG5zT7B8BbaDv+6xNla3rL4prheW86SJxwV64Nzg4Fe3ISv/xK
         SQwm7e1Zj/rvecZPXNU5YdhIP2HsdRJTHQnRgOs3+gnYlfw4fmGnWwmEiJ64TNCIJPax
         scK+nQrguCmBuHFCSIHaC7SzMFT2LcfXtAuo+2XIWhu/n5f2T+AgU59JpbvDe4A3zXcY
         P9JfHguaoglHij2M59EzgG9Xr5vFyYJ+PE9fFDb4I6r7Tc/jfP/E3imRBevZFr54rv3f
         Sk8g==
X-Gm-Message-State: AOAM532NPPOH9m/4bWpnGKFNjqvTp/4uYyE3gNufDCtUrvzviVDlyE6c
	Kqoh2PXEQgN0U/J8zTAhEqs=
X-Google-Smtp-Source: ABdhPJyXvsUMjtIqZxubWCTSCxzMoERaq2tiRv+spQK/AUttIwejkDHvmBuLave2iWzzbNAi6XNkYw==
X-Received: by 2002:a1c:2d92:: with SMTP id t140mr10005584wmt.114.1610732524506;
        Fri, 15 Jan 2021 09:42:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e608:: with SMTP id p8ls904172wrm.2.gmail; Fri, 15 Jan
 2021 09:42:03 -0800 (PST)
X-Received: by 2002:adf:b1da:: with SMTP id r26mr9951202wra.198.1610732523699;
        Fri, 15 Jan 2021 09:42:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610732523; cv=none;
        d=google.com; s=arc-20160816;
        b=qzHm/6nXG2nmd6xfCPH/UMf6sAJzFozhLwgZRsOF9wyK/y+dKYiUPiA1/cK7r1KyeK
         gqLUrfRoCo7ixFR1oo5vScmAYCDzdBkH05UAzk1qm6QzKMn9vx6l4o0QZ94NEPXc+b7s
         PRkBzD+lhNdPDbkh+eE1w/bk5mM1o7uEayq6e7xb6j/fcgDPcSyAKa7t6pX6rRio7uY6
         nX+l5JdQijQI0Vl4Dep1wjIzgLPPOgB81pCm7YtyPop7lSlwG5dKtRxZdwbSrIcDBx0u
         z1NDuM2b8cne6bJ+lAvnfVv+32C+JYm0sYa7ZlqcIHHM6z6wWh1lXQzldv08UYRU+7YV
         KjNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2Jh+PMvtwPBdOf35KI8y5U59fASZU17QcTjkcKex3tI=;
        b=VgpoBtMeAJT2BMW9TRZpnUTCDYKp/3KD/8pmiMdRXvEAYWgvIncQAwwCqj9p4CB0G4
         PJrYK1RZbXxC96ysvlVjbvZA256BjFDiP62pXv//nMUSv2KLFXNnvEoZH03KKt9tz8P7
         4XLc6KE9mMfmmxWag+7WGzaQiF5Tjc1OxAjQp/NdWneLgJJZnZfVJ1CXP1a709ZakK1Q
         x+weq9aWJI5nL7vnFiOOuInAZZKDGGF7o1V5hfqiWTUob5RflwArfXR4J+TF//N3s8Ja
         X/opRic3rx7pgymITkn0bCWjj/wFOlvlepvAERkx55nheTjtvOg6CdqU9IFYveyXoxIu
         Ikrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hd2IN4XM;
       spf=pass (google.com: domain of 36tmbyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36tMBYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e16si547801wrn.1.2021.01.15.09.42.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:42:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 36tmbyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id i4so4461082wrm.21
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:42:03 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:58d7:: with SMTP id
 o23mr14634604wrf.288.1610732522952; Fri, 15 Jan 2021 09:42:02 -0800 (PST)
Date: Fri, 15 Jan 2021 18:41:53 +0100
In-Reply-To: <cover.1610731872.git.andreyknvl@google.com>
Message-Id: <ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610731872.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 2/2] kasan, arm64: fix pointer tags in KASAN reports
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
 header.i=@google.com header.s=20161025 header.b=Hd2IN4XM;       spf=pass
 (google.com: domain of 36tmbyaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36tMBYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
that is passed to report_tag_fault has pointer tags in the format of 0x0X,
while KASAN uses 0xFX format (note the difference in the top 4 bits).

Fix up the pointer tag for kernel pointers in do_tag_check_fault by
setting them to the same value as bit 55. Explicitly use __untagged_addr()
instead of untagged_addr(), as the latter doesn't affect TTBR1 addresses.

Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/mm/fault.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 3c40da479899..35d75c60e2b8 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
 			      struct pt_regs *regs)
 {
 	/*
-	 * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
-	 * check faults. Mask them out now so that userspace doesn't see them.
+	 * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
+	 * for tag check faults. Set them to corresponding bits in the untagged
+	 * address.
 	 */
-	far &= (1UL << 60) - 1;
+	far = (__untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK);
 	do_bad_area(far, esr, regs);
 	return 0;
 }
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl%40google.com.
