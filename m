Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPN47T7QKGQEJ3V6W2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB7E2F4FD4
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:22 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id a17sf1708128qko.11
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554941; cv=pass;
        d=google.com; s=arc-20160816;
        b=KUaV5rNRzZ5o2Xqub3NLzKVKRANR116RT4ymI7xAgOdoVfT45YTqmLBMXyOW+OBXrB
         MkPvFmgZy6CE26GPJQ/hkXR9QXZpnixgu6p5+brkcDCcVGhrgWZUvLPzyTG+kARi16v0
         ycuWJxvKSNpz8QcuJUmo5EyHQeTlV8XYScLNgL7O2cMv2SfPnir2gyUVWqwSGk/5/lMw
         9fl34d8bKwnvlAbmfUCV3qZo7j9cqm+2qulP+/75a0HMlzwGV7iaXqA7E+pxjbOUCnoz
         cHZnXlm2ycEy9GpGSBs1qu1VlyJJJrrfYDD8vEdHjXOZSwmclI/BndTuJwl7geZHhxY8
         mT0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SYIO/qkJ7BXnEgD9P1imuefRSMNuXYzvKpJvdKTO5W8=;
        b=kFpH9IlNouSMMyzvLTHzDZu4uf5FxRQi/bPBkZFw9ajIWfsR+I+T67gRGQ/KUqgfrq
         iTMUbevsUYH6VMUYFVUaqhmBg9xwuh+UMptNsVcPr9I0k6TAkjoT+gXLZhjUoS3akI1P
         oBzx5N1qtVrW0LRIGdu+3vvqBmRCJICz/pRHmMug0PEHh1ZMn4kbqvce++kNN26LNEeC
         pyyZv89oihBE2f8HZy+3n0X/SahIjyntJDi9+3Haaj45rPEN6nBpwmjYPvYKebVj7wvz
         k8GVOedc/cxBNJcVVanuQPVkbCMQraMot5U0QXHG8bpaIGWN43+Y0EsghTDvQGNF96HP
         Cphg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tYlSj+QT;
       spf=pass (google.com: domain of 3pr7_xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3PR7_XwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SYIO/qkJ7BXnEgD9P1imuefRSMNuXYzvKpJvdKTO5W8=;
        b=qhxC3Qi+batFXECCfL/rlXRTmy/RtNkiCWCeXwhx1IQLTlbVb/9l3ECgFSnXkL4AWH
         u8LfANUKFVLjJaZXoLuX54EPYJRWa6WPInGq83OrLVfBZz8xUYAxlANxu7D5+NdY1WYy
         LjVIM9Tpdbikb9PQKOXVjaj7pulr2e+FiFZYuIMw3R25emKIZk4VDOrw95XrwzsID/8h
         nRxxzZVhgQmFduJQg6uqYEo/j924L+XgNJ4hH3+mfHJHYqbwhoT5ZILBLQs37qb2pi6R
         mCoo1b7g5AkMkwfKdMAR5OKq39qsfv2fQern5zjjf2BmnmpZKaNWrvaXcmA0eBVRnQ7H
         DLZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SYIO/qkJ7BXnEgD9P1imuefRSMNuXYzvKpJvdKTO5W8=;
        b=CaHDf3agEnk6qAs59nr65y1/O5pIEtdKVwK9x7x0LLuS7C7G3si7hXXmGeinPSOxef
         U43nXb5fKACetuylRs+famTOoB0sidoc/9R62P4Upcjl+JSwNNYjk5dLiXf9/GtvYDOz
         ILjz3HT8pDaodyh3J5CA8dT0Dl16nZWE4PmUwRZyjHlIVCehX354nWWW8p4gZp3xp9ta
         2LzWXHS1+/Uvs7XlNeSGX24OYhdGRYbylzWIcqWTVtufTeMjpWyA2kJX6AS9k/KK5goP
         KOztKKCILBGH6Jgi/ggh7AHTg18rWBF3pD+94X3SjH2OMogUo/V6XUL6UqLYCfrPvqJ9
         idHg==
X-Gm-Message-State: AOAM533m19A62Brj2PuKNd4ETAh5gD0YqEjMDBl6UHNVoFAjlBlWPFGH
	U4Ug5N2blvdNRXzUMQLal7E=
X-Google-Smtp-Source: ABdhPJw6R/K18bbxqamHu805CZB9GxYJem9kh29Nvj4qumXzq7tn38a1nicLna4AXaGmag4Rm9PI0A==
X-Received: by 2002:a37:a544:: with SMTP id o65mr2792202qke.238.1610554941802;
        Wed, 13 Jan 2021 08:22:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4787:: with SMTP id z7ls559696qvy.7.gmail; Wed, 13 Jan
 2021 08:22:21 -0800 (PST)
X-Received: by 2002:a0c:fb0d:: with SMTP id c13mr3161918qvp.1.1610554941415;
        Wed, 13 Jan 2021 08:22:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554941; cv=none;
        d=google.com; s=arc-20160816;
        b=RK3ys1sywVE+rzTnFJrq9iPkMI6VimNCl58+sa6XnOd2DFrmw89QEa+9BEqGcXWIyE
         jB00klym5d6Uaw66dawRCFn3MmAJ3hbsmkKOd6LLGbNhNPuOxMLr67lKwqVeXyRiqMfr
         ieK5FvlCoO6fe/Q9axxf7lHqkVbGL7ecHn9bn5Le5RzDgBTa4YiY+TccfCMFOwIqNtIs
         mwOGX9tDGm6dWKz7z5/Fi1213VkkVlinzxo2WfwDZrgUSMJpnycbDqluL7pe2k4ihbDw
         N/+1ij0rH36t6ajTYyEMqE0oudAbdLssBsTOJLFowXwvR/mRod/vuaNFjk2l77hdBESm
         QIlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0oH7aBBGG/x9vXdKvNsdbcmQExRVmREsCFEoJWJ3HWQ=;
        b=KL5PaIkx5saZ57bIPy9GLXzZ/akYKVzIwHzsIb//VmRvZeYcD0COvxBgHqQlM4NSID
         4YzxYufExnLR9GE7//AhZZD8AfIQPDWcHU48XzmEwq5KFahiSw8D2qwfcYYjZr4RQ2q4
         xf2oSTPHxeZ37duEl8BMqyWAzeoENRc2HNmCOPbXoz9jLhuEUVt2sW/hGwmTRRQWLZnV
         /bBiW6w3+dyC/dSevfuK4KHm+vnAwePE3gREe4FDCEfUwYeVgUf9doU9KR/9RE49d+ku
         nwCzZTg6HtKvr1JYhEdeIM46Pdlqa3KSW/c7uKVOGX4o6VU2Dk9ywPcrTgLGC8NoS15a
         v1wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tYlSj+QT;
       spf=pass (google.com: domain of 3pr7_xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3PR7_XwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id n18si141038qkk.7.2021.01.13.08.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pr7_xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id g26so1713810qkk.13
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:21 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:cc12:: with SMTP id
 r18mr2847745qvk.51.1610554941000; Wed, 13 Jan 2021 08:22:21 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:41 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <654bdeedde54e9e8d5d6250469966b0bdf288010.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 14/14] kasan: don't run tests when KASAN is not enabled
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
 header.i=@google.com header.s=20161025 header.b=tYlSj+QT;       spf=pass
 (google.com: domain of 3pr7_xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3PR7_XwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Don't run KASAN tests when it's disabled with kasan.mode=off to avoid
corrupting kernel memory.

Link: https://linux-review.googlesource.com/id/I6447af436a69a94bfc35477f6bf4e2122948355e
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index d9f9a93922d5..0c8279d9907e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -47,6 +47,9 @@ static bool multishot;
  */
 static int kasan_test_init(struct kunit *test)
 {
+	if (!kasan_enabled())
+		return -1;
+
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
 	return 0;
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/654bdeedde54e9e8d5d6250469966b0bdf288010.1610554432.git.andreyknvl%40google.com.
