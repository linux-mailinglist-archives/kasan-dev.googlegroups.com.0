Return-Path: <kasan-dev+bncBC6OLHHDVUOBB4HXQD5QKGQEBDZUUAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BB42269CBA
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 05:58:41 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id q12sf1299983iob.18
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 20:58:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600142320; cv=pass;
        d=google.com; s=arc-20160816;
        b=gJ8APZfOSHlioneFEjm3qqcuSU7+ZpXv0uS5NqdrsABQ5UpHzhXdUy0TTC4u5vDp/3
         pofKhkBsK0W6A+WLRyrSGwwMihCTDB5ZJEwIPKD4SXFbmWaJEZZlCVIsiDd4fqfo5U+H
         pbx4oU8xZoj++VB8N/4KGADL9mU8r9lYrfQrvGKDeChxR4VYVA+LNJu0N5HzmrvnRUg8
         6cJrh312e24sKgxoSNCCJiyEwcgHtprGdRM1azjX2CA+SooIvGPDYGDEiIWSTBMh9M6M
         9J5MKVlOQDTyRBf37m0OwVgsPUwGc3rnkPmHZk10tFTzAgMnA5LKXNB9l2xu/RnzwIVx
         ivWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=03dlstkq+Hww8CvO4qUOiH99Xi1Z9lfvN0/n2z+sTDk=;
        b=Qc5E2P3A4vRvEO5JusXMPuTbqAfHY8UBPkuLGidPFzTRL/sQ0259f+UGXQtAZoyJfc
         zkv4CCIlIXc9T9uzLIxIUJRADNm4p+6Rjapp2E4RJEmYk4JLYZImeDgyy14OdNYjeZyB
         LOBcn4Qkk36jlhq6r3p/zOuERrBrsU05qts48gaYJPW4G0/sOmA/sJZG3U+aDeGO+edP
         S0IEBPkhmbQMjS7nrmo7IXBkkMv64WckvVLebrJQtMsw3xxxax5GZEVq81DFzLMiMsgW
         Onh83vpea+qc4BpyrLQqU0gek+Jwie3YK5Yj6g6ocYtx7s9K3wUmlyMWg9SfATdm1Ijy
         SLqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ABVIJhX8;
       spf=pass (google.com: domain of 37ztgxwgkcegnkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37ztgXwgKCegNKfSNQYgQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=03dlstkq+Hww8CvO4qUOiH99Xi1Z9lfvN0/n2z+sTDk=;
        b=rzPpq75WMLdtJzXPJW01/WObYwdmFiEnSX7OMGm29FvQmantKHE9fSvgjJ5FOuib95
         UO1qbS1Xr2wkpdVGNeVVhqhI96JhKv2XPG7/8ZHG/nTpmX1KMn2sCbtVG6DW6hT4n2X+
         FM5sNVyfaN7rxb/SHh2IDLfbM6N1VdFDsTfIC36cGf08CQ47BCWkshN6Ah5U0M/8FNIq
         TCH6NuYhyoBQ1q2dtNMwisvJK/RribXI4gPQFDnpWqmWKnQEDtWyFKzYhtyrTkeYI7Pl
         wK0ZLTyNn/KnF9uN8Pa2ii6TR7pupz7psFJb5fbVV4DomdCCMtuujmzspEnJ9OaXrG9X
         ZQeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=03dlstkq+Hww8CvO4qUOiH99Xi1Z9lfvN0/n2z+sTDk=;
        b=QgUN02huynDsqr+mr8BAFPIHFA2FZrJOaq62GZXeuFu6KESUSYL22+oNqR7AXamaBE
         9644gUedbSt9MMIO+uFX/s3jrdyZPpcs8ubpwecVz8KyJcvqgGcssTFULdozTs2VrHsq
         kNJ0l5PFD08bnGCNAyHRI12iU9s3wx6qY3+b8Dpamz7TolprvbXI/QxPbcq1bk4Fyz8Z
         IoFHREIXGRdtc7IU481iXdKk7GEc47LlAsE5kyZCBYU/nB+PuJDzxPuywl7Z7NQBu3bv
         cl87+RgfAArdFed94azXXI+blso3RaVQQVGiNOqpHzy8GDHAmEVcuz4lCFE90kqXlXq1
         1gXg==
X-Gm-Message-State: AOAM531KSUWn9Z7CHuZtXRhalH52zN++oqpnEUMYJ8YP6anaYNxPli87
	gVqIWhkxlD7QtDTjcrcraUU=
X-Google-Smtp-Source: ABdhPJz/otJ/UI7z4QYW5WYpIEKfVA6R63RyqqC0Cs1NO/nPB3LlCwIUeZotP67VCHUhFNPqVMnNxQ==
X-Received: by 2002:a6b:b787:: with SMTP id h129mr13810552iof.202.1600142320128;
        Mon, 14 Sep 2020 20:58:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5bce:: with SMTP id c75ls2978841ilg.8.gmail; Mon, 14 Sep
 2020 20:58:39 -0700 (PDT)
X-Received: by 2002:a92:9115:: with SMTP id t21mr13445136ild.33.1600142319673;
        Mon, 14 Sep 2020 20:58:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600142319; cv=none;
        d=google.com; s=arc-20160816;
        b=HIXIEtsu6FHe/VorLKtMLoOgK120tEHrdxFjRE7TXHbC8AvyyqJXunDPosBYCkJlfG
         xdtgwYWOpwN53Yp6dmHd/fhc9Fjjk4SrFT6GN2qAghp07Hi6xlR4KLWCBP7oxPqzxMhY
         kJbjGi2FOJqHtkWdtv1LJFNgw+1N6ZEEwmtZGW2D8gdAGi4hoim6+i5sXiuQkAI6TrG/
         63v60irn16oWHsvQph3yGWH0lwFuQ8GS5I0RAKwrSnr8couCmoT+MnH9b55nCUg9fkTH
         fYzdTOuuiCpwRGhATMpoSjaZupLMKchbEooosQCm6K0Afn01DGSkG1Cnjp688xmhqs5L
         ttRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SFW2h14ECMMfzbUIsG9wID+6ZK02/eLwTYcr5ku/IMk=;
        b=i1fZiMq5lm/wE7RCPQwroj2WughWkNakPknXj4EqdXZFadyNblI69Vj0aTV32OVA1X
         XBuuAvAeLGkR2P1SaHiIrOfSqiX1yTXM30DivoUOPyA/6u2JNOtW1HbxLPtUIojSzKcB
         ZM8L5kH8dWYMJruTmMZM5JHkbHfFqAh999Voi6yKoVHbU1g0my6bcpsiPFTl3WRJcknI
         UIEKFZ/pMyfC7Rfeg0L9o6odgn4KPSEMVtTJj8qIY+6xLYSRKqEH7YPe1qe+eZbp39BW
         jw+w2gaeqhMEPrDLTonqTwvVrCVU170jnpqViwdHdAbdtRQktKD2taNVTTNUEsYyMmyo
         64wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ABVIJhX8;
       spf=pass (google.com: domain of 37ztgxwgkcegnkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37ztgXwgKCegNKfSNQYgQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m2si999986ill.5.2020.09.14.20.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 20:58:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ztgxwgkcegnkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id x10so2019600ybj.19
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 20:58:39 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a25:be13:: with SMTP id
 h19mr27646628ybk.50.1600142319270; Mon, 14 Sep 2020 20:58:39 -0700 (PDT)
Date: Mon, 14 Sep 2020 20:58:24 -0700
In-Reply-To: <20200915035828.570483-1-davidgow@google.com>
Message-Id: <20200915035828.570483-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200915035828.570483-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v14 1/5] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-mm@kvack.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ABVIJhX8;       spf=pass
 (google.com: domain of 37ztgxwgkcegnkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37ztgXwgKCegNKfSNQYgQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index afe01e232935..9df9416c5a40 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1203,6 +1203,10 @@ struct task_struct {
 #endif
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915035828.570483-2-davidgow%40google.com.
