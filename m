Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF6WRKAQMGQEUPKVI4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B8F1D3152DC
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 16:32:40 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id n12sf15579280ili.15
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 07:32:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612884759; cv=pass;
        d=google.com; s=arc-20160816;
        b=UvrF+eOzL5urmOjeaVT5qP/36aiyNjZ+pDrTGP39oAWyleCP4c5mK6L4B+H0OjHMvA
         l09zu9yB7LvOUgxLfvC8ESk8B3v6jY98AFFUKR1bUa2fCotruFDE2W/5MFU/fYuj2oZi
         vBjLXDs6O/lfV1heSSG7Pt6UQBOeTOZgJRzeAdwKNEHHq7f3C/ztpgh8zP1N7o00IbzA
         6VlYZDJDBL36Vkev1wYyURjBWVl4vRuxCHQiwmFJLyYvLHqnCxyzWa8J2pekyaEulFTs
         gm0R/rQyjA0tm5nmdjHuu6p+V2S1F6IQlvrPfuhMl9rZGkDJP1u/3NxSP2qIqyRuF1Nf
         2ZJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Tp/20aq4qqQwkrPbU/TF1JBllMfKukUqM6dsWYS4EJE=;
        b=cmQ22YmlwZfTf1gA+vm2ljqIB5HuSI85oC+49qgErxiRBxiqaj3EmQVmkWztmow8W0
         97h5+zgvd4fhcB6o11/SCyHS9QQt3siN09oBjGZ4zk8FBQhEDvdvA4awJJalr7eCHgNo
         ZEQ6Ui6OsTyHlKNhMFTNpgVqugSxC9N3K/vCK6Crjbw+JFCnSo2GKTZJ0IAgmLOfPacY
         ByR7URhPMyPZOcChJuRtVqdooDzTx+Z0hMxAWlk4at+F4zCUPBmcEUJ7Z9fbiKTAkzOC
         yf8wCq6zQTbIv9pTK7icouSHNCeovFp/v1wUGuqroc4lTgD/J+9Z64qtcBoA1lcKSDDG
         5UXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k1rtx4PV;
       spf=pass (google.com: domain of 3fqsiyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3FqsiYAoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tp/20aq4qqQwkrPbU/TF1JBllMfKukUqM6dsWYS4EJE=;
        b=lP8eBxWuWt7BZRDGDasDjEXscYy5ur3UhjDLoVhUZS1LsZALI2JDqN4XMnweyidM4m
         XdUwixO37/wZrAqkl8XF3eMBufpKalYeBNe31E6bgpLrRNUod9sl6N/ih2shncJ2x1O/
         lXZ+L7pqn+kg9LxIIU+RVxo9qLRoroypDQwnxTqL6pvTHa+TU2v7JsSQYv4zX3JtkBNz
         ztehUILn4yMuPkEMAksaXkQPMl1GUax3dPqCrHtBgYvlZLn1pLPLg6KTQOQ2Lb7/30TG
         w7gnlq51IRArt1aFQhePGmMsx0jfw4ldFcTB9gnWtqM6tDz1DpQNDagExVVx95byY/TX
         cBTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tp/20aq4qqQwkrPbU/TF1JBllMfKukUqM6dsWYS4EJE=;
        b=m99LhEQtDX/GIgTxOx4SpvonpO+PyXuiyrO1c7KnpInW9bnNM9RcrkZLdjBMOEecbE
         nQQlnZXF1Afk3kLC8PP69184gfzsHEw2tmF9w7d/zXN3RHVcuv0R5VCXljPM/g14RMMp
         PzCORE8bsVv1v+5WHAbx5rL1DuVw/By+MvwfgXfkiTYM3VphEZzSNJSJK+5O7K+nUbL/
         TFC1UVj1K6plHZ0IxJR/BOf3Gi/UaFO78Gt2A5X0I8ozmbMuqCnLSXnlOgTSrULLUkBO
         xjyuiU6AuegqLj2cZV6fUslT8XKcJrjkTgv+npbfmkSem5K25bi06P/6nawOaqQw53v+
         N5Xw==
X-Gm-Message-State: AOAM530GllHzYTH6/uIVIjcCXTUkeqWItB0s58W6G0uhoLcedLvzIHD6
	FQDaIux3B1IohJP533NaR1w=
X-Google-Smtp-Source: ABdhPJwzECBWnwOVbxuUsTB0Q3mji9GCh0ByUGWPesKFlAeNNi2WdybRwHzXeMnoab4CUg/ZsXm0Vg==
X-Received: by 2002:a05:6638:2192:: with SMTP id s18mr22692805jaj.18.1612884759723;
        Tue, 09 Feb 2021 07:32:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9691:: with SMTP id m17ls1267517ion.2.gmail; Tue, 09 Feb
 2021 07:32:39 -0800 (PST)
X-Received: by 2002:a05:6602:2e8c:: with SMTP id m12mr19682516iow.19.1612884759168;
        Tue, 09 Feb 2021 07:32:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612884759; cv=none;
        d=google.com; s=arc-20160816;
        b=wkSaeeDcVxLEZYN6zO64acjnzAf50iHfHTFwfaU3DzeqKXy+psxwq9fJG5a9aMomqE
         ld8NUsnXZZP1l7EX9zIGL3KYs4KhnqBRMx4fX1avBOceFYmIWR4bfc3jS2iYX6FQgU/X
         F0gPV/JTBswcddtm7nvjCTJtxyyXRbLfdKuCIihIiMlDHeOAB3oE4j+s9UjTMiZYJ3Js
         cjQBKkNIAZjxPmbOPD8LKT+K4HjF81XPx3MrG+hWZq1Pf0mI77Z7Q2YllAvyQVoARKKz
         xkQhEjjysQbbgaD8FDIo0ejgooOSYBuyHBjSEmabNuJ2UW3AuMTjofYiU1PPFgNsyTLV
         hKSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=3AT4g9LoM2snc1rY1VWM+BOoG0vxl/R52Ax9ZAP8Pps=;
        b=NDS1+ZfxxWhsIKN9yJE37nv1PZ8S2EewlR1/CfK2RGVxWr/fg+q0Ik2lqg/6les/wh
         Nz+naCBJUASjCPCG1UKM3E1F1rOKHy9cy55uAV4C74/6IvspjG9f2HZ5Iy4estGp3q0D
         mfHpsTmufyvWV46RnSH7MKSnK4oj+xK8Q5rZakXBZL42UuDFHG6k3ZgWJbKwTxiwpMiG
         +KXnqhjRwPC9hPIIakIjSOFLBt1D3K0P4vjlhbiVVem7pYNGsaFbiG7XeZNgkXtmQVBi
         vKJ/HyzluNvxxucfbcg7IOHQ6ZU5Q+dJ4OBKFEYf7PDgw200L9PAcQJOSNc0mDALA1ia
         pheQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k1rtx4PV;
       spf=pass (google.com: domain of 3fqsiyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3FqsiYAoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id y6si785227ill.1.2021.02.09.07.32.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 07:32:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fqsiyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id r15so6691706qke.5
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 07:32:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:55a0:b27b:af1c:327])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ee89:: with SMTP id
 u9mr21350165qvr.40.1612884758518; Tue, 09 Feb 2021 07:32:38 -0800 (PST)
Date: Tue,  9 Feb 2021 16:32:30 +0100
Message-Id: <dd36936c3d99582a623c8f01345f618ed4c036dd.1612884525.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH mm] arm64: kasan: fix MTE symbols exports
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k1rtx4PV;       spf=pass
 (google.com: domain of 3fqsiyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3FqsiYAoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Only export MTE symbols when KASAN-KUnit tests are enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Andrew, please squash this into:
"arm64: kasan: export MTE symbols for KASAN tests"
---
 arch/arm64/kernel/mte.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index a66c2806fc4d..788ef0c3a25e 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -113,13 +113,17 @@ void mte_enable_kernel(void)
 	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 	isb();
 }
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 EXPORT_SYMBOL_GPL(mte_enable_kernel);
+#endif
 
 void mte_set_report_once(bool state)
 {
 	WRITE_ONCE(report_fault_once, state);
 }
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 EXPORT_SYMBOL_GPL(mte_set_report_once);
+#endif
 
 bool mte_report_once(void)
 {
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd36936c3d99582a623c8f01345f618ed4c036dd.1612884525.git.andreyknvl%40google.com.
