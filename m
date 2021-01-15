Return-Path: <kasan-dev+bncBDX4HWEMTEBRBINNQ6AAMGQEO3QSP7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 11D352F8307
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:38 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id x186sf3348325lff.7
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733217; cv=pass;
        d=google.com; s=arc-20160816;
        b=KQzcSPVZgHXZ24aZ+290bab0Yb0J9ZngwcbP7j856WBhQuoZlGOhHtF/UBvTFUJ1WV
         VsGF9BrNJ5IOJpvdbgI3yjXem2okNSpqDy6ivnyrDUtpNE1RshZpBwuSgUqfoA3eyJXT
         01NTet73WCh/8XUSMP7NgPPFpgAE7hF3xESsiuWoko2HuIu02Uxfy1Hkaz7ZCqEOe++A
         b4Iqck0R74GU8Nx/R51TmecvLPtLUFp05gl/2yLGpPM/RT71TCIn3aEoZC/zkq09h4Vl
         bw9UsPw5qhYkLt9LAPEelyEYyXnotvc53cCzA097Exgh9Fft6fptwx16WWViR+9rWb5l
         pzRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LMOraClRGoQEdyniag+RG6YbnlgUridkh4/AgqUyRXY=;
        b=osigxuAWySdol4kh2xol9jR7f0O+qT+C6tKQdL0LIOFnJPuwkEsYCeSYTIDqsNJ2Xa
         7vuU8xV18hJKF17323hVgErzAU5paYpRCWLqiJIhuDOeNi40oGROhTlpnAzn31BnAWGz
         bfW/IGboxAuwhNCwZiNk8NyLFsAhN9nWvaiwzV2YcwC77Ff/ysCTUA+CmED0V+rCZF40
         YeEtgHmbUCxDBnItuuMPtUSWmsDUVLd+TTX/pnA+vDulbrlleQjTN6GDEQvkjwR+1QdO
         QECDcSWzLK4uP7q6FCcqw+CsNRwHAsFsXga6zqG73T++34x/QvJhu6VcKpHNdR3y7WRL
         n20g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SmjPm6Fs;
       spf=pass (google.com: domain of 3onybyaokcvs3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3oNYBYAoKCVs3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LMOraClRGoQEdyniag+RG6YbnlgUridkh4/AgqUyRXY=;
        b=VUrpTRW5XzRwC9s3y1nhYTzUEvdM1EfgAl8T8/Enbz3DYqUcIzM05TosVTR+Wr292e
         fKZkYkv2Q70vLDG/BgHTcYlv9IFyqoOJeoiCedvpY1Au1KAf53Vi/44IOdCc29lo2luR
         xJ5OuWvJq94Dton0K9cFa2UCSUfqeebOvufliwmtAsDi7n9ptEDH6KPdDguxk2yHJX+a
         U5jn74JtX2Ct2rYc3kGaSkDGAjE+TTNxIycVFBXPh7pQHvfS+WHv+WojNBKBja7Ry7Fg
         6GnUqeuYqA2WwBe403sT+thN8mL+YcZwazBEwt+GVyPdoxmSbPz/TFNSPntsSJEVH3Wz
         WtoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LMOraClRGoQEdyniag+RG6YbnlgUridkh4/AgqUyRXY=;
        b=fTebreQE5K9yAfMoXfsdQJEPdT5O0UQvp/wBleDYK0WbfvO/2VnZB35TitxIY9bauv
         E4bQphzmMKwBNk7S5ouifUWwUog+7JH0GafLKjltRslA3QBDvbNANFcbjVar4JQ0USUS
         ZJgQtQClMrIBKcEQNBmsv/7W3kzRBNTr3fYdDUdrWi/naSHtL001jAvacSCoVdvIeZw4
         NVe89ta+C0qSQIK0QyQP2weT9ziITrjzXwEXANjoJrEBse4Slh7gUh37m2+gOhKnsxdL
         s0ZyjaQXQ4aBhzY6mDZmcmLnOch1YrRYMo2hhpVajkLb41WvY2hGlL4HklGtlheX0Yrb
         oipA==
X-Gm-Message-State: AOAM530Lbhf/LcfbsUv5VwHCU97rMokilEhazY2ShPNsqANbEM6qCFhZ
	GDohxmWhTAwAJhDp3OYNntw=
X-Google-Smtp-Source: ABdhPJy1/Jp7cJOyKZP8HeCofEXQzYzRRkPpWUa69z0tH+OKE9nZGCxr1GrcuQLu1x/ouIylUGen7Q==
X-Received: by 2002:a2e:9b41:: with SMTP id o1mr5884154ljj.14.1610733217651;
        Fri, 15 Jan 2021 09:53:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c1cd:: with SMTP id r196ls601204lff.1.gmail; Fri, 15 Jan
 2021 09:53:36 -0800 (PST)
X-Received: by 2002:a19:2d10:: with SMTP id k16mr5656425lfj.161.1610733216785;
        Fri, 15 Jan 2021 09:53:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733216; cv=none;
        d=google.com; s=arc-20160816;
        b=TPqyBl/1NGJWBNvNCPWhP+IbxG/eJ2UGaO/S2sAQnYoVk46zVQ5Vryv4ze24w+Qs8s
         B1USDBHtHhsnHusRNqTxkORqK0sgWFcgYAcn/fKBlql4FWe+2u1HsnX9heJc7+91HpSq
         La5qOiBLWqhBWSrkFRCqZdjOwI9vvI86wGo2+WqwRpOdsOlPWH4VfeloL2ulEyw39H0a
         smTkaywfhHSsI3tl/muwHJt66b2fBSOumsZcXQb3O/HAz+SfX6KIj4bnWI8lyTG3zNAZ
         9Og8daLEGNw2Nb0hKYqXl8GR6KQGDDazVhaitKMfEOX/dPBnzmbCZvKGYuCEe6MA8khC
         HLiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2dy0JKUm8Du/4wd3SX5MxOAJub1HPeeRj+5dAQlPBLw=;
        b=rF7cWuhsnpWyydNeXDQUMMAbJnj5rsxko4+V7tZcZGIvmIqxmquZgsXgPV0+2WDAVm
         TOxAIJQgN9wLYPNI/1E6iDaHkH6qquBv2pXi3RYApMxA2H+o9AwZKKvbKCqj45+J+id7
         spKFVlGsI1+PhRdPxGTHSt+QMdq0jhm4oa/kJ7aZ1H2VIYiptmdVlf48nYHhZ9xwc9Uo
         wxhUy5Sfz4lvKZyHFqi/LOIcinQ33w79iNT+46UY2JnO7EHWdOAXxF0VNvXsLjiV4DsN
         O6yIVMYGdfMufEjdfJlJhVgO1UNvQ4XK5XU6CPmCm7Eb44KrM8yrw5XD866kQ4h1Yuqy
         Mrag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SmjPm6Fs;
       spf=pass (google.com: domain of 3onybyaokcvs3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3oNYBYAoKCVs3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z4si572835lfr.7.2021.01.15.09.53.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3onybyaokcvs3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u67so556403wmb.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:36 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:51cc:: with SMTP id
 n12mr13912569wrv.375.1610733216075; Fri, 15 Jan 2021 09:53:36 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:52 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <25bd4fb5cae7b421d806a1f33fb633edd313f0c7.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 15/15] kasan: don't run tests when KASAN is not enabled
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
 header.i=@google.com header.s=20161025 header.b=SmjPm6Fs;       spf=pass
 (google.com: domain of 3onybyaokcvs3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3oNYBYAoKCVs3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 4ba7461210fd..d16ec9e66806 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -47,6 +47,11 @@ static bool multishot;
  */
 static int kasan_test_init(struct kunit *test)
 {
+	if (!kasan_enabled()) {
+		kunit_err(test, "can't run KASAN tests with KASAN disabled");
+		return -1;
+	}
+
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
 	return 0;
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/25bd4fb5cae7b421d806a1f33fb633edd313f0c7.1610733117.git.andreyknvl%40google.com.
