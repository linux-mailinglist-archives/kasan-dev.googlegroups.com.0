Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHGE3H5QKGQEA2WOFNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D255280B02
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:24 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id b7sf127779wrn.6
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593884; cv=pass;
        d=google.com; s=arc-20160816;
        b=WAM7A2+RsIZExj8yY4aEgjUZG4KtplOoKrWYoKl6UxWdgftYhXhFnHE7XAt8pUeM/L
         E/M4+Q7Ebz9wy7fravOLVOLnQ4a4hi8PyqWqcKuLiLse1qv/wptuI0Ru0mME0BjO2G2D
         apkuVEyRf0MKBIBFRku00F4uLBIefr2H0Iy8i+GOwegLmecJZWbyBwdUW+NOLQL4DmMl
         aEv3WREYRmWLO6svrSZGzzPmVwge6iIrhVbQ7oHgKvf1r86pYBKfx3cAXxbriQ4+8o0E
         6xW8jM2SSTSTvI/kMLTDAAvEIVel1/F5rSZ/zFZ9KnOCPoi+VIJAyeSHKjU/cZf9FY1M
         FDww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yJ8hYviHS5RcOxOrlwdVdXrstvPtC5fJZ7NYe/Wi3Cg=;
        b=eb5bYkpMzji/RCXjQNWziMARmM4QteiH1Wr8yR9RFlVsOEq029IHXRQ3Tc6vftrIEX
         qUYFKaO0p/pxBx0OjCWptnD9k5Q1p6wfIaRxQuRvMEiebnJOXXyPKNgN898hU4fF9Gl3
         F+s5mf9I7LUb/qhhdrAkBhZapU+Cr+oXGBPR54pZN0hnlTLyDOC1CpiTEd/dLXg9D3eA
         Hyvo11bll4ZwBSKUghbZ152f7nCapTCjef0Ike3z2WXqTXpPFw29PZjzO5QwVMwi3zZA
         r9v2riwxKhTG4JUjxEkvn8YbNX2HQs25PBMMSrpHpFKPJS51dU4lQXDxOXMcRYN+/RBR
         rpEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I2c3loWO;
       spf=pass (google.com: domain of 3g2j2xwokcbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3G2J2XwoKCbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yJ8hYviHS5RcOxOrlwdVdXrstvPtC5fJZ7NYe/Wi3Cg=;
        b=SkYQus+0ZBRmrx9gyNsfAvGfI/5eoNLXvGdd6Ojq0uoYhfOU3d7hcGJZm6nJ2+WETP
         FurY6QPjMqrBKYEmx/kmZlaaTBWmVLp0YhnniZuNXcdBCU/UIpi+Db3JukKNXUj6gAEg
         Xu1XjnZDPBnDeXeTiiL4uklHQv5TEyimJApA+jgLLLCeOjHjry2AGLX08uPcLVZpumeJ
         fR21DuYZgRjQc4FkEByMR7ZfQJ6ghL+t1lsrObhHxcqSGce2BWsOFeHyiu+x3Tux7sLq
         jT84+4AlBl3qQzlIOTv02JJBE8p6QUieGWvDRywbgSL3Vdq77kYqCR+bzxyLLntjb7SI
         Y0EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yJ8hYviHS5RcOxOrlwdVdXrstvPtC5fJZ7NYe/Wi3Cg=;
        b=mO7xRdDD+5gmSH31zqpsL9oR4KJJXk5pyvLVU+AXWgUqOmbdb0756TL99wQ+Cgmw96
         eU2wWi3C3T+S+uXZBiK4vJm3LX4QaZmYgiEmEJhkogtx46STPYe454s7ozWq0cgGeO+J
         pwFJsbUCQC9IQcoL3VXx81d5jg0DqsDy7GnbqCyhpOaEJehlhmlFYV9pO/IQc7KIg/TC
         ZwO84d36Hw51B/WckUjUJv6C6ZNp2jSKzwEpT7KM+OBSuTumSryAnxMyuGUvUCbZ6Lo0
         BO/7+TO91lOiFbarU8KwzqfAdntgUjfPxZeldZDMkEcspgjb/H4C/Z4Spa1aWYGHB/yY
         L8uw==
X-Gm-Message-State: AOAM530emh7TSV6VjTsFJaucGybH5oXTlH8EWnRW6t+HHAiHLL8tGrgs
	ZM7hV4wQaJp9JL0HMHJ1dg0=
X-Google-Smtp-Source: ABdhPJwt+b98+9VtuhdBRYYpdWaTx6pgvlnnz+uCp7ZIov+kzhosBtEQValw8B+a8saWJ+SCJf0w/g==
X-Received: by 2002:adf:a3d4:: with SMTP id m20mr12283162wrb.29.1601593884352;
        Thu, 01 Oct 2020 16:11:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls3659719wmi.3.gmail; Thu, 01 Oct
 2020 16:11:23 -0700 (PDT)
X-Received: by 2002:a1c:2e53:: with SMTP id u80mr343381wmu.58.1601593883453;
        Thu, 01 Oct 2020 16:11:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593883; cv=none;
        d=google.com; s=arc-20160816;
        b=Ch/HWgxfhI1oIcRtXlE+/lesbqtZESMYW0W5bt/YC1eGENjY5GRhSovEmxrS+vL6Dq
         ZaSCvXwKBTjvfKPXVtJwEtVOkY8Yyz9DfOClOmlLNAUeod2HwYusDut9zYgsjJEcdrF+
         M9ozIgB2+3JrxQXQdbSQJnGoa38sKEYUVQ8V8ueQ5xc53TXyhll4knZ1IRjfC5aY24pU
         LQQ11nqfBOXrq89iI6vILAiSF1BWDCDT2/aCj02XXv3/zPvtFTCSwpz7ML93rEacYROK
         hJe8Jsi+DAMgV39kNZhLMPCJ91IbxveO1ICnP4ioipkD1sIgZfev4+eEHJ3XVkqiMGpk
         9PNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RtCJwMgIYvelzx6W+VqX6CCQBYnpjAVMkxalLwUkkpk=;
        b=qRBOpnEaakEImopuURVilnJHxNvOgdEtT5s0gdvjpD4cCj1NRQ64q7Qin2Wl5br7sA
         Q871XkFrdVPOUiqWxVz0h1jyWDEEts2sEMcQyWQ3kgCXqAqe0ob+iEU0GhQoGcsvw1yx
         ikQrNeoqxI0jvb0RkWXBYQ4SpwEoWtoQ4l1LRbaHnDapl6HfMTaNa/cw3s0iVPFHO/pz
         0Fi2dKMz+0j9dwZtcvspXt9RC2bWgoYU4QD9aFDAMc+ogGpEgp4RRGZyO8WZKtg5sbsY
         myPa99zHXUrrj5THBr9GlFvYwiSDCj4nDT7KX95hoe+2S6dE6WreoMQP8HcIXlGK3m9q
         fviA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I2c3loWO;
       spf=pass (google.com: domain of 3g2j2xwokcbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3G2J2XwoKCbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w2si151714wrr.5.2020.10.01.16.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g2j2xwokcbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y3so113310wrl.21
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:23 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9d82:: with SMTP id
 g124mr2345719wme.4.1601593883158; Thu, 01 Oct 2020 16:11:23 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:17 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <c89a70b8b83467442ce2212f98ee3af9dc7af956.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 16/39] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I2c3loWO;       spf=pass
 (google.com: domain of 3g2j2xwokcbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3G2J2XwoKCbofsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8dfacc0f73ea..0bf669fad345 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,7 +146,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 91b869673148..145b966f8f4d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -329,7 +329,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -340,11 +340,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 42b2b5791733..ff067071cd28 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -117,7 +117,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c89a70b8b83467442ce2212f98ee3af9dc7af956.1601593784.git.andreyknvl%40google.com.
