Return-Path: <kasan-dev+bncBAABBXUC36GQMGQE64ZUX6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 46CA2473707
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:43 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id q17-20020aa7da91000000b003e7c0641b9csf15127890eds.12
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432543; cv=pass;
        d=google.com; s=arc-20160816;
        b=VHcsFHjcTAkijhKaJ/BLxd950MkDR4EfBnmO1XmxUzM74SnBvNVu8Kh/0Sk8ZlfJGI
         vp6mVx0ixyu+Z5FEicelng51lRb3J3l+TOdK9oZ0nPZvASSWSitWBoTmtHdsHKD0PFKc
         Za0gbhwQCLHmyvImdvAP8bKD8NOdDAYETQHh/pSHwzUDmGXWqpIj3Lfaiuwqc+ImFJQF
         8bRw7rrFquMoYUmYw0r5TuFpabhqTpIlEKYgtOb+y6nKQEBu15grgOU/72oJNcXluyNA
         kGRZ05GimLItFhNZniu2VtfmRewz1jg/nxOGMVg0spLHlCI0u97DMlnvLtsnRu4OKzBF
         TkzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5ux09BsXQySBSKc5AMNYQTAiwM3F17bWeaRMGbktPhM=;
        b=wHK45cUVbX7EEXvUhqzA4eJ5AjZBw2r5R4CJsJysSfKY9fXXcLWXSKah1i7GmFXtBK
         oK5xOYF9RKUswxy0xQFp4FB7k5BJGE/yA6fUoKUgHM6DD5DeNo2LHHWcZQrIkz91jXES
         0NQ+AiVr2aRp2oJrt25Vt7YUokgXz9DcRJN64DaJ8kBKYcWNNwaAv/VO1tdU7C2zS2uJ
         iHM2+8/Ifr37aoZQsETNPQtVy/+RRv9VGXPYxAJwPHFxFDJKSe6yIFu92Je1LabJAEWc
         ZmH2Vcm4iQD3mkXg6LjupOwMW4A4s9CGDK+BZfs6HFYQ2mmUe52E7KcKXB/ENVJFhLcF
         QzaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n8Iiezgr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5ux09BsXQySBSKc5AMNYQTAiwM3F17bWeaRMGbktPhM=;
        b=hyHxQ3x+6o+DBL56R4t/GKy3bE/kPjimC+EHOnJWJDOKwPlfnhltViyJxe7fhN63EG
         A56hXrKuRNyJxWAfnAiR0woKRr9xOud4pkgpttBvf4OtfmMDCDUSsdZSblCNX+ezZ1uG
         w9b1D3WukM4YfN4XazkYT6GNbFPEnShSHMOMgtcXqULZ2b+8vm6GucOevNIZ6XvJ6Ot5
         tGS+CA9wlmN6pcLKCk3UpFjKpg5thPzd2IH+R6mc+HTxNlRC8J5Xu1TjYveP0tMkcPgG
         NFx0alDogediInXAnbhxbKbxHWGbxA4bUL1uoKsbtsfcrcsDcOBrMDk/cOGxlKrONxtH
         IAQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5ux09BsXQySBSKc5AMNYQTAiwM3F17bWeaRMGbktPhM=;
        b=nhyRiN8WQZjQhihr7y5Rw0aLNVy7y12UidIUX4Snns4NcYGAElby3itKkSikAwcuPt
         Fp7yqqMnzZwonzoQnyT6G+W36JkHVT4hdFnEA3Angp4QKon2A1CBZg2WBO83Sus1n5Tn
         QTFSvgkfJS4E9TrEquUYKLl+EY/5dUZYGTSArABtZYgsRajtn4h3NEcmt6kwHxQDOZDx
         YR3X+5R5KWfZOtsnsjzA+0MFMe3SHHWPsZ4slESQJpAITH3SDxHDc0OnEADgP6VQ5z4h
         fTZipJ2ib+esVrhEcNEUEeJX94pynQx/nRUX0ALRk9mK/jkxFXZ7hTQMgsKZQhHdFfLU
         MAng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gj0b7fQ2n2PBvBENXF5hx3KTTGZxXHfYWg+iMVQNhQC0YdlF+
	GwnGiJisVWgztNPumqvbcGk=
X-Google-Smtp-Source: ABdhPJwtca22j/+dSZiOsqQCuDmNqy3icUBmWmKubjAxFPy4AVWIRuIJmN2OXXZdG7wfqS4O8baLvQ==
X-Received: by 2002:a17:907:98f6:: with SMTP id ke22mr1169613ejc.500.1639432543036;
        Mon, 13 Dec 2021 13:55:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6283:: with SMTP id nd3ls1784270ejc.0.gmail; Mon, 13
 Dec 2021 13:55:42 -0800 (PST)
X-Received: by 2002:a17:906:54d:: with SMTP id k13mr1000760eja.545.1639432542264;
        Mon, 13 Dec 2021 13:55:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432542; cv=none;
        d=google.com; s=arc-20160816;
        b=r401E0rmQ97xIf5bfgNG1Ogqdu6+HFH9FPt/6eYmZbBlyxRypxMyAD2ZOXIJxaRuIh
         QJD4/Y1onOcwov83uHh7zXmUXVRULvkriJZ5+m4T0CFy908ypPV1/uGxaiCshEbCPPEu
         uNRmRdm0PAk/cuZ/6nT2Yx3lSEQhHAQcsowYYUaT5YE/iZK2kyOZqG0+ExrYWbQOgww7
         JenJvyFdvPMs4+OanA8PSojE7V6BBmdkU74CUnaSZg0YTJqMSb4yDzI2swdORbsx/dg5
         i9ulkGZXQQRhI5+e1+3KQWtQzpjKbzDtP1dKeXxdySM3Owmgt6zuI6z0C9B7VPBVAx24
         yqCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kHZOj5WZAaymd3SINeiupzKAuzG4dvu/muRorIs4Zec=;
        b=ypkjo0cqtwgYh+K6usDnF4LSslSA+CH1qevQbPgXbYYVPFMhubL37DLJiOd+XtLQxj
         wwwmmr9z8fw4CW+9lyDdp+j1JtFKUqFbbQPcoNb1LoLge/pizkcSICb+nyZ5XUHORtuc
         SMnPSHlVlK5AwK5B1giYoPm4FnkhrH/abVdDYfPhXjSsleD2gcT6E0tf+QG/ogk93RHI
         doCwEp4n2hlM2BFFfznKBrvxGBUSn/4z7zZqtAUaCak0b4ZZdMCa9dKGHk7EVqLUfAQQ
         HRiE2riwCht52+oYNyT2imNySh6gKwR+/MwRPqCQS4DrZr9F5mezMLbbvOIGeBSXYtzX
         0ayA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n8Iiezgr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e10si779268edz.5.2021.12.13.13.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 33/38] kasan: simplify kasan_init_hw_tags
Date: Mon, 13 Dec 2021 22:55:35 +0100
Message-Id: <8c59009047ebbb0a8ba3d8c30e2c4fe820fb0c78.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=n8Iiezgr;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Simplify kasan_init_hw_tags():

- Remove excessive comments in kasan_arg_mode switch.
- Combine DEFAULT and ON cases in kasan_arg_stacktrace switch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index fb08fe1a3cf7..6f7ed8e3180c 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -159,20 +159,15 @@ void __init kasan_init_hw_tags(void)
 
 	switch (kasan_arg_mode) {
 	case KASAN_ARG_MODE_DEFAULT:
-		/*
-		 * Default to sync mode.
-		 */
+		/* Default to sync mode. */
 		fallthrough;
 	case KASAN_ARG_MODE_SYNC:
-		/* Sync mode enabled. */
 		kasan_mode = KASAN_MODE_SYNC;
 		break;
 	case KASAN_ARG_MODE_ASYNC:
-		/* Async mode enabled. */
 		kasan_mode = KASAN_MODE_ASYNC;
 		break;
 	case KASAN_ARG_MODE_ASYMM:
-		/* Asymm mode enabled. */
 		kasan_mode = KASAN_MODE_ASYMM;
 		break;
 	}
@@ -180,14 +175,13 @@ void __init kasan_init_hw_tags(void)
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default to enabling stack trace collection. */
+		fallthrough;
+	case KASAN_ARG_STACKTRACE_ON:
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
 		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
 		break;
-	case KASAN_ARG_STACKTRACE_ON:
-		static_branch_enable(&kasan_flag_stacktrace);
-		break;
 	}
 
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8c59009047ebbb0a8ba3d8c30e2c4fe820fb0c78.1639432170.git.andreyknvl%40google.com.
