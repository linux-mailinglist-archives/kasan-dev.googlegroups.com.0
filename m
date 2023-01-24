Return-Path: <kasan-dev+bncBAABBLMEYGPAMGQEYEB6NWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FBD667A40D
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 21:40:14 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id x7-20020ac24887000000b004cb10694f9bsf6987285lfc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 12:40:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674592813; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+uJp9NAqMHdIsEtQRBWNMkIcNg/qXxsHWUBG9jUx2ls5oXl2yqoH3AGbbY6xYXmFz
         oJlK5eNy/P8Ta/qpoOrCXG9P7j5qJSwTcwzUUbUSqpkHqD6snRg9TjUFYkpOBV/By/8p
         vZpCoHJGWuowXvCPouYerqpWNEqNAncl/h1dqF992KkN94hHgM5qmx3h9WrKMJUxUsef
         77/dHTZZ/KGBujKyzXDCw5wNeb/xzoGKMN54DrRpc7XKkPOEAX2o9CC3DilTL06sSX2x
         OtVItU1k1Ft9zOeRLRoxS6abJgUkTqicufzRbwpjPrc5Jx9ubcgwtN52pv4UCbS7nvW8
         j/aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kvyv9WaKpQUUuCehmS4wnNKKJ83NP+k29AHx7JGP6nI=;
        b=VTKL8V77FwhSNo2g101YfSJucq8xI7pG/hUuQ+ol8OQzGT6qTB3hMaP2sbi+gJVqiX
         L4M9nBIMo2nkjLg7Oxkab/imLeFtH64YZ6n9V/2gKiD0CLV6JInxxdIYqu7/nBMoOIIT
         VZ5fqDgK4j+D4D+oeEODAceta0qhM92TdwoTwQ/pHRta40g5XGrahNjE17NgsBqo5KFZ
         ioLRsZ6X8XqRZI1Nww3Bb8b60bfkEgKbbVJaQwZTwtbo6+xAdlP9SUbhrArHPL90hLyN
         25FwPiX1mRjT0CqFEwRwWam8h+7nnXkOYdsWYKXVbiXwzO0TUfMPSVmS6M4FLdyRYpYI
         NjhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LRQ50Wlw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kvyv9WaKpQUUuCehmS4wnNKKJ83NP+k29AHx7JGP6nI=;
        b=j+6yyeMBuhjts46d9xK4WtyvKOrCDPY8ZtP/ojA/0NAv8j1hacnOGclgVHBMeuvJMF
         NCpR/xOP3WpZAYuSLljgr5bM+qntjnE/kjUdLSZYLYDeenUgATfnKSGSonmL9x3Gg7Pq
         HVwXAelRiBcjJzRosYjRuuMzfg4CbTNPiFBPFDHOfZ8aikTjn0qXngT2YJfN8iB+22te
         9+IbxmEMH1Uwj3W2U3gHUsVW5H+TvhwHTGgVkCJtAgJ32pYtXAuIQHvwI5FPHmD9qf9E
         lq6U6g+WQzJ8lL15ote5QUq/+LDUq5GhBiCJmdhqAgTkK9p7Z7zG13BBhHyrmInFmpZE
         L9wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kvyv9WaKpQUUuCehmS4wnNKKJ83NP+k29AHx7JGP6nI=;
        b=d7PHQ4emmvyG9rRS0/5uNc3jGG/S0SSYdTRQsMqjy3mvfbMwD54IhsrylhsyeU6eQm
         6+f8m5Got0d4UHbMDihDpA6x8AprYmUqq0P5NZYNnGsjR66Y6p7t+JcApzyL27RK0C2t
         s9+k03V368qhDzyaD8H1fngbtX8077eaEqIsDf8HbHcJdMnF4fhW2NFKbYWeXPEMl/qo
         mMgL5D3g7tHTf54qB/wpwBP3oLHNmaNcoc51d0hWd+CJqUkHS0hyzxMY4Q8Qf/8SRtxh
         CJhIoEkeQaGKBQJoZVjmzHjlp0ykJzKbr+AMpGxU1PSvSDQ9oueXvw1GWbmkeGf/E/Ig
         KFlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpstGktG0tnogY8p5RNrjvcFejCv4SFSVy62726GF/Uo5x1vRAh
	PsP5fOBqKat4o0kq4yfnlTY=
X-Google-Smtp-Source: AMrXdXsQxOLi+1Y9YkKsXe3keBCI58BWp7Pr3jod6ahnRNatF34Orfj7/rtpQjfz9EXuivj/L2mV6A==
X-Received: by 2002:a2e:808a:0:b0:28b:6aa4:9455 with SMTP id i10-20020a2e808a000000b0028b6aa49455mr2079423ljg.408.1674592813690;
        Tue, 24 Jan 2023 12:40:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:368e:b0:4cf:ff9f:bbfd with SMTP id
 d14-20020a056512368e00b004cfff9fbbfdls7911196lfs.1.-pod-prod-gmail; Tue, 24
 Jan 2023 12:40:12 -0800 (PST)
X-Received: by 2002:a19:8c51:0:b0:4b6:ed1d:38e9 with SMTP id i17-20020a198c51000000b004b6ed1d38e9mr10461914lfj.64.1674592812299;
        Tue, 24 Jan 2023 12:40:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674592812; cv=none;
        d=google.com; s=arc-20160816;
        b=Yl6/BqPuW7VidT6OxIaOJ8J7VKrsKYFOmZc1SOzZOUwgBkYDkCr6U+p8BLRogiwx70
         wmXtQNie8JrwPAwDI2XmoyAa5xgpPZ/+WdOU1+r/BDXsDSziRuBnkRf/EHCdBXnivY37
         ESXwjqq0HFSxrN4CRUv01De2krTONgzHg59gRkWm2MXiRagZf4bEaXvbvaDWIjDOnZ02
         HusUgcDzKuStY1qkbuDC9Wx6kiZk3F//s0BVOJ30Hn+siHOUHX7QfH/Sm1RcMsUs4jsy
         /Pwr3XMJvvgf9mexN77yVtR7FcLt3Rg/Vatguk8nzYqkZfKLdUS28E6SSluL8DSZjwQB
         j2bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1AR/rv3Oa6O7jvIvFBjmYxJ41m4mSBsPB4PLJyrZR80=;
        b=0XBhgp5qpaiOxcYRaDy6KS9dFW9gVGoAz94YOWMKOryiQ9/dRpmtFFwE1LIAXERzlB
         HbCAzp+uT1tx5Uu/TtXz5oL7fp+NrUBsUdaqqv1mLBXyA3El/uIhgPlKkdEFR34QTzHO
         7XoRkwIp9aPGEQzMoMNmNG0LxDnllt+v9RwkKC+9jFGOg6UV+7e9oyFl1RPCub7WQTiT
         WTpX98w5+J5D3kWZZDbhljShJLvk707Iv3H+pYVfdt52GLU+VyhAF31KK+jw35ikiIwb
         O3BlLTA7pYkly7lGjpmIG/WbOv0Y2ud2uLtPN6bkyFadHfB+8lB5X2vNLKCslWx+KYXM
         NvOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LRQ50Wlw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id f20-20020a0565123b1400b004d09f629f63si153970lfv.8.2023.01.24.12.40.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jan 2023 12:40:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Collingbourne <pcc@google.com>
Subject: [PATCH v2 mm] kasan: reset page tags properly with sampling
Date: Tue, 24 Jan 2023 21:40:09 +0100
Message-Id: <5dbd866714b4839069e2d8469ac45b60953db290.1674592780.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LRQ50Wlw;       spf=pass
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

The implementation of page_alloc poisoning sampling assumed that
tag_clear_highpage resets page tags for __GFP_ZEROTAGS allocations.
However, this is no longer the case since commit 70c248aca9e7
("mm: kasan: Skip unpoisoning of user pages").

This leads to kernel crashes when MTE-enabled userspace mappings are
used with Hardware Tag-Based KASAN enabled.

Reset page tags for __GFP_ZEROTAGS allocations in post_alloc_hook().

Also clarify and fix related comments.

Reported-by: Peter Collingbourne <pcc@google.com>
Tested-by: Peter Collingbourne <pcc@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 11 ++++++-----
 1 file changed, 6 insertions(+), 5 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 5514d84cc712..b917aebfd3d0 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2471,7 +2471,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
 	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
-	bool reset_tags = !zero_tags;
+	bool reset_tags = true;
 	int i;
 
 	set_page_private(page, 0);
@@ -2498,7 +2498,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * (which happens only when memory should be initialized as well).
 	 */
 	if (zero_tags) {
-		/* Initialize both memory and tags. */
+		/* Initialize both memory and memory tags. */
 		for (i = 0; i != 1 << order; ++i)
 			tag_clear_highpage(page + i);
 
@@ -2516,14 +2516,15 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		} else {
 			/*
 			 * KASAN decided to exclude this allocation from being
-			 * poisoned due to sampling. Skip poisoning as well.
+			 * (un)poisoned due to sampling. Make KASAN skip
+			 * poisoning when the allocation is freed.
 			 */
 			SetPageSkipKASanPoison(page);
 		}
 	}
 	/*
-	 * If memory tags have not been set, reset the page tags to ensure
-	 * page_address() dereferencing does not fault.
+	 * If memory tags have not been set by KASAN, reset the page tags to
+	 * ensure page_address() dereferencing does not fault.
 	 */
 	if (reset_tags) {
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5dbd866714b4839069e2d8469ac45b60953db290.1674592780.git.andreyknvl%40google.com.
