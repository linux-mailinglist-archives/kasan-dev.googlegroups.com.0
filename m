Return-Path: <kasan-dev+bncBAABBN4I5H2QKGQEOXMEGWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A7801CED19
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:37:44 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id n77sf6590920ybf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 23:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589265463; cv=pass;
        d=google.com; s=arc-20160816;
        b=k8EDfWobBiNBp3CCGnDj1So/O3uf2xGWhpy8AGaD2A16AMxKXGEp5wXjxoTy6qsT6J
         L0ODKh8xm6T/jJNXBnbYKR/v67kSegZGFNfLeUpGeMdvOpYv5fxv1scK8ttSTG9JsoRD
         JoxZLatIVE2232MQUPHWlHcAo4sfbmXEhhwG240KX6TdRzrmnArQttI1HXX8E2TjC5+q
         zlhR7/3Pj88M/4wtEEEyvJVU5qVhioW1bP1ruQb4sTy3w1+SJYlJAgHnMCHg/3j17zfg
         YfR+xGkYKqN0yvbhkr3YTcvypGR8TsxWW/r6n+2H2h8/C6NwjpUEuf2KNFjpn8j8qOpv
         L5Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=a3I6ryUzHEb7vofTEvQe6kSLUNkAnoiUVfp365+pWiw=;
        b=D9FKiydEceYYnExcc1tuvmxR3aiVsVhHcYyMkqX2AFVJOmEixd+FNT3ky6bDjFPe+N
         Oax0e+8zsuUeQOOfkytulhSvkpY7pxvXH/PMt9LWWCr/KFPYVwQUdnlzAldkkm1+we5E
         S+UiymhKEGrFHhtaXzal6MBCoKQJB/+oB4B9/G4Pmf0tIhGyObNgLL9K414sUqBxHCSM
         x2PfRO3J1Qh+zv9vO2U1Dc3jW/K7vLf0K/uVHFUqbDuwo2hbVRI3qovDxLWDMJRXYpn/
         kEpHW2A+/1MCMM+a60ODFJcf5DFhpoaRFy38loQxv4xu5lZVRGulA1+CTmEVDpBcKQT+
         vbeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=k6mn2kkb;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a3I6ryUzHEb7vofTEvQe6kSLUNkAnoiUVfp365+pWiw=;
        b=J3+OmDDxVFfS9swB9ThtGaCodYQEQkLya3eRejzyc9IM8/EhLHwQf0WpPJEgtjvOVy
         asMRFu3nZwB4Doie/+VwskriOiL56RClTiHiRKGzTQqNCypp81trtPtI3Jdtb5E1Knpv
         yl9+MEyPs9eYdudFebclnRHKZaezcz2tnE1SvtxlJD12hTNcHRBbz30+helc51VUUoZq
         nTsfcr2eoczBOMAebLbjsbyzJdhxFmkSUh5I/BXzFjHQ993NNiE062SZs9DBcUID9bG8
         m9sqe9aBEdE9g8pF2srARKDomfVSpUPaQ3iexvhH3LcDr+8Twn7lPaAhnARI2h59EV0A
         laNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a3I6ryUzHEb7vofTEvQe6kSLUNkAnoiUVfp365+pWiw=;
        b=BqEh4HYJc44ULKuyh8f+l78no5601+fJrxP2nRMQU7kHuGtWxaMPuWVNk6UuKm+TYe
         VH4Ihc0RCS5uz+gMdsq6WoPlhU1cZwWn5r4fP3pmhjhG3BUsMky6eXpaP3zQ6IY8BMkh
         auM7jsgojYce/LfG0+rWcOe9CbBCpOrHiPKBrI3R9RSHeZ4UgryqilQps2hJH4v3b/4U
         AP7vbqNQX1TKwDHh+X4Dgj5Iq7LGZwrNaCUO1dZXXX9fsU5dcAX3BQtfRxK6Dqr133ZO
         dg/q2Cws5i0sxDjsRRSmFzLHm6t//MKp6o4ubolHVQdbPQsNMs0LjUHauiZ4qk6HmH3Y
         w4JA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ+SH26ruD9yskVSR8ovWs1fgN17n5PEHm3ZFuk6HTP/tp3Kckc
	jOzUJ8kfJR0NojIb0qSgHFU=
X-Google-Smtp-Source: APiQypJkT2CyBcXBsTFlukaRtO+p0Q2Z27B+rhcOpmJLdQvhxtUiYobsJc1togq0lV6p7g9HOWmslA==
X-Received: by 2002:a25:bbd0:: with SMTP id c16mr32346936ybk.296.1589265463407;
        Mon, 11 May 2020 23:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cd43:: with SMTP id d64ls4431970ybf.6.gmail; Mon, 11 May
 2020 23:37:43 -0700 (PDT)
X-Received: by 2002:a25:e6c8:: with SMTP id d191mr11898210ybh.271.1589265463053;
        Mon, 11 May 2020 23:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589265463; cv=none;
        d=google.com; s=arc-20160816;
        b=WYoZ8KQBq13014pQAQh5402qmJUjqFszzVafvL/mBQaZiyD6NqJTsxaYHX5GB1371U
         +JmSgBgSkWKWZItdlVfNlhMewedlr0RxNQ1Ch2AtH/s2+dw7+trGozMKW4WU2OV2oIW+
         nlM1plMTmaHrPts0izQX+/wGexp+3Y0B4O2lUYKXw3ApeTik4QPCUt5OahnEvWQmE0e4
         +cefY3k7AEfTD71h7YjHUOnjwP1Avq6jh+AqX9uRK4I/uaHY1OItaKSElu4nhu4v703c
         vGXsKu95qU6G5qj7Gt2i8FZ0BE+2kZOtVDT9SM+a3WcfBvsnEY7rUslh2dfzR7OHIcsW
         ULyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=O+mK+whApmmZCIgaUGywGIf3tiE/s+BUdS5NHNOMy9w=;
        b=ndhqZIb3aR1FUBab+ey7M82hte4U95+etyAp5T1a+aULp5At3lGLgwhKyiHTBql938
         OkgrkR9C4Bb3qStHBzxlwE7pBmi/gxfhnHItgHThEuP8dnHfUq/mQhsjlH6tHluwxHub
         0dR7+feHgrngHpJWwLM3fvIy884JwcPwTrJ3MTz8kvcOXH7ZpB70C0cHGF+VWUKCUPjw
         YUaF4qlxGiCaLaP+jYff9pi5kIMS0E+oGQ78s0WcBRfbPE9jmRaRi22kPXftnJnV++AF
         ZogHWXPTfPnONOJeJa/r0c6S2+7B4Mff9hceP/gZPsQhKOAkrzjCW6OtOJlyNTKSgabI
         FvlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=k6mn2kkb;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h14si298899ybq.0.2020.05.11.23.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 May 2020 23:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (unknown [213.57.247.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5D46E20733;
	Tue, 12 May 2020 06:37:41 +0000 (UTC)
From: Leon Romanovsky <leon@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Leon Romanovsky <leonro@mellanox.com>,
	Ingo Molnar <mingo@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Peter Zijlstra <peterz@infradead.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH rdma-next 2/2] kasan: add missing prototypes to fix compilation warnings
Date: Tue, 12 May 2020 09:37:28 +0300
Message-Id: <20200512063728.17785-3-leon@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200512063728.17785-1-leon@kernel.org>
References: <20200512063728.17785-1-leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=k6mn2kkb;       spf=pass
 (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Leon Romanovsky <leonro@mellanox.com>

Use internal kasan header to declare missing prototypes to fix the
following compilation warnings.

mm/kasan/report.c:457:6: warning: no previous prototype for 'report_enabled' [-Wmissing-prototypes]
  457 | bool report_enabled(void)
      |      ^~~~~~~~~~~~~~
mm/kasan/report.c:482:6: warning: no previous prototype for '__kasan_report' [-Wmissing-prototypes]
  482 | void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
      |      ^~~~~~~~~~~~~~

Fixes: 57b78a62e7f2 ("x86/uaccess, kasan: Fix KASAN vs SMAP")
Signed-off-by: Leon Romanovsky <leonro@mellanox.com>
---
 mm/kasan/common.c | 3 ---
 mm/kasan/kasan.h  | 3 +++
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2906358e42f0..cbb119224330 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -613,9 +613,6 @@ void kasan_free_shadow(const struct vm_struct *vm)
 }
 #endif

-extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
-extern bool report_enabled(void);
-
 bool kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
 {
 	unsigned long flags = user_access_save();
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d428e588c700..02d54a1d0b2d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,6 +153,9 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);

+bool report_enabled(void);
+void __kasan_report(unsigned long addr, size_t size, bool is_write,
+		    unsigned long ip);
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
--
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512063728.17785-3-leon%40kernel.org.
