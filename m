Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZUYTDFQMGQEGR4ESWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B6A0BD1786A
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 10:12:07 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-430fd96b2f5sf5376726f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 01:12:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768295527; cv=pass;
        d=google.com; s=arc-20240605;
        b=VETF0MpvhylQzDO5dLsnI/q49+DxsEcdBOID/4b4XfR2y3eMqiGgEAxgncTpc1QB3r
         /mwqJBfCG+VhmzfliWmBcFjg2JFroxH9DkNIX60vnaRhAv5r6g4Q7HDSYu9Reo1imPYm
         ub96jrrGTZtwxzEQmUcmZfBvi7AZGttPzOyH8hqZMxcBhZbLy2GErG0rIXWDJgBLViTP
         MKnmxL/bu2GgAs2hZ4CHUox9deOIHyXdMjojE5lYdC0+AbQSamR4XkSDbZTcq0FLaPR6
         vwkqbPM/dappFG49imztKr4WXtJe3eopjbButmtrg88PHMz9vtKCIx0bkqm+y1VrkL/N
         Q8Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1PwR0LMb1jcq+3vuf6dZACq8KNwld8rwm3Xp6OaANjM=;
        fh=zdSAKCa9C0RsI8DPAx56dSbnRwcxcjuBWC9gCzPH4CY=;
        b=eRA217icXjKZw5UkSHc8T3zH91g0/dK4H6X1dRPE9GaFhaUpok5l6kPk+IwiDknHoV
         K+ieL3GA6Tc8HjskHNQICYNcV7FZ2ul59MOg2MhhAKpdq54nNLUqwQCd+YOfpuHuEk/5
         bIIiIyqSDXxQ7NDqH0odbuA5Bkr6AZUk8Cjog6XzqsLAUk9tGrBi4Z4051tTQ07F6Lkm
         qQkkZDfLtmsB72wnzkTovg8djsipCtRx70dS/mt0Hx6Xx6lgB2uYvUS5duPbjFdTQDiu
         XFeBkzqEu2qqEvQprnOIxf3IEeIALwIzDQm8YRxOTi7O//dCl7va5fymQwu4HP9QPDSf
         7oww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mQQA+oM9;
       spf=pass (google.com: domain of 3zaxmaqykcwclqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ZAxmaQYKCWcLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768295527; x=1768900327; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1PwR0LMb1jcq+3vuf6dZACq8KNwld8rwm3Xp6OaANjM=;
        b=s8bO5L3FwaffuuRl9ks30Eaw8quS7G956ejww5+F+6KV3P6beT+yhd112jqqV5heuM
         5vKlhHZdLUtwFMIYO/82LVKP2NEVdS8+HVHQo9CwDo89Gx8QeYBO5mwV1ODycXoug1n+
         iDgUB30IX6B8Pl/kULkbYbx25NPSzr0rU27HW1bQuU8OLqRut8ZsqO+hpDdjA00GzZ6m
         Z1wXAa/zfme+WcUzdmmNa9KciY/DAGCy7q1ySAkTvJH/Y91JZCp+S/7nKHOPSz9I8Hoq
         zfzxDXQyJq2Sbu0a+phpKg6JAF8uVtw5nbWHht6aRYgkbcidnEjnaJ+sI9tS/sBB1k05
         NIIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768295527; x=1768900327;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1PwR0LMb1jcq+3vuf6dZACq8KNwld8rwm3Xp6OaANjM=;
        b=mcq8JGjHOhS/VfC01gwsEk4WBliLFE5xvJSETIGdxe7f88cgE7+MZ/gHdux1+kokE9
         bbFDFU1TUYg+k6lDo3dD/kXPpqsbfZxnyLjfV8T10a7QCY6GMLIDhN5+CJiQvaHCNFXq
         1L27HXeTuz9PP54Il1bHfTyuAQ9Fc0GYH/r6VAaRjEXEpwCO3H9IO8PUqoqyppPpr9+R
         BhdUnCDCrKYLJ8qIYnIoBTXyBifrqkA1EghH5v6gxHwL1WhNpFDpa+rWyATbWm6nQ+jS
         TToxvD5999U5jmTQvOIUKnmKse/jSEU72s4W7u65jlo/zqxy5teeayX4HKBbvwpG8bYm
         rNRA==
X-Forwarded-Encrypted: i=2; AJvYcCVTLk/CAQKJcjw1+kPQ3mkybWbO5I/WTmwO38Rgmr0+nsHbgvniC+VnrRBzErNrYFOlk4qo3g==@lfdr.de
X-Gm-Message-State: AOJu0Yxlic7Dlv8McLq5vbjWdBqW4H0foWuQEkO5/bqC3CljzGu3WRi3
	HzKJLjldUsS0IV/5yqToto2C5PFdXy98djZe7j7i3EL3yZsIFYz4lEcC
X-Google-Smtp-Source: AGHT+IE9MiFGt/1ijerm4B31xCox12d12EfYubMqYLk+UrdmzdGOm/JjZzSi3jqL4rGC79CrWkv6aw==
X-Received: by 2002:a5d:5850:0:b0:430:fcda:452d with SMTP id ffacd0b85a97d-432c3790c68mr25471063f8f.22.1768295526970;
        Tue, 13 Jan 2026 01:12:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GxH3OYdUYa0iz1uOAF+zhEJZf/McddGEgf8A0geVtx9Q=="
Received: by 2002:a05:6000:220e:b0:432:84f4:e9cd with SMTP id
 ffacd0b85a97d-432bc9185a3ls4750561f8f.1.-pod-prod-07-eu; Tue, 13 Jan 2026
 01:12:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeD3+VSTfEHyJfjkRcVgpluAPPspYIX5Xfam2x3b0NnEZvV2MB0Pnz2sOYWGzEN9cuSMAeDNe9eHY=@googlegroups.com
X-Received: by 2002:a05:6000:a91:b0:432:da3b:5949 with SMTP id ffacd0b85a97d-432da3b5d11mr11922562f8f.21.1768295524806;
        Tue, 13 Jan 2026 01:12:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768295524; cv=none;
        d=google.com; s=arc-20240605;
        b=i5TkWDXyn4O9uWgVLv6RlfyzPXBCJA91g2g0xbpUGZ2ogNAjKQBSCKndBD+CeL+PI8
         UCeG7tNP1QIFuHNfnztISKzjK7N60ReRbrRvnBpeLlr9xdA3Ck2E2vN5ulq+zQIeU8g+
         I564/UzpkzVS/QTxMBfmQICp4hbaKN1mtdEdS3KmvJ7z0HzA+OJAxI7ASSgFBEM0yg1n
         r8/gKhAcbzUSniy+HHp1wh4WepNC8DDA6kUf15ienxHPSX+IejTjJpjE5MfVtNrRX8WE
         EMf/P6PAqZA51mh32XX/DlNBbhbzAVfNDpjVca2KNOr/kDAOvyNp6036u2G1F7sjDrcb
         IE+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QoyuWfM/l4vhVN1gT6WNx7tPdfw0LF0dPn1W/6MnGsg=;
        fh=bKXM2+JAPaXuIBqbjcTsv6sY30pRNPH6eqpEcBrndE8=;
        b=b+nC24bL5Sy1MxStnKKAWjhzey3s6BgH0YLfqgi9S7b3eQEiGstFt2FNaBsHteW7bu
         /FutGEGXAWDGRIy7uyhugQcz0lVeWilBTPP+w8JYHlIkjRgWwJuH7R2TKakVRrUTHbu/
         UGLQDT/uC6EwXaONkeB1Bs6pfKJERiwxYS4XxQqZF3cZqxqKr4QRX4L0rFViyzgQZofq
         1ZEfhZ3RDXhditGX2yv0UXlk5Nej2YFSlHqiXOtU8wjKf3qvJc2xNGFOn6X5QiFYxoXe
         f7raZGp97eThH6DjiPMWzKzWPG+pOrVNwog8sd6ABP3QB4vYCYpYYDz9zBl0Nwj8hyco
         YHrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mQQA+oM9;
       spf=pass (google.com: domain of 3zaxmaqykcwclqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ZAxmaQYKCWcLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be35a0f7si348134f8f.4.2026.01.13.01.12.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 01:12:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zaxmaqykcwclqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477c49f273fso74851805e9.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 01:12:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWYNhYrd33HDbyqSeoahFtUH+7TWyF/orjPiVaBTEH9/y4Z5nlN9Va8vJFv0oHRDfHhbG7qgSAx3OM=@googlegroups.com
X-Received: from wma11.prod.google.com ([2002:a05:600c:890b:b0:477:a4d4:607a])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4f87:b0:475:da1a:5418
 with SMTP id 5b1f17b1804b1-47d84b0a9a4mr228119995e9.1.1768295524305; Tue, 13
 Jan 2026 01:12:04 -0800 (PST)
Date: Tue, 13 Jan 2026 10:11:51 +0100
In-Reply-To: <20260113091151.4035013-1-glider@google.com>
Mime-Version: 1.0
References: <20260113091151.4035013-1-glider@google.com>
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260113091151.4035013-2-glider@google.com>
Subject: [PATCH v2 2/2] mm: kmsan: add test_uninit_page
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, ryan.roberts@arm.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mQQA+oM9;       spf=pass
 (google.com: domain of 3zaxmaqykcwclqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ZAxmaQYKCWcLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Test that pages allocated with alloc_page() are uninitialized
by default.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 15 +++++++++++++++
 1 file changed, 15 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index ba44bf2072bbe..81e642db6e239 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -378,6 +378,20 @@ static void test_uaf(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+static void test_uninit_page(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE(expect);
+	struct page *page;
+	int *ptr;
+
+	kunit_info(test, "uninitialized page allocation (UMR report)\n");
+	page = alloc_pages(GFP_KERNEL, 0);
+	ptr = page_address(page);
+	USE(*ptr);
+	__free_pages(page, 0);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static volatile char *test_uaf_pages_helper(int order, int offset)
 {
 	struct page *page;
@@ -727,6 +741,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmsan_check_memory),
 	KUNIT_CASE(test_init_kmsan_vmap_vunmap),
 	KUNIT_CASE(test_init_vmalloc),
+	KUNIT_CASE(test_uninit_page),
 	KUNIT_CASE(test_uaf),
 	KUNIT_CASE(test_uaf_pages),
 	KUNIT_CASE(test_uaf_high_order_pages),
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113091151.4035013-2-glider%40google.com.
