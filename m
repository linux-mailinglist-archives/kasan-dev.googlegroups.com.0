Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZWF2OGAMGQEGCWVFUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 895A745455E
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 12:09:27 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id bq29-20020a056512151d00b003ffce2467adsf1213024lfb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 03:09:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637147367; cv=pass;
        d=google.com; s=arc-20160816;
        b=fSf6sK9j4UrFbhnH9zs7MmAo1YQRIYvxcdKCk9jepH1Jv6FE0MaOT1vvC32/3G6Zih
         rmTbs4/PLvXxJseScFBfHoN5Nb0R0fNwSgjOabCWlFkfKPyfgA417Lj2M+RkaW1Fgavw
         JlXrOC/kz0DZiG9qptb4zdOd7vL0CSX4W1881JIBXgPvLTbfjB7IffM2swLQZhGcb4FE
         Huru3tbHIKf/OP8fKK5jXEBdXMzpl3JgYf8kuWEUzcz5tUi+fxdi106fUV8McBiji7xg
         GdIzf0GzItP8weIzesvg2uA1E82mIo/TVApcNk8HCPaW2upxQekeiWXaErnZN7yqWG2H
         q7UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=XpUaOvIpPpS7yov1QqvnjGdHQ5dssrSeOdXaladgWxA=;
        b=cxSVhkUCW1RM8gj04EeebsjVps557L64dGyZA7hJ4JjNiP3z5Hr5OI7pFptzPXOFmQ
         yCilH9j1EVZFARfzhugaOGo3xfPLhd6Q+3UQBddbuW5mZWDEtKInUilCriKWwSbuRvhC
         RBUWFAo62SuDelvq9AGnGkZ2vmQnINzPPhsQSb43R+SygB0Hf4VlVU/0+L0CUNe1bim0
         /szAgVZ34gjfvVbRkPzUDUZoEj/0Icu+GTaKoVJMyR/0m7oQPjVKD00KAQl+Sx3b45lp
         0BJ9MSzdO4XwRJzLEHgzwPDTowaXr0U06LhkToA069gpeg/chuYdT61e3+CWuURHix/d
         anRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sBRFbICW;
       spf=pass (google.com: domain of 35ekuyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35eKUYQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XpUaOvIpPpS7yov1QqvnjGdHQ5dssrSeOdXaladgWxA=;
        b=dVzF+7h9TC2AkPBWZehHb3iLZqJiTe1e/1QAZxI4YMbXYBHcpOHRb8V/4NI3wbZISn
         oNhIbtbOBTX/QfGeFYRoPwk7gIm/JPJ7iVA/FG4AHjWApcby18HZr/tXkqI8anXD1ijJ
         FAvhpgWDbJlic+hWTdHh/2bbMplpy6vMaa78UVQ1B2Ti8FeUi7XyHaG4S/MOc37ujI8Q
         Hj/3i09pihhesUtvPlY8TIPvn3fhwDmcG041B7DR0/qAw7084rvK75Dla21Fe3hrDrk5
         X5NsTaZslf0dNfC5sP8k3o2mMXTS2SZi9t2zuOnT6NScE6kuaV/JNNfJNVqw4PseFRua
         6N0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XpUaOvIpPpS7yov1QqvnjGdHQ5dssrSeOdXaladgWxA=;
        b=gyw2h8mdm8Sq7b5Lc3+K+YZO/LGIw7q5xHdpYHJpgXggId97V9IUvgod6nnlHo1nEG
         nK7ke4KOp0GDMrPClhPzRpebuTgoWYhCGQIIIenV73HfHSi7La8EVIZ5kWfDQSYl/P/6
         +0LnfU1vE3sfLWGhINxhMczDLl9zVDG8B7tohIPTou40qaTt3mHD1afVloOnq6s7YwV2
         LEjkF96hF6CZePlLYWqcw3rSRNl+7rOQHTXGzFyaXeubM8IK4CN54WeJlO7uxUeitD7S
         KlP4iHmTNjKMKQchcybl6KIck67zWM8LB6l0UswrRj+gbonarwGGRYoGcJunqLpBxTh6
         tgmw==
X-Gm-Message-State: AOAM532iF45+w1SYpcHPY3tCc9ZTHoxb9sqsvUDunXsF0Y8cBmugkFV6
	xo0RIgEslLhnc0y8GHd74OI=
X-Google-Smtp-Source: ABdhPJwr/CRyBbm+ROBChOz8cuNhNFzPDCng0/IVONbYQAI7GV78cwkFa8m7yqXOflb/NzAlnjCaAA==
X-Received: by 2002:a05:651c:113b:: with SMTP id e27mr6780364ljo.474.1637147366984;
        Wed, 17 Nov 2021 03:09:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls219933lfv.1.gmail; Wed, 17
 Nov 2021 03:09:25 -0800 (PST)
X-Received: by 2002:a05:6512:3d1d:: with SMTP id d29mr14678387lfv.685.1637147365858;
        Wed, 17 Nov 2021 03:09:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637147365; cv=none;
        d=google.com; s=arc-20160816;
        b=zn3QdFoOGmp9ZIMbGyoA4Fm4ke+JOcmsNLTKCkNhVBK3/F1RapB0dg8dZkDXU4R583
         Ieubwt2SFPM4wBIpmqKAmX3vvacrjzgUAOSucYThDz/G01q3BH6y1iiWungd1LWbX8O+
         TfOUE8+JrRMDnqucRYpBwrWkTenNz18JPW4Jp1iv1BwuVmqYernjAaeWzTZg7ea9qQJs
         vYQ/XOJRJXMOK3w2s5SwFTxhzXTZDYoxc1xWM6RNYW7qZu7NaWnU6jeTm0StesjIdkZ4
         9NWhcAr6bAIWRGLX+YbAD2iUR+x2Tva2VQeHBZGwEQ/PKf0oMoDBQAZ4FRPG/IfDpdgY
         lbXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=9taf4pcDDL8ZRr8QtehQRp327fUKjZJHKOwSYb8Gk0w=;
        b=tKRzMrpzQa6AkSCxGpcTvDY7p6ZiBbRKeJywC8nTtzz54HJyPdr0U7eLDa87yOoL3N
         3kUOVPCa6qbQN6YWFXkhRk8Pp8fleeq5zLYp2AmrB9Opog/vEVQoxCipogk0n3Tw6Cxo
         WQqjDSvZw8zKbrKugfNFm0s4qIovYeOn+eRPVGszNFjVGeUo9wSIVzbedrZhzJ31DFh3
         91Q7dVYJLvrlxI6aEp5Y91nmS+Y3vMjLb+zMxJVR7/00Ae4IWEkeTgNVwO27ZUhi17QE
         z5SGzUhtrbZfFIvjOz1ok/9Y2CJOF5/AGtyzmgSpJhvKsIpO4u6jLpNM7XmUITXmlZ6u
         MQ5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sBRFbICW;
       spf=pass (google.com: domain of 35ekuyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35eKUYQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id t12si1785278ljh.0.2021.11.17.03.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 03:09:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 35ekuyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id l187-20020a1c25c4000000b0030da46b76daso2667686wml.9
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 03:09:25 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:80aa:59e4:a6a7:e11e])
 (user=elver job=sendgmr) by 2002:a1c:9dc6:: with SMTP id g189mr16624727wme.87.1637147365103;
 Wed, 17 Nov 2021 03:09:25 -0800 (PST)
Date: Wed, 17 Nov 2021 12:09:16 +0100
Message-Id: <20211117110916.97944-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH] kasan: test: add globals left-out-of-bounds test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sBRFbICW;       spf=pass
 (google.com: domain of 35ekuyqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35eKUYQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add a test checking that KASAN generic can also detect out-of-bounds
accesses to the left of globals.

Unfortunately it seems that GCC doesn't catch this (tested GCC 10, 11).
The main difference between GCC's globals redzoning and Clang's is that
GCC relies on using increased alignment to producing padding, where
Clang's redzoning implementation actually adds real data after the
global and doesn't rely on alignment to produce padding. I believe this
is the main reason why GCC can't reliably catch globals out-of-bounds in
this case.

Given this is now a known issue, to avoid failing the whole test suite,
skip this test case with GCC.

Reported-by: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/test_kasan.c | 18 ++++++++++++++++--
 1 file changed, 16 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 67ed689a0b1b..69c32c91420b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
 
 static char global_array[10];
 
-static void kasan_global_oob(struct kunit *test)
+static void kasan_global_oob_right(struct kunit *test)
 {
 	/*
 	 * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOCAL_BOUNDS
@@ -723,6 +723,19 @@ static void kasan_global_oob(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
+static void kasan_global_oob_left(struct kunit *test)
+{
+	char *volatile array = global_array;
+	char *p = array - 3;
+
+	/*
+	 * GCC is known to fail this test, skip it.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_CC_IS_CLANG);
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
 /* Check that ksize() makes the whole object accessible. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
@@ -1160,7 +1173,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
-	KUNIT_CASE(kasan_global_oob),
+	KUNIT_CASE(kasan_global_oob_right),
+	KUNIT_CASE(kasan_global_oob_left),
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211117110916.97944-1-elver%40google.com.
