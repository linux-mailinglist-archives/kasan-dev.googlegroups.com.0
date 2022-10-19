Return-Path: <kasan-dev+bncBC6OLHHDVUOBBHHYX2NAMGQEBPQYZUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id B556C603D23
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 10:58:05 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id u6-20020a05620a430600b006e47fa02576sf14441133qko.22
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 01:58:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666169884; cv=pass;
        d=google.com; s=arc-20160816;
        b=G2nX5mdj0EehEDuVWREAU1TOEyJMYIBEpcUNMqZHqaMxkUNnqWa6VShylenm6f/zgh
         ndS6qT0oaCe0Psm35pW/s/R3kp7QkXqPdSnbJZqnp7vTt7bp1FOe/o3M8kuGbf1aVrq6
         CKBf1LaIBaHk0M0M6xbvKcXDjOfS01T56HQbXf8X03PbnTXh/Qpw/4SAUeFxZ0LpMT2L
         Q2bXNvi4bpUSBoZBAD5C9Bp+DLVvlhN4pAulypn809Uh4h9afvQV3++NhGnRXGvRyO2n
         Z677SjDF73vxVR2CPoniVgq0ivnfFaIen7NPlcJh4CJwpfRi6sy/gjJvAoJH3MdiEf6T
         MNag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=Ej7xlyPICurl/+ily0mq8IJkYljpsQESXZJMPDJTuLs=;
        b=rbkfNFEC2FTX/tTA+UqSy29sy5wA4tKb+JTuZy3jy3jvP0j2Y9fuMasFhQlVvzMS5I
         6djxCn1EZZ/1ucnRDsczOCdbkmmpcqzTJ5sbdr4MDIFHqNFoaFlK/ptcvdRyFhRooI0l
         ewEryuYy+519Bu2r14M7B4VyrYbE9/FARuve1w0uEuaweD7tyOdgrTi3jTIU+Di8BKSr
         VgvXwqjA8uzGMzLE3pLEEueKbgPaPcVAS3qwBA8PriyniCxI6xdfce3jqv9LRsXdaOPH
         XzKl2N2YQDFO+g1Qw663u9PMrrekqG73XTiuZf7rHg+CJp9lEhOKxIETcAa3GmIMWV0b
         kiYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F3mCd7yV;
       spf=pass (google.com: domain of 3g7xpywgkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3G7xPYwgKCfIXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ej7xlyPICurl/+ily0mq8IJkYljpsQESXZJMPDJTuLs=;
        b=rRX/VpezN0Nmg0J5DK/UGvbBlxH47hvSGA6eZMpHFbaybXLy1ym250rhDXr/X/SDoL
         VoUUMcxNCfVAEASA94JC5rhMO9po3BVNGHEQ/S7awvJZShaGWwbKsIdzKjCCNUV+WlY1
         ntrJz7TZNKxZirhuDm3yNWuzBdhQmiMSJWSciJxLwzSF2YVGiX39I3GwrzuIXI3b3FNG
         KgbekXRANvrxKHSfghqxgOa93393u2X8ibwAwp6uPTaL9uXJ8j8jH860vgJnPpbpLhkf
         Pm/XpdsR2dzXnrNmizIc4EiP1h0Wvf3mzn5e7amNbPcKmSOph2W6OHkA/Z0RqRn3x4q+
         b8JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ej7xlyPICurl/+ily0mq8IJkYljpsQESXZJMPDJTuLs=;
        b=7tEAS4lqDn4L8xBJ9qvekxs1WCxhjMd3zGx/pYYojYZPIXTwCv1kU7vAfVxqFOb8FY
         YrNKnYpcgQdnu8pwarnetmW4roEW82uKjLkR8ilRsldgyxTj2bM5BWnQVuY2BaPtD3S9
         raNsLqvWMya27RCmi6t+ZpwDIQq0bxC/+A9oEw/17p+L+nJL+eFtXT0ePYzrWDSit4lI
         cbPvjW5OH2yozibZ/HjfevnITThVzf8oFc+fGfempJhGcDyoFCRFcGAqwtk/qQrgEvgn
         jOL8nkNNPzObCu0ujp27cQKA7qeLNyICL5HWiFdfwwrqGfPt5woDIKA1ZPlqYs1Adzu1
         dDhg==
X-Gm-Message-State: ACrzQf0Aq8IwwrVa4ZT9/ec9FN/VSonr6tDs0n/OcEGo8HpYl69pwwZr
	FonAJPsJmQHRVutZXiofbJ4=
X-Google-Smtp-Source: AMsMyM7f+q777t1o07x6fljpxsEMT9oXGyaukk1ayPdoQHYCebJbjbIcdCkt2JXiZf1UPZSG13d5eg==
X-Received: by 2002:a0c:ac49:0:b0:4b1:ccd5:6bd6 with SMTP id m9-20020a0cac49000000b004b1ccd56bd6mr5838458qvb.130.1666169884307;
        Wed, 19 Oct 2022 01:58:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ab5b:0:b0:4af:8fc8:3851 with SMTP id i27-20020a0cab5b000000b004af8fc83851ls8381185qvb.1.-pod-prod-gmail;
 Wed, 19 Oct 2022 01:58:03 -0700 (PDT)
X-Received: by 2002:a05:6214:2502:b0:4b1:70e4:2653 with SMTP id gf2-20020a056214250200b004b170e42653mr5392258qvb.6.1666169883761;
        Wed, 19 Oct 2022 01:58:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666169883; cv=none;
        d=google.com; s=arc-20160816;
        b=Uld2kXXjSNuMvBfhMACp8RkMTxcG7TpZeg65BV/UWyCrxD3AHQr3N0Bg0bRogvsK31
         wVjEAoQVUUcGUW5Es0aIfKqZyn4JHcyf08COcB5t9C9VzjQrWmXO/Rj2zgqiWIqAFwf8
         EZ/SI3QDHWAtzaOhiliewam7rdqFVnHWMXg0TaOfsXleh4YlK7EH1pfUnnt32o4DCdUB
         wAvSYGssv3QxlRnDkEXkb4qccMBAKdx9GW9E8Dptwso80fSaCClNXZOQ6NKtAskvBOrf
         KBYGN+wq1XwScGB/u4zKg7KoZzV5tSRBK7kWXg8HF3vl1eSgmyY+Lf1mbXyjpGW25l2G
         q1kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=c8o2xpxs+RS4/DEwLn7pAvuoJ6D9DUOeVpcYY5/eGtA=;
        b=EdXAXv2u8Fj6uSM9d9JDOwVeI8wSeYmvnNTaMX4a9jfjxp2Wyy//qNc6eX0jo/DZat
         Xxc8pn7YPmp/6US4yZbaZcsIi0tbZ9u1F/+YTd0XFYwFzEFTv9o5e3HZxb/AyTPttWXD
         vr8A0t8UBRR+8HMzGoQ7nzn977jNhizR3sEAsn9LZ2tuzNzj0JK86n/I0zAZk7zyhrHy
         v0IcRMX4EJIwYAn//PXAsCoAgHuyYRII9H4Js0FR4Lal8EHaT7ifDVOtaiEiyDPmwBbZ
         RfOOijK/uHQZGt2mOt5mv3TSL1LpOQRJLjYAuRPHCLUXmr0ItO9dwO+k9u1orzk9VkpZ
         E7jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F3mCd7yV;
       spf=pass (google.com: domain of 3g7xpywgkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3G7xPYwgKCfIXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id a23-20020a05620a125700b006ec80b54a06si654308qkl.1.2022.10.19.01.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 01:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g7xpywgkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-3606e54636aso164567807b3.16
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 01:58:03 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a0d:db52:0:b0:357:94ca:f32c with SMTP id
 d79-20020a0ddb52000000b0035794caf32cmr5703668ywe.25.1666169883452; Wed, 19
 Oct 2022 01:58:03 -0700 (PDT)
Date: Wed, 19 Oct 2022 16:57:48 +0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
Message-ID: <20221019085747.3810920-1-davidgow@google.com>
Subject: [PATCH] kasan: Enable KUnit integration whenever CONFIG_KUNIT is enabled
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Gow <davidgow@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F3mCd7yV;       spf=pass
 (google.com: domain of 3g7xpywgkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3G7xPYwgKCfIXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
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

Enable the KASAN/KUnit integration even when the KASAN tests are
disabled, as it's useful for testing other things under KASAN.
Essentially, this reverts commit 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT").

To mitigate the performance impact slightly, add a likely() to the check
for a currently running test.

There's more we can do for performance if/when it becomes more of a
problem, such as only enabling the "expect a KASAN failure" support wif
the KASAN tests are enabled, or putting the whole thing behind a "kunit
tests are running" static branch (which I do plan to do eventually).

Fixes: 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT")
Signed-off-by: David Gow <davidgow@google.com>
---

Basically, hiding the KASAN/KUnit integration broke being able to just
pass --kconfig_add CONFIG_KASAN=y to kunit_tool to enable KASAN
integration. We didn't notice this, because usually
CONFIG_KUNIT_ALL_TESTS is enabled, which in turn enables
CONFIG_KASAN_KUNIT_TEST. However, using a separate .kunitconfig might
result in failures being missed.

Take, for example:
./tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y \
	--kunitconfig drivers/gpu/drm/tests

This should run the drm tests with KASAN enabled, but even if there's a
KASAN failure (such as the one fixed by [1]), kunit_tool will report
success.

[1]: https://lore.kernel.org/dri-devel/20221019073239.3779180-1-davidgow@google.com/

---
 mm/kasan/kasan.h  | 2 +-
 mm/kasan/report.c | 4 ++--
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index abbcc1b0eec5..afacef14c7f4 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -261,7 +261,7 @@ struct kasan_stack_ring {
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+#if IS_ENABLED(CONFIG_KUNIT)
 /* Used in KUnit-compatible KASAN tests. */
 struct kunit_kasan_status {
 	bool report_found;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index df3602062bfd..efa063b9d093 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -114,7 +114,7 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
 
 #endif
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+#if IS_ENABLED(CONFIG_KUNIT)
 static void update_kunit_status(bool sync)
 {
 	struct kunit *test;
@@ -122,7 +122,7 @@ static void update_kunit_status(bool sync)
 	struct kunit_kasan_status *status;
 
 	test = current->kunit_test;
-	if (!test)
+	if (likely(!test))
 		return;
 
 	resource = kunit_find_named_resource(test, "kasan_status");
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221019085747.3810920-1-davidgow%40google.com.
