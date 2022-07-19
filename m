Return-Path: <kasan-dev+bncBAABB4XN26LAMGQE67ZZRAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D92B578EDD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:12:34 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id m10-20020a7bcb8a000000b003a2d979099csf4852862wmi.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189554; cv=pass;
        d=google.com; s=arc-20160816;
        b=j3KXHGLUFIk4UdNbB5UMQgybhSTG8Yt6R79paSrJcbLnLVHBAU7RFdu6JbLAN/c4Or
         T6C9uBWqAC7QLZzHCMyCgXq18x7UzjHdz4kraVEKUUikqvgM/gO2RQSOIeHH3LBCOwI3
         djttgl/mOAGGbOh/U1a6E583T0Xv5Ljv29oE+Rmky0aQUh3qBYraQtVe1eSIXxSYViGz
         RUX+r9KoEMLdW7w4ftW67fqhXb99ZVdV1wIJPGLNfikawPh6GNdH2imIJp4l8MKDV6dp
         tI3dO8WF8kXmYTlM/Qjif1Y5lbRTsziT2PMWjjwEV3jMqI7H4idmXKOcJ0KkeH+9ry1Y
         FnSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pgqiajfVcaguG4htG/NLSDnuvw7KF6t8Ln7dpP2vLnQ=;
        b=HFtjy6fJeSEn4IjF65CsGLQvEttF1Y+iDNH4VWgoLruKxmQScFBDJ9x+0L0/ECZyqO
         atuF7TU/tlgZjJXLDJe7zRtSGp7N3CSt6oHEqMg4eCgKjPQCQ0vePCvwmiKGpwy02jcn
         VcVqyt7NF+qYi8I7NhG1Tn3vxbrfDkfirhkbAPV1D2qANtjtK+JrtPgHuLl1dLoV2lBk
         3LP4c41MCeF7HA4JvoJqjkY0c6YTH52wfhsYugUqNcgUPe2J+VPAV7Yd/K9XfU9thZb+
         lkYenVbiEHFnOVmj8cqi27pwB7cYqli5zYvOu+xqpLjLdrMUBYXYO3eR6D6RaKl/Lakd
         FtGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LQyieyg1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pgqiajfVcaguG4htG/NLSDnuvw7KF6t8Ln7dpP2vLnQ=;
        b=kWjME7EQO0pdM0Pu3nAfDuxAZyeH2eHDdxQj5ojnfQ1DkFs6WanF2Y4+gtTtU5kO36
         8++H5USieAwt5t3YPO2RXSBDdmgdJmAjAve9dVmtPdjB4cz+ye/fKjRgfa+nRtHzB+cJ
         1F9VcdEr91hEamPSAHKX09IB/9jSrslJU7m9x35FNoJzDc9DhJquHekaGu8WQatFSe1t
         1j3FL/ANqxK4f8UjWdHBRreQ2yrWjTlflu9yV3eWSzvn/2EqxnBLlbkFlb8dGxQN+kS2
         aVdumYLlDTp5Lw/YLWMwD3g1sP0p51TcZ688AoiZFPUfWUXuTDga9C4SrXqlgJW0MVIS
         aF3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pgqiajfVcaguG4htG/NLSDnuvw7KF6t8Ln7dpP2vLnQ=;
        b=H9Kb71B1WZ6JAp10bUyjC9L2JmwpEuvsJ2R5fA86lQ1Qe6zluhOCO24oyW2e8oqYog
         CMvZ9JS422lvqUZ0mIuzOlOphnx1x22SpES1b7/P2HzqJ/Q/RA2N5zE/H1ULC21asGYb
         3MtDPEwywCvZab5sxaBAmEUhGupdhiP6lZLTLX6EOSq6+Gn8/o2kRd57n7XlxJhKvYSO
         6uBP1tDQ9ORvxeYVFtLMmyWusxZLEiLZy4JHHZ8utQPFtsiCFue2ppB1Ytmaahb7SRg4
         IPMNqdh0WbiLsJJN7idoI3Du5ZQratvcmCKiEN7958ltD6wQzVXdXL957oktajQi2LJY
         wrgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9jGI8PNMTdcKm5fEIJwr9R2luLCGKpT5m2YMhUZSdW5p6podbZ
	7FSH/2QorPl/n2X0Xc1HdWs=
X-Google-Smtp-Source: AGRyM1sJTRb2p91N0x+AKdHnK0dbA89x6rxkKVeJbAwGdLtvKez3oLkH9E0/kNvwO03pxayLp+l9kw==
X-Received: by 2002:a05:6000:1ac5:b0:21d:beaf:c2c3 with SMTP id i5-20020a0560001ac500b0021dbeafc2c3mr22972809wry.609.1658189554311;
        Mon, 18 Jul 2022 17:12:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:284a:b0:3a3:7eb:364e with SMTP id
 r10-20020a05600c284a00b003a307eb364els41410wmb.0.-pod-prod-gmail; Mon, 18 Jul
 2022 17:12:33 -0700 (PDT)
X-Received: by 2002:a05:600c:3d0e:b0:3a1:8cf3:3f1c with SMTP id bh14-20020a05600c3d0e00b003a18cf33f1cmr28640137wmb.0.1658189553761;
        Mon, 18 Jul 2022 17:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189553; cv=none;
        d=google.com; s=arc-20160816;
        b=aTQJnS4mynwJ+MxENYZ08iJ+PZLw46PsgVOZR6vg5bOqX9BsW15K+yQdCd/CARfH5E
         cT8QxmXGUnLLvWhR2WCUkvBBILsOI/NXI9OgUAE5q0lipiudj5/nbBDcL956JaUl+YSK
         XOMH02ijws9xRzyApMtlAw5rarfnraZzb6JKZPXLK0Mghkxxk2WaqgJ3zg2euM8ltNfi
         QA+0Yi1IOAScmFuVyLT3/H+DvfLb0Yk+BAUre/JfWomQrfT6O877viU70KlERMpSe69V
         aAnrh8rIo2e/LAvBQmOAwYBxRP6yMeW8WdogrsNzGHwLE/aUqTpiTeX3Uo/cNMJiVeun
         Jlcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4Ug+nRhk4S0scNxkqaQhWMyfD8pnsHKB57f6laJzIdM=;
        b=HRXQJK9hwbAdNSleICDtwqsbLsxqtE87pRJ2asjGJNXOxQe0GyZwfmZKP+TTZIHvXj
         nNBV97U2Xi7H2/UQrMBMjaOd2DdwGsJBLd+Apmb9svMY62wVGC4LfQ0PxB9jZsOTc1Pt
         cgt9+CkTzjpN5DfKuukaLrp3ocmBbGgQHWggU8yEr2woXNLGcZ1CgmJQHR+cXaglDT8t
         DaB2zqCDmiNxETGOlCFa7WZhhZi1rDZ8fIiGFdfVyq4dUicafqLdh7lSTJRGRa/6RwsP
         +6LkaQk9QDeK0p5PsjFEYGgeCc6BSxBO+GhcnIPjIdyKjjKKTuU/c54WByG3yvpMlD3I
         R5uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LQyieyg1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id u3-20020a056000038300b0021d9c42c7f4si300709wrf.2.2022.07.18.17.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 17/33] kasan: only define metadata structs for Generic mode
Date: Tue, 19 Jul 2022 02:09:57 +0200
Message-Id: <93569dbf8c3615ae49e62e7be1607b6fea406ae9.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LQyieyg1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Hide the definitions of kasan_alloc_meta and kasan_free_meta under
an ifdef CONFIG_KASAN_GENERIC check, as these structures are now only
used when the Generic mode is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 6da35370ba37..cae60e4d8842 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -193,14 +193,12 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
+#ifdef CONFIG_KASAN_GENERIC
+
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
-	/* Generic mode stores free track in kasan_free_meta. */
-#ifdef CONFIG_KASAN_GENERIC
+	/* Free track is stored in kasan_free_meta. */
 	depot_stack_handle_t aux_stack[2];
-#else
-	struct kasan_track free_track;
-#endif
 };
 
 struct qlist_node {
@@ -219,12 +217,12 @@ struct qlist_node {
  * After that, slab allocator stores the freelist pointer in the object.
  */
 struct kasan_free_meta {
-#ifdef CONFIG_KASAN_GENERIC
 	struct qlist_node quarantine_link;
 	struct kasan_track free_track;
-#endif
 };
 
+#endif /* CONFIG_KASAN_GENERIC */
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 /* Used in KUnit-compatible KASAN tests. */
 struct kunit_kasan_status {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93569dbf8c3615ae49e62e7be1607b6fea406ae9.1658189199.git.andreyknvl%40google.com.
