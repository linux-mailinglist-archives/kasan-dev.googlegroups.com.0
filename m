Return-Path: <kasan-dev+bncBCLI747UVAFRBDF3WONAMGQEOVOJIVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D23260060A
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 06:43:58 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id bx24-20020a17090af49800b0020d9ac4b475sf3864514pjb.4
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Oct 2022 21:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665981836; cv=pass;
        d=google.com; s=arc-20160816;
        b=sxpGgbHCEzhlmLPtH7HYrdG1USzZvzAjRjfUp7GEBSCCSDh0Ejt2ZxSQiMj46twhKo
         kJrtgb/9Eb/jQPUb9zkPp2XICA/zB05wBWB1/YEKKJ+O2hZBN78j5cXn8wAGodHYQBlK
         xijNKPpRVf926cTkWbqaLJUXeTOil6YSjrvCpEK5gHrDZcDDZxepXusckNRubQM1LbXQ
         d9W8oT4jkVyjD5t0CPUKU+lWNaFeDKm0v6EvmNAKT2k46pWV5JcPxx8oE0z8hyGHAawp
         UxcIVGZ1eIpW+rCyZdyMPEOHP19t0fTrue6I+k34qLNoeFI238whFHVYCRBOEgK4j77G
         Oq+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=OUjm78j16X9yMEl1QYLIGGrRyhHkLdj9V5CzkkGthAU=;
        b=XTke5kzaSqcn0mcZg20GBx48trLRCbTrMlFZyPkiEDtNSKH8zOjM0/f8qH9+KkYz5B
         L0QUNjKxV92BZqNVUZwU4kcahQpPBoUdgS4szbvmwWysB40o7E4AESmPWt/pgpPNo1uI
         f8I5XLktgq8kA8Fwm+1ILNWfaoDLDjRd23TakXoQ2lLXmOEOL16LiP2rN6flFi+TyZnH
         +CSGfk8AdPXEncWHK1eenFSrbK/pq9onG7NSetVeHMD48Gq/PJV2DKD3vYfg0kJEhtbx
         Puh7jSxFxdNrJj7re0+0xf5nJ5ZcIjqih01bYNYiOTN0C4mvE1POufozFoCVQfRQkmnB
         JaVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=hHKZuBt1;
       spf=pass (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kNOZ=2S=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OUjm78j16X9yMEl1QYLIGGrRyhHkLdj9V5CzkkGthAU=;
        b=qTAncit2ht1mneLpy3ik2nlXYGfsZacwKydRxm0B278zPDIh38QchJjwJ+WD3y4iFx
         eFP8k/0QO5VEa3rS6n3+kRSDVEyt0T82r4NYfLQgoFF5xnjQ3xmd38f+JYY2zmjDpdf8
         vgwQ5arzw/o97g/SiMQTeJaD7CdDURJ2ZGhLckKIjZ5VxKpFdNHj+56vM1PJGCJWvyXl
         FcLB/3kLHHw7RfXDM090hcSgtl8JhPK6HhthEr0wrjbwmuF3UVlO6YJillkCakJ0zQ9b
         MzLiQ39O8SVLZ7j8SoKuwBcA3qoT5+KtV8xt+ixZ7HDR74E6QHEzIrLwCT4/+xTNJucF
         8x+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OUjm78j16X9yMEl1QYLIGGrRyhHkLdj9V5CzkkGthAU=;
        b=AVuDaIf2qt81r4tyF3spU114HZgrB1mR/6FgXdTC+MGMY43s0FKKvv9gySTwmChgmF
         fNSSKiEv2j9Fehij1zGPllde2JChwcnTLcGppxsNbTbOZc6O1QW4Pn+pgombWyKKjVI1
         KIq4WcdEKf0DnL9XQ1Ok6G2sL1QX4bmfbMEHJVcLK2SunhOr2sHoLl1FoDlmMtuUvfoS
         txqkALpyx8RBa6pk26g9SwyKe8+t96cBVnPonkRJTNijOO5wQCxb3s6fqkCHBvNFhBFT
         ET2ZSQXNY0gEFniwjuSjXVGrjQTwK4Y9e0jiF+YHsGXE0LSLArX4JaeT294KXn2yqKKV
         ACWA==
X-Gm-Message-State: ACrzQf2GIsipe8bp6ZvvpJ9DpZia1DjkmkENlHpLkMPFNQJDZtAD296N
	NT+1HKGrjq+Vi7ku0htuMz0=
X-Google-Smtp-Source: AMsMyM6hMc9V1kmhiqzwuTSS4Qp1AVq5VWji5kJnUCCgnOZdxLvyamW97HtCWV5KpOV7F3ZxR756NA==
X-Received: by 2002:a63:83c7:0:b0:46b:2a7b:a65 with SMTP id h190-20020a6383c7000000b0046b2a7b0a65mr8951429pge.169.1665981836455;
        Sun, 16 Oct 2022 21:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e847:b0:17a:6fa:2290 with SMTP id
 t7-20020a170902e84700b0017a06fa2290ls7532799plg.3.-pod-prod-gmail; Sun, 16
 Oct 2022 21:43:55 -0700 (PDT)
X-Received: by 2002:a17:90b:4b88:b0:20a:cbb0:3c86 with SMTP id lr8-20020a17090b4b8800b0020acbb03c86mr30073058pjb.207.1665981835690;
        Sun, 16 Oct 2022 21:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665981835; cv=none;
        d=google.com; s=arc-20160816;
        b=JYt7e5HOx/l6ZooCw6iiJ5fzB8QYHKB4WsPofdqtVgv06ATVos7mJQ2rG8iHi0a+95
         APZp0J3Fc4waptc8pM4hY1IXhiM7c6YcYsIDG+U68xWQcHdXZg74dDQO7w4MJO/0Wi5G
         jvYkomQs6x9k6mvLtk5VcQuu7xl050LJhqYgKRxIbW/2/FXxsBKZcMYJ3+J0XsslGFoE
         FLQfB/XMK8J1LK8WfYBmMOBZ1J4fvxvTZROLcoIBCi4gbbWqP2R9L57kYo/7LIDg3Ub8
         MuZKxicE6NMJdOQrFTS4n3oNFsMOwgkg4wVM4LdXGHBwy3irJtzecbcDLYh1eQObgn5J
         pXag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5JStNHk0+LrndNMdMSbJEck91l1dLZQIDKk5fDCxAUY=;
        b=gToikAJP1+QMT+I11BuQaea3tdS1IunLMhtl+qxgFeYxD1hpNR2GUT7OHGI+9wldaN
         IHD6vTnvJkI8bwQxlSjuN6nQs91Fs7qrcsLeCcItwT46pj2lXa0T0DnJ26HGqL8mZijK
         +zZKUkjjTzMsp9X48nGFqD2sQ6OO5l9vsULNUXF0afe2Ri7WqVeLD4YBN1aI8ORY738z
         6cSdSsm4AUK2899NjY0UCLoyymsZAYGyg4WMSfIqxTU+qJY+iJGprureIA/rVCICM3mU
         zoHDMK4D11jyTxfaag2PikwlaPnPHsNrILMzeb0KVYwHcGy7WvdXXqkVmIFn039jK5dP
         Bhiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=hHKZuBt1;
       spf=pass (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kNOZ=2S=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2-20020a170903230200b001811a197774si300396plh.8.2022.10.16.21.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 16 Oct 2022 21:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 01B0060F23;
	Mon, 17 Oct 2022 04:43:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C7A3EC433D6;
	Mon, 17 Oct 2022 04:43:53 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 850eec55 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 17 Oct 2022 04:43:52 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
Subject: [PATCH] kcsan: remove rng selftest
Date: Sun, 16 Oct 2022 22:43:45 -0600
Message-Id: <20221017044345.15496-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=hHKZuBt1;       spf=pass
 (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kNOZ=2S=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

The first test of the kcsan selftest appears to test if get_random_u32()
returns two zeros in a row, and requires that it doesn't. This seems
like a bogus critera. Remove it.

Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 kernel/kcsan/selftest.c | 8 --------
 1 file changed, 8 deletions(-)

diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index 00cdf8fa5693..1740ce389e7f 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -22,13 +22,6 @@
 
 #define ITERS_PER_TEST 2000
 
-/* Test requirements. */
-static bool __init test_requires(void)
-{
-	/* random should be initialized for the below tests */
-	return get_random_u32() + get_random_u32() != 0;
-}
-
 /*
  * Test watchpoint encode and decode: check that encoding some access's info,
  * and then subsequent decode preserves the access's info.
@@ -259,7 +252,6 @@ static int __init kcsan_selftest(void)
 			pr_err("selftest: " #do_test " failed");               \
 	} while (0)
 
-	RUN_TEST(test_requires);
 	RUN_TEST(test_encode_decode);
 	RUN_TEST(test_matching_access);
 	RUN_TEST(test_barrier);
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221017044345.15496-1-Jason%40zx2c4.com.
