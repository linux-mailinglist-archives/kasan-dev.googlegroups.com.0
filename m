Return-Path: <kasan-dev+bncBAABBFECYGPAMGQENYDSXDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 69FB467A3FE
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 21:35:33 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id m10-20020a05600c3b0a00b003dafe7451desf9796795wms.4
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 12:35:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674592533; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojM9IvflQTXDwAFQupc5mkR2rmruDmdZLmveg87Jg4HItWIQle7f6oPXlJnwO7UE8P
         Q6tDBaYMOlC6eWZTN/TQ8aGjTcHej4uoqP+pq9AXfZ3NlV3V+jHp1dezrpY2RA9eLgZT
         jksMA0HwQn6DIf21PaTObpx3UX+IgAfoX9bqS8AMdxuzFi3WGaV1mtjLQh+o/qKwOCHv
         pJsx/S4CAAW9lr/nO0BIhuW1PDof+mUipsSs7EA+AEONGWveHeGUa26ahtYredfKpCV1
         bPzXaAbojrqvVOioNX4fkCPuulD0m8Vff8GCOxL1jkWaGPk7dVWZcsTI1jOwAIc1qy7+
         fr5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pEEfmR8qQBNetdBTuBIzRnw/JzRXNMK9F1cU0ZDmLq8=;
        b=C6OZ2VXGC9tVATDYX6s+Pb49SAiJy+MP7r2O8hfUTlG+DbFoMUZl0LCGDT/KoiEmp3
         9dE4TTwri1N9j/h59vUR/fzZwhEwuSoRD47JEEe/YF2eab3jCSeXO44bsGwp4wfHMHOM
         ugbTzNCW/8SuTUnxioo1LBczsjBqSTky5ALRuls1U/TLyqky/BJWh8FQFOp9gW4QWTRO
         ojqJlnFH/grPskw6fw725z7AUfkRkMeY5PI0F82ySnwCD92nhrwvsygFmcwtOJaIWXqy
         SHGZ1RBcknch3Oe2i4MC6pGoEZZAhobrOOhFpfEcC4JeoeG/WM26cTI98FMAhn59FY5A
         nFXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e31nyy9b;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pEEfmR8qQBNetdBTuBIzRnw/JzRXNMK9F1cU0ZDmLq8=;
        b=SN60J2SsI6xGFLphBU3z0Wqf+COpph5VdtcZuZImRCH/r9MydQ6AvrqCWl0dG/myEA
         /Swo7MtY7vRH+ySh/f2UxJHKxUoYbBRzWUDvsiHTJUSEKcYABZ+VfuhQFVdV+8uOWpOM
         QamB0Xs22HXJLjiVOFBzUmceedB0N3TetLnOdx0Ds+bK6JcBdDGj45R16tmpOH1Zo7OV
         YNXCin0kCLLqL+7riO5bbD0voU2/9koF90wbmtud1BnziIIRkmFvqOfhMo0TNYqb7rQn
         K9VaM49dBCog9e0NvAIXzKl5PB88FYlrJk3/guhRWG0jv9hsL0x24ceduHrfm7wnvSkH
         Ey7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pEEfmR8qQBNetdBTuBIzRnw/JzRXNMK9F1cU0ZDmLq8=;
        b=QxFsfMHx7SbmZmN0pejIrqhMXEXraGzXyXfNKrvut/ou58CY0Cby5UDiGr8bAKLihB
         KV6EHdUN2TO8qghblaADQNmm/BHIr0vfQsXAVaqoxcOq3Z3ohLAolhJu1B747TSpfLtl
         4GqSiPdHrFiS8AGQbwbfDaCxkmkakei0JjEBMoERL12Or5Jq1HbxLPDYCvTd5sXD5TSI
         N6l5nOzMhGFAgyxm4lGsO8ZSuVFbLDo5o0CarEyZU0dy3FHCY+6mlW0cDOjwlidfI7j1
         XjkUxYvzWbhA2agqnhKf2GI/oAS1+NOqGzusjXO7bn/9o2ZsxrO9lFhUlXuZJvoaumfB
         8o3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpNC8wZTA91oEVv4Vaisv3ZeDl5MPSC+ekOfKG/4Ggwq0dGn6d4
	wPwAv4HoeLkVdWjW/oFQWJc=
X-Google-Smtp-Source: AMrXdXvDLpLHLqNSpGwhjE+LTkef8vxTZpmA5KM6z0oxDFX2l+XHjhmm2CHBz3AHkiAk8GYX9HLl1w==
X-Received: by 2002:adf:ed01:0:b0:2bd:e721:725a with SMTP id a1-20020adfed01000000b002bde721725amr1404357wro.678.1674592532885;
        Tue, 24 Jan 2023 12:35:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b90:b0:3d1:be63:3b63 with SMTP id
 n16-20020a05600c3b9000b003d1be633b63ls10694350wms.1.-pod-canary-gmail; Tue,
 24 Jan 2023 12:35:32 -0800 (PST)
X-Received: by 2002:a05:600c:a13:b0:3db:1de2:af31 with SMTP id z19-20020a05600c0a1300b003db1de2af31mr21386103wmp.37.1674592532145;
        Tue, 24 Jan 2023 12:35:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674592532; cv=none;
        d=google.com; s=arc-20160816;
        b=hJQWB9w37Sn6FJxTv3Nx/KaEPPiDuqoTeUHQ9f+U3XvlRwP/uwkATLhXy9lhjRaUxd
         ve8C58CklPfn4R1+iAcWf1IReIoujCOqInZ3Sb8Bd8WD3PONjOpgYe1UGadbJ88j2d7h
         DHWZlLMhlA2/DFzNVPExYrtyfoQsxykg7o8cckani1djhxgpx1DJ9B5CfctwsWxQoIRK
         JA/gweyCjPod1dxqA7g/2meVJUXxAdI8+EPITbu/6zPTf8tJ4NGHFLilLhXVihUrpUkI
         SHzTGHGi5SuUU4a+UVkD3Ega/zjl8/j4/+JF4+atQmpEJHAThZpTYd+3xUImR5O/k139
         5rcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=W129RU0688CMkJERFUWutZmKNSTdtW1e5I8TwXB2ZIY=;
        b=J2p8wENETW/MOUHqlb0ik6UQZQwDrmTCyMk11BHFbRpq3dxn3fpU1piM9Tbm+dSstc
         R5ajynRdQxZSNO2XB0Dch1pbL5hp77RpeJusik9ZLtgq+czePak0n6dUS7uFRadZfrce
         sPexR58uHdE3WIqtAxs3OfsFYQNmSfXspA2lANJyOIPOXSQnQiO7pcujpJ2mLNc4BxG7
         4ZeIFfPmqYJtCOPXARQhVNcLSrabhrksZGMVGyMzpJvVw4J0yoSK0ypQSia1BiqTLADX
         dLmj4T4OSx5WLhVtJy6YSKYPP/h6mLfPvcG+3SrqjSPoSXpnKGSw3ROhPaXDFY7g2/TV
         Hvvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e31nyy9b;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id bg16-20020a05600c3c9000b003c4ecff4e2bsi201685wmb.1.2023.01.24.12.35.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jan 2023 12:35:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm] kasan: reset page tags properly with sampling
Date: Tue, 24 Jan 2023 21:35:26 +0100
Message-Id: <24ea20c1b19c2b4b56cf9f5b354915f8dbccfc77.1674592496.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=e31nyy9b;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 mm/page_alloc.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 5514d84cc712..370d4f2c0276 100644
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
 
@@ -2516,14 +2516,14 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		} else {
 			/*
 			 * KASAN decided to exclude this allocation from being
-			 * poisoned due to sampling. Skip poisoning as well.
+			 * unpoisoned due to sampling. Skip poisoning as well.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/24ea20c1b19c2b4b56cf9f5b354915f8dbccfc77.1674592496.git.andreyknvl%40google.com.
