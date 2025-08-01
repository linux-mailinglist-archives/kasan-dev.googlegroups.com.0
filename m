Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBY6ZWLCAMGQEQZLNDQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id AC8DBB18170
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 14:02:45 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-306ca683dcesf2092717fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 05:02:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754049764; cv=pass;
        d=google.com; s=arc-20240605;
        b=FAHQbD1jqZ5Zv7SDP0YxyNubnSPKwmFpmcQh+n/eKraHPEzwEYGxc1vVSUI2C6JNOc
         Q7U8DEhcLiXcRVOdqucxE/MmhMQTGcEU3ngatRdqA1gQCIerXYOoghDf+J3AXNWcE72a
         d5n6vB3QkFKouvFO8DQeaJJaGNw9nfHtNC3asLZnR5CrSzEVPEgo65XEKZoUf12CGtQD
         qdmrTJph/3c4ik1xNW8Cc+iJgV7IQioF9N2b2KeLUohAwBxNkO9cuXCROLPH8LVAPRh/
         +a03tm9AfeFZlSu02UEoyVNwtTpK9x2STZkYNHnN+BeXW8zD7hpboki7vZxECVlj3Ax7
         nUbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=41qz8792T7UJBhvCVgbV6ahKyRe6NrxON5Ko4e9ArNY=;
        fh=911OqIi+58Ep42u/kGzTXvg4b7mYqpMekkI1lenG7GM=;
        b=FD31G7enhViWq4AvysUQdn4q5o5+wvVIq4pVNkljSidFp6VGO1Bs/dcvqgqX6ws2b2
         rDHFidA9uDXRs0qZNbOw6mvVeKh/xg3RzC9T3acx0JdTwhrePY97bPFFz6BQZ9PIWdTx
         +9WcspWdN+z42MTsb80b9TyMgaFKGuwd3rm1O6NAwTHyg3VCpYN7O89E/4qvfPXkCxtO
         lnyFdyvl20LkqvCgi58QWBirMjT5TLZofjiDPjEXnsbFP4SliJwR9Zlhnnkxi6Razuoz
         XZ8jPDGCHQ/FG33lDUF+gvTQSfXTuiXNQGS0sSNVAKSqCqLc4KjR+R31pDvw91Po5lY+
         iSRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754049764; x=1754654564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=41qz8792T7UJBhvCVgbV6ahKyRe6NrxON5Ko4e9ArNY=;
        b=MbVCNKWpoJOQ4lhzKIosO7UrUTmZL4xf05a++p8aMAlClOEqRPHAEoB9kpRyc2b7/2
         RXZCbpIJDj8JNkNmeMXT4VOTfNxxr/2ChYvxdDAC8xR0Eq2CioWHEv17ANJlINXjuNoN
         PISitEHb1s7My04QqiJ9G7epsdrc8MtwF6CtOHl8d+dgfLGaVhnPRax2jiSMErUAorrj
         5eNw1G/JD9Af+VWcy+ApcOKp6NSosSFIlmYuu3DFHwXclLDksQRYpCFmqRcqsv0QEAj0
         P58ic/JXZmpmiZ6bDL31xsNdvefeNmvPJEiSkUw99L2QYSKRae2lltQxrGjqS9zQzBBs
         KBOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754049764; x=1754654564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=41qz8792T7UJBhvCVgbV6ahKyRe6NrxON5Ko4e9ArNY=;
        b=p4Ci+2WHpYxHxJueUdNvYP/vm0z4hsmutjZjwjAZXFUruA/GK5X1oXaVnrFtjteMtQ
         GxKnd3RycEntZdjpXHt/PGOgtMdfBdCYOeMMstybLmLhg98fSTLW9g9f6f7NqhAKnLKG
         OYn3hipd19A1/ivylJyJbscleTeCyFgxUAVVHE6Zr1QSNxbClG5YGtitkrivewckstbn
         eGAiP8bu+i27qP650Sg8B2YYgm6y3O62PkIszyav5O6yXmvavYq/Zm75iayoL5O/2PzS
         1JX9ZJw+YhDibCODKkP6bQOvXtB0ufh8bqHSn7btU/ZD6s1C98pTr23VEXc2A4pdRxwS
         jkhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcP20E1vhBDZnUQU4Xm5tZNLGg8ZZyUVzNKDwrcB40i0zZaWhbaYSVQsn39Rzce7fYW4aWfA==@lfdr.de
X-Gm-Message-State: AOJu0YyUYN7uf32d5iV6BGUxs7vErJBtqMO6RxeTSOBXemMPSJsL5FDC
	G6aFVAL4o2EyCe45+dHeJrR+1dFHNi3TPexsK7RKiHbi0DnhzXEe29JW
X-Google-Smtp-Source: AGHT+IFzyqqtuptgkafq5o15ZAw47Ur+MrUUy8LzWB40H7WdQT9kHiLc1Was1Bs0tpMDhElYqhQQpw==
X-Received: by 2002:a05:6871:878d:b0:2b7:d3d2:ba53 with SMTP id 586e51a60fabf-30785a2b023mr6889929fac.12.1754049763818;
        Fri, 01 Aug 2025 05:02:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcxPJMd3AUIFFacReOtJDvo0XbDfWW1ZCmigwNZGk26lw==
Received: by 2002:a05:6870:4015:b0:2c2:2ed7:fb78 with SMTP id
 586e51a60fabf-307a711ed6bls727431fac.0.-pod-prod-01-us; Fri, 01 Aug 2025
 05:02:41 -0700 (PDT)
X-Received: by 2002:a05:6870:3c19:b0:2ff:a802:6885 with SMTP id 586e51a60fabf-30785a2abd6mr6830274fac.11.1754049760632;
        Fri, 01 Aug 2025 05:02:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754049760; cv=none;
        d=google.com; s=arc-20240605;
        b=VXZ6q2kD7IPTXzsZawsr6Gc1Wg2vqzvenR4/2sXn168TblW3l6Er3ocN7GiZAsbVnE
         RwXR/Q2NNkzSdyCvsXp9BH+CrVKA3l9QjzSKz0NqESfelHc38xOb2zbXGlXaTFLFeNZ8
         V/2ZnjEGPEUqPq5FqfpRJqw0uQqFniqBmcCzEniimoYz6eMUH1M+9KA5+2T7ynd5uV7+
         TZhv46tTeiGe5gII/aaTFRcPW4Wsq83IE2mlYz+ld4F2iLvx+A946LGkHHadExRd9qAr
         sG4Ph1EUItplm8KX/2aV11jK6xo+/79F0vFMUV3WIoGVJqnZW++f/bhtvBypC8rPZbKM
         AJLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=tIgHmUWD8+nFQPu2B5WM+mFSv+KskxpOdza9tHpomR0=;
        fh=3LwrvSBe3PJwQU1VQ/HIl6WQZkyfdcGJHLCyC1aCtrk=;
        b=WXHjMA+VsJ+bbztZTRHfWqwJuGTr3TbakarEeit+4O6NG1j+qB2OawM2DAxNqGgowq
         m4Eur7kELko8Zlk0PuF+kJRJuup0XYOnRYS7p6R8/UHLd1sFX75HC5g4hlYcBpJOB0/r
         MEDXFoSeioWQQVZ2voWi6p6T1yQcXTmfJyrDd81fHEgyCBFJjy9mZblWQ5S5u7aTz/k7
         Ok2lN/4/OfecpLEGoxVZQWD6Dm776ssyR50RD+dWSiFhZEts/nr/QeJ1tUunsNzagyhm
         WnB4WNy8BPEfcPo5cFtGh9cVSKbNfNnsDqD94u2Q8Bgv10byfa/g0UBeZa9IRO6KRwYC
         1UIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-307a6bcecc2si180890fac.2.2025.08.01.05.02.40
        for <kasan-dev@googlegroups.com>;
        Fri, 01 Aug 2025 05:02:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E5FAB1516;
	Fri,  1 Aug 2025 05:02:31 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 4CEF43F673;
	Fri,  1 Aug 2025 05:02:38 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: thomas.weissschuh@linutronix.de,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v3] kunit: kasan_test: disable fortify string checker on kasan_strings() test
Date: Fri,  1 Aug 2025 13:02:36 +0100
Message-Id: <20250801120236.2962642-1-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
FORTIFY_SOURCE") the kernel is panicing in kasan_string().

This is due to the `src` and `ptr` not being hidden from the optimizer
which would disable the runtime fortify string checker.

Call trace:
  __fortify_panic+0x10/0x20 (P)
  kasan_strings+0x980/0x9b0
  kunit_try_run_case+0x68/0x190
  kunit_generic_run_threadfn_adapter+0x34/0x68
  kthread+0x1c4/0x228
  ret_from_fork+0x10/0x20
 Code: d503233f a9bf7bfd 910003fd 9424b243 (d4210000)
 ---[ end trace 0000000000000000 ]---
 note: kunit_try_catch[128] exited with irqs disabled
 note: kunit_try_catch[128] exited with preempt_count 1
     # kasan_strings: try faulted: last
** replaying previous printk message **
     # kasan_strings: try faulted: last line seen mm/kasan/kasan_test_c.c:1600
     # kasan_strings: internal error occurred preventing test case from running: -4

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
Patch History
=============
from v2 to v3:
  - rewrite commit message.
  - Using OPTIMIZER_HIDE_VAR() instead of __NO_FORTIFY
  - https://lore.kernel.org/all/20250801092805.2602490-1-yeoreum.yun@arm.com/

from v1 to v2:
  - Using __NO_FORTIFY instead of skipping kasan_strings() when
    CONFIG_FORTIFY_SOURCE is enabled.
  - https://lore.kernel.org/all/aIs4rwZ1o53iTuP%2F@e129823.arm.com/
---
 mm/kasan/kasan_test_c.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..a1a0e60645da 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1578,9 +1578,11 @@ static void kasan_strings(struct kunit *test)

 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	OPTIMIZER_HIDE_VAR(ptr);

 	src = kmalloc(KASAN_GRANULE_SIZE, GFP_KERNEL | __GFP_ZERO);
 	strscpy(src, "f0cacc1a0000000", KASAN_GRANULE_SIZE);
+	OPTIMIZER_HIDE_VAR(src);

 	/*
 	 * Make sure that strscpy() does not trigger KASAN if it overreads into
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250801120236.2962642-1-yeoreum.yun%40arm.com.
