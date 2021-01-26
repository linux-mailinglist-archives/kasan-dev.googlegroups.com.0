Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBNYYCAAMGQETTF2FTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 11685303EF2
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:41:26 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id r204sf6881781oia.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:41:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668485; cv=pass;
        d=google.com; s=arc-20160816;
        b=GYe3g9bJmLmIUQbnrZ0ROvbiXjRePHEK8AGzIJVWsrp4Ps885545yqtfzy8ZWF5Psr
         adO5EmhyJkZzI9Z2045YCxEOXFhDxYzxAVOjVr9vY5VVbm97yhRQUnjqEcwKHRrM/cxn
         3u9cc9G2LXYw+JxnrmjbeGwk7HwtBc+Mnm5+79hDpQhFkC/UGFRHWHuYHgag2YftgDoD
         pg0pjhiHatY1x/0uQznF3PfVJE5Akdu0xpSsywLGpkbv0LEQquZH6IMGUizhb9vTQFU3
         HdfHnWqESG/UqFarXZYeVlRIxnh9MSlQLFl1T+OrMjBIWy+A45CKltwz18lWGavoKQKX
         EZYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/vhdCvKCYSZUZYB2VMiU7NSXoPK5u6cUhwELmfw4kL4=;
        b=T4R7IcGttGFCcFbmS3eRK9gj3Px3GzBvjUC+xqGcjwbfNj+pCwsbge0m4TZ4ENTOGq
         vuRvmxAk+JpcrYObEB4s+EH1WB7Kae8TNzw50dMAYZgdw15+xtUz/9BdBGnJg4q2ir0h
         44+KW/C7rfdlrdFqX4JQ2U2TeDHkxlFan0OFS67KnopXU33UTvOrJ35zb1kf2aHCxjSg
         RpL92qU8BN6NOc0lYq18EBfGCRAfY8JE0F3sBAbaybHzt2eHRh89zfok0naHPPCN1JKW
         O/NnOVMWtv4xUHSrTHnbO1RlsiE7qW081PzxZuWvlKIeauWpnLjKmV2mrJq0+ggXAqE5
         WyNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/vhdCvKCYSZUZYB2VMiU7NSXoPK5u6cUhwELmfw4kL4=;
        b=GM47+1DeMM+6bBAPzQjaORyUzcuREHkwKuvu5DwOtXItbcqjL8++zmVjjkmdkAOVtL
         dmW1Y6+eGE/ABIk6BqQmixdFPlTqy3gle8V9wPMSgNC+wB7cLounPaVdoA/F5bPxBfQ6
         zBRS8nwz848QXc+eVkOgYoeiXK8AcD/bmKPa0skQH8a6N/bC1x5H1e90ORxZGenxDat9
         vd68v9h9yE9s9ngjDk/1puQcz8MVtEU1BtS1TQCqwj/vbBaIaMbp9p0YPxxuISdxGyUY
         7Ekf2d9he61mzx6tZROQp9jCNcqf2wP+XT2PyZX5tlm1L3pBDmuI5EK83vVdlaE12N+b
         xxVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/vhdCvKCYSZUZYB2VMiU7NSXoPK5u6cUhwELmfw4kL4=;
        b=Enf2aIKCbusE0h32Gtn8UPXe07T86Ql0lI1UnyTfmAkl2qAlBhlQ4wvytZlkvEhlyp
         vfqWk+zFejnmSpfNe8W2ifEW0YdqiU6eCad4iVQA/yMOiulbK59NizUm5FqFcE1Blltz
         tzQdfGOmLQHajB/LssuFcCf7EN1PACiO3Rx6qlkI+oOHA2SJ2SsqPkB7lsub+yl2syEO
         cN8BVGEhfH3NH/3QRMn8smTPzCuIVNCxUbYvKwaI+NfBQZj6oW4Zp9PDdcovtQNHcTQs
         yltVu/P81Pf+hh96nlDXXRKe4E9H1Tr/Ue/74FYOraImMYbcGABt4+Ji+7fzXA1wLjha
         Wipw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hcpEtu8TYyFZGm5j+TvJocGbj1/WpOxLZ5p4VO5kRbwK7t1Lk
	fa7AzHfYFlgpNF8eNbcc9z8=
X-Google-Smtp-Source: ABdhPJwdqvOrqO18+s8+q+H1f+Wvy3SYC8kn3f9++CmIUZhRyLdfkqKxBQF2P8LIBDvb35Ysso31CA==
X-Received: by 2002:a05:6830:15cc:: with SMTP id j12mr3982267otr.145.1611668485043;
        Tue, 26 Jan 2021 05:41:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1391:: with SMTP id d17ls3487270otq.2.gmail; Tue,
 26 Jan 2021 05:41:24 -0800 (PST)
X-Received: by 2002:a9d:6c13:: with SMTP id f19mr3920036otq.237.1611668484729;
        Tue, 26 Jan 2021 05:41:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668484; cv=none;
        d=google.com; s=arc-20160816;
        b=QP+/wTxaVdjF4AcXF71TC9dOssmFMzIc2LWiioBKe1SJ6uJFgw8tUFlycJren9aK+s
         629SVjxKifskdFQ/BFiOW9pUC0w3hARXlKzefEFYqvipWq6b/nLuk3sVdCPz6J5lx20X
         jvqggzu5Jg45WUNmdpfjgl3LqU+fTo9Z6WXgwkoyoDO3vKrvndPTnPjaWDa1CDvMLY0n
         1k5KAr3zrVF36Srn4mJrQTZlBhTzg87W7pHWMQ0ZdznvvcfOJ8lShpLtX0knO7DpJ2q1
         R3VH9rUtz+GApDEthmkpv9blazi6npMAkdKsyrH5qcKFrNAi7Q15WE19u1mLmhbQBHIT
         ADcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=wUCvWmDBvCvKbDuk3s/FniHdNoweLX8aCqSfbzJCwik=;
        b=IcVUAi1kx6P1kb6+SxHxc7E76DkjrU1ImfLpMzePzi4m8ijqUZpwdUPTEhVQAVb+PX
         C8mQ98kVRFVJ8V3qHK/o/j8txwLIN9+qAGYi10QGe401oxVrHKWISfhrqiDXPIQVrIuc
         sAWMND/ZLz0KH5RsT/pIevHb9m2hrbJFQxHrd12PcrYZniQ2fTNsSKDo+hLg1M6cHIIy
         AU3JUmSGOxx4IWp6504qErAHN+sZigA7qjoOJB3YiNKUh4G2zPCEG04BK9okpOk1cuSW
         pb+aJInQaPfitz1/w0mIowVQZnyytavWLBq56rxEB6bAoZVb4QktKJo8js+6QLwaF2j7
         kTvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r13si1037785otd.3.2021.01.26.05.41.24
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:41:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 623C831B;
	Tue, 26 Jan 2021 05:41:24 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 45C933F68F;
	Tue, 26 Jan 2021 05:41:23 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	stable@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>
Subject: [PATCH] arm64: Fix kernel address detection of __is_lm_address()
Date: Tue, 26 Jan 2021 13:40:56 +0000
Message-Id: <20210126134056.45747-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Currently, the __is_lm_address() check just masks out the top 12 bits
of the address, but if they are 0, it still yields a true result.
This has as a side effect that virt_addr_valid() returns true even for
invalid virtual addresses (e.g. 0x0).

Fix the detection checking that it's actually a kernel address starting
at PAGE_OFFSET.

Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
Cc: <stable@vger.kernel.org> # 5.4.x
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..99d7e1494aaa 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -247,9 +247,11 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 
 
 /*
- * The linear kernel range starts at the bottom of the virtual address space.
+ * Check whether an arbitrary address is within the linear map, which
+ * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
+ * kernel's TTBR1 address range.
  */
-#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
+#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
 
 #define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
 #define __kimg_to_phys(addr)	((addr) - kimage_voffset)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134056.45747-1-vincenzo.frascino%40arm.com.
