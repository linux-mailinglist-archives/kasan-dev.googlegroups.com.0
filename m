Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBK6Y7OJAMGQE72MFERQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 325A3507608
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Apr 2022 19:06:52 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id dk2-20020a0564021d8200b0041d789d18bcsf11363105edb.21
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Apr 2022 10:06:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650388012; cv=pass;
        d=google.com; s=arc-20160816;
        b=MCqid/8zAGpmTY+YkDFjWaXtpHEX/mmjhyCsdYEJBjO5yczLQ/aGlmYbPhMWHPHFDD
         p2/5AvOUibPRf4ipvo0D3pTEQ+s6UzTOqfadvHYCXNFQ6OeeDk3SXAdlt1tImFqv3utu
         a2QrsfqiuhrMPuWy8omW4NCKc684QzGEvI3zZFscWZnIsZvbMRaoeP07I8jfqxegjT0w
         2qVJZ3AfU0zTRYvSb/2w+La9pkcYby/3kzI9p2O78d8I5GwxPOWDMA1SbJiQAFZCWnqp
         Bh4A+MO8GuKD5foL5wN/DBqQ7G9JUHSwlWzM2iEhIRXpPjnlmRu9mWzCUuX25pdtQ69s
         3JQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2rYakx2hnV4Pp+R6j2wUfLo2kXmWz7+Bate8CQftzxA=;
        b=ihwNAecqrCOxeQNoh37ed11i5vtdlSfpqFuInuK+M5pA/OeCOfeUPnprMwd6P+GeNq
         zb9zarxw48Dvl2VH8zzySfQPPilXh4ez+5Vd2wgaF0UXirjMieYPPmoCeCIRxOhzPEia
         4bEuxs5WCo1anojVw+QWn1p6Q5EDguFdIx1yYMDvjwzHxMFs9WH8TqrANgq3rS0eJGSa
         o6S4QyJgGJmZo0IdkBmwEkJeCDpyBGMFTF/WQtJPIRYM2L46zVZSxdOSULNP1ecQz+fB
         U5U+CFRQx68P4uV8GCCHhDH4UysFsBsYyhL4nsMaCxBPA3Mr2+9kRZtUS2/Xt6FTa1ar
         yXZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2rYakx2hnV4Pp+R6j2wUfLo2kXmWz7+Bate8CQftzxA=;
        b=dtF6REdbOjq1SEf1kV1EGcfRPvi+KeEij6dIsqGzdYD0kHe2gA27+bDfh+OIWickbp
         jwflBTRMSjutXEpEMracYAuoL8cs0N07CmdXcWE/qlunSxL0cm/vQef5ugskxYMDEWnL
         NgxPU8wr/IsC69uJZkUf8D85m+/Xm39wrPddroijbiwepw6q8Z+GX1Ayf7oWjRyouCUg
         BNCSWy6/Z0cUqVhN7AheqKK8Z9xkYgEQyyl+zBvaE7U1+KPbc6gpd58BIg28ov/pNH38
         7E+gf/hmlirVX4WtVxoxvkILZz0qR8zRrr/l54P2XvOr8eQO3Jz4gEa8VY/Z/WVSelFI
         +1vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2rYakx2hnV4Pp+R6j2wUfLo2kXmWz7+Bate8CQftzxA=;
        b=u4edMlvwPrH6U4TImCpWt6Z1TTnaTFAAS2UWbMIUj6LJ6EBYjpSdG36ts+XxNF5Hkn
         xIN0axLWkH4k30OSCr9K0gcMDvP6nimuv8olt2ju4WiDqzSY6JPOngw3H89SH2u1L35a
         5Cjh82TtW0NUgxJwKJ/dec9YsETew08sB+L2wR3YoLzvnTnicomO4HebjRJJ3CJ3jiFi
         RzcybiZVolaLfiSmivTFDllpPogj/qb81F07fJv09a58irqeVNhzXk6gZOtyBNEDIiYP
         Rh6IGWG8vKRjeUDcJkrUfy1b6NOIjIY3vNN7yiUcLr9uPFNpqX4eIcfxfpkoUJLxV5EK
         tuww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ia/z9fmwtL0/NgENvir9fJlV0Uxaboz9g/s4ZmkqZWJYxQVjE
	Oao7cY6zfcFcS2kKbzHL5Po=
X-Google-Smtp-Source: ABdhPJyuLGEqKNlGCipSvIxv9BhAjaflfFliw7hpji3nVS+/zFJoPCoGUrFd3vzFxw2eaQN4Clk7Vw==
X-Received: by 2002:a50:954b:0:b0:41a:c9cb:8778 with SMTP id v11-20020a50954b000000b0041ac9cb8778mr18669695eda.165.1650388011734;
        Tue, 19 Apr 2022 10:06:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34c8:b0:423:f341:6e06 with SMTP id
 w8-20020a05640234c800b00423f3416e06ls1613727edc.2.gmail; Tue, 19 Apr 2022
 10:06:50 -0700 (PDT)
X-Received: by 2002:aa7:d543:0:b0:416:13eb:6fec with SMTP id u3-20020aa7d543000000b0041613eb6fecmr18922293edr.348.1650388010723;
        Tue, 19 Apr 2022 10:06:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650388010; cv=none;
        d=google.com; s=arc-20160816;
        b=xE6pIGmfYOSf6oDR4QWPldXzC5fsSlfEl/tqO5Y+OjtofH+IBQUMYu01bnJn6++E2k
         V/jTBjtIZgD/I44aEm+Y6zvYc+3SNH7+McGfd/5kdODhaGnH2gGMMhW9WrBkTmhaCAxu
         2RcGG2HjYnzcbzboGKFAnr3hOVkwFb8BLTSCobBa7gDrUQjNOB/4T3vWyz08yicRcpiA
         pO9Ch+crKjPP2FOiwLgSA5rNqbb73L+AVUCYRxkDr5NlzfFXxGodpoaaoA3gCgl7o5L7
         qcgYFcvZ3K65do6xtGLT0JeXHruDHu+q6ms3Um74LBDaeJKtxT2vVz7ngVZiKjvkaJYp
         M5bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=2RDBx8qN7+yZmLuE2L0JpY9IH31QtRXiayvbeT1tdK4=;
        b=COAYBvo4sjm1Km+pcOyMAUrlSvtGmx49VhFFCcsbCYTz+997t3baUW5mflmFPiYU34
         8OlNYsh1nP6J8Ylyn0N+DkPlfwut+VYBSwtrE5F7yoZEQZvrKoKg/QOgcUE3YWGKX2Nv
         Xb9BBt+cInUqUS/zAwT0TVqq0OXGlh819IJnVSt4okMLRZZRRFVRiC3ajgj/VAig8e5o
         WtsY6h6acVH8zenDL94mJy8c9orJZMCBkZB8VSxkzGZIX+CNhfTFzm7SE0wt/CCn3fJ5
         vvGeEiddeHwHCOtdNsDYeAkjlMXh7jO9BYGf8hFOrBdbvyksEXnkgto3eKDL0EA6WyhL
         MM8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v9-20020a056402174900b00418d53b44b8si828389edx.0.2022.04.19.10.06.50
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Apr 2022 10:06:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 165291063;
	Tue, 19 Apr 2022 10:06:50 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EEA023F73B;
	Tue, 19 Apr 2022 10:06:48 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH] MAINTAINERS: Add Vincenzo Frascino to KASAN reviewers
Date: Tue, 19 Apr 2022 18:06:39 +0100
Message-Id: <20220419170640.21404-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.35.1
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

Add my email address to KASAN reviewers list to make sure that I am Cc'ed in
all the KASAN changes that may affect arm64 MTE.

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 40fa1955ca3f..19053767bed2 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10549,6 +10549,7 @@ M:	Andrey Ryabinin <ryabinin.a.a@gmail.com>
 R:	Alexander Potapenko <glider@google.com>
 R:	Andrey Konovalov <andreyknvl@gmail.com>
 R:	Dmitry Vyukov <dvyukov@google.com>
+R:	Vincenzo Frascino <vincenzo.frascino@arm.com>
 L:	kasan-dev@googlegroups.com
 S:	Maintained
 F:	Documentation/dev-tools/kasan.rst
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220419170640.21404-1-vincenzo.frascino%40arm.com.
