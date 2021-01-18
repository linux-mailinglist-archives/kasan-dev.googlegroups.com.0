Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFGSWAAMGQEMSVWU7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 375D32F9BCF
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:22:06 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id w8sf19985890ybj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 01:22:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610961725; cv=pass;
        d=google.com; s=arc-20160816;
        b=R6giSp6aS82j3dioJD4PTvEjA8EwD70n0VEI8jjXL94aRXnzeklhWnEU2JXuIA7Cmj
         UlvYE+E4M0pwWGoWC5UEcvFMxVbvr0TZYqo7NgOVTM0S39f1i1qqdsvad1zT2YGL8PeB
         42Pu1FpDDAizroXvPifBoSQuZZl6EzZCKRHuzBFz5eV829Zb62f3bIEbz7lZ29x4ReR6
         SltQUZLkwbKoPM0mGrfM/n8pogLQ2fUA+08TI7V8eNf7s1lVUFTbaMO+yx5XzpNoAKRs
         M5IQ+JrhOIEj02f017N+KqpBG5p5SSaf9NfnwNoEYc0w07mdMZ+yiiAvWx9Xr2OZwsLY
         06Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=ydEtgIhji1RZaURdQOMRMmBmHbXMKEoi6xsfT2cTIJ8=;
        b=p3QUzcYf+P0318xTQl2SJnx/BMHtmtp2o+UPevPu82S6XM3D8Th4dtjQe0h/n3M5dR
         i50/MjhhxFefcbtCZAZBk7YN5TGtFyyPqPvS/QENDDneP6aVNv7TpmKvkDWgXgpYXMed
         fUrvHichoZhytC1yEkak13/vqZaqsF7yN/xQsh3J/2jMq9mvNTSbpkZ8phmRZrXtsBP5
         L4gZL0LIFEoul7sXSvPIvnMPpI3RxTVUdFHcLVEoNoULU5ntncbVCQREi+0CK0VUEWbT
         ZFv7F1KTcGFlXMSfR0WagRbfyRam+nMNNZ0kloIoCWbEZGpyuSovYysLZsr/vHtVAG5m
         NGJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X6NZCPTB;
       spf=pass (google.com: domain of 3pfmfyaukcf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PFMFYAUKCf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ydEtgIhji1RZaURdQOMRMmBmHbXMKEoi6xsfT2cTIJ8=;
        b=eofqz1DwFD7T77DUmzJ8AH3JoINC33tMlfMEKaFtomKcvLFOOPDjAA098Fihgep6zM
         DBQNDoRd2TxruxjomovIDjYqCUMfSNeeiSYxRlTvwVKud12/JDC16vHTN9PCrHwBk4ut
         a6mFPrF6AlOOxkQNtdfD5u62tjfgERANs2Mzdz61YTZfiL/pcOqmyY36ay4TU0LtLtKX
         vPvrdAm8+HT1y4l2NU3L5XNKUIQk0PRFE86R7jYxjAkKm4HHx3N7COGoHlEVT3eGtZGy
         BAlgolfxzfDaJQ58RGuw+74njnVi5WD86bsEaeGLDlNULhrBMNA8BcyMwZU8nSZgKJk3
         z+ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ydEtgIhji1RZaURdQOMRMmBmHbXMKEoi6xsfT2cTIJ8=;
        b=cFfs8KOwZW25NgKzgiWVBBUhCSRNRfsMwpwoCY2mY8sRN+YLujOZugcndwm/ukZSYr
         2fnNEn1xu9CQrpJTWUty35BYTlc9Rae+B8k40ETpzUaK3udBxoIaU37FbQuGZisQWxPt
         Pcxpbo3uvJOxz99Hcdfr2Rb0zpJCBsn4yXL/29KNk0hlmDGeeHJbX13q2ddsoD59W3mQ
         5vLHMfFAj7SnLAacU41dMvqVTgWcT/UeRNhWBoIXAmA4gbrsih+JeFF4FDT++Gr7hT2W
         xm2q7BErOrOaqC1y9idgelMnlHPXcbKInac1ZBlu7Z80gcnX9YiqngHrqiyBlmzoTZ7i
         SIvg==
X-Gm-Message-State: AOAM531JPDQMXR3g3YMTmq8lF7m6rzyQnzn6Q6DR5VXjZJC66NruxjFh
	36JHJUPaqJdl2eKTFNTGjoU=
X-Google-Smtp-Source: ABdhPJwzy+C5WD1PYMSVyA5ZLz7w3AypOlUwDcm895qIQ3wWwC8cpc8uBG2Qd/MfzTW0sEZAwuNqzQ==
X-Received: by 2002:a25:6ec3:: with SMTP id j186mr35030636ybc.165.1610961725057;
        Mon, 18 Jan 2021 01:22:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8b88:: with SMTP id j8ls5627874ybl.3.gmail; Mon, 18 Jan
 2021 01:22:04 -0800 (PST)
X-Received: by 2002:a25:b3c2:: with SMTP id x2mr32016183ybf.304.1610961724603;
        Mon, 18 Jan 2021 01:22:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610961724; cv=none;
        d=google.com; s=arc-20160816;
        b=clqkoK7zvxjba0KawA+l/UXgADZqUk2sE1hzEFHiiYhocu0mHIIiJyCAou63ZchQBz
         jQCPM0EN4Z14R3K+0PIILFzTtgmWGJdvXxUiky4j0na8V5z+GX7fU3VE+3cnFMq2Dfhw
         f2A2ulkJlPwVZqT1JlhwrjE8v1UtzlkeizOe5haezuELuqJoP9Cu1gjnsVYi4ZPmTXOx
         9iEWInbIo46grnzAcb+K3VP0roGysknUfpZCrPsuRBARV3tbUYlP+bNkhUQIfxhpJgvz
         axHn/3kSgemdVPWORiR8dZyNyfmU0gTURzisEq90iL2wkX0f3FiOH10uEjEKfJz9QPaG
         HNDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=QzGOv73ZFTudUcHTOtMvLbaz7ljjqIpJFfG6qI+sI6U=;
        b=L9n40yM6PKj1jPMGm8NWGqxwrPFvP8bH9h2Ri9x5D3iCz6QIqZ7NGyIf50fsVb6Dpb
         VM2jF/7AkxlImKTFlHp1gsmi8epxYiulA9fv4bRVk+gTdCiCTpIcvhYPipWiS/qcFhGs
         xQzVnW3FUgYnm9FGaqTO9n2L1KAPBXsstU7eHzp/W+S68l9t99/DVhPjyvJo95RWA6PA
         4QsovCsqooN7ILNv+qOxx7RKwebbDzyAmhqXk8VVbr4LpDgf+pmxpt+7cxm0oxeTwNZi
         QZzXlfyaq8E4VgTxgJ9k3O1inaRsje1PnMeITPhQH6I/r5mlmQmO2Nkuj2BEkzaOx5do
         lvHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X6NZCPTB;
       spf=pass (google.com: domain of 3pfmfyaukcf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PFMFYAUKCf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id k19si1450191ybj.5.2021.01.18.01.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 01:22:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pfmfyaukcf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id m1so16008930qvp.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 01:22:04 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:43ea:: with SMTP id f10mr23237470qvu.52.1610961724181;
 Mon, 18 Jan 2021 01:22:04 -0800 (PST)
Date: Mon, 18 Jan 2021 10:21:56 +0100
Message-Id: <20210118092159.145934-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH mm 1/4] kfence: add missing copyright and description headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X6NZCPTB;       spf=pass
 (google.com: domain of 3pfmfyaukcf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PFMFYAUKCf0jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Add missing copyright and description headers to KFENCE source files.

Signed-off-by: Marco Elver <elver@google.com>
---
If appropriate, to be squashed into:

	mm: add Kernel Electric-Fence infrastructure
---
 include/linux/kfence.h | 6 ++++++
 mm/kfence/core.c       | 5 +++++
 mm/kfence/kfence.h     | 6 ++++++
 mm/kfence/report.c     | 5 +++++
 4 files changed, 22 insertions(+)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index c2c1dd100cba..a70d1ea03532 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -1,4 +1,10 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Kernel Electric-Fence (KFENCE). Public interface for allocator and fault
+ * handler integration. For more info see Documentation/dev-tools/kfence.rst.
+ *
+ * Copyright (C) 2020, Google LLC.
+ */
 
 #ifndef _LINUX_KFENCE_H
 #define _LINUX_KFENCE_H
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index a5f8aa410a30..cfe3d32ac5b7 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: GPL-2.0
+/*
+ * KFENCE guarded object allocator and fault handling.
+ *
+ * Copyright (C) 2020, Google LLC.
+ */
 
 #define pr_fmt(fmt) "kfence: " fmt
 
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 97282fa77840..1accc840dbbe 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -1,4 +1,10 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Kernel Electric-Fence (KFENCE). For more info please see
+ * Documentation/dev-tools/kfence.rst.
+ *
+ * Copyright (C) 2020, Google LLC.
+ */
 
 #ifndef MM_KFENCE_KFENCE_H
 #define MM_KFENCE_KFENCE_H
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 1996295ae71d..901bd7ee83d8 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: GPL-2.0
+/*
+ * KFENCE reporting.
+ *
+ * Copyright (C) 2020, Google LLC.
+ */
 
 #include <stdarg.h>
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118092159.145934-1-elver%40google.com.
