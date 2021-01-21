Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWO4U2AAMGQETEHPRTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CE142FF091
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:39:54 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id c7sf1069256oig.17
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:39:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247193; cv=pass;
        d=google.com; s=arc-20160816;
        b=CPMXzY9A1FD3L+ANyPYVaowpjr/Pqvk2z5KwznaBG1cJNpqoqXHJNofiWed3Acdc2d
         g/jfZceehaoabrLerzE6OxDIEDIPNbB220tzzEKsMW9O+ZxzqPWraFef3yz2Py26BqWP
         n4wlyfaKNQFqKsYTiingPk3D/sBLtxfNAHJ6OAFxmoMbSg1VRnv4mC8DOqfbTa46Be9k
         n8wpDjWprt4JA5xwxGYnrOV37Uu07TGex4Zaj+URvF0f2QV2ICeOnjY39QlK1Tnp7dKB
         bn8cO6Kn3TpowcaW6dW/FAeWzEp2U+hN/XivmCL7jcW+EWc6QItD87j12tvUPJOcDe0J
         l3gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JxG7M3sfPKiQtv9tIWcDqLmPX+4lsiN1ZoRDCXyBvR4=;
        b=J5zC8c9Eyiwr0T+eKaL0B3DVxSHb+oqFJwbHHMLBWS068/yRG8BngeWzDrDtzETseN
         OTleFGB67JpeBg8KpkaYES21UwWS52ZLjAde9f4HJQybHtU3K/gLdmoOOhf/5tI7k5TH
         K37ebLhahEkZiGtA9Bd5bbC/fEITfFJSJ8e5D/0Rz0yUc0a+/Z0DbQRKQ7Kj2mcHvSWg
         nsR5F78VURdbWne27eOEOUvLtiShn7C4a1EGDMh5T6mbxGZHs/cHB3ypRH8pAziDUNg5
         6kjgFJnu5ZrS3YfyrYFDSZhuqRZHBiPv80aaX1++Fufv8Y0h1POzOKzgBfh9lP7qIUQ4
         m8Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JxG7M3sfPKiQtv9tIWcDqLmPX+4lsiN1ZoRDCXyBvR4=;
        b=UZDE65seKMJzQpMLD6HRwAIgk/qiTEN68Hz5n0/eH+xbiF3ay8awdukwqSMN67Vhv7
         6C99C/051oNL1Sj54TwRwu9SUgpCYlW+Z57lBHYBAWG1uf+98ONQKJpBuwatRvG+1VsH
         Y/XAJCF6Ib48h0PDANIWr/IjFO1qAO/pZpQupYVRNSAszz77z0oA9ThriTMJEtrmL6tj
         yfZe9oQNC+CtsLTuZfxeRXtWIeizE+lsJNsPMV6uVgKG+Z4GQ1jPF6alcgKj7rYogOQ7
         yifBQXR2LeBzP2QYRCWrw1bmdZxgmQcPtYJSYxg6cwEBecTqA8t2PMfl2MPJ/2BQZbWP
         KvhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JxG7M3sfPKiQtv9tIWcDqLmPX+4lsiN1ZoRDCXyBvR4=;
        b=j/VCQ0UlY70K85EZqdZcFKPn2DPZ3fKW3puze4mvJM3wDBso0OiwaC1MvalOIG5wvT
         fQgsJIe/gBT0ea8YiOeOcdHPc+WYuIXzT+u46/+zbs85+u10xRC/aGXiszm67Qv2NrZY
         zyvVjW36pUso9vLYQyxqYTs7zPiD+UOYmFCUPWIyzOuBwxK6DjyVT0Gp3muWBLDOAgI1
         r9Gh48MnWi0stC+2U4GONmj5+ULsKhb5e/7qJpqUtaLLqMdRTBGK2bvze+P/f8P6PMmz
         /0GQdjoDErNJjwQ632TYgzF0hF78QL47I0F0c1QvavCrBW/Lgc/hopCN8bzz686uTD85
         S1mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530o3nay3jp3yQ/bdyD0dY9APTRI6HNdaUhrI6Po0czMoC4BPnJh
	ykE+pLq3lL3uZN+wr8XrSt4=
X-Google-Smtp-Source: ABdhPJzvsTLsd/5lA6fRLswsi8AxrQwMhKSdYNrEBLzi6LlwupaRmLjERyoSb9zTzInCf+/EqR1J9Q==
X-Received: by 2002:a9d:37c4:: with SMTP id x62mr11311431otb.87.1611247193442;
        Thu, 21 Jan 2021 08:39:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:52c5:: with SMTP id g188ls571845oib.8.gmail; Thu, 21 Jan
 2021 08:39:53 -0800 (PST)
X-Received: by 2002:aca:418a:: with SMTP id o132mr294411oia.53.1611247193127;
        Thu, 21 Jan 2021 08:39:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247193; cv=none;
        d=google.com; s=arc-20160816;
        b=YvHEZ2d+X+nb5g7ULbYaDARoxVNJ74VPirvcIWSOO0uQq9zaMRM7ojDopHkkP3NpW/
         BTbRqLtYv08dGXWT2hc2P46tBrOuyVeTWGRw+9B7LQPqAJ30jldDHZv+ON1w6G7QEdmE
         4nNDblI5Pt05cnIPMoVbHhgp19XHwA3+ttWbWIaRzVmsQmAi6RH25CVhcbNTQYqrNI4b
         aM1CdGwwvLoYq/VNXcSmnOyJgJslvLIw2X9VnP+dTFmCSes3Kh0BTkJXdzPd6vAyMgo4
         XGiLIxb4X5ri3a00DxS9zdQDtCqN7N+fKNZ3WBjP4oOa5Y8UGJuFBm9ybLlU0rYZTluf
         DBGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=8idZcHW4dAFaSdSUIuvQfsPdw6qkpYsrDUNuOwJkWlI=;
        b=wNAvFfJQ4HFQzNk573JL/bFf+Rqcq+xgOyfaHc7wnovQJssqsevXDPRvnYt30l/zqE
         xvso+w2i868+JzsttefVMG2CVZLpm55T9a5p/XQnmJ1ny2h79wu9cEDiJ3WfOfkriU4h
         RQdoPSwCiSBTz0Ls2iRg4IZ5IBgcR11w8xq6OIl3/Agmu/XfOqDiTq9hLJ0xx1PKrLsY
         2oKNUaJ3OASgnAgW5AoyE7MX157Cd3atU8DkGBA0kUOr4zmMr/aJHluiVH1tgZi8JQfj
         EfgU5p12YhVZ4FW7C50xgJma14EZF+03bBUe75rq2TsPMtLrx4rRzOzIyHzL5IWjIMj6
         5wJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a33si367666ooj.2.2021.01.21.08.39.52
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:39:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CCB0711D4;
	Thu, 21 Jan 2021 08:39:52 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2C0BD3F68F;
	Thu, 21 Jan 2021 08:39:51 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v5 0/6] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Thu, 21 Jan 2021 16:39:37 +0000
Message-Id: <20210121163943.9889-1-vincenzo.frascino@arm.com>
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

This patchset implements the asynchronous mode support for ARMv8.5-A
Memory Tagging Extension (MTE), which is a debugging feature that allows
to detect with the help of the architecture the C and C++ programmatic
memory errors like buffer overflow, use-after-free, use-after-return, etc.

MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
(Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
subset of its address space that is multiple of a 16 bytes granule. MTE
is based on a lock-key mechanism where the lock is the tag associated to
the physical memory and the key is the tag associated to the virtual
address.
When MTE is enabled and tags are set for ranges of address space of a task,
the PE will compare the tag related to the physical memory with the tag
related to the virtual address (tag check operation). Access to the memory
is granted only if the two tags match. In case of mismatch the PE will raise
an exception.

The exception can be handled synchronously or asynchronously. When the
asynchronous mode is enabled:
  - Upon fault the PE updates the TFSR_EL1 register.
  - The kernel detects the change during one of the following:
    - Context switching
    - Return to user/EL0
    - Kernel entry from EL1
    - Kernel exit to EL1
  - If the register has been updated by the PE the kernel clears it and
    reports the error.

The series is based on linux-next/akpm.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm

Changes:
--------
v5:
  - Rebase the series on linux-next/akpm.
  - Forbid execution for KASAN KUNIT tests when async
    mode is enabled.
  - Dropped patch to inline mte_assign_mem_tag_range().
  - Address review comments.
v4:
  - Added support for kasan.mode (sync/async) kernel
    command line parameter.
  - Addressed review comments.
v3:
  - Exposed kasan_hw_tags_mode to convert the internal
    KASAN represenetation.
  - Added dsb() for kernel exit paths in arm64.
  - Addressed review comments.
v2:
  - Fixed a compilation issue reported by krobot.
  - General cleanup.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (6):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  kasan: Add report for async mode
  arm64: mte: Enable async tag check fault
  arm64: mte: Expose execution mode
  kasan: Forbid kunit tests when async mode is enabled

 Documentation/dev-tools/kasan.rst  |  7 +++
 arch/arm64/include/asm/memory.h    |  4 +-
 arch/arm64/include/asm/mte-kasan.h | 15 ++++++-
 arch/arm64/include/asm/mte.h       | 32 ++++++++++++++
 arch/arm64/kernel/entry-common.c   |  6 +++
 arch/arm64/kernel/mte.c            | 68 +++++++++++++++++++++++++++++-
 include/linux/kasan.h              |  2 +
 lib/test_kasan.c                   |  7 ++-
 mm/kasan/hw_tags.c                 | 27 +++++++++++-
 mm/kasan/kasan.h                   |  8 +++-
 mm/kasan/report.c                  | 11 +++++
 11 files changed, 178 insertions(+), 9 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-1-vincenzo.frascino%40arm.com.
