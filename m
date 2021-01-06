Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6GK237QKGQEQ6T5ASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F1C12EBD58
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 12:56:41 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id s127sf1380615vka.11
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 03:56:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609934200; cv=pass;
        d=google.com; s=arc-20160816;
        b=qIZU+ZJDQqsQ1maSMezBQHeDOv22IQ9irp8UssQnFdAfQLmbHQquTp/oA/+jw9XqHB
         rlhesNafZPrBcWyzMDcsw0IPIFdsBoJ5hoXoQf3+edumGxJZGa2roO61+l+PecvJc1Px
         FLIxhC3i1LymFeu8SN8oK+j6tO7bOBKdfCAmLsx3MiXFYHJc55MM52yA6khCdJtheuYI
         mkPcf65j5bhiYBya53e7D6cQkRIwaRcQVLq9skIiUj4PUnOT4xPP/29kuar11xl2LPEJ
         DdZEtbbbsHsJArVpWp5z3arjDEcsZ0FjETlq9Z/k3w31iLUJ5XqZNXPhHs6NWNLc23LD
         /m9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GhcRcITrgSXurLSCOWsIZI3dnT/wLHhR1eGZDMPFBqs=;
        b=zdphH+dnYGAdvar7kIKlmqes+SRqQAKmd4pGRrfcOe4ui7WCaGVoI3AUPKGNjhumZo
         fuK2gaD9fJ2Z6jDhXX+H2Uqjy1TMnpMEpyBXyGPlAcWZPXk7gI0S219Hxu1SJ4nF/M/l
         IIUQlMX/e25VROtSWeEVLfr0cXcWIoBfqnHWRFrjKgHkFU36/Y0mT58ROZpGHlyszZyB
         UsPr6bzIsSti/fpGM+BdEJdtJi+ec+UAGUIt3JGDi+QFlB9J+76KS8pmetd3AclF5WPX
         H5JqkInC+M01tHSVR5CQMCg+Eq18v8VLrFGrGdDSXRAmssOmmZoQdzfH9KZKI1MXWNin
         hxMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GhcRcITrgSXurLSCOWsIZI3dnT/wLHhR1eGZDMPFBqs=;
        b=jDLTte58N/ux4HRXXTzEhh1ryI12EY5t5Wgcvv9aF1ZI3UU1eEzs2QMJWKhmHxMXJr
         ijpd4JpLTd7woz/ZkSiEMwvU8/nokXHdBUFneGpCBkVe4tR/7QakaWb1Jh5tVHUZXpjl
         BRiy/loJ4hp5simczYDDBYo9Rfxu1EPqk5Xj06V/6cE5EKga6qHjrvyA+sb72r0hEAda
         xm0WmPhTb0JfpvOLxMRcgQI1OsTD4R5l6umIiMDlQ4maC5+uhtChPW8jLSg9i5/ssfam
         z2zXJINlmTyk7b/qE/JsEyK0o39v6C9CkltzTHUt8vjagFbKjRfsrD5yzRVjW8bGed0g
         /ajQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GhcRcITrgSXurLSCOWsIZI3dnT/wLHhR1eGZDMPFBqs=;
        b=VkGR5vgT7o+10RFRVIKYOq7oNBDV5fYjRpaE+/Nv7ZpD903ESgYr8ialJLHX9/JuuA
         1MxlzN3ofZSHJP2ZiOC/51E/rynanV1XX3CjvUtFyDGU8JnMp33cfdQ2O7NkUk2PtGn/
         rwHsc8FX3jiyCrrzsU8OBvwFzKtiUXtmuE/hXmfRLACGPxitE8cqa/8PbBQ+ZFiG7rNJ
         GtgiVBwQB20A9cgDDc80/Lvohyx87NMmyzR+T5CuXp3HOWvjhRhEjgbh6Gp8ABTyUAIU
         1FQ09DJG6aQk9NqCYL4rUYUzsT0zDxeQpTKQZlCT0qZisA4CfpcV9zV2aT1zQiuNweoQ
         Vulg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZBy9f8vIBxXlkx3BkO3RpIfsluu9LzvgzMoEBTqi3JXMghhH7
	o9IxT5WJjhRhG74Z41OS8/k=
X-Google-Smtp-Source: ABdhPJyeNtgAVDRj9bZ+hlpk0zH1raA8o0+mgHEqUWaiKZMecDJIDFNCsqV4ai1/726+S7gv7ywwGQ==
X-Received: by 2002:a67:ec4b:: with SMTP id z11mr2732993vso.26.1609934200213;
        Wed, 06 Jan 2021 03:56:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:382:: with SMTP id m2ls341571vsq.8.gmail; Wed, 06
 Jan 2021 03:56:39 -0800 (PST)
X-Received: by 2002:a67:6686:: with SMTP id a128mr2737365vsc.11.1609934199595;
        Wed, 06 Jan 2021 03:56:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609934199; cv=none;
        d=google.com; s=arc-20160816;
        b=I2xAEmTh7EBgFhMZksrR/QSrfddZZ+a2fJeoABfU25+75/HgWlhFi4f0632LBGXi9o
         FelKliGtdTmjSk+aKG65Bo/TOS2c3vL4PXWxSfdyHiPuAmkX4nn7wlj4ZILK22IgONLQ
         VBzkxJQRZXR87crt4tbyZlYex1LNg1QYZQn8cOS4mNMhlbLMDyOhUE8RcbAec1CYr2uj
         vW2ssVvA5YK/SfX4JQ5BKaojE1KtIosoKEoXfwHsL6yzkzw/PWM7nFJwry1yQmInPOKL
         bmPmfQdMxgwApwUjY3DWaRWYfSFy6NzFyouDrX+nZScKY2Wvq7QQ3Ere7GFfbXgublnx
         vegg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=yyCz25jU/dtnjba8G1PN5e/uTq3BFSME9cLIp6PTHtE=;
        b=XeqCWg4DhOWN25e1f7K89sQAW1V17k31oGuqb7pLx+CPXjOKTGKB+BgMQaIQRhl/ku
         2FVt/ekpusDx0OLhzNM3BE6jv0EiATZum2kzKKVzIRS+P16I2fo3aqNPfbmlWY3SNJDR
         iDIia72kwh8JElyM0EMnA7nxyzsyUirejs7as7Xqe9ywQA4ICLbO08c2i1+/ssYLEOKx
         O3sdGvnBmVOXLqT8ncv1mO5bz36IVTe3rAhnOr2qUEV0qetftZBP/pdAQM66OfIJAbYt
         gF/igTTN4JH9CfkhVF0TKkodS11yODxFQOAhRaiwoiLwWoT89CFMBRaATzCga80RGS7q
         eFFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r207si128889vkf.2.2021.01.06.03.56.39
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 03:56:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D0D26D6E;
	Wed,  6 Jan 2021 03:56:38 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2F3E53F70D;
	Wed,  6 Jan 2021 03:56:37 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Wed,  6 Jan 2021 11:55:15 +0000
Message-Id: <20210106115519.32222-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
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

The series contains as well an optimization to mte_assign_mem_tag_range().

The series is based on linux 5.11-rc2.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (4):
  kasan, arm64: Add KASAN light mode
  arm64: mte: Add asynchronous mode support
  arm64: mte: Enable async tag check fault
  arm64: mte: Optimize mte_assign_mem_tag_range()

 arch/arm64/include/asm/memory.h    |  2 +-
 arch/arm64/include/asm/mte-kasan.h |  5 ++-
 arch/arm64/include/asm/mte.h       | 27 +++++++++++-
 arch/arm64/kernel/entry-common.c   |  6 +++
 arch/arm64/kernel/mte.c            | 67 ++++++++++++++++++++++++++++--
 arch/arm64/lib/mte.S               | 15 -------
 include/linux/kasan.h              |  1 +
 include/linux/kasan_def.h          | 39 +++++++++++++++++
 mm/kasan/hw_tags.c                 | 24 ++---------
 mm/kasan/kasan.h                   |  2 +-
 10 files changed, 145 insertions(+), 43 deletions(-)
 create mode 100644 include/linux/kasan_def.h

-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106115519.32222-1-vincenzo.frascino%40arm.com.
