Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGF2VOAAMGQES4JYHIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4150A3004F0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:11:38 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id w135sf3462196pff.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:11:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324697; cv=pass;
        d=google.com; s=arc-20160816;
        b=MrjTH8y9WS73DSY7JCtnSRMtN0SEfqfNsqFk0jSGic0qgIvkdHV2HhVhNUy+ck4+F5
         RYN8VhM8GZ3zLunz9WgPaHuKsf9H6+EFqXyBLtWcWdnzt9MWYYX+T8eclSiwMDRlbcVy
         KN+0sxkjFHYn+zJDIQ4scY6HQsGAxcLLuwKnsrADD2t8/t8ViZ8oojmO8j3lB1LbIsjz
         35K77u90VsFAmqMtgQ37n+YRtW3kXhvOMotrYy5zxQJDitfIoDPy7BtODNJpHXhLBD4y
         zAmWC8q3rjSu1Eu9bKf69wZPxYHaFL2xFv9Phv3aopwRSEcgOPnWY1F9HvJlMQu8GKq/
         ShZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8f/psHqw9F38wrgEKwLPJ5/H82URZBTbUsEdqbcX2gU=;
        b=jtTH99Ie6OThMkjxMPbpFzjXoCLee2Lc08TSmF3ESv2eaZukA2no5PkV4U3JntDwDe
         AaEkBsnmMTsEE8esLrWfmQL59Q0WWZj8+A2QEQdorRdXsjUeNc2afI4HcbJhjoel6/zl
         KDUeBb6463sRnniTbPlOpH9UnHNI5Sp5T3+5KM668dqemQnkI57CL7DY4H5yE9zSBW3l
         Z4YUgT5d8a/ebxOW2Dp+5dpxF2M4JSBGn4xsVbuQjG79c/+utmKZEUm72ZZrprQS2Dh5
         1lRZDKAHfzjTzo3P97OWCBqtb7aOO8HI1Kxl9rypFhliu2TPNFREmYSOpTMaTvcwRzHu
         ykjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8f/psHqw9F38wrgEKwLPJ5/H82URZBTbUsEdqbcX2gU=;
        b=WZ9Rn57gWradUZy0phanN3A0vkKb7yyeKDWR9v6O9CZeeqm6flFPtkE4ArQ9qxY3Ob
         e/VA93pnKcIQtXn5bR1RGZzK3EM7btk1ZJ2o6Q6aM2XrGjg89pE1CB6fivW57a2bLH5i
         cUAWeHz7Hm9b2b4m6dNwgLwtLv+VzsHG1dUUJknfW2Myfa5o9puVeZUw+QLxHzOBl8x7
         kEWN3zSK0UnsXWEvJO+2ssvHdPXQw93FizUTcQcSczvZRk1KWU7TL+EuxrKg4rd+7OsI
         Szj38vVKoYJH+lZ4ozixozkkEjq6XASrepHtF5Nw3UxMI+Gd7HH7IymddWB7gNNvOdfm
         mfUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8f/psHqw9F38wrgEKwLPJ5/H82URZBTbUsEdqbcX2gU=;
        b=it6ec8KyYdV7Wg7jAKmMjg0QqaYG39xg6mrIDa0/Tk0tVFfsO1FQ70oDrtnhOIf0+S
         fb/eeltouNiRG4lReJ/BJEXW27t2UFWyQ9SttGna15OsJj4th0rRHqkDNPMoNbOiZ5LI
         Fsz1Uvc0SQg7/mHNNlANGD9KzbSfWUU4dlJYzX3+t6C2QL/S7fD1vhaae+qP7zsV/mGa
         9wSLbQlQLhA99G/Js7VmMJC8Ppa1igy8ymBXKb1kdqvfu6LkvlpSCHzGRl4H3kJlD4ax
         RQGu4EXnfr57H/FypI7sDkee9t1hIy0fODEx7NbZhqGZUunAbwQ7UjIwh2FNPgRZi0bN
         hZZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FYmG/RENAHr+vEMZfvgedPswwh2nKzVIzTA7QNyIKBoR9yof0
	oUFFRHJCmsG124ELwEz7af4=
X-Google-Smtp-Source: ABdhPJzCWsPBCERQPPSz5WESF32Akcbi25+aNHD47AWHbl6B5OWTmoY2iqFQCjCudAxpUQnngUnJfA==
X-Received: by 2002:a17:902:ed8c:b029:de:8484:809 with SMTP id e12-20020a170902ed8cb02900de84840809mr5179977plj.23.1611324696949;
        Fri, 22 Jan 2021 06:11:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls2177818pgu.6.gmail; Fri, 22 Jan
 2021 06:11:36 -0800 (PST)
X-Received: by 2002:a62:5142:0:b029:1bd:b44c:4326 with SMTP id f63-20020a6251420000b02901bdb44c4326mr2523260pfb.70.1611324696349;
        Fri, 22 Jan 2021 06:11:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324696; cv=none;
        d=google.com; s=arc-20160816;
        b=XMjwKjv+Rz7BNRO9rLCpG16vHJ3D6Y3Jy17bjdzsSWNH8VqoUKzijFt20jGd7U8h8i
         rJW3D+/BQEHUu78FBB5vidHZyeh8AV/ABm3KrrOKQcrQ2jU3ZBWHuM+LyzeulfFliOZK
         dux76QXt5MprAwoIbWFDGF4Epju1z5jn20HR9XWTFC7PLeetPZKhtvkleR3kVfd2Beus
         M8xuqp6HRZ4fC2T/T98WBdwU2MZFlS9OGEeaJ6kRXFfb0s3XHxo0/iYrworMaFaiKxy5
         4EC5Ch4Hx8e7px9RwrzLjhEjItVe3HcXL3V07hmnULr9KVUk3m5TaaSf89NOB3BTmE/I
         f/tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=MCWKKZJ+CVRFZ4ouf+3dhL5B4BKHPUACYsPoHe8YUHU=;
        b=yAku3rzEN8IIv0BiXQA2KJAgV5FxyFCxtN7ZZB2FCgag+7xqFqnLQPePRmyJOoLY8o
         wyAt/fht78RsAGvowwnP4XCJzjV4DsK+crAcanxy3OI42N4JP2X9SEK0VwH7rmtWcl9N
         +ybzYd3Vejsm1Dz5Cwuu+a1QUd2fhHEGX4B1rr4LIEjg49CmUqbfaPihRqBtOKLX5i7m
         tJNs+CH9nSwc/8KH2ksuTEm2KOW9QOGDhbmcn7q5Ni4VBbgyASUN0+ZSBBLjVIgBXoJF
         lGryHhqLaSm1kL0e+U/swXw96C+Oc0BTdRbto6KKVvL3LmJBSgvLFdIvHu8zGYRsKRoJ
         qC3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v3si197450ply.2.2021.01.22.06.11.36
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:11:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8E7CE11B3;
	Fri, 22 Jan 2021 06:11:35 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E25693F66E;
	Fri, 22 Jan 2021 06:11:33 -0800 (PST)
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
Subject: [PATCH v7 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Fri, 22 Jan 2021 14:11:21 +0000
Message-Id: <20210122141125.36166-1-vincenzo.frascino@arm.com>
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
v7:
  - Fix a warning reported by kernel test robot. This
    time for real.
v6:
  - Drop patches that forbid KASAN KUNIT tests when async
    mode is enabled.
  - Fix a warning reported by kernel test robot.
  - Address review comments.
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

Vincenzo Frascino (4):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  kasan: Add report for async mode
  arm64: mte: Enable async tag check fault

 Documentation/dev-tools/kasan.rst  |  9 +++++
 arch/arm64/include/asm/memory.h    |  3 +-
 arch/arm64/include/asm/mte-kasan.h |  9 ++++-
 arch/arm64/include/asm/mte.h       | 32 ++++++++++++++++
 arch/arm64/kernel/entry-common.c   |  6 +++
 arch/arm64/kernel/mte.c            | 60 +++++++++++++++++++++++++++++-
 include/linux/kasan.h              |  2 +
 lib/test_kasan.c                   |  2 +-
 mm/kasan/hw_tags.c                 | 32 +++++++++++++++-
 mm/kasan/kasan.h                   |  6 ++-
 mm/kasan/report.c                  | 13 +++++++
 11 files changed, 165 insertions(+), 9 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122141125.36166-1-vincenzo.frascino%40arm.com.
