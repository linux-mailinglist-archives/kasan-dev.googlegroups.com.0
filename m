Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRF2QKAAMGQECVO6KIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 909E12F6B14
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:37 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id k21sf4459797pgh.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610652996; cv=pass;
        d=google.com; s=arc-20160816;
        b=xIBC9cGNaJ1lqc6CkcZb4u2buVngQkKUftbNWsiURtJcVfZPo86wTtLI7/c8ptEUET
         MwvgQMeiwVYhyIfQImVNaTVbHMP6iKBmEGs7j3G6UWxSwZ+yQF621qmCxPIOGTYu9lT9
         sbWMHNMxw8oNuGri+qdqxZaiMl0TDqMbTpIA6X+KUeAE3zXIoZ87T5twoz/M/xvh1ydh
         BNRoYCeM2rfZrK/O7O9V+Zy8/OMafA3DVVmlI8UZF+VvBhBKsIYIzyJT3GjBKqm/LbS1
         oJ4P+dBHQ2i+6CmV2EtL0dpAQE4e5FyoMI7AsOLobFmj+PHyWtWf8BRNUusF26LlyIgj
         Or7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=r3iHXA9Kl1nccIJWHSSUgbegD0/qMBC9CVB3EDXYp2w=;
        b=AicJ5F/7hJb9Iu0UTk20YVhwh0Ntxk55d6tukDMr3GIoX1Mj+RJvGwWuE7kMXK22xV
         lFFU7JWSmnj94TqQJ83X/3ouRww14l2MubYY61je2x+heRvKL3h+8xvni9S3EO6NQLX1
         suGcrEuPWYn4sPKASBDREV2MUsAgEHRxXQmhMtabJMuDOvEQJvJ+O3+ifMe0cU8n0uy6
         M5iu631N1GeU7UgRFwpWoObnejFp1LaGM6Ex14JFPqQoYoA4RgyDCq7YYr9aDYDdnzlw
         sdXy8s8mHlACQbvIywJlbvcyHjLpqFYlODPtUtZdNrXHU9lEL0/mUm1SgLqr0Ue5QI7f
         3VKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="swxZvrs/";
       spf=pass (google.com: domain of 3qp0ayaokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Qp0AYAoKCYUjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3iHXA9Kl1nccIJWHSSUgbegD0/qMBC9CVB3EDXYp2w=;
        b=sbKAtxyLceBOR7KRIGmQ1L5jvCMaBRTg/oE3moKSTw0J7/do8Jr9RNhTxUO8Um4YmB
         1oT/am6+Ikwk0IjkJqvNVQ/BLUhkd3OIAHltIbs3/E9Mih//CE8HWJeIZzTtWv+o3x7O
         SJzKOo4DD9rkGPiqBB0pwoWHaAG9WJeUV4pZvi7BtcGHI5O6XyYp5dpxVWj/PHCM7AZv
         uyJAX4tCNIFUgA9OtfmT4HH/k7pO0EhKzSefNfq8xLPpLOiY3NxFeWAbzm8UPwjG3zVN
         6RZyrN/Xu0FX8sBRGVCl4nvzJIJXY0mZNyjmkaWMG8AadL/F+cweJ1qrREbJhRFfWMbw
         avcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r3iHXA9Kl1nccIJWHSSUgbegD0/qMBC9CVB3EDXYp2w=;
        b=Z7P/qEFi9v8AkwfRI1z1mEcnHlWNcwkzDNSBTPhWP9JHIBaJ/liklM5rZVMpcJ24cS
         fWmh3bJCZh2yg+WoXC3M8rpg/bpwopeRGOpnp7BST6+tR5O2zPyIJhAmAcm41HwLtB7e
         BF0imAq7WcngQDdLfcRKbuR87KyKhQyAeDEmFCFx/v9gQmWTa4MbBognga2ecMGSr6+d
         FesVzz4IpC34orrc7XgRNiCLcM6BSZSiYvjHPR70Vn1RQVrKwh++xkfIGSZEd78JyZsm
         z/J7gAXaBGai8p484/BdM2LIsALEOsLgLyNfhRJ65vWPPl453n9CAs73I9OQa6exKZm5
         K7bQ==
X-Gm-Message-State: AOAM53369w0VBREjJODK4HIRA7XceJkd27sNE1rzldyTPQKl7gevUEEm
	SBfshdRVFvBuiOYs75oEPBc=
X-Google-Smtp-Source: ABdhPJzjLE3xN/6s0HHTLTQ/v+kIavqPk/BLwUc1rLrw1ppZOR41M9z44grQaVnqb3+nx+LeonIPpg==
X-Received: by 2002:a17:902:b496:b029:da:d356:be8c with SMTP id y22-20020a170902b496b02900dad356be8cmr8893220plr.56.1610652996225;
        Thu, 14 Jan 2021 11:36:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:959d:: with SMTP id z29ls2510176pfj.2.gmail; Thu, 14 Jan
 2021 11:36:35 -0800 (PST)
X-Received: by 2002:a62:17c3:0:b029:19d:ce3b:d582 with SMTP id 186-20020a6217c30000b029019dce3bd582mr8839912pfx.18.1610652995610;
        Thu, 14 Jan 2021 11:36:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610652995; cv=none;
        d=google.com; s=arc-20160816;
        b=YSP1mE5C43xGRpZsK1KC1FSt15yNhJY3DQskrzrGVcKZ5Y638nub7mg9/v+gO0Dpgm
         DZfKAvqtgTexOsuHPL4RYjh4rJrTGkB51MyhS8+cNgPiJCYHslNCJ749e6D4B3SU5GMB
         NSyP19nKZaK+ChIhLT4AY75bS4eUrmvRrxO52LyOTDwPfLDAksI1ejF2Zs2DkfvPQSKo
         9ylwqAJpdGMFAk25WFeGeVPn5WVdJkTRLXCaTtRQCpH3a4tPtD7yOBAI8kIi5xc/Xw0c
         TCzuT8/zB0bpOMvm2Pq3dranKDJVB1yC4vLdQaygjOzOwTcdbLxxLBIAADytBuE3o0Hv
         Tybg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=R63zbbCAwIca54YwZmiIwYnYLBR+THCEQGhD+FuGdpk=;
        b=wgX2yUXUdGosaPjp86jtjV7kLPVGeG5VI6rrXP1Jd864p+rqYENS75tty3Ii+akrSt
         nKpsb4KOA7o9JVURwb22YXWqmIT7HrYggBOiUMNp3I2Hs/zCvVtHjHMtr2PTWuGFdZ6L
         RpDXB4FQB47yMd//fRpMU2xiZs4f/0uyZtli1JdPHY6ryT+OpUNv15Vd6kfBEpHQS6eG
         T/DIHchvB2B43LUtFQEmOZLpLs/UkePKqHOi5vLdhjGJCCBmGlHiAa5Nw58GhFRRf1AS
         DWpPJRVoWpBvEGCjRzQdUaCxDfJr0bZPdL0iNtVJGLv1tHBiuBFVvAznKmpTKfjt2NaO
         vEuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="swxZvrs/";
       spf=pass (google.com: domain of 3qp0ayaokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Qp0AYAoKCYUjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e11si782673pjw.1.2021.01.14.11.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qp0ayaokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id p20so5335974qtq.3
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4643:: with SMTP id
 y3mr8625481qvv.3.1610652994549; Thu, 14 Jan 2021 11:36:34 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:16 +0100
Message-Id: <cover.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 00/15] kasan: HW_TAGS tests support and fixes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="swxZvrs/";       spf=pass
 (google.com: domain of 3qp0ayaokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Qp0AYAoKCYUjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patchset adds support for running KASAN-KUnit tests with the
hardware tag-based mode and also contains a few fixes.

Changes v2->v3:
- Don't call kmalloc(0) when generating random size.
- Use ARRAY_SIZE() in kmem_cache_bulk_alloc() test.
- Print error message when tests are being ran with kasan.mode=off.
- Move _RET_IP_ to inline wrappers for kasan annotations.

Andrey Konovalov (15):
  kasan: prefix global functions with kasan_
  kasan: clarify HW_TAGS impact on TBI
  kasan: clean up comments in tests
  kasan: add macros to simplify checking test constraints
  kasan: add match-all tag tests
  kasan, arm64: allow using KUnit tests with HW_TAGS mode
  kasan: rename CONFIG_TEST_KASAN_MODULE
  kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
  kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
  kasan: fix memory corruption in kasan_bitops_tags test
  kasan: move _RET_IP_ to inline wrappers
  kasan: fix bug detection via ksize for HW_TAGS mode
  kasan: add proper page allocator tests
  kasan: add a test for kmem_cache_alloc/free_bulk
  kasan: don't run tests when KASAN is not enabled

 Documentation/dev-tools/kasan.rst  |  24 +-
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |  12 +
 arch/arm64/kernel/mte.c            |  12 +
 arch/arm64/mm/fault.c              |  16 +-
 include/linux/kasan-checks.h       |   6 +
 include/linux/kasan.h              |  37 ++-
 lib/Kconfig.kasan                  |   6 +-
 lib/Makefile                       |   2 +-
 lib/test_kasan.c                   | 424 +++++++++++++++++++++--------
 lib/test_kasan_module.c            |   5 +-
 mm/kasan/common.c                  |  56 ++--
 mm/kasan/generic.c                 |  38 +--
 mm/kasan/kasan.h                   |  69 +++--
 mm/kasan/quarantine.c              |  22 +-
 mm/kasan/report.c                  |  15 +-
 mm/kasan/report_generic.c          |   8 +-
 mm/kasan/report_hw_tags.c          |   8 +-
 mm/kasan/report_sw_tags.c          |   8 +-
 mm/kasan/shadow.c                  |  26 +-
 mm/kasan/sw_tags.c                 |  20 +-
 mm/mempool.c                       |   2 +-
 mm/slab.c                          |   2 +-
 mm/slab_common.c                   |  16 +-
 mm/slub.c                          |   4 +-
 tools/objtool/check.c              |   2 +-
 26 files changed, 559 insertions(+), 282 deletions(-)

-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1610652890.git.andreyknvl%40google.com.
