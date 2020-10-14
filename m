Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPOGTX6AKGQE5LASSUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CEA828E7F4
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:44:47 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id v7sf258264plp.23
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708286; cv=pass;
        d=google.com; s=arc-20160816;
        b=V57oR8mkfK1rj6K8o1tywxjuItfjxa8uwsvdGOUVBzBMJLIibVjDoC8Q2xUQzDcS9O
         Ik9UzfSUP0pYPpxPZHAdfUdsQ3yvquKudq0MS0XA28/bqmDdXOUAJ+aSp9L8TKvQB3TX
         t0i5bbpGwEPpUM2SJmgCOYvhZNtmy9hzU/yDGyWuMfx1ZfLZT4yKaF6zs3lTNkuG17aQ
         MSsEBLLK8K38rycMQPxjQp5c1S9F1ktR64oFjT5qKUrJz1VnACrPp/2TNFDODPeEuQxQ
         k0KuCO9fZjqSF3DiKyBK4XZ7l1eMCyN9agi6KPjuaW5/nyhbBV/4LOw+Z2nbg9c5Fz6c
         6wcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=t+HDP6UjTppto34TtbgkzfGi1CUEfcvGe1aVXMeiynY=;
        b=y6mlAE7VGU7HvnVMZ2bZfRg3UDci9vs/nT5JlhU7k6MI1GvnlUqaghuUgN6v0a53wy
         ri4hbYZDhgDDlx+YEnk3TZD91UFRjIsgu1nfS3jwLbAq56FDIrXecGgMr4DZ5AtXvoks
         f03m0By+cpR+sbj3Vqf68jA+/siVBb9sa03gVqRN03lakQRU/hMC1bAvTV3UvKS+CoaG
         tU3t9Z1BibkLUPVHcb0Xtc9TLTsk2W9jc3Pgefip+EoZarhPS9r5Be4zrNrW1lbsqbfo
         R5BwoDT4/BqWMz4H997HghrltPxHrAHh7UVqRvHkAqSaNM+FakgigNWWwsNzVyF9IK+0
         zqKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XHIWX6TP;
       spf=pass (google.com: domain of 3pgohxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3PGOHXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t+HDP6UjTppto34TtbgkzfGi1CUEfcvGe1aVXMeiynY=;
        b=bNwMtk1z1ec5k+ziO4POT4VKCc1iEacW4Tb8pAq7Cagh7B8Kc/C1bjvTo4rUsPtz/H
         MiNbck1iDPqZBr//NUVw3Yos2w9yxnVm02iiYe7WUkppaYsCQmvvum7sGsli+0eTUE21
         qZWG9G/TYJEjc5/wSoTmBau9eGVYbOzYbxC2xWDrODI2Dr+Sj3ItQsBnxoEf9bZLQfUY
         qBtE7QFueshxJF4fQiywM80dNZTqQwVUGYxeG79m/R9iwEUaH0JB54Dcb/HKrUUEgT6U
         axmbLpeTKVzXWH+f5TnvpAQNtpnN+EicNirDtxwSvpFkn4XXyp0MOBjWC+PReZdWTrKs
         FKIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t+HDP6UjTppto34TtbgkzfGi1CUEfcvGe1aVXMeiynY=;
        b=eACs0YslwaAVRcS10zhzfq98TVw+w5319cL6R476NVkKaNA4bElnN7efINWn1nit1E
         2jlH6H7AV/dErWDq1OyXigiQcAqcqOgkMd05cZWMBlDd9Xvwos7jA6N0TaB78yQ1bJu6
         JoYn/mXmgiQhKBgs4OqP5XcOkbeZdUTLWsDhcrwKt7Q1RKwUm8AqdQZM3xo2TsWi+ejH
         3VgJdXfjrcAu/EzNU4CPAcB9i3CwG53IPs9DRnhr/FhQ48dN8l0O4q1qx5cx525MPhYU
         qyaDojEd0I8G6szz7DkHWekuM1VodTy8RU6sjNwQDkC9TtgrcwkgMY8UOWp08MgfGjCu
         apoA==
X-Gm-Message-State: AOAM5323twe8apNAHKsK/SzYwHO7x9UDXKB8CsiUq8ZgaAqQV2/ffTdV
	KkKSdo6B5rvL0RCj4y/iqA8=
X-Google-Smtp-Source: ABdhPJw/AeO2zucNJN1WgQGqq6px5SBYODyhtJKPYna7V93+HB78HxMZ2U2XACFcYLy3qdLfNe/CTw==
X-Received: by 2002:aa7:9575:0:b029:152:97f9:f884 with SMTP id x21-20020aa795750000b029015297f9f884mr1000163pfq.80.1602708285870;
        Wed, 14 Oct 2020 13:44:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8b8a:: with SMTP id ay10ls166219plb.6.gmail; Wed, 14
 Oct 2020 13:44:45 -0700 (PDT)
X-Received: by 2002:a17:902:b785:b029:d3:d779:7806 with SMTP id e5-20020a170902b785b02900d3d7797806mr823595pls.70.1602708285239;
        Wed, 14 Oct 2020 13:44:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708285; cv=none;
        d=google.com; s=arc-20160816;
        b=H+sT/HVR2WftyOKoxNk+XmUWT3CiFI/aIA6sTTg86Z59zfWvUtpLUGKiznnHzd1Fs/
         NNQ2jE4vBLX98n/3W1hlk608VwGnp34vWi04W5UkVtts84K4+hB7JArXGBHs9DNjBwJ4
         xnR9NEpji+KQFz/SWwI4KkrDiBoweZh2vV7n+CgA2/82wDlxxErlI31qXPJJZccIF4tZ
         P2J6CnFi7SFcZVp9KUMy2IXO2x71SWPf/LfvYUVJypRTiKxJNA0DHlMKQMMDCwzlUR8V
         LpX6c/xSl6YcEHxQu6R3CEQo+ASNztCWWbmVHaFvgsy4dYzhvjw8bviOAwEyehOQPp7i
         UZkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=Wp6ksUSUbEBH3QFRcUbKn90ZmE0mGR4EaPOxflY/Bhk=;
        b=bhM6McRQNhcsU29XWmyEUXuxFXDN4hEF8rnnE16SlUgH5ic9lDrGTpaQdblF8gko4/
         QMSm//xF8Y1tCNO5COEklXv3PKqaOdbMOOwzScP9qxrm0BBXDp4Pw8Z/uKlN0Wx2Uhso
         o/F2jXWTLqNml4ljhkMmXP1TwM63gTBAntl2BpS1Yux80+k6k361OZFQHceUM7TtNjwD
         64IENcwYLpmlpP++7JatSm22jvRbKZry8hnHfZAMPW9IQX6XwOvWGalyWF1/NPsK2igX
         iXox2/sQX+4vCRiPbGoWEtg5eAJz8KJrFdm9jbTX1f23zqexWBrTS6D9HuTt09CV1pPv
         WQLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XHIWX6TP;
       spf=pass (google.com: domain of 3pgohxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3PGOHXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id r23si65289pje.0.2020.10.14.13.44.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pgohxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id d16so292123qvy.16
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:45 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5747:: with SMTP id
 q7mr1451102qvx.0.1602708284222; Wed, 14 Oct 2020 13:44:44 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:28 +0200
Message-Id: <cover.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use on arm64
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XHIWX6TP;       spf=pass
 (google.com: domain of 3pgohxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3PGOHXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

This patchset is not complete (see particular TODOs in the last patch),
and I haven't performed any benchmarking yet, but I would like to start the
discussion now and hear people's opinions regarding the questions mentioned
below.

=== Overview

This patchset adopts the existing hardware tag-based KASAN mode [1] for
use in production as a memory corruption mitigation. Hardware tag-based
KASAN relies on arm64 Memory Tagging Extension (MTE) [2] to perform memory
and pointer tagging. Please see [3] and [4] for detailed analysis of how
MTE helps to fight memory safety problems.

The current plan is reuse CONFIG_KASAN_HW_TAGS for production, but add a
boot time switch, that allows to choose between a debugging mode, that
includes all KASAN features as they are, and a production mode, that only
includes the essentials like tag checking.

It is essential that switching between these modes doesn't require
rebuilding the kernel with different configs, as this is required by the
Android GKI initiative [5].

The last patch of this series adds a new boot time parameter called
kasan_mode, which can have the following values:

- "kasan_mode=on" - only production features
- "kasan_mode=debug" - all debug features
- "kasan_mode=off" - no checks at all (not implemented yet)

Currently outlined differences between "on" and "debug":

- "on" doesn't keep track of alloc/free stacks, and therefore doesn't
  require the additional memory to store those
- "on" uses asyncronous tag checking (not implemented yet)

=== Questions

The intention with this kind of a high level switch is to hide the
implementation details. Arguably, we could add multiple switches that allow
to separately control each KASAN or MTE feature, but I'm not sure there's
much value in that.

Does this make sense? Any preference regarding the name of the parameter
and its values?

What should be the default when the parameter is not specified? I would
argue that it should be "debug" (for hardware that supports MTE, otherwise
"off"), as it's the implied default for all other KASAN modes.

Should we somehow control whether to panic the kernel on a tag fault?
Another boot time parameter perhaps?

Any ideas as to how properly estimate the slowdown? As there's no
MTE-enabled hardware yet, the only way to test these patches is use an
emulator (like QEMU). The delay that is added by the emulator (for setting
and checking the tags) is different from the hardware delay, and this skews
the results.

A question to KASAN maintainers: what would be the best way to support the
"off" mode? I see two potential approaches: add a check into each kasan
callback (easier to implement, but we still call kasan callbacks, even
though they immediately return), or add inline header wrappers that do the
same.

=== Notes

This patchset is available here:

https://github.com/xairy/linux/tree/up-prod-mte-rfc1

and on Gerrit here:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3460

This patchset is based on v5 of "kasan: add hardware tag-based mode for
arm64" patchset [1].

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://lore.kernel.org/linux-arm-kernel/cover.1602535397.git.andreyknvl@google.com/
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] https://arxiv.org/pdf/1802.09517.pdf
[4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
[5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
[6] https://github.com/qemu/qemu

Andrey Konovalov (8):
  kasan: simplify quarantine_put call
  kasan: rename get_alloc/free_info
  kasan: introduce set_alloc_info
  kasan: unpoison stack only with CONFIG_KASAN_STACK
  kasan: mark kasan_init_tags as __init
  kasan, arm64: move initialization message
  arm64: kasan: Add system_supports_tags helper
  kasan: add and integrate kasan_mode boot param

 arch/arm64/include/asm/memory.h  |  1 +
 arch/arm64/kernel/sleep.S        |  2 +-
 arch/arm64/mm/kasan_init.c       |  3 ++
 arch/x86/kernel/acpi/wakeup_64.S |  2 +-
 include/linux/kasan.h            | 14 ++---
 mm/kasan/common.c                | 90 ++++++++++++++++++--------------
 mm/kasan/generic.c               | 18 ++++---
 mm/kasan/hw_tags.c               | 63 ++++++++++++++++++++--
 mm/kasan/kasan.h                 | 25 ++++++---
 mm/kasan/quarantine.c            |  5 +-
 mm/kasan/report.c                | 22 +++++---
 mm/kasan/report_sw_tags.c        |  2 +-
 mm/kasan/sw_tags.c               | 14 +++--
 13 files changed, 182 insertions(+), 79 deletions(-)

-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1602708025.git.andreyknvl%40google.com.
