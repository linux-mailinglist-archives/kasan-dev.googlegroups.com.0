Return-Path: <kasan-dev+bncBDQ27FVWWUFRBSH5Z6DAMGQEMQYJGIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A5FF3B258B
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 05:40:58 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id k12-20020aa788cc0000b0290306b50a28ecsf2642900pff.10
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 20:40:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624506057; cv=pass;
        d=google.com; s=arc-20160816;
        b=MBedE13vsVE4HgZKFn3UCdFUAUSRJqvs7X2q+UsFMQhE5J7emw2tnEaqPFc+clkzqD
         AW5LtoX0LuP2dAB5zgJ72VBxTF5GkpKAaA7zE8M8y0fT27Qnhfp495BWBPwtdaAqX5Ih
         W3jeEA0Y9RFOfuK9Ls9PswX35IY0WAGXz6n/FScWOxYgtiznlUaCUZIN5rdZ8iiDEGtt
         xXM1KLeEUuXQArzZPUQF0iGffFftbHxlPDP8zLRhr57TN8+PKA3cycsUKQ+LwgRmWn2c
         295VPYUW4CoSKrJVCfFRUx/E0rUX7YAqh2X8bhVtGVwAPF4cw+zNNRE/ke/4Y8CDdROH
         t6fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8YKYl+8qoflR77aMJP5ymTDtYdPT8APdn0zxsb2SL4g=;
        b=jGeJPMKtulv3Kklvjirs9rPdj2H+i0RQO+4PwkVmAOJbG75oJGc7tS2QvK5c/XAqgR
         Ma818MbpgQMKRJJmLPOYsb+ejP1YY6mun0cUhi7EHrEqDaOkw3azciAZp/NaEE0NUgou
         jS89wxIxiibCQfsKcdxcx3x9JHoEDmAEA+BSBVWVMA+Zr+TTsQTnKwTh4N8jPT8vGEaF
         WlfLzKXCYSed5dZvIWIS2CXJk7NKCEtjEh9jyL6wP6Kv0UnNmF9k2gx3EeJn7lC3NQAZ
         FNAJNvAS6n1c5kV+X+m5da0lSI8doUhzwTYy3Hey0OTeMCjtwXX6hzWGIYGeGlejk+Au
         lSUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bPxUvfH1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8YKYl+8qoflR77aMJP5ymTDtYdPT8APdn0zxsb2SL4g=;
        b=La2wO0d7HbMYgnLyYtWdr4or89Mqyw9d2Z3/4agy2l9y83SsDsmgrBDpTwRUAgAI0/
         Cjjr7CgE81kOZMFNEGit+R5oJ8w07qdmcJMUEUdfUZ9B4FOyz6MU2vyn2NQ4Ot0D31sG
         n9X5fhyJgDqfRmz7j9LZhF+SpEZVCS+JW3fU2Ter5XuS04Hb/U9BN8g8w7TPgc2os10M
         LlnTU2kVUFE8RxzNQNf1E9vFx9wcLmjv8cozj+gLDad23IEG61HEsh7eMlnh0FLUaJwd
         GopQm+WzDSqv/1XvXL3/WCQIMQ0uhIgszXnm62H422tP4AJogEgzzLuHxcrtJJ3i796X
         EaIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8YKYl+8qoflR77aMJP5ymTDtYdPT8APdn0zxsb2SL4g=;
        b=YCTmiHkWsOYfEggtTOevTlupVeKoUGmVQ6GyON+2DCkgokbkrY/jOsTg3QFpKfjCno
         JtmUiWzH+MCnEwLyJU+7gKbNpRkVrVRhcQA3BIoMu7EmNvTTz02kEf7fT677JAPyYCv7
         qLB3JUtKuXKt0NqyzYzZMlZwzezGte8/DfRS6Vi0nseQJsO2FcwZHLcrxske+iocoQeg
         FJUHDe3atLqJ3NGq6iZXqspgU7ACtfCmIYlcJKDeK5oF9efy8eqIvw8UulohewFx/nuY
         HRUULIcxj6qA64vYn0EuhUffvpm9lpOECSeIwRdbmoL2ifCWmSS4dKP3z7GYVJSuK4x1
         QPFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530yFYfgTC6Y2NemkB1hzLJNs6xl9JmNEDZ1MjEFnXEk6wAfTNAH
	2txOIfiSnsLh7f9hx/mq9cc=
X-Google-Smtp-Source: ABdhPJzfjIu8TCpAbIwBiVAwON/+RSg/mppQeE1HUw3KeRpqhHR9xRuKFkp/j5PgAhaKGiJ6bnw/cw==
X-Received: by 2002:a17:903:18c:b029:125:b183:798f with SMTP id z12-20020a170903018cb0290125b183798fmr2471340plg.24.1624506056980;
        Wed, 23 Jun 2021 20:40:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1dd4:: with SMTP id d203ls2076393pfd.2.gmail; Wed, 23
 Jun 2021 20:40:56 -0700 (PDT)
X-Received: by 2002:a05:6a00:a89:b029:2ee:da59:e89c with SMTP id b9-20020a056a000a89b02902eeda59e89cmr2767738pfl.17.1624506056423;
        Wed, 23 Jun 2021 20:40:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624506056; cv=none;
        d=google.com; s=arc-20160816;
        b=gBxgBBEpUjIriH5kt+AwXpY707kJ8awkaKARgJlNbyza8zsxjVjDEkZjNyxKSnSIig
         ZH0MIK5sS2wqFVYpIdzB8wwGboQ8LC6kYSG16by1TwAFVpy/FM7Q9HvxqLp8nf1afdYN
         M2icigvJ4lwlpD8cd0OcIWzvfhaM1akDQPYR9w7t0piv+Ox47sswtlYV+ZuKrOjaHw3g
         HTs9DCwtWTEnFGxB1uLpULHjP26Y5KUa1CZGnoEFvCdoMUUz7bOTJXHLJgPA6PqUB87D
         5ppR6V+aE71LX3NSUQcLT/uW/S1RXXxDLYQu0wuEVoSaaNPaGZNDgdfsTkmd/272yMUL
         tPcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NZ+5u/3FQBWJpz6rgvDEPJOqY9HFVit9UNSurv/3XAo=;
        b=zstroSC2CDRZldbqG5Z62I6E42AW01D2jGEezFMK8W1ukQJ4ZmZLP5gbr6l3wJHD4C
         MxkJSeBUyvEKD5tqDfvw1LJzBREAPM88KMlkD0HvPZ85zRfcySXLLp4FTIx62UYEgsJV
         F6zbJgTQ9V1jX3JoQG1cav56LS1TF1846oX4FFT884Kj+a8tfPbf4TK8KPCPAhWD1h88
         YMYuuEtwQf3xI2eQXyhVIeTiRHhMPgI1uPizZJv8bxqkya1QurakG93TVmno+w0B2p2f
         JQvivGtxFgNkmGUzdnK2U3dbmwdrOJMJ/Bf1k8iyQZ0IQDYAuiLqKzzLWZrEs20iWdtm
         2Vpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bPxUvfH1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id m14si592122pjq.1.2021.06.23.20.40.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 20:40:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id a127so3997816pfa.10
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 20:40:56 -0700 (PDT)
X-Received: by 2002:a62:ce83:0:b029:306:f58:aa14 with SMTP id y125-20020a62ce830000b02903060f58aa14mr2705692pfg.67.1624506056039;
        Wed, 23 Jun 2021 20:40:56 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id k9sm563729pgq.27.2021.06.23.20.40.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jun 2021 20:40:55 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v16 0/4] KASAN core changes for ppc64 radix KASAN
Date: Thu, 24 Jun 2021 13:40:46 +1000
Message-Id: <20210624034050.511391-1-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=bPxUvfH1;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU. I've been
trying this for a while, but we keep having collisions between the
kasan code in the mm tree and the code I want to put in to the ppc
tree.

This series just contains the kasan core changes that we need. These
can go in via the mm tree. I will then propose the powerpc changes for
a later cycle. (The most recent RFC for the powerpc changes is in the
v12 series at
https://lore.kernel.org/linux-mm/20210615014705.2234866-1-dja@axtens.net/
)

v16 applies to next-20210622. There should be no noticeable changes to
other platforms.

Changes since v15: Review comments from Andrey. Thanks Andrey.

Changes since v14: Included a bunch of Reviewed-by:s, thanks
Christophe and Marco. Cleaned up the build time error #ifdefs, thanks
Christophe.

Changes since v13: move the MAX_PTR_PER_* definitions out of kasan and
into pgtable.h. Add a build time error to hopefully prevent any
confusion about when the new hook is applicable. Thanks Marco and
Christophe.

Changes since v12: respond to Marco's review comments - clean up the
help for ARCH_DISABLE_KASAN_INLINE, and add an arch readiness check to
the new granule poisioning function. Thanks Marco.

Daniel Axtens (4):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  mm: define default MAX_PTRS_PER_* in include/pgtable.h
  kasan: use MAX_PTRS_PER_* for early shadow tables

 arch/s390/include/asm/pgtable.h     |  2 --
 include/asm-generic/pgtable-nop4d.h |  1 -
 include/linux/kasan.h               |  6 +++---
 include/linux/pgtable.h             | 22 ++++++++++++++++++++++
 lib/Kconfig.kasan                   | 12 ++++++++++++
 mm/kasan/common.c                   |  3 +++
 mm/kasan/generic.c                  |  3 +++
 mm/kasan/init.c                     |  6 +++---
 mm/kasan/kasan.h                    |  6 ++++++
 mm/kasan/shadow.c                   |  6 ++++++
 10 files changed, 58 insertions(+), 9 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210624034050.511391-1-dja%40axtens.net.
