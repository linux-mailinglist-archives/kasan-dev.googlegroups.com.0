Return-Path: <kasan-dev+bncBDQ27FVWWUFRB3UY6X3QKGQEYNUYYSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD98211A4F
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 04:54:39 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id w13sf3979957ooh.20
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jul 2020 19:54:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593658478; cv=pass;
        d=google.com; s=arc-20160816;
        b=aZkwWiC8c/Gf1jTgHZ2m9+JApyQ+G2m/YV0fW51w5oUZtCgtaN0W1yubokfnUdbUiV
         fsy2bko7aD3bm3B0Ueeb1Bdjp7K4Z2fGrM8+iYNbahg+4lvy3VAQnR5oRTOtZamWScli
         4BsbRmSW+xVsFjo1wgllwyBNJOabGX69mHdGeP3HQchXOr1VBhOPy0PbMvyCQILbD0/1
         BTakg3f1BjvkncCZX6oL5gxglO+yx/2Gridmi46/N7oc2hlHP+6YVzgY42vsQnsrQX/L
         z8B6+rLOyQyl8k6xX/XATkVt+r2oCGM6ZUKaX4ZpAOcwNg9Lq3IL8wtu7mh2Lu+FA3hp
         UoWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dmy7maPoVkT2qGqOq0kw/08P9D/jNJNUrWSHCU1cQws=;
        b=qxwSBrIXzSHLmOfKa3vqKpOPYtmtJrRX3TXun3V3AkhtpCG7BLxEWeEb8WC1KxQH0e
         VNZld3zquLRsYqXbl+Osw55YEyQsyZhFMcR59tzjsdJhEyksT+GYDNjrHXLmLpbCiOzm
         sLuh3j4IrudvAilPPfRv22+n7YHJZdFnqnXq2po7GG8jtaaSbyPeLz1UpZwdznzR4ppv
         JXMaeIivg3X1Ig7BlHvc73ZjnNbfXdc1xUyRQeWq+ng+DsuHpQnuBReNoqaz2+pM+1r8
         XcE8xhw6u52jh8rA3wiuwaOn1FIyEuG5MXpd8VMsEK+Q3+2LQXQjEY6bwxUe0HmQ964e
         nLNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=cP7JTsXr;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dmy7maPoVkT2qGqOq0kw/08P9D/jNJNUrWSHCU1cQws=;
        b=R+6XA0l8/CSXu/pUsh/NUAa2NVIYGb+FEuEToy6+9i8/c7U6AcUsre20GtAMQtmeoD
         eGIHpRWXMmapH2p17bzPj72VJQcnDTm9ebx7t7BMLpx/fai2mEYzsNcCMV1D31s/FKIP
         XCidHSVmXXB4R1qY24i+M8RSDoomzR3Ouuou6BDx2G5yAllnZANi+WICSkTMw6/9zQXO
         WM5BnUGXScN2KUBcL8ujLDUwi6nIf6ZUHqvlVFAunu8yQrxU2wBUUmZQmooBdtHmAvzy
         F2EtHPAvo+QcAVDciWy+LMi9v3Vnb6tlSz+ITq7AnneQsqf5WcP6grz78ErnqW+QuDjG
         RwrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dmy7maPoVkT2qGqOq0kw/08P9D/jNJNUrWSHCU1cQws=;
        b=PUaOx0wslcJ2JSPiUS17I+OAqwug7T7YcJNbfiKgYmyik/SnkPnGYNG+5pzbVPxYmO
         JnhCWyC34ozhImOWLOfLXVZvXzk9Q2N5kGycnotbE8o5P7vG/2oxVL34qZ/WRSTPfC3y
         Y22yoUQb4gt7VLOWcYN6aXMBNNHkA5wc9ojKMYYaJZOM1DpsRpNiyze3h78MYh9wOKRs
         zPVT1xfhfRM4ytpMU8SsWk9frflaIEZxT8SXJTgLGPnJICXG9bFBhHhPtwNN2KnBdfbh
         izhWGS5iMdnbvX7yo7V1fVKCNetEMPqhPehJFDlb7rLHzIv/FS84QSXLwMrph3/4llv9
         UKCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GjDeiuL+MzTMziIP3TAJl+ZKTFyCG+R2XlLBfdsI0C8pXmj3t
	+NfF+OJNGZiGaXWg2iWoOxg=
X-Google-Smtp-Source: ABdhPJwMU7T1e4Z7rpwgs4RZ0KLJILsKxpzto6QSlnUTJCo8eLugcNIcXVpD0u3TpNtVI1sq3BbpXQ==
X-Received: by 2002:a05:6830:4d3:: with SMTP id s19mr15137398otd.247.1593658478207;
        Wed, 01 Jul 2020 19:54:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:544a:: with SMTP id i71ls957342oib.9.gmail; Wed, 01 Jul
 2020 19:54:37 -0700 (PDT)
X-Received: by 2002:a05:6808:687:: with SMTP id k7mr23121807oig.18.1593658477917;
        Wed, 01 Jul 2020 19:54:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593658477; cv=none;
        d=google.com; s=arc-20160816;
        b=xEDP5JywlqvclqvN0YH5UYzOhQAAlYj6zp/Fr5HeKQv1BouaBQ+542e+CRd7BdIc2n
         RRAXE9nIdpsSLECbX4dzgdq0P+PmPoL6l6vyVhTm9EEvqWLpTMplWF/hk0vA9qy41vAd
         gYIcTTyJHj6YubDPF1sBACf3PYTBc9ZYjoclUfc2VtTW5EbkrK1IWihecPdhB+T32hK0
         IepQxKxXDzal0MayYg0iNPJaJ5qCkFwJgesm/uruWpfh9poV1MWZROhyGN096iKLR362
         L7xGYlM0XVxHg8d14PQFC7nUkUQ1O8C7LNaajQ5NjfZSE8rxsZMV++QN3e2Je0L274Lf
         EM3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hmqaZJTWyrZ0FbjDXm8RaPiEdszyKtA9q/J035BPFVA=;
        b=oTi1dKtPe3QxGHgLzqfCeUq1rvBLRHj3vpwyzf6z9NWTWwm/NMwGs0ZsLfVN08LRvD
         rOd7O4IwOeWQ5FQJRpupkxoP+2E3CEJQhqq3+8gqEfNpyoem0ap2gGJlVYbsgTL3QAcW
         E+ggMAKYWEVbRyNv28qvR2jiAt8f9o1Q3AqNwiIzfVXi19/WtXilSDY9Gmp+A2DqDSst
         4aFdvU68WBYUSenAlnptBd/+wybgshAFWNehAtC5U1u1h886Bea2KvBP30RWwYDFdR/i
         OQWLW7RRpA05O+DxOPsmBrUx+MpkY0JKKGMLbwdkdX6Uk72XH+EIvHHcngd+p/4EDiBe
         H5iA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=cP7JTsXr;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id y66si490655oiy.5.2020.07.01.19.54.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jul 2020 19:54:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id k71so8287121pje.0
        for <kasan-dev@googlegroups.com>; Wed, 01 Jul 2020 19:54:37 -0700 (PDT)
X-Received: by 2002:a17:902:6bc1:: with SMTP id m1mr25456864plt.158.1593658477129;
        Wed, 01 Jul 2020 19:54:37 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-3c80-6152-10ca-83bc.static.ipv6.internode.on.net. [2001:44b8:1113:6700:3c80:6152:10ca:83bc])
        by smtp.gmail.com with ESMTPSA id u26sm7243117pgo.71.2020.07.01.19.54.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jul 2020 19:54:36 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 0/4] KASAN for powerpc64 radix
Date: Thu,  2 Jul 2020 12:54:28 +1000
Message-Id: <20200702025432.16912-1-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=cP7JTsXr;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as
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
KASAN to 64-bit Book3S kernels running on the Radix MMU.

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of physically contiguous memory
on the system at compile time. More details in patch 4.

v8 is just a rebase of v7 on a more recent powerpc/merge and a fixup
of a whitespace error.

Module globals still don't work, but that's due to some 'clever'
renaming of a section that the powerpc module loading code does to
avoid more complicated relocations/tramplines rather than anything to
do with KASAN.

Daniel Axtens (4):
  kasan: define and use MAX_PTRS_PER_* for early shadow tables
  kasan: Document support on 32-bit powerpc
  powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
  powerpc: Book3S 64-bit "heavyweight" KASAN support

 Documentation/dev-tools/kasan.rst             |   8 +-
 Documentation/powerpc/kasan.txt               | 122 ++++++++++++++++++
 arch/powerpc/Kconfig                          |   3 +-
 arch/powerpc/Kconfig.debug                    |  23 +++-
 arch/powerpc/Makefile                         |  11 ++
 arch/powerpc/include/asm/book3s/64/hash.h     |   4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h  |   7 +
 arch/powerpc/include/asm/book3s/64/radix.h    |   5 +
 arch/powerpc/include/asm/kasan.h              |  11 +-
 arch/powerpc/kernel/Makefile                  |   2 +
 arch/powerpc/kernel/process.c                 |  16 ++-
 arch/powerpc/kernel/prom.c                    |  76 ++++++++++-
 arch/powerpc/mm/kasan/Makefile                |   3 +-
 .../mm/kasan/{kasan_init_32.c => init_32.c}   |   0
 arch/powerpc/mm/kasan/init_book3s_64.c        |  73 +++++++++++
 arch/powerpc/mm/ptdump/ptdump.c               |  10 +-
 arch/powerpc/platforms/Kconfig.cputype        |   1 +
 include/linux/kasan.h                         |  18 ++-
 mm/kasan/init.c                               |   6 +-
 19 files changed, 377 insertions(+), 22 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200702025432.16912-1-dja%40axtens.net.
