Return-Path: <kasan-dev+bncBDQ27FVWWUFRBYVC3PYAKGQE67M7CSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id AE61813537D
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 08:08:19 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id 24sf3548893qka.16
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 23:08:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578553698; cv=pass;
        d=google.com; s=arc-20160816;
        b=mYq8K1u28qw7KIpaXIbEP9YCDzxdYUiKmhVpGHyf7wp4AZTggymoDTCiTx67iY8spv
         K8cnBeEgHCYNtWGpsBvXjKsf3zLDiN9FeB8lZ5OCagFoSGoSKcyy3bVHen6nAm2X+eCb
         wVr4Ll/C3X6qTFxWuLkZz91ca135TCYdw/etNaURrVeX+TOoOltcvrmEqdRFN9KjevUm
         Bard2D4Dfcgu5zEFI7a2Vw9eLr5xKrWXbvLtuQGTcGt56DBoZDcTSWcRPGZ5UeR6HnPx
         CGUshQfohPMvMw47fBox2WfCQN1IBnoLKKVNfhBO1nh8JxdpdjVgcKf1PHud5bbSDHsC
         +CMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PD3EQjHUD1t0HlmwvHRekVaJxT5zUB2sIGy4U9NFkDs=;
        b=jQTXaq3YXHwl4NebzqdDOZQO50vp8taG61/0TF3hT66qExLvaFF2GkydkImINZS2a/
         I3ofMLM1l90qv1hH8CVctqszjfQ+kTbinzx/iKrnw+7grOHaZzN7fyirSuzwFrwzMMtI
         Zj2JV2VW3h+pcRLPvdFAVLMFdkC3VnV0ozTo8CWVBmUZfI25kDOiw1YbOHRrRCn4YQsP
         f/n0xjc2/3/KpRGL26uHFe1ckW82WFEFvyGemc1XAIkeshFQV1Qhl7qS8U/JvtXwHhpY
         vD0LqEyTWbN5gm7bVv9Ac053XgiP8BH+LRVSCu3m1rExKCo8laoMz5+dGsDJ5/ufQ4Y7
         0oRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=X0mwyBro;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PD3EQjHUD1t0HlmwvHRekVaJxT5zUB2sIGy4U9NFkDs=;
        b=Y7LNZDa/KmUFUZ/CV42kyHfKBfaKHf7LVRdXUgz0Eybj0ypZuTMpeYcYVPuYbZpsUV
         qvehElNruZTbGgT4fq+YIyLUCPjcTn4UW5RL2gBecRixchvg1/QkBhFNLlkW2AAL6xFM
         eGBc4GngdN5x2ARpIIsSNR82sRqk9z3dNIiCmdWL3ZK+O8UbgoLGjWoKB9533MhApAm/
         3otoR7Q1EnOquUWvCF9AXVnWQIeWjDAjX+RylYPwYZnJa+W7ot+C1n1kE1ipx0kBSc46
         tJhxR8YRO0GGue255cHuYYOs7WuwXP0uuv8Zz2tL7C+dAhVmak8Ow/LnXNdJYP4iN3Cb
         a4Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PD3EQjHUD1t0HlmwvHRekVaJxT5zUB2sIGy4U9NFkDs=;
        b=OdGT5u2ZIru9gzbY44ID647kHpv6XXltT2LAdYzk3nRh6AmN9s14zTMWLRcRsp3/PB
         /uMD5UfT4mbQPTqB1UC82ZVfCNQOxZ2lY27EgYkyfQrRsWO5jZWVjGw1zK/5pOs4GP4I
         KGwl8DdYWQDb01yrEZlXTwBuL5LyeG7AFPXKhZN/o9Qtgs7m1Wcgi7uTlDYOcgCZ2UEe
         mGdMqdrEvLH0uX4CGpiEmK8vfYM/8RQThOsezqvY7xPIqLq8e/AMTuaPYxKNoCO19Jtt
         ylosM+J6im32I9Fgxna61X3LT70QwxJxcbja5iI1A42rxH7R8EDgyFdh2QL7uADMWGoe
         pOfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUT9j5/BcOQLa3ydJkFlbtPq5NJH1czcMnPgA+1H0TbMX7/fDYa
	12lzFv77Bt0k71Ylh2Mjigw=
X-Google-Smtp-Source: APXvYqxsvFXy+QBtJVVC3AzGggXQEqrbQI15jlSIEWbQ7hv2wzfYfeKC235iPhuPr7fMai/nsjYaLQ==
X-Received: by 2002:a05:620a:13a1:: with SMTP id m1mr7847687qki.67.1578553698448;
        Wed, 08 Jan 2020 23:08:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3a07:: with SMTP id w7ls339575qte.15.gmail; Wed, 08 Jan
 2020 23:08:18 -0800 (PST)
X-Received: by 2002:aed:256d:: with SMTP id w42mr6803254qtc.385.1578553698166;
        Wed, 08 Jan 2020 23:08:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578553698; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJHNbRn3LpVMldAAdTl2pC5hL9v3QibmyYzqTbJwsp4Af2lqlc69PPkrVY2azpsF7Z
         Qk+j2Lk4ckUthK7mbMwfy9PSj0vwvr/aiO+482JTI0GV2tiacZfq3sYsnyNQZKuNMLYg
         ZXFdKe8tDe9+DtmDy/7EeYN5p1Jtypmrsr2YL3pzAA30f/KXUoRMRslIVqweoKAEQrDY
         lh17R++0LefzJJMcEe1hNX0FPdde3j4HCmg/SO6lMpx2KMy8m1cYzakppptdbx82oeW8
         nGlSiLyIV/GWqkQ66dGBbpgLmG4ZmFCs1i4tO1rVXZJY5QzJVsiHVgRBfbmh1vqMF8PZ
         O1Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=T66c+Moc6bo3p93sqP0BtCTOoS4UuskhqiuSGC0rhF8=;
        b=LHLesjc7yXr0CjrR9lVY2Rq0V89lQGBMHPlQ2MGKjjGZNjXOl1Tkcz+PM1IaTOFdnt
         SB6HiOf8Gy5LhpbqOXHq2UShMJatMpoenfB1ii3mzd1kO+0pRtL9IPCOEOldHsX6H3mr
         mkGMDN9u+rQMcbtKyxYbX0MZRTeEzN0iaMZu4A99Xz9G/lVEPsyAJ/I7afkZJ/y7nKrS
         Gd39AvPpDUWTYwtbxduGToiHxUNm8QuG8iFScfuSM0ZR6F9pNsvwAUkvJ3bHbxYOOvY9
         JsIR4FcAo27cltAVDM+QDcA7PPZDPBcG8SOHQPtGlA0NC3aiVD8GhLMbpxNAiWeSJxyt
         209Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=X0mwyBro;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id g23si270778qki.4.2020.01.08.23.08.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jan 2020 23:08:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id s94so651445pjc.1
        for <kasan-dev@googlegroups.com>; Wed, 08 Jan 2020 23:08:18 -0800 (PST)
X-Received: by 2002:a17:90a:cb83:: with SMTP id a3mr3531968pju.80.1578553697170;
        Wed, 08 Jan 2020 23:08:17 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-5cb3-ebc3-7dc6-a17b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:5cb3:ebc3:7dc6:a17b])
        by smtp.gmail.com with ESMTPSA id i23sm6139143pfo.11.2020.01.08.23.08.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jan 2020 23:08:16 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v5 0/4] KASAN for powerpc64 radix
Date: Thu,  9 Jan 2020 18:08:07 +1100
Message-Id: <20200109070811.31169-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=X0mwyBro;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as
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

v5: ptdump support. More cleanups, tweaks and fixes, thanks
    Christophe. Details in patch 4.

    I have seen another stack walk splat, but I don't think it's
    related to the patch set, I think there's a bug somewhere else,
    probably in stack frame manipulation in the kernel or (more
    unlikely) in the compiler.

v4: More cleanups, split renaming out, clarify bits and bobs.
    Drop the stack walk disablement, that isn't needed. No other
    functional change.

v3: Reduce the overly ambitious scope of the MAX_PTRS change.
    Document more things, including around why some of the
    restrictions apply.
    Clean up the code more, thanks Christophe.

v2: The big change is the introduction of tree-wide(ish)
    MAX_PTRS_PER_{PTE,PMD,PUD} macros in preference to the previous
    approach, which was for the arch to override the page table array
    definitions with their own. (And I squashed the annoying
    intermittent crash!)

    Apart from that there's just a lot of cleanup. Christophe, I've
    addressed most of what you asked for and I will reply to your v1
    emails to clarify what remains unchanged.

Daniel Axtens (4):
  kasan: define and use MAX_PTRS_PER_* for early shadow tables
  kasan: Document support on 32-bit powerpc
  powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
  powerpc: Book3S 64-bit "heavyweight" KASAN support

 Documentation/dev-tools/kasan.rst             |   7 +-
 Documentation/powerpc/kasan.txt               | 122 ++++++++++++++++++
 arch/powerpc/Kconfig                          |   2 +
 arch/powerpc/Kconfig.debug                    |  23 +++-
 arch/powerpc/Makefile                         |  11 ++
 arch/powerpc/include/asm/book3s/64/hash.h     |   4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h  |   7 +
 arch/powerpc/include/asm/book3s/64/radix.h    |   5 +
 arch/powerpc/include/asm/kasan.h              |  15 ++-
 arch/powerpc/kernel/prom.c                    |  61 ++++++++-
 arch/powerpc/mm/kasan/Makefile                |   3 +-
 .../mm/kasan/{kasan_init_32.c => init_32.c}   |   0
 arch/powerpc/mm/kasan/init_book3s_64.c        |  71 ++++++++++
 arch/powerpc/mm/ptdump/ptdump.c               |  10 +-
 arch/powerpc/platforms/Kconfig.cputype        |   1 +
 include/linux/kasan.h                         |  18 ++-
 mm/kasan/init.c                               |   6 +-
 17 files changed, 350 insertions(+), 16 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109070811.31169-1-dja%40axtens.net.
