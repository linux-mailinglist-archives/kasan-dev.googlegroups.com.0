Return-Path: <kasan-dev+bncBCT6537ZTEKRBYUJSDDAMGQEHNOADBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 66BA3B54B03
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 13:32:52 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70ddadde46bsf36270466d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 04:32:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757676771; cv=pass;
        d=google.com; s=arc-20240605;
        b=DDfqD+rADzVEk8ru+hPY32KADe6dLCl5sCdQGPdEJkjYX5vDVnFGzfzg79f0FvCSXi
         X76s4JaBeRAunFXWfWkR3SJNn1iMa+zzJ8OeDI0RG4qJxZZ6g2xsPlTUQr6QaPKDqorm
         yRc9FBvhgVJ1UZgjhb7Pl3P8KuUVH4Z5vsC7hXcAJHkCHlLUTVt3/Uo11v4N5MhUQ71A
         3/qyrzblogGxJwKos1nWjRtMJpR78ggHcY2KPZAHGOcON7/zxGJGOA7uMD0yg4LGHGuv
         BOogIfYyKdCbJ+cnDabws1zs+2GKimFjaf0zHvrMumu1+nhx5m9Z0u3MCasTUE64ArwV
         5ZPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=XKQmrDU7Rd/RarCdwH96+g4frwwY+MgFew7EI/+CiME=;
        fh=mPdMp9EXUl83o+IexCkzeebO11n0kS9NE1WSaKV7pLI=;
        b=YUyuTXeGSuRmebC7OSFBIpJsoIo7V7Prr4pyERqlMKY2oyDC4AloCLFXLr6pWLX4LZ
         BQS3drEQk9mJSaZv8K3aa2aBuN0AiXG+C17bGqtb6WBZpQHGgHHFqoVl4+YZAJnxV9Cr
         nOywcgddJGH0LNYE8c9rMrCB2HzvZjz3Qj9va2dmWNvIkv/OIgX/qvMj9XhCQK/N8yIo
         awdWQsLtBj0/kxWydWtIHfl7WzTwyy/jNMpGVREeJPB2mTCXFoMb6RU6dSw8wuzANeJz
         4ke9gjSCjG9P71on1fBbnbWTACmHvAdcFHWSRf0BSAKeY1ZC4B3Rib8GP9znWgyDumda
         1nIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ntNmyy0S;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757676771; x=1758281571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XKQmrDU7Rd/RarCdwH96+g4frwwY+MgFew7EI/+CiME=;
        b=E8EGz5xfQ3GvdwP3oO/7R3K45vpKORqRY/fwqCCrdNjpiRAkX7/Ms7TkPZD9TCBBjB
         LwuF/WQHpKr1blni5Z09AJm0xuAGgQrtyDZWWvPYKQ+nNeHQlN5belXBIvbVFcDdjdYx
         OuBKQzVf+jMV4rmVzJGUR/taNtZGstcMuTV8ImFo+cBfeNqEQU9gGDCKP67p0IS3j2tz
         Fs2GSsBELhIiYcqf0r6Wf5v+fxtXBgZ3dp6fnvGZYAqUSCCh/d9EUdDVQ1Ggv8Wqhhqw
         6YizgxpA9GtYsBFq75KI0L2ibPlMzQnwLjwbewoET1ZfsDqIwe/pNp1r1pc682Br1It7
         QBOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757676771; x=1758281571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XKQmrDU7Rd/RarCdwH96+g4frwwY+MgFew7EI/+CiME=;
        b=h7lLutaSemjP7Bgzj3ON568c2WZ6L2JZzWUJwfI5JsfnzG8Vul7Gxj3bx1wkol6QVU
         6uY94YjcbOSqYUna0uL4mRwQDqrs4yBDbCREa4+cHLReYmQGiYYwfq6VEBHp03+bRIim
         uHBydNmjU3eJghJ5AC4od5CjJMRgxrqBiKN0UnO88ny5dLTLkcOXJ1looADt+ze1vDRy
         j6LsPF8nUZY/1Hi8/9tFG2u8nKlBYsMiLBKBIUxUkfOZaoL00dhKB+CpyA8GKczdUeUM
         brOgntyk2kE3FAdEN9IuylJ4rxQucnBnzWbNprwqO+gyPCW/57pMApyOEJl13govz+1t
         mQZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjqaEb20Tj3/A2R6+qzkzbvboRuWyC7X81fHl2ZdqDz9McSJYWR4KSht9P4gHB5/kkI08cRA==@lfdr.de
X-Gm-Message-State: AOJu0YweFHNeFsydkprCyncPhn5O5JbdgxpQoYEzsmLt6rCBtWFOIBhV
	eHXrfiAj7iG2VhgWDm8BKMbJmgc6m6PmM8MUowifm6kAyFx7KS56ZDGA
X-Google-Smtp-Source: AGHT+IEFGZpZB21j6DmJ287jssjMgU5eVx8Y/YYRFaENKl+BttxMwyz6+U0d5azYPhlHfJXwlO9upw==
X-Received: by 2002:a05:6214:2524:b0:70d:cb0a:92ee with SMTP id 6a1803df08f44-767bc306d9fmr37676016d6.23.1757676771076;
        Fri, 12 Sep 2025 04:32:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd62gSA0Z4tAPNFRHlvUurkgBXzO1q08nuNej0EbQ4Nobw==
Received: by 2002:a05:6214:d85:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-762e47c0ab3ls31946216d6.1.-pod-prod-01-us; Fri, 12 Sep 2025
 04:32:49 -0700 (PDT)
X-Received: by 2002:a05:6122:1d4d:b0:531:4041:c4c7 with SMTP id 71dfb90a1353d-54a16baae49mr685070e0c.7.1757676769391;
        Fri, 12 Sep 2025 04:32:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757676769; cv=none;
        d=google.com; s=arc-20240605;
        b=RcXtI5nnQfNYILgZW5kQtB74r5nJ9u4JFLab01j16HQpHfL3HaptzEIUhkcReEnauF
         1WxN8mTHnoQdBt0m6JEkAU3ZVSww4On7GF08UNGZMJDMkwfxwPfD2jwMPYFRJEuz7vWk
         VvsJtx9y5DT+NuquJ5Hb3/cWca06SrVwBc81PGF3xwz2IEsjOA2B3JkBDis9aIXRJ8LJ
         KjJhurc9yU2uo3CFMNfg7rKYsLZdUDTYExayX4Z1vEW/tXC0t9eodt2aE7yP4Uu0Watp
         F7fePoNcRbnjAqajTGpNoYP/vu4NIrag/8xvqM+h52GZRzmKm2Ub2+Dz95H/XRlvyUk0
         sbBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=y6Vu9krI8L/L917eJRdmIwH3Jf+YuSh9fi/gZdnGGTM=;
        fh=i+wcg3wcWN/PFM5Fc2ECW6aLI5UxIdYvoVScs4ZPYFA=;
        b=PxxoV+Gf0UwByAGiE9zmb0yCU8kIZ8/940b1jllbmKgNseUatmOivAkJU8H2t5ITV0
         o+wKJzIERqgqNMVxrUjG92m5iIjgJpg87W6QI8CLJDjqP26TwHny/QrCM+r8ybn/d1rk
         0rqssrQHdWCRjsho3DhhNECbIpcF8KBT7BcUNmWdrQWFGFuEgs0lTClEJ2sMgZMpvHgZ
         kteYRYnZgMyQNJ8qJS1LDRFZz/jTrgTP9ejwmjnS5Gaz4iQhsNOcZ7s+zkF3/F9cswo3
         Uc0Ws9FFDpe7k/Sn6D12QPqN3v6Mzr67ZYEiweh6/hwSz2qrENMI/8eDEz4y1y7vJ+Dw
         xs3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ntNmyy0S;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54a1706318fsi86973e0c.2.2025.09.12.04.32.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 04:32:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-b52047b3f19so1286694a12.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 04:32:49 -0700 (PDT)
X-Gm-Gg: ASbGncukJ1s7Yp/JTzwm7pWb2YY+uA+vDnmzQYCsyKXxNCUW70j2kS4QPpIhhXn/8x6
	TYGv1rZrmkUVvNB4oRlDw1EoV/VVup0gWeDO3nBR4xM47XyXyXL8nXi1XFxy5J8Fi+QteLYwllG
	Bf9DfrzrAE62/LqJmVRYv3LNJS3fyN4Ii1IBTr/J8+JCGCKtwTc93pykXXmhWhRF2KgqhGV/U/R
	qEmHlSNatUkMMfhNffgKGHmDSFLVJP/fS0m+84vW0vYg6avUI21wJU1gWR3TCaDSw1C1qE3lH+T
	o5lnTTM=
X-Received: by 2002:a17:902:c40d:b0:251:a3b3:1580 with SMTP id
 d9443c01a7336-25d24cac4eemr35190575ad.6.1757676768437; Fri, 12 Sep 2025
 04:32:48 -0700 (PDT)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 12 Sep 2025 17:02:36 +0530
X-Gm-Features: AS18NWCRkwK2BEtW0uxWjqehT8uEFjWUmULflZWeqoftij31KvQE0_RmSXQs-jg
Message-ID: <CA+G9fYvQekqNdZpOeibBf0DZNjqR+ZGHRw1yHq6uh0OROZ9sRw@mail.gmail.com>
Subject: next-20250912: riscv: s390: mm/kasan/shadow.c 'kasan_populate_vmalloc_pte'
 pgtable.h:247:41: error: statement with no effect [-Werror=unused-value]
To: kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>, 
	open list <linux-kernel@vger.kernel.org>, 
	linux-riscv <linux-riscv@lists.infradead.org>, linux-s390@vger.kernel.org, 
	lkft-triage@lists.linaro.org, Linux Regressions <regressions@lists.linux.dev>
Cc: Kevin Brodsky <kevin.brodsky@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Dan Carpenter <dan.carpenter@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Anders Roxell <anders.roxell@linaro.org>, Ben Copeland <benjamin.copeland@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ntNmyy0S;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

The following build warnings / errors noticed on the riscv and s390
with allyesconfig build on the Linux next-20250912 tag.

Regression Analysis:
- New regression? yes
- Reproducibility? yes

Build regression: next-20250912 mm/kasan/shadow.c
'kasan_populate_vmalloc_pte' pgtable.h error statement with no effect
[-Werror=unused-value]

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

$ git log --oneline next-20250911..next-20250912 --  mm/kasan/shadow.c
  aed53ec0b797a mm: introduce local state for lazy_mmu sections
  307f2dc9b308e kasan: introduce ARCH_DEFER_KASAN and unify static key
across modes

## Test log
In file included from include/linux/kasan.h:37,
                 from mm/kasan/shadow.c:14:
mm/kasan/shadow.c: In function 'kasan_populate_vmalloc_pte':
include/linux/pgtable.h:247:41: error: statement with no effect
[-Werror=unused-value]
  247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
      |                                         ^
mm/kasan/shadow.c:322:9: note: in expansion of macro 'arch_enter_lazy_mmu_mode'
  322 |         arch_enter_lazy_mmu_mode();
      |         ^~~~~~~~~~~~~~~~~~~~~~~~
mm/kasan/shadow.c: In function 'kasan_depopulate_vmalloc_pte':
include/linux/pgtable.h:247:41: error: statement with no effect
[-Werror=unused-value]
  247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
      |                                         ^
mm/kasan/shadow.c:497:9: note: in expansion of macro 'arch_enter_lazy_mmu_mode'
  497 |         arch_enter_lazy_mmu_mode();
      |         ^~~~~~~~~~~~~~~~~~~~~~~~
cc1: all warnings being treated as errors

## Source
* Kernel version: 6.17.0-rc5
* Git tree: https://kernel.googlesource.com/pub/scm/linux/kernel/git/next/linux-next.git
* Git describe: 6.17.0-rc5-next-20250912
* Git commit: 590b221ed4256fd6c34d3dea77aa5bd6e741bbc1
* Architectures: riscv, s390
* Toolchains: gcc (Debian 13.3.0-16) 13.3.0
* Kconfigs: allyesconfig

## Build
* Build log: https://qa-reports.linaro.org/api/testruns/29863344/log_file/
* Build details:
https://regressions.linaro.org/lkft/linux-next-master/next-20250912/log-parser-build-gcc/gcc-compiler-include_linux_pgtable_h-error-statement-with-no-effect/
* Build plan: https://tuxapi.tuxsuite.com/v1/groups/linaro/projects/lkft/builds/32aTGVWBLzkF7PsIq9FBtLK3T4W
* Build link: https://storage.tuxsuite.com/public/linaro/lkft/builds/32aTGVWBLzkF7PsIq9FBtLK3T4W/
* Kernel config:
https://storage.tuxsuite.com/public/linaro/lkft/builds/32aTGVWBLzkF7PsIq9FBtLK3T4W/config

## Steps to reproduce
 $ tuxmake --runtime podman --target-arch riscv --toolchain gcc-13
--kconfig allyesconfig


--
Linaro LKFT

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvQekqNdZpOeibBf0DZNjqR%2BZGHRw1yHq6uh0OROZ9sRw%40mail.gmail.com.
