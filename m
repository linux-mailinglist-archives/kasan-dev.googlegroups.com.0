Return-Path: <kasan-dev+bncBDQ27FVWWUFRBFMM5PXQKGQEQN6GPYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C7276125891
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 01:36:38 +0100 (CET)
Received: by mail-yw1-xc3f.google.com with SMTP id o200sf2686960ywd.22
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 16:36:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576715797; cv=pass;
        d=google.com; s=arc-20160816;
        b=pVe5u2lMuJCeVzWnuBuzr1gPqiqHgxuF/RhjqnOv92nEGQFkfApPL7Ap3XMuxsDk5B
         KbQZ0QaUgbfAxH7xJpWjgcyHmci4eBNefDW2lciUYRNMtPKBwSXBko5Dcz3MW+0+ZIGC
         boNHGWyzW8EwcPwWlbg51guwNHTpZG2wMfVvm/jeJS1yVK4+PDf2qOJnbnFNGfMb5nJ+
         AAMbHp6ReFFc1pmbzy62pYjcxW2beethUzUXwSkxfnjvxO8g6vk1ynxx087jOhH7/wr4
         Nf2gdhvPdF65xbRmfZ95WGK+hOx92z+9hprIPzBuFlX+TqINEtSw/Tbns1Yj2T218M51
         lpSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CVeTeFPT4c7d7MQh+iouH42wHoPAdRU20REeYniuUR0=;
        b=W5IPecd/LEF/+1+tVJZLayAfB7FdvSMWi7jmG116RSJmwDk1NpMXdOMC0/mVEAxr/W
         8uBfjIuud3BwNUPLXsvIaiZ+sHUTFCffsjGuiWH0BFcUAo6bncrVV370Mo8lvdAvEbtb
         0iieQGy9QZJ8H0zC4lq9BcPKRGG+EYMR5TYlApLCO5rWMKZ+J3B+AOwcegIct61dEOeJ
         ue/qVuaQq1C+lr3RRSp92fhJ2itVHzAexrmT4VcbkkrCN8/XQTZxHGL8bns0aGFrhj6N
         StFXzvcTMYs/ZaDyEM1RVVnpIDR2LeSs1l22L7+xDytdyVNcqZOk/FHVS4Do8uvm3bZb
         UdUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Dka6E6Kx;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CVeTeFPT4c7d7MQh+iouH42wHoPAdRU20REeYniuUR0=;
        b=ajzUGcbt0T60kjr//BASKkVN7mfVRwAC5CRJ2QxZi8dG3ncTx6t4u06Es9+O1MMHM9
         kKCaIcObFVZZLfmOJF4G8HQvaKUHRocTYZYzrKih7M3Hpf1nNQYf3O3yyniyox3hLEIc
         iU94GDX/bkZ4q/W/NieWrekYp5CE5Ahge298PojacaJYCpNNi0nMAzg5oNPWt2bcuAfT
         KzLXhgNftpEE7dYLz1tHfL+82hXpRqrYIJeJlB8S9eP1CWLOevk86cqER6QfoUIxQ4pb
         YiBw1Zf+pL8SG53iR3QZdBkTKal8lJE4dfyJbvP6BxfK0W44cNzuiS05HOs2gfU9J3PW
         sb9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CVeTeFPT4c7d7MQh+iouH42wHoPAdRU20REeYniuUR0=;
        b=qB6cKltTREN8ZabP8h0s268dNNqt1KzZnuoxP43FUH/AalTcQ7asGpTQs2Eky1AZJ7
         Q+wyfudEYLJaYPGBNxnVdUihel1l2zpMVA3KdykLdX5CRy7qhcbWKc1jhigOB6HRHQ/d
         cZSMKlinkZ3mUHylJiXFoQPR/ORXvHsncJr/i/Ww5n6PjPe6a7cUSssB363vj9Yn/UPt
         VoDD/dpDi5GiRuyXZs4T+RwdRK5PBYeD/9FtiX9wo95/aRKoa3BK0GwUrcdsuknqEyy4
         KcVmXUHolA58YAvCm6CarLnj+3DS5NEMKKAMoM4bus5JYFMSpFqOs8jIljdJIwtss/fN
         xPdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVnlvRcGbWMeA/8r+eY3ZcXY9QM5NLAfCPnApzjXP7fQIqlTiP/
	3ev5w+qHP8TtdI5IxLWe8l0=
X-Google-Smtp-Source: APXvYqxWCh0lnWIEQQu+uEeKXVn00SFb4FH4uZUaMvIPsywhjE16T+lTwVVsEU1quxT65cpnoWv/kA==
X-Received: by 2002:a25:7349:: with SMTP id o70mr4515290ybc.476.1576715797472;
        Wed, 18 Dec 2019 16:36:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c64c:: with SMTP id k73ls612856ybf.4.gmail; Wed, 18 Dec
 2019 16:36:37 -0800 (PST)
X-Received: by 2002:a25:c514:: with SMTP id v20mr4381774ybe.293.1576715797051;
        Wed, 18 Dec 2019 16:36:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576715797; cv=none;
        d=google.com; s=arc-20160816;
        b=zTBUrQFd/AMLSS++NPlF+M+x0NVn5LGU1QVWRlPe6vyqH594yJt1W7Aon8oUwzA7e6
         UDrzcGr55ihVUDpGD+rUsDW1W0RQyyLZQW0BQFw7TWqym851QC/H0iobUO8tZS0SmbM9
         uBLqSsaWgS249fuScVS6QRLPMWro8tjXRalxPobd/Y5i8o5NUciLXXZ4lt+Q3nEi6TwZ
         YQRD69vPvtbBsrd51LjDfRQqI8JLI3RP9ScIvrpsXkWLG0gzfc/XxZ9/PswN4OfOFXF6
         Uekc0WnKNzkAjsnb44uY6B3N3hwgzQVKstlH/FxEyWj32TNV1YS8ZVGiXUTMJUX372DU
         69ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5NTtETEykOhr2nCmuKVWtyUmiz45NkjCC1EiRzotiV0=;
        b=kYswxhhGvHegsx+jFh5QY0qP9sZWL95q+0q4S4E+BRlNhxdrdGJzh05j8+cQ1brMBx
         y1KEU6X2ouwEqe3FZxhYjx3TVBG+2JLRlV5tfLR9xsF/eOqFsaJGZ6yDF7nzc/G0114d
         X/v4Nl5hppyXp7vgKTyT5UEP5T9If7GhS88Z98Gyjd+mGvqAkRTE27EQdtk9h5I8Gp1v
         lFRbLU1WCykgphMPBkTBjGvvFIsmnNqBUXmAgX2OY9JWOBcvkcXtEPvmEKWBOIseeBB9
         RisRmbUTrBQ8mnUzgeilS63aEi1PvWH/ZGuxBmlDblGFyXvRf5N634qWTmdSlC6TrW+W
         MqRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Dka6E6Kx;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id r1si261659ybr.3.2019.12.18.16.36.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 16:36:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 195so1287296pfw.11
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 16:36:36 -0800 (PST)
X-Received: by 2002:aa7:93ce:: with SMTP id y14mr6301702pff.185.1576715796122;
        Wed, 18 Dec 2019 16:36:36 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b05d-cbfe-b2ee-de17.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b05d:cbfe:b2ee:de17])
        by smtp.gmail.com with ESMTPSA id l1sm4610430pgs.47.2019.12.18.16.36.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2019 16:36:35 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 0/4] KASAN for powerpc64 radix
Date: Thu, 19 Dec 2019 11:36:26 +1100
Message-Id: <20191219003630.31288-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Dka6E6Kx;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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
 arch/powerpc/Kconfig.debug                    |  21 +++
 arch/powerpc/Makefile                         |  11 ++
 arch/powerpc/include/asm/book3s/64/hash.h     |   4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h  |   7 +
 arch/powerpc/include/asm/book3s/64/radix.h    |   5 +
 arch/powerpc/include/asm/kasan.h              |  21 ++-
 arch/powerpc/kernel/prom.c                    |  61 ++++++++-
 arch/powerpc/mm/kasan/Makefile                |   3 +-
 .../mm/kasan/{kasan_init_32.c => init_32.c}   |   0
 arch/powerpc/mm/kasan/init_book3s_64.c        |  70 ++++++++++
 arch/powerpc/platforms/Kconfig.cputype        |   1 +
 include/linux/kasan.h                         |  18 ++-
 mm/kasan/init.c                               |   6 +-
 16 files changed, 346 insertions(+), 13 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191219003630.31288-1-dja%40axtens.net.
