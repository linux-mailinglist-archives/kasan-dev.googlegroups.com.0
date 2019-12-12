Return-Path: <kasan-dev+bncBDQ27FVWWUFRB35TZHXQKGQEU6LKZGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D6C3B11D0B6
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 16:17:04 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id r127sf1022056pfc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 07:17:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576163823; cv=pass;
        d=google.com; s=arc-20160816;
        b=sIUWMR1SNh3PSzz2Kz7AOBeGfj3BXwYk3gDtlsS6luZFygltw9bct+lGnxMjpYfIQB
         d2WsETVDFJk3c0llWqqFPjK/+efQkFT98wGPmld3H6SRVxC8XLSeTbK0b4ftdjnwU+Vu
         OkL1paxh/7Ed0P2QJx2LAVGu0HoY9AXgoZ/ySYkvA+m16Gtsz45gQAN3GQZxojtlHxX0
         EuVRxmJ6wfZIVD2ql+pCJvA1W+lsibRgNLrZrXQ7LDLqP1JUVy/Jwc8MZaJRGTJm/QEV
         0M4648PsqUJko7RQVbcySpT7nrU7mtFltGa7VX/S+pJGf1lvbVa9n/gNmjcMo00PTMvF
         rTAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=IjHLj8cVIu8gtDe+PCmr1qHddwFfAfZXbXsv9SRvBQ8=;
        b=0AdqkArTfMlXszHc1z7o8ClN8grajVVIvlKZcVgGHliFD8P/OyrUpVCI26zQvPjVkA
         s8gTUb5+RPR07yn2ZoSUkbWvA48QwVOmO7bMn+qBgJxnFdCYXa4IKYg5TxWRjbYm0tRu
         1hRdQ+a9CZrm2O/W9G6hCRbka3jcgxetAWdfTig9Nj1ZTHEi4rxcUFDWoN8qrdJBpelE
         JxEp5NS4eEA5kX4vv80Oy2VuiTvSm0YYD79ywDW65P98BBptM60r6Z1/pvGy+KcPNM/3
         8lnw4hAyYqoN9haJKIng0cQowXsnRZN0gz2P3AtuEqQqHCTs+Okopmm1y4ozlnkpZG5u
         VgnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=q7DQztUh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IjHLj8cVIu8gtDe+PCmr1qHddwFfAfZXbXsv9SRvBQ8=;
        b=ptMNDGmWWc4WNZoxSCg4lE6xO3YhswZ5EtO3B0ls/gjtjIDtoAq+d/BCgKDgSGtGrV
         G6AHHGN1YrYuKlZZGkWeHGQXIZOZq0FNh5AxoIGxE7C1MVa5sdZqjV/8OpdrodPlM6FJ
         3sZPIyz1TrMvvsW2tAfMo8sjpjf/zlyPGRnmUI4stBkij+ah9GsaYeNRwZceP9kxmGpU
         VXiipZBYyjHxH4vUwCr3sCt2XZQ+SDU/DVQZ1h71wfcS9xzFYk+gJ0vNYbAJtii4XMri
         OPMnPLg8W8cruKpK1dHHDnIif9sP0k7q+SUHz09FtG1gYyIeFvdOedF9tllu5XnBJWSe
         q9zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IjHLj8cVIu8gtDe+PCmr1qHddwFfAfZXbXsv9SRvBQ8=;
        b=OJF7yClTxw5PW+v9xmfb76odpJuNh+C0tWPmtYnJyLVvF0sWJ/JKQz6H6duu6dp82X
         m+42hVLxSQ9PCs9p1XysY7rLXO8p8bp0C/Upp+A6p1EVeRcd3ixvMJhcGylPrCvSz2u7
         RWrquMbJhKHAKxjdI8akRSJu7xReH1bvX+DsQpszaFsf7zVfA/miBhxeEBzWqRbymlvG
         wKXGfe80J9jBhMdjhisQ//vWtBaC3SBcDSv/kKkPxq0IBiZ661DO9Yp2JMIufkNatzi/
         d3ktdE7+3A9wA6cq/vnAXRjmO6N1NOiMkmt8khai1r1tMcRc5rnCzqlhUGdVvh3d3S/E
         7PRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAULDJJZWWbsyAO4HjD7wqamLvamlyOHpnzDxuHSRBiCZJXbNMy3
	PymVqRRzy+gcQDS9EFMmGaA=
X-Google-Smtp-Source: APXvYqwzt17SaIIh/jGwqUWFMZcb4uCqCgtbQqZMe0feoFPRf9k+HU3vgrI7H8+cdI/U3XUXF2YORw==
X-Received: by 2002:a17:90a:a386:: with SMTP id x6mr10765784pjp.116.1576163823093;
        Thu, 12 Dec 2019 07:17:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ab0b:: with SMTP id p11ls1596187pff.0.gmail; Thu, 12 Dec
 2019 07:17:02 -0800 (PST)
X-Received: by 2002:a62:382:: with SMTP id 124mr10517908pfd.11.1576163822760;
        Thu, 12 Dec 2019 07:17:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576163822; cv=none;
        d=google.com; s=arc-20160816;
        b=pyl80oeMQCEoKMW+r0P1xo/DekY/5U48TSUIQrpexBlgP0twOyj0/rLgrDip4/2pNj
         S80oMgCCGD60UQzIMDaRycHJM4HcyEs2lvjt0bDy7nII0OneVwMSbX3VB/XJ3AtdPTje
         8EW9g/wvwQEQ+wenZXZ3hH9vqzZY7GEx8BZjejZa9GWo3lg519REdD56Ha8HJs4LcA0M
         iEOau/9g4+I0tgs7OptGgq9AXbsAoF/f/s0Re2RZlP6HNxzixkTVcSWY5NOgVxwDt+V2
         1sM1/9b1sECmzYSRX6UDvYcZ64/DGdlIqt8kiLcsvcVLGjOtotsfyCAI34j/U+ws/TA0
         CqGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=v26BsJHtOrSEIqcupCpn6pVHwbqhLlNjRKE6OChruw8=;
        b=newxplfDzX8sLCLspZBWCQ8I7xvd2zTBMhlHsiJgwC20SY3edKQK9n7CAwtncEpexS
         u7avIzIe1zD6pX0ARBP9maK5E10YWaJaEmpYWKrCrXXJUxrmuy7aFKDdiqlE466E7AT0
         9/2jt3JyBW+oBr1VLJ0p7RsCejAUtg3Acg/Q0BvsL6Gge1i9zTKr4BBvsECkkD5dhKeK
         uHSJRk2j5UKdgJ8e2yhNlaGBIxUU5JN8g59h6abanX8hck0S0WeJFhDwwOSIt5uTxSKn
         ncQITGZXjpvDMuFzEBv0pH8e031al0T5bZF2lbnsBZgAf0gv05kYc9rLfURQlJRWAoJ1
         uaFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=q7DQztUh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id i131si280180pfe.3.2019.12.12.07.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 07:17:02 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id k3so1305237pgc.3
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 07:17:02 -0800 (PST)
X-Received: by 2002:aa7:90c4:: with SMTP id k4mr10406197pfk.216.1576163822527;
        Thu, 12 Dec 2019 07:17:02 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-b116-2689-a4a9-76f8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b116:2689:a4a9:76f8])
        by smtp.gmail.com with ESMTPSA id 5sm6415205pjc.29.2019.12.12.07.17.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Dec 2019 07:17:01 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 0/3] KASAN for powerpc64 radix
Date: Fri, 13 Dec 2019 02:16:53 +1100
Message-Id: <20191212151656.26151-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=q7DQztUh;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
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
on the system at compile time. More details in patch 3.

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


Daniel Axtens (3):
  kasan: define and use MAX_PTRS_PER_* for early shadow tables
  kasan: Document support on 32-bit powerpc
  powerpc: Book3S 64-bit "heavyweight" KASAN support

 Documentation/dev-tools/kasan.rst             |   7 +-
 Documentation/powerpc/kasan.txt               | 122 ++++++++++++++++++
 arch/powerpc/Kconfig                          |   3 +
 arch/powerpc/Kconfig.debug                    |  21 +++
 arch/powerpc/Makefile                         |  11 ++
 arch/powerpc/include/asm/book3s/64/hash.h     |   4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h  |   7 +
 arch/powerpc/include/asm/book3s/64/radix.h    |   5 +
 arch/powerpc/include/asm/kasan.h              |  21 ++-
 arch/powerpc/kernel/process.c                 |   8 ++
 arch/powerpc/kernel/prom.c                    |  64 ++++++++-
 arch/powerpc/mm/kasan/Makefile                |   3 +-
 .../mm/kasan/{kasan_init_32.c => init_32.c}   |   0
 arch/powerpc/mm/kasan/init_book3s_64.c        |  72 +++++++++++
 include/linux/kasan.h                         |  18 ++-
 mm/kasan/init.c                               |   6 +-
 16 files changed, 359 insertions(+), 13 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191212151656.26151-1-dja%40axtens.net.
