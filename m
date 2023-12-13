Return-Path: <kasan-dev+bncBDXY7I6V6AMRBW5I5CVQMGQEVVZWU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CBB5811FF9
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:30:21 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-552233ea9b5sf448220a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 12:30:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702499420; cv=pass;
        d=google.com; s=arc-20160816;
        b=X3svHYXfWow6AvVmy2gHSrRUd7+/y6QBErbQOCn32GsA01cWqrWFFfTErHtjrPD0Qj
         blItS+5iCsfGfOGgaM4LSwsFtz8oTzDMGRRFflocF/QECzJjaPAN/PNUAkkKujKLLzMJ
         56N7WC/pl8pcTkgIwyZxcYrRkTOgN17YUyl0tM8n360bUHph5LZ3cMOgIg81mMI+2b0U
         0KSL4wJR/CP7FBNffkm2Bt+7xRno2FS2Z+Y4WX1ZmWpY0opgtiK8b+asOdtLYBl1Q0+f
         9nC1PEeEUtXPs4magVpEW9MKTeWuedpELgDCq/hgqrkLEMWceRL8nYH0c51coGUc4w2U
         ow6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=MhgjL01vXqApiNqkjgaw7kG+k0ykXOXHEXLTtwm/CYk=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=JYjEOTCxFJJqPOezGX6Qn01vNlSFu2l6kNEtmOY0DYc1j0KloMF6FnMCj37W4BOKvU
         XGDWfsVnZljSNwnjP0E/dEc3SQUui0ll/Gr+vo2tQ+yU4i3i9UhljmuG2Kp7fFIcLusF
         vch92+bKokp6NbfxYI+tMsTjmw4hTmLzVrWvnuTvsi7bmMhZ+EiDtk85TbgeWkT5JScN
         EuED8R8k0Ihv7mkK4deZuOCke6oF9unPghpg7SyMjQ3JYuvDlxR9UY3xczeVOBnYVzDx
         cv7yfIPr34U5r8/AWFQu2tNGqW3c2INiJvRJw2aWZ7UmqxCEtD4AQLDDutXtF5O9QxPU
         qj3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=QxkgXqvE;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702499420; x=1703104220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MhgjL01vXqApiNqkjgaw7kG+k0ykXOXHEXLTtwm/CYk=;
        b=XX/fPutXfUVESKF3st3mByDTOe9HjjH5PV5W/JklS1e1tDrGNzl7NtWEO6g+D+RcDQ
         8Udxr5gq1xvZmvFIj9kSdED305TSmKZJ73QPTl87bOwFq4pMkFnwghjQ42lhcSUK9KQH
         mWM0FSi2ekxXWMrt8hEy/T1Gf66o2LJZcpugXU9ZM145Z8Kb7KLgULVZ7UQ345/rpdUC
         9DDSaV6FoVaW9Chanig4U5ycWrlLlb7bzg5e6Gk84HBpEmixUqeoGiBCPB6GnZ/nUkuE
         GU8BK9l/6U9j1JcQF9PZdW/8PaOdzljr2E4lrJ5jo0DH+hbTPQ7Ep5kjQDP5Ep594GQu
         0GAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702499420; x=1703104220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MhgjL01vXqApiNqkjgaw7kG+k0ykXOXHEXLTtwm/CYk=;
        b=oSJcENaJIKlQzl6aAE20Ypwn6ncRzcMSd7mYz9a/cGVIJTIJonh579echOJaZhJO+B
         qkQwvTY4OffbNDoBTCcooJSIGYhXW6uvbu4F/DfccaVLJWY4UvlSwpykTmf7MxlaF/Jq
         bN0oK/4xxErZSp/bpQo9oPfa0V+iyHmUQ/NYBIQ2jNqy9FCbTze5rcMKIMDALy5jqQWG
         t/LgeexXzimRXh7PCShDurbztKLoR+crMxjt8UWbQhHij0PNmXF3fWU3yWRPqcDOzT/p
         QE/RiTR/jB96BnMC0EieH6qrC21vh0VKdjBUlDhQT0aU7ayWoS4nQaIZGwnTUE/FvHiN
         K9jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxbXBc7GrxHSeWyK3WNwi+k9NeO/mFXa/WRcgRJZlpjqO2xgWl5
	6Gsy70aiGYAPJjD6TsgknqE=
X-Google-Smtp-Source: AGHT+IErkPwHisqZJtn0ZPT00SWtUBIWIprkXV7QC8WPkhW5AvkNSVDhIS0nKX4ZwH1QRvHlYghDgQ==
X-Received: by 2002:a50:9f8d:0:b0:551:e52c:4003 with SMTP id c13-20020a509f8d000000b00551e52c4003mr1309913edf.36.1702499419462;
        Wed, 13 Dec 2023 12:30:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:b55:b0:552:34fc:5cbe with SMTP id
 bx21-20020a0564020b5500b0055234fc5cbels261483edb.2.-pod-prod-01-eu; Wed, 13
 Dec 2023 12:30:17 -0800 (PST)
X-Received: by 2002:a17:907:741:b0:a1c:fba4:b9ab with SMTP id xc1-20020a170907074100b00a1cfba4b9abmr6229028ejb.95.1702499417484;
        Wed, 13 Dec 2023 12:30:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702499417; cv=none;
        d=google.com; s=arc-20160816;
        b=SEjWjYJOFl6Kmj2cD9JeV6Nofqg45FeRTtRQOcc+LhUhPa7HxI3lzeVJ/JgRA2jJL6
         eANjY+idy7IjxMAwPyg7ATlKxtFqc3wpIooe/mCxuITp210Yiv3iMJHx/gIVm+zk1FUb
         WqbAYSoIxPGoz+a3WwRkDZYvNcNM+8U0XcZN0Ik866glGNeLlgA1FIHbZXjRG1/o2DGa
         GWNJdEX4zbT/QD3K9LbUipr8KqC0nFPK96WphnCbCWmOv4z33uAvyqblMLnR0SGrkfFu
         M5QCXY1YN4ebmqshlVpUPr6+e4S5WSqIqwcqbBqbCD8c8moITMswTJz//H2q8B7eroFr
         6lIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=i+467Loz3LrvYEdXAV5s12LMqcUY9odwCyEv1IdVOvU=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=MeFwXDCWNPjtlaqNhD+KRr34EatL06HZ/j5eUjlcAY8bTdp+qyNlWrEr7zTzTZOCMV
         Jo9V6pxX/yotNjr9Y4019YxH2L3+m0ws57amvmTGBZXOnZ4T605a95fbc6l3bX6XZjdq
         1nAejLMtypTH7S0p3RM7EaPzIlBb82SOUWZTOVkR0qJHrS4LpDPfb6JL9f+KjPAghchK
         rUTxi3Gp8jU/kelgG+/Rob5TwwE+DuknA8im9iL4O+He2J95oC+ELtlydEsg8IgyAJI8
         oQCamIe9RDSHQ4c4M78F17COvwgXGiMeL5546HzTeTHUt9hT2PQmdytYZYflTr5cUHUn
         TJAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=QxkgXqvE;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id ga34-20020a1709070c2200b00a1caaeae776si423989ejc.2.2023.12.13.12.30.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 12:30:17 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3363653e180so1719828f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 12:30:17 -0800 (PST)
X-Received: by 2002:a05:6000:10c1:b0:336:38ef:1e91 with SMTP id b1-20020a05600010c100b0033638ef1e91mr917003wrx.128.1702499416911;
        Wed, 13 Dec 2023 12:30:16 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id x10-20020a5d444a000000b00336371fafe6sm2945256wrr.16.2023.12.13.12.30.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 12:30:16 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Russell King <linux@armlinux.org.uk>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 0/4] riscv: Use READ_ONCE()/WRITE_ONCE() for pte accesses
Date: Wed, 13 Dec 2023 21:29:57 +0100
Message-Id: <20231213203001.179237-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=QxkgXqvE;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

This series is a follow-up for riscv of a recent series from Ryan [1] which
converts all direct dereferences of pte_t into a ptet_get() access.

The goal here for riscv is to use READ_ONCE()/WRITE_ONCE() for all page
table entries accesses to avoid any compiler transformation when the
hardware can concurrently modify the page tables entries (A/D bits for
example).

I went a bit further and added pud/p4d/pgd_get() helpers as such concurrent
modifications can happen too at those levels.

[1] https://lore.kernel.org/all/20230612151545.3317766-1-ryan.roberts@arm.com/

Changes in v2:
- Fix the kernel test report on arm32
- Remove the pte suffix patch
- Fix pud_offset/p4d_offset which were missing the use of accessors
- Rebase on top of 6.7-rc4

Alexandre Ghiti (4):
  riscv: Use WRITE_ONCE() when setting page table entries
  mm: Introduce pudp/p4dp/pgdp_get() functions
  riscv: mm: Only compile pgtable.c if MMU
  riscv: Use accessors to page table entries instead of direct
    dereference

 arch/arm/include/asm/pgtable.h      |  2 ++
 arch/riscv/include/asm/kfence.h     |  4 +--
 arch/riscv/include/asm/pgtable-64.h | 22 +++----------
 arch/riscv/include/asm/pgtable.h    | 33 +++++--------------
 arch/riscv/kernel/efi.c             |  2 +-
 arch/riscv/kvm/mmu.c                | 22 ++++++-------
 arch/riscv/mm/Makefile              |  3 +-
 arch/riscv/mm/fault.c               | 16 ++++-----
 arch/riscv/mm/hugetlbpage.c         | 12 +++----
 arch/riscv/mm/kasan_init.c          | 45 +++++++++++++------------
 arch/riscv/mm/pageattr.c            | 44 ++++++++++++-------------
 arch/riscv/mm/pgtable.c             | 51 ++++++++++++++++++++++++++---
 include/linux/pgtable.h             | 21 ++++++++++++
 13 files changed, 157 insertions(+), 120 deletions(-)

-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213203001.179237-1-alexghiti%40rivosinc.com.
