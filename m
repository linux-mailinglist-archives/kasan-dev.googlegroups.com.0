Return-Path: <kasan-dev+bncBAABBYPEYWLAMGQEP7GVZGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 273EE576335
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 15:57:55 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id k7-20020a17090a62c700b001ef9c16ba10sf5331348pjs.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 06:57:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657893473; cv=pass;
        d=google.com; s=arc-20160816;
        b=AfrjhjXbWHF2ZP2MpaCqKRxlMyfSI6nOpIcv7m4Z7A5XO+Rg5Jj3yN3H1oZIn0xjU6
         U+zTOtgtFxqCB+IvG3ffsuDH2pf3OJX1NdAT/fO8lsYP9bId2QlXY2MU72hZdugZaR5R
         Zi21F9pPhwfEb5d8irUOvaHihYfGpCYXktcEvBl8GK2ozPDVbvo6f+oG4BeSfVVjaEt6
         E6/3uV1dlSu+RwguejK8Y5jR1JXdLbstwFhrESgxkNqNBXd3YXxnME1KYqsNWjK03lph
         PYWzVGXWZZqjmZRJ6+jeoaauhPsjIzAYFphIgNP1c2HstkhqAomIeSniNUe4+QhmVJo2
         pJFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XwHJ+KRBBjOTb+ILBSaKS3DmpaQvQfHaM/M8TfT/xW8=;
        b=z+b2c6/rxP31BpzxYfz2F2BXMSrgNoRC3Q/RnY9YIctCgxijLSpl8o07JbjFAJPreC
         PaC4dt7f3VkNV2tYnS0GZubFtWmyE3y3bOFw/z/uYck3aAtHwspnl6LDeNtH7aiCIPE3
         9RC1CgkIG+xtkYkeUoxlMLTWsj7INN7I4ts8GzK5B476PSLqrEwpdrpv6n96YCObcpII
         RnQQw05qmPwCklvz7L3CRq7lztW/GS8lXgQ9bBJgG0wH06N+wttvToyVt2X+04+W6nR5
         GYUT/Yd2PM3fK21iWP/NCYo0qfg6lcnYr3p7/WlPDqrO3DFx12EX8eeLWPJmLb43tYlO
         iXYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="H/NtYc2q";
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XwHJ+KRBBjOTb+ILBSaKS3DmpaQvQfHaM/M8TfT/xW8=;
        b=sPBOktOUrQ/D0O+CkdbTb1r8HRqbC0/QeiopROLsrJuEaKsbcUJXqeqSg1lz3LtYw5
         LzTDo6AJCkFgMUGm7aRMbtzZJr+cB1Jrazsla4HwASrfEE8NiRo4I3vZlxTQMhN0qz3R
         8z7BpDASv8DkMklEuK4CtQS+AMLNeuRu5NiRNK7wDSeG9aDac5WRUiaJ2IJse6fjBd39
         0PsVzWFhghXb0ZSZKGA/FAo9PSq7HTsIhWVcYij5Id+y9/RWAa5qDWKfxrqwUoH4mtt4
         egFur5eDYlD1Z5/hzXUvIrSJtXbxUaDEiSNujZ/O5ZAqtuSLnk+y2HH6wpeHWS+ZGG42
         nlGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XwHJ+KRBBjOTb+ILBSaKS3DmpaQvQfHaM/M8TfT/xW8=;
        b=FJUdAWNES3Xqa/LtsK+j1V8l4Z6gFEFOJLNKKNNQR4iiJfyZOYEcAO3H973Y1Cu41e
         mklMmw3UoYZNXtex8pPxPmEqSU7yspx+BIh+P21K9n/5GATFv+xzdXClMdkn4/w9meSS
         ZrKNc4nuHLD6aUIWq9sIBj84/TsT9yRtucnZdwiV/sdwQ/eDi+vjMmI2xE2oTqCP3R5K
         jAE953OHmtKsfE3h3VsvvEUGI26oCdc0TjB1A84jHs0buMANIxOXU8lre4xG5NEuVco0
         kIAU+LXlZFOW5r/fbnhkPOmYTwXdeuJWrjD1iKu2wr4oI77pyPbNkre+1tr8pWmrhpXy
         AzoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+ynmQaRvZtRPD+FrEhQx0Bk2EsyMhYBiTk3sMe9u8NJthoqEeU
	vc1M/Fl6KH2rEuhtvzFyiS8=
X-Google-Smtp-Source: AGRyM1vpNlvRty7/polggxr5DxE9iwH2rYest+JjeJh6Tl7BI/r3bfNeNtJsgD/YxYH3oTEEUaWBew==
X-Received: by 2002:a63:4d0e:0:b0:412:1877:9820 with SMTP id a14-20020a634d0e000000b0041218779820mr12411252pgb.177.1657893473651;
        Fri, 15 Jul 2022 06:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:67c1:b0:1ef:26af:287b with SMTP id
 g1-20020a17090a67c100b001ef26af287bls306590pjm.2.-pod-canary-gmail; Fri, 15
 Jul 2022 06:57:53 -0700 (PDT)
X-Received: by 2002:a17:90a:7a8b:b0:1f0:80db:129c with SMTP id q11-20020a17090a7a8b00b001f080db129cmr15303631pjf.209.1657893473153;
        Fri, 15 Jul 2022 06:57:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657893473; cv=none;
        d=google.com; s=arc-20160816;
        b=bgaXz3C7SiLQqu/XYdcBDiCWQwubcaiIAh/fw2i5YKx4UVqjvMjvhJuNusWIv+oO1v
         2Bz8ASqCv9itp3HKKiy3kdpRifREsp9RuamNAPlAhr/mX0/aZlnJBayQrccb/kCzjjiE
         voe3w3jqyrTlQu+KDu5hR2QJGJ797k9xdt1fHMY2dfH1RoS/4EA8NJoTZtPwBjsiNc3V
         ADriq1c9SHkGiE6DWQljLfkSQ5c0L3TOkotBD3Dpre4TuZ+EHb7CP3slxdoigOvUo888
         A2xFFFazg0AKcLV7csMjyubHDeFvZLdI49HkP6aN86IZBFBgqKzvwBnYYFmhDYK2Ja4N
         TKoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9jtywILMXnCLfbhIJvUaMM2s0LYqFP9lwIuWv5cnlfo=;
        b=NIhKckOgDBHS2uyJVAUIc8SoOWvPkoFK7JLt+oF7zaFPJa/hGGpQc4sUmMVjxTVB5P
         d2vXj6hKFh7l5SETDgcccqmSJ/QZKfwWUxngxJTJpQIVxGIxfqf2OHUCugPXwpgQyABU
         rxFfTboqNfn7Rp29mBIGVFoucDTw2Wa477uMr2aFBUN6GKK0GZsz/i5jTZWMyNvXaXa3
         a+eXeKHiGs/SdIHOXQy6RrMl3StJTleNdS2soJ16n/MHOqv4I9/zPmvhKOz1nO2OWl11
         s4IVKsr9Fa84LW+kmbPmYw7YCvNgEkcv2u8KsD+YJzzHXJHmLp84uc8sEGe0Cz3WYbm0
         TuNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="H/NtYc2q";
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b001efde4c6699si203025pjb.3.2022.07.15.06.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 06:57:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 1EBC2CE2FAC;
	Fri, 15 Jul 2022 13:57:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E54BCC34115;
	Fri, 15 Jul 2022 13:57:44 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v5 0/2] use static key to optimize pgtable_l4_enabled
Date: Fri, 15 Jul 2022 21:48:45 +0800
Message-Id: <20220715134847.2190-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="H/NtYc2q";       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:40e1:4800::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

The pgtable_l4|[l5]_enabled check sits at hot code path, performance
is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
boot, so static key can be used to solve the performance issue[1].

An unified way static key was introduced in [2], but it only targets
riscv isa extension. We dunno whether SV48 and SV57 will be considered
as isa extension, so the unified solution isn't used for
pgtable_l4[l5]_enabled now.

patch1 fixes a NULL pointer deference if static key is used a bit earlier.
patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.

[1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
[2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t

Since v4:
 - rebased on v5.19-rcN
 - collect Reviewed-by tags
 - Fix kernel panic issue if SPARSEMEM is enabled by moving the
   riscv_finalise_pgtable_lx() after sparse_init()

Since v3:
 - fix W=1 call to undeclared function 'static_branch_likely' error

Since v2:
 - move the W=1 warning fix to a separate patch
 - move the unified way to use static key to a new patch series.

Since v1:
 - Add a W=1 warning fix
 - Fix W=1 error
 - Based on v5.18-rcN, since SV57 support is added, so convert
   pgtable_l5_enabled as well.


Jisheng Zhang (2):
  riscv: move sbi_init() earlier before jump_label_init()
  riscv: turn pgtable_l4|[l5]_enabled to static key for RV64

 arch/riscv/include/asm/pgalloc.h    | 16 ++++----
 arch/riscv/include/asm/pgtable-32.h |  3 ++
 arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
 arch/riscv/include/asm/pgtable.h    |  5 +--
 arch/riscv/kernel/cpu.c             |  4 +-
 arch/riscv/kernel/setup.c           |  2 +-
 arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
 arch/riscv/mm/kasan_init.c          | 16 ++++----
 8 files changed, 104 insertions(+), 66 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715134847.2190-1-jszhang%40kernel.org.
