Return-Path: <kasan-dev+bncBAABBQOQZKLAMGQEQMOXOOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 767BC576DAB
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 14:00:02 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id o9-20020ac24e89000000b00489c7acd6cbsf2772258lfr.13
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 05:00:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657972802; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vg4fmVuz+Ug1YUINwQDoN1cERsetiGNA2TtwQJs39xVluhXWrB5lp7wIgUrW4WFc7R
         gXkW1g6VYObNbRz1FNfN2PSSosrdQzN4NcdBC6kkBBecwlIBs/w2TD4bjoTqiPJEn1lq
         VeOnvZgMYDV12UIbituFnj8u5I/HD1BSClzRLd53ApAxeKBwb3HUNlFX7DHdIYqgZlM9
         86Bq071SM6BqFRu6qvwa3EDAdlSAGgXwFgmhEk+JTunZghLP+N4Xy/f9nLkMPUui/kVj
         OJjVD9dazXel2Y3Bp8w+kfhueNSIhQVLrCB7t79YG4tfnqRvw3NZTDo0ZBisqggR+JGX
         Rf7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cL9ezgfOeqbwSK8N/Ri5hHyEiChAle7t2tHmjI8ZCGE=;
        b=oEOebHnreCazzlb2cjh9Z9ZVZfGezarLyKhR+LE4ulTdvXxHZZILRCprE+W3Enmlof
         2fTugT3IIYczE4wNcHx9q5uYyals0fb74lOgMlABiIjOn6xPyxIkhDs0jfju/3LErnto
         M6Y6rk0gzYdAopRO0sH/opTJ4AbXEtFF4fFmUvsv2nZ6Z4uQGosjN+SLLvnerFJ3gMMS
         R8iqLeGjRNOMVsWf9/vMCRh1GN21mzul8dlP/zQ/9wTyfLNvdpBfXv3Sv5CfFj+iO/JJ
         jRKJrExpYPAuOgCDr2+g7knAxYS7tNztw1Wjg/fm5T5GIQX+cSdP2rDkrwnFXWkNgdyl
         n6CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=foj8ufD3;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cL9ezgfOeqbwSK8N/Ri5hHyEiChAle7t2tHmjI8ZCGE=;
        b=kTKUwkbFoyAeH31q0r+P2xwdFuFBT6mPG9IXFUDHs7qAqCEud3JVC8kNkheev4BRfx
         j7Yfw361x4pfnwJNsUojf1NTMPBGcimWSP4/rgkrn1tsHM/pp5dTh8qhN+DXfGNaN83j
         ELTTz1aiuLiAvlUaJ5y2kvsyypDnF4Q000SAkMNsZREszpeHcT9OqTl46R/3vci6nOnY
         Knj0ZLZmoRyeeKX0NKyJVWwZyk4pbENzw8RcU6cz+MuJfbkuZcifcWRtX2haHFlI9A2T
         CQzAR3iLj7mm5W2kVOTrS8c2lZoFrlBUD7W8mRFvcdwH2hPyqPhpM9H+BgdDiHeA8V/s
         IN5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cL9ezgfOeqbwSK8N/Ri5hHyEiChAle7t2tHmjI8ZCGE=;
        b=Jtv9dc9+0P2XECC19hRS8Vsdk6JF05nNSIy3NHgxmyCLGMmsOHwVbC3xovOr6EST/1
         dWMYhCkkt+JHL7vzBuDBkj7ilfjrgzyAkNj0Jw4d4GwQzWeH8xlfQvuqYYZaf1zZGseq
         9lyTB+VmUgdxkSWJoWI+9PnIWuZ4d+EVzd+fRWwcpi4KRkNzEV9MaS3cWh4IMF2G9HZX
         /XQd4xPgXyj2L7oYuh+5NLLFB1dqYKLi3RUwYPejCuMRgDMsNEKFNKr8HhxdW3lqrS0a
         9oZXCSyHWCWyRAlGu+OBKRvWkn41keS53s+jHy7ePjhRsAKbMtNoxy+mqjeBdP3kikry
         dGww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/FYMLEabvVduxI0lpyh1G4mx8lvHrKBQFQn7V0WQWBIoRCTHR8
	zE4SO+A7znN12NSu7rp7TgE=
X-Google-Smtp-Source: AGRyM1voO9HKuY5PC8OSISMlphrVMhmmLWOSnwiX0k3qZHLv8tFdVNnxrSDrAJJFZGyf43Wu9+KHhQ==
X-Received: by 2002:a05:6512:10c3:b0:48a:b6d:41d with SMTP id k3-20020a05651210c300b0048a0b6d041dmr10322748lfg.679.1657972801674;
        Sat, 16 Jul 2022 05:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8d1:0:b0:25d:64aa:955a with SMTP id s17-20020a2eb8d1000000b0025d64aa955als2441526ljp.5.gmail;
 Sat, 16 Jul 2022 05:00:00 -0700 (PDT)
X-Received: by 2002:a2e:9f4a:0:b0:25d:7502:e18 with SMTP id v10-20020a2e9f4a000000b0025d75020e18mr8983178ljk.201.1657972800570;
        Sat, 16 Jul 2022 05:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657972800; cv=none;
        d=google.com; s=arc-20160816;
        b=1ApUwERtjDBT7ECaJu0f5+3J74k5kGdPboyelDJe1X9ARGMYsd6o+I81O/703fzO4U
         fauBhc8NrYaifEo9u9zYr8DsU/0Wvh98yqD7tRRK2CsaLEPHwPSW0YNjkoXvQC4sVhv/
         T0x4VlHIWSQhDNA70AMXJA7uwMDYkVhhg0WOGsFej600kO6M+BWXwpjzN+c0KHYxm+Cs
         /+zYPfg8V9Gdnfjt339YO8p+b//oJblynEw9GSJYznVAq5++qi7v9lzKLY1VUe1DfJ4C
         FCAraBMWEAKXN3HFdtpSoatQ/qIzlMJ/DpFIn7BpSJSq7g4whASOjHm66lgY8qwjmzsQ
         YIRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cwAKxMSCN9QgWP7bt7zYcETt2/T5IBJSYsyYP2BJNds=;
        b=iQgyym+wokrZUapP90/2qy+RMDfeiF0B/eeGeRomlywx14Inr0yti5uYf80DZW5g9V
         OPbLIFLhdape06MhitIxIK5zPUic62LvU233lgcNSw9OSjiFlqqCHHwrtw5ZYDb6MoNu
         FNOBI0J02/UgiD2mEhY5eDfM5jWcLXv0jdlhqaFK/0wFvkviIlMoqt3sNJyXUcNEPJJg
         nRujkF2KNORrt4ZI4cD2I+jLe2B/e6gVNoCJfeD0kLO0YMtWbEl/wXLHLhmZj7l4KZ8d
         EWdcqYF+F9/i3T6AzA03W9Uj3UkbkJvNSy2/UI062HgbrCFmuIhiC/47WvpLlcg+fakN
         DfTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=foj8ufD3;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id be19-20020a05651c171300b0025d5ca4448esi94443ljb.3.2022.07.16.05.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 16 Jul 2022 05:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C50B7B800C1;
	Sat, 16 Jul 2022 11:59:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 60E2AC34114;
	Sat, 16 Jul 2022 11:59:55 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Emil Renner Berthing <emil.renner.berthing@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v6 0/2] use static key to optimize pgtable_l4_enabled
Date: Sat, 16 Jul 2022 19:50:57 +0800
Message-Id: <20220716115059.3509-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=foj8ufD3;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Since v5:
 - Use DECLARE_STATIC_KEY_FALSE

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220716115059.3509-1-jszhang%40kernel.org.
