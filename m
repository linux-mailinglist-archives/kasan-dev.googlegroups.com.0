Return-Path: <kasan-dev+bncBAABBXWWTGKAMGQEG3K6PHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15D8152D9D1
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 18:07:59 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id m26-20020a7bcb9a000000b0039455e871b6sf1978638wmi.8
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 09:07:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652976478; cv=pass;
        d=google.com; s=arc-20160816;
        b=L+KYVXHDrftRqrQqxd6OHe9i94jzY/TG+2z13JJBb7PUnYKfAiVj8BHPX819z4g3tC
         krcfVIcrAfAAqAXnmgE48GrIeoU1/E4RrigxLd1iVM9LQkuyzL/F7JRd+SfiCbZLLE8T
         Wsv7nnHak5SsaVzm4NmgYdZ13P2s4nUm0rRRP6kefZK6TfxHjn2HLgm5hXxn91dlj9NL
         kg3u01gseIl09UcrVRnJnn5QMIYrVQG3H7vStcSnruE5MbTJAYR1kLoGjrb5J9dD7kqi
         0a6UUoxEkrMAxCdERW5M6MXH/zbhiKIb3gEs4hSP+i0G/GTRlrIzNvndsnI1U1iZuTu1
         sGVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=EMJz+IHpQMioUgfXu1oA/vidoT985cLJ6cdAAC7lr8M=;
        b=mf0hBju5gh6GZNh8GD5YG72SwCy67Ei7pjV57yhavPQlhROF5Gu2aM++cvwFamQSfd
         XBVMVQzMQt4gfMdhI1Zu5Nl98I01LP3M7+7KrqvEoDPqxSl3T8K55kEBLBvG2fta9Sv2
         xNfUD0+QLDZwNjyxRutKCdUr2XAorWA/znA+hz1f1/8nUjJlQoIiucn5DACAYy/jFkyX
         DCl3qW8Rh9YTdTkDh7G/C26FFrz33bps3RSzgc5dzk1euakV3WdZ/WBocaqMocNypXIf
         /y8x5OpsABTg+t6kITgztoytr7nx9IYFmxAYyGA3FiSac2hvM+bZXBpqQeSPfq6HrYGi
         p9PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=g26P3IuH;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EMJz+IHpQMioUgfXu1oA/vidoT985cLJ6cdAAC7lr8M=;
        b=THCuTM1l5ErXMUlWuNYAet1loKXAfy1FkLiUTpjFtcwslHD7hXGGgE6PryYd/2VkB3
         Un6/jmRx8TrF6BArvlVSvTDOeGOAEWFLSuThsAYOlZzKP6dHVekrRiha0xgfuPwY3ByP
         WM2Wzj5istZyy2HbnWQCnuWFxKk8crunGbBaZ3S+AeHtMqzSXl6b1VT/YKrv+aJj925R
         D6rTjYiwQfJ2Itm94X21vy3Zuc7DAiXuR0rKWAu/3m0YjhaFfizwsgCujzy0zw/OYU4+
         Ed+Q1blNTWImHRc51OfO2LZOYmA1pH9dgWO9B5YTICb6vGpfc5XOtCvcAl+yIjF55QSC
         eZ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EMJz+IHpQMioUgfXu1oA/vidoT985cLJ6cdAAC7lr8M=;
        b=mrLlbGiXfsZuygXAcIuFd3gHLdVkncutoR9S99clzStD/6DQ0gOCi/MYhKLl4fNYtn
         57YsunBCKeaDwBcsj2XM5ejKc+6aw9RPa91EpnXllDaFthotqsNEHP1YLRk8+843D1Xy
         YBWZPJxHb/Cq8bfLBAiI6qLUnTJ0Aa1+amkEjj5c4bT7QHT2ZsVoh7LZ2YU6jXcRjYYd
         ApxvhCyWyzN0bjiBLBBflkRUJQTH2KphiLgEt2aSQahLUw+4xQEv8tCu42aM8T4Y7tBa
         sQBtkADyP2x2tQ70t0uSZpY/vw0ThXIrZghbbPY0BKGPep5xMhLy8oSYwYqttRiQ6WHi
         Ykqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53032E827VoevojNoM+0Eod3045CSMhVmqPMTmRd3v63VM79xnj2
	eRXpzFT8kIJG2I+7t49s3Ag=
X-Google-Smtp-Source: ABdhPJwS/PiaHzOHHnjyIVmN8K3oRxFYUtTNkglf82EZClRFNT9CjUDXCDuydaEQa1cH61Omzqc3CQ==
X-Received: by 2002:adf:ef0d:0:b0:20e:5f0b:806c with SMTP id e13-20020adfef0d000000b0020e5f0b806cmr4724917wro.93.1652976478678;
        Thu, 19 May 2022 09:07:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d9f:b0:394:51e4:7b18 with SMTP id
 p31-20020a05600c1d9f00b0039451e47b18ls4397732wms.0.canary-gmail; Thu, 19 May
 2022 09:07:57 -0700 (PDT)
X-Received: by 2002:a05:600c:1e17:b0:394:547c:e5a6 with SMTP id ay23-20020a05600c1e1700b00394547ce5a6mr4444831wmb.203.1652976477890;
        Thu, 19 May 2022 09:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652976477; cv=none;
        d=google.com; s=arc-20160816;
        b=X0fC69nc1MH7cYrjWvmHks8aWR/QlY7reWEJDQGq0sUgVuYFUAzlZ9teGkuzN4KaWb
         KV5lkRqwRDUkS46QUIwBRLRaD8nW0oXPCYdVK05cPni1Lt0z26yCp9HfpAdu9+/lbQQd
         zhH5NBmqWrbkJw0/5xK5zeZGWg+ElOP10sAKhg/QeG0yBPqH2JIliYPtc7/71rxccVym
         F8tVp/WJBjN3WX1xgm5jmKxr0F0vqnfN0xiFcEV7VTEzYMStSVMK+2syQnJIAJeO9sQI
         7rXJ4oEHHZyUWzhBoKyp6O7ZHIqMYF+V/I5cb2npYHegr6llfhQ4UxlIMiQCLwM0pSd+
         3O0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pELL0kvd/H5+lVPyZcUIFeqfgLmY5zx3cTb88OjHg+c=;
        b=X7GA3KuUT6d7oW+3/pkvJb9BowYF7CsYa5h/Ah367LFz6dToFesudm1Oa01xCBR2Cv
         2FarXVlgQbsvo4Y9QX2Abd3dajk1hZiB/5DU3H9KIfCQh+Osk6XRoHPdFDhkhI0D8HbV
         kv4WQ4YAfocD8iGrqx5wjBULLWWKy/b2MxqY0M5252EeZh5pL9hz6MS/rywQgZRExaf5
         q2KjLNJYupeVI2s3izIqTUWj1pF7j/HnbUu/hLMjhjIjN6qf3DxloYT7IH+8GXs54TM8
         SaaY4oc/MZDICGtj+fbYzdFlGTwaIQ7hwkB03L9q6MGcZm5pfrHbcVaadbx7rWU3+SMj
         eRnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=g26P3IuH;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u12-20020a056000038c00b0020e59274d31si116wrf.4.2022.05.19.09.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 May 2022 09:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 86AD8B825B1;
	Thu, 19 May 2022 16:07:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 06A04C385AA;
	Thu, 19 May 2022 16:07:49 +0000 (UTC)
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
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@rivosinc.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v3 0/2] use static key to optimize pgtable_l4_enabled
Date: Thu, 19 May 2022 23:59:16 +0800
Message-Id: <20220519155918.3882-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=g26P3IuH;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
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
boot, so static key can be used to solve the issue[1].

An unified way static key was introduced in [2], but it's only targets
riscv isa extension. We dunno whether SV48 and SV57 will be considered
as isa extension, so the unified solution isn't used for
pgtable_l4[l5]_enabled.

patch1 fix a NULL pointer deference if static key is used a bit earlier.
patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.

[1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
[2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t

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
 arch/riscv/include/asm/pgtable-64.h | 59 +++++++++++++++++---------
 arch/riscv/include/asm/pgtable.h    |  5 +--
 arch/riscv/kernel/cpu.c             |  4 +-
 arch/riscv/kernel/setup.c           |  2 +-
 arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
 arch/riscv/mm/kasan_init.c          | 16 ++++----
 8 files changed, 103 insertions(+), 66 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220519155918.3882-1-jszhang%40kernel.org.
