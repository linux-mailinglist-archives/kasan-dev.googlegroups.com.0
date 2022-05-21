Return-Path: <kasan-dev+bncBAABBGHVUOKAMGQE7FB6HGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 867A752FD6B
	for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 16:43:37 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id k5-20020a05600c0b4500b003941ca130f9sf4151965wmr.0
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 07:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653144217; cv=pass;
        d=google.com; s=arc-20160816;
        b=jil6i1lfmZcsXq7BK35VjdrzdEmBK9NcVR+Nn1OvhCplwxrkMYMZmotIS59yW6Pm9v
         ++gJQxnYPjdkeGkGw0h4U60Jwk86WG3sNX25WV7fe26VMSfK5nRD0RVUjEA6LYIfmQuu
         hZhFqO6N/zEUQBwBFzMWysiS4x6EhF+8c2LLbbwbmxmimqZfeFIOaNkdDl2AvR33eaO9
         aRbpWUAbDD8kOW9uj1Q84GCb2JsImhgooWi3cyNozsYT8chMpP9ClPsQK4DHguTd7jYz
         M/7GNIJKDoiXWgkyIzWEt74BYn8ccfAk1s6LQJbia7PpALj5IH4AY4voioExWBG3j3JF
         ut2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=swEdh+o4bGxAaUqPGlahYTK4OeQnjK+9IGHBpHwnhdU=;
        b=cdxQ6k56fbedivBAANYtE/1Xoz29Juu+vHngEaReVmsVc7rMayXL9jyLS0no7cxI3g
         3Jjq/uYymDzABBc5iNGOHypHM689HaqZWZpPW8b8gavje1Eq/yJUwwNNqIBkZI5YuUlh
         +2FJ5EXG6mw3t8+3YEv22VtHFnRKCfgUMubB7PHXqbcURDoVE/1eXbAGXfWYF79mNBd0
         cWZWbuO1dCsYapBFQLiupb5//CMRGY3uC8EVRa2KbGFviSz3AM7uj8wkukGgUz+Wa/t+
         ojNHLBVX+JSdoLunyPID1wGPhINxY0LJNMCyV0PxzuHmc+ym3ihBCNd3UJ7xUct8mZeL
         mkWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hxUufeXe;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=swEdh+o4bGxAaUqPGlahYTK4OeQnjK+9IGHBpHwnhdU=;
        b=FDu27h5etjdgP82AEkVj8/MSUgxX/2CN5ebMMeKDUaZoQ7xjdMby7Pf9S796QhoA1G
         nsGMGkuniroTr7fumWiGM+q0ClRTQAhKvK1QQSdiQU0ZfnpYa5k0qlA6o5so2cjdIc0H
         jmPXKbXBlpSpTcqt0CyEDIEhGs23jGKjPL4sYYpUHArOfecWTxahytHsWI1U1I+MnvM1
         /s9Au2AtCSouEY6z8s+xW+llcpPbVFPS4YiIpyKT0XyUKInQq4EGHhIyD33apt1f/qO9
         uOXhsXX0MLxI4F5ynaTX3hx3F1g8T68xwgj2NJQ82XOBqo/FIoqsYSkSNCKJN0fDsfjc
         l7FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=swEdh+o4bGxAaUqPGlahYTK4OeQnjK+9IGHBpHwnhdU=;
        b=4e8QVPhjL06FDq3B/bQQTfGdgIYZDye2S7ddlzgNigmNTOvn4swHCYUH7iAvCSKY/1
         zI4epTjgHg3SzFRotMeUwh/qudHTZtzDw3XFe2NRXX+7muZXqAweyh4LM0uEzFbCJE2E
         P45N5+tioI0IeRfXCwik07JTFvds326A97I8kjI3Ti6jeiPeculbxhqUEoJozHnOZxsA
         E1xml4Izj2OnEfIGfSCMeJbz9qiO5OQUBTqYhcEBC/tX+VyWL+pzVgI8vLzGzSc3j70/
         4ZK2+0zrhOW7Y1IgqUxUTpQ7Mu11ecQnBubCLjOe6YsX780+Jdk69Q/raXBNI4lAPecR
         WYIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533snWjcREHANXt9yHQ4NO8Rs3rh9MaAtxlirbXGbBrY/RdPMllC
	KgFJ3b52qIPBLd/ysKYyg3U=
X-Google-Smtp-Source: ABdhPJwCfk3BL/Y7rU/u8cNqHioKdf8IyhS8k5p8//fhHJPF9nRFrRN4q61QIGSgsrkl12gbrAJC2g==
X-Received: by 2002:adf:d1cf:0:b0:20c:a6c4:98f5 with SMTP id b15-20020adfd1cf000000b0020ca6c498f5mr12399129wrd.501.1653144217003;
        Sat, 21 May 2022 07:43:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4807:0:b0:20f:d148:f68e with SMTP id l7-20020a5d4807000000b0020fd148f68els117592wrq.3.gmail;
 Sat, 21 May 2022 07:43:36 -0700 (PDT)
X-Received: by 2002:a5d:4e82:0:b0:20e:4aa5:9caa with SMTP id e2-20020a5d4e82000000b0020e4aa59caamr12054588wru.589.1653144216253;
        Sat, 21 May 2022 07:43:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653144216; cv=none;
        d=google.com; s=arc-20160816;
        b=gWTTY5mEzSDAT/bvjJ16GrQ3Sme1BHz810lUQEXIUgf6aA4ideV2PKrUNKBGrbDJpY
         ITI6HsH+Gy/lwTBxWGAoZ9DspqKA80RszusdSCWjqts7+rqkn75rMxMbbGC055xLOWem
         R7qccaSaaChxObHewBGEJ24/5dybcuswb+szDh9N/SHCrqp3q4ryHhCGACT0IxF0LVMI
         mvcbbiXly8pPw3pDOk3e4L0SLEJmfOMe4GYocKY7DBWrgYLvKhEEEC5a1JsXOtnIMqL2
         0GPvtM10aA/KN6mf/f2uOIL+A/S/Um0qxBW6loZAaSdyRD0nUfkbsBn+Gkj1SVP5hL6P
         lK5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=430W0NyRi8yr3SBYLcmF45GkQILubarLJhbXCz2oytc=;
        b=PDsKns85TU/QasgBQnqrtz0EosZVnKB44FdsxQrYMa4HQXsF+s0YF5NeN91Ig7ls3I
         ZIm2c59J3NBeexTILLqIGsy0WOLpHM6nfmd3kOf+PyAiIJCUEP0pFPSQw8XPupMnS0cC
         8q8/0yq5pRCyKssH3ODKRXLE389asvHEG0P1XULbPZHFuAxwg+w37ZIgGM/pfQOOK6WI
         OpWEn0uRZpV/b5uhwGjpZ7evxQvHZPGLXfx8MX7x7Y/ANsSqtbNCAMka6pZgmjPPvyyg
         N6VFjzE4m9WFmrG2NKLpupCVcuK58UXdl0gbLA/dJQQ9mRKI0Now+X1z5F36Dy8+CTwx
         G1zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hxUufeXe;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id ba11-20020a0560001c0b00b0020e674a0d19si37000wrb.0.2022.05.21.07.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 21 May 2022 07:43:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id D1935B80683;
	Sat, 21 May 2022 14:43:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E6C66C385A5;
	Sat, 21 May 2022 14:43:29 +0000 (UTC)
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
Subject: [PATCH v4 0/2] use static key to optimize pgtable_l4_enabled
Date: Sat, 21 May 2022 22:34:54 +0800
Message-Id: <20220521143456.2759-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hxUufeXe;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220521143456.2759-1-jszhang%40kernel.org.
