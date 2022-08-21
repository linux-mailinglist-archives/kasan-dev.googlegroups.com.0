Return-Path: <kasan-dev+bncBAABBOP5RCMAMGQE2IFPMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A16759B45B
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Aug 2022 16:18:34 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id b4-20020a05600c4e0400b003a5a96f1756sf7330428wmq.0
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Aug 2022 07:18:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661091514; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tv71PhTceZ8jWf5w7iTMeBB+0IqSqPywepVzR+7Cmg9d1OFB14LJQl80PajtpJAVfr
         Srr8N+igE0kzqdNUwOzda56wKjF9ororZ4gZMOQ6focRibHVsAIz8Nb0g4URtByHhHAR
         QPT5ppXpaDL0ig1H3xeivEyN8/KkMV3OuTTXRSkXADEuWWdYYGacXGXxEuzEXCi6aWEG
         2T/7AKgPMazjfALRPKaZZZrO5CDOfdIREBkHA8frUUXswj0thbCNAlsPzSsj6mXPqys7
         /xE+598ePx0vmzCTN4TpKZI2PO6GutGOhsAWQnQYQzA92QVrwUyRmJV0kF/M8FOzU7tG
         BAbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=MWwOYGE4CBOSev5tphqCFxfKlRUUf2Gci0hzBKuwMWg=;
        b=eMI911GFComNh30oyl76bZaLrkArc1xMEFcKTzTe4I1osYMdHhSd3ewl0JTavO3mIH
         0dt0hGb/5vR1Z7hYnWr/FZm14hWY4AWdl91hS3PysI+cz9Ladfyf18B7NUo7/WB7cO4R
         8aY7KAAd5H1gHB3eKkVAllmxMWs6bswDExEvBNNQDUp1o853K3h5TLOWms4ig3bCqqqt
         DYvsG9YwbDvc7L9Scf6iNq8BlvwwJ+zrMlMqWSq+64DDGPqHZWLK1j7jPFV9GrVV5/EJ
         SVpYJtCbtpKHqF/Gw2mdU06MNrdvAJ0+2D6ZRM+TadBeOCAjXx5edvNy64UkM3QkYu2m
         CD0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ml7H9mfM;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc;
        bh=MWwOYGE4CBOSev5tphqCFxfKlRUUf2Gci0hzBKuwMWg=;
        b=lUVCO9q6SAfvdzyDKd6gDzDeJAA5na20nAKECPynR1TM5F796Ve2gt68HfALmwlzTB
         T0S3zckl/zQTv+DYtzC3tE5KqFXKHywe71QFXGb1oilMjZGyBExeI6WVQxTwrIN656QH
         WyNwoOUKqgs2+OsCM2wdfMlTB22yaOqD5AAEZZoPd+9lYpOaxjzsK3NuhS+AOd2NZaMT
         feMdV67UURoMT1FUVoxEtzAFFM6oX0OGWmEy+cnPzwBfSZGEqMb+VOHl5VfK5fsWWmeq
         btB3Qu+H4ARNLij7fXXbN8lAIz/g6YqMr3LR4CFHo4FBgIm7MEwoy2l9m7FkfTrLj/Kn
         TU2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc;
        bh=MWwOYGE4CBOSev5tphqCFxfKlRUUf2Gci0hzBKuwMWg=;
        b=QyTt2iPfw2pN0b9zb+omcjRyu6Y/UNGHTUvZVHOiuyu42mLPybXRhA7HmafDckZI1B
         qsVoa6dOxW1kotewvDGajXI5KBtqz8EUyfLRbpaKHh0Ww5tlpkeDAQACLaXM2f8lsQrh
         c7vNV3XLuVW9RTYqFolXlWr/l8aZClIkzY3LNbYaP5qJnrOD4Ecu6rP3WgWQCs5OaXtU
         bZ3kFdQFKjgaRYAmjuhhlLkuIyVMIpi8mEFmPLbWFlaS2UbZmTrVvD3kYsfaXJMMLHWu
         09neIsCQLOOmrao009LbX83nLPgxUPj4rPc/HWa7Q/Lhc4qRzlzFQ/mIdJapTdy4G9fd
         GabA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1yC8xWOHAUfbPpdybW0gNdqUN4WiGWPJLwsDETDX2oBcokkGxW
	DerxpAJfTtp9ce6oio5f36k=
X-Google-Smtp-Source: AA6agR62c4c94m3VQ8mkCgAXu2yzv7uMIi/ezQGpWqjP1rmbeiboyEF5TYAavPZSnVP5DKUgq8yXzA==
X-Received: by 2002:a05:600c:4ed0:b0:3a6:de8:5e7d with SMTP id g16-20020a05600c4ed000b003a60de85e7dmr12864202wmq.181.1661091513892;
        Sun, 21 Aug 2022 07:18:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:e916:0:b0:3a5:2d3d:d97a with SMTP id q22-20020a1ce916000000b003a52d3dd97als2749106wmc.3.-pod-prod-gmail;
 Sun, 21 Aug 2022 07:18:33 -0700 (PDT)
X-Received: by 2002:a05:600c:3b93:b0:3a6:c3b:37eb with SMTP id n19-20020a05600c3b9300b003a60c3b37ebmr9789549wms.185.1661091513076;
        Sun, 21 Aug 2022 07:18:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661091513; cv=none;
        d=google.com; s=arc-20160816;
        b=AWfRE4bivKBfknPqie78wFIeFvAZnv0NRW8oIFeYAq4yFE7vCOzzXSoL3Kcv4RHndN
         lKUTSwDiQ9/KjNGLn1gdEJ/a4IB6xVfxUXILDtX11y72nNAEA1Bwz+pFk3Xx+xZXd1Dp
         JXqFFw54T+zC0eV6aUD3D1mF9bwNu7uTCa8muRPNsYVOM71BSBU7vCtKhVh8xjo6Nlqb
         3mqblZtdB0CxwIeUlx4TPpbWwQrwl85wGR+vA81+rF94QUTjIxiWQ0ROXpFuQqv+olup
         AjjbeYO9Tb0Jy7kowmTd7C6OC1td4BCeLmAcx3OiRjb1UF8zmBm7NXigYNobe3Egvoi6
         aPuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5xgOfiUhPpgAk7SZoDJ6EaMp0DSa60+skRFgKfdEy4M=;
        b=tGqKh2kCxtRzsy+k1pn/LulZDvmzyHcNBHdCnCQzRPM0/LfK1oMr3C8dGfd+7aJGPa
         ZHbh69G29PuXW5sGlFN78weKN34c6YGdnpy1l3xfq0yR/4xsDhmD6t0/7VYOAy+Kz99Z
         Y8VMjskWq4wUx7/iFKRK47Z0FqQJhrmGDwaqKnx4yV1CBqctNvg6EcuOnl+aN7v+WRv+
         Vn3fzXjzbN1kEOv5agCIEr8VL20jnm22UFQfYj5/d7+Z0PEKaX43+6NCA9uSPwz2ssvD
         foOaZnER/i2HKG/l5bGib4AtVzhZLmIkJPWppJFEXXZ2LgCWBnLz6SoFGdaYBSONMitx
         kjUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ml7H9mfM;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id m17-20020a05600c3b1100b003a62e4da7bfsi806073wms.1.2022.08.21.07.18.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Aug 2022 07:18:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A3283B80D7E;
	Sun, 21 Aug 2022 14:18:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5E092C433D6;
	Sun, 21 Aug 2022 14:18:28 +0000 (UTC)
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
Subject: [PATCH v6 RESEND 0/2] use static key to optimize pgtable_l4_enabled
Date: Sun, 21 Aug 2022 22:09:16 +0800
Message-Id: <20220821140918.3613-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ml7H9mfM;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220821140918.3613-1-jszhang%40kernel.org.
