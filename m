Return-Path: <kasan-dev+bncBAABBWO7VCSQMGQE7LX5GBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0937074C0C4
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Jul 2023 05:56:11 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-c5cea5773e8sf4192743276.1
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Jul 2023 20:56:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688874969; cv=pass;
        d=google.com; s=arc-20160816;
        b=KnOISux66zGQ7kFKAQE+JBlCdz1Y7p9lNFkjg/q5HJfZkVOKH1Q4mWNIB9T2b9X/ZL
         49/Hfu0jhtienjoYXxY5C7IwdWXoJMwy4uvKeDJ3vNQu1J/Q75jvxBnuDQqmZP6gPR0S
         2SpqWAfW6zARzw9S9+U2IWa+3WkAyA3LpJBzvCI3WMCVDIB/FhPfiot/1xRYum9e9tAD
         wI2JETCs4Xdq/7LJX0Fxk6RchmErAmaUDcRrn9MsajCXdxHbYALXWBuuA6mw0/g4yrsQ
         Z5VnGQKJ4IoRVcgxYyvnjJ0y7Ev6jgIEjlf5d6M0F+zybm45mCWcl9WK8j/lwmp5po81
         Cx9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=98KYRh2U+S3s6HkmnlNRKWHVl4vKSy98D/UgBqZHtDI=;
        fh=FnIIe/vQQbzYprQBokhgFj1uohkP19forFNv5hWqnzY=;
        b=FSN7RHfaTAKJ6AqE7Pke7sUDh/SzLGcKr/Ndqr9ARCf9ZMpAishexdv6sEEHCXn9j4
         q2pRv99x+3ihSX0gfFatxzdh1R2FgbQK2wwjVAClt8hfm/mU/J47j07JX9/SPuowmUnw
         jhiKgg6vWT+hPkRntIqW7ik7jrtq9aRyJ3DqaGZttWytzQHp/kSfAtgLCcqAj6saiVsU
         2vtdl2XrirhW/mDY7bzHcjSMs5EOuTpqV+ELzD57bSU6c8U5OmT5SlbYrTUtjLTWH9Uw
         rPyjJ5woPtjZZQYMZq3qCB6xHyqEon2jfDWKzOewP51QHr/C4j4YcWct50+TtHElAxzn
         ffTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PKcvWCrU;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688874969; x=1691466969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=98KYRh2U+S3s6HkmnlNRKWHVl4vKSy98D/UgBqZHtDI=;
        b=RMuZjBvPq0GAfJfOvpQMC9CnIwcxciLCgjhwCRtxJTm4IKVec2RbAcFpaYIYssYVVT
         VBzCQGHqGAv6Klw7cKlVwdcjPCtexFKIi2FOQ50Be24UXc8dQHypUGio/MFzfSLCVV5A
         y8MmYQNLh+penYJrRWMJxRhuPuHHf7MswF2EBlzZ0Tbuy7x+p9orXR4oNtcKloaCw1zy
         fwK4704FJAgZXdelmL8f/eVpU5qxCsZU7ef3O7bsRPLrjAkgqqu9ipCtlTAM4HmU5NRJ
         laMe8LylXzIk4WGhEVEqIT+zC/nmLFZ2a50S1TY/2zAKkxQ2xWmU0wwRqgp4uXBcbKar
         yL5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688874969; x=1691466969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=98KYRh2U+S3s6HkmnlNRKWHVl4vKSy98D/UgBqZHtDI=;
        b=UbUW+Ho2T5jTGZQ6ICykhkskbiLfl0NiX+Ld+/BEquTqUrZdcrXFf/+NCZjZP01KbK
         YTRi9Sdu77gE0RFi+t7hOtlCFF/LQmRU2I098R1/r3juykkerElpY87LlUFYHb2lsGOb
         YCZS0o4+b0rbDfcuGX1323l7rCg7o/TchgmLT6ALTsKA6nKZX/gMP0O76CrnaNwQHjvR
         vjPcUbHVmzzjSgaPSdrSkxcObJpAxlSFYoY/W1iQbCGJEiGFBC73mIowXqpVy0MYZVpx
         Pe4jlX1JjMlAJKsiO4UOvLIqTH6Y3wFFYNIxKZRBqj8PgXNR+00Ye25fA/ZXtlMIwVQw
         7Q5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZhepmWOMMhpUXK747iBiBdMVvUdZyIPWq5d2hLjDSIsaiB/vBG
	3Vf8P4BI+Hx8LvMswt8pWYU=
X-Google-Smtp-Source: APBJJlHXRqB9QNeOVT7ZaLWaL2OIh70irmFeHQvhQxQj75KxQuXf0YF6L5BwXBfQZBNgLu6WQ/I0FQ==
X-Received: by 2002:a5b:187:0:b0:c4e:50fc:c2e4 with SMTP id r7-20020a5b0187000000b00c4e50fcc2e4mr9002456ybl.61.1688874969682;
        Sat, 08 Jul 2023 20:56:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1024:b0:c64:776a:a7d9 with SMTP id
 x4-20020a056902102400b00c64776aa7d9ls625165ybt.0.-pod-prod-01-us; Sat, 08 Jul
 2023 20:56:09 -0700 (PDT)
X-Received: by 2002:a25:9cc6:0:b0:bfe:d93a:8f2b with SMTP id z6-20020a259cc6000000b00bfed93a8f2bmr10045726ybo.60.1688874969207;
        Sat, 08 Jul 2023 20:56:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688874969; cv=none;
        d=google.com; s=arc-20160816;
        b=f7xMtlWBMOE8SdKAml15jvP0nWTJ56FNvGc8Lj377aX+GSHLXZqRDARkaqK2N8R1br
         u/zJVa4T83SSBrlQpb1WV2pM1AhuUrT559otcfjQ09rFg4ivBohD8mWvleIuqk4ShNII
         sMRz/koV/xa2ZP474cVG0YFwNSbf4zJET3ewszk3BQjHklRZHQjg2/utaJtwXQGLVjt6
         Gx/uHggZtK42CExNFab4A8HOs2H82+uTOABhu5nyVpoBzNSKyeNk6+rzD5tMOjyPA6eP
         es27fh5YZ59yncebeBtwH/H5wMkZlycBceuyLDN/AEpWGYVNd001OWnz1ShuyM9PE0ap
         Pa6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6hOuVJtKeV3rBSbTyHOYN2VtgO/nlMSphMrotm1JH9A=;
        fh=FnIIe/vQQbzYprQBokhgFj1uohkP19forFNv5hWqnzY=;
        b=fps1S+bfQ/FVC/vZtXtuMmRQBmkAlTxYolpU/jwsfZngZSA6CvJF1xMWUXY8wGzMPn
         dpO5HKjA9GP0pwNHIvKew7jU4Ts8kdcqmJ3IAtaRzMB1M8jmn9PpU+6rr+ICjx4EeI2G
         JN/TRwoG7JajP71Bptg1ZR/xOEh9SScALJnUr4W3TNj/yvBa+Q/OIiKw7dXxLlGlE0Nt
         pJbIQrwCvQ6/cOvqODIHz5LDJJeQ9ghgIgdV944DYdp26VQvT467qq7B44bIa5uBA8/h
         bk6uhZgc9sSlErX84uvAZndQ52OTYrIV+Sth5zUpd9jhCXl/VdVBkpTX5FuzjLB950dr
         OG7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PKcvWCrU;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id s66-20020a257745000000b00c70b9b9189asi256107ybc.3.2023.07.08.20.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Jul 2023 20:56:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D71ED60B62
	for <kasan-dev@googlegroups.com>; Sun,  9 Jul 2023 03:56:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 28785C433CA
	for <kasan-dev@googlegroups.com>; Sun,  9 Jul 2023 03:56:08 +0000 (UTC)
Received: by mail-ed1-f45.google.com with SMTP id 4fb4d7f45d1cf-51e29913c35so4588835a12.0
        for <kasan-dev@googlegroups.com>; Sat, 08 Jul 2023 20:56:08 -0700 (PDT)
X-Received: by 2002:aa7:c0c6:0:b0:51e:166a:ac7f with SMTP id
 j6-20020aa7c0c6000000b0051e166aac7fmr7183978edp.28.1688874966365; Sat, 08 Jul
 2023 20:56:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1688369658.git.chenfeiyang@loongson.cn> <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
In-Reply-To: <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Sun, 9 Jul 2023 11:55:55 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4yaJExw8zSYvEiHaXQJXfCkmwa4yuFfrrT51QT_25NJw@mail.gmail.com>
Message-ID: <CAAhV-H4yaJExw8zSYvEiHaXQJXfCkmwa4yuFfrrT51QT_25NJw@mail.gmail.com>
Subject: Re: [PATCH 2/2] LoongArch: Allow building with kcov coverage
To: Feiyang Chen <chenfeiyang@loongson.cn>
Cc: dvyukov@google.com, andreyknvl@gmail.com, loongarch@lists.linux.dev, 
	kasan-dev@googlegroups.com, chris.chenfeiyang@gmail.com, 
	loongson-kernel@lists.loongnix.cn
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PKcvWCrU;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Feiyang,

Please update Documentation/features/debug/kcov/arch-support.txt, thanks.

Huacai

On Tue, Jul 4, 2023 at 8:53=E2=80=AFPM Feiyang Chen <chenfeiyang@loongson.c=
n> wrote:
>
> Add ARCH_HAS_KCOV to the LoongArch Kconfig. Also disable
> instrumentation of vdso.
>
> Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
> ---
>  arch/loongarch/Kconfig       | 1 +
>  arch/loongarch/vdso/Makefile | 2 ++
>  2 files changed, 3 insertions(+)
>
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index ed9a148cdcde..4c21a961ab88 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -14,6 +14,7 @@ config LOONGARCH
>         select ARCH_HAS_ACPI_TABLE_UPGRADE      if ACPI
>         select ARCH_HAS_CPU_FINALIZE_INIT
>         select ARCH_HAS_FORTIFY_SOURCE
> +       select ARCH_HAS_KCOV
>         select ARCH_HAS_NMI_SAFE_THIS_CPU_OPS
>         select ARCH_HAS_PTE_SPECIAL
>         select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
> diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
> index 7bb794604af3..7dc87377688b 100644
> --- a/arch/loongarch/vdso/Makefile
> +++ b/arch/loongarch/vdso/Makefile
> @@ -5,6 +5,8 @@ ifdef CONFIG_KASAN
>  KASAN_SANITIZE :=3D n
>  endif
>
> +KCOV_INSTRUMENT :=3D n
> +
>  # Include the generic Makefile to check the built vdso.
>  include $(srctree)/lib/vdso/Makefile
>
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4yaJExw8zSYvEiHaXQJXfCkmwa4yuFfrrT51QT_25NJw%40mail.gmail.=
com.
