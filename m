Return-Path: <kasan-dev+bncBCRJ7M4BUUBBBLFMX2PQMGQELOZWY7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A035869AEB1
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 15:58:54 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id x16-20020a634a10000000b004f74bc0c71fsf362137pga.18
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 06:58:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676645933; cv=pass;
        d=google.com; s=arc-20160816;
        b=KZZII1pRHl2awwYyIa72FwOr/jiNcX3wqZzfmekOUC2h57CgmoIw4YiK4FlyZ+o8BA
         ViAwJVvXvQh+Ujb3YfGD/ILo2Y6YlU5BUlUTN7A7KNOruUjIKlPjpHNLBTKjr+kzKShx
         +nd4k3y12yk4zO/IMzYLAcECfcQxYo7vD7mCpYPRzT/owUuD7XxeJtpNR15Ivj2IDuaK
         WftlghLLpiaJ8kKISadtVd0wv5/Rfx+B49v0kbVxjOrxpz6QU7mvlvWuQJepiNTcdDD2
         EHsH/d2GIlKkjuU8CviXFwbqB5WGe1J4gem2ctRETYFBR+yKIW90yj8l5APeV6DLVYvL
         mqcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=siID1vpwbM3igbP2fCCXRH+5rzAzuDdC5qsKd9guWHY=;
        b=uO4Q5ML7HNjI6UVNtn/jtJb9lqDdYMyGx4+sJPyxzWS7ugOtIlS9JjQdf90EjwWFHS
         vVEUuEwa88AyFqrl1hOLbnrFPNDqnSF9Q0gaukQHsaLoTkDKmNQaqMgEDSG9a8ShhhTf
         c1iTCfhudA88sjIU7atESIRZdLL7FlAlFQXnc2rNtTT2a/fFjVUwvVwcSo2c/Po8T25z
         W7bCEkd1qMoQWhyYUNcIJropwV4x6y9mM5dsDi4DVrWerIaDz3DV9SHMFFgvLSgedMrR
         Sx7RrPVxlMqYhs25xtVStL5MehyK9KUy2Syeq7Rh6Yxz2KGyen6UBBTpVcPZPgwhy1ss
         dBVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Y+nxlJ/g";
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=siID1vpwbM3igbP2fCCXRH+5rzAzuDdC5qsKd9guWHY=;
        b=AQ70Q0H2UTlYjreHgHa7zDMN31fQJyYVuBlghGMzpnR6NjIYJZM6FBX2/tXotME81P
         RmOW4/w14IIx8ZporJ+7/s1Gb13HA3IwLuIQLaGvGh+e34zBsQe+R3j8Pr6QRkhHDBTh
         2eIK1Mvmskz55abA0QzakE31weJva06sy9l5ZsgPjDKvnf837j6iqVxRniKmJiWwJrxA
         w3XIWbIsktazCUD2K4EJlIzhvfcj5zMOZDxPNQutEji8VfnAC5roR/B3zlp1ezUbUcRC
         RCanvtvJ/0d9aSj12u0xoyOc/MTpHJuBZBlfQYpwBBmN2ZYNE9XNVGCYWgwG4aSIXmOm
         +FRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=siID1vpwbM3igbP2fCCXRH+5rzAzuDdC5qsKd9guWHY=;
        b=YkDFJ8+AsFUL1YADK6lFj8Z6lDlbbW1uQnkL9lyIL6fiR8pjjTJXIKEErpSpdRBm12
         8BQYLFP9/glclMoXYF0AejG+vjYAhPYjWLHacPMQcHpEeySTYgAtCS4hmzvni5mpRrEH
         Nt3k2E8lW7lSL3FKKADvsV+a83f92oAtmbRSXAUg87fok8jro9fPs7da3ruJ8NQGIIPc
         bGGHLFHZlxRzMk2iPAL9aTblc6cYqZ1s9K3JshWjdV4nKcvon/nWu5thM2Vp5wI8BE9I
         zHuweNdMeoxaIegovUDUMDX7Do/So+6K3Xh36CsaVVHj/h8+5g5uhlMaWNg7/MK4Y19U
         BaTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU/hOSc8Bx+Zx8093sd0zK81C7g6n8KYE/szi3UYYGDo1fK6CrG
	oY/AClj3X5GFfwFkG2eqOao=
X-Google-Smtp-Source: AK7set9mS5Y/pqvZcpjGHCnQd92KyaUHL7s5uI3A2KcaaXRxUvVN0VcRdDaYQIpvtvyuXesXhmGGGA==
X-Received: by 2002:a17:902:c3cd:b0:19c:13cd:32 with SMTP id j13-20020a170902c3cd00b0019c13cd0032mr266855plj.1.1676645932839;
        Fri, 17 Feb 2023 06:58:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2015:b0:199:182b:34bf with SMTP id
 s21-20020a170903201500b00199182b34bfls2078336pla.3.-pod-prod-gmail; Fri, 17
 Feb 2023 06:58:52 -0800 (PST)
X-Received: by 2002:a17:90a:195:b0:234:409:9754 with SMTP id 21-20020a17090a019500b0023404099754mr146400pjc.45.1676645932074;
        Fri, 17 Feb 2023 06:58:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676645932; cv=none;
        d=google.com; s=arc-20160816;
        b=SxtyQCw/JrEkqqNFu9FzS30wdycmnEcJSDM5ke7WdVxF9VnjsHDEU+t07wld/VvpSv
         5QBiWwJ5ekXPwI9DfQ1YvGLeojLpe7s0fiFeXwz2IiDObW2+YQBfL1BtsXwcGDtoLhEH
         QvgkGVJNtQnN8XWqCeEZQqFRb5mwD/tGiewUnwR3EFKR8rgkaekAKJ0y1Hf2QgOxtMWM
         bIt2Y4iYZG3HUiXoyXJfXX0NgfigIaGsB26WPzycvDC7HmKkPMGCGXT/tW2Zi1UNJO9j
         YKU1nFQC6U22x9SL6jIMQ4rRjVTFcIWLpFFLvoDcorV8Z1U6p6FFv3Ktet2/rlOD2Z0F
         mKKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=MtqNCOwgfK+uXpcr0rZdEnDp31xRiNLfgJsnxPeWYqI=;
        b=iAIq+qimRXFnz74lOjh09wicBX8Q3BGqvBnm1XGjVtEJhHI8ryMO1F3CMKq5BokLAW
         waxzI5WP9YBJCC8gajAQll3BE8ZsuO8DPG5EF1dDIZ1ad4WyWuYGJfFfE5zjt408RxcZ
         P9OCu+WnqjZrP7tIiFEofkbhtE1bkGyRQMRGTaDiZi6IdBrSXhsM9P696pR8of3yBq15
         pBKAz4nHJ7wJjWHj6iSkhSGgBqzz5z/BTyJulSZF4dzXe/tdzTzYiAW54OaoR8H+bBxE
         JBMMHvnrwfDBtCh6QZYgQCulxQA2yd6vE6NwdvncouxooltQqS9sfXDyn1lIXLPg3hhT
         9hxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Y+nxlJ/g";
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id pf10-20020a17090b1d8a00b002309f8d0078si86756pjb.0.2023.02.17.06.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Feb 2023 06:58:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 8002561D4F;
	Fri, 17 Feb 2023 14:58:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CECF2C433D2;
	Fri, 17 Feb 2023 14:58:50 +0000 (UTC)
From: =?utf-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>,
 Conor Dooley <conor@kernel.org>, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH v4 3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel
 address space
In-Reply-To: <20230203075232.274282-4-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
 <20230203075232.274282-4-alexghiti@rivosinc.com>
Date: Fri, 17 Feb 2023 15:58:48 +0100
Message-ID: <873574uymv.fsf@all.your.base.are.belong.to.us>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bjorn@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Y+nxlJ/g";       spf=pass
 (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=bjorn@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Alexandre Ghiti <alexghiti@rivosinc.com> writes:

> The early virtual address should lie in the kernel address space for
> inline kasan instrumentation to succeed, otherwise kasan tries to
> dereference an address that does not exist in the address space (since
> kasan only maps *kernel* address space, not the userspace).
>
> Simply use the very first address of the kernel address space for the
> early fdt mapping.
>
> It allowed an Ubuntu kernel to boot successfully with inline
> instrumentation.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Reviewed-by: Bj=C3=B6rn T=C3=B6pel <bjorn@rivosinc.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/873574uymv.fsf%40all.your.base.are.belong.to.us.
