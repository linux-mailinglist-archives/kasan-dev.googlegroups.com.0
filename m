Return-Path: <kasan-dev+bncBCRJ7M4BUUBBBTVLX2PQMGQEI2T44YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id CBB0269AE95
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 15:57:19 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-17172aba586sf593098fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 06:57:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676645838; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3PsDVMPecMT7qH5eE2KnYRxD16VlKTveYOQunbTYJbLkKbCuqt0u+LX1GV6mwGVDG
         Scc3GbFcmkEC0Q4NR+h/8nxcDXBcckC4GsYt8E3Db3nexVo1werCaGivbi9GuGPp9Z56
         C+lvh08+ULxn6kxVjrO833pPrwmtywi9A55WqxBfVmE+uZFCYNmw2Csb63pZebxt6EuZ
         vbc99Ajn1ZAgwiKXLRoimEpsZb+qo62QMhvkTwE2p1P57g7i9XuLvp7Qk9brTGSZpKUS
         c6nPjXNMDIgD1muWmQjppH1vqDIB1FW7+3Ld5wg0kgrvms5hbmzwQHyoZNc0lrDBLBz/
         fGZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=0Y3eL13oDTsGAZh4syznH/lr+8aJa3xIA5LEwwhpzKM=;
        b=Df4rz4PyErNN+0qgOP4GV5ayVhFqlgNlkWmnEzO07vlPRzSBKZYX2lvr6l0zREYXlG
         v9r+vRjIbtQg5nbxVXk3ByiiiwMCUryuFX/NxJtzzkowbWmshgKfO2qlvMzkAA+xYz8V
         VzvVnuOH9eRxHjhrKi+LOKgQoT8g9rGy3jS7k6Au7FDW8A6y/yAG+UrRlHmHkmFKUIbH
         crhSTkLVHN8AYYgqtiixPxiZ5WSBPfBGFTszcT2RE+vsEgxhnpfFuZnSltcFuz0QXKyv
         9zWzgbpRhnzxZE1crZtLz4b0Qo22SjugEEFDH2aVq45OjmcvpvCI4F8+GaWaRhQfoMeA
         ySBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i049caV7;
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0Y3eL13oDTsGAZh4syznH/lr+8aJa3xIA5LEwwhpzKM=;
        b=jbFt6q0KMQKJtygkT0ivGEhuSBZBoZUxjDlymhuI0NaNkotsK/29yBeXOq5TWk+LET
         lfGwvYNII3TPpfMFe9Y7aeE0oSuAsmxHzcVmoFnG3R1w+iGRMjgXMUKjE9watMnku7VT
         qDgAVHgP0wNF3sRD1a8meXZIVSIfOO72G6V7bLn/u4FHtphvHdBGbACE4X1XNOtm9pkx
         J9VAROFlILkWnUAEwZhmPX8BkstT0jvHoFGLt+aKcJq0KYW6y6itn99IGSSuqikzsUpb
         oaIy1jJPtRXxz2BPzuZr1IO9bHukAGexHxu0EmEoRfVBQZy1bivyoNOE5tp6Usj07XVe
         nQLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:in-reply-to
         :subject:cc:to:from:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0Y3eL13oDTsGAZh4syznH/lr+8aJa3xIA5LEwwhpzKM=;
        b=xvz+ZkKJuOESZPAzB0YNnmHDDC4BaeJj6Ag299Ghzjfk3PWaWDj/U1cTlfWUCWywWa
         YSAms+fIY6h5IaY7b4Ckq0RwEMgGRd43/iJPQj56SH1aYIEYV8mxYQ15f9SCA/Sy26bn
         YYj40WGjf2GVYQWNAhzxeb8qIHy2/XRTa4+KVR7lNMwoOSRwpvP09TKLCa3xCk/KyaGi
         Eon8MW9WR50ME8OODYKuhjejZkDhK23YdbcThBreObV9eK8elHzgkJl2trSw+b+KEDgo
         85+2sCxTCx2BNc1STMCTIYcoInjaLq1FtQRO8+sCUbf1gBo1cysjtz22KOQvsJ8cuaq1
         9BiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV9a2tmPWKSHJTsbXe7KfxJZ48AwiTtUrjdNm+6Xq9IrhBGs0Ha
	86TdW8+8uTS/F8Cbnf9iseE=
X-Google-Smtp-Source: AK7set+uvY1U9HqLJE1TE2oOesiXGq4t6nRe8T5UA+HclRAq+LpmAN2FZ2TbK5Av2iooDdxoP4IcIw==
X-Received: by 2002:a05:6870:4151:b0:163:5216:1466 with SMTP id r17-20020a056870415100b0016352161466mr723143oad.44.1676645838580;
        Fri, 17 Feb 2023 06:57:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:220e:b0:37f:b1fd:37f5 with SMTP id
 bd14-20020a056808220e00b0037fb1fd37f5ls857888oib.6.-pod-prod-gmail; Fri, 17
 Feb 2023 06:57:18 -0800 (PST)
X-Received: by 2002:a05:6808:5:b0:37f:b436:fba6 with SMTP id u5-20020a056808000500b0037fb436fba6mr985955oic.21.1676645838175;
        Fri, 17 Feb 2023 06:57:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676645838; cv=none;
        d=google.com; s=arc-20160816;
        b=BGnazWDDOe2lYPAFGlE5tecHA7KWBMfygkmE/udD208iFGLK+3FOUs3bpYkRP1kx8L
         +4ChdbxeptH8zueWz3lX9qXVr8r7mPlRgi3yOdC8KPoUEMS2HygdwFkdj0k2BTxfmdyq
         C9WSgaAHuMWZVYmC8YW22AbMfLSmalOHIF7k2ucyzMnIXE/2qw2sxyjFIcYk+6YQ5xjn
         vXHQeWW/tow4cStmFklEk1gBD5AXR3kFj2XmDTvkl8k8NDiVahJnpSLI/dnuGWZCVpea
         22osTssvHYqmRPgpUJOMvrzsmtgAhSZjIbNHVf20HFvVHVyXtFxZmx7HHWq0H3qt+fnm
         Rp+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=BTFggd/Tt+eYMh7lG7jR9TXG1g1R8MGJ9JNjMNiGaD4=;
        b=z0sgtHwsjQsMjzvvG8nzoFQ73GFTggrSSMj6khgHYeJEZa9Ya5jfeYqpfFTF2WdPfU
         epKjdbH+rEB9Ykaj4NTwMx8whIk4pQnIppUaw6EASLhhUndJoOwK9FeWMumeIt7Pgw3C
         gkWMICw+evlsFgeF6YtHuFaqpVlenUx5aVwE+LDFmDoBDqANtmKvQR6GN+NrXB0/ABJZ
         Nywp5mO3YLJE9dO90+wt4gkXDKsFP91gZ+qNR3E94Lbr5/w+yYSk859WwaDd8wgDd1gf
         ujxR0dXnS4ImymsMjBP5wbDzuRGl28WKZ9j60JB+QC6r94YatUuFqKHNyIY7Y8rC2GTr
         133Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i049caV7;
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id j22-20020a056830271600b00690ed90f8e0si156450otu.3.2023.02.17.06.57.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Feb 2023 06:57:18 -0800 (PST)
Received-SPF: pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F27E461C30;
	Fri, 17 Feb 2023 14:57:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E5798C4339B;
	Fri, 17 Feb 2023 14:57:16 +0000 (UTC)
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
Subject: Re: [PATCH v4 6/6] riscv: Unconditionnally select KASAN_VMALLOC if
 KASAN
In-Reply-To: <20230203075232.274282-7-alexghiti@rivosinc.com>
Date: Fri, 17 Feb 2023 15:57:14 +0100
Message-ID: <877cwguyph.fsf@all.your.base.are.belong.to.us>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bjorn@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i049caV7;       spf=pass
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

> If KASAN is enabled, VMAP_STACK depends on KASAN_VMALLOC so enable
> KASAN_VMALLOC with KASAN so that we can enable VMAP_STACK by default.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Reviewed-by: Bj=C3=B6rn T=C3=B6pel <bjorn@rivosinc.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/877cwguyph.fsf%40all.your.base.are.belong.to.us.
