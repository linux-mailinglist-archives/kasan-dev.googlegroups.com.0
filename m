Return-Path: <kasan-dev+bncBCRJ7M4BUUBBB5VKX2PQMGQEBVJCRZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DDFA69AE87
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 15:55:52 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id j12-20020a056e02220c00b003159820c0b9sf1728072ilf.6
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 06:55:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676645751; cv=pass;
        d=google.com; s=arc-20160816;
        b=w7ouzWNmS53tJW8ERkgMLG+tViUK+lQmUVqgg4Pw1ZQuQS/Ciy4lq2F7jQAXLAM6o4
         cT5X9qXlQvytPjLX1ApV/TS3K+IjylSHo9IQa95NfAwjY5o604a32CzGTLkTPBujzoj+
         bk+OjwsflzvcyHMCqDZv16k/PyaZoGr/I4Cvw/fEcojJ1D6VXBJjI4pbQc7ob2rDs6G3
         RylZZGtFSt7W1opp2vjq4wTebmH4t0bdvx/2nWIGp0duWhEnuMMmSEcqfAESvbAP/Bq4
         4dnDxjyBwo1L5e0sh6M/igw52j27Ucsedd5R7kwsEgJnwX7kxercQxzWunmSp6787AeA
         XDTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=XZRQ5PXCrMKFueu7yPYnAEGg5xEINFXReV7WiFs/H74=;
        b=ACe4gfgphW4wllTAAtGvckNqGi2vynmoRyA708rOrvgWvRvulXMJVZIEXawmoRa6F3
         G7w8hoAOTj4vMaNyrI0S0/u3cZt+eejyMC1jkjv6oEJCuujtvYWF7mGvm0dTkW9KLOYt
         kzjt+z6o2D50C1Gn+IGVCLOndbKLZOCpXK4lYpK8JctZtaUBLkvPx5fBqugCTBTgpvjp
         eTsYI0hl6cOD06oy80cXvrlpLJNND28DToh+Ey5D2vzjdR7FLXYYS7bA6+Pe6Wl5PlZK
         j5QrGv9XIcelcPRJLLKjBC8StB19KO4su/j+tiZYu0TFnocqGk+pCjdKudfPlhBkz2wl
         R89A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vDnmzDRw;
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XZRQ5PXCrMKFueu7yPYnAEGg5xEINFXReV7WiFs/H74=;
        b=Tdt4Tq+OIxQ6dZSlvS70BlY8r+NZ+kYffP9ibFCP7vYdkEBmm9AV+2KjjoxPlpRufx
         d3caBgro+/0WR+BX4sh/CNbGd0CyXBQ5SfrqitNOcfwd/CtzT8igzzwdJxG5NElBJFM6
         hZib5Q+uj23km3GB/CP91qCSM95yv8OvmY5k0gv8Qpw8VAEJItKPlxnwBi6SxfmECPWr
         eZU4R8LzPScHFXY6x8gAqPAo4ZqxuNg+79xniaDkVai+MXopJveaZSWS0AiPDGn6QsXD
         Hz4NG01yK+gj3f2fXUKpwiDdALtNu5q6B7WHGq2Rid+da48UL1FINhxiUCD362r2tzdz
         8kkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XZRQ5PXCrMKFueu7yPYnAEGg5xEINFXReV7WiFs/H74=;
        b=m0bZNp7AqujMDEeIiiO7+kQAgqttWxVNMl1XZeie3tgsiGIJ72JMlUrw8wMcUYHIm0
         HX8eB97yx0iqmO1uO/ZdGZUdvX3i+8iNnHkUgHKT3ic1WB8aKeVmPOkLjjnwNorX39fS
         qtCxqoktbmXAHj7ZFkk2asOcpLyULPi1mDpjpCTzEax5MwktN402YuYAVL+THBReZJK0
         /qnhB2F67VgSaRFS47zx+vFvt132pwwGeVeb0rbijsv+IRP2YNj2mi+3m7v+YCM+2Utq
         nzeazxqw/dvRnZlzR2Iu5e+RXh4P42GEUWnjkPnTDFJJ+UXIHu6ZBEHwMQkBZd+blajZ
         1q+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWlOeJUZFQG1TfDduTVBNkJP+d2nLwcbTtsHRlPviu2t1wVzbu5
	uRQ2Ly5NyA70H57SVTpf4nw=
X-Google-Smtp-Source: AK7set/O3k1cw8grQPdlu96Svo0wsIXeFGgxzaA7O6Q7Sm29A7d1mR4Hwt8g99nciUD5pN3gKW9zWQ==
X-Received: by 2002:a92:1a51:0:b0:315:8de2:2163 with SMTP id z17-20020a921a51000000b003158de22163mr1319141ill.5.1676645750719;
        Fri, 17 Feb 2023 06:55:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d581:0:b0:30f:5830:d010 with SMTP id a1-20020a92d581000000b0030f5830d010ls278363iln.2.-pod-prod-gmail;
 Fri, 17 Feb 2023 06:55:50 -0800 (PST)
X-Received: by 2002:a05:6e02:66f:b0:310:d7d2:548 with SMTP id l15-20020a056e02066f00b00310d7d20548mr193572ilt.31.1676645750255;
        Fri, 17 Feb 2023 06:55:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676645750; cv=none;
        d=google.com; s=arc-20160816;
        b=ASd8nJ0Fy2Er+ApMrRIxRY/lJ3lU9X8sClLT8rpuB3hT8LBqN5i7SQIKp6EukdjQLi
         P0r/MMsoXUbRiXuDIZ3piArVUZnSsdqKwRYvTANTQi4Nq4lQwnNHI6uZQ4r7wFJ/tKcQ
         ifdyu4Y28+r9dpf4KfjO7EC0BmdJyiysdd0XAsULZKhM2tCVTp7g1AHjJtJz5BhBzVML
         iiIUgM8lfSgsD+NUFJwHe4a/TR4c86qa4htArfS87ev4rPyPGn9WWWf8Ns4yT7XKKZDd
         jyKLa96TEtk1YUwy+eGZ96QfrGU9RrMm1lvT8fL+5UwCLnG173D5FUSF8V07UMyg4jo1
         Sv3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=oBBS7zR/ngaH2wd6CRyl7EabRqWFBiQfaWOFffYmUc8=;
        b=gr8wHo+i8jRIfkI8+rs8UZDpMk54eh4pWbUiOB6mA5gDSDjZRGvU4HISZ+uKpnoXA5
         1lx4fI4I8poe2ogazzIBQU96vp4GEigbbrHC3d/Cpn3Cd6fGVEAx5HvNjww5HVvRUxy9
         31wCpIlONUsPR7bX1CQTlGu44f2n0EvvgIMc4gs96TT5G6Ay+dYnUvtSbnJGhb5dplsX
         qXTDTpWl+434cWdwI/ubVmxd+HKcqmulPE8UKrQBS5LfgkuzBzZYI8eiMa7HrqAxofJA
         7NPK251NW6JM/egFDLLsLSvA4wc0OlJot+jZnBYSD1ZjWz4Z+OsPJmacML6OyDr8TyyR
         ZQWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vDnmzDRw;
       spf=pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id cx23-20020a056638491700b003c4fb897b88si570287jab.4.2023.02.17.06.55.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Feb 2023 06:55:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bjorn@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F151E61C0C;
	Fri, 17 Feb 2023 14:55:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DB6C4C4339E;
	Fri, 17 Feb 2023 14:55:48 +0000 (UTC)
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
Subject: Re: [PATCH v4 5/6] riscv: Fix ptdump when KASAN is enabled
In-Reply-To: <20230203075232.274282-6-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
 <20230203075232.274282-6-alexghiti@rivosinc.com>
Date: Fri, 17 Feb 2023 15:55:46 +0100
Message-ID: <87fsb4mjd9.fsf@all.your.base.are.belong.to.us>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bjorn@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vDnmzDRw;       spf=pass
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

> The KASAN shadow region was moved next to the kernel mapping but the
> ptdump code was not updated and it appears to break the dump of the kerne=
l
> page table, so fix this by moving the KASAN shadow region in ptdump.
>
> Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mappin=
g")
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Tested-by: Bj=C3=B6rn T=C3=B6pel <bjorn@rivosinc.com>
Reviewed-by: Bj=C3=B6rn T=C3=B6pel <bjorn@rivosinc.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87fsb4mjd9.fsf%40all.your.base.are.belong.to.us.
