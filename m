Return-Path: <kasan-dev+bncBCU4TIPXUUFRBM56XGPAMGQEIUO3FDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3581E6778F9
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:19:32 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf4874247lfb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:19:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674469171; cv=pass;
        d=google.com; s=arc-20160816;
        b=gpL88yDGsX52BjLu2my6pnv5Pp1Ufsmx9rRLpe7nAcJURMcORJFp43MZrUXzKx+Cu+
         oBmIJxA8gNmsJl0RDS8eJPZduSOZqKjWNFI9LyIpwGdPsgOw42bO4ie0Mwkwnmtbn8VD
         9esQFgLFMaLbmG7B7w0dMH3j89m4WJtO0aafvWYWJFHoppa+Dxi8xNi8IeLgI7Iw6bXB
         7vtngm6LR/IEQ1aN13SmPKo0shiOfKlOazXGIPuaXW1dhj/Z3/RphRL9TReoo54YMjES
         1DoZnQe8Ln74UKE3ZESLxT/a0DCWyKPV9w942YmsADU3g3Oj+GJ1YvAlq64VJLwdbmJS
         o3Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=49+JSFRUU0MKTHapE5IrpR0MjEDE7JArS/CLhYFgIo8=;
        b=kiHRVpJr1z4W9pnTrB6uW6r4NeO6EMxYgO7duBKZ80XA/9Z/rnmzFRPKg1LC+jcac8
         c9VV59B4xSpxc317n7VvG31iLYEqhyu16GOnHowuJ5yV/iDjB6Ed8k7Vtxu5xFZVA59I
         R1vuZ6uB/QF6tFfbVuZ/oqLdQb15oAwIyhOuSFHyTwFRNaGuMbJVbNBTKA6b7TOSZ84R
         q7tOiBRkCqoGOoaAnkQSc3CEnJF5Ro/Zr0sY4lC7Qe8cdaM9PAjyZE3ZfaMBV5YD1KQx
         8xoh5gzZs95Z3LcRwOhIw06b7wmiJbuorfo5+SynOU4rRJm4kthzw10DAR55BvG6sFsm
         VKvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qyAVZIfr;
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=49+JSFRUU0MKTHapE5IrpR0MjEDE7JArS/CLhYFgIo8=;
        b=De2YGM3FCBsDy3bAUv1fSJn3If8Ctyp3019Oze0AiQhaPkAvoWM0f9CRqL8MJs0bmV
         L3yKP/sMBrigWDimB95jBAosx4iJDYOgrx1Mxzwt+bYxB0IOJas+bkV/pCXLtDbRR0Mt
         95Rb57mrAx8BVERlQRQ2N/lqbPQ4m2pWr9OV2MKIC5W5M9qUFdKeBmWHQdaFe9y02hQW
         1NzSnkPGhfQqjW9BRWtL2TkYickN5jrkYaExBo0cbsntT6TgEbN4pmFjNsAfxf1+CtwY
         LnTEwucqZuejmIV1g9fA0ofCo7Dwe88+EPG+U491u/34ZQEBHjY0y4olO8x6fqxVBM5q
         /hpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=49+JSFRUU0MKTHapE5IrpR0MjEDE7JArS/CLhYFgIo8=;
        b=rOCRHYfKVZ1WEj6KPhsjBc0NZ36UQpK8hdHNaGmnMEgUBCplE9ka54RDdMogS/uFH4
         +65D3stK77HKzK5uRs9jgsRim5QCoh59Nl5zAj4ISuUgBiw9m3rODmjYjPgvWbFJ0A8l
         CDAUmp8CuOXenJLOXyps8dlo4r4YpWP/f1iJxNa6YOcGegbEpJJ33bGOYlVdAdTuEYMG
         n9RC8SqzraJEz/aNW1vke6SiXk0cfGJCe4KLye/B/ptFqQHYDKn/ts9zidZunBPVXlpi
         nNIzs7tkTFWHkcZIZm5w26kZEDn8bOWx6s11gfiPCpJxCQKDxQrmx8dK0OIBXtcIWDj1
         d1xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq8oSqe5/2Ts0oDAlY4Kiz8KjVKN87/iG2COMOQKoHLzZxXZfIl
	QhGTm2HgHe7xmO5piG55sug=
X-Google-Smtp-Source: AMrXdXt3CXEHa/yGODf3SXjrzhlEHkhzqvklT8mZpI7DEQJ4qWd3CY2a7K7M1Gsgc7q+wfK1bfURSA==
X-Received: by 2002:a05:651c:102b:b0:28b:95fe:660d with SMTP id w11-20020a05651c102b00b0028b95fe660dmr1581714ljm.131.1674469171633;
        Mon, 23 Jan 2023 02:19:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b90c:0:b0:27f:d6d7:84c0 with SMTP id b12-20020a2eb90c000000b0027fd6d784c0ls1451092ljb.5.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:19:30 -0800 (PST)
X-Received: by 2002:a2e:86d4:0:b0:284:53cd:74d0 with SMTP id n20-20020a2e86d4000000b0028453cd74d0mr6178636ljj.14.1674469170208;
        Mon, 23 Jan 2023 02:19:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674469170; cv=none;
        d=google.com; s=arc-20160816;
        b=bsFkYrCaVFmIJkTRckDMx6mpvw69dXAmyDJ0vtdUUUblRue9LBhghSlnOs9YkG1+My
         QskPLwrIZqpJuwyehBdwKfPJm/kNMFitgpxHq52KcxIcbcnPhzMZtHeRkD6NExmwASsd
         XAMMG3DcJzX4Rcvf1lBBiLBKl99B01FbXhD1BqS4UoZRelWccEM9hK2z77lZ5ysPxU6i
         C3psGZT81xKczsD2VMwrF7n2+5sYB1uXrC+wzBZdV1vrqsGb/TzxwTtediMhHT8dYbcL
         kWqLOWMFkROXyB6SLF36N5+lqMov4k3uxKwiYgumh0XAa74cfzxi7nw7pW0dDNi6B2zR
         jJjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=49abDuRGTQoOeEHxYV8XHLPa9mr381EFlBAMY5a18W4=;
        b=ZAffER+MUCOi3JNTnBQ61kC78cTD0ma14mfH6natJi5m7eYQF4iZ51KGBYNjostg/b
         809MlyRQSm086sL+t8a9hKS15K9j1LoGoT90mibNMwuW22FUdNBHNJSGDEK57nVwa3to
         YRIzcp3wsWxQ77KNRRd6UC+hdTOrT593UIgvwmfYIblquNgk5mCyPf8ESPfim3mLn3rC
         rXxnEQTo3iw0NjexQ2hKbGhsJNLqE7yGyQ2HUsl+3FI9UcD5Hiz3R7y3NNpbxMzO0k2q
         6aVaHEdD0PH2FJ2/I9XeuM4/tCwyud8fBUUd7sXEuWjjpdAJKx2eCWX8Tsd1xh7j3VC3
         +J8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qyAVZIfr;
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i21-20020a2e8655000000b0028bce3cdc06si335186ljj.3.2023.01.23.02.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:19:30 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B39CDB80B9F
	for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 10:19:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6A1EEC4339B
	for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 10:19:28 +0000 (UTC)
Received: by mail-lj1-f181.google.com with SMTP id o7so12590920ljj.8
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:19:28 -0800 (PST)
X-Received: by 2002:a2e:964e:0:b0:27f:b833:cf6d with SMTP id
 z14-20020a2e964e000000b0027fb833cf6dmr1969790ljh.291.1674469166406; Mon, 23
 Jan 2023 02:19:26 -0800 (PST)
MIME-Version: 1.0
References: <20230123100951.810807-1-alexghiti@rivosinc.com> <20230123100951.810807-5-alexghiti@rivosinc.com>
In-Reply-To: <20230123100951.810807-5-alexghiti@rivosinc.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 23 Jan 2023 11:19:15 +0100
X-Gmail-Original-Message-ID: <CAMj1kXEk0Vpf6-_iVwyg36MWtQa5HXGdExDzaFU5-12179shmw@mail.gmail.com>
Message-ID: <CAMj1kXEk0Vpf6-_iVwyg36MWtQa5HXGdExDzaFU5-12179shmw@mail.gmail.com>
Subject: Re: [PATCH v2 4/6] riscv: Fix EFI stub usage of KASAN instrumented
 strcmp function
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, 
	Alexandre Ghiti <alexghiti@alexghiti.eu.rivosinc.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qyAVZIfr;       spf=pass
 (google.com: domain of ardb@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE
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

On Mon, 23 Jan 2023 at 11:14, Alexandre Ghiti <alexghiti@rivosinc.com> wrote:
>
> From: Alexandre Ghiti <alexghiti@alexghiti.eu.rivosinc.com>
>
> The EFI stub must not use any KASAN instrumented code as the kernel
> proper did not initialize the thread pointer and the mapping for the
> KASAN shadow region.
>
> Avoid using the generic strcmp function, instead use the one in
> drivers/firmware/efi/libstub/string.c.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Acked-by: Ard Biesheuvel <ardb@kernel.org>

> ---
>  arch/riscv/kernel/image-vars.h | 2 --
>  1 file changed, 2 deletions(-)
>
> diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
> index 7e2962ef73f9..15616155008c 100644
> --- a/arch/riscv/kernel/image-vars.h
> +++ b/arch/riscv/kernel/image-vars.h
> @@ -23,8 +23,6 @@
>   * linked at. The routines below are all implemented in assembler in a
>   * position independent manner
>   */
> -__efistub_strcmp               = strcmp;
> -
>  __efistub__start               = _start;
>  __efistub__start_kernel                = _start_kernel;
>  __efistub__end                 = _end;
> --
> 2.37.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEk0Vpf6-_iVwyg36MWtQa5HXGdExDzaFU5-12179shmw%40mail.gmail.com.
