Return-Path: <kasan-dev+bncBAABBOERQGHAMGQENQVMPHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 79EA947A6A1
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 10:11:21 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id a8-20020ac86108000000b002b63fc40062sf7968934qtm.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 01:11:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639991480; cv=pass;
        d=google.com; s=arc-20160816;
        b=D+JobFPWZ0gKk1ul3MrYtZHbgEabK+wnytKARNPYy0H1NU+ejxVjiTp1nqqtm5jrmP
         GKv0F0pQZGI+08AIASnM6dR2P4DE3fx0iuX4/JqSSUOPumIoYTz10bbS0FxVUBTpu+fe
         Z8TrkNQVFntaM3+PDNvAwwicnmauAPNkMkuVyf4N4p0+yYvnklDsY4CvGqFbXe8qZfP1
         7nrckqk/19Rbwl4YwbqhS/4mxk6/pI1J0x8GGKcdPaTm5sYtunMX2ftMvAfqR644UBbI
         AnWNdHpuQXHlg09Z/5IAir3j7bpQ2nMjcqgmsNNVxsQE3DUMeuJQwkDqFuD+jJVa9scw
         G3Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=98L+85VlfC/0T7pykTFWNGxOl2SE3Lb9/BuPX0mJY4o=;
        b=og/U2MG8YUMbhZN6g+XPXTHYY+uOkq/99eD4NRWFdXzJIJvC51o/4maIv+WtWW6bKi
         TgNdmGtr+R4Yftuwgox+ajYLQXt9c95MpGyQ/zOQ/fEGLXgO6PAf8r8PLByV1kfEl7wC
         5uia340QpsrEUWkGyD24NPgkodEcwHo1IPO8UCSC9PweV0nYnDwjQcojqV/YL1m3ABzo
         7E1tYBpj7NSjd3GgbWXD9eEaUb1yAw42gnqO2J3VfV1SZ0oYglQRnoIz3kH9cnUFc+fJ
         VTA6T/wjFaejQPHn45YWZlPuOWuF4mL6dujwTMA5T3XpbEcVJXcaaJUT3pO5xs2bO0Va
         DvBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=S+pQs5Py;
       spf=pass (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=98L+85VlfC/0T7pykTFWNGxOl2SE3Lb9/BuPX0mJY4o=;
        b=UCcgtYqus2JrrM067cyPxFxLaDJ29KG+W6b0MyLLCHal7+X3ge8XveQer9cdfXbpd6
         1Pc7UdvRh37nTlubX4i8fifuDEH2i1w01InYI1guafXpyz63D0p6saULl+9NjQh8bJ1h
         Dn4B8lhwV2rDcQoDx4ZIX1mJE/2fqrUafJCMA3b1BklFVWiOWtHuoMJg6jOVVjiJC1d8
         NuiNiclANGrSoIix2/H9OZnbQdT2sggZpMr3lbs38ZO22uEakmCs4we/ubfM0unvospi
         3O1eAGqfB4wDANXE9Yd96xWSG7a78Mxk/EvD//EL99QJ04fwlHk2f66qxOqARdJi0rE7
         1gfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=98L+85VlfC/0T7pykTFWNGxOl2SE3Lb9/BuPX0mJY4o=;
        b=42vZJJe++tsVSATD5HgMIO21KhUB7pAyeTk/YXw1ghKaPUWvuZWeJWICZnGNOJv8RA
         qlfmz+Q3sRe5Vw3EtLILW4DLwgOGeDwbJ7YRyUkUQgwwURU5bINs8wFLjJGdFvnB9Lvx
         7d3VWSLjs+6jAW8gYdhqwYUi1fpCz0g5y3QDEk6K5+edmpRibpFQJ+LAlpELn4Jrmm0L
         Z47Vvt+u3rRjkp9qhAYx+WXRpQxze49dcmP33Kk2c+ffYYkQwrmPoYRb4cmo2Y+W6Yh3
         BZyNxhozbNf+HbHaNkzm+X6Exytpll6B0/DlaxgfZ5FAyImD68U0pkVMz7xxdKs4pEgz
         xg5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MhxgQyejZ/5hPmKo4qiDJ8scfP3Q+O+iL2Eb5zmjs3H/Q2HpL
	hEl0dyWGxXFomrhrf4NlG6I=
X-Google-Smtp-Source: ABdhPJyDvDffY8R0g4JAvExxgEV0FPw4+fm52yoKLbXkTQZiElvtUYQ+amxfSZkl/pmuM/2L0x5fog==
X-Received: by 2002:a37:647:: with SMTP id 68mr8857229qkg.343.1639991480235;
        Mon, 20 Dec 2021 01:11:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e40e:: with SMTP id o14ls6871620qvl.10.gmail; Mon, 20
 Dec 2021 01:11:19 -0800 (PST)
X-Received: by 2002:a05:6214:1bcb:: with SMTP id m11mr11742994qvc.0.1639991479778;
        Mon, 20 Dec 2021 01:11:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639991479; cv=none;
        d=google.com; s=arc-20160816;
        b=yxrJcd8mtENI2sb7A9vFOSof8EAupJEn9XAS74MCnvyVzUeq2fJoXtg42EBKc66CEx
         XQyRfdYCoquLHj+R3eBhOqBtoRX07XD+DcYETNLiYM8k2KYMUEmFKe+40/UDcgqiMSAF
         NY5ekBW3AUc+4cnHk00tI8D9kLaZRxhM5/BnupPvE2yEr5DFiGAOtFAk9iFyvBpo7z7o
         vzJNMq9Sr4CxhhgFryXHsRIrqWXt4pjzD/c411VcKGaMRFFwj2pVxk0BNVuC4ibY3lMA
         TdOEd6wh+5GXp8nK4afJLgOCoy+qAuRu9vUBZh9YxKVJAI3lHQDK5V8WVDG+E7nkCHDa
         9onw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y08IJCu203XMK/RQhohC3po71DDKzuX6UfzCP08GzLg=;
        b=ZMU3vGRYf8zG+PK13R3k2eCSt4vcVtaiXfR07FMUck6nAWMWWAGexmMjDqtknCzneu
         lbLxsYpm3LzvY14gIT9Jiika8aREsY1ffkkJDIDt5CZXhQVdOmQr0Stka0BClrP6zM8o
         nIK5Ayn+0lX5HxaIzjNscXCEkSZyASuvn/NpuP8gGNKQYAmppTWE2jBOc1+dl+PjScwe
         PD0I4eEVeiXYeLRUZAS+2KN/EXKkxCQea5lV35DROtszZEF8C9RR54JRX4PGldgpXxns
         PUY1Fxi9Jsj9STPOGq8n/MhatpDkp2IxqxLO9k0StqUCRiTsmWwcmtTZ7xxTj2d+KU0I
         SE1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=S+pQs5Py;
       spf=pass (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bs32si1143643qkb.7.2021.12.20.01.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Dec 2021 01:11:19 -0800 (PST)
Received-SPF: pass (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4D9A760F10
	for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:11:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8ECA0C36AF2
	for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:11:17 +0000 (UTC)
Received: by mail-ua1-f47.google.com with SMTP id y23so16437584uay.7
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 01:11:17 -0800 (PST)
X-Received: by 2002:ab0:3055:: with SMTP id x21mr4783242ual.97.1639991476313;
 Mon, 20 Dec 2021 01:11:16 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com> <20211206104657.433304-13-alexandre.ghiti@canonical.com>
In-Reply-To: <20211206104657.433304-13-alexandre.ghiti@canonical.com>
From: Guo Ren <guoren@kernel.org>
Date: Mon, 20 Dec 2021 17:11:05 +0800
X-Gmail-Original-Message-ID: <CAJF2gTQEHv1dVzv=JNCYSzD8oh6UxYOFRTdBOp-FFeeeOhSJrQ@mail.gmail.com>
Message-ID: <CAJF2gTQEHv1dVzv=JNCYSzD8oh6UxYOFRTdBOp-FFeeeOhSJrQ@mail.gmail.com>
Subject: Re: [PATCH v3 12/13] riscv: Initialize thread pointer before calling
 C functions
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@rivosinc.com>, 
	Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>, 
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, 
	Mayuresh Chitale <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, linux-riscv <linux-riscv@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: guoren@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=S+pQs5Py;       spf=pass
 (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=guoren@kernel.org;       dmarc=pass (p=NONE
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

On Tue, Dec 7, 2021 at 11:55 AM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Because of the stack canary feature that reads from the current task
> structure the stack canary value, the thread pointer register "tp" must
> be set before calling any C function from head.S: by chance, setup_vm
Shall we disable -fstack-protector for setup_vm() with __attribute__?
Actually, we've already init tp later.

> and all the functions that it calls does not seem to be part of the
> functions where the canary check is done, but in the following commits,
> some functions will.
>
> Fixes: f2c9699f65557a31 ("riscv: Add STACKPROTECTOR supported")
> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> ---
>  arch/riscv/kernel/head.S | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> index c3c0ed559770..86f7ee3d210d 100644
> --- a/arch/riscv/kernel/head.S
> +++ b/arch/riscv/kernel/head.S
> @@ -302,6 +302,7 @@ clear_bss_done:
>         REG_S a0, (a2)
>
>         /* Initialize page tables and relocate to virtual addresses */
> +       la tp, init_task
>         la sp, init_thread_union + THREAD_SIZE
>         XIP_FIXUP_OFFSET sp
>  #ifdef CONFIG_BUILTIN_DTB
> --
> 2.32.0
>


-- 
Best Regards
 Guo Ren

ML: https://lore.kernel.org/linux-csky/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJF2gTQEHv1dVzv%3DJNCYSzD8oh6UxYOFRTdBOp-FFeeeOhSJrQ%40mail.gmail.com.
