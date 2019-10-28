Return-Path: <kasan-dev+bncBDAIRSWYXQGRBX5E3LWQKGQEN2OVT6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 38BB9E6CA1
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 08:01:53 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id n30sf5447252ota.23
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 00:01:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572246111; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYzbBedTOTh3CGOXPlAHurjtxCSqn3eqA0bC/DKn/D8rkkC7jdDk/sRh7ofJc53ln3
         KtAvh+RkCIQmCqlvQuu7ZB0cm1YidSeDxNJMvqLZHQbuvshSzc+Mz4AE/QC4B3wpNyem
         I8degIqUmO9rnUm+9FOn9sU+LLOG3h2D60HwhkRAiwWkcP0EugM6cn4xETEwF6poaHGK
         ZDyZoUIqScjMh5KaRF65TF+GdipMmDpXJlNIt0u58sa89l3yJoH5q2UYWIQrhUzR8s/T
         ZMwsjwkNbGJT9J/94pXFYqk2pQ26s5bgMsN19EEwK4i2T/vRY4Bzj2TUilxH53gIcPUf
         n3qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=37IWDmTg3cnTqup6iz3dOQ3N+b57r3xcb7frulg08Gc=;
        b=Xgza4J/JsIxXBjUqS+/0pgu0VQYTps0yV9oQ3uZ3EZMb+Og4IviPOas2dPfpQ5x0RV
         +6naf7adCfHCA3y7GYhTSRFb+Y/PskljsFvvonmXDLT7SkWyxaj62VMy/sgC1ALkXcCR
         zJJeoq+Kj5ys1acmOVMRXg2f8D9cyVibQMJaxMAsBOXNJ69sJ3n85vs0qIDApAtt7gG2
         efZLyCSSTXaHSTXsn9DNEfvx0T8ubIB6bB5CaY/j+q7B4LiKSCP1P831vKeApgZxvc+c
         rO+HCnUXfUbCe6PEZst+WcnGaynqELmMAXpqOsXijzt0dOyC9Qjp9d3uN4brWgp/Bho1
         kI4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hx7QfTuE;
       spf=pass (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=green.hu@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=37IWDmTg3cnTqup6iz3dOQ3N+b57r3xcb7frulg08Gc=;
        b=P1uaooEdvnJuZKelkssJRIortLVSU319eX5WPGvz1Z48H562ju+Uf/Z6sZFlGobCB2
         YijmbbdxjHf7/cXAGDJsTyrVS3nFK9nVxfOO744J4buTYbMaJPub/9HC+RBesuCqDfnH
         cgZplDj1gzmGyK1duRVv6Qtma1GlnOp0M3i0+EgxIcbt7jfoqjX8m5m6cy8xntBI3uj5
         OyXmAcK082o0Oxe8SPd56Ua2L2ZYZ5SJ6QpfdoT8eE9owUQT3cvmJsQ+mR2iNnYo33IS
         9l1eZF7qH8NpAqeNMyOdPJh+dBcnhOsEo085J43TT8smxjOfXBaXC8nXJ8OoFTe0jP1A
         Jqjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=37IWDmTg3cnTqup6iz3dOQ3N+b57r3xcb7frulg08Gc=;
        b=Fo/FslrXKqELt/ALdfwVw6qTIMqOXeCoxDot2IAfvWwn3+XFdyhb0GTEQvfBI+SFLd
         oP7/tpgLLwn0wfI2tklQDH3TjY+hrMfMy4/X4/CyyOE49aDE1xQp3cQr8ApN2WSZQLeO
         i3AVd6JMsLgCTpX/l8kE9tEusYD81ES6QkOU61fyLYdT59p6pMouMVjcu1RdPWjU+Dd4
         k4HHqpE8tptEWCpv9kP9Rhlyn+zoBnoP6oCPAumA9qC2iQBx5txjkyvL4eP5ZiggKOfC
         xSQEOfP+1kz0F49hGKR/E0wkLchGfnyXUanKpVxWiu5NOD6Z5aWuI93nDpf8wiYWEBqs
         TwPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=37IWDmTg3cnTqup6iz3dOQ3N+b57r3xcb7frulg08Gc=;
        b=pgoAN520TQhRR5kA98qSUDAPzFmYZKioUEjbToMfLvVGk3419N3vHIcNbMXK5wYxLe
         lFg6jImUZrE7005uDXtDu4Bac+M7xyf5LUmsa9oNmHIef9heEDFY/Twn3pJa8wX63Qbr
         HqTqGhGv1z9eSTWneJxTha7vQDYyWS+E6KHLovExWNpQ2GA5br/OBJc6V2aM8k2OGT2l
         qwLmt6mquVT9rRnUR9UwPysf9ljjx0HRQKLLEFNc5W4R5uF27g0xJlTf3yp8EEXCAnpK
         mqMhnl16n1T8Fuu2mM6WCLIX1NELT6eMRNml64UmJl5/hDKNkG6F2HmCA/1UsdHBRSgw
         /u2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWG57k052jZlhNAUf0tNvoGCqROzt4Md3bYty4K10O9kpE8gcpO
	ySLkgoGr2cnwVPkSsZoTXXM=
X-Google-Smtp-Source: APXvYqyNPXDFtRTf6uJXldbXi6zXQUGYjjA6V5V5QYyBtE7XyXDXCsV7D4xJJzcNLM/zfiFgYDaCGQ==
X-Received: by 2002:a05:6808:255:: with SMTP id m21mr12794479oie.32.1572246111616;
        Mon, 28 Oct 2019 00:01:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:32a4:: with SMTP id u33ls203363otb.16.gmail; Mon, 28 Oct
 2019 00:01:51 -0700 (PDT)
X-Received: by 2002:a9d:73c8:: with SMTP id m8mr7444677otk.17.1572246110798;
        Mon, 28 Oct 2019 00:01:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572246110; cv=none;
        d=google.com; s=arc-20160816;
        b=gq34lL4t2oaeSRPoD+LCkXbxyjU69BrxqGWaD5PQ5p69hSlzJ4Ds+pI3Kfgs3LlUD9
         EFXp+BfgXOi8Yb7MBDZgrSh3FRChQSN30UGgkMhNxZkesiyuv7N1RryuuWl7fAzZRI7J
         Lv1+67g5Ertgqtkc22uxjuBLFCGUeAJxj9qssk2kPwzmSnHl5aOYUZuL9AyEy8dhs/Ma
         8WNy2WlYa8c9oovs2st+1jWwBo54Tcr0RCcYB2VBKBZ42aEZpJuJTmHLSD2uYXtigsHz
         G/xH5xtzxlZuozUJi6/8ZZDATmZpilaQzidJQG7xtAEgZ3GqEUM+LUgxsH+RKOIfd5Gr
         QYgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B8JVLFtcc9aWg+tsverFb6TLrQIPxF39zUE7VKNDhoI=;
        b=XpmcdUV+CAu5AXLC9b7zjtTbizpPBOlDgNsv+J/SWWbTd0wF7iJj7UVCuTu7O5rpAC
         zNBexVO3fUYf+mQuFUtcs6aY+CIL3ppEfySRF8arf0lDAYv8KrXh0slsxOe2Id36u2Fr
         Uk1mddkGU4HXwww0gda1uyGohVKyPwTSljFnXLSIae8NdYRfdBhxyArytiazIkVjhO00
         wmhbrhuevFIhCHttb2J5wWKbM6HVxImHhjlqRMSy5wvPlpu86GI1sdIN6AK6BVmB0b95
         aFuNJP/vbXXjQfuUAuNrmPkfwoWM3iv3xyD/60T3i0rjenpTU++ilqmcvvojkaESPwYl
         H8Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hx7QfTuE;
       spf=pass (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=green.hu@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id i19si511589otk.0.2019.10.28.00.01.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 00:01:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id o3so13169314qtj.8
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 00:01:50 -0700 (PDT)
X-Received: by 2002:ac8:542:: with SMTP id c2mr16290854qth.338.1572246110227;
 Mon, 28 Oct 2019 00:01:50 -0700 (PDT)
MIME-Version: 1.0
References: <20191028024101.26655-1-nickhu@andestech.com>
In-Reply-To: <20191028024101.26655-1-nickhu@andestech.com>
From: Greentime Hu <green.hu@gmail.com>
Date: Mon, 28 Oct 2019 15:01:14 +0800
Message-ID: <CAEbi=3cs1h4pOU9TcP3JCp921Jj4qYiGtqWCkJ2VKby0YFbbXg@mail.gmail.com>
Subject: Re: [PATCH v4 0/3] KASAN support for RISC-V
To: Nick Hu <nickhu@andestech.com>, Greentime Hu <greentime.hu@sifive.com>
Cc: aryabinin@virtuozzo.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, corbet@lwn.net, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@sifive.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Thomas Gleixner <tglx@linutronix.de>, gregkh@linuxfoundation.org, 
	alankao@andestech.com, Anup.Patel@wdc.com, atish.patra@wdc.com, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-riscv@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: green.hu@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=hx7QfTuE;       spf=pass
 (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=green.hu@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Nick Hu <nickhu@andestech.com> =E6=96=BC 2019=E5=B9=B410=E6=9C=8828=E6=97=
=A5 =E9=80=B1=E4=B8=80 =E4=B8=8A=E5=8D=8810:41=E5=AF=AB=E9=81=93=EF=BC=9A
>
> KASAN is an important runtime memory debugging feature in linux kernel wh=
ich can
> detect use-after-free and out-of-bounds problems.
>
> Changes in v2:
>   - Remove the porting of memmove and exclude the check instead.
>   - Fix some code noted by Christoph Hellwig
>
> Changes in v3:
>   - Update the KASAN documentation to mention that riscv is supported.
>
> Changes in v4:
>   - Correct the commit log
>   - Fix the bug reported by Greentime Hu
>
> Nick Hu (3):
>   kasan: No KASAN's memmove check if archs don't have it.
>   riscv: Add KASAN support
>   kasan: Add riscv to KASAN documentation.
>
>  Documentation/dev-tools/kasan.rst   |   4 +-
>  arch/riscv/Kconfig                  |   1 +
>  arch/riscv/include/asm/kasan.h      |  27 ++++++++
>  arch/riscv/include/asm/pgtable-64.h |   5 ++
>  arch/riscv/include/asm/string.h     |   9 +++
>  arch/riscv/kernel/head.S            |   3 +
>  arch/riscv/kernel/riscv_ksyms.c     |   2 +
>  arch/riscv/kernel/setup.c           |   5 ++
>  arch/riscv/kernel/vmlinux.lds.S     |   1 +
>  arch/riscv/lib/memcpy.S             |   5 +-
>  arch/riscv/lib/memset.S             |   5 +-
>  arch/riscv/mm/Makefile              |   6 ++
>  arch/riscv/mm/kasan_init.c          | 104 ++++++++++++++++++++++++++++
>  mm/kasan/common.c                   |   2 +
>  14 files changed, 173 insertions(+), 6 deletions(-)
>  create mode 100644 arch/riscv/include/asm/kasan.h
>  create mode 100644 arch/riscv/mm/kasan_init.c
>
Hi Nick,

I have tested KASAN feature with test_kasan.ko based on commit
cd9e72b80090a8cd7d84a47a30a06fa92ff277d1 (tag: riscv/for-v5.4-rc3) and
it passed in Qemu and Unleashed board.
Thank you for fixing the bug. :)

Tested-by: Greentime Hu <greentime.hu@sifive.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAEbi%3D3cs1h4pOU9TcP3JCp921Jj4qYiGtqWCkJ2VKby0YFbbXg%40mail.gmai=
l.com.
