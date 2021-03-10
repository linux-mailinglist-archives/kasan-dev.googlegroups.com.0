Return-Path: <kasan-dev+bncBCRKNY4WZECBBZXJUCBAMGQEMMXPKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 05EF733335B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 03:54:32 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id g11sf9418903ilc.8
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 18:54:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615344871; cv=pass;
        d=google.com; s=arc-20160816;
        b=f7ZEZu40Flt38frjKvc9Fu8vlubXr/4Mw4aJGGUIs8Evk831srUXelQpSEt+mYGzze
         I3O5fBLxZ0qtdNzJ7/Zz0XOxt8GwYJuW15ZAunNg/ZGFV+vfqXLlFNrWnRPJlVK5P+8Z
         /9heXJW6xWPGmzeetCx7b0+qjsmH0a1jnNMfHtSisH8HtaRBYLlz8JrhnZMhLM8h678N
         JXB02LEhgghxv8EsrvOagom2yf0LMLyisyC9fHT2b8fSVgSjXDq+faO9FcxJrkIf/2lc
         0C6Q9vGtEI1q1y/pxHtVX/piWmNjg280on6ZWkCNxVztAuGLP/a8Znmt46ssB5ntFNzD
         dlcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=Vw+iN1I7DZmME/5fVPNqCzon+zoIzx2uhM9dQF+2uPg=;
        b=H514aQP+ffazAY+R3/gNzDucz+WeflH5EuHxCjJMCZfDGRuJXKMyiju5EfW0vZZneH
         M25auWsbyb+rg7nPzwmxi08q8tGbSlrlaBzNn7lZVgF47H577T/ZnuTY8AwBITVDwtcE
         XWkIFQ7RBGyCIonGlRq355MGSyclykCZJE8pueErt6Y25GBZyeSxN4T2qhx6FHTOFF5D
         TufvQcVQvQilSCEtatAHz9o/Ifa00ZdUMseCQ8wSwP2hlDXaUj1nsrTsrPxBYIkL3REP
         j6JYaIkDLgQUJozfHSWSTx0ab55kNn6Sq0WN/L9rk3ClDva8Q8Ve9yj7MnbWoZLxVo+U
         bq+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=mgPjitEL;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vw+iN1I7DZmME/5fVPNqCzon+zoIzx2uhM9dQF+2uPg=;
        b=AN9gl1pfAJe80CicmzW725a9j3NzEQFsQLeOW9WyjI+ZDMfCTk2+vg7dfUT51wZ3Tw
         nconN6scfVO0xTqK5fDGRDJjteZLsFo2PNkJZpIeezpMKlqfKHp3YhMPJCjmZq2mmKr2
         HR+uni45/nmwZ+lm6enMNgoq0lGbXOBvACZUXCegHJCP6lDmZET/z3zCiyhi3YNVqKaF
         lzPYj37c1RAK35pb474h4tk5WeTGGwoarsqCgdMkdxpw/jpDQ5UL28YVHi+n4wxgP675
         btbg5eQ3PyhnLQUC6vYFgXOuxx2+zH4B4X5XWbiXv8bq/oxhA1nhyjFR3rfLvYi+E8rt
         F58w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vw+iN1I7DZmME/5fVPNqCzon+zoIzx2uhM9dQF+2uPg=;
        b=SN3E2qjd5tag/kKqBnfnDrAxeTw8qQ5ylcOSwALSCPX9ExNauhCC+FbTwYPDSJ36/F
         uwkTd8l6EG0c2XZ0/i3zykDhm7y0Ok3AErF+MQ8ny3SsWk6VFc4ZGgPog5wNKyL3xqfG
         oALGIQRqyz82m7XgpTKx9mTBAubkvdgSujGO5o/VDResUyTu1rRiVhOSX47z6ljC2xCy
         C2LVgB6uMdVwqrO7gwbzntZ9MofHNLHOL+ZkL/QuES1lA2ujrk+e9c2Tg/ORESaoQR2I
         KlF39U0HRhXw/C/9cEld8z5o60gvbv8cjVD0BmhQEk5BP8tQM83N2sagejdqdHEHLTky
         b1Cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533sgs5/Tkyo2slpkWZ0RHCOvVHASLQY3Mdsm8/mwC9x+CDiCIRv
	8KQymSyztHw6m2YVzrgiGJc=
X-Google-Smtp-Source: ABdhPJwwEH7bt7KB2cq9vdVcCbjNot/wtUiCpCoJjlFlYOTmKxc8NsgaNVJugKPs4lY5sLWX0dvhmQ==
X-Received: by 2002:a05:6638:343:: with SMTP id x3mr1244583jap.44.1615344870797;
        Tue, 09 Mar 2021 18:54:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a44:: with SMTP id u4ls209368ilv.2.gmail; Tue, 09
 Mar 2021 18:54:30 -0800 (PST)
X-Received: by 2002:a92:ce02:: with SMTP id b2mr1195382ilo.182.1615344870429;
        Tue, 09 Mar 2021 18:54:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615344870; cv=none;
        d=google.com; s=arc-20160816;
        b=Fo4xM7llV8DhzCF89MCHIsd1fUPECN98bVjeHsm8sGsbDwmzmbmug3F0NQ/kL6hmK6
         6+zKtm1bvgbxFYm4+avo2356s6tWtQdLYL7KCttWs8PWmbZVvqIyE6xLafbhIw5FR1mT
         LlIcQm2ls8sB2WwasahPTexDqNP/xUyKgvLJ0icMjffrh1R5jZh88fhtRdRJlBmMCUEa
         m38Qj7Pe/ixHDGgzlp/QFSDQz/2s0RaJlA3Slz3dcW5Zq2hTPbSUWqoqvIiB1k60CojM
         qU/2lcjk/KA6sGyE972WlmuFEGk+CK2tA9c0tMi/zg3uYMKVgTg3gOMS5Asweq0vhKvA
         W0rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=YBxARwCSnvP/MPs48fuZLZiuQ0mo/90Nc+1kxldAXvY=;
        b=Jhk19AjiCyu9yTdjbOc8JduihwhoClz9Mqy/hSHh9l90JE8s3/1spgndBX4AIbIKTa
         Wr5lulobcwk04JO4boDCuVw1d205Z4q94zKcT9xNWksKWChT6qJMkToxw3z31631f+8R
         g8Hkq4Zt/WJ4CoZQG1pip09PldCYJoGC1MBKt/sClVbke2mrplM3FKTUbA2l/3TbXKmv
         RevrWFr+NkTlBYVr4SKdZxTGGg26cL+PRevto3l2F0qbuMgVBt9Bjs58MlQPGv3XEtus
         Uk1x7buq/+2AsxZiHxtlgm1+vskua6kxX/suDH3TmQ3LeQRqeIzjbLcD0AN7pfncuClu
         92KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=mgPjitEL;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id s10si680573ild.2.2021.03.09.18.54.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 18:54:30 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id x7so7611754pfi.7
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 18:54:30 -0800 (PST)
X-Received: by 2002:a62:b410:0:b029:1a4:7868:7e4e with SMTP id h16-20020a62b4100000b02901a478687e4emr891769pfn.62.1615344869693;
        Tue, 09 Mar 2021 18:54:29 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id v1sm4250210pjt.1.2021.03.09.18.54.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Mar 2021 18:54:28 -0800 (PST)
Date: Tue, 09 Mar 2021 18:54:28 -0800 (PST)
Subject: Re: [PATCH 0/3] Move kernel mapping outside the linear mapping
In-Reply-To: <20210225080453.1314-1-alex@ghiti.fr>
CC: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
  linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org, alex@ghiti.fr
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-cf5d29ec-e941-4579-8c42-2c11799a8f2f@penguin>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=mgPjitEL;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Thu, 25 Feb 2021 00:04:50 PST (-0800), alex@ghiti.fr wrote:
> I decided to split sv48 support in small series to ease the review.
>
> This patchset pushes the kernel mapping (modules and BPF too) to the last
> 4GB of the 64bit address space, this allows to:
> - implement relocatable kernel (that will come later in another
>   patchset) that requires to move the kernel mapping out of the linear
>   mapping to avoid to copy the kernel at a different physical address.
> - have a single kernel that is not relocatable (and then that avoids the
>   performance penalty imposed by PIC kernel) for both sv39 and sv48.
>
> The first patch implements this behaviour, the second patch introduces a
> documentation that describes the virtual address space layout of the 64bit
> kernel and the last patch is taken from my sv48 series where I simply added
> the dump of the modules/kernel/BPF mapping.
>
> I removed the Reviewed-by on the first patch since it changed enough from
> last time and deserves a second look.
>
> Alexandre Ghiti (3):
>   riscv: Move kernel mapping outside of linear mapping
>   Documentation: riscv: Add documentation that describes the VM layout
>   riscv: Prepare ptdump for vm layout dynamic addresses
>
>  Documentation/riscv/index.rst       |  1 +
>  Documentation/riscv/vm-layout.rst   | 61 ++++++++++++++++++++++
>  arch/riscv/boot/loader.lds.S        |  3 +-
>  arch/riscv/include/asm/page.h       | 18 ++++++-
>  arch/riscv/include/asm/pgtable.h    | 37 +++++++++----
>  arch/riscv/include/asm/set_memory.h |  1 +
>  arch/riscv/kernel/head.S            |  3 +-
>  arch/riscv/kernel/module.c          |  6 +--
>  arch/riscv/kernel/setup.c           |  3 ++
>  arch/riscv/kernel/vmlinux.lds.S     |  3 +-
>  arch/riscv/mm/fault.c               | 13 +++++
>  arch/riscv/mm/init.c                | 81 +++++++++++++++++++++++------
>  arch/riscv/mm/kasan_init.c          |  9 ++++
>  arch/riscv/mm/physaddr.c            |  2 +-
>  arch/riscv/mm/ptdump.c              | 67 +++++++++++++++++++-----
>  15 files changed, 258 insertions(+), 50 deletions(-)
>  create mode 100644 Documentation/riscv/vm-layout.rst

This generally looks good, but I'm getting a bunch of checkpatch warnings and 
some conflicts, do you mind fixing those up (and including your other kasan 
patch, as that's likely to conflict)?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-cf5d29ec-e941-4579-8c42-2c11799a8f2f%40penguin.
