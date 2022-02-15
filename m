Return-Path: <kasan-dev+bncBAABBAUUV6IAMGQE4MDCOFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 43FD84B6FE9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 16:43:00 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id bf12-20020a056808190c00b002cf68d61ccfsf4830169oib.8
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 07:43:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644939779; cv=pass;
        d=google.com; s=arc-20160816;
        b=rlAsCQmnAIEqJESbeYtcKnIGgytj5t9f5iRoUxhh9gJYLhquLm79tVAFADUkAnt3Sz
         hMEcyrStwZGeOKnfq2CmkgT7zQ6OO8QDjqAG/tacAlVM+8laBYPzwfVv6F5RsJ+MW/qw
         20sZj5rgTzU6SH3AjgjNWkctZrBqMZB9lHf7Dg0aXEFat71jDo/WXxHsjRCPNKk5xKnv
         L94RoNuo4v9cW8eBAQRkINeL4CRppZjetuAeq3tpXbEBbCnaJ72gopBjSv4V27DV9EjG
         qNqV96mT2FNOugJrrKOeHXoxQTe6wugc9yptbY7VSLwWhHDrJpJIj3ihLkiuGK9PVr3J
         fKSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dNH/jO0CPQrAJR9Z2NjIZCazyAI2+SVzIfeGFdAgz2g=;
        b=poCrlJK1ZaH+f9jalqQdepqOIjJ1AnsWTM5kgELt5z7DCFNOJLhFJuUHocv9VWCe3O
         n+n73vJBkSzmHRgHau3UWZGB/nySv13s9uv+QdgGtAYdnet7QZgwAB7NBXQ63Nj/Fiu3
         RgvNEkbS+zKNfqivccLslyrvXPEKqnXP0rqoPxIOr1gC7mGkl2fMV7j/tpFCMwT50B1s
         CJi6JLAkc+mp/NIvtxQCNBIaJoisWWIiFzRfwKM0ONybOUVXP33B6sax7RojLU8dj6o7
         FB/kS52FyxR6rVSdLrYcilU3Kzaea/zPQTHAj/UQP6Q3Hv9JR8Tr4m1pAw+A409uC3ht
         gwpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cNI7u7wC;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dNH/jO0CPQrAJR9Z2NjIZCazyAI2+SVzIfeGFdAgz2g=;
        b=qnMhFl0JB/CQFfdiI2zA1F0SZ3yZoSzeGGT7ug/knWM/7TOxRW8gKKOf82jj1CC4qq
         hNWlZlvOhm3BXFeoPrWfKn8o5UGWuStbV754DUG1s+HLh+/PnFatkI9IJjLgfareOEj8
         lvscrAkYZ6brED1w2IaMNwo3xYZZOtcZKGoSj/2jbxtmj7Wy4nClVTAUE+3iG6dFquva
         /M93dHJcBTJWDjttWQ3nUOCiHZJvUQr6Z3QkAFDuhfPLH3rerdOG7N8YCVXRmXuhXMwV
         CPUBBzmHNRAtRYRZJ8LC7tJzPQ3+jNwblAnYYYWogyr+2mn8vofg5s0sM/vqp0aTjd49
         OKkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dNH/jO0CPQrAJR9Z2NjIZCazyAI2+SVzIfeGFdAgz2g=;
        b=DiF6rYUXJlp72anVf7Nexuk2xBSLQpRTC1vN0bY9l/q19kL7GXvkIAvlPhk+g7HiMY
         cSXYjEoe1Oiku1TQ6XNB2ZsD3Mp3wjCKk6mS68Yoc6sf2ypn+p7cH8jBJqRNqKYdQeS/
         3QBTE97HLv+VMIwGmUgWSi7PsLPpeA/4NP4gW69ZWrwflAMtb1XtFAoZ9xj7X6ICzhFX
         oxqJT5Mn1DLclm5k6I0icFsv/zRcW2fHgxJnrpAFftrnOedDu5SF8ou6VEe3TZAwVEbd
         Eh92dkJBVdu0Ami5T5G/rI/2z92PegPTTBcSuObdfsvavxSXXu8U4geBzKL2xzoP/M2S
         BZGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MLKft4skANLfwWcNRXdj9vM/29bJ3D666vyhjj7AzgEXFEHJb
	s3PNdX/qNWteO8yf3LBOHIk=
X-Google-Smtp-Source: ABdhPJwhoohrQiqqyicrCe4JAlaEAMuCZw37RWvW2k1IZ3/dnuSBcJ771+TRkVNqjCqorgM8vOqukA==
X-Received: by 2002:a05:6871:692:: with SMTP id l18mr1609546oao.61.1644939778830;
        Tue, 15 Feb 2022 07:42:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1507:: with SMTP id u7ls913981oiw.5.gmail; Tue, 15
 Feb 2022 07:42:58 -0800 (PST)
X-Received: by 2002:a05:6808:1912:: with SMTP id bf18mr1835778oib.199.1644939778541;
        Tue, 15 Feb 2022 07:42:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644939778; cv=none;
        d=google.com; s=arc-20160816;
        b=rGmjkKDrmEzqi1+zVnaf1AWSmzYwdMIvSgXaCmTt7unJV46814SLpxh8MKmB3YQtDc
         bTrbINrPfIGcBjmfwpploU4viB8nDMEfAnjgsVUH222wX3VCshZlsGTQrzbafFsFiBQv
         +BzYy1auiMwBL30ULfPThYjIr7cf3vi7Y5yKSC04WOBoqCGF0ZN15tsLwsr5WbZxaEJq
         oPafdbtKTZ/ZuNb7HMJEQkSk5CsQ+5i7s/2nL3zYl4ZeTF7ePBneJLjdw80JIFBH2BkH
         UPY2UP3rpZthiHcYhJERDjgbSktfMt/nz4ySWvv3IEKEXbVBQdNhmxkVAkbxq4uPCk5P
         pFrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JqxJCeFtX/Dd+E9JErS8oTLL0+ISFiM795Cz6beZ72c=;
        b=qz9kGuU09t+DlwlEAoD3j5/P5Lo52fuzx01Ik8CecnJEXGrM4ZVWdAWtEIPWgCbX2N
         8qh7XlF9ldYQBP7oepsQei5AahaaSURXHi0Q8v5qdPSHWBd4H5TonHWW4f1z5dgH+DeE
         yYCVhLkLJ28fD3lqjeS8V+2gUQGXalI0qdjQ3fd1/3rUxb/MuAqBzkWZMNov9rCQRFDS
         uGfoFgvq8ZQ3Z/yLytslfXThymCU0gKyN18ygV/y6xac/zLkw08uuXLDL20HleAunOWU
         MIlpRS+eUJk4t7SBQhMsR35lwyXubPQ1P1RRsPGnt9d2JAGK9ruP25vsNJncUK3wxVCc
         R9hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cNI7u7wC;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id x31si1920967otr.0.2022.02.15.07.42.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Feb 2022 07:42:58 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 43C2B61738;
	Tue, 15 Feb 2022 15:42:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DF950C340EB;
	Tue, 15 Feb 2022 15:42:51 +0000 (UTC)
Date: Tue, 15 Feb 2022 23:34:59 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>, Atish Patra <atishp@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, alexandre.ghiti@canonical.com,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/3] unified way to use static key and optimize
 pgtable_l4_enabled
Message-ID: <YgvIIw1CV4gxn2lS@xhacker>
References: <20220125165036.987-1-jszhang@kernel.org>
 <mhng-41f2520d-7583-41b3-ae7a-95e74117676a@palmer-ri-x1c9>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <mhng-41f2520d-7583-41b3-ae7a-95e74117676a@palmer-ri-x1c9>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cNI7u7wC;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
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

On Mon, Feb 14, 2022 at 03:52:44PM -0800, Palmer Dabbelt wrote:
> On Tue, 25 Jan 2022 08:50:33 PST (-0800), jszhang@kernel.org wrote:
> > Currently, riscv has several features why may not be supported on all
> > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > kernel Image style, we need to check whether the feature is suportted
> > or not. If the check sits at hot code path, then performance will be
> > impacted a lot. static key can be used to solve the issue. In the
> > past FPU support has been converted to use static key mechanism. I
> > believe we will have similar cases in the future. For example, the
> > SV48 support can take advantage of static key[1].
> > 
> > patch1 introduces an unified mechanism to use static key for riscv cpu
> > features.
> > patch2 converts has_cpu() to use the mechanism.
> > patch3 uses the mechanism to optimize pgtable_l4_enabled.
> > 
> > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> > 
> > Jisheng Zhang (3):
> >   riscv: introduce unified static key mechanism for CPU features
> >   riscv: replace has_fpu() with system_supports_fpu()
> >   riscv: convert pgtable_l4_enabled to static key
> 
> I see some build failures from LKP, but I don't see a v2.  LMK if I missed
> it.

Hi Palmer,

I also saw the build failure due to RV32, fixing it is easy but I have
some thoughts/questions here after reading Atish's "fraemework for RISC-V
ISA extensions" series. 

Hi All,

I'm considering how to support cpu features or new ISA extensions.
IMHO, we will need some static keys for ISA extenstions as well as
the cpu features. for example:

if (static_branch_likely(&has_isa_ext_foo))
	do_something;

So I have a big question here about CPU features VS. ISA extensions:

1. Is CPU feature == ISA extension?
If yes, then it seems we'd better rebase this series on the ISA
extension series. If no, which is the super set? If CPU feature
is the super set, then if one kind of future cpu feature is implemented
via. the ISA extension, do we need to combine the cpu feature bitmap
with the ISA extension bitmap? how?

2. Is SV48 considered as riscv ISA extension?

I will also comment in Atish's series.

Thanks

> 
> > 
> >  arch/riscv/Makefile                 |   3 +
> >  arch/riscv/include/asm/cpufeature.h | 105 ++++++++++++++++++++++++++++
> >  arch/riscv/include/asm/pgalloc.h    |   8 +--
> >  arch/riscv/include/asm/pgtable-64.h |  21 +++---
> >  arch/riscv/include/asm/pgtable.h    |   3 +-
> >  arch/riscv/include/asm/switch_to.h  |   9 +--
> >  arch/riscv/kernel/cpu.c             |   2 +-
> >  arch/riscv/kernel/cpufeature.c      |  29 ++++++--
> >  arch/riscv/kernel/process.c         |   2 +-
> >  arch/riscv/kernel/signal.c          |   4 +-
> >  arch/riscv/mm/init.c                |  23 +++---
> >  arch/riscv/mm/kasan_init.c          |   6 +-
> >  arch/riscv/tools/Makefile           |  22 ++++++
> >  arch/riscv/tools/cpucaps            |   6 ++
> >  arch/riscv/tools/gen-cpucaps.awk    |  40 +++++++++++
> >  15 files changed, 234 insertions(+), 49 deletions(-)
> >  create mode 100644 arch/riscv/include/asm/cpufeature.h
> >  create mode 100644 arch/riscv/tools/Makefile
> >  create mode 100644 arch/riscv/tools/cpucaps
> >  create mode 100755 arch/riscv/tools/gen-cpucaps.awk

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YgvIIw1CV4gxn2lS%40xhacker.
