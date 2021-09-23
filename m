Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB76JWKFAMGQE274WSXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 09ADE416298
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:02:08 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id i4-20020a5d5224000000b0015b14db14desf5508933wra.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:02:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632412927; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSSNuLM/iLsMBVy7jTJv/Eq3LWkYoKYq64n0ISD/JJ7jPvMGYo4elpqEqM5I5hlLFj
         AtD4fxsgQsPmao9VJRhGL/fmHTwdYhoM6I/3MTpBxhID7tbqUKqdMizE4ON2HI4WrCjw
         TQq+xYmaQKKILLD3z1rUlgr5+mcoZsht7VdwywWggE987X4pqaO1mHpvhLzsoyrapYxH
         Kfjt5K6wPKRLZJNvsXFcL0ZGCFSmgKO2Jw7oW/Ui/dvuxPOCUuhvVsD14natvZUqt5Mj
         5htM+wyLbELkZViv/ZyMdnp4VEG6BBL01+zIk9krH/DgB0o0BPfZUscx25pHLgKUENJ0
         g7mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=uziXy4Y4bX/xi+tpHiQBHaIqPixVkdkomyeOLpGU/Ng=;
        b=pNAHYXnUXrFwYereC/J+EeOPtSkacyvwnAkoeiwg7joNJhnQaL2iMFW/ElHCyXsw/e
         KZ5DGgsMlAQM52zmDS7s+cG4Aw8PJTG0ah8J5D3S/T85pwjh21JdPInLqJdm2XgjXNWW
         xV2jHtIhDE8+xqQCir/QF8rjctdRilVogxZblTzP2DXdK+oowplhCK2kJvcxnwnbqvU6
         mSnVJ49G4G8Gw2J0hbcB7FNRY7jV3WEjdImLyDT6d7z3pne0cEgiqdCFyHxmGkg7hxUr
         ZTz1BQ8ZyNKh8RRRamM+RGko2CHLzfRxd5JBPjKAelf3hU3epHCVBg42rJdbX1rmOfpy
         kZ+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=QMXOiJ6n;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uziXy4Y4bX/xi+tpHiQBHaIqPixVkdkomyeOLpGU/Ng=;
        b=ZEm1054IhwOqX8R3TSdcpiMxff0HKraZfkmDFKDiYCGUK3QI4ArCmvp/VmyITfHTCO
         3Av9R/oOcHD4cowc/x1uxIdwYV+ouefQXpVAXb25OflpgMltWulBKI26/IajhYd+MSNi
         EdfNsDXQjaPYstqC1bnjqIFtwYgFfAyW+qAWznkygPmafGw47s3pOGUHXpZ4zYcIamyK
         jSW0VpcyAXP9iFOi9YuQFcaie7b3w1qVfqM02zYRLpUYSkhOV1DdIeo7f5ZbPP07EC28
         io2TNLILSAnwfEDabWE8BYO7ybxBERSSb3J1wTAgVtyBSu18JkgRgcBm9BMEgMqYOWvm
         26qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uziXy4Y4bX/xi+tpHiQBHaIqPixVkdkomyeOLpGU/Ng=;
        b=clLnTia+CFUSY2lD9LmtmJ9jcaUpz2ox7D++Ms+1yJgSkENzTu/4EQxvG97y44VxEm
         /thvL7A+9bgJBdEG2NvLPgcubr8v9oOGjXnggF65TATz2Khq+A1QMqH8A3RiVUph4DSs
         w2fKqzD9kFXgkWU5TpsTmFWsiLgelkLE7+2H2pgqsSevXx69wz7rSm39eMvj2oBm3mCK
         TkazjkAo6KdyvIAovZk1qqcWan+JdF3820cZzIABzSCLdEFrlmOtQ7Aee6RgkHp0/cIl
         mwLf/ylklk3dv1ZPB4B2scz+zHIUY1u8ENWxREIAPjZFSO5HeCQXSERZIz1yA5KyGVun
         OCew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vh+nlc80rDLFNI12TWbYiLhlK1udWPqTbI016txXCGsm/7uPS
	+qRv2vr/MPrlMNcvYt/ktB4=
X-Google-Smtp-Source: ABdhPJyd2ZCuiLt1dgPtwdEJjEdBablpSbWfWhbecaPiRB/ljNx38YFcmRe3AKoNBcur26hLeuNkzA==
X-Received: by 2002:a05:6000:1090:: with SMTP id y16mr6087268wrw.208.1632412927803;
        Thu, 23 Sep 2021 09:02:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9bd7:: with SMTP id e23ls1188565wrc.2.gmail; Thu, 23 Sep
 2021 09:02:06 -0700 (PDT)
X-Received: by 2002:adf:f50b:: with SMTP id q11mr6189967wro.306.1632412926641;
        Thu, 23 Sep 2021 09:02:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632412926; cv=none;
        d=google.com; s=arc-20160816;
        b=CDcdokuYqzkoLnuACSOo1P+mWyAY/MksLEtwHYVI/W51YoKgNBCXCBmj5bp+GRWtBH
         YMl3SLaOOZBzK7tes75eA+M+WI1d8J6TMc1t3ewoe1C2x0ivppwBkbk5MHbea5ddBJIq
         j6NUyATgpWosUcZp39X4YW14UzX71UFxhfxKkJMSzz6S67ZkJVO7eAmzPPsLekPRgeJQ
         10vbN8vRmEyitj0Z+HoyEFo8l3qw3DYCLqaHSgU++rVj4fuYXYM0c4QtTyjVoMilehwH
         n2xPVk0gXQ4kFJ+1q2TzswfwcCqZvvNtfGLiVmJnVjFH7ZLWc+uI6lp0PLnmIJXeZabF
         BNrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DLOxhnwH/JaVIhRbDcxcZPpiYGHLJbtd0CRIGAWnOsw=;
        b=K/kuE5GKRyP3BRi3SFsLkyeYhTzxuRjT9QwALk/Uaf8GgQRlh9goq1eI8fgq4BFk29
         c2JBK4pFkqRuimZe96rE7ansMUFW8mOntkDEhd7MTzNukaHmn4LKgjL83jFA/RWXxQbZ
         ory8/vrvLwNlicpWda5JFC/G6lDQVIVfBH9xeHb1nrSMUHCVZEhcMBBDMFBIo3iYWGjG
         hJtZ86VTa+dNU6G0mzS1BQb5SW24EX6Lf9WYJoJk4g+df21XFGLhyqY564QpfXBNZa/t
         RaFV0VD7i8Ac+I4gMjH0V5AataYMyb3ul/lZDhkBe6KwbttX0XDKvIoLJ8XMINiK124l
         G43Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=QMXOiJ6n;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id g8si405289wrh.0.2021.09.23.09.02.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 09:02:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id z24so29056931lfu.13
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 09:02:06 -0700 (PDT)
X-Received: by 2002:a05:6512:2184:: with SMTP id b4mr4840341lft.288.1632412925517;
        Thu, 23 Sep 2021 09:02:05 -0700 (PDT)
Received: from mail-lj1-f169.google.com (mail-lj1-f169.google.com. [209.85.208.169])
        by smtp.gmail.com with ESMTPSA id v77sm492327lfa.93.2021.09.23.09.02.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 09:02:02 -0700 (PDT)
Received: by mail-lj1-f169.google.com with SMTP id w4so2721578ljh.13
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 09:02:02 -0700 (PDT)
X-Received: by 2002:a2e:3309:: with SMTP id d9mr5950451ljc.249.1632412922441;
 Thu, 23 Sep 2021 09:02:02 -0700 (PDT)
MIME-Version: 1.0
References: <20210923074335.12583-1-rppt@kernel.org>
In-Reply-To: <20210923074335.12583-1-rppt@kernel.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 23 Sep 2021 09:01:46 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiJB8H5pZz-AKaSJ7ViRtdxQGJT7eOByp8DJx2OwZSYwA@mail.gmail.com>
Message-ID: <CAHk-=wiJB8H5pZz-AKaSJ7ViRtdxQGJT7eOByp8DJx2OwZSYwA@mail.gmail.com>
Subject: Re: [PATCH 0/3] memblock: cleanup memblock_free interface
To: Mike Rapoport <rppt@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, devicetree <devicetree@vger.kernel.org>, 
	iommu <iommu@lists.linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KVM list <kvm@vger.kernel.org>, alpha <linux-alpha@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-efi <linux-efi@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	linux-riscv <linux-riscv@lists.infradead.org>, linux-s390 <linux-s390@vger.kernel.org>, 
	Linux-sh list <linux-sh@vger.kernel.org>, 
	"open list:SYNOPSYS ARC ARCHITECTURE" <linux-snps-arc@lists.infradead.org>, 
	linux-um <linux-um@lists.infradead.org>, linux-usb@vger.kernel.org, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, linux-sparc <sparclinux@vger.kernel.org>, 
	xen-devel@lists.xenproject.org, Mike Rapoport <rppt@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=QMXOiJ6n;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Sep 23, 2021 at 12:43 AM Mike Rapoport <rppt@kernel.org> wrote:
>
> The core change is in the third patch that makes memblock_free() a
> counterpart of memblock_alloc() and adds memblock_phys_alloc() to be a

^^^^^^^^^^^^^^^^^^^
> counterpart of memblock_phys_alloc().

That should be 'memblock_phys_free()'

HOWEVER.

The real reason I'm replying is that this patch is horribly buggy, and
will cause subtle problems that are nasty to debug.

You need to be a LOT more careful.

From a trivial check - exactly because I looked at doing it with a
script, and decided it's not so easy - I found cases like this:

-               memblock_free(__pa(paca_ptrs) + new_ptrs_size,
+               memblock_free(paca_ptrs + new_ptrs_size,

which is COMPLETELY wrong.

Why? Because now that addition is done as _pointer_ addition, not as
an integer addition, and the end result is something completely
different.

pcac_ptrs is of type 'struct paca_struct **', so when you add
new_ptrs_size to it, it will add it in terms of that many pointers,
not that many bytes.

You need to use some smarter scripting, or some way to validate it.

And no, making the scripting just replace '__pa(x)' with '(void *)(x)'
- which _would_ be mindless and get the same result - is not
acceptable either, because it avoids one of the big improvements from
using the right interface, namely having compiler type checking (and
saner code that people understand).

So NAK. No broken automated scripting patches.

               Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiJB8H5pZz-AKaSJ7ViRtdxQGJT7eOByp8DJx2OwZSYwA%40mail.gmail.com.
