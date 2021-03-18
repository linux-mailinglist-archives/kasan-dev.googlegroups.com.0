Return-Path: <kasan-dev+bncBDW2JDUY5AORB4WHZ2BAMGQESD27TSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DB8340DBD
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 20:03:14 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id r12sf1170788ljp.22
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 12:03:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616094194; cv=pass;
        d=google.com; s=arc-20160816;
        b=XeKKwTU0ib45SSs2DsnVLPeFbf7jPeaO/3l8wkYIbfrbTtjJm7Byxh5WT8OhT0HITT
         g2Q1IGLfsCTBGIo2UaKYNU9g75xYLxEDHcfxeu5JYoEJe9FnW2YJLNTsB28ZPpRizk2+
         vjWUxRdw2U2WrbYoWzbrKVSZzAK5/UynUencjziqPomSUwzm0PpbUv4t1EaisSs4au59
         6/peSMfceXpXLdXeVRcfirTgbBITUYaWRgx8/U96Jco2DK9fRTle7E0RU09WO43zrPTd
         WIWQYQsJc9b2Izs75EpDVLZYBvchTGTcZVbl/TZn+4En0Q5sw2lsE3LAPGG/U26Cildt
         b20Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TwKaV2TDRggUbeGwj2RVMcWSCYRClpKagDBmOKj1Tkw=;
        b=P/bdLiRUEUpfj/5GiqeCPli7wvqfQ5Wh9+Er3hd0+mbgQwNqcv7DjqtmdgfmhiSWqV
         StRlHB97zunsM0p1I+Z3ex8wM1T4Q8IurWGBKXErPfgT1ZlInS9RVuvi+qXpxL90R2Z2
         WEkLpz5e71/MsDOAf4aFBbLG9ns5J09iLxwCeuvsdAsec/qEKJe7reDnbnYveghB0AXm
         PJFldGDzE3XflVcRYI9EJknYXAxknI4kjgD/OkIb2bGCil24hPuGeAi3gWjNDb36Yick
         XYh+WbP9d/h5Q8PpPO0+XZKwQtFVcr+wyv3S9Mg2Y4ORixrL+fxzY4TujqieArE3PQot
         CIRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Bh4S37Qf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TwKaV2TDRggUbeGwj2RVMcWSCYRClpKagDBmOKj1Tkw=;
        b=gS7QXPfxAsPVTuXnRCWumUUDN9tJIigROv4yPWEk1wKMJo6o+DwpUlpiZppaxjzycL
         Z0TLyOiFJVj2IN12yA7LpMQ5ZWgDLWkpGfjEktRr9MPHFLO+vYUD/Y81/hD+DIi0FlxM
         jILinQDGY7r/26Uq9z8OXU1u6N7eiqvPzR0hFCn2ag0MKAgBUJX8wzzAT2g8xHBnhL+q
         6Y1wC7M9Js5P2tZ51RigOB3v3YbSbWTciLvtI6grqbqIUU4K8mc/0CCqw2yuCJS2poEI
         KkkkpeMo/pVNrdwgnGUFohOTiTU+cXSrr2N+sGs6G0BiSfq7jEolKh+3nItOsLuq1jRv
         i1bQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TwKaV2TDRggUbeGwj2RVMcWSCYRClpKagDBmOKj1Tkw=;
        b=gB5Rf5e/Jm6D/3jA1/5mBXJMRlBrRRIt0Cr47UKKmotLCN28lrU3DLPbRQ8c1HwpU1
         24iZ+8/icLddbDGP1i4UOtfq2gmf4qsZp1gHtGLFuj1+pahgRMPOrCdZ5PWfi2Lj+AGq
         oPupKQikJ0SJA87paqfNjGHcr3o1b0wii1Ua1AdZfhKwCfb7qe4yfblY8/mOHZVsmqjJ
         1OmpANiG249HRhgogSJKJb2N3qkMcijf1EELejnZCHYCFynnh985OYerIBFV1j8BX3hj
         A7LXx6LN2QTjHc6Fk77vbCaDZxkwim5vySToBCbIm5DhiM1JiHxXXru70rT6LSH99nLi
         JQsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TwKaV2TDRggUbeGwj2RVMcWSCYRClpKagDBmOKj1Tkw=;
        b=qal39cwmTctYJyGVSDiBI8RF7mVl4EHqGeCWxkJWgyfPLpL67kPqmO5rFzYjMjVSDq
         pKgaVTcErVC9L72QvLiMkbwFh2yJZbZt0O3ms0yTFiFcqX89+NqK6Zwrya7MhizNk9i0
         W+ht0gDw0Q5oqwe2IR56J4IWe0DhVJVb73JyZqV75dnBmW7rAR3SmY9MfqFaMfct9SV4
         ls36U9A8fKt6DWdqTeYuM+DXj9RZZyrYnYqAMa3vwWo8HrhQJIfXqAuXKKsPEc0trowv
         avGJFLcgf5/npvjQmkxXtHeNbYHQv0KoktTZj6F+2SOBsiMEnT3Tb0nEhcyu67njXK8G
         80Rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EbXwCgvWdMurGunPNRBkzLoBS0ji8YaYyxKtzWDOvNayTIxDW
	p8bP3h0VjqX0hSZornDPPLU=
X-Google-Smtp-Source: ABdhPJwti9R20y0wgOvpfC8IxfqnbpyXkcQsqlcZaghM4TZ4hoEPeg0BdBNb+dTd4QmZMvXn0sWrZw==
X-Received: by 2002:a2e:900b:: with SMTP id h11mr6264696ljg.258.1616094194348;
        Thu, 18 Mar 2021 12:03:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9212:: with SMTP id k18ls694691ljg.8.gmail; Thu, 18 Mar
 2021 12:03:13 -0700 (PDT)
X-Received: by 2002:a2e:a48f:: with SMTP id h15mr6265897lji.234.1616094193331;
        Thu, 18 Mar 2021 12:03:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616094193; cv=none;
        d=google.com; s=arc-20160816;
        b=F3ecgdKrrqfcDv1vwhS8JGljmEkLrc87cN8vmspAwbSE83ZSzuhTmwzaHTuOOwHap/
         FY5cE1QB0kNj1rb1ADn0tAeJvl0XJ0G1Por5/choIAK6B+ghVVB4Z933RxIn9aIxDfyK
         eCXhfVqhvKr5tmRyiQLL5osfzagu7igfNi5MhVLUFGNQmM9VcgSHiSysoW/9gb+IBncz
         h/3LZKt3VGck/LAqYdl2UsZgMxPunLj3GhH4uwFNg5BaEKxiLdqiyiQkHJyvJSXuPq46
         77SyVjl+3o3MWHhzV5KoeWAlnN+50CUD5x9SvH2ikAK70F3HoqF9az+9Zblw0IiexL37
         Mm+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wTZLK6beX9SkhbU18uwJiCTDV/7tO8mXN2d8l/pVAAY=;
        b=vW9auwL4kYzjX2HF6sknn5/BZ2FQqH3u9eYF2AQLu50ox9RsTm13c31vIhwTaGsm/E
         kBUtN0Eq7Uwxl1E7wSB+TguDYnC5b0YxMIVLymgNTIpCScT41EPCXGTPyEqZOrR+ph7f
         xFS71YKXTzrRaZd8Q6UwHHlwTLcsn/JLn6f8PEEhkD5rPwFj0VeRk6/ISw/6zQoXP1BA
         dGUC5WHRx3n0Llt3MSxk5dkP0rMc9ORbZNy8DO/HkIKFuSvssinE+/T4BOu3zCGS6jGm
         AYnbtEcpttNC59vG9oHPW7nqCzz+EmEOCR/rtwrL6cS+rFVju/VmzHSiTr7WYaW9GSfz
         AVXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Bh4S37Qf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id o10si152287lfg.12.2021.03.18.12.03.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Mar 2021 12:03:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id y6so8036566eds.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Mar 2021 12:03:13 -0700 (PDT)
X-Received: by 2002:aa7:dbd3:: with SMTP id v19mr5437548edt.314.1616094192925;
 Thu, 18 Mar 2021 12:03:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210315132019.33202-1-vincenzo.frascino@arm.com> <20210318185607.GD10758@arm.com>
In-Reply-To: <20210318185607.GD10758@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 18 Mar 2021 20:03:02 +0100
Message-ID: <CA+fCnZc9ayxT_u3qJmB1MV0Wi93=8tNYxWFbZK52vK4S21U2qA@mail.gmail.com>
Subject: Re: [PATCH v16 0/9] arm64: ARMv8.5-A: MTE: Add async mode support
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Bh4S37Qf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::532
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Mar 18, 2021 at 7:56 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Mar 15, 2021 at 01:20:10PM +0000, Vincenzo Frascino wrote:
> > This patchset implements the asynchronous mode support for ARMv8.5-A
> > Memory Tagging Extension (MTE), which is a debugging feature that allows
> > to detect with the help of the architecture the C and C++ programmatic
> > memory errors like buffer overflow, use-after-free, use-after-return, etc.
> >
> > MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> > (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> > subset of its address space that is multiple of a 16 bytes granule. MTE
> > is based on a lock-key mechanism where the lock is the tag associated to
> > the physical memory and the key is the tag associated to the virtual
> > address.
> > When MTE is enabled and tags are set for ranges of address space of a task,
> > the PE will compare the tag related to the physical memory with the tag
> > related to the virtual address (tag check operation). Access to the memory
> > is granted only if the two tags match. In case of mismatch the PE will raise
> > an exception.
> >
> > The exception can be handled synchronously or asynchronously. When the
> > asynchronous mode is enabled:
> >   - Upon fault the PE updates the TFSR_EL1 register.
> >   - The kernel detects the change during one of the following:
> >     - Context switching
> >     - Return to user/EL0
> >     - Kernel entry from EL1
> >     - Kernel exit to EL1
> >   - If the register has been updated by the PE the kernel clears it and
> >     reports the error.
> >
> > The series is based on linux-next/akpm.
>
> Andrew, could you please pick these patches up via the mm tree? They
> depend on kasan patches already queued.
>
> Andrey, all the kasan patches have your acked-by with the google.com
> address and you've been cc'ed on that. You may want to update the
> .mailmap file in the kernel.

Good point. I was wondering if there's something like that for email
changes. Will send a patch.

Thank you, Catalin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc9ayxT_u3qJmB1MV0Wi93%3D8tNYxWFbZK52vK4S21U2qA%40mail.gmail.com.
