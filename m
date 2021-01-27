Return-Path: <kasan-dev+bncBDAZZCVNSYPBBA6OY6AAMGQE3YD2FTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AFA4306724
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 23:19:48 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id u7sf1928095plg.21
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 14:19:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611785987; cv=pass;
        d=google.com; s=arc-20160816;
        b=XneznwbBBTsKauBMZVyDpxqW3YV6o88UpJcGr2fq23CLWudaY5oxyEoWSi+ZMRnxgR
         Ni2nkavwRpvS1ehZ20+d1O9F/7UL1ACtof8NywpUNZ27P7llie8F5MQ5B7UBG4DYXb+z
         O/netNsuRhD9QQ1Jplb0840tZ7e01nu1vVJNjrWG1mwqn6EIHK3r210lU8FiHUZTAO9b
         RiT+9RGY8FvatUlCFjLMKujDjnf0jKXtKame9ZRw7FoigGy8cUDPrmRl6LcG5QwdwQM5
         acVKpLFF237x8hU0LrcNrYQCCW406VcNHKyHH0wkER4rhaFzEooP7VRksWZWEJhUE+9r
         +VYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=BTUHcl4seS5W9JAl+l/vtayBALgo1LmVBDUiueDsYDw=;
        b=CkEaaevO6vLn9X5y7JpFYaOOTLxE8N1AP/QIVPSgE5UnGYQlJyd6mON6uj2EOLmu4t
         jF1lBEUX6yxdsBUDjNz9sFoxNywEA0qvj5lVouQ5as665aUUiSk+hE/WRK5mBu1DNK86
         lQobc3MhoLRzRBUv4WoEZ5mpwNEy6+3PCbz3RoYh5YrR5BF7Xkab/XA+HVjZf+N6Dvj3
         ytAhzlSuvI4YVHA1etUreSzBcEQ17O8xNdhNFNmJDxroBkTtucjCbyWf2FjpwCTe8939
         dvg90uTQesPr+ksa3BmnMK78ipbhDI0InbZbRrablOmHkrtzrJdIy0HElOh5p7ZVYoU1
         3y1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u+exvneJ;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BTUHcl4seS5W9JAl+l/vtayBALgo1LmVBDUiueDsYDw=;
        b=EWlnTodH5mxrbpWMUzLgv8Q/1FxEWt+FNEe8z1oas0VOc6oA7cK5BmAnf586Da4vNX
         lLHdL+dtLkI4PCt97htTkB24PUbTpuu0sK6usB9fzGeLqNdtDOOf6iDMa2vxRMHBFVc3
         e1dYOXYY+vC4OCKqvmJXwgSDU6XaHzMMVAEVKP7PYxWTKJ69ufxh05VFb7tEeeEQIlKB
         xsW18hbas2WsUjE3/FnsybpkwKDasyAPaYsgHAbm0XAfW8Co5rGD15bUwZvA9sOKrLnN
         4u/aCptBF4NPRAyiJqrJ6GNfoJ9YZMtNSFc8HRiOHep7eJ9H1iCvwBqP3s/137wcPhdM
         zicA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BTUHcl4seS5W9JAl+l/vtayBALgo1LmVBDUiueDsYDw=;
        b=PyNyIMMQcdY+uGypCZ0DfzP+QJMu9TEkUEmqWvSonLIrztedvUvkAU6TNP22kbMU2+
         DWkgFpdG/uhY6g9erx39frg17sTQJV6YdrGDuH5DgYDdMJLCj7eohDBstomifguo/zpj
         xziu77GTo4DAuqGHYLlAPuJBQKTdXo9aD11S9Tw6yLwnEUDdmefOdFeS5Avku7xY1mUe
         Q7MfsXilwyiC3qrERJpkFidpHJqYv77y45bLXvhxfdL3kOmQxfdLtSTS9iZ7M18ixHJP
         hG54zUi7Zf0kq96vgq0fJlAs9eMN3zUZqyy96uoD3DlXiHgjctq5oM9SY1UjjFyyNUbY
         SFxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VqrLBbGfsBqB8xlL9ZwntOp87IWjNlcCV9ZIRB/Y4KkuiIgxH
	FeoqmD8EUkm7ple9g7dwsC4=
X-Google-Smtp-Source: ABdhPJxK00insvcjcX6QZwjj/SQqVkuMYONwEmBxrPgx++cMJY+n3F0C99VLmQo1E76dY7RQ5GhicQ==
X-Received: by 2002:a17:90a:ae12:: with SMTP id t18mr8135931pjq.92.1611785987375;
        Wed, 27 Jan 2021 14:19:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9155:: with SMTP id 21ls1362393pfi.3.gmail; Wed, 27 Jan
 2021 14:19:46 -0800 (PST)
X-Received: by 2002:a63:1519:: with SMTP id v25mr13338436pgl.217.1611785986571;
        Wed, 27 Jan 2021 14:19:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611785986; cv=none;
        d=google.com; s=arc-20160816;
        b=S5DmWJN859Uw5RCw/LQ/rSNcoNCGLL7aW6ZroGLSRpHHpYDifCuRwl+yxINZf+6QQv
         HCS5bsI9eIYtOvEUsocS5akuyKU8cWD3HvsuqMXflpDMV+PrJo3udmkHsb54bFb5Q6a4
         CehiBscFcvXXNl/rmZgPbecd4nYGOEXycKcuw/faKfXshF91Fu/gyirJ3prFMsx5mvu8
         Jiqt0fvsEB1PGfIW+kIMA1ALQNn4zEZjh/wArCKeXOnyPzuwsP4VAN4JNwDvMBhfNv9w
         4AlKOF1fYj65ss4JpjENYgtrQDn5tsqO/NFgx2xSfsrtG1MoQqYpWrsTv+2K+Zl7sFT6
         rPDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4M400GxWqEM/oC6PMOKM+ztcI/P1WmaaOFCpJlHbpFg=;
        b=Ls/m+uFrbnxzkW8bIc/ZKqthKjJE8D3KruvDVkvgdjQ1uDVVWhiJwKHjVsO4zYOsSW
         7QlG35UAX9NIXlpz3DIuij31Y8UVexZb/1bJXZXEwIESWPSe6wYXRQOIy2/OlS42NaXY
         mRgpFqrphYFcAU9N96nvu2/T+OA+6t6mmw2TnkSrc7oCDcbbhd1TIaef8N2oDojUxADs
         V7atm0FMXWhK2+Z1ErsPXqmYcjMP4/LMtRRzVY0I1U2nH4G4gNefGWiNHmvw3kDa1r39
         ylXLmgKLeyKg+ntdOA44vi5V96vnQZTlJeTYnxOLMJOajQEqheyKIm++gupzTD93ya4C
         dByA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u+exvneJ;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ie13si146558pjb.2.2021.01.27.14.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jan 2021 14:19:46 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CCB5D64D9F;
	Wed, 27 Jan 2021 22:19:42 +0000 (UTC)
Date: Wed, 27 Jan 2021 22:19:39 +0000
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>
Subject: Re: [PATCH v9 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Message-ID: <20210127221939.GA848@willie-the-truck>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <CAAeHK+xTWrdJ2as6kBLX+z64iu3e6JEGppOkN-i_jsH74c6xoA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+xTWrdJ2as6kBLX+z64iu3e6JEGppOkN-i_jsH74c6xoA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u+exvneJ;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Jan 27, 2021 at 09:00:17PM +0100, Andrey Konovalov wrote:
> On Tue, Jan 26, 2021 at 2:46 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
> >
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
> >
> > To simplify the testing a tree with the new patches on top has been made
> > available at [1].
> >
> > [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm
> >
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Catalin Marinas <catalin.marinas@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Evgenii Stepanov <eugenis@google.com>
> > Cc: Branislav Rankov <Branislav.Rankov@arm.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
> 
> > Vincenzo Frascino (4):
> >   arm64: mte: Add asynchronous mode support
> >   kasan: Add KASAN mode kernel parameter
> >   kasan: Add report for async mode
> >   arm64: mte: Enable async tag check fault
> 
> Andrew, could you pick this up into mm? The whole series will need to
> go through mm due to dependencies on the patches that are already
> there.

Please can you check that it doesn't conflict with the arm64 for-next/core
branch first?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210127221939.GA848%40willie-the-truck.
