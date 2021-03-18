Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTWEZ2BAMGQEM6JIVYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DB2B340D94
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 19:56:15 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id 41sf5800650uag.11
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 11:56:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616093774; cv=pass;
        d=google.com; s=arc-20160816;
        b=KzqrivD024kNkKzHacyutu7czPXBR7TnDKFZdNdokUW7XN8Bx/EfsG9ca2IMBHjyeQ
         4EtDmLHA275BcHXj/4CJxlFJ2ZxRLqnJz25kJOFCDrhz7LftIEozauOTHSJ1GRT1x9Mw
         +X3yEuh0oCAZlcKNP5fjKshq9gNMJoek1xw2O+qFCc8+RzeNII9RVFKDeBBQRO7x8Ezi
         KeLFICPw3EkBU+xDiTrUBTp5ROiWzdkFB6yEJ2KeliHfYu8SjiJlrpUqXeLsEZ0+ueNe
         U5UXhis5Z44cmcvFuVGzajHX/rDYeeKY0LR1Bgh3vItpAKRohC93ngsiaN7pa+zm+fi2
         +I3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uioEBRzZdWRmT6wZ69Qa+KVT+RbrHjOcBIrkJmjp1S8=;
        b=G1x1NEpIufBuO8V9Aea5hawElcwCdupuvYAHxD0Q3Bz4QQAdIILyYSPA/nuUPwEiK3
         drGuN+zbKoy5L/8dYCmpyv9uMVVjrkNJ/o19cWvtWlSa93qTy9Dqo4T8aY5N7BnZRSrF
         +quDPDUXVGg3PqZ6SbReEwDd+rf2xccB8s02qXgfkPU0litaEnhaGWYsc7F5Qz9NTpc+
         4neggWs35zL0cFnWvVjWcYY2M2iVXZ4PANcUPJsDNf3XJUjBEfYD+ST+A3PT0JyeMl0P
         45OaJuVc7sTB0i9A0ezzVZZ7L7hcpNKfzFiASAMRpWXFjObu5+X2IYMKAkyOVikc8ifo
         2YpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uioEBRzZdWRmT6wZ69Qa+KVT+RbrHjOcBIrkJmjp1S8=;
        b=L9Fc1zgOS0s3qOw8nUT6QY9mC/oQ1iciPSu8Ibksgmx0YbHVYH1IsJ6iCchDv9h7rP
         UWLazi7ShDnFikt4Dwe23bFwRJOH34FUgCHgy5j2w167O+/kdKlv7aM6kpymncxbcGVf
         S9wBNrGUM9q9HsmTymHA/6YygxGHd9GfRCv1tuVH+Xngsc+rchIIajm7ECGgIPbxcpfc
         qsRINeQPkvwuSopUWpGUdhVAh8bqSpDigfYyRa1+S6AXj6Pogy74KwolYDYii6wCvArK
         O/P5c0n9sjCV4QwpsyOeM5EXUnd7QXxvW/WibhtnEaiU21q6yWIIwzN2yzmGtC/m9N28
         /g+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uioEBRzZdWRmT6wZ69Qa+KVT+RbrHjOcBIrkJmjp1S8=;
        b=Ly82Lzz4MDwkgnorXeRRZlMx3pKtbGwm6/JtF3LGnnE78z63nGS+ZhxAK/0GRk8Syg
         t4To24gMo7DdPh+GRZBigXY3LvdW/uYvYxjGBmrzXwFaNNnTmVekELODgXl7tXoNLl3l
         7P3INorKG1ibALCjVYycvm80QQMvGz0X/mqEGbqMS0ILQ+CK5ur+i8uPfAgx0XYA1rlX
         /0a/auFF6fls9r03tPbMB+N6hdkOv2gxzBEDG28RWFn0N7Cqyd8KDep6YFf7B0fl8VWK
         w8226QRtSei4ijUXvjeHj19305mDubIlwp+EsvRsxolHQoweir3yScy/Zmr99FF68X2F
         bq5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W2IbIIJweToT/QZWbdeACmglBoeDWEDNXC1YEfH5LuxceYTvu
	FaXjyc59fFCeUp9Ly7tbMxE=
X-Google-Smtp-Source: ABdhPJxiKyoucLI0YTy8uditMR0qwrzMKS3yuRgz3Z5BPh4dyPyNF03RTXVyIBG7sMPs+g7ENnAR9A==
X-Received: by 2002:ab0:1327:: with SMTP id g36mr3345251uae.16.1616093774191;
        Thu, 18 Mar 2021 11:56:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2e10:: with SMTP id t16ls237794uaj.5.gmail; Thu, 18 Mar
 2021 11:56:13 -0700 (PDT)
X-Received: by 2002:a9f:35a1:: with SMTP id t30mr3443145uad.106.1616093773599;
        Thu, 18 Mar 2021 11:56:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616093773; cv=none;
        d=google.com; s=arc-20160816;
        b=nzUiB0bYWIALiJchGvCSuIVk6zKDQ6Te3PPb629xSUeg5gs5hoPGkPu/NrhEuh8NX/
         4Q3J4s8U7P9OzhPMm19htAGj+Ef7mz63VljqkOGTQpQvjQolQTNOvQ4Tp0MzBvaAWpOi
         keKrYNeE2Q56qXJvG4m91aaljUg6J8/f+gTLUgnwBioinXoYV3z6/++LJND2WcpJOJSC
         2/aqv8KOG7vCm1hPj9tuOKISzRSTewB1me48iKeOkrAVVD0CFlkywrx8F8BS9G4MrAYH
         8QjPKwk07aKrtUAGtUmFaE82XodbsF8//Kz/Rb4GxZtt4UWD2LHaCPdwhK8v9NCAZDJ1
         cuTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=or4u0oaBIK7/3Vls+HaViVRYBlgFy0iiFSLmIeBLeyo=;
        b=KIPVVt9runsGflvEq44qeySjmK0ZDdb7lF17lsx/cGN7fiofzdkZMNOdbox43T6ZIb
         rUqz2b+4SWcXU2ehRy26TeQ77Jruxuam+KOZsEU5mNQc5QsNZWkzcq91SrCrGT7vZ/aa
         awY740IUny6izlTJiTgiMlJnNM0VRQ878xhLt5HN5AdB9NkzCsg5zutc5lA8C72raQCO
         NeiXztFvHYJomPrqr57/rEa93lbB+7p0eYg4Fh2U54tKRO5QrnzH/RUeAPuADeXR7GMK
         76OjEjFUGuUEgKd4ktLQbx+MGnbT8o7OWLigbLk7Ro49v71+2uwt6sOe94iFKwp/WooS
         wEHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j11si178174vsi.0.2021.03.18.11.56.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Mar 2021 11:56:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0547864E64;
	Thu, 18 Mar 2021 18:56:09 +0000 (UTC)
Date: Thu, 18 Mar 2021 18:56:07 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v16 0/9] arm64: ARMv8.5-A: MTE: Add async mode support
Message-ID: <20210318185607.GD10758@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Mar 15, 2021 at 01:20:10PM +0000, Vincenzo Frascino wrote:
> This patchset implements the asynchronous mode support for ARMv8.5-A
> Memory Tagging Extension (MTE), which is a debugging feature that allows
> to detect with the help of the architecture the C and C++ programmatic
> memory errors like buffer overflow, use-after-free, use-after-return, etc.
> 
> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> subset of its address space that is multiple of a 16 bytes granule. MTE
> is based on a lock-key mechanism where the lock is the tag associated to
> the physical memory and the key is the tag associated to the virtual
> address.
> When MTE is enabled and tags are set for ranges of address space of a task,
> the PE will compare the tag related to the physical memory with the tag
> related to the virtual address (tag check operation). Access to the memory
> is granted only if the two tags match. In case of mismatch the PE will raise
> an exception.
> 
> The exception can be handled synchronously or asynchronously. When the
> asynchronous mode is enabled:
>   - Upon fault the PE updates the TFSR_EL1 register.
>   - The kernel detects the change during one of the following:
>     - Context switching
>     - Return to user/EL0
>     - Kernel entry from EL1
>     - Kernel exit to EL1
>   - If the register has been updated by the PE the kernel clears it and
>     reports the error.
> 
> The series is based on linux-next/akpm.

Andrew, could you please pick these patches up via the mm tree? They
depend on kasan patches already queued.

Andrey, all the kasan patches have your acked-by with the google.com
address and you've been cc'ed on that. You may want to update the
.mailmap file in the kernel.

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210318185607.GD10758%40arm.com.
