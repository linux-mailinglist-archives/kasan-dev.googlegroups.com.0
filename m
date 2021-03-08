Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3NBTKBAMGQEZ4624OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 821D23318F4
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 22:02:39 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id q36sf2141799pgb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 13:02:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615237358; cv=pass;
        d=google.com; s=arc-20160816;
        b=sLlR/yzfl+cjOTIFh/KFv53yHEE0D4R+9SLkfuOjHOYkOmDMBEdxLzPN6P942ao4iu
         y6DwmW7pruAZ9C+ZG+Le+JI/bXvX9KPC3ApPsAVAmGQRweAUakdeshB5+KzdYD33bTKh
         OE+zvhQYuhETPFOECThNeUlBSY44VU/JI88o0WKW0OFNjMSh0Bx1k16S35sbwA3855Tn
         YEBzAWzNYFKKTYTXaEH2f0gHcvWTPi1VCvHEyHIV0MPQjTGppMLcO7oM6NsR66elisif
         vElienM6RSWztYoGPwxlThXgouxgcw/L6SmFSgzBvm7GOOJwaG54z/6rLBPP/u+1BUv7
         JPdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UFVSmbNr7O7606YvHLXCnwQdrnlrH/vtnC6RRhLcinY=;
        b=J5HphaTIHKgo3RKpCDSQGAsQ8xBNvcWStmTvvQ6lgIRUZWwkt1XDq80IVQ724Xj6jo
         9jt6k3K4suQKdpgsA0m5KLfXjNdyxRVGGYDKSHpA19R635Fg7vvuUw6joJlGK7N+tciI
         hTVlcRUaAywvxslenCqO3oa2cfbii3l0fNmieJ71i6J289SKKBfFL9J9BCRy2mLRX4YL
         sg66MjHqbsdfNAehWc0c+kAPEk+6ZARSmYad7x9adqlk2HaIpOlVKzGoXip2e9KzrjIb
         xyYhmJNR0Iy2bP3gY/wsBHpQaQ0QVwrrtHA3tmng9XLWaf0T0KmvmfU9mK105IluOWcu
         U+hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RlT5RTEl;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UFVSmbNr7O7606YvHLXCnwQdrnlrH/vtnC6RRhLcinY=;
        b=Ys4EzbAPfRymhtOUa61sURaEZKIP8aiZeowj4doxVoEXJzDxTY4QTl0SEtfc84LVon
         ONM5jB74LJIjrorze0uFD7nTSOFx8Ng8LB3h42ADAzsI9OsMVQT/rIwrmwqkoog3AAzz
         3pMRpxq76mwH2QWZBPh+bf3xjOt+m2gJKXYO2Ok4nyVrSPjRqjkegwHZgKFn1FBGV7oP
         fkXtmPpFr2vuTaCFX+1bz85pz3lmlIyW2rG2Y+77d7mkX6O8LYWGexQEgF4b/QAnRnk5
         bBse6JUcz6dPllzLInwOGPc09WwyXeAl0xcZcQxe75MZ7o1gqSt8JiZNSobnca05GAjq
         lxbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UFVSmbNr7O7606YvHLXCnwQdrnlrH/vtnC6RRhLcinY=;
        b=hcYEEqovwtNa8gXp1jmSuBGtYMkRWMwYjllix1iMGsCAqyW1/h5PDR9Nwun4lXdeD/
         h6g7QbCPxLxRJo2ZNFF1EusqLcWC+sCkjzJnq5UMh94sHcCFcw7Esuzi5Nyhq5C+AMto
         owbh+3CCcTdFmMPo3sbnPF2umOZ30V5ZjNy+sjERZg9AC9AWZLcrGcM/pifv9ZDtapFs
         mq4mmDrBhGQXA7bDfz9SZOF5V7gIverfnkjnUfMYzIjOSjc9i4Z6qV0ksLP/N3j5zYpy
         ytmCjtWBITixTxr24x1NR4klcya904v5+U5ynQXT0AK+yQB/1aP+D3NvIZtk1KpHWjr7
         rDEQ==
X-Gm-Message-State: AOAM533D7FUSywuBbrjOxvj1nlgsMy0xMROojzk7rjPFIRz8oTICZ3F5
	/pce8tcjzV13VgJnqOuSbrs=
X-Google-Smtp-Source: ABdhPJyyycdQI51NnkWLETJdMP9xBSFJh7KtoHYWUjOO+O+pTKKym1s+IOC4SuRZ0s48g3O3eZhxhA==
X-Received: by 2002:a62:ed10:0:b029:1e6:2447:f8ba with SMTP id u16-20020a62ed100000b02901e62447f8bamr22433155pfh.61.1615237357971;
        Mon, 08 Mar 2021 13:02:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5302:: with SMTP id m2ls5521963pgq.5.gmail; Mon, 08 Mar
 2021 13:02:37 -0800 (PST)
X-Received: by 2002:a63:1946:: with SMTP id 6mr11322525pgz.359.1615237357469;
        Mon, 08 Mar 2021 13:02:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615237357; cv=none;
        d=google.com; s=arc-20160816;
        b=u8bEG6gifHX3RkePacMtm3QbL0a1no79Fe8dy/p9Q6w4NYR3QEBC7/6ppZMx8a7zpM
         Cc+21FFs94cWqoBE/+P5s5ex3OT0GlB3YCRja8jE8VNkc5hS+0P6lWyYQEAEX+Y4Xt91
         Br6WMznyH9Bm2P/nHreMhY4o6NvaomVBn/kxRdynuHqJsGVT8Ch7+C/IxQIcUHnFggM7
         ydYFx/sLXa+ETiFu3yIH+Z6782S5ZZjH/5dI1Ypj+Xb6JJqm4H/gifKXyTYFBwXi8tcA
         wnd8Bf/bHtUeERoZD3YXJVi/o1GxJQaB7BU3vc6sqeRBJJ1p3n2ctUAbb9rmQ0ZO4IAT
         0MnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qVM6aF4+Z0E3PMKrGgvJCjoVZqdQ6xy0HWF9QbJkCLk=;
        b=ZyTOMuUEMl+kDXsUEafNVSYOdNMuoFWgG79unIiriOllW5kyDYGy7SLqf7eJr+1uLD
         oxgD+3RYKJmdb6amx45yRK4VJwCJYdsuROO51o7vaQxY+2q8f17P1S47cYRIimANgUsu
         FRRav2KGEs2tTtK+rJQGkVzUymG744iQaoZ8xZCDbLdEdTXSH4kaumgUj+0Y4IAK48yq
         Xo6NfoTR9yCJH/814cCFZNOsLWhTFNgpCz3wNxjkQEdVS8stzpqwXxIXAyPWsB9xAaBX
         YMQbAhRq+ueZ+qvXUeKJdoGQDh++ORC6PDBaZ7ejqipx8Dt/b8IjnUqTBZOVoAST4UYe
         yneA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RlT5RTEl;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id f7si45537pjs.1.2021.03.08.13.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 13:02:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id x7-20020a17090a2b07b02900c0ea793940so3726535pjc.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 13:02:37 -0800 (PST)
X-Received: by 2002:a17:902:8641:b029:e4:7e05:c916 with SMTP id
 y1-20020a1709028641b02900e47e05c916mr21769229plt.57.1615237356824; Mon, 08
 Mar 2021 13:02:36 -0800 (PST)
MIME-Version: 1.0
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Mar 2021 22:02:25 +0100
Message-ID: <CAAeHK+xEc8spQWh9Mz7z-mVQRavD2y84ufnGx6cm-gK3AkJfAw@mail.gmail.com>
Subject: Re: [PATCH v14 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RlT5RTEl;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Mar 8, 2021 at 5:14 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
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
>
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
>
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v12.async.akpm

Hi Vincenzo,

As previously discussed, here's the tree with tests support added to
this series:

https://github.com/xairy/linux/tree/vf-v12.async.akpm-tests

Please take a look at the last two patches. Feel free to include them
into v15 if they look good.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxEc8spQWh9Mz7z-mVQRavD2y84ufnGx6cm-gK3AkJfAw%40mail.gmail.com.
