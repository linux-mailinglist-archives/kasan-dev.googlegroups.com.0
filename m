Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAWBTSAAMGQE5Y2UYAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 24FE72FBE97
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:10:12 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id b3sf24463538yba.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:10:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611079811; cv=pass;
        d=google.com; s=arc-20160816;
        b=021J+LfC9cHYKKm0z7RZzgX7IZyH+jsNLBmvNJzfeVENALaOOLzA2gdpdIJoL0WVQa
         TpO+tX8es+rxRC2Yt0FcMEAgmECgHsFQroC1BSllCrS+Ek9DcX2hgFxIXIpufcbbcVZ9
         LMlFglSajnTZZso96Zd4sLvCcvr7oFB55YZ31/r1DsvAYHsIblWTgZgfjezV8infJmE0
         5s0a99CTZkuPHczn4k9EpRmih0nQbiw7jWTaaR47h/gQbkdEKr5oOyUwabfgsc7kFpVZ
         f03N5RcIu7/yiJ4hslUUn53o30DSOq2Brzi+mz+h2MOFAeJM1Ipm+VoiDNhKcFTWjlIz
         VNMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7LY4NxkPy9kvbGAF1UHOFsNjJwPFezAeQfvvaO3tKqw=;
        b=YPNmikQeYrnZj4ZCF96Xm0H38NvdWad4LKUR9V8Kcdi+wtghXGw29dGReRT55FqbsY
         usixJl9jB6OyF5cVKeYcoSz5mhOEIKIQlicXg1GlO/cGVIfOMVopjDnrmzVThSrJeesp
         ceQ69OJFN4HU2g3UaX9haBgi+Q+8E15WvZU88JpxV1jFUtk3eqJqZXUAbgvvJngRwQev
         OYfnCDczcytURSNLHzy0m2ZwnMb6M2jy+8SLp2auWh3TOBEkyZ2NWfKkFyq30Rg3LwZ7
         qpO6MWT+IYyQCI0orbohfKXQCMl+SLp5fvylWe4Jr6DH72xNbxHBFBEQ2m3EAJ8cSsvj
         0nJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iTVqpmbo;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7LY4NxkPy9kvbGAF1UHOFsNjJwPFezAeQfvvaO3tKqw=;
        b=IfYMNh1NrOyFJ5mFNVgjcyc1L9fv/a0sl4fYG3RugRyWiZsFRWf+XqlhWhr3HCwNYt
         pyMzeM5FbIFwygQ8VzSjpPC/hhhBWCcAkjOA2Lwb7vjvGrle+/agd0YTxTscwidazzJ1
         XpzRdGbBdWtCipaxk9etNVSW+tLfW5Py4CvkwBJHjmYarkbGXuhlUKY5sKOUhxVFEL/i
         3M6Le0oMsQT6dYOvhW+xZWAEzXzKgcPwhDgNxXKWEg+RW4QaAVP0eKYBGA8iklJC5h8t
         NeIkTQysxXTcCqDD6XrchyFrRUgypzzA9U07okBzGZsXT7evBB0P86P/hMH+MaKY6JSh
         wVsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7LY4NxkPy9kvbGAF1UHOFsNjJwPFezAeQfvvaO3tKqw=;
        b=qCeVZ/XDc0z5rClVe1vNeMdnVCrLfOtGL7nNTqAUdOd1k5URtufvSpfpeCEGt8HMTy
         0OwB9GORLUc4sTTVV+9YlFT/NaEtp0OAJenDnWHm/y358pnYbFHTxra5EsLpbxFbIRd1
         RSSues+9F21s11hO0gWJIUQEDP6yIykjk9YBtY60yIigMxm9TP1nP4KwqGKdR64HG6tJ
         Xi2Ud8jWb/Q5oeLlNNvOsombgyAq757DmoHyQKNztgByIJ9xxN/6M2cIg9LdsUNq5riy
         BtOjaGLU05NQo83f9em3u/cHtY03pEZ6aRomUP/SfTLWPj6Jqog4ds0cNbe5wEx/Zk9U
         scxg==
X-Gm-Message-State: AOAM530hOOaBPsFmZH9MkhDR116PAVvKXpHAEZ8c6ujbS05yt5dQOXGl
	xiZteaohqTAonvCS4vKleM8=
X-Google-Smtp-Source: ABdhPJyoqjg9Ulo95bnzhYd8dSCv4YqELVMFJaxWO2Ce6cy+SNvsYsLRqcSv75xhRWZhGRJQDQnHTg==
X-Received: by 2002:a25:9387:: with SMTP id a7mr7645937ybm.73.1611079810978;
        Tue, 19 Jan 2021 10:10:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2f84:: with SMTP id v126ls7174396ybv.11.gmail; Tue, 19
 Jan 2021 10:10:10 -0800 (PST)
X-Received: by 2002:a25:73c7:: with SMTP id o190mr7521628ybc.482.1611079810547;
        Tue, 19 Jan 2021 10:10:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611079810; cv=none;
        d=google.com; s=arc-20160816;
        b=YJrQ/ZuykW9yEOwpQtTml4CrPgox5mOAEoJYqFRCDAOqQC0Pe5CQrxlUPjgg6qfRI/
         Kp2Gz6tvJj/pBLlUlfzZdqRFo8AFRHcxv4YIhrrWmAmg4C6RSr8MUOycLe8GTb5fFr36
         m1Gp6aAUXu4FwE2noAJat0Fmp858Nx8ETwDPIdSx7XN4JkGWhT6p2Hf/6BF0r7ssSGny
         bI2ipGdHn7NIAH417rMNpn/cmheLzKvNL9yOwCOu/mc4bpniXi8qwBgn0dBwj3Ti4I+H
         /kbKGxkj3IGhwApL3LNUO1qkNpotvWMdjKYnBVJmV/v18c6X3R/JaXL3snBfuk95IPDz
         B8pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vFtaJ8H/Mdt6Sr1dyWjnP3+YFNQP6voHmOJMCqsGuZc=;
        b=X+PNI0OPFXKgefZyurkjIHt3xxY+Vz8n4eKL0Lezi1o6S7zK6LsLSV688Wx4vlKoPk
         yEAaz16p7PQlXnutiP6EMUJ1hFMHEslc4DDnbW21F9oq+Qq+JKL9yJJc0+rJ7BHJAvS+
         dws8Y2xiBPAn88bbWf6VrUf4FLEwvJ3E8FQentWCaGVDbY+OjEPTecx81nTaLs5OnJRW
         DmxRL0GaBEHJxjI2sXNGGvV2Ad2ewX6B2C1svbmkiS3B1gAZOD5u3yq+4fT4mLGvdsBT
         iMyq7rgIe9jNy2pdWwA1bncJ/TXsGPfZfUtGC2ZAkAb3kXmXryCgYtHyT2mQbNGGAKQM
         aWrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iTVqpmbo;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id d37si1564857ybi.4.2021.01.19.10.10.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:10:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id x18so10972773pln.6
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:10:10 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr992416pjb.166.1611079809851;
 Tue, 19 Jan 2021 10:10:09 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210118183033.41764-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:09:58 +0100
Message-ID: <CAAeHK+xmmTs+T9WNagj0_f3yxT-juSiCDH+wjS-4J3vUviTFsQ@mail.gmail.com>
Subject: Re: [PATCH v4 0/5] arm64: ARMv8.5-A: MTE: Add async mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iTVqpmbo;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632
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

On Mon, Jan 18, 2021 at 7:30 PM Vincenzo Frascino
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
> The series contains as well an optimization to mte_assign_mem_tag_range().
>
> The series is based on linux 5.11-rc3.
>
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
>
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async

Hi Vincenzo,

This change has multiple conflicts with the KASAN testing patches that
are currently in the mm tree. If Andrew decides to send all of them
during RC, then this should be good to go through arm64. Otherwise, I
guess this will need to go through mm as well. So you probably need to
rebase this on top of those patches in any case.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxmmTs%2BT9WNagj0_f3yxT-juSiCDH%2BwjS-4J3vUviTFsQ%40mail.gmail.com.
