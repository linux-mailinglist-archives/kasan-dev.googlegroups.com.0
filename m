Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS6A2GAAMGQESBADYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 071EA308D33
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 20:21:49 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id o77sf6525782pfd.9
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 11:21:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611948107; cv=pass;
        d=google.com; s=arc-20160816;
        b=VRMrBxIyRiOt9U2SyYgnAviDy5IeZ/H/vbkV2j+JkZJ8Ak3sHilcN+nbYXS/MiO/WK
         Lm3xfs9xMjffwwG/XzDfE3ncoOcbC67+1irFaZpDFOB9ljRUBigFgMgzkyhc9N2nghiA
         AJAZUSE0HJWaTM918n5MQrACs4rzENhu7pABrnB0mKx8TpfPMheh+G5mGgBYfqE1jg6F
         V7mcE1jLpEhuTx5b8RNl0ZuYlsEKngBJ0cQGgh+PmHPuOGjUz2evhuTJ+NGhCItPzodq
         Xo9UQVpXmtkJasz7HWEATyGuf7xRIwbAWeJPh1fHHHnpA0DHxKagRNQx4pcdUfvH0ug/
         sK5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4RQOzVaGRmw+onUt0gBUbaTs+SM8xIkbyrqulET1t0w=;
        b=P2kV9f5y4CAlzBbjDN6XBYOlZrBKz2tdSfyzbvEpUwijpTYxlTaakATli0NdLBmuJu
         4ZZkjvG4aJgQXbAwMom/aYFnIi/TJXcWVgr9aArJ+5EUiUKER9On8jd4q6uxgePlnOYc
         iLRCeVZ+b1qk7ebYSv9F9fGMK3tBNrx+RM/fU+WZ0JvBVUiedxm3pBRhk42it2JddfZs
         omFRoqZh0kkjKv/iCR0oT5lUfxtHkmrGtUoqkvOCj3PM2vN+rmCJ0SX161tZsDDFIJLf
         NBEycQpxPwD/xeVBslBFGD/l/VxjD53RwwjgjaM7Rf6LHGNbkX+86lYZv+tKfk9/NW+x
         AfJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IjgzGb7w;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4RQOzVaGRmw+onUt0gBUbaTs+SM8xIkbyrqulET1t0w=;
        b=Z5t7rTqpjyLJSMY6CDb8D4iDGtRGRAF5AlhYrTXR01RUR8qtH2EfwBV1o1BeEm7ihV
         TQ74o7QFE4mwS8gxfWobLoT/9+M0brn8OaT9O06qW4HaVBPhvEZlX4pOkRv/CMm3rSNm
         VvVqewC6iklgUBW3ZgITdsFCRcPRAPgguUPgSzYFm281SJLLOxbIbt4OTFxrwO9KajnQ
         F1oHi5OvFNDITjktLBQpaCQuZqe/e5i0KNdXT+HkI7n6Q8mDufcVLRkb8eOKwLps+YVy
         RnOtAf5bVxi0bmXHvgtdb2IOm426ueNxfEtsABWto2UBZLrJtYdLaZFQ6JLASus3d00F
         +3AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4RQOzVaGRmw+onUt0gBUbaTs+SM8xIkbyrqulET1t0w=;
        b=R3VXmK/UL0kBCXWoNu0U5d49ACRC5CvynMpXyD8Mc8io5lqox9VDZt6FZGgNaEltXy
         YkKtnn5RUcWf3ci12U1c3FLjm6xWAwwaNBwLSZG6AsgHCCbIftdYKtTPgzh6CZQoceU0
         Oia142LqNMOvNriOzNoyRrbsK4wN788PURoQ9N35rhzxR7Go/Wft5QFBciljVj8XXHKR
         Y4vUQDDcJxQuQSuQ39wLAmVHy0DvVK3kIwSqUprVgCIDwCqDMGHmhdHmJexCiMtkBqtD
         Wsryd9gO4C0GUwEYv6Mji4L8bMwKjTLv5uAiVyEPyWBp//oDKqcyQa9fJ44iGll/r4zr
         AOHw==
X-Gm-Message-State: AOAM532sJHZsM7UZcELDhwsncKWQb+zuyhJini2aiBxqACWgHhZgT9dv
	iMCmY8PoKLH6JmDo8evIbWA=
X-Google-Smtp-Source: ABdhPJxq96gaOu9PewvYARtSZr6/QFenmSpKOIOgTjWALxaHDb1uXEAZ3hkNRiUPv5+9dCfjeI2FBw==
X-Received: by 2002:a65:5c48:: with SMTP id v8mr6132319pgr.400.1611948107759;
        Fri, 29 Jan 2021 11:21:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9386:: with SMTP id t6ls4001853pfe.1.gmail; Fri, 29 Jan
 2021 11:21:47 -0800 (PST)
X-Received: by 2002:a65:6542:: with SMTP id a2mr6147542pgw.148.1611948107199;
        Fri, 29 Jan 2021 11:21:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611948107; cv=none;
        d=google.com; s=arc-20160816;
        b=uuoZJ7CCCuPun4j/OHlWm376rGP1/aUMCeiFgNoZc1Apojzk1uAoaEZwKe787B1NuO
         VmRj9cc3ClpWoUU4GXQ2RWXO2geGlwqKqR0F5gzTrnZLtQHaBs9DyAsDo1u+L8r8k31k
         9TO625mNdXLd7o3AwwVK3qoUO00umare9eH/B3wS7KRzsq7TqGj5QSM2l0J52ytSH8SY
         XeE0xRvDCh+qKDunenfGCiiSkSLcCxgrs4d0xHi2vU9Jz6WfDwuo/Bo6PZkqvRgCklX8
         JrX2masXq5YRpZO2J/NDzuW7o3vcvL+NaO95Xo1o1G2VKg/aRpNp0seaJL9nyWVV3vcn
         bJnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NcjbEbjTpWYG73gblgVXiKLVQUYE+zg3Ldwequmr1XM=;
        b=t3EVDYKtmJ3auFzSHyJzkdNH493xCfgAkS0f/9WGhb9kzblgvun7XCgR3RpQGg0xS4
         sC84+VafE7JwX8zO9BG337pKoCVbX6XTjYam0DXBBJ0Wb2sS9zO0iB9PvIFEUwU9URdF
         QTFX587qq8Aq7vRXKSdgl7asZhIC07v9OazRj+KP3KthMCjPeE0xvjsHy4xVX7Kise+N
         1KJ2WI0PbkARmfaLx3BWiHnPpwO+KmN2u0qCXuauMcRuh7PewytjvDy9UmDTKPh4sFrX
         Bb7SZQD3at0yYfw6nUofJncdbLQEMxkIeNuvSoz9hsSFw6rdUn7y1DwlmWUGWrDNpNfE
         YuFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IjgzGb7w;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id n3si432654plx.5.2021.01.29.11.21.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 11:21:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id u67so6846942pfb.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 11:21:47 -0800 (PST)
X-Received: by 2002:a62:115:0:b029:1b4:c593:acd4 with SMTP id
 21-20020a6201150000b02901b4c593acd4mr5704865pfb.2.1611948106699; Fri, 29 Jan
 2021 11:21:46 -0800 (PST)
MIME-Version: 1.0
References: <20210129184905.29760-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210129184905.29760-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 20:21:35 +0100
Message-ID: <CAAeHK+w5hHcN-4Q8KYpMnG1rQvz9N_kXc7=uY07nH=937MUTjA@mail.gmail.com>
Subject: Re: [PATCH v10 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IjgzGb7w;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f
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

On Fri, Jan 29, 2021 at 7:49 PM Vincenzo Frascino
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
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm
>
> Changes:
> --------
> v10:
>   - Rebase on the latest linux-next/akpm
>   - Address review comments.

Thinking again about this: properly fixing that tracing issue is
similar to fixing the issue with the tests. Let's do both as a part of
this series.

Here's a tree with the fixes. I've marked the ones that need to be
squashed with "fix!". PTAL, and if the additions look good, please
send v11 with them included.

https://github.com/xairy/linux/commits/vf-v10.async.akpm-fixes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw5hHcN-4Q8KYpMnG1rQvz9N_kXc7%3DuY07nH%3D937MUTjA%40mail.gmail.com.
