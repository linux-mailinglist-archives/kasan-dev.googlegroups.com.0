Return-Path: <kasan-dev+bncBDV37XP3XYDRB4MD2XVAKGQEHL5NSBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2BEF8EA35
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 13:28:49 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id f11sf1303253edn.9
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 04:28:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565868529; cv=pass;
        d=google.com; s=arc-20160816;
        b=VVlnEedyZwu/o/iTsrG5m/GkDufTXfPeWo73+j8vlF5x7kZeZpIxFCscxVY1RBMo6o
         c8hDTKo8CUqgi3WD0ISPxbg9pDHjS9kbmvLZjzO8GkpTeIwV9kIMDcRoJHj3ft6IcFEI
         XE7/F+Q7PHg+mgFcUQL3vhcUwvfmgJNvEW+QeOU/VeR0vooonLsI5GFuk1Hys4rNaHeu
         2mjYB4NAgh6vP1QLvSQZdkOzZtX/fRKv3Nx0bYefff6yxMJFr6jMrzF2U5Uu6AZW+OZm
         upd0SfMI7Hm4KO0APcyfv27vUyXMpLJ59T9bzlTq+BtftSBI9361raUZsBhR/m5U+ZIH
         MkhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=YtG/HjVilZRUltp0Ic8ODw3kAzguQpOEkfbM8PD5ISI=;
        b=soRHcXJsb9JEa/tNJ+lIvqz9++awzMmdQJ0hyOd3lOr2nWChHQa9MwTd59F0PsNrss
         u0RUPN5Gd7tzm/7JAaw5B3p0GYg4Xw56jA+GP8zSPiqvQ62+4HJd/HUR50ZnYjNTlxZg
         OIzuvf6lnro0kILcU7KvD0FN3Qk9hl03sDt7EdCLEXUwOfE05FGwqud4TwvRc6VI41gl
         2T/gEm5OXhWgKyC9T7VCd3IJIh1AGaS3aTN8nFKZzfkS2bt+uZPEVCXBn53V0rNbrcmO
         QON7679H+dhRtvCfR+c7jP0T3T5WzEDOBYRQVN56VTnTjRGtD6/paMV/tAnpSamCwOsS
         FdtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YtG/HjVilZRUltp0Ic8ODw3kAzguQpOEkfbM8PD5ISI=;
        b=rGdgWL33HZ1b2hPD1dsobAWOZMFGbYJXh31Tn3rI5tRGE9BPu2ExcxmYv6/1lAW1RO
         pe8UIyYGx7GhdnAga5KOpF6Gb4Yf8K0kF7zSXaInS8Fuwvg7TOJGXkq2m72wKYajWibI
         lZs/7WdeH1DV+C0bcpDHfo0QzOobh3wRnv1x8IqQzX8J9/e9B3hYfNJ+uYz5J957ZrCI
         3NgzOV+u5vtIR83mguZdAWNF7XC8Pjv0UjNXQ/e3DQ4RbAMKN4N/66xgg5n0qVUQaXcw
         3JxjkOvi4mp1gtO6nAy42+JIvCsilYVbW73hmJ6vkoYdh2t6d1NglqWnQ1bByE7Bc6ES
         ypQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YtG/HjVilZRUltp0Ic8ODw3kAzguQpOEkfbM8PD5ISI=;
        b=NF5tFrmAlRzbvCx4fxA4jxcTfdQNqDDrfuCF661BWbTOpN8MCMqLbKVrPMGSLyIEx5
         VNsvORhWfamXy2gausla8sR/hCHmvS/PhMOFdljDCZEi6Ala9vqK4U+jU4QB2Zu+P8MR
         CniRcRI4zYCD+/XPo9cML/L1rzS/ICSd07sgN2+1Sb1SERcdLzorSughEATdIUyT4N0D
         sJE55xMEAoCpVHO8kSCLKOxUFBOp+Qgd35ya0VrouHdukQr/zZtqkLnfw0woXA3biqet
         aVNvu/yAswhJha+lNVCXYgByr35as9t0one3F4t/OY56NJyfZ3qV530bjRwAwZPt4WAW
         RF1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW1rMnpXGYdckb4Ig9W0/4GzukMnM5vgNnGBQxFdUB1mmuIS+if
	uYX5DPvgV2gTgp1gngjWq4A=
X-Google-Smtp-Source: APXvYqyYRT5hfy0k5QA+82jqyorxt0a0lxEa+mI6KAH533Lcjv8MEXfXmZwkWbnt1VB6lChqz0dJpA==
X-Received: by 2002:a50:f70c:: with SMTP id g12mr4873177edn.139.1565868529639;
        Thu, 15 Aug 2019 04:28:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7a05:: with SMTP id d5ls1135592ejo.13.gmail; Thu, 15
 Aug 2019 04:28:49 -0700 (PDT)
X-Received: by 2002:a17:906:76d3:: with SMTP id q19mr3883772ejn.249.1565868529083;
        Thu, 15 Aug 2019 04:28:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565868529; cv=none;
        d=google.com; s=arc-20160816;
        b=aZcIVaMWr7qj/iC4XJqDzbHeFHl7bIIIfIQ8PJxKspigQUDDKwy1nF1izoArjRDkUS
         Aovj/MQIStyIzX50f5EkmkK147C2Ey0zb1KvRNM4rvMFcCNYslsYtzCrI+GCKvKnhbvf
         ZceLpncUXcVIaCUqV/pwH6vwyUwZ2CztCCv5ubj23VPifRAluQp0nzNu+ApXKQLqRIVu
         nlav3gc7vWfF/989E+noJkaOcaSzJ1PT72HLiRFVV3HbNV1g4JVolN4YBAnBa0aGI98Y
         HwJNlbkM3SErqjET+iGm7U6U82IlsOQrtMTPcAS9vCUlLb/bTvFPYfEHRQVtxOgQWwPa
         KtFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Z8ojWW9gL1tNN+GgjQ9upxuIgdMzuO44sl/zmmoG4+s=;
        b=OBPGBrZ1FlGoO4a6IfXwVdy1QABTzEdgZlQ91uFqY88HFeS4BmaWAW+6ZjAtOCGlEi
         Z+dXFEOv+SYbafPPJrQidXOeBuel6uSm+qKIs0izRWGq1LZrfnMxpOD2cEoU7chNfKdY
         BEw2uhTCunCITEB8jeTk8rmAISxwzWLi11swiY9N+zYDrzoWTC0K2+V7o3EQaQkPM4YQ
         rsBpJ1uSEGURiIzPqq/qtbqWdDqoI9XoIYC+ERRXzX3YO110zV9kFWfET7Age9eD94jv
         eKAodKpmdFUlUnur3Mn0vZPYpv9cKAc1Y69ZLHdfAFty790C/B836JYOMWOxaTlllzT8
         d7JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m16si139192edv.2.2019.08.15.04.28.48
        for <kasan-dev@googlegroups.com>;
        Thu, 15 Aug 2019 04:28:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4A2E0360;
	Thu, 15 Aug 2019 04:28:48 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CD5DA3F694;
	Thu, 15 Aug 2019 04:28:46 -0700 (PDT)
Date: Thu, 15 Aug 2019 12:28:44 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com,
	linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v4 0/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190815112844.GC22153@lakrids.cambridge.arm.com>
References: <20190815001636.12235-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190815001636.12235-1-dja@axtens.net>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Aug 15, 2019 at 10:16:33AM +1000, Daniel Axtens wrote:
> Currently, vmalloc space is backed by the early shadow page. This
> means that kasan is incompatible with VMAP_STACK, and it also provides
> a hurdle for architectures that do not have a dedicated module space
> (like powerpc64).
> 
> This series provides a mechanism to back vmalloc space with real,
> dynamically allocated memory. I have only wired up x86, because that's
> the only currently supported arch I can work with easily, but it's
> very easy to wire up other architectures.

I'm happy to send patches for arm64 once we've settled some conflicting
rework going on for 52-bit VA support.

> 
> This has been discussed before in the context of VMAP_STACK:
>  - https://bugzilla.kernel.org/show_bug.cgi?id=202009
>  - https://lkml.org/lkml/2018/7/22/198
>  - https://lkml.org/lkml/2019/7/19/822
> 
> In terms of implementation details:
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate
> a backing page the first time a mapping in vmalloc space uses a
> particular page of the shadow region. Keep this page around
> regardless of whether the mapping is later freed - in the mean time
> the page could have become shared by another vmalloc mapping.
> 
> This can in theory lead to unbounded memory growth, but the vmalloc
> allocator is pretty good at reusing addresses, so the practical memory
> usage appears to grow at first but then stay fairly stable.
> 
> If we run into practical memory exhaustion issues, I'm happy to
> consider hooking into the book-keeping that vmap does, but I am not
> convinced that it will be an issue.

FWIW, I haven't spotted such memory exhaustion after a week of Syzkaller
fuzzing with the last patchset, across 3 machines, so that sounds fine
to me.

Otherwise, this looks good to me now! For the x86 and fork patch, feel
free to add:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> 
> v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.net/
> v2: https://lore.kernel.org/linux-mm/20190729142108.23343-1-dja@axtens.net/
>  Address review comments:
>  - Patch 1: use kasan_unpoison_shadow's built-in handling of
>             ranges that do not align to a full shadow byte
>  - Patch 3: prepopulate pgds rather than faulting things in
> v3: https://lore.kernel.org/linux-mm/20190731071550.31814-1-dja@axtens.net/
>  Address comments from Mark Rutland:
>  - kasan_populate_vmalloc is a better name
>  - handle concurrency correctly
>  - various nits and cleanups
>  - relax module alignment in KASAN_VMALLOC case
> v4: Changes to patch 1 only:
>  - Integrate Mark's rework, thanks Mark!
>  - handle the case where kasan_populate_shadow might fail
>  - poision shadow on free, allowing the alloc path to just
>      unpoision memory that it uses
> 
> Daniel Axtens (3):
>   kasan: support backing vmalloc space with real shadow memory
>   fork: support VMAP_STACK with KASAN_VMALLOC
>   x86/kasan: support KASAN_VMALLOC
> 
>  Documentation/dev-tools/kasan.rst | 60 +++++++++++++++++++++++++++
>  arch/Kconfig                      |  9 +++--
>  arch/x86/Kconfig                  |  1 +
>  arch/x86/mm/kasan_init_64.c       | 61 ++++++++++++++++++++++++++++
>  include/linux/kasan.h             | 24 +++++++++++
>  include/linux/moduleloader.h      |  2 +-
>  include/linux/vmalloc.h           | 12 ++++++
>  kernel/fork.c                     |  4 ++
>  lib/Kconfig.kasan                 | 16 ++++++++
>  lib/test_kasan.c                  | 26 ++++++++++++
>  mm/kasan/common.c                 | 67 +++++++++++++++++++++++++++++++
>  mm/kasan/generic_report.c         |  3 ++
>  mm/kasan/kasan.h                  |  1 +
>  mm/vmalloc.c                      | 28 ++++++++++++-
>  14 files changed, 308 insertions(+), 6 deletions(-)
> 
> -- 
> 2.20.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815112844.GC22153%40lakrids.cambridge.arm.com.
