Return-Path: <kasan-dev+bncBDPPFIEASMFBBAF44CLAMGQEOOYKU7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 820BB57B985
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:23:45 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id y21-20020a056402359500b0043adf65d1a0sf12259352edc.10
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:23:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658330625; cv=pass;
        d=google.com; s=arc-20160816;
        b=h/d51lM8RO0ChXo/f7c6v5fNvFKEDP0Po3RZcG4WFU0Ij8UcEOOMSx/RYKLglK2YmC
         boWasFa7ipmWVuNG/keJFBzcP7uYieTb+KuVqxzZiO9FMsUYU3JyUQl8YwPWpCoxYe80
         7rcP/Iz8HZgRELErCMUHsqkehxK3PnZcbWo07EH9MsbK8zaMTPoj3YKPGqQDQnIMBeyD
         hsPPjnS6OMkSN5o+v/pQbcCl8cCtWW70Ff747ADTrySoOJGMebJ+JVpL0+bau7QHkVEQ
         RG36awPlejcpq8j+Mxqng+0xWCnpZ92ADkRARqWFmYgFH6ozMHkK6G8e+j8U7nu44z9q
         aJJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tT9hBaeeQWwMqx1k+WgZUufoJXBsgDataPpqQ72ptoA=;
        b=sb/PcG/4sZstO5NmYylhsUoT70CxiXE11Ip0rKqGDl/Sc4x6MBviKW6kgbdrCLEeDb
         o1j5D+JItJ8Hgtc+bi0+STD4UO68s3kDrgR618PT9t5Ba+uv3VfIZSMdZrf77bCeXkMS
         8QAAZoBuySPQRsKMX+qVXoWdLbfhlx1ftENZsGdGp305pB3DGirGQLkRx6qtwG7kN7Lu
         pInriZorvk9tA2kdWBDV6kuC8fpKTedu5S+Mt8CsTET66dtD3tozQYZstFYSK/Eh0pBr
         JlMhXUWTtpRZq5gDPv2wibnUqUapt8YspDDqgRJj8GbbMdCF7aWSmsReptNHMUgVSWXD
         hAJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HIhV3Fd6;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tT9hBaeeQWwMqx1k+WgZUufoJXBsgDataPpqQ72ptoA=;
        b=MjHAonMoTozCnVlSOGcosODqQRwFK/g6WQdo2pgA4XM4ypat64VnsAkj9gnsuT11/z
         9BbQSD4tHbp4sbCROE5PI+7SxutT/xYLGNhxNOPX9VgIalYOtDMBT8ORiD/aaNtD65L4
         WBn+t/Bw3jBX0n71W65Vt3SU1UZ9uLSsztqnXGsR7Vs9CodjNZpsChNiV29ABfvfujrd
         nzcWLwEknpRtvR73tPRbCiyuoB8jfgLMMEsuH0jpzg6K+DXqiffiId/ISbd0uuK0TsnB
         wus7lAQ6I4JOgcgoaYckl2x575OMMLeDzoOPMPea+AGXB2uOK8VzKUql/PO/CRqxi/He
         0GmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tT9hBaeeQWwMqx1k+WgZUufoJXBsgDataPpqQ72ptoA=;
        b=QYA9pLDg2r3x1IZWPJFX3OnmYacxZqWWbF5kg/TSgE0BOZ7PRxAjIpmc+PC2sQptX6
         vfrxYgVmb/P1pjulqpPvY6QjP2OWCRd+Rd5FPczaUgwKQmY9mlKL68Y2QvwDCwy4+IbZ
         rd9V8DwSPE7BNdoHwfwJn1Z6gCfDFNs+8kMiJX7k1VFg1KkZ0kRZkkPfr15g1aYOOtto
         c56cyVWsKy6uLJ0vyuDa7Wf7tDV2TicV5fnck/beax3za877dyFru/2NuW0kJEolumkf
         Sgsy8OeLCUfQQz1BHLN9OwFubrKMpsSrU1lJgylEMJcvRi10DLGvPz6+1/IYWqMXyijw
         EoAA==
X-Gm-Message-State: AJIora+nMjfi1FhvcJwseeyF0yDKNLKzpcIv4qoFClF/LUzxfsF4qD2g
	iwVpuC7op1eB78LkQWO2FMg=
X-Google-Smtp-Source: AGRyM1s+yOXAKgX5fZtEBTAsM1kPN+A1+qrv6JMSRgkFtW2YvQaroobRjOU6vunfygyG16bdbEuLJA==
X-Received: by 2002:a17:907:2854:b0:72b:7daf:cc0d with SMTP id el20-20020a170907285400b0072b7dafcc0dmr35316918ejc.524.1658330625184;
        Wed, 20 Jul 2022 08:23:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4889:b0:726:abf9:5f2e with SMTP id
 v9-20020a170906488900b00726abf95f2els296836ejq.9.-pod-prod-gmail; Wed, 20 Jul
 2022 08:23:44 -0700 (PDT)
X-Received: by 2002:a17:906:9b14:b0:72b:7c96:58c9 with SMTP id eo20-20020a1709069b1400b0072b7c9658c9mr36830966ejc.648.1658330624085;
        Wed, 20 Jul 2022 08:23:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658330624; cv=none;
        d=google.com; s=arc-20160816;
        b=JR/KfxBZZ7Mt6nZOX8L6r3sfKJJRvFr14SHem9249cIJgIqKa+qOFTImBejg2pKzRk
         BJzPNfrg56sV0VeyHxKGe6rzeTY4y1qcS5Rwf5fZVT85nBLS50vjZ96xzw0BdyynK+NJ
         zDoHP7Gim6zKN8odgpVN6nzmmJ37KAG1G6Z8aqc6Z3dEbL5FKYwGHQy0EdpLtUhDkNIA
         hv1v4ygqLpU1Jo85PMoWem2h0G/dzQoMqjUnsr2WumCYfGnWsejM2hm/UAVNnyf0lA9z
         HppxPgy2amohGeBvNZtS0b/gAU2/6SrOS0KEYB4+C3us8Y8VSHW0qDLHA6tCx8C+HqSB
         RVoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=slmyMPLStcdVZwVLrygegZI1kQWoRXJ3dHO76YDTpRY=;
        b=Cg6vcoxNsQO5WBdSOZ4sqkyVE5/5AstrFgMveWQCv+NtHuhFUx2OGK6y4vr4TCnE8V
         rq96TkFEOs9aUR8EIX3ib7/dbpWsABM7TgFbtEr8MoRzkQQ3RGQHEd4U0sjrZI3rw1//
         L5fRDCHRATgBy82SnyGtWjUbErZdj3uIR9dSup0SDNE9U0Dk3XvI4m4bYtXlyT0C2LdD
         gnDEC6KIh3XqQxLMM9bakWGAAoEJ2s7nDriu92YK/dC3MHbmuXwaS7M7o5cfHETsyVAG
         djQwbN2GFE7d2L3lxAxAbPhSfGHZSp3AwoP47BskgZhcOB/UbkQJiO0bjNiF6nEgWoK1
         Ot0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HIhV3Fd6;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id h22-20020a1709070b1600b0072695cb14f9si680964ejl.0.2022.07.20.08.23.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:23:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id n185so11071098wmn.4
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:23:44 -0700 (PDT)
X-Received: by 2002:a05:600c:20e:b0:3a3:214c:7ffb with SMTP id
 14-20020a05600c020e00b003a3214c7ffbmr494719wmi.1.1658330623182; Wed, 20 Jul
 2022 08:23:43 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-4-elver@google.com>
In-Reply-To: <20220704150514.48816-4-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:23:31 -0700
Message-ID: <CAP-5=fWWB7qnxn0WMwqGuiO=CXqfBdvjAWMc52BHSJciz04gCg@mail.gmail.com>
Subject: Re: [PATCH v3 03/14] perf/hw_breakpoint: Clean up headers
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HIhV3Fd6;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:06 AM Marco Elver <elver@google.com> wrote:
>
> Clean up headers:
>
>  - Remove unused <linux/kallsyms.h>
>
>  - Remove unused <linux/kprobes.h>
>
>  - Remove unused <linux/module.h>
>
>  - Remove unused <linux/smp.h>
>
>  - Add <linux/export.h> for EXPORT_SYMBOL_GPL().
>
>  - Add <linux/mutex.h> for mutex.
>
>  - Sort alphabetically.
>
>  - Move <linux/hw_breakpoint.h> to top to test it compiles on its own.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v2:
> * Move to start of series.
> ---
>  kernel/events/hw_breakpoint.c | 19 +++++++++----------
>  1 file changed, 9 insertions(+), 10 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index fd5cd1f9e7fc..6076c6346291 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -17,23 +17,22 @@
>   * This file contains the arch-independent routines.
>   */
>
> +#include <linux/hw_breakpoint.h>
> +
> +#include <linux/bug.h>
> +#include <linux/cpu.h>
> +#include <linux/export.h>
> +#include <linux/init.h>
>  #include <linux/irqflags.h>
> -#include <linux/kallsyms.h>
> -#include <linux/notifier.h>
> -#include <linux/kprobes.h>
>  #include <linux/kdebug.h>
>  #include <linux/kernel.h>
> -#include <linux/module.h>
> +#include <linux/list.h>
> +#include <linux/mutex.h>
> +#include <linux/notifier.h>
>  #include <linux/percpu.h>
>  #include <linux/sched.h>
> -#include <linux/init.h>
>  #include <linux/slab.h>
> -#include <linux/list.h>
> -#include <linux/cpu.h>
> -#include <linux/smp.h>
> -#include <linux/bug.h>
>
> -#include <linux/hw_breakpoint.h>
>  /*
>   * Constraints data
>   */
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfWWB7qnxn0WMwqGuiO%3DCXqfBdvjAWMc52BHSJciz04gCg%40mail.gmail.com.
