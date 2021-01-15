Return-Path: <kasan-dev+bncBCJZRXGY5YJBB647RCAAMGQE26I4BBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A7312F8802
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 22:58:20 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id l18sf17373999iok.7
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:58:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610747899; cv=pass;
        d=google.com; s=arc-20160816;
        b=XrGD55EJItykrnmkr0znd+AKvurlWaIRrD3eG+JzhQjTGOfxaylRmZjMdKaJAYkmh4
         3f+OCRS1vd1Z6cDr3K9XayZJMFUGNKXla0vkZv7sbLzkco7Uqg13J2RgKjQOna4TRDG/
         D8sV/GKyJGK4C5Gh2MuCwvWPpJSu4M/JBb6L02IXYNWk73M5fMg8JnAEJJOQniUqL3fy
         jgfz9aV9C2BxtLn6bLl01/4SwktyMsb9a9przdxg0lg5bLlorzXdAqFuqLaY2BGkgEzA
         nutB99nb0/g7BZ/U3XWUmImM5J5RpR9oQp2k2xF4yx6g0Q7fJNha6Z1carkLMGQT6We6
         nvKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=MP0cjQIkPgV7iXTyoHUS0RlQzdxlOuq5J7GvIXmXgYA=;
        b=JBRn+2rgR3jCNV/ac7U6+YOYXEb4cviBR5zktFbAU5Ti876Tc2/LzVl7d7RjASojER
         nYhj2MHLfDd6txVcZDvCX7mr2SzJRtSYpEdD5AFXzTscEyKr6JChtSLutRQMRAV00LJ4
         d6ak0xGAwYPhuZwdb5y70x4oYIKhoxE5PqUrcQwj0A2shal6NsAsP3pMBicNDHnt7fZY
         b2uGfT+e3GLfJ9oZPLEPC/EIT7tcFYB0CuFEyAo9GgpC9QR130JPv6xGubptQE0F79i7
         O6i89JucnP64B1e5xdvg745ubCdK+BLmYErPV3Rhr2dQPiLL/9VQeQitz1W5xkKTHz3F
         01/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IePHwf1E;
       spf=pass (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hXhP=GS=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MP0cjQIkPgV7iXTyoHUS0RlQzdxlOuq5J7GvIXmXgYA=;
        b=okxPFSlUeTTUjmn8LaAZILajbg1ro9QeLfDcSzTh/WsPPr5avcfhQ2Q+3Xa1RNrvsz
         9IPMgvwU16MlwonAatqbkDeXJY0Kr9VVtYLFHiD7aeFCTyN2w/sWFBneVCRtv6jEPeGc
         Eq1UYgXwA3glBNqVYUvYJ4zm0IHVYxARq9UqyOScLAhcUcO5awSf4KJf2nkmeidXOTTi
         CmVEt8qXT8DL/KZ2Jf39MIPA8tld0GhS2IsEuTwBR8dqdXS79Z5vdGScKKKoop1RQbAE
         X1cQYYg+Ye6iCrhuC8NICv/KQLbqa9/kMNdv4E+73XWhWtobVUGA0Bqg5sr+1NXkZf4M
         NXYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MP0cjQIkPgV7iXTyoHUS0RlQzdxlOuq5J7GvIXmXgYA=;
        b=cXxbfplTRNnY40sraGq+OEsmoqL9XtjcOr3fDruLxnokuaSF+ZsU2w0n+00gZy6NlI
         VtraXS8FsLdU6/IDKOIXrhEsCTqd1ma48qNd6fKcxx4HpLDjS2MTFIuWJyviHwoclcbP
         7jSZ3482jH74yaIxb4BMTYV4GGH3eYQAd67lMGc8AaOQTTVHQq6LDCqFJN3h05Z3dbah
         rtA3OFsWWFdvC396g/P+xMGnIWZiOdPYG6mcSqyITwQ6c03OkDSEjj2FmLLzaz5vCClG
         YG94jT2YajmJd+I7TF2Db4XTrgYtz13iEml/2jS1HJKIi+JIiF2p3lMn6pm7kvsDauRL
         S31Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+g54NjJt0a8GNwfz00PeNCVeCnNphCsUOSINsuLcklLOmgGBx
	TIY15NTeb285OB98D2fRvk8=
X-Google-Smtp-Source: ABdhPJzdZp/XsNhxcRVUiljQugrfAx2ffJ3oxA/8cB7JHPMnhUOSoNtLSUamArGd6697LFnJkalx3A==
X-Received: by 2002:a92:6410:: with SMTP id y16mr12822818ilb.126.1610747899355;
        Fri, 15 Jan 2021 13:58:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8356:: with SMTP id q22ls1600367ior.3.gmail; Fri, 15 Jan
 2021 13:58:19 -0800 (PST)
X-Received: by 2002:a6b:c981:: with SMTP id z123mr5581161iof.206.1610747899002;
        Fri, 15 Jan 2021 13:58:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610747898; cv=none;
        d=google.com; s=arc-20160816;
        b=gyGjlEuO3MhpSxQ9jS1AdHxL0V1jlM8+2vstdTyNRIoVYI3N2stPFaSJObxOL/Xk99
         5zSs+O9gTS5SX2NjjAfCil7ZVz1VW5qU3w/zUKF3fYWFYBdAa/v+O2P1vOpUUGoxYEwP
         SYBBKbRodyp4oiGGOLPvgjHUm07/UgrGrztV66YuxmzSJrh/wRi0+E31zUTg51ZdmHh0
         d9lGSq/7S0RdVMuARPxWlhC1lihlA6FwxqsR6M71OJMRC5QtO/u7MwMfBnhoxKucRcmq
         DJ6iXAouZK3XmtTblo8yh2nN32Hu9rwjxApzOHL21DPmLzDxEs462Z8qHyo9zB+vw+07
         dQhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pkJHHRybd/UJMw2wJo5ZoK60DTkKOI/g9OKU5TE1XnI=;
        b=I+Zny3Zr49S+ZN19la0uSUM80lbSHgCuE2GBcjGm4naf+VW1aW8NOA8pa3v4vxdAdI
         +yO3kiDnhM6qoIX7e5+UdpQrSxbPhE4MXaK9zQ/VVVQcotG3u9JqaNqYKLQQGI5/d9iJ
         wUIongBaMHSEBCKgoRf0mxCdr/du5CZBb1S1cRzvS2aY+D1mX0qA0fRbe23DnZcf07lu
         0vXH6MQP1eReApztsbQpG9d5HMDeBrtxJKOFVD2JxbY0vlqN6HkLn6b3IMPTIEKayMk0
         pj+RUvuxUwBWO+DiW9mlyKC0odk5/yptgGCKao6L/BHeXiJyDhsWTrYlBSpizrO3xQOX
         1CmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IePHwf1E;
       spf=pass (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hXhP=GS=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c2si80412ilj.3.2021.01.15.13.58.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 13:58:18 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 37C22239FC;
	Fri, 15 Jan 2021 21:58:18 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 05CBA352162B; Fri, 15 Jan 2021 13:58:18 -0800 (PST)
Date: Fri, 15 Jan 2021 13:58:17 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Add missing license and copyright headers
Message-ID: <20210115215817.GN2743@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20210115170953.3035153-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210115170953.3035153-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IePHwf1E;       spf=pass
 (google.com: domain of srs0=hxhp=gs=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hXhP=GS=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jan 15, 2021 at 06:09:53PM +0100, Marco Elver wrote:
> Adds missing license and/or copyright headers for KCSAN source files.
> 
> Signed-off-by: Marco Elver <elver@google.com>

This one seemed straightforward and I heard no objections to the previous
two-patch series, so I queued them for the v5.13 merge window, thank you!

If any of them need adjustment, please send me the updated patch and
tell me which one it replaces.  Something about -rcu being in heavy
experimental mode at the moment.  ;-)

							Thanx, Paul

> ---
>  Documentation/dev-tools/kcsan.rst | 3 +++
>  include/linux/kcsan-checks.h      | 6 ++++++
>  include/linux/kcsan.h             | 7 +++++++
>  kernel/kcsan/atomic.h             | 5 +++++
>  kernel/kcsan/core.c               | 5 +++++
>  kernel/kcsan/debugfs.c            | 5 +++++
>  kernel/kcsan/encoding.h           | 5 +++++
>  kernel/kcsan/kcsan.h              | 3 ++-
>  kernel/kcsan/report.c             | 5 +++++
>  kernel/kcsan/selftest.c           | 5 +++++
>  10 files changed, 48 insertions(+), 1 deletion(-)
> 
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index be7a0b0e1f28..d85ce238ace7 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -1,3 +1,6 @@
> +.. SPDX-License-Identifier: GPL-2.0
> +.. Copyright (C) 2019, Google LLC.
> +
>  The Kernel Concurrency Sanitizer (KCSAN)
>  ========================================
>  
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index cf14840609ce..9fd0ad80fef6 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -1,4 +1,10 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * KCSAN access checks and modifiers. These can be used to explicitly check
> + * uninstrumented accesses, or change KCSAN checking behaviour of accesses.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #ifndef _LINUX_KCSAN_CHECKS_H
>  #define _LINUX_KCSAN_CHECKS_H
> diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
> index 53340d8789f9..fc266ecb2a4d 100644
> --- a/include/linux/kcsan.h
> +++ b/include/linux/kcsan.h
> @@ -1,4 +1,11 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. Public interface and
> + * data structures to set up runtime. See kcsan-checks.h for explicit checks and
> + * modifiers. For more info please see Documentation/dev-tools/kcsan.rst.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #ifndef _LINUX_KCSAN_H
>  #define _LINUX_KCSAN_H
> diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> index 75fe701f4127..530ae1bda8e7 100644
> --- a/kernel/kcsan/atomic.h
> +++ b/kernel/kcsan/atomic.h
> @@ -1,4 +1,9 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Rules for implicitly atomic memory accesses.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #ifndef _KERNEL_KCSAN_ATOMIC_H
>  #define _KERNEL_KCSAN_ATOMIC_H
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 3bf98db9c702..8c3867640c21 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -1,4 +1,9 @@
>  // SPDX-License-Identifier: GPL-2.0
> +/*
> + * KCSAN core runtime.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #define pr_fmt(fmt) "kcsan: " fmt
>  
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 3c8093a371b1..c837ce6c52e6 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -1,4 +1,9 @@
>  // SPDX-License-Identifier: GPL-2.0
> +/*
> + * KCSAN debugfs interface.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #define pr_fmt(fmt) "kcsan: " fmt
>  
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index 7ee405524904..170a2bb22f53 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -1,4 +1,9 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * KCSAN watchpoint encoding.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #ifndef _KERNEL_KCSAN_ENCODING_H
>  #define _KERNEL_KCSAN_ENCODING_H
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index 8d4bf3431b3c..594a5dd4842a 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -1,8 +1,9 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> -
>  /*
>   * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
>   * see Documentation/dev-tools/kcsan.rst.
> + *
> + * Copyright (C) 2019, Google LLC.
>   */
>  
>  #ifndef _KERNEL_KCSAN_KCSAN_H
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index d3bf87e6007c..13dce3c664d6 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,4 +1,9 @@
>  // SPDX-License-Identifier: GPL-2.0
> +/*
> + * KCSAN reporting.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #include <linux/debug_locks.h>
>  #include <linux/delay.h>
> diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
> index 9014a3a82cf9..7f29cb0f5e63 100644
> --- a/kernel/kcsan/selftest.c
> +++ b/kernel/kcsan/selftest.c
> @@ -1,4 +1,9 @@
>  // SPDX-License-Identifier: GPL-2.0
> +/*
> + * KCSAN short boot-time selftests.
> + *
> + * Copyright (C) 2019, Google LLC.
> + */
>  
>  #define pr_fmt(fmt) "kcsan: " fmt
>  
> -- 
> 2.30.0.284.gd98b1dd5eaa7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115215817.GN2743%40paulmck-ThinkPad-P72.
