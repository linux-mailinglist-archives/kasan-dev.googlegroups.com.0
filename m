Return-Path: <kasan-dev+bncBCMIZB7QWENRB5V64XUQKGQE5DKVI4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F28774874
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 09:51:19 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id k125sf41578213qkc.12
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 00:51:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564041078; cv=pass;
        d=google.com; s=arc-20160816;
        b=nqlr71eM5mO9b6jCmsQBv1sMhmvnbBiD+dA6JSh3dsq3i/yko6fWwRdL9Fk140sjTX
         TgBF2R77WIpwMNFVElEW+UuwbMyJFF0eK5NTTcKviKdFSN7Jdo5120E3PUPHSZh9JrVY
         jhSVH7aIPi3woZcgyx5kekrmcIRLkBtITefHuXWLx+nRGgn+Uq3YxH00NDxw96DzQc0S
         d1OqEP1Q5wZjbPv4xkgovZOuNlPZUypAP7pfo1rnaGiTAMSCAriggev36HmwAFPy2LYC
         b4k7wMybVxamGqkFccNAjN/IcMXPDme/8UZSVGoK1HaZNrodeuR267ObMyUUUs1JyLp3
         Pztw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TgYCawduzCYs6EOej5Tsj0d/toH1HlVfYRIdCr0lyLc=;
        b=wpFgvEi8HZRlF/fnQmLG4It9baDnyuJQqTmE+FWjlEopXDga+Nie8KD5C1Aglnmpab
         wrANpq4GiKmdwdp06Rtws6RF+KU5WEUvQfjUpwc3MeYr+5s1ct3T8dUYZoAlaMajviFW
         zwoeZ68WF/WMp6UaXps1SklfTfhxKu4KMQTyX1QNkuLwFmMfr8AJRY4oOAcW7uZd6t/+
         qMFt7VLn30/VBYtzWiyC8LMG6edNmtO/eplnL8cWJxrjpbKIaa8X2Z9B94pBqsJInngb
         42+ZXw/NA59Rn8H1HoCKgOie8iF8Sc7tdFVKWXfswWiq1c01ZPFzBf6WFMezFHdjp23q
         fEhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oWNimkmu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgYCawduzCYs6EOej5Tsj0d/toH1HlVfYRIdCr0lyLc=;
        b=qmCAyMCnpPLZog8aJSZf4cKUNPG16+f0snqD9Yt5tTFDUAYbhjF9ggvfvjcz0IPwt4
         U+JlOaWedBa4xQ+VcQlpU5WglZFNnRXMRU3BX7zbJcDuxNrQGcZQdzk9+dI3/drkH07H
         2vlBrm8vYFe0s+ukaMbz0dLHKcuq7+YkIYH7mbdB9AXFDsDbhssZFag8R0leuF674r/z
         hpjEDOjSTtcW/WF0i414bzhQRDeEpG8OSoLuLzUSjbl1013XXeIXbOGMJl/BQZanZvEw
         0Vb1OITP/Sxaftmlu/eZ1CHAbvMRQ5qVxKlwbNY0SRjidLRsHURsi4vbrbnPiHNsRD2c
         Cv3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgYCawduzCYs6EOej5Tsj0d/toH1HlVfYRIdCr0lyLc=;
        b=b9Edb968RcxeAUn4miJvt/pE//jvdLA4Rrha0FV+mGfC7p2KScq9b4Yefdw01ck34H
         y7g7Kk62T0X0NHs7pYq7IZxAaO6VLJh4Q18oMCtS77yjl2t+dzuB4hCOaBZv7Um013aC
         20AfsdUDOpAfbhC9z0IuLLN/F2izJKYOhIFd8j1AY2j91rLk0X8O6uq1aE8266Rm+Y8e
         38K0yH6jsdrHavBeoC7NkSZnuGZhOQKZsfe4h/0CMcEBLyyGzpOAWaIczR9da0Mq3jST
         bJ4b7cbQj64sJ7K0ywd5nUXzhc4CcnHy7stn+9zc2BLcCWFGk3Yzc8qiq3epKF0J1IWx
         od3w==
X-Gm-Message-State: APjAAAUgt3/yOWX/FF15kY8yAINc4kVx/06BRVzjuqM4zStr0Nk1Tfxh
	2x5KyrbKdQ/CnuYBbpMXkFA=
X-Google-Smtp-Source: APXvYqws3csHvPWLfjiAVj3bdByhDWR2WXh1SyBnqJaliQbHB76R9gjnxiG7/KB+ybKXnlnjxag2Ig==
X-Received: by 2002:a37:9b01:: with SMTP id d1mr56213128qke.46.1564041078250;
        Thu, 25 Jul 2019 00:51:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:bf42:: with SMTP id p63ls86251qkf.14.gmail; Thu, 25 Jul
 2019 00:51:18 -0700 (PDT)
X-Received: by 2002:a37:48d0:: with SMTP id v199mr56291344qka.318.1564041077986;
        Thu, 25 Jul 2019 00:51:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564041077; cv=none;
        d=google.com; s=arc-20160816;
        b=CWryWAZFBaKEnTneXJUh/OTj6+Dz5ltlJBwb00BzCMDt+Dz9pnwIP4tDG6TIcHM99Q
         VwOvFPshFXiGAdE990N+0pL1f0dLDDIhq+0EF3LytooPC4QChw9NnwcAiieevnzsphDO
         oPXNGeGofiS+3HzpUxUTK7vaR27Dr7rargk6QjefkcD5AieYCCX4kib0p0grIjVOZRhY
         qvIH1GPbwqUdJGjfOWbUAv6F92v/EIkojaa6bcwc5dW25jPdQYtmzR6X7j1SQQ+eNUq9
         xNttZb/yOwq2thjrOlrgIR4sSeLPnRyTZjoJejYjGUC0HdvGVMcnprQcUDhK1WzLCfTq
         /96A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TmgaTiXkuQ0JQAv3RzHXQAmQ/i7QMKlNUf8MnSGnxuo=;
        b=Zi8vqdWd2KZ5dvsa27iZdNuFpsnN4XmefT8y22p6nFv/iyjlj0E1VotgmuS23sopW9
         naGtxlvufiSZfntUZIOUOslKrbIMMYjajlxuyH5bauRgR8SQGSxiWc3vivo6CpKJBD5H
         L0geRSg5/xEea/bi7UJ8F5BsLBs0RGqf0tLorxyYj/8aL4yjLDYAmwQvaYemygvkTfEc
         D8yiOz+Et5sw7tHYTaMSL2KB62pozP7e6lETL1TWIijDMjDRM8LI69UgQKsjIFGefQXZ
         WxB5zsoNCg3k21R9D87JwHHf9rOTONJEOq5/HaSV6e94YkFEC4h1wFhyh0UaOWcVRheK
         VyfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oWNimkmu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id c79si2209949qke.4.2019.07.25.00.51.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 00:51:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id f4so95315124ioh.6
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 00:51:17 -0700 (PDT)
X-Received: by 2002:a6b:4101:: with SMTP id n1mr54000678ioa.138.1564041076985;
 Thu, 25 Jul 2019 00:51:16 -0700 (PDT)
MIME-Version: 1.0
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-2-dja@axtens.net>
 <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com>
In-Reply-To: <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2019 09:51:06 +0200
Message-ID: <CACT4Y+Z3HNLBh_FtevDvf2fe_BYPTckC19csomR6nK42_w8c1Q@mail.gmail.com>
Subject: Re: [PATCH 1/3] kasan: support backing vmalloc space with real shadow memory
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oWNimkmu;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jul 25, 2019 at 9:35 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> ,On Thu, Jul 25, 2019 at 7:55 AM Daniel Axtens <dja@axtens.net> wrote:
> >
> > Hook into vmalloc and vmap, and dynamically allocate real shadow
> > memory to back the mappings.
> >
> > Most mappings in vmalloc space are small, requiring less than a full
> > page of shadow space. Allocating a full shadow page per mapping would
> > therefore be wasteful. Furthermore, to ensure that different mappings
> > use different shadow pages, mappings would have to be aligned to
> > KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> >
> > Instead, share backing space across multiple mappings. Allocate
> > a backing page the first time a mapping in vmalloc space uses a
> > particular page of the shadow region. Keep this page around
> > regardless of whether the mapping is later freed - in the mean time
> > the page could have become shared by another vmalloc mapping.
> >
> > This can in theory lead to unbounded memory growth, but the vmalloc
> > allocator is pretty good at reusing addresses, so the practical memory
> > usage grows at first but then stays fairly stable.
> >
> > This requires architecture support to actually use: arches must stop
> > mapping the read-only zero page over portion of the shadow region that
> > covers the vmalloc space and instead leave it unmapped.
> >
> > This allows KASAN with VMAP_STACK, and will be needed for architectures
> > that do not have a separate module space (e.g. powerpc64, which I am
> > currently working on).
> >
> > Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> > Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> Hi Daniel,
>
> This is awesome! Thanks so much for taking over this!
> I agree with memory/simplicity tradeoffs. Provided that virtual
> addresses are reused, this should be fine (I hope). If we will ever
> need to optimize memory consumption, I would even consider something
> like aligning all vmalloc allocations to PAGE_SIZE*KASAN_SHADOW_SCALE
> to make things simpler.
>
> Some comments below.


Marco, please test this with your stack overflow test and with
syzkaller (to estimate the amount of new OOBs :)). Also are there any
concerns with performance/memory consumption for us?



> > ---
> >  Documentation/dev-tools/kasan.rst | 60 +++++++++++++++++++++++++++++++
> >  include/linux/kasan.h             | 16 +++++++++
> >  lib/Kconfig.kasan                 | 16 +++++++++
> >  lib/test_kasan.c                  | 26 ++++++++++++++
> >  mm/kasan/common.c                 | 51 ++++++++++++++++++++++++++
> >  mm/kasan/generic_report.c         |  3 ++
> >  mm/kasan/kasan.h                  |  1 +
> >  mm/vmalloc.c                      | 15 +++++++-
> >  8 files changed, 187 insertions(+), 1 deletion(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index b72d07d70239..35fda484a672 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -215,3 +215,63 @@ brk handler is used to print bug reports.
> >  A potential expansion of this mode is a hardware tag-based mode, which would
> >  use hardware memory tagging support instead of compiler instrumentation and
> >  manual shadow memory manipulation.
> > +
> > +What memory accesses are sanitised by KASAN?
> > +--------------------------------------------
> > +
> > +The kernel maps memory in a number of different parts of the address
> > +space. This poses something of a problem for KASAN, which requires
> > +that all addresses accessed by instrumented code have a valid shadow
> > +region.
> > +
> > +The range of kernel virtual addresses is large: there is not enough
> > +real memory to support a real shadow region for every address that
> > +could be accessed by the kernel.
> > +
> > +By default
> > +~~~~~~~~~~
> > +
> > +By default, architectures only map real memory over the shadow region
> > +for the linear mapping (and potentially other small areas). For all
> > +other areas - such as vmalloc and vmemmap space - a single read-only
> > +page is mapped over the shadow area. This read-only shadow page
> > +declares all memory accesses as permitted.
> > +
> > +This presents a problem for modules: they do not live in the linear
> > +mapping, but in a dedicated module space. By hooking in to the module
> > +allocator, KASAN can temporarily map real shadow memory to cover
> > +them. This allows detection of invalid accesses to module globals, for
> > +example.
> > +
> > +This also creates an incompatibility with ``VMAP_STACK``: if the stack
> > +lives in vmalloc space, it will be shadowed by the read-only page, and
> > +the kernel will fault when trying to set up the shadow data for stack
> > +variables.
> > +
> > +CONFIG_KASAN_VMALLOC
> > +~~~~~~~~~~~~~~~~~~~~
> > +
> > +With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
> > +cost of greater memory usage. Currently this is only supported on x86.
> > +
> > +This works by hooking into vmalloc and vmap, and dynamically
> > +allocating real shadow memory to back the mappings.
> > +
> > +Most mappings in vmalloc space are small, requiring less than a full
> > +page of shadow space. Allocating a full shadow page per mapping would
> > +therefore be wasteful. Furthermore, to ensure that different mappings
> > +use different shadow pages, mappings would have to be aligned to
> > +``KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE``.
> > +
> > +Instead, we share backing space across multiple mappings. We allocate
> > +a backing page the first time a mapping in vmalloc space uses a
> > +particular page of the shadow region. We keep this page around
> > +regardless of whether the mapping is later freed - in the mean time
> > +this page could have become shared by another vmalloc mapping.
> > +
> > +This can in theory lead to unbounded memory growth, but the vmalloc
> > +allocator is pretty good at reusing addresses, so the practical memory
> > +usage grows at first but then stays fairly stable.
> > +
> > +This allows ``VMAP_STACK`` support on x86, and enables support of
> > +architectures that do not have a fixed module region.
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index cc8a03cc9674..fcabc5a03fca 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -70,8 +70,18 @@ struct kasan_cache {
> >         int free_meta_offset;
> >  };
> >
> > +/*
> > + * These functions provide a special case to support backing module
> > + * allocations with real shadow memory. With KASAN vmalloc, the special
> > + * case is unnecessary, as the work is handled in the generic case.
> > + */
> > +#ifndef CONFIG_KASAN_VMALLOC
> >  int kasan_module_alloc(void *addr, size_t size);
> >  void kasan_free_shadow(const struct vm_struct *vm);
> > +#else
> > +static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
> > +static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> > +#endif
> >
> >  int kasan_add_zero_shadow(void *start, unsigned long size);
> >  void kasan_remove_zero_shadow(void *start, unsigned long size);
> > @@ -194,4 +204,10 @@ static inline void *kasan_reset_tag(const void *addr)
> >
> >  #endif /* CONFIG_KASAN_SW_TAGS */
> >
> > +#ifdef CONFIG_KASAN_VMALLOC
> > +void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area);
> > +#else
> > +static inline void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area) {}
> > +#endif
> > +
> >  #endif /* LINUX_KASAN_H */
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 4fafba1a923b..a320dc2e9317 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -6,6 +6,9 @@ config HAVE_ARCH_KASAN
> >  config HAVE_ARCH_KASAN_SW_TAGS
> >         bool
> >
> > +config HAVE_ARCH_KASAN_VMALLOC
> > +       bool
> > +
> >  config CC_HAS_KASAN_GENERIC
> >         def_bool $(cc-option, -fsanitize=kernel-address)
> >
> > @@ -135,6 +138,19 @@ config KASAN_S390_4_LEVEL_PAGING
> >           to 3TB of RAM with KASan enabled). This options allows to force
> >           4-level paging instead.
> >
> > +config KASAN_VMALLOC
> > +       bool "Back mappings in vmalloc space with real shadow memory"
> > +       depends on KASAN && HAVE_ARCH_KASAN_VMALLOC
> > +       help
> > +         By default, the shadow region for vmalloc space is the read-only
> > +         zero page. This means that KASAN cannot detect errors involving
> > +         vmalloc space.
> > +
> > +         Enabling this option will hook in to vmap/vmalloc and back those
> > +         mappings with real shadow memory allocated on demand. This allows
> > +         for KASAN to detect more sorts of errors (and to support vmapped
> > +         stacks), but at the cost of higher memory usage.
> > +
> >  config TEST_KASAN
> >         tristate "Module for testing KASAN for bug detection"
> >         depends on m && KASAN
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b63b367a94e8..d375246f5f96 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/slab.h>
> >  #include <linux/string.h>
> >  #include <linux/uaccess.h>
> > +#include <linux/vmalloc.h>
> >
> >  /*
> >   * Note: test functions are marked noinline so that their names appear in
> > @@ -709,6 +710,30 @@ static noinline void __init kmalloc_double_kzfree(void)
> >         kzfree(ptr);
> >  }
> >
> > +#ifdef CONFIG_KASAN_VMALLOC
> > +static noinline void __init vmalloc_oob(void)
> > +{
> > +       void *area;
> > +
> > +       pr_info("vmalloc out-of-bounds\n");
> > +
> > +       /*
> > +        * We have to be careful not to hit the guard page.
> > +        * The MMU will catch that and crash us.
> > +        */
> > +       area = vmalloc(3000);
> > +       if (!area) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +
> > +       ((volatile char *)area)[3100];
> > +       vfree(area);
> > +}
> > +#else
> > +static void __init vmalloc_oob(void) {}
> > +#endif
> > +
> >  static int __init kmalloc_tests_init(void)
> >  {
> >         /*
> > @@ -752,6 +777,7 @@ static int __init kmalloc_tests_init(void)
> >         kasan_strings();
> >         kasan_bitops();
> >         kmalloc_double_kzfree();
> > +       vmalloc_oob();
> >
> >         kasan_restore_multi_shot(multishot);
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 2277b82902d8..a3bb84efccbf 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -568,6 +568,7 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
> >         /* The object will be poisoned by page_alloc. */
> >  }
> >
> > +#ifndef CONFIG_KASAN_VMALLOC
> >  int kasan_module_alloc(void *addr, size_t size)
> >  {
> >         void *ret;
> > @@ -603,6 +604,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
> >         if (vm->flags & VM_KASAN)
> >                 vfree(kasan_mem_to_shadow(vm->addr));
> >  }
> > +#endif
> >
> >  extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
> >
> > @@ -722,3 +724,52 @@ static int __init kasan_memhotplug_init(void)
> >
> >  core_initcall(kasan_memhotplug_init);
> >  #endif
> > +
> > +#ifdef CONFIG_KASAN_VMALLOC
> > +void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area)
> > +{
> > +       unsigned long shadow_alloc_start, shadow_alloc_end;
> > +       unsigned long addr;
> > +       unsigned long backing;
> > +       pgd_t *pgdp;
> > +       p4d_t *p4dp;
> > +       pud_t *pudp;
> > +       pmd_t *pmdp;
> > +       pte_t *ptep;
> > +       pte_t backing_pte;
> > +
> > +       shadow_alloc_start = ALIGN_DOWN(
> > +               (unsigned long)kasan_mem_to_shadow(area->addr),
> > +               PAGE_SIZE);
> > +       shadow_alloc_end = ALIGN(
> > +               (unsigned long)kasan_mem_to_shadow(area->addr + area->size),
> > +               PAGE_SIZE);
> > +
> > +       addr = shadow_alloc_start;
> > +       do {
> > +               pgdp = pgd_offset_k(addr);
> > +               p4dp = p4d_alloc(&init_mm, pgdp, addr);
>
> Page table allocations will be protected by mm->page_table_lock, right?
>
>
> > +               pudp = pud_alloc(&init_mm, p4dp, addr);
> > +               pmdp = pmd_alloc(&init_mm, pudp, addr);
> > +               ptep = pte_alloc_kernel(pmdp, addr);
> > +
> > +               /*
> > +                * we can validly get here if pte is not none: it means we
> > +                * allocated this page earlier to use part of it for another
> > +                * allocation
> > +                */
> > +               if (pte_none(*ptep)) {
> > +                       backing = __get_free_page(GFP_KERNEL);
> > +                       backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
> > +                                             PAGE_KERNEL);
> > +                       set_pte_at(&init_mm, addr, ptep, backing_pte);
> > +               }
> > +       } while (addr += PAGE_SIZE, addr != shadow_alloc_end);
> > +
> > +       requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
> > +       kasan_unpoison_shadow(area->addr, requested_size);
> > +       kasan_poison_shadow(area->addr + requested_size,
> > +                           area->size - requested_size,
> > +                           KASAN_VMALLOC_INVALID);
>
>
> Do I read this correctly that if kernel code does vmalloc(64), they
> will have exactly 64 bytes available rather than full page? To make
> sure: vmalloc does not guarantee that the available size is rounded up
> to page size? I suspect we will see a throw out of new bugs related to
> OOBs on vmalloc memory. So I want to make sure that these will be
> indeed bugs that we agree need to be fixed.
> I am sure there will be bugs where the size is controlled by
> user-space, so these are bad bugs under any circumstances. But there
> will also probably be OOBs, where people will try to "prove" that
> that's fine and will work (just based on our previous experiences :)).
>
> On impl side: kasan_unpoison_shadow seems to be capable of handling
> non-KASAN_SHADOW_SCALE_SIZE-aligned sizes exactly in the way we want.
> So I think it's better to do:
>
>        kasan_unpoison_shadow(area->addr, requested_size);
>        requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
>        kasan_poison_shadow(area->addr + requested_size,
>                            area->size - requested_size,
>                            KASAN_VMALLOC_INVALID);
>
>
>
> > +}
> > +#endif
> > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > index 36c645939bc9..2d97efd4954f 100644
> > --- a/mm/kasan/generic_report.c
> > +++ b/mm/kasan/generic_report.c
> > @@ -86,6 +86,9 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
> >         case KASAN_ALLOCA_RIGHT:
> >                 bug_type = "alloca-out-of-bounds";
> >                 break;
> > +       case KASAN_VMALLOC_INVALID:
> > +               bug_type = "vmalloc-out-of-bounds";
> > +               break;
> >         }
> >
> >         return bug_type;
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 014f19e76247..8b1f2fbc780b 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -25,6 +25,7 @@
> >  #endif
> >
> >  #define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
> > +#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped page */
> >
> >  /*
> >   * Stack redzone shadow values
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index 4fa8d84599b0..8cbcb5056c9b 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -2012,6 +2012,15 @@ static void setup_vmalloc_vm(struct vm_struct *vm, struct vmap_area *va,
> >         va->vm = vm;
> >         va->flags |= VM_VM_AREA;
> >         spin_unlock(&vmap_area_lock);
> > +
> > +       /*
> > +        * If we are in vmalloc space we need to cover the shadow area with
> > +        * real memory. If we come here through VM_ALLOC, this is done
> > +        * by a higher level function that has access to the true size,
> > +        * which might not be a full page.
> > +        */
> > +       if (is_vmalloc_addr(vm->addr) && !(vm->flags & VM_ALLOC))
> > +               kasan_cover_vmalloc(vm->size, vm);
> >  }
> >
> >  static void clear_vm_uninitialized_flag(struct vm_struct *vm)
> > @@ -2483,6 +2492,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
> >         if (!addr)
> >                 return NULL;
> >
> > +       kasan_cover_vmalloc(real_size, area);
> > +
> >         /*
> >          * In this function, newly allocated vm_struct has VM_UNINITIALIZED
> >          * flag. It means that vm_struct is not fully initialized.
> > @@ -3324,9 +3335,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> >         spin_unlock(&vmap_area_lock);
> >
> >         /* insert all vm's */
> > -       for (area = 0; area < nr_vms; area++)
> > +       for (area = 0; area < nr_vms; area++) {
> >                 setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
> >                                  pcpu_get_vm_areas);
> > +               kasan_cover_vmalloc(sizes[area], vms[area]);
> > +       }
> >
> >         kfree(vas);
> >         return vms;
> > --
> > 2.20.1
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-2-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ3HNLBh_FtevDvf2fe_BYPTckC19csomR6nK42_w8c1Q%40mail.gmail.com.
