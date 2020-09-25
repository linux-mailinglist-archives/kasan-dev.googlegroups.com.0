Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMNKW75QKGQEXSX4BGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C8952785DA
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:32:02 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id u3sf1552747iow.15
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:32:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601033521; cv=pass;
        d=google.com; s=arc-20160816;
        b=q/3E0LIbCDimcuaiebFixdX0pCt72+tBBq6E6eRIB9buWJ/POzTA9OSrxqNXXR/xK+
         Z/lvOeXkhELG0FSJjHolzeAikJMMBdeOsxa1m/Q1P3j53uxLnQwT2y2Z6OmTAubgdSPa
         RSmhyvV7NsbxBTDR+PyK+jV0VeuT7KCatUIEPd1INA1awnJvWPAsDesDVql8cXKFjWHA
         IfaCxaGy9jrg+wZVomcR5AkiH2EbsRrnFakEs2f3gVfTcit5Pe5WjosU8OVMsrzIMshQ
         3BhVavWBjMj1onn9F2Yqq9CtJ2JEUf1V7SGSwqmc0TUC0teH5qX14ydkfeyo0beaR46b
         Gs9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6R8pyTZKbY4Y6P/tvV3ttOicsN3Npfg+RydAWzy49ss=;
        b=sO1VI+ImBM+Lc8j4CexbjNK1yI6hbOgKvm2X6vaL2C+o4LJYQfqEi5dNnmBF7cSZNQ
         S5UAWYnAUEK3I9M10+A015M7lrX+F3AVJEh3EDNASdOnGhAUQ/vpXiLOIC71pV+VpTkg
         bjwFUiluayK06kv7fGa0Ja+TCSh3MnmGdgPhqaQuHCyACCC3s/AZL1afx5362NpYfGkz
         Bw2wAR2bUX2t4w9oYiXoSJ88J5kjUZvEjfPxO0J9wjrFkYXeIQWK6vSqKrPdM3+PJsyt
         6J9TA/3K1gXiSB3J3kucUZGUqD2nJhvaSRFSdnRUdk0HE24x4jC0GmCAEa4Td6HY1tu1
         tsew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qyHbJgNn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6R8pyTZKbY4Y6P/tvV3ttOicsN3Npfg+RydAWzy49ss=;
        b=QmKV2NZVdLjMyQpRl6xwqW+/joC0skMOmD/1WMLYFuYqAP5FhIzr5Zt8OVFYU3IUzW
         ZFSITYi1PjZYcV2kLdHQEYUOot7U1rX1PmXgMkrADHbmlDNWzcy9OPeSN1ozW1irF+Na
         LkXLEVpuApshwV4rsfVj/2b8up4Pd8ptb3yHV1+ZAM32Ze8s975k5k43U9agataa93qf
         UaiajMryTy9pb9Pstl9sDCh1QS3Xia4zkEFBI9smsI4BaAfQ+oZL5idk50gAP5s32Lpd
         D5xIs24j5R3oqlZKdxf7wHwMlVDXq1oS80gU5BHsJC4P5G6oOVTzQ14W/TIbtzoxofyc
         wyQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6R8pyTZKbY4Y6P/tvV3ttOicsN3Npfg+RydAWzy49ss=;
        b=eg4Y1P+2EkAvBbb3TNW3ZI7k2MTT9IPZ5eMrkKH9ZR3ZDYkBmPvXoLMRqgZ84lTITy
         3Cnax0XUggaXad0pL+qGCf6I/lTkqAJPAKPa7yjnb8HriKVXu9cH2htUXYZcH9tXyq4u
         OVhZULD/sMtZRnYqzE1ibeRKaw/QYxbLZj4E+htAZFAGClsDkTuPjCEc4a28inoK5dst
         vOUH9adPntc056Ud6hAH+L+nk5lhXgbKbd7Uv+9N0FFBTSPd/1KQyltxtbWT4KHDwgvs
         0sN5pZDNjrm8HvlEh4qpw1BQsvd0IFGVCueW2G8C5Bm0YCr85SI85GEtulunPKc9G34l
         e8rg==
X-Gm-Message-State: AOAM533QERtcDatX/auQ4rK71FyA+N2YeQ7XjWeF/+jYo1QrOkYoi6lr
	/1/P6qwHD9uY4R8edwb5a4w=
X-Google-Smtp-Source: ABdhPJzQCROkLS2RssJ2PX7sFwtLJVINnYAmGfmd63ZaZxtoyFLPv2yPWxqLDXv9hUXgrCy9zN63hg==
X-Received: by 2002:a6b:8dc7:: with SMTP id p190mr2831621iod.209.1601033521208;
        Fri, 25 Sep 2020 04:32:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:220c:: with SMTP id l12ls331833jas.6.gmail; Fri, 25
 Sep 2020 04:32:00 -0700 (PDT)
X-Received: by 2002:a02:ccdb:: with SMTP id k27mr2733060jaq.103.1601033520772;
        Fri, 25 Sep 2020 04:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601033520; cv=none;
        d=google.com; s=arc-20160816;
        b=FOwIBv9O+HiPwtWtGn2JEppNYGPNwPkxzdMJtgroEwvjQIS3fU0Oy2wTfANjXZW44v
         dUWqFxUCCv3hrfLabOCE6lhgesnAvQgXSVK6WiTaoo1WY8uCELMZXtsx/TUXYNtlhZxI
         Rh/vIGpFFRaUWettvd8QjIXwxe/mnlY4CW7WbLkdkHKYfV4nDi2Hh2p0ZNYawGbKGE3f
         YgWIPnm7nDEhMdCkxfGoBVsdOn2rCRe4iDvmHQVGFrLjQ/lfZUcKb4JQ33KMaYUzE9fO
         kHQzokRmit4AW+jRlNCOMBUua4F324pcRtw7wrxe9gH90pGHMu8fdb5pebP4Udcaakb+
         +MVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6L8pDz+HxatuOD/RjMAAdgwqh+b4jciwbLlL8vlXkeA=;
        b=eq1lJ5aK0BF/8IB6PriOd3dLNR09XiBOydkIyu2ctFWS847trC2grYOu3IgH4gViP+
         nYxHigCV5LBEcFyWvbO7Wojnw94527w4LKoxtRetUyxRq+31zzN7T5oTRwlm/WUWifNw
         lnxOPUpL8ItM5emWSL5cUkV4xz+kWYHk4QB9enw1q8qJjn89eov7uTVxr1Fnf0UjmR1w
         ikIDyeOMYpBd5HLj/K2cAoDCe2HNQeTYIFwNfbQOVtMEhtRVxmmQQbJQBeZejBo+UxAJ
         3YJTSRk6zZ93F6/ra69DfRW6kIMi2NfNYPJ6i7c+6P68eBthb/cN7Y7xwywlzJIkVojM
         6r/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qyHbJgNn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id k18si136693ion.4.2020.09.25.04.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id m12so1987843otr.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Sep 2020 04:32:00 -0700 (PDT)
X-Received: by 2002:a9d:66a:: with SMTP id 97mr2621626otn.233.1601033519970;
 Fri, 25 Sep 2020 04:31:59 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-2-elver@google.com> <20200925112328.10057-1-sjpark@amazon.com>
In-Reply-To: <20200925112328.10057-1-sjpark@amazon.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Sep 2020 13:31:48 +0200
Message-ID: <CANpmjNMG+1Fiff+_PMFanRVc9SRoTKa-Z9SMM9eKTRL9MsoD0w@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: SeongJae Park <sjpark@amazon.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Hillf Danton <hdanton@sina.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Eric Dumazet <edumazet@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Christoph Lameter <cl@linux.com>, Will Deacon <will@kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, "the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Ingo Molnar <mingo@redhat.com>, Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Kees Cook <keescook@chromium.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Jann Horn <jannh@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Borislav Petkov <bp@alien8.de>, Andy Lutomirski <luto@kernel.org>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, LKML <linux-kernel@vger.kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qyHbJgNn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 25 Sep 2020 at 13:24, 'SeongJae Park' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Mon, 21 Sep 2020 15:26:02 +0200 Marco Elver <elver@google.com> wrote:
>
> > From: Alexander Potapenko <glider@google.com>
> >
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.
> >
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. The main motivation behind KFENCE's design, is that with
> > enough total uptime KFENCE will detect bugs in code paths not typically
> > exercised by non-production test workloads. One way to quickly achieve a
> > large enough total uptime is when the tool is deployed across a large
> > fleet of machines.
> >
> > KFENCE objects each reside on a dedicated page, at either the left or
> > right page boundaries. The pages to the left and right of the object
> > page are "guard pages", whose attributes are changed to a protected
> > state, and cause page faults on any attempted access to them. Such page
> > faults are then intercepted by KFENCE, which handles the fault
> > gracefully by reporting a memory access error. To detect out-of-bounds
> > writes to memory within the object's page itself, KFENCE also uses
> > pattern-based redzones. The following figure illustrates the page
> > layout:
> >
> >   ---+-----------+-----------+-----------+-----------+-----------+---
> >      | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
> >      | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
> >      | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
> >      | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
> >      | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
> >      | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
> >   ---+-----------+-----------+-----------+-----------+-----------+---
> >
> > Guarded allocations are set up based on a sample interval (can be set
> > via kfence.sample_interval). After expiration of the sample interval, a
> > guarded allocation from the KFENCE object pool is returned to the main
> > allocator (SLAB or SLUB). At this point, the timer is reset, and the
> > next allocation is set up after the expiration of the interval.
> >
> > To enable/disable a KFENCE allocation through the main allocator's
> > fast-path without overhead, KFENCE relies on static branches via the
> > static keys infrastructure. The static branch is toggled to redirect the
> > allocation to KFENCE. To date, we have verified by running synthetic
> > benchmarks (sysbench I/O workloads) that a kernel compiled with KFENCE
> > is performance-neutral compared to the non-KFENCE baseline.
> >
> > For more details, see Documentation/dev-tools/kfence.rst (added later in
> > the series).
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > v3:
> > * Reports by SeongJae Park:
> >   * Remove reference to Documentation/dev-tools/kfence.rst.
> >   * Remove redundant braces.
> >   * Use CONFIG_KFENCE_NUM_OBJECTS instead of ARRAY_SIZE(...).
> >   * Align some comments.
> > * Add figure from Documentation/dev-tools/kfence.rst added later in
> >   series to patch description.
> >
> > v2:
> > * Add missing __printf attribute to seq_con_printf, and fix new warning.
> >   [reported by kernel test robot <lkp@intel.com>]
> > * Fix up some comments [reported by Jonathan Cameron].
> > * Remove 2 cases of redundant stack variable initialization
> >   [reported by Jonathan Cameron].
> > * Fix printf format [reported by kernel test robot <lkp@intel.com>].
> > * Print (in kfence-#nn) after address, to more clearly establish link
> >   between first and second stacktrace [reported by Andrey Konovalov].
> > * Make choice between KASAN and KFENCE clearer in Kconfig help text
> >   [suggested by Dave Hansen].
> > * Document CONFIG_KFENCE_SAMPLE_INTERVAL=0.
> > * Shorten memory corruption report line length.
> > * Make /sys/module/kfence/parameters/sample_interval root-writable for
> >   all builds (to enable debugging, automatic dynamic tweaking).
> > * Reports by Dmitry Vyukov:
> >   * Do not store negative size for right-located objects
> >   * Only cache-align addresses of right-located objects.
> >   * Run toggle_allocation_gate() after KFENCE is enabled.
> >   * Add empty line between allocation and free stacks.
> >   * Add comment about SLAB_TYPESAFE_BY_RCU.
> >   * Also skip internals for allocation/free stacks.
> >   * s/KFENCE_FAULT_INJECTION/KFENCE_STRESS_TEST_FAULTS/ as FAULT_INJECTION
> >     is already overloaded in different contexts.
> >   * Parenthesis for macro variable.
> >   * Lower max of KFENCE_NUM_OBJECTS config variable.
> > ---
> >  MAINTAINERS            |  11 +
> >  include/linux/kfence.h | 174 ++++++++++
> >  init/main.c            |   2 +
> >  lib/Kconfig.debug      |   1 +
> >  lib/Kconfig.kfence     |  63 ++++
> >  mm/Makefile            |   1 +
> >  mm/kfence/Makefile     |   3 +
> >  mm/kfence/core.c       | 733 +++++++++++++++++++++++++++++++++++++++++
> >  mm/kfence/kfence.h     | 102 ++++++
> >  mm/kfence/report.c     | 219 ++++++++++++
> >  10 files changed, 1309 insertions(+)
> >  create mode 100644 include/linux/kfence.h
> >  create mode 100644 lib/Kconfig.kfence
> >  create mode 100644 mm/kfence/Makefile
> >  create mode 100644 mm/kfence/core.c
> >  create mode 100644 mm/kfence/kfence.h
> >  create mode 100644 mm/kfence/report.c
> >
> > diff --git a/MAINTAINERS b/MAINTAINERS
> > index b5cfab015bd6..863899ed9a29 100644
> > --- a/MAINTAINERS
> > +++ b/MAINTAINERS
> > @@ -9673,6 +9673,17 @@ F:     include/linux/keyctl.h
> >  F:   include/uapi/linux/keyctl.h
> >  F:   security/keys/
> >
> > +KFENCE
> > +M:   Alexander Potapenko <glider@google.com>
> > +M:   Marco Elver <elver@google.com>
> > +R:   Dmitry Vyukov <dvyukov@google.com>
> > +L:   kasan-dev@googlegroups.com
> > +S:   Maintained
> > +F:   Documentation/dev-tools/kfence.rst
>
> This patch doesn't introduce this file yet, right?  How about using a separate
> final patch for MAINTAINERS update?

Sure.

> Other than that,
>
> Reviewed-by: SeongJae Park <sjpark@amazon.de>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMG%2B1Fiff%2B_PMFanRVc9SRoTKa-Z9SMM9eKTRL9MsoD0w%40mail.gmail.com.
