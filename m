Return-Path: <kasan-dev+bncBAABBVVGW75QKGQEB67LNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D5A12785B1
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:24:07 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id b73sf1546882iof.10
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:24:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601033046; cv=pass;
        d=google.com; s=arc-20160816;
        b=0z16MD5kW8HGz+ic4stm+DOdBWtL3yuzKF/WUL5UREiN/PMpar7gqd6iInOY11liSg
         F+k95ohB1bX0Pp7xXJRKdMuqCA9a7uJo2egp7Vb8Yk108+a0wJ3pPqjI5lerwW5XHXPW
         ATBl7JNjISF59nPN6CJo7kKE7ff/T4RMes7Qxw8zjmw2l72f3y4e8XU3dAggWA/EzDK/
         BnCb2ae1pLFB/OrjeU5LjTDXy0KKdauuLQyzxxd4lTgXLRTdIlGOD2tLHtvirE1keOf8
         06XaId+6oLwMQ/m6LjmK8ELRSJmncnVYW58FR1FTdPlMSXMo7q88n67SAPRISnsQgUy4
         cWMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2rtXy5M8nqeWV5fIVppPBvtf+S2OAt84FZ/R3GI0K6g=;
        b=OCfIP97YMZzpOPAPRRTSZl8VF7YW2aMHgL2PyaQtrzsJNNfFq9YGULE6GkCbdAcQgu
         Hhklo5ovcaxGYxDfMvKZCD8o1VMlK0Aw82tbYyCwAOZ+45H4HXyF347Ae7PnRVntOm5U
         TEj9XpS31V+TuTbAc82NIJwLYf7XlRNm67u99YBRtTbdrFsfrPr3SBCA0OU/KBGwKPOS
         m7Ni+zno3KOVi8MWieFLP17b6V7CBUMpvyAhSn4VSq+32141WI83mg9HaY3ZxXPAnRB5
         CAyD2VC2irzxURQq09x8lAZIJV+wuKXR0U+/pMji4Zv0IXpYcbOQvry8ZhyLX821ZXjp
         K0pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b=KFvhSpXN;
       spf=pass (google.com: domain of prvs=530411ae7=sjpark@amazon.com designates 52.95.48.154 as permitted sender) smtp.mailfrom="prvs=530411ae7=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2rtXy5M8nqeWV5fIVppPBvtf+S2OAt84FZ/R3GI0K6g=;
        b=hED2swDIOcQB0PAbcKhzl7c4fj8sN4H0oPjus8TnApDIr9itzRk9gTSisfm7O7ejjT
         rwdGZbx+w0Fm42yMJE+mcnriR2XgHCWRoSgVph1brQSFQf1/hPgN7vb8bNeJbc99GZUL
         o2jH6cirr+EzB+Lj5ppgf7AAhi1mk+oxVO2eKt/yKPevJ0bNxcBJ5l1UMWSSb9oeV+iO
         y5wOmU/7moTVxrxMwa4Ph0Dhm12hvBPpADaKan3NujoUw6gh7xiFE1wZ7WgwjiDjjYDI
         bMrPmh0xaZDvhLEgNyNArC+1/NFQ/BNHjWrGzgEqzvCkhtuaDZylpn+uwSNqVlHQa32u
         Fi7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2rtXy5M8nqeWV5fIVppPBvtf+S2OAt84FZ/R3GI0K6g=;
        b=lEqUQtl/KpPVpbDHqBKi4kvC4We6g+aXpeyKHWSFlfyBuXVEuPRGO3tTAVvwbfA68p
         VHq0ZBEOIRUmntIsi39ivOfvFPDxj3rj/gkPvGjXR6jwpUuEEpcyYZYwk6KpxFslsI9d
         72xfZtg7SCaK7MDjDH4i7fcovbAi/NTkNJ0pdl6tKmU+eyT4GFgicnB+lJK258MFIlGd
         Ud80oeb99Q8xKsvv95CgCXuRxZw+VzW7o1v41qayNvSLRaKQA/qrz0FqqsBggARwa39t
         YM9vb7Fgpu/jrU3vM2amhTfVTjpaSQpA24i7Yc4Nw3NpLtsneyYkpyzAvDL9dlHUS7kz
         RS8g==
X-Gm-Message-State: AOAM533/rekx/jmbZNWKHfFYzQBsQoFrqgZ2BaqwKWimFI1dg919hmDY
	K+rvFxL8QSysNNtS9iDIhrc=
X-Google-Smtp-Source: ABdhPJzGNwGKYIcoTJyrnZ8a1sPUQ3aZqXMVPbabttJnTt7aWLEXmffsfi/G209eMKF6hIxnYDgQaA==
X-Received: by 2002:a92:ce05:: with SMTP id b5mr2804974ilo.239.1601033046563;
        Fri, 25 Sep 2020 04:24:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8154:: with SMTP id f20ls413060ioo.11.gmail; Fri, 25 Sep
 2020 04:24:06 -0700 (PDT)
X-Received: by 2002:a5e:8206:: with SMTP id l6mr2822530iom.127.1601033046223;
        Fri, 25 Sep 2020 04:24:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601033046; cv=none;
        d=google.com; s=arc-20160816;
        b=JzF6OzCTf1D4y8WM/K6lCDrcislFUX4Y7ipPix+JyoI8N8AxGxkgJTjCdedI9n0C4Q
         000iBh6i03aK1HzAxAE7mSt+uDr4WPCPLywQbziSfboV6zy8+HtUPAyEZEfh6nZPeoFE
         PMWt8C4NWl8mOOYtxISGTYVoZbyT2hHPyx7PCn7T0y8d7t9ko7BVW10j3K2qpmTt4ES5
         fWpxeyxd/MlubxUWVnQSb0B/bPEm7b/zdMgX2wlTsduoehhC8+ZAH8c5RmMXasktC/mv
         xfotP8yxnOFEiQjHWKu9bjMraIXQrOVZABQfmmqUBOu5mQPp27lqMhQ88cJWHsMdB7o9
         xDNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=5NMENrUjSNjCsQoUiDftw7mzxLQdx0hBB98A7KX4Fnk=;
        b=Kc0iW3dvYYEhAZJh5w5XIghorxEKiRoFzpz22XNZ9u93JgOcnQ4rwhNr/6+iRHeZYI
         n3ljOqu7S6bis+ojIikQM1Yi0kyxDHwK5/wftiQ3uU/rHr8Zz0d2KDNfI7KwtOv/AdVB
         JXhJjTBJ6htvhrrqoLuJXl9RIf1kHwvGokSnA887DmDKKUBvSu7cK9SyG1zE9/Zz/CPQ
         FSTeY3QWjTVc9asiGDEayMQl6mLjJHKKZACuEpVdxawx026rrgKNL8wRZf8c1RzBpaZ9
         s6uMys75mW2aUSq4OqAyX5/lT1c4sLu83dA6Sxy1/bjriX1z0PVnMKqI0YynMBzpWWMR
         //mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b=KFvhSpXN;
       spf=pass (google.com: domain of prvs=530411ae7=sjpark@amazon.com designates 52.95.48.154 as permitted sender) smtp.mailfrom="prvs=530411ae7=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
Received: from smtp-fw-6001.amazon.com (smtp-fw-6001.amazon.com. [52.95.48.154])
        by gmr-mx.google.com with ESMTPS id a13si138444ios.2.2020.09.25.04.24.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:24:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=530411ae7=sjpark@amazon.com designates 52.95.48.154 as permitted sender) client-ip=52.95.48.154;
X-IronPort-AV: E=Sophos;i="5.77,301,1596499200"; 
   d="scan'208";a="57674777"
Received: from iad12-co-svc-p1-lb1-vlan3.amazon.com (HELO email-inbound-relay-2a-f14f4a47.us-west-2.amazon.com) ([10.43.8.6])
  by smtp-border-fw-out-6001.iad6.amazon.com with ESMTP; 25 Sep 2020 11:24:02 +0000
Received: from EX13D31EUA001.ant.amazon.com (pdx4-ws-svc-p6-lb7-vlan2.pdx.amazon.com [10.170.41.162])
	by email-inbound-relay-2a-f14f4a47.us-west-2.amazon.com (Postfix) with ESMTPS id 73A44A0334;
	Fri, 25 Sep 2020 11:23:59 +0000 (UTC)
Received: from u3f2cd687b01c55.ant.amazon.com (10.43.160.229) by
 EX13D31EUA001.ant.amazon.com (10.43.165.15) with Microsoft SMTP Server (TLS)
 id 15.0.1497.2; Fri, 25 Sep 2020 11:23:44 +0000
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: <akpm@linux-foundation.org>, <glider@google.com>, <mark.rutland@arm.com>,
	<hdanton@sina.com>, <linux-doc@vger.kernel.org>, <peterz@infradead.org>,
	<catalin.marinas@arm.com>, <dave.hansen@linux.intel.com>,
	<linux-mm@kvack.org>, <edumazet@google.com>, <hpa@zytor.com>, <cl@linux.com>,
	<will@kernel.org>, <sjpark@amazon.com>, <corbet@lwn.net>, <x86@kernel.org>,
	<kasan-dev@googlegroups.com>, <mingo@redhat.com>, <vbabka@suse.cz>,
	<rientjes@google.com>, <aryabinin@virtuozzo.com>, <keescook@chromium.org>,
	<paulmck@kernel.org>, <jannh@google.com>, <andreyknvl@google.com>,
	<bp@alien8.de>, <luto@kernel.org>, <Jonathan.Cameron@huawei.com>,
	<tglx@linutronix.de>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <gregkh@linuxfoundation.org>,
	<linux-kernel@vger.kernel.org>, <penberg@kernel.org>,
	<iamjoonsoo.kim@lge.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
Date: Fri, 25 Sep 2020 13:23:28 +0200
Message-ID: <20200925112328.10057-1-sjpark@amazon.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200921132611.1700350-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.43.160.229]
X-ClientProxiedBy: EX13D29UWA004.ant.amazon.com (10.43.160.33) To
 EX13D31EUA001.ant.amazon.com (10.43.165.15)
X-Original-Sender: sjpark@amazon.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amazon.com header.s=amazon201209 header.b=KFvhSpXN;       spf=pass
 (google.com: domain of prvs=530411ae7=sjpark@amazon.com designates
 52.95.48.154 as permitted sender) smtp.mailfrom="prvs=530411ae7=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
X-Original-From: SeongJae Park <sjpark@amazon.com>
Reply-To: SeongJae Park <sjpark@amazon.com>
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

On Mon, 21 Sep 2020 15:26:02 +0200 Marco Elver <elver@google.com> wrote:

> From: Alexander Potapenko <glider@google.com>
> 
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.
> 
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.
> 
> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error. To detect out-of-bounds
> writes to memory within the object's page itself, KFENCE also uses
> pattern-based redzones. The following figure illustrates the page
> layout:
> 
>   ---+-----------+-----------+-----------+-----------+-----------+---
>      | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
>      | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
>      | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
>      | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
>      | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
>      | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
>   ---+-----------+-----------+-----------+-----------+-----------+---
> 
> Guarded allocations are set up based on a sample interval (can be set
> via kfence.sample_interval). After expiration of the sample interval, a
> guarded allocation from the KFENCE object pool is returned to the main
> allocator (SLAB or SLUB). At this point, the timer is reset, and the
> next allocation is set up after the expiration of the interval.
> 
> To enable/disable a KFENCE allocation through the main allocator's
> fast-path without overhead, KFENCE relies on static branches via the
> static keys infrastructure. The static branch is toggled to redirect the
> allocation to KFENCE. To date, we have verified by running synthetic
> benchmarks (sysbench I/O workloads) that a kernel compiled with KFENCE
> is performance-neutral compared to the non-KFENCE baseline.
> 
> For more details, see Documentation/dev-tools/kfence.rst (added later in
> the series).
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v3:
> * Reports by SeongJae Park:
>   * Remove reference to Documentation/dev-tools/kfence.rst.
>   * Remove redundant braces.
>   * Use CONFIG_KFENCE_NUM_OBJECTS instead of ARRAY_SIZE(...).
>   * Align some comments.
> * Add figure from Documentation/dev-tools/kfence.rst added later in
>   series to patch description.
> 
> v2:
> * Add missing __printf attribute to seq_con_printf, and fix new warning.
>   [reported by kernel test robot <lkp@intel.com>]
> * Fix up some comments [reported by Jonathan Cameron].
> * Remove 2 cases of redundant stack variable initialization
>   [reported by Jonathan Cameron].
> * Fix printf format [reported by kernel test robot <lkp@intel.com>].
> * Print (in kfence-#nn) after address, to more clearly establish link
>   between first and second stacktrace [reported by Andrey Konovalov].
> * Make choice between KASAN and KFENCE clearer in Kconfig help text
>   [suggested by Dave Hansen].
> * Document CONFIG_KFENCE_SAMPLE_INTERVAL=0.
> * Shorten memory corruption report line length.
> * Make /sys/module/kfence/parameters/sample_interval root-writable for
>   all builds (to enable debugging, automatic dynamic tweaking).
> * Reports by Dmitry Vyukov:
>   * Do not store negative size for right-located objects
>   * Only cache-align addresses of right-located objects.
>   * Run toggle_allocation_gate() after KFENCE is enabled.
>   * Add empty line between allocation and free stacks.
>   * Add comment about SLAB_TYPESAFE_BY_RCU.
>   * Also skip internals for allocation/free stacks.
>   * s/KFENCE_FAULT_INJECTION/KFENCE_STRESS_TEST_FAULTS/ as FAULT_INJECTION
>     is already overloaded in different contexts.
>   * Parenthesis for macro variable.
>   * Lower max of KFENCE_NUM_OBJECTS config variable.
> ---
>  MAINTAINERS            |  11 +
>  include/linux/kfence.h | 174 ++++++++++
>  init/main.c            |   2 +
>  lib/Kconfig.debug      |   1 +
>  lib/Kconfig.kfence     |  63 ++++
>  mm/Makefile            |   1 +
>  mm/kfence/Makefile     |   3 +
>  mm/kfence/core.c       | 733 +++++++++++++++++++++++++++++++++++++++++
>  mm/kfence/kfence.h     | 102 ++++++
>  mm/kfence/report.c     | 219 ++++++++++++
>  10 files changed, 1309 insertions(+)
>  create mode 100644 include/linux/kfence.h
>  create mode 100644 lib/Kconfig.kfence
>  create mode 100644 mm/kfence/Makefile
>  create mode 100644 mm/kfence/core.c
>  create mode 100644 mm/kfence/kfence.h
>  create mode 100644 mm/kfence/report.c
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index b5cfab015bd6..863899ed9a29 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -9673,6 +9673,17 @@ F:	include/linux/keyctl.h
>  F:	include/uapi/linux/keyctl.h
>  F:	security/keys/
>  
> +KFENCE
> +M:	Alexander Potapenko <glider@google.com>
> +M:	Marco Elver <elver@google.com>
> +R:	Dmitry Vyukov <dvyukov@google.com>
> +L:	kasan-dev@googlegroups.com
> +S:	Maintained
> +F:	Documentation/dev-tools/kfence.rst

This patch doesn't introduce this file yet, right?  How about using a separate
final patch for MAINTAINERS update?

Other than that,

Reviewed-by: SeongJae Park <sjpark@amazon.de>


Thanks,
SeongJae Park

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925112328.10057-1-sjpark%40amazon.com.
