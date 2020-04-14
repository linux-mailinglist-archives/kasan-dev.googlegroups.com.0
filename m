Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFEC272AKGQEL2CSLPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E1CE1A7EF2
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 15:56:37 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id r64sf11700725qkc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 06:56:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586872596; cv=pass;
        d=google.com; s=arc-20160816;
        b=JM42/oARuGa9X+5z2PKbMAM7RfTDvTS2cd51mIh5X4y1Wlaf7azodMjQpwM5kaJCXn
         C0V4EXLOA6QjLDbIAeFPGKgLa6ignH++pd8gIU16VS+2OBnDC3gl242EHtiglRy+1iQm
         YmLXf/ch1RCb9LGiIbtzDbWQf52i77duJcO9WdvVACcZc2jTAvDwNiHZODVuvaPVaYB4
         zdrZ8lr7ZGEV4Mn3oVYSlKH1aKutmtuF0bikd2sSFxtzk+OWi4rkataBTPlfSsoGKKXn
         hgOPiyy/3kpQrUV2YGd4kUx39joTO3jeCsj+gtWHgBkIFJ+rQ57iDIIldgM6MEBximtb
         NTZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zPo6Gg8+ALginDuIoLOlGjcYpsixcegByjL0nswrdPg=;
        b=YBcI8w2Bz0HI7MvJ7d6VWkbBUCaWUNQ3P36G9kV4IE+TiNVGFmR/g/JrIImvU1OYFE
         s/rMvB1ZZBhkZSGmqJfWvW5WVfkyGS0ZS4o4A+M/00vfJJjChsHlCjFwoEnnijFWSw/2
         CLfV5BtkAud3ABhed4G75f+vR0BVA2IAIqa9sQ8LGbxbkWzP/1wSBPuC8crPn925a4g8
         M6esff6bLezOK9gs9x5g+bg+tnK8UML9mUpbMDaDgAnXt0DhuMqWOk56MCuxZ/ceSC8u
         PJEQKx3K+V3kyyN3AtYTyoZpGMCoPwpifcQOEE4YERRvcEMLpS5KB+S8qpPNJoOZnGoz
         Q+rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zw93CQ7w;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zPo6Gg8+ALginDuIoLOlGjcYpsixcegByjL0nswrdPg=;
        b=ZthVnVx+ySDcrOWhfJbwh4wxNbKfFPyALJ8ptgIYV/zWerYcq94iGqPTS0Mbk3hx+u
         3UFC6079rPm1q6OXqBstcYMxfOhrQIMJJF1a8DaMpQVmtGrIpigCyDKn/ctg9BrufgI7
         sVPxxwWQsl0ypucK82HiiUzcZi9UvzH5jSRyttTOCVZwg8PlO3/rWOPlpS03M0cyhh7d
         EfIS/AWb0aqNV11NBur3qxH8rrJK8d3qO14si25hY69qRIaoJ2tsV1AVMpoBYfT47CrT
         qXE6j9u72LyvVdtWh0p1MxG/zcipDZ4UK04hKelFx08fjkba07jvr1k8qnxmBS5rOPC0
         Hzng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zPo6Gg8+ALginDuIoLOlGjcYpsixcegByjL0nswrdPg=;
        b=CQ/9guS46auvgjgOgGAEzkJMCbTsdTjueoHu/i+9yd9TAE6QnPi8agMmEzgrqMabh4
         IazeSsJ8E1Pfxbw4CMPzn/0/Sjhw4rJrJBjzbyITOZ+w9EC0bIbFGOjCU6QMZ+5LRW6m
         QLWGKGxm5D3eGtxQIkYp9bSkuwYSWXEOdcasZVs0VXNVn13fTRIqc1nVdCN3svrpE3Ko
         fphZgsxyyOIym1tRg97xnXDmyXCmfuK6I+foyFJgIN0ELIVGytD/F8kmMxY/7wX/y5My
         OEtbkN0PLGhBwPGdwFYGQ2+cyF4QO+phdoBX+ztKSrjtNit4OilNuWm8ZyEGIiChD7HA
         7Unw==
X-Gm-Message-State: AGi0Pua79X+GRLpPu2UeWGNxzqPCscSLRcPTjDSIwHuke8pEWNpUcHWL
	nh6FOGbuFlwAdPZpUpdy4j8=
X-Google-Smtp-Source: APiQypJP1171nDkG83L9/5Dk133WmXHE2MOM6jRZQHeFDfGVll+wVaqvhSNobwI3Rw+GRrSuTRFyLg==
X-Received: by 2002:a37:2e44:: with SMTP id u65mr21619792qkh.42.1586872596380;
        Tue, 14 Apr 2020 06:56:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:51c4:: with SMTP id d4ls1678523qtn.9.gmail; Tue, 14 Apr
 2020 06:56:36 -0700 (PDT)
X-Received: by 2002:aed:3223:: with SMTP id y32mr16975501qtd.133.1586872595949;
        Tue, 14 Apr 2020 06:56:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586872595; cv=none;
        d=google.com; s=arc-20160816;
        b=vfAY6EgONzsZC6pyGEwl2QB3Qgr2N0JYHqQluUQcmCLoowSMBzbTgNdrKJmK6+ITJy
         Y3ctx1Bsg4YSeLL5sREyjNi4hqZcjqtoyXYw99CR996qURnjjOGeZo4i/8FJbU8UMKk5
         W5dmKPagkOsAriL6uiBwBP0kKC7aM34nOLGUjqIHNI8VImY2EiVcZUS1vXRNfS7k9N+U
         AI6rebAq+IGHjDBqrZpei0rjEBfpLu62YD6/I9DnbSJw2vk+ehIPxLEH812Tw+3E16Y8
         M0StQxNjAMyb9iYyKZoSi/rM3VDO3aTUQgGq3yheaIxtEBVv6SHbLwy5Vn5xJgQPjl2U
         thAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CdHyZcZTKwMKKbebErAZluDvkJ+zw3eiekp5EmZ8JSo=;
        b=VdF5pBu1WRCmpCIPOFbQlqCwaWCn3aTphO0OE/ICEy0HZNsi8uQcd+QLjL/3RKPH9O
         ilT+N32i2NJQEJCt8kBAFI/iaRXlbQCbd4RbclpihNkRFv4o8TF1sv3CBckIblDj7qyN
         AyoCp/p64QRiziyXgwvVIJ/qo5pl7p9Az9/1jyNY0/Frn94/fSHFppmRvJ/MnQlqe7ET
         IoF6PLx4HPbZr74LsBMR0IV1bBDOPcYB3FjBBfHlE3/IHpdvvkFEXiSgK8tzx1PmpBY9
         zBJ0torQ6NcH1k0ZqvKWOyFTYzHnh4vFHiwBWJTbbzNsvfJtZljScNCcQ/HQgxrA4NtS
         vLJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zw93CQ7w;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id o2si69430qkg.1.2020.04.14.06.56.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Apr 2020 06:56:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id l1so6072498pff.10
        for <kasan-dev@googlegroups.com>; Tue, 14 Apr 2020 06:56:35 -0700 (PDT)
X-Received: by 2002:a63:cf02:: with SMTP id j2mr22289788pgg.130.1586872594761;
 Tue, 14 Apr 2020 06:56:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200414031647.124664-1-davidgow@google.com> <20200414031647.124664-5-davidgow@google.com>
In-Reply-To: <20200414031647.124664-5-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Apr 2020 15:56:23 +0200
Message-ID: <CAAeHK+wq9VTjqCu6dqjn+UyrEWbuW8fFSZObmnN1X6mR4Pzo2w@mail.gmail.com>
Subject: Re: [PATCH v5 4/4] KASAN: Testing Documentation
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zw93CQ7w;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Tue, Apr 14, 2020 at 5:17 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
> CONFIG_TEST_KASAN_USER.

This patch needs to be updated to use the new naming, TEST_KASAN_KUNIT
and TEST_KASAN_MODULE.

>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
>  1 file changed, 70 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..287ba063d9f6 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
>
>  This allows ``VMAP_STACK`` support on x86, and can simplify support of
>  architectures that do not have a fixed module region.
> +
> +CONFIG_TEST_KASAN & CONFIG_TEST_KASAN_USER
> +-------------------------------------------
> +
> +``CONFIG_TEST_KASAN`` utilizes the KUnit Test Framework for testing.
> +This means each test focuses on a small unit of functionality and
> +there are a few ways these tests can be run.
> +
> +Each test will print the KASAN report if an error is detected and then
> +print the number of the test and the status of the test:
> +
> +pass::
> +
> +        ok 28 - kmalloc_double_kzfree
> +or, if kmalloc failed::
> +
> +        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
> +        Expected ptr is not null, but is
> +        not ok 4 - kmalloc_large_oob_right
> +or, if a KASAN report was expected, but not found::
> +
> +        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
> +        Expected kasan_data->report_expected == kasan_data->report_found, but
> +        kasan_data->report_expected == 1
> +        kasan_data->report_found == 0
> +        not ok 28 - kmalloc_double_kzfree
> +
> +All test statuses are tracked as they run and an overall status will
> +be printed at the end::
> +
> +        ok 1 - kasan_kunit_test
> +
> +or::
> +
> +        not ok 1 - kasan_kunit_test
> +
> +(1) Loadable Module
> +~~~~~~~~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built as
> +a loadable module and run on any architecture that supports KASAN
> +using something like insmod or modprobe.
> +
> +(2) Built-In
> +~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built-in
> +on any architecure that supports KASAN. These and any other KUnit
> +tests enabled will run and print the results at boot as a late-init
> +call.
> +
> +(3) Using kunit_tool
> +~~~~~~~~~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN`` built-in, we can also
> +use kunit_tool to see the results of these along with other KUnit
> +tests in a more readable way. This will not print the KASAN reports
> +of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
> +information on kunit_tool.
> +
> +.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
> +
> +``CONFIG_TEST_KASAN_USER`` is a set of KASAN tests that could not be
> +converted to KUnit. These tests can be run only as a module with
> +``CONFIG_TEST_KASAN_USER`` built as a loadable module and
> +``CONFIG_KASAN`` built-in. The type of error expected and the
> +function being run is printed before the expression expected to give
> +an error. Then the error is printed, if found, and that test
> +should be interpretted to pass only if the error was the one expected
> +by the test.
> --
> 2.26.0.110.g2183baf09c-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414031647.124664-5-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwq9VTjqCu6dqjn%2BUyrEWbuW8fFSZObmnN1X6mR4Pzo2w%40mail.gmail.com.
