Return-Path: <kasan-dev+bncBCQJP74GSUDRBQXQXODQMGQEHOKL6RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C57B3C8649
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 16:44:20 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id a18-20020a056a000c92b02903282ac9a232sf1907892pfv.6
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 07:44:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626273858; cv=pass;
        d=google.com; s=arc-20160816;
        b=F8KPWWQqx3TBRtQXBgEjmwG1ZLY7Fktu8qjrg/g4EmzYIHuxRYS9bm+kkkIfE95ZPu
         eq25JJxbKHqTjYTMyhLhKDmYkLmUZqp76D+F7Qzl/xp3gTQyXoZCjTmjMnTQ6HWO2N8V
         +qe/cULfLYjnPr6ZF+oNu7eXpIWkTaN+GdSEVgrgRABVbv5i8OPAYuFDo8/MRgXOFO4p
         SpArfPQ3RhRfgaFCyd7q9DsV3XAFK91KIo6uHgdhAc2Nc1qVNe883K/hRXFjGyseBjov
         U4mF0Ej9cuHa62wS1IUhKD2EaAJjpUD9xEIB04Vbw0dwSfkMHmTIyBdeP+ABRbSP5o8Y
         v3mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=BSkSJ1dwthc8+qrGM2VFSNw3RVjdJi/gFtY0pB/RNbA=;
        b=qKbKS2kr04UWqut+UgNWoWnReW5ZT8RSPBa7djgB37wKbXS4z1ZwT6moZY25IaAQi+
         JK4FWKlkkI6ThnM44sO5/91XUr70i6X8I9sFTwHKXpVqmf1/BRSMK2Argf+ZcDO0uOxY
         EiM4/UPv7l4kzK49y4MxksDoNhbS3+TxE+TAcDFKwA4fZwFOcrS0A1ZIul0nbApwRTni
         ffYmKlG6+kGwiThrNhKU9hTbke2nxZkCI5tUQLGhVh28rBsZ5j9+D2La6OYl8MIpEtkC
         VAtlmEG0HDHr9CkEOEfvLMdMbpqHpI4+AJmTGsM/ynWSJCiB+nHpqTjXE42O2oHcVAFv
         /FYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.44 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BSkSJ1dwthc8+qrGM2VFSNw3RVjdJi/gFtY0pB/RNbA=;
        b=lMIWfFjR6i3gD0NZeuGUCgDZ7uAuQRSRysKDcyqe21chWsgODfz1jGwxySMoQa1zLi
         BV6TCIvNPiNwZR2ZxAGu63qA2broSGU2B0MOidkWRDEo56UlBWA/60WWdFs8HoMg4q6/
         IUhG5g3Km94pkTeJxCbvpRPqU8Gbzmz+lMLD3NjfoSgz5Ivr47cTPMsE6nZFX6klE4FB
         /xH9Fm+lKY8racA144a/vyQUigAjCZrhMW/XxIQU88sID/i131nqJlfWBemEzS5HlefU
         yzYTkte286f6dVHg8Bq2f8V+ZQAQJ0bp/W3q1ueDXLxwsK35nxL4JMVPLNlFTb+yV2z+
         vhLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BSkSJ1dwthc8+qrGM2VFSNw3RVjdJi/gFtY0pB/RNbA=;
        b=HSxQhPfaLlGeuGMJYFFEnIP0l6hYGpkA5+oxR+6i3e+0DWcAak9zgx6BNZwTdQnyN6
         LfVHW6sBF3S2l4bV63zOkTyjvIC9rTzIQWVARHfoiiWkjvWkOi8gWIU+6Mya8OGSSKHj
         9QSOTEsQ0Ey5wX3A0eiG7mlBp33Ttq5yHv02svScryy/QVLsT6obGwFMs0c+RrWO00+L
         +EJyGZAc+fkE4J7xhGOqhcxCM8JQ1194DIOmG+5ngPN0oRQi/1PFKLPf94HHf7VXV/Di
         nD8Y/TemHy0yORUIqFyMSvf4dwpX0uP7fHNsTNnGP1hJSiiXgzbrMjPAttsFYpLzzK5y
         F8ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hO4s1F6O/ElsOedxTQV4pv1HSNl6/T27BrRM5udwXajpPm6/I
	tFJniV12Ecp0qfTJyanCvso=
X-Google-Smtp-Source: ABdhPJwKnOhQN/8p6FWqNkGTsrQegJjN1llZ6nCC93wpftxpovKi/ZfGu/j6CDA3xChSmBE1uVWdoQ==
X-Received: by 2002:a05:6a00:bd3:b029:329:3e4f:eadb with SMTP id x19-20020a056a000bd3b02903293e4feadbmr10453491pfu.44.1626273858471;
        Wed, 14 Jul 2021 07:44:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls1342737pls.3.gmail; Wed, 14
 Jul 2021 07:44:17 -0700 (PDT)
X-Received: by 2002:a17:90a:7a86:: with SMTP id q6mr4187875pjf.141.1626273857835;
        Wed, 14 Jul 2021 07:44:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626273857; cv=none;
        d=google.com; s=arc-20160816;
        b=JQYeB76c1cLrnyw3/xoVimc//+1977Jp0nHtbfLjOiB2M9sES4Myo0E1c6eI5Z5Y/d
         Ec66vkdyxf7SQZccFFtgN3L67/QIGYJcQbHsOE8C/EylT7BTCWryJaw6beEG7NVBt5mP
         qqR1IotBxSMsq5yFRn68JatYZ1dHl5dJcJ3hMJbQ1eldqFp3pjX8ZTxvCG78UmBw8Ffw
         t+PsVp3co5TQPSfDkIu1WWFwgs66ETSu1VyP/RviJ63MfvfrkzQ8wF5/SzqJpuF+7N0O
         KzNIg2qqLFDzyqiAnyJvmYefAGzlpcJ7WsB+gSjDxeb3+L3zIj/6ccZl5D7g/gPg3bx9
         8TuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=0AK4IWMPZivSss56HDU1sJl/SWfYmT+xP3wCgy5bOzE=;
        b=Rnr2vhWcd99eQ9yxqLTc/64YyO+FSgDq9/IEbZcBATowDwyaocodS//8Far7vxlcO9
         0EPY4z0oH7Bdn0RcZS+dSsF3VEVvJwFSWraqUmsANjne3RzelN3cXgmxVkSK7Q5fbG51
         E/ZAAm5auhsCGdNw/k+tmtPWyNCzBeFnSmJkJ+EVEJJAcrGdJQ1DBE08Mp9s76NK+Unz
         iKWFesoegNgIGEaWA4ifHvBMcBIjZHcMKAYwurfMye+4WsI0uL2OmluN1t3//fqeApsH
         a+4o3KiO/zntOUXjIuALX9WkFWCvDH2RAujQviYHO4KDR4p7iztpvhf5R4tg4wg/Z7Tf
         gfGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.44 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-vs1-f44.google.com (mail-vs1-f44.google.com. [209.85.217.44])
        by gmr-mx.google.com with ESMTPS id o13si956434pji.3.2021.07.14.07.44.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 07:44:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.44 as permitted sender) client-ip=209.85.217.44;
Received: by mail-vs1-f44.google.com with SMTP id f4so1049532vsh.11
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 07:44:17 -0700 (PDT)
X-Received: by 2002:a67:3c2:: with SMTP id 185mr14479038vsd.42.1626273857075;
 Wed, 14 Jul 2021 07:44:17 -0700 (PDT)
MIME-Version: 1.0
References: <20210714143239.2529044-1-geert@linux-m68k.org>
In-Reply-To: <20210714143239.2529044-1-geert@linux-m68k.org>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Wed, 14 Jul 2021 16:44:05 +0200
Message-ID: <CAMuHMdWv8-6fBDLb8cFvvLxsb7RkEVkLNUBeCm-9yN9_iJkg-g@mail.gmail.com>
Subject: Re: Build regressions/improvements in v5.14-rc1
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Cc: Marco Elver <elver@google.com>, Steen Hegelund <Steen.Hegelund@microchip.com>, 
	linux-um <linux-um@lists.infradead.org>, scsi <linux-scsi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, netdev <netdev@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.44
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

On Wed, Jul 14, 2021 at 4:35 PM Geert Uytterhoeven <geert@linux-m68k.org> wrote:
> Below is the list of build error/warning regressions/improvements in
> v5.14-rc1[1] compared to v5.13+[2].
>
> Summarized:
>   - build errors: +24/-4
>   - build warnings: +71/-65
>
> Happy fixing! ;-)
>
> Thanks to the linux-next team for providing the build service.
>
> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/e73f0f0ee7541171d89f2e2491130c7771ba58d3/ (all 189 configs)
> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/66d9282523b3228183b14d9f812872dd2620704d/ (all 189 configs)
>
>
> *** ERRORS ***
>
> 24 error regressions:

  + /kisskb/src/drivers/dma/idxd/init.c: error: implicit declaration
of function 'cpu_feature_enabled'
[-Werror=implicit-function-declaration]:  => 805:7
  + /kisskb/src/drivers/dma/idxd/perfmon.h: error: 'struct perf_event'
has no member named 'pmu':  => 24:13, 35:13
  + /kisskb/src/drivers/dma/ioat/dca.c: error: implicit declaration of
function 'boot_cpu_has' [-Werror=implicit-function-declaration]:  =>
74:6
  + /kisskb/src/drivers/dma/ioat/dca.c: error: implicit declaration of
function 'cpuid_eax' [-Werror=implicit-function-declaration]:  =>
64:18
  + /kisskb/src/drivers/dma/ioat/dca.c: error: implicit declaration of
function 'cpuid_ebx' [-Werror=implicit-function-declaration]:  =>
17:31
  + /kisskb/src/drivers/pci/controller/vmd.c: error:
'X86_MSI_BASE_ADDRESS_HIGH' undeclared (first use in this function):
=> 150:20
  + /kisskb/src/drivers/pci/controller/vmd.c: error:
'X86_MSI_BASE_ADDRESS_LOW' undeclared (first use in this function):
=> 151:35
  + /kisskb/src/drivers/pci/controller/vmd.c: error:
'arch_msi_msg_addr_lo_t {aka struct arch_msi_msg_addr_lo}' has no
member named 'base_address':  => 151:19
  + /kisskb/src/drivers/pci/controller/vmd.c: error:
'arch_msi_msg_addr_lo_t {aka struct arch_msi_msg_addr_lo}' has no
member named 'destid_0_7':  => 152:19
  + /kisskb/src/drivers/pci/controller/vmd.c: error: control reaches
end of non-void function [-Werror=return-type]:  => 127:1
  + /kisskb/src/drivers/pci/controller/vmd.c: error: dereferencing
pointer to incomplete type 'struct pci_sysdata':  => 700:4
  + /kisskb/src/drivers/pci/controller/vmd.c: error: field 'sysdata'
has incomplete type:  => 116:21

um-x86_64/um-all{mod,yes}config

  + /kisskb/src/drivers/scsi/arm/fas216.c: error: 'GOOD' undeclared
(first use in this function):  => 2013:47

arm-gcc4.9/rpc_defconfig

  + /kisskb/src/drivers/tty/synclink_gt.c: error: conflicting types
for 'set_signals':  => 442:13

um-x86_64/um-allmodconfig

  + /kisskb/src/include/linux/compiler_attributes.h: error:
"__GCC4_has_attribute___no_sanitize_coverage__" is not defined
[-Werror=undef]:  => 29:29

mips-gcc4.9/mips-allmodconfig
s390x-gcc4.9/s390-allyesconfig

  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_1857' declared with attribute error: FIELD_PREP:
value too large for the field:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_1864' declared with attribute error: FIELD_PREP:
value too large for the field:  => 328:38

arm64-gcc5.4/arm64-allmodconfig
arm64-gcc8/arm64-allmodconfig

  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_399' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_417' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_418' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_431' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_433' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_450' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38
  + /kisskb/src/include/linux/compiler_types.h: error: call to
'__compiletime_assert_517' declared with attribute error: Unsupported
width, must be <= 40:  => 328:38

arm64-gcc5.4/arm64-allmodconfig
mipsel/mips-allmodconfig
mips-gcc4.9/mips-allmodconfig
powerpc-gcc4.9/allmodconfig+64K_PAGES
powerpc-gcc4.9/powerpc-allmodconfig
powerpc-gcc4.9/powerpc-allyesconfig
powerpc-gcc4.9/ppc64_book3e_allmodconfig
s390x-gcc4.9/s390-allyesconfig
sparc64/sparc64-allmodconfig
sparc64/sparc-allmodconfig
xtensa/xtensa-allmodconfig

Gr{oetje,eeting}s,

                        Geert

-- 
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdWv8-6fBDLb8cFvvLxsb7RkEVkLNUBeCm-9yN9_iJkg-g%40mail.gmail.com.
