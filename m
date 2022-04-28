Return-Path: <kasan-dev+bncBCSMHHGWUEMBBDX2VKJQMGQEBZYORJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 17197513972
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 18:13:04 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id c3-20020acab303000000b003226fc84078sf2840876oif.8
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 09:13:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651162382; cv=pass;
        d=google.com; s=arc-20160816;
        b=SP6697kGVeDhP+kyYRAxvm5HbhBe5YnylNmqKZaHX1tB9EF9ZkoUaNdaJPN9DMGQ+Z
         77Jrvo6T/klos7jFWOm/mRDsGWoCPrkd7eB1SDiAD9uSmtfg5ocnJ/V/nW21S4Kx7MR6
         DIiVdeHLJWjxrvW3eSMJwRF4oouGiZfYPI3siadbJ1Cm4txRz7VZPRVPlplMwoP0BJ7S
         CkioIrhXYl8fX1k9BGGqqmREkrtr7OKHoQYQpdga2wE5IsKOrFedDxxmI4rE8c8WN7rq
         HR7ro5PcV0XxuV6TOdiBmxz3dEv5n0FrNVy2B1cXiOPiLO1s+dgO3Nerje3NxxfC4/S9
         Aguw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KpPHtmcXxSD+g5JyHB6IE5Z89keNuiwOIoeirZoQDyk=;
        b=n1ZiPzK1/f6T3WB5BVXHoLBEBOV0tvVuzCt4IEG2SdEQoHb9wFCFex4qrhkqZDl+Jb
         BjEyfBEtf0qwZCWgjcZy/X56tWDvPv1nigTM04BjgPGeZGeTmAPXRL8pChCkTInw27W4
         9pBm5/dHjXs361OJ7PzolVQHxdgUOuqrTmFqkUgkx4tJicF1iFeOZWK8FG9ODi5oUw46
         Sd4/72gGrxOTRLN/nIi4Jg3WNJVKlhG1nLkjkgr1ewCmg1FlcTCtNv3giNeoMQJP7DbU
         BmUb3HDkDvVzDkV94dbB0Vc6a0XzK08o93lctXVQUDi9ISP1sIKWGnbuWU9BCg1LddPR
         TYFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=wsKFhs4F;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KpPHtmcXxSD+g5JyHB6IE5Z89keNuiwOIoeirZoQDyk=;
        b=cG/rz5/xiSIFGJuQGpg/9fTAhDAq+9RDQvN6/P4Dptl8Gw4P9J3BKjV+HB2FqcR1zk
         K3tbOjrlw36nqT7o5i3WmRY1dD/WBLfW8wsgGidfulSEepC1DtknP0YUWzOrnPjizO1G
         WV1VT3CLJYNfD4FSuniGWV8E4mSk7aHXWit9wdStkbdw9xarJc7EumwjNTElTfiMA21Z
         qy4Hmuh457a8QlfIoVbGP7X+pz00lepX1o0uDJIZZAs8+AjzBQHeKVjXwyLenDUqXVD5
         h1jExCZsuEf3ihK3AF4d0EQXJl6P7DDdBsOVVONikD/ogTrLJ54HYTtvdmxFSvWjT01O
         5cYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KpPHtmcXxSD+g5JyHB6IE5Z89keNuiwOIoeirZoQDyk=;
        b=tr/aGf5WR8UwH4Ql9sSdaPSdGh60yMKabaz4Aa0IKjO+RiVCZPM88vuzu9vd1qwnd/
         BraDXiEulQIscOpWFvm85RhzjZplVxf5w3svJ1S4bg+onBh3Ev16UbAuswdy35nkIVLY
         bNMZe6xdlh4j0CLCfRGurDUiz9bKUwMWM6BDKVkV/qm+tVs17Bu+pk2+ofikXvM256z0
         Axxj7zOOXG1iCPt3KGceDriOIqgxB8PfyI/uxraWqI9W1/fTzqT4p3ylbnlrlVsLbXmX
         lnEaERNC3TEeAcrQUIMLHHtcS80lnTix46FIkyJ783HCicldGHHL1PLa8umRsansPB5Q
         mwWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dn9tviOujHMTLbzsmRMpdYEYVnHajuc0zvbw8OywpsRrYDp8C
	kJspHUUaXBu/GXeDep6PYLA=
X-Google-Smtp-Source: ABdhPJwpSoDGtiAeNmQ86Tq34f8sTDAQE85ilG6GZjsU3gHEHdr4TpvRGA6Gd+X43fASFWx3+B9TpA==
X-Received: by 2002:a05:6870:b024:b0:e9:a3eb:a57a with SMTP id y36-20020a056870b02400b000e9a3eba57amr1949900oae.23.1651162382599;
        Thu, 28 Apr 2022 09:13:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d296:b0:e2:fa0:dca4 with SMTP id
 d22-20020a056870d29600b000e20fa0dca4ls129546oae.6.gmail; Thu, 28 Apr 2022
 09:13:02 -0700 (PDT)
X-Received: by 2002:a05:6870:5620:b0:e9:ff1:c8e8 with SMTP id m32-20020a056870562000b000e90ff1c8e8mr11947748oao.8.1651162382140;
        Thu, 28 Apr 2022 09:13:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651162382; cv=none;
        d=google.com; s=arc-20160816;
        b=EkMlHpcTGuRAi/w24pSw8oHokguQSCl1Omb9lR2RrTgm+et6n3tUIIL4ZtnjfP1yk2
         Lh3SHW8K/kOVEP0oWpcHLr2qjcdTbw08JLmYXTro/746WUAUKpCMQQTAuzuAiZ9RyHyi
         G4HWnU7vfTfpiFrne2lPeOC5zZc1STZzr3jlXjsT0JYD7emyFLsLrk3CQHErlP1ZNt79
         Yt4a9e4Flu0ySz9gMixbbDlCmT9FA/fZMAXrzeyGJ39lN3OYBoi5auu5Ppfcteu4Cfgj
         CBF92/KfXujZWP3tjTJNxMYcd7OjSNfAQmkLesm5f9ELxelN1msE2ePvpBsnxuldpUwJ
         0/nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FrfyPGyrRql3+c1AJp/BIgQHA9i1fgkYU3oOQT+9KWw=;
        b=PXeYokOmP1bwp0BxFUOVN/7McbaFujA+qQ1IccMM/8ecA3c4M60RPz7id/uOCZjhfF
         o6aRjdQ0fOIqh/acmjDaNKMcdVQhjUKo7NqXDHvou4hcN1dKvf4Mt/LgJ5CX4akmyOIi
         ahxX7m1p1jLAFAadzY5drU+z1A+hIgK9HrP/qqVcXNEaMk94CLyOCLIUJ+LjQL7BTSE4
         EKZ3sVGBMVOuFhuojacvGn6KIL6VRGhyeHzoCM3c+kDLshAYlyG0UnLgJytXMW0v0RGQ
         6qrJjuZGDKALkb0VQy95NS6a2uncgDGVwMY8ndXrXpN/TrEm0f6E/h1re2p4+UEsLPDX
         pPFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=wsKFhs4F;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-02.qualcomm.com (alexa-out-sd-02.qualcomm.com. [199.106.114.39])
        by gmr-mx.google.com with ESMTPS id i16-20020a056870d41000b000e2b65e71efsi616654oag.4.2022.04.28.09.13.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Apr 2022 09:13:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as permitted sender) client-ip=199.106.114.39;
Received: from unknown (HELO ironmsg01-sd.qualcomm.com) ([10.53.140.141])
  by alexa-out-sd-02.qualcomm.com with ESMTP; 28 Apr 2022 09:13:01 -0700
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg01-sd.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Apr 2022 09:13:00 -0700
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.22; Thu, 28 Apr 2022 09:13:00 -0700
Received: from qian (10.80.80.8) by nalasex01a.na.qualcomm.com (10.47.209.196)
 with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.22; Thu, 28 Apr
 2022 09:12:57 -0700
Date: Thu, 28 Apr 2022 12:12:54 -0400
From: Qian Cai <quic_qiancai@quicinc.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <andrey.konovalov@linux.dev>, Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Catalin
 Marinas" <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, "Mark
 Rutland" <mark.rutland@arm.com>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v6 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
Message-ID: <20220428161254.GA182@qian>
References: <cover.1643047180.git.andreyknvl@google.com>
 <20220428141356.GB71@qian>
 <CA+fCnZesRG_WLi2fEHtG=oNLt2oJ7RrZuwuCm_rQDPZLoZr-3g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZesRG_WLi2fEHtG=oNLt2oJ7RrZuwuCm_rQDPZLoZr-3g@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_qiancai@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=wsKFhs4F;       spf=pass
 (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as
 permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

On Thu, Apr 28, 2022 at 05:28:12PM +0200, Andrey Konovalov wrote:
> No ideas so far.
> 
> Looks like the page has reserved tag set when it's being freed.
> 
> Does this crash only happen with the SW_TAGS mode?

No, the system is running exclusively with CONFIG_KASAN_GENERIC=y

> Does this crash only happen when loading modules?

Yes. Here is another sligtly different path at the bottom.

> Does your system have any hot-plugged memory?

No.

 BUG: Bad page state in process systemd-udevd  pfn:403fc007c
 page:fffffd00fd001f00 refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x403fc007c
 flags: 0x1bfffc0000001000(reserved|node=1|zone=2|lastcpupid=0xffff)
 raw: 1bfffc0000001000 fffffd00fd001f08 fffffd00fd001f08 0000000000000000
 raw: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000
 page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
 CPU: 101 PID: 2004 Comm: systemd-udevd Not tainted 5.17.0-rc8-next-20220317-dirty #39
 Call trace:
  dump_backtrace
  show_stack
  dump_stack_lvl
  dump_stack
  bad_page
  free_pcp_prepare
  free_pages_prepare at mm/page_alloc.c:1348
  (inlined by) free_pcp_prepare at mm/page_alloc.c:1403
  free_unref_page
  __free_pages
  free_pages.part.0
  free_pages
  kasan_depopulate_vmalloc_pte
  (inlined by) kasan_depopulate_vmalloc_pte at mm/kasan/shadow.c:359
  apply_to_pte_range
  apply_to_pte_range at mm/memory.c:2547
  apply_to_pmd_range
  apply_to_pud_range
  __apply_to_page_range
  apply_to_existing_page_range
  kasan_release_vmalloc
  (inlined by) kasan_release_vmalloc at mm/kasan/shadow.c:469
  __purge_vmap_area_lazy
  _vm_unmap_aliases.part.0
  __vunmap
  __vfree
  vfree
  module_memfree
  free_module
  do_init_module
  load_module
  __do_sys_finit_module
  __arm64_sys_finit_module
  invoke_syscall
  el0_svc_common.constprop.0
  do_el0_svc
  el0_svc
  el0t_64_sync_handler
  el0t_64_sync
 Disabling lock debugging due to kernel taint
 BUG: Bad page state in process systemd-udevd  pfn:403fc007b
 page:fffffd00fd001ec0 refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x403fc007b
 flags: 0x1bfffc0000001000(reserved|node=1|zone=2|lastcpupid=0xffff)
 raw: 1bfffc0000001000 fffffd00fd001ec8 fffffd00fd001ec8 0000000000000000
 raw: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000
 page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
 CPU: 101 PID: 2004 Comm: systemd-udevd Tainted: G    B             5.17.0-rc8-next-20220317-dirty #39
 Call trace:
  dump_backtrace
  show_stack
  dump_stack_lvl
  dump_stack
  bad_page
  free_pcp_prepare
  free_unref_page
  __free_pages
  free_pages.part.0
  free_pages
  kasan_depopulate_vmalloc_pte
  apply_to_pte_range
  apply_to_pmd_range
  apply_to_pud_range
  __apply_to_page_range
  apply_to_existing_page_range
  kasan_release_vmalloc
  __purge_vmap_area_lazy
  _vm_unmap_aliases.part.0
  __vunmap
  __vfree
  vfree
  module_memfree
  free_module
  do_init_module
  load_module
  __do_sys_finit_module
  __arm64_sys_finit_module
  invoke_syscall
  el0_svc_common.constprop.0
  do_el0_svc
  el0_svc
  el0t_64_sync_handler
  el0t_64_sync

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220428161254.GA182%40qian.
