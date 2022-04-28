Return-Path: <kasan-dev+bncBCSMHHGWUEMBBK6CVKJQMGQESOYZYRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BA2BA513696
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 16:14:04 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id i22-20020a056e021d1600b002cd69a8f421sf1816328ila.6
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 07:14:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651155243; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uy9QbmvI/2N92ezJTBrgcdyqT02ymhmlPiuduSGabYPTBpxdvBUfpnazrcCD3Yox/T
         5L11E07mxQpN4ZYqsZ/RXhX8NrVmrCOcFexTpmDgpp80DIrY5Mdzf0qdSyVEMIoyl19u
         5M89NAKUf7LhM9djprvRws/NmCL1cDcfWjuxAZ9RTwZJtISvxA2hzx5RhIzck/ggt1cU
         EblsI6A45QHK+iBYhK+/Xvx81oxNxEqtyelwGe8CfZNRP/LtKlOKsaZfDO6sHexJY7GG
         RFvyNn9fQlotmgkReGPAfxU76qZYuRFPjCE7muVJMbOpn2WO4EUlG1YK+IwNnUMfzXij
         C6Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mK/Qw3a00DiGXAbHxP5LDsXSy00TWKBHEGhZDzClsZ8=;
        b=s4R78DRoDdknr+Wecqhx0KTXN7Xlqolg8eqj3CaNUutn26stkH+C5tt3Ub1lShp9aF
         NfkSedat0OJ7vkh0MALbUG0dQwBDYqNMKlf4pAhKBoS+A0Xw8VseZATo7DG67u1AtA1J
         MzA02drisUNtWk4D2WCZ4O4NTfhxgkhOq++tJuwG9+9q67DJ3V5S3DJEQCmFgvKsmbak
         4wvJE0Wf8loHVJ8Mngb54xqiKCuKszC9gIjYQxjmjdK+uFp36uUE9J7GpFQXBsbhJKtE
         P6fA/UMNRDjxltLyW9JmVgcZM02LUJpL1b4MMnUChdF8hcq6Be1lbuGY4SL8ciLa61Uz
         olKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=ToK9CeE7;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mK/Qw3a00DiGXAbHxP5LDsXSy00TWKBHEGhZDzClsZ8=;
        b=qduzUkZKPUXIVmadQ28iA78+BIew6r/PNf2iSpVUq0JdbQaBVbqtkJRvZ6L9J41cjz
         C70SvSs2eDMxtoWUHJ+Qdx2LIWGY9/d+oaghzffEQJsIffNUa1jnw7sHDnS+ROzEJwIG
         thEfTGDVCfrC2AcO+dt8pxPLpX1aUtePvWM9fNOkxJd+mnvtCmaoAGYKT5eQL5zgG/gE
         2JQpvllUh79UB2PegbbkVFkyfJBBXJugnXqz/eVzHY1hQPHsiPkEYVXJSEjCs16XHTJG
         TMbbxcfnfkn49/AaxNWnGcYuf8sX9vYzohIuuj4X1/9q/6NJ4ZPP2g+VKlf+2uj3CsZs
         2hgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mK/Qw3a00DiGXAbHxP5LDsXSy00TWKBHEGhZDzClsZ8=;
        b=Tds2ejM/6umOFQ3u/CaJZOawA5qtjQh1uKfXRJ8UYTromzlYVQC6Vmdlat9X16Y0ay
         r/2uT92gWL12R7qZafW4Puv97rP6//NOTvIFMEDtbCyLmDUfUq7w5oEKrQKZECH4AyUr
         jFBE1a4DfTfiUpyhs2ow8IGfY6JrBJMPT22+jg7YUHeMn4kwZdwa/I9K260VoCOwcp/I
         HEWC5arfObU17ZobSJLSqbQ6Y4jRc5Zo76Qq0Cw197ktRvdL8g//qL70/dzfjLrX9Cl3
         BqnRIiN4B9eRmO9UZxsERnz7a4tJ5FK/zu6NO9IdwdQ3j9ukQt6/bgPdiTIRSFTW348A
         tjhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532fUak6IScCnIeOMZoKJP2e+gnrBP6IQTOAQ4yVWRxzTV3L812a
	jssP7CTA6ksHr5PN3X7Hofs=
X-Google-Smtp-Source: ABdhPJw38ihMEvuRCjX5J73Poa9K/nLkkp4C5dtDg76z0r+1ZiG2rztrC8TX0k46Fl0JomBXeZTJ5w==
X-Received: by 2002:a92:c269:0:b0:2cc:505f:d963 with SMTP id h9-20020a92c269000000b002cc505fd963mr14248979ild.118.1651155243498;
        Thu, 28 Apr 2022 07:14:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:34ac:b0:32a:fd21:f5ed with SMTP id
 t44-20020a05663834ac00b0032afd21f5edls31418jal.4.gmail; Thu, 28 Apr 2022
 07:14:03 -0700 (PDT)
X-Received: by 2002:a05:6638:481a:b0:326:6a2c:2396 with SMTP id cp26-20020a056638481a00b003266a2c2396mr14023174jab.122.1651155243012;
        Thu, 28 Apr 2022 07:14:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651155243; cv=none;
        d=google.com; s=arc-20160816;
        b=MfBZCpWYg7ylaKLvk+AXHSLqgAgjBU68fZCXYjIdNO7zYbJ5pCr0YJurtU8LKA1zSR
         0FlPs01xWB6WCg22vuI1VJ3kKT/XJUVC+vOzCGY2EoweSpdhyMuo1j0cUtJMdJ3YSOQN
         jRBTnh4Zwdbay6AgZQt2VwH4bkTY7YkgHTXhk27FergfwhasScckWaKm8evuhh0kokw7
         t4hH9h6SgHM9K8gejLNaXUDj8uVkeMi2XKQagqcO24ttm5PASsatLYzmLBeHABmeebOt
         PJePvZa4I4MO01CpwsxPdjX4HLS5CTzW5k8+2hLoX1rN5dm2ArRaeyBxuuOooGqOoF/C
         AAwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=c4OmeIZ6y+f2JRwt4I1DekUCqDfEai6t2MRiaiReNuU=;
        b=XF2VcEuaOtjFF07tI2NPM6hfIiyBAxd035RRwnaE90dPxN8t7Dptz97anU88clKTmo
         ryivVUgWzemSmAnwJEz9ot/CJGXYStfFlj8QbCNrModK68nT+swH2M1VzZx9IFkMtMUP
         RK1dC8/OVuJgMsNgw4MBbde1fNnm04Esze8v8wBvPbb1ZVXP5OxK/hQXYHW3AsiSW+rh
         bUNjWGvHbC1HVQwUB2c5jS+4HBBDSMDkzc9jknmU+oUxIsOrvMCMODqafOqZzC2IejZ0
         evVdC/20NBiBan1HCU5fan9bkpYCDBK/LX8/fvtNSPSJFdvALAITEEb2qJWjEXLBX1Lk
         Cjzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=ToK9CeE7;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-01.qualcomm.com (alexa-out-sd-01.qualcomm.com. [199.106.114.38])
        by gmr-mx.google.com with ESMTPS id s11-20020a5d928b000000b0064cedb07afcsi655001iom.3.2022.04.28.07.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Apr 2022 07:14:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) client-ip=199.106.114.38;
Received: from unknown (HELO ironmsg01-sd.qualcomm.com) ([10.53.140.141])
  by alexa-out-sd-01.qualcomm.com with ESMTP; 28 Apr 2022 07:14:02 -0700
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg01-sd.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Apr 2022 07:14:01 -0700
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.22; Thu, 28 Apr 2022 07:14:01 -0700
Received: from qian (10.80.80.8) by nalasex01a.na.qualcomm.com (10.47.209.196)
 with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.22; Thu, 28 Apr
 2022 07:13:59 -0700
Date: Thu, 28 Apr 2022 10:13:56 -0400
From: Qian Cai <quic_qiancai@quicinc.com>
To: <andrey.konovalov@linux.dev>
CC: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov
	<andreyknvl@gmail.com>, Marco Elver <elver@google.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Mark Rutland
	<mark.rutland@arm.com>, <linux-arm-kernel@lists.infradead.org>, "Peter
 Collingbourne" <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
	<linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v6 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
Message-ID: <20220428141356.GB71@qian>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_qiancai@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=ToK9CeE7;       spf=pass
 (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as
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

On Mon, Jan 24, 2022 at 07:02:08PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Hi,
> 
> This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> KASAN modes.
> 
> The tree with patches is available here:
> 
> https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v6
> 
> About half of patches are cleanups I went for along the way. None of
> them seem to be important enough to go through stable, so I decided
> not to split them out into separate patches/series.
> 
> The patchset is partially based on an early version of the HW_TAGS
> patchset by Vincenzo that had vmalloc support. Thus, I added a
> Co-developed-by tag into a few patches.
> 
> SW_TAGS vmalloc tagging support is straightforward. It reuses all of
> the generic KASAN machinery, but uses shadow memory to store tags
> instead of magic values. Naturally, vmalloc tagging requires adding
> a few kasan_reset_tag() annotations to the vmalloc code.
> 
> HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
> Arm MTE, which can only assigns tags to physical memory. As a result,
> HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
> page_alloc memory. It ignores vmap() and others.

I could use some help here. Ever since this series, our system starts to
trigger bad page state bugs from time to time. Any thoughts?

 BUG: Bad page state in process systemd-udevd  pfn:83ffffcd
 page:fffffc20fdfff340 refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x83ffffcd
 flags: 0xbfffc0000001000(reserved|node=0|zone=2|lastcpupid=0xffff)
 raw: 0bfffc0000001000 fffffc20fdfff348 fffffc20fdfff348 0000000000000000
 raw: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000
 page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
 page_owner info is not present (never set?)
 CPU: 76 PID: 1873 Comm: systemd-udevd Not tainted 5.18.0-rc4-next-20220428-dirty #67
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
  (inlined by) kasan_depopulate_vmalloc_pte at mm/kasan/shadow.c:361
  apply_to_pte_range
  apply_to_pmd_range
  apply_to_pud_range
  __apply_to_page_range
  apply_to_existing_page_range
  kasan_release_vmalloc
  (inlined by) kasan_release_vmalloc at mm/kasan/shadow.c:469
  __purge_vmap_area_lazy
  purge_vmap_area_lazy
  alloc_vmap_area
  __get_vm_area_node.constprop.0
  __vmalloc_node_range
  module_alloc
  move_module
  layout_and_allocate
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
 BUG: Bad page state in process systemd-udevd  pfn:83ffffcc
 page:fffffc20fdfff300 refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x83ffffcc
 flags: 0xbfffc0000001000(reserved|node=0|zone=2|lastcpupid=0xffff)
 raw: 0bfffc0000001000 fffffc20fdfff308 fffffc20fdfff308 0000000000000000
 raw: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000
 page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
 page_owner info is not present (never set?)
 CPU: 76 PID: 1873 Comm: systemd-udevd Tainted: G    B             5.18.0-rc4-next-20220428-dirty #67
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
  purge_vmap_area_lazy
  alloc_vmap_area
  __get_vm_area_node.constprop.0
  __vmalloc_node_range
  module_alloc
  move_module
  layout_and_allocate
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220428141356.GB71%40qian.
