Return-Path: <kasan-dev+bncBAABBV6JWX6AKGQEVUQMNYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C398292525
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 12:05:12 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id z4sf3410913ybk.15
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 03:05:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603101911; cv=pass;
        d=google.com; s=arc-20160816;
        b=eEewNKNUR2r0kbX7q28VjBZD7tM7zQM3cC19IEPjzRK8PooIFXv9Y4QkLZG5/aUAeB
         DLlvMTNvWvEVcFzJvup9BOQwNo7G0G1CjK8iRhBK/i5p+oMifLFMivGbShDMSqzJVDnw
         LymwnPyRvP+aEnwiiNrcViMri4/4VKyNwpyRW4mK0MWgG1FRC0VaehH0iBgoO4EFNCnU
         U2t4gjKXBKCyiXqeLIIIhFk/dxTfHIO4pVliF9Zr62Q9jK6qOLqDaROM7yQLD4v2TToP
         DujqzDrkHdZ33Q+6hPj6vxlUzLa1mxJqvUwMXGYawwcVP85fPCd3ElcylulpkZxwYP7E
         M9xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YlY//AAtSsdcztC5UrWneIQa9+tSoW87eKPI6rGQzPM=;
        b=kjaovHFcrGMlTV85PLixapjfqm1+VnJW61+9tCkXq+zr9aEZ9LeOZYhARy66N8BpvM
         Bv9IrsnS00VZ+MSVnruKMlZxNHugFT49nPx2imqXMY8AYGXKb0d+doqil/xXEAPu4fYT
         S9oD1gki3QSSxYy3xSw/AT3ImuQTZT30P+M/FMldoOxiNePm2zj+TPPW5VWRC/w5GmVd
         6sY0r4g1uIj4SV6WUA6KDKp8VVciaNNkcTHIelCixjL5I1ac2kk+c7bNBD2M8mDyziUl
         Y2TvaFw6GldTNvw7b2CRBcHOiLIA6GeJYDgsqv6kVhM9+/9NI1uSqgAuMh0/pcOuY4wi
         CPzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LoKdogj9;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YlY//AAtSsdcztC5UrWneIQa9+tSoW87eKPI6rGQzPM=;
        b=SAWyJWZkUYUDlDhCAaXotBfijXUB1FPefm1URXTr4aWFazyHpeb42S+y13EYYb9kNk
         H4xKfz6HFYTvL+QehLGhNa7r28L9wo4yCfFQO8vOd24NpjO7n5XCSiDBholGKvi+VyRd
         SiZ3wHehsxXS9HX5JhpMW0ajIK9xRUedOZaEIgji26T+rSuz2LtpuoMbUjv0XQGBXdWB
         9Cg82r4BptjuZnIFis8RF0MmYjA53pBMasXuV7CoOu4KwxK04LoafEnZu7BWs37zQxlo
         4KQai9wWA0uEpSzpOLkUGmRSGsCXLLJv0+/CSzHSd7A7x56YryyRqcv3fstZNHj6tSUr
         HQog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YlY//AAtSsdcztC5UrWneIQa9+tSoW87eKPI6rGQzPM=;
        b=pcZh7D3iXC3mvGlPNVO9ZjpoDYK0LCVe8nXbHOuunT3C01UiPDDkK3uNqPqowmMA+Q
         4tBo+vxTDutMgzl2MQnIP3y7Fzy/af9Juwz5tPiAbDpKFnxCL8DXNXLuY9UMhdjVFhZB
         NpBGbXZEskwHpZwmzRcLS6lieoZh+MFHvkfeJKn1bkX1p9/H6/E2fetCOSdVCBKS9H3k
         WHuDIQS2oa55M+nks7EypAHjHZjiC/TY0yYRoGt3MNBX9BAauASPKA79rdcY0tpdXx00
         KAUULH1PIPOpZEvSYwCPzq5vz4zJ9RvXdol8H3TFsLaWoY7zOHW/JORBfmpyy/c8pm6n
         UfXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MYdTSU7JHN2oNqwkqeAzS7OSSZGM6YbDyk4sVllXEcgKMHrhy
	EfHlVIN4ZtL7/EdcF55BxOA=
X-Google-Smtp-Source: ABdhPJyG3MObj96xrw/Rn3uk6uI9mU57I5WDfdhujwcxtC/DcM42S9S7rYOZHcUh+t+wKhKG/EH5YA==
X-Received: by 2002:a25:3b4b:: with SMTP id i72mr21401367yba.22.1603101911354;
        Mon, 19 Oct 2020 03:05:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:550a:: with SMTP id j10ls2304279ybb.2.gmail; Mon, 19 Oct
 2020 03:05:10 -0700 (PDT)
X-Received: by 2002:a25:1442:: with SMTP id 63mr21358129ybu.173.1603101910828;
        Mon, 19 Oct 2020 03:05:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603101910; cv=none;
        d=google.com; s=arc-20160816;
        b=EPV/4j779Wn0FehH7ZaoYzd3zxd1+K9gD+mMtJ7DM4C4DRrzhLEeX5GMlUszX3VZAT
         7Z79srsARDcnpwUhjbqa5hvHbzW2G8fGLVh6VJXxq4eYStaQjaH/Ajrc5lAC1uu6qusm
         urt9P4Nca55PmhJmfe4eNCCChG0cC6iIfLwv3vmDv72TtrpJ/x6wlp+sHxLEwYAHoBzg
         Z9LWmHuLg1Qo7DYOaV55ZuH94K0adgNQSJv4DXz5mCKJJToJuiR17g/vWtO0NpNT4/B8
         luEx6wG/yavhVIuCLr/ly5BGjgRgTh131EAvxkh80K3tHdUE+K60SaU+ksrDnZtpqlRA
         eJ4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Q7yLpk89mef1+7HqpucR7qC5KiIHsVSBjK5x78JpXZM=;
        b=Wiuc7DHivXJbb9adWx2zlyG3o8Mdj3UrlWDvZ8dC7OBVFRcvNLycXuAAuo64HK+QJ1
         lYNn4Qr7LsnEVlKa+0w+XpZGSN+1J+m494BsC6zGvrd52jCIF2nRTH/6MeXCZUv9FiDr
         3+vNA4poIN5nwWBRYPF1fc08gXIeURIvjwQwEhPVkZpmD8AFxrnIz0mW/s1rBaVBI7zV
         s+c2W+u0X11MzoH6OrrneptD1SX1vU6lyjhM9KR/9OvFGxn31dNWwxSmZ0XpDXdbfl0n
         DmyWrpLnr6sVKJl0ezD7ACvSoZEvFgo2SPj1YLmO6iBYPejjHwmv5Wgtg197ZFpxHgyW
         wwFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LoKdogj9;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id t12si702527ybp.2.2020.10.19.03.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Oct 2020 03:05:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098417.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 09JA3I3L049331;
	Mon, 19 Oct 2020 06:05:07 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34987h112s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 19 Oct 2020 06:05:06 -0400
Received: from m0098417.ppops.net (m0098417.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 09JA3RuT050131;
	Mon, 19 Oct 2020 06:05:06 -0400
Received: from ppma01fra.de.ibm.com (46.49.7a9f.ip4.static.sl-reverse.com [159.122.73.70])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34987h1109-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 19 Oct 2020 06:05:06 -0400
Received: from pps.filterd (ppma01fra.de.ibm.com [127.0.0.1])
	by ppma01fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 09JA2Zv6001774;
	Mon, 19 Oct 2020 10:05:04 GMT
Received: from b06cxnps3074.portsmouth.uk.ibm.com (d06relay09.portsmouth.uk.ibm.com [9.149.109.194])
	by ppma01fra.de.ibm.com with ESMTP id 347r8810ak-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 19 Oct 2020 10:05:03 +0000
Received: from d06av24.portsmouth.uk.ibm.com (mk.ibm.com [9.149.105.60])
	by b06cxnps3074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 09JA51OA33292554
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Oct 2020 10:05:01 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A8A0A42049;
	Mon, 19 Oct 2020 10:05:01 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3B1074203F;
	Mon, 19 Oct 2020 10:05:00 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.52.221])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Mon, 19 Oct 2020 10:05:00 +0000 (GMT)
Date: Mon, 19 Oct 2020 13:04:58 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Linus Walleij <linus.walleij@linaro.org>,
        Florian Fainelli <f.fainelli@gmail.com>,
        Abbott Liu <liuwenliang@huawei.com>,
        Russell King <linux@armlinux.org.uk>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Ahmad Fatoum <a.fatoum@pengutronix.de>
Subject: Re: [PATCH 4/5 v16] ARM: Initialize the mapping of KASan shadow
 memory
Message-ID: <20201019100458.GB455883@linux.ibm.com>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-5-linus.walleij@linaro.org>
 <20201019093421.GA455883@linux.ibm.com>
 <CAMj1kXGgrtj79UQ7Ei5NEEQ1_ALTJRVALFnjOmhZLb_4tSHauQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXGgrtj79UQ7Ei5NEEQ1_ALTJRVALFnjOmhZLb_4tSHauQ@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.235,18.0.687
 definitions=2020-10-19_02:2020-10-16,2020-10-19 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 adultscore=0 clxscore=1015 bulkscore=0 malwarescore=0 phishscore=0
 mlxlogscore=999 spamscore=0 priorityscore=1501 mlxscore=0 impostorscore=0
 suspectscore=1 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2010190074
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=LoKdogj9;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Oct 19, 2020 at 11:42:44AM +0200, Ard Biesheuvel wrote:
> On Mon, 19 Oct 2020 at 11:37, Mike Rapoport <rppt@linux.ibm.com> wrote:
> >
> > On Mon, Oct 19, 2020 at 10:41:39AM +0200, Linus Walleij wrote:
> > > This patch initializes KASan shadow region's page table and memory.
> > > There are two stage for KASan initializing:
> > >
> > > 1. At early boot stage the whole shadow region is mapped to just
> > >    one physical page (kasan_zero_page). It is finished by the function
> > >    kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
> > >    head-common.S)
> > >
> > > 2. After the calling of paging_init, we use kasan_zero_page as zero
> > >    shadow for some memory that KASan does not need to track, and we
> > >    allocate a new shadow space for the other memory that KASan need to
> > >    track. These issues are finished by the function kasan_init which is
> > >    call by setup_arch.
> > >
> > > When using KASan we also need to increase the THREAD_SIZE_ORDER
> > > from 1 to 2 as the extra calls for shadow memory uses quite a bit
> > > of stack.
> > >
> > > As we need to make a temporary copy of the PGD when setting up
> > > shadow memory we create a helpful PGD_SIZE definition for both
> > > LPAE and non-LPAE setups.
> > >
> > > The KASan core code unconditionally calls pud_populate() so this
> > > needs to be changed from BUG() to do {} while (0) when building
> > > with KASan enabled.
> > >
> > > After the initial development by Andre Ryabinin several modifications
> > > have been made to this code:
> > >
> > > Abbott Liu <liuwenliang@huawei.com>
> > > - Add support ARM LPAE: If LPAE is enabled, KASan shadow region's
> > >   mapping table need be copied in the pgd_alloc() function.
> > > - Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
> > >   kasan_pgd_populate from .meminit.text section to .init.text section.
> > >   Reported by Florian Fainelli <f.fainelli@gmail.com>
> > >
> > > Linus Walleij <linus.walleij@linaro.org>:
> > > - Drop the custom mainpulation of TTBR0 and just use
> > >   cpu_switch_mm() to switch the pgd table.
> > > - Adopt to handle 4th level page tabel folding.
> > > - Rewrite the entire page directory and page entry initialization
> > >   sequence to be recursive based on ARM64:s kasan_init.c.
> > >
> > > Ard Biesheuvel <ardb@kernel.org>:
> > > - Necessary underlying fixes.
> > > - Crucial bug fixes to the memory set-up code.
> > >
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: kasan-dev@googlegroups.com
> > > Cc: Mike Rapoport <rppt@linux.ibm.com>
> > > Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
> > > Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
> > > Acked-by: Mike Rapoport <rppt@linux.ibm.com>
> > > Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> > > Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> > > Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
> > > Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
> > > Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> > > Reported-by: Florian Fainelli <f.fainelli@gmail.com>
> > > Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> > > Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> > > Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
> > > Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> > > ---
> >
> > ...
> >
> > > +     cpu_switch_mm(tmp_pgd_table, &init_mm);
> > > +     local_flush_tlb_all();
> > > +
> > > +     clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> > > +
> > > +     kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> > > +                                 kasan_mem_to_shadow((void *)-1UL) + 1);
> > > +
> > > +     for_each_memblock(memory, reg) {
> > > +             void *start = __va(reg->base);
> > > +             void *end = __va(reg->base + reg->size);
> > > +
> >
> > I've killed for_each_memblock() recently and we have now
> >
> >         for_each_mem_range(idx, &pa_start, &pa_end)
> >
> > instead.
> >
> 
> Will the enumeration include NOMAP regions as well? We could actually
> omit them here, since they don't need KASAN shadow.

The NOMAP regions are omitted.

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201019100458.GB455883%40linux.ibm.com.
