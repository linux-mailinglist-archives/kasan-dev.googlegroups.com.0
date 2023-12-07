Return-Path: <kasan-dev+bncBCRKNY4WZECBBJGRY6VQMGQEH6HIPYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id D733E808C1F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 16:45:41 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-58daf9b195csf1059140eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Dec 2023 07:45:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701963940; cv=pass;
        d=google.com; s=arc-20160816;
        b=q7KDMDxsuRkhgQF9K8jfc7HPeeOgSjTpnsWXLLk5f1T6J/jKFBNtnLSqEC7F8Eo6Yh
         Pdd1Q2z7T0m/RH81xhUGNy3HByLxZ8IoJeHNwI+xMn8yiabD5PZe/RUldqt5S5ONUCSj
         lM1rGhx6W8/5sGAXCLfPMusMQBcAjWM4LmPMJ+dhcjPBIg6keBAtmz+pOBOFIz7rnT4A
         QAVaMqluNWlTM1/Tuw2Yt2TRCBs7q3ESG6sdvdWplSFPhqUHJIy9/MKbr2W5J23CmlYs
         D9hfSKdSf54hwqRQUsQqcJOcSd+Uf9mxuDFvXuzy85L9AUx557YZGnfU+5bZWqs/NKa7
         EqPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=3U7wnwJVpK8mAYNvHJdZmtlH8sw/lgl5QHivglWg1HE=;
        fh=ao3wT1IWZtlV76z0noBV4yexrjjBkJG1lnByrAgVCqA=;
        b=pu2YaWysjEHGtbG2Fghdyi3yDONqEDVtkyPjOGCIYehzvscKBcx8T72tJcVlHBBb4C
         z+jEHIztGTvuXEIOHh/Kye6QWeri/M5sHYB+lpaplfgKGzm6e34qahvRVcbQ8SHwnbHQ
         eqmT6UNjGqpv2EU177mTXdaj/LbAQ5CzUo7mWxEknLKPE5lCfn4vb+tcRXfB7O7b0/Po
         UXrBifaIY/A6ypFEWhOBC+oKcrGeIByYfpBA7ZJMc+6INdCPPoL0fLMiVCfGd3vj8eav
         WpDSbH4y4zGWJrr8RnVHo0aL6F1rU3+6XLMKrSUOQG3vXQwsKOcIxZvrEjS2WrT/QlCj
         5DSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20230601.gappssmtp.com header.s=20230601 header.b=r65AmKvP;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701963940; x=1702568740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:to:from:cc:in-reply-to
         :subject:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3U7wnwJVpK8mAYNvHJdZmtlH8sw/lgl5QHivglWg1HE=;
        b=Ki/0/wmVwVrjwfGds3R8xr4vD4J8uPwWl9u+n9gC25HPhOis0Alt8/VnNmtjGdKD5p
         yC2k/nOx38qsAagBRVabhkyrqOem9MxnQNTay59wtcrozSpUHNIQyXFq3rMNhLeYdmWq
         rdC8GMQbFeK8tvySFNsSSa2aAvEB+yyfz1mW4iMIPFobpJm2ZEI6DoNm1gj2b1+yRJB8
         viIKr4trs6TVbMI9v1rAyyOMkquiRGGzKvd3nd8Aul5GLdIVriqi2pvjZUveTPHWPp8l
         yJuJ5hovGWkzyKIiqNGfDaNKEVc3O3kXNupPyxqnQc7PjsilJWV+oWql4EpkoP5107mn
         unQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701963940; x=1702568740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:to:from:cc:in-reply-to
         :subject:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3U7wnwJVpK8mAYNvHJdZmtlH8sw/lgl5QHivglWg1HE=;
        b=K+mCNjpsK2105MRUlrMu4JAGiA47lp6GQ949GeFx0G63Sw+XVsmlRPsiHE3vsCWiKJ
         i3WmjRcZo0VbHv8CdZFcC/tVc5S7AqNQlOgqnPmV6itBFafLgO5VzTWjk9dD5gDnMG0P
         1Btz6CHy0CZr7koGwZZqjCQHkznkhc1Hy1I+jrgegP1Py95BAzfSSxmPcu8nWjgbFyxG
         nEGaOy5jI7vHfnWufCfpB75HL0ZbtP+hACVutVRnUsnMuPmuNnNSL7knVtO+8Awah+lI
         Ofld7YTHyspnixdju/BHpRt//f8bcSewiIO4It5Itg5hque8vTduxVqGym+DO5SVfnPM
         XaNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx6PHem8oWL5UOzS9O8ysMeLin5obYyesSlxxil8KfSPlSz22tJ
	lVvaqClolermp1fy3GS9A/g=
X-Google-Smtp-Source: AGHT+IGBYs2nWM84mmODcptrRyQdvZYz/PkPiIl+OKb7Le5P4OtxWms20fSCaqnORF7LB9ia4sPa1g==
X-Received: by 2002:a05:6870:420b:b0:1fa:f15d:e200 with SMTP id u11-20020a056870420b00b001faf15de200mr2482401oac.6.1701963940681;
        Thu, 07 Dec 2023 07:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:218f:b0:1fb:17f2:5fa4 with SMTP id
 l15-20020a056870218f00b001fb17f25fa4ls1084487oae.1.-pod-prod-00-us; Thu, 07
 Dec 2023 07:45:40 -0800 (PST)
X-Received: by 2002:a05:6871:741d:b0:1fb:336d:e34d with SMTP id nw29-20020a056871741d00b001fb336de34dmr5739829oac.0.1701963940352;
        Thu, 07 Dec 2023 07:45:40 -0800 (PST)
Received: by 2002:a05:6808:218f:b0:3b9:e2a5:d630 with SMTP id 5614622812f47-3b9e2a5e8a2msb6e;
        Thu, 7 Dec 2023 07:34:59 -0800 (PST)
X-Received: by 2002:a05:6870:aa87:b0:1fa:3df6:29fb with SMTP id gr7-20020a056870aa8700b001fa3df629fbmr1573109oab.2.1701963297545;
        Thu, 07 Dec 2023 07:34:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701963297; cv=none;
        d=google.com; s=arc-20160816;
        b=xoAAznj7Ezbdj+3y1ap0Fcm6pb56ABXj31BXbrvVsd21BsdJJQEYON4DB+GGjBMSJi
         wtx8W5lytUMsu2MoCfTPrdlr6VgwsYS+t6zpO1iaixiCUgGbgxKAFHi22C77KNjHmY6H
         wS2M2bsdhfHojQ1Q2nn/bId/Q1eyv5qy++MESpaZwRS/KqtL7D4aZTqBoJx6EN2AfZBj
         S3zASn7NRjCUr80B+ZUp0zUPVlXHtX0zu9H7HljodCOWViIN+9q8HgESh1bWjJcxDqEU
         0IpEkIsAibTB5evDfyuxAzIqbq4TEgTnFTwLa/g6YD/zP2bV2FmgusEqchDCTBaATbE9
         CxyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=nxNM9WK2tvtShQbb1K2hHNFEu7MJ8bT3CozvqGIxTXw=;
        fh=ao3wT1IWZtlV76z0noBV4yexrjjBkJG1lnByrAgVCqA=;
        b=LmHtcVT3W9ry4J3gIisTDqpfC+I/9QtkFob1oBPC5WNmw4J7rSkRkS9UkH9VCvUluw
         1ECq4E3aJkS3TqSFHk7cT66W0KfirSLWulhpQXSXwSxkgaYIXDp/4Wj3eGurR+BUSR+Q
         GbPSb0iplM+/z8mW9JFFVILByINIU1gD1BpMSzlXvMH+dkGhFOLz+YH3Z9KVc4GtOsdF
         y8GxHpo7ghaRE7zUgFupMyCn6XL6KphlZfQfIP1dk98b9PRVRwIK3KL0+sHG0lmdxMkJ
         +URyMuu5sxg3paWq81VxukosNHvjuyBD/HFwa833wj7jDH+zf/OfLdkaU04LfWvHF8qt
         DZOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20230601.gappssmtp.com header.s=20230601 header.b=r65AmKvP;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id m19-20020a056870195300b001fb34066b5asi7075oak.2.2023.12.07.07.34.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Dec 2023 07:34:57 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-5c6839373f8so786798a12.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Dec 2023 07:34:57 -0800 (PST)
X-Received: by 2002:a17:90b:30d7:b0:286:f3d8:de2a with SMTP id hi23-20020a17090b30d700b00286f3d8de2amr5477031pjb.45.1701963296891;
        Thu, 07 Dec 2023 07:34:56 -0800 (PST)
Received: from localhost ([12.44.203.122])
        by smtp.gmail.com with ESMTPSA id ok6-20020a17090b1d4600b00286573fc6e5sm24874pjb.4.2023.12.07.07.34.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Dec 2023 07:34:55 -0800 (PST)
Date: Thu, 07 Dec 2023 07:34:55 -0800 (PST)
Subject: Re: [PATCH 0/5] riscv: Use READ_ONCE()/WRITE_ONCE() for pte accesses
In-Reply-To: <20231002151031.110551-1-alexghiti@rivosinc.com>
CC: ryan.roberts@arm.com, glider@google.com, elver@google.com, dvyukov@google.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, anup@brainfault.org, atishp@atishpatra.org,
  Ard Biesheuvel <ardb@kernel.org>, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, vincenzo.frascino@arm.com,
  kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kvm@vger.kernel.org, kvm-riscv@lists.infradead.org, linux-efi@vger.kernel.org, linux-mm@kvack.org,
  alexghiti@rivosinc.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexghiti@rivosinc.com
Message-ID: <mhng-079ed07b-4a53-4d32-9821-768bbb34fe58@palmer-ri-x1c9a>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20230601.gappssmtp.com header.s=20230601
 header.b=r65AmKvP;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Mon, 02 Oct 2023 08:10:26 PDT (-0700), alexghiti@rivosinc.com wrote:
> This series is a follow-up for riscv of a recent series from Ryan [1] which
> converts all direct dereferences of pte_t into a ptet_get() access.
>
> The goal here for riscv is to use READ_ONCE()/WRITE_ONCE() for all page
> table entries accesses to avoid any compiler transformation when the
> hardware can concurrently modify the page tables entries (A/D bits for
> example).
>
> I went a bit further and added pud/p4d/pgd_get() helpers as such concurrent
> modifications can happen too at those levels.
>
> [1] https://lore.kernel.org/all/20230612151545.3317766-1-ryan.roberts@arm.com/
>
> Alexandre Ghiti (5):
>   riscv: Use WRITE_ONCE() when setting page table entries
>   mm: Introduce pudp/p4dp/pgdp_get() functions
>   riscv: mm: Only compile pgtable.c if MMU
>   riscv: Suffix all page table entry pointers with 'p'
>   riscv: Use accessors to page table entries instead of direct
>     dereference
>
>  arch/riscv/include/asm/kfence.h     |   6 +-
>  arch/riscv/include/asm/kvm_host.h   |   2 +-
>  arch/riscv/include/asm/pgalloc.h    |  86 ++++++++++----------
>  arch/riscv/include/asm/pgtable-64.h |  26 +++---
>  arch/riscv/include/asm/pgtable.h    |  33 ++------
>  arch/riscv/kernel/efi.c             |   2 +-
>  arch/riscv/kvm/mmu.c                |  44 +++++-----
>  arch/riscv/mm/Makefile              |   3 +-
>  arch/riscv/mm/fault.c               |  38 ++++-----
>  arch/riscv/mm/hugetlbpage.c         |  80 +++++++++----------
>  arch/riscv/mm/init.c                |  30 +++----
>  arch/riscv/mm/kasan_init.c          | 119 ++++++++++++++--------------
>  arch/riscv/mm/pageattr.c            |  74 +++++++++--------
>  arch/riscv/mm/pgtable.c             |  71 +++++++++++------
>  include/linux/pgtable.h             |  21 +++++
>  15 files changed, 334 insertions(+), 301 deletions(-)

This has some build failures, I was just talking to Alex and he's going 
to fix them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-079ed07b-4a53-4d32-9821-768bbb34fe58%40palmer-ri-x1c9a.
