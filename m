Return-Path: <kasan-dev+bncBAABBJO42SOQMGQERHKV65Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05ECA65CDC5
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 08:43:35 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id k7-20020ac84747000000b003a87ca26200sf11425865qtp.6
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 23:43:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672818213; cv=pass;
        d=google.com; s=arc-20160816;
        b=AylVZmVwT/UW6ZmvPgDxKahJw+4kgqGofPnNLUodFRpS7hfeskLGoRUdVujkYXbhPw
         +H4KpUYV8I3J21JRTyEtBKT3f4vB/rsqWbb3KAEMO30SJLdE+rGMqfoR9pT/bVnMAo+F
         +xSLlcyjK+iz+JfxZqwzor2/0pzM2rGtzqk1eGIpQRayF/pMfHM6nkncQ4As98iIiRz6
         uVsFDYnXP+T0Xfw59g/672qG0HEMPXOWvgwxd/sfzwv+WlsUfkN7rYKkFVBQuKNOLZNM
         18gjBkTUdzU0vSoA7T00oKO3X/Eoy8wHbwq4sEh+lHDhfPNEqPiROpymaFhUp6yYlt2E
         ohsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:mime-version
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=W6wNBDeDckfjmLlMih6AyxCwLAfDJlKvHDFgDA/jVic=;
        b=A+NmUmf7yyM8M8Ytm1Qpdn+gyq7dfeBiRN34QVv2pAMm+ev3kpiM8uqL0fRcgWepcu
         h0TphxP1okNu9T9knwO2bZLwXsR5v62UEBdj/11OcOmEINA/uXk1RiifPTCcmUXMSIYa
         UfwtA7g6DLOs7neESCpuuV1w8dRbgUKFm+Nmt1VOkTXhAdcZie0QCqIrqJNtpHkTYVeR
         26qpO77RN9fCe6bqdsKrezNoRdgStZfIwInDxX8yw+mbfNpof34fvTX7YvITxcjlu45c
         XeHcENFP9mq1gWNiZh+sSUtl63j3nqlPkw/A9LGbNQIHHwoKrES8RLkfk03U2Kn4BW1F
         ZIUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=QOWpEF16;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Zpn6P8cO;
       spf=pass (google.com: domain of 010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.53 as permitted sender) smtp.mailfrom=010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=W6wNBDeDckfjmLlMih6AyxCwLAfDJlKvHDFgDA/jVic=;
        b=QNYo5cJRfmI91f7IisRLKI/zOTb87m6pbRsh8+q9kQq7gN5Y0kN8tN4XF/n/hy+E0I
         yYDl2vZ30TsWKzZLyP9cGFe6RgXA2txdG2w7YKunpg8XngSfsMzgv3HEIZMSx86nYDke
         zOFaiAmSZbTrKRYjhS9htzlaWYskHEaWgn0d9+RzAGmPgtyzTZ81loY/Vafq/FHbwb3i
         VAU74Jq0erHySrordPKQ4Hmvc8oNKQom/3O2w2wP6AdUAD3pYSGw1EGPJ03++skTK50B
         QZvWDWJ1YT2hBkiSOq77I28vhR3+4kEFaLUZQuMiM5hHdWJ9uyLKOWJadPSC2/T2if00
         t56w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:message-id:date:subject:cc:to:from:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W6wNBDeDckfjmLlMih6AyxCwLAfDJlKvHDFgDA/jVic=;
        b=lW765hcXnR8Ar30JOrYPD9F+d1t+v0pCuxnYIe2qprh7V1+PIZtUPeHKTcZXDctm6m
         87M/1nP6u4kyeJdG3e3i++JQfGMluQNdH5lxTGIzotWkPHLvBv39tAYQH4Mv3Z6vNnOm
         Vx+R0PpUImSMZvTa1BSiqIIQXjiWgMjRHKnzUBt97SBapUAumo76Ns9kg9Urs6faoZ3m
         EIwJ2OhkESsOt8IpqfWymcKgcfJR3faiZpYqfQgtcJylzJiii7O0HgiT1VWvFLHWrcOS
         JPg6kbtvSTW/ysZjlQlnUby3LEnTV8U94dSUAXRZwFcjigufSZiNBwqPd5ech7moj3D2
         Rdcw==
X-Gm-Message-State: AFqh2koPO+wv9Y+pdhWuSeYBxWseqpVVl1SuchvueWlOO9GWybCPEdv3
	yumeAc3PPTSTVsTE0zltpg8=
X-Google-Smtp-Source: AMrXdXvpke+I7ZoZzYK9nlLKsW/BIbZmNOR2dgggLRB3nnysY5K0AfzFO1rKH/5B/II97vJM/1SI3A==
X-Received: by 2002:a37:e118:0:b0:6fe:c5f2:656a with SMTP id c24-20020a37e118000000b006fec5f2656amr2466073qkm.603.1672818213713;
        Tue, 03 Jan 2023 23:43:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:5c92:b0:3a6:9e8c:1506 with SMTP id
 ge18-20020a05622a5c9200b003a69e8c1506ls17598467qtb.4.-pod-prod-gmail; Tue, 03
 Jan 2023 23:43:33 -0800 (PST)
X-Received: by 2002:a05:622a:5145:b0:3a5:fe93:7dd9 with SMTP id ew5-20020a05622a514500b003a5fe937dd9mr55145938qtb.44.1672818213324;
        Tue, 03 Jan 2023 23:43:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672818213; cv=none;
        d=google.com; s=arc-20160816;
        b=VASr5193RaLH11JS5FXf+I3Ralvh16NSK3O1i3zaJvpWdXTBn+SaAsnsPDjzGz36HQ
         5a2ziI1Rs3omd1YzKXGHnEhqgwlrqWYn5gG2+IxkMxmJmV0d7XQFbC85PHqxs26/j/0n
         wnb/rIVuzoYuBDbTrCsArSAQoVlE4DaHawSx/SfswoFI7HNUZz74i7qDn+gYWKER27av
         b49IdHPzMcbg9ss1NRiBIJccdm4jmxQnYB8XaD241oRXHPQFNw+xsvJ14ah1yidtIaFl
         8DVBTSGJb6unTj+NJPWfHwIWn7ZH1bADKCUtSr2nsUOj+KNNQ53sY5oJJ4x1EUVEtKkl
         CK9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=d/kS2qV6jUTi2z7KiqaKiSozpqh0oc2+tu1KAR2pOxA=;
        b=G5VjQK6+z6ee43MX8PvsvwHdkNF/kUfxZpTQo/rn/hs5/T09QfzB4NecofBMP2JhlD
         98jk8Vu0Erlv0W/AWec2cRD5ObpaKW2HNEUnm+8FIC9zgWRi0LcTlKGiD+I4mITtFIYa
         /qdqy70tRCHY8R4btkYejb0d3DbrnKFN/aOnzYtXmoxlYn/zWqQIyYtjp7uzWqF+MskI
         RlI1qz3kMwAf8zUPuL/1uceyCQmUCJrcpYJrQ3Lfp+Cb0L31E+m6TAzgQa6uxKEW2fXn
         LInAP2ddAEoEWSSH5/MUUQfvuiBWNyvKrbpygMyUAQmPH4UOMIbynrcyzdVRUcWW6XR/
         A5uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=QOWpEF16;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Zpn6P8cO;
       spf=pass (google.com: domain of 010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.53 as permitted sender) smtp.mailfrom=010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a27-53.smtp-out.us-west-2.amazonses.com (a27-53.smtp-out.us-west-2.amazonses.com. [54.240.27.53])
        by gmr-mx.google.com with ESMTPS id 19-20020a05620a06d300b006fa04da5987si2090561qky.5.2023.01.03.23.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Jan 2023 23:43:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.53 as permitted sender) client-ip=54.240.27.53;
From: "'Aaron Thompson' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org,
	Mike Rapoport <rppt@kernel.org>
Cc: "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	platform-driver-x86@vger.kernel.org,
	x86@kernel.org,
	Aaron Thompson <dev@aaront.org>
Subject: [PATCH 0/1] Pages not released from memblock to the buddy allocator
Date: Wed, 4 Jan 2023 07:43:31 +0000
Message-ID: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
Feedback-ID: 1.us-west-2.OwdjDcIoZWY+bZWuVZYzryiuW455iyNkDEZFeL97Dng=:AmazonSES
X-SES-Outgoing: 2023.01.04-54.240.27.53
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h
 header.b=QOWpEF16;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Zpn6P8cO;       spf=pass
 (google.com: domain of 010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org
 designates 54.240.27.53 as permitted sender) smtp.mailfrom=010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
X-Original-From: Aaron Thompson <dev@aaront.org>
Reply-To: Aaron Thompson <dev@aaront.org>
Content-Type: text/plain; charset="UTF-8"
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

Hi all,

(I've CC'ed the KMSAN and x86 EFI maintainers as an FYI; the only code change
I'm proposing is in memblock.)

I've run into a case where pages are not released from memblock to the buddy
allocator. If deferred struct page init is enabled, and memblock_free_late() is
called before page_alloc_init_late() has run, and the pages being freed are in
the deferred init range, then the pages are never released. memblock_free_late()
calls memblock_free_pages() which only releases the pages if they are not in the
deferred range. That is correct for free pages because they will be initialized
and released by page_alloc_init_late(), but memblock_free_late() is dealing with
reserved pages. If memblock_free_late() doesn't release those pages, they will
forever be reserved. All reserved pages were initialized by memblock_free_all(),
so I believe the fix is to simply have memblock_free_late() call
__free_pages_core() directly instead of memblock_free_pages().

In addition, there was a recent change (3c20650982609 "init: kmsan: call KMSAN
initialization routines") that added a call to kmsan_memblock_free_pages() in
memblock_free_pages(). It looks to me like it would also be incorrect to make
that call in the memblock_free_late() case, because the KMSAN metadata was
already initialized for all reserved pages by kmsan_init_shadow(), which runs
before memblock_free_all(). Having memblock_free_late() call __free_pages_core()
directly also fixes this issue.

I encountered this issue when I tried to switch some x86_64 VMs I was running
from BIOS boot to EFI boot. The x86 EFI code reserves all EFI boot services
ranges via memblock_reserve() (part of setup_arch()), and it frees them later
via memblock_free_late() (part of efi_enter_virtual_mode()). The EFI
implementation of the VM I was attempting this on, an Amazon EC2 t3.micro
instance, maps north of 170 MB in boot services ranges that happen to fall in
the deferred init range. I certainly noticed when that much memory went missing
on a 1 GB VM.

I've tested the patch on EC2 instances, qemu/KVM VMs with OVMF, and some real
x86_64 EFI systems, and they all look good to me. However, the physical systems
that I have don't actually trigger this issue because they all have more than 4
GB of RAM, so their deferred init range starts above 4 GB (it's always in the
highest zone and ZONE_DMA32 ends at 4 GB) while their EFI boot services mappings
are below 4 GB.

Deferred struct page init can't be enabled on x86_32 so those systems are
unaffected. I haven't found any other code paths that would trigger this issue,
though I can't promise that there aren't any. I did run with this patch on an
arm64 VM as a sanity check, but memblock=debug didn't show any calls to
memblock_free_late() so that system was unaffected as well.

I am guessing that this change should also go the stable kernels but it may not
apply cleanly (__free_pages_core() was __free_pages_boot_core() and
memblock_free_pages() was __free_pages_bootmem() when this issue was first
introduced). I haven't gone through that process before so please let me know if
I can help with that.

This is the end result on an EC2 t3.micro instance booting via EFI:

v6.2-rc2:
  # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
  Node 0, zone      DMA
          spanned  4095
          present  3999
          managed  3840
  Node 0, zone    DMA32
          spanned  246652
          present  245868
          managed  178867

v6.2-rc2 + patch:
  # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
  Node 0, zone      DMA
          spanned  4095
          present  3999
          managed  3840
  Node 0, zone    DMA32
          spanned  246652
          present  245868
          managed  222816


Aaron Thompson (1):
  mm: Always release pages to the buddy allocator in
    memblock_free_late().

 mm/memblock.c                     | 2 +-
 tools/testing/memblock/internal.h | 4 ++++
 2 files changed, 5 insertions(+), 1 deletion(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000%40us-west-2.amazonses.com.
