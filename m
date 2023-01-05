Return-Path: <kasan-dev+bncBAABBU463GOQMGQE3257M3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9380D65E486
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 05:17:24 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id x188-20020a2531c5000000b00716de19d76bsf35787744ybx.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 20:17:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672892243; cv=pass;
        d=google.com; s=arc-20160816;
        b=ydv487R+w4Nk+Y9YvM1UplfAvJ9OVyweZryGeEOywzgqEEc7lgJcldFUu0bkC0AoED
         RlCto/n4qnhThiYtyj/s2J+d1VzCsnA6y5iQ/OimteVwM4x7IrhYYzWKw5+CZWJbDXB1
         NXsgjM5LMLnGRWOfh+fOVrzOoadZoXEbvfkaD8GhLKJFbdmdnLuMuYr7Fsqe8nN66/em
         wJRuuwriIwTN42xPFg6pRMOQg6wR0cY4ygo1Z+TitE6juCrLnt0d8Ks9yFbmAol6TKQu
         F44AUtBe0XJjEWUsfPxep4bLEwvwUKYRZz/S04a4vCkVAGX+PDWaPzUybheGCrmT0h6U
         nlNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=FsEgG3EYeU8DG96ZWul2rU3Mgx0+Q7wO867g+nzuGoo=;
        b=nZ5nlBtY/XMLQQzM/mi7BJV1BA9HLE4z2onmsgdBj282oHgnORwLkgSFY8oUz7in8G
         Kx0dMhmgCyBViEW0UweE7doLeQne3647eKrqdRwr1Epz/aveuzxgGPsaT7aABGbmDVMQ
         2WrTvNC+akLMk9xFHkoVA+aR39SgkVEYj7zFMfCHgCdqzdJWbUsDyTPHTOD1ukzX5duN
         +b5DkKKqfq7JBeerE7gCymR8r/cggEW0TmOmqc2LfRcnwqD3vBBOlTjOZOnxKHfMYGiJ
         IBlR7N6AJczw4NOlZVVz0gH+gDSf8ndgLTp8/afU/vqJO+sngpL/EKoLpz7MrYrXMtwN
         awQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=zp2ap7btoiiow65hultmctjebh3tse7g header.b=DvN1oZol;
       dkim=pass header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b="D/diO4iD";
       spf=pass (google.com: domain of 010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org designates 54.240.8.22 as permitted sender) smtp.mailfrom=010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=FsEgG3EYeU8DG96ZWul2rU3Mgx0+Q7wO867g+nzuGoo=;
        b=fmEeCugZVmMhk8/rG/RGWsnmRLOQhJ6w9/SlRWGPFRnWk0kqpXQRaUFar3ReZYw30p
         Kr+Sb4HKGZcC93OW6TBFWB/rk7aZm4tANMUNhotMWiynYydb9Ih54xfMq875Cldkanz+
         dzn3usUYg/QBvE4W+rKJrv8HQNBotjTHlnD92mkqxbViXuxDxhQLiGS8wCQnMGoQrw87
         VVqVBrItrFgY00BN3yWbW11+nqXQAEVZOF9vlK+kf0zrk//RTVE14NaideBoBvyedjkc
         FIXE6+egZ2MxDzoc+XhnVHhLXvwzIipjtfMbiIJ83YROHa9F/Q7JJE7GBwuW66hP1rVD
         iK6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=FsEgG3EYeU8DG96ZWul2rU3Mgx0+Q7wO867g+nzuGoo=;
        b=GxiVrwd8GlWuFl7J1RSnFsngReDyRflXbLMnbbOCEzRExexRPSFHBEFAV/c3L/trdk
         agDfWBaM+27SRgKQ88WohLOlK2iFYTT14siS7VnVjdIkDyHqAlRKNnsqqXFTjfSssRHD
         vfzUS1OLREn7MPgIQN44YmtCMEE+6xsJPIhs9Z30DzYYvLPLHLaH4nKdRpublRNQpdEM
         gN2Bz0tAX35pg9zYexufx5Pk2oTratyV+R+XkQw/iqcBekUnIjUgS3FRb9od7Ao+x9OL
         tcnYmIQ27w5NGlVZYYUj62OzwgwYaDXG39yi6sDgX1Zv6ED03nldrHNjuEa/fCkjXbe6
         Z2VA==
X-Gm-Message-State: AFqh2koDEodlOnvlRAMz82YcZklvyggpywf1QKMtY8vwwUxntk908gE1
	vO2VYTpm3kK+MfYOs3yxQFg=
X-Google-Smtp-Source: AMrXdXvg7zppSmsT70hHOw6OUER5A0fosIggJN3RC4CroiH2p88gNDBpBk0PrVPsHBFMZtClLrSkRQ==
X-Received: by 2002:a05:6902:1817:b0:723:be61:1a2c with SMTP id cf23-20020a056902181700b00723be611a2cmr5621907ybb.130.1672892243405;
        Wed, 04 Jan 2023 20:17:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ac8d:0:b0:7b3:5365:a8a5 with SMTP id x13-20020a25ac8d000000b007b35365a8a5ls1468991ybi.3.-pod-prod-gmail;
 Wed, 04 Jan 2023 20:17:22 -0800 (PST)
X-Received: by 2002:a25:74ca:0:b0:733:4e28:2818 with SMTP id p193-20020a2574ca000000b007334e282818mr48883743ybc.61.1672892242865;
        Wed, 04 Jan 2023 20:17:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672892242; cv=none;
        d=google.com; s=arc-20160816;
        b=0XP1ywvvGnNr03OO3SmoyImS9RWtuY/l/ikv0QLYcReVNGF1abGrl0kfNcgA9xAXXa
         tDBgqgdQEvSmw9OHyQNhHQNwD/rNv/aZ1yh7wXp3n+7j+DiDo3vnVCsfBUVW6ysHksSS
         RBhpjglWMkkxqZ8j93vX2JaOMWcEMzrLToLG9MbF2CrfpO4rqenaQwAefiFAAqGBmcO1
         WSkc5cvP62QXj600vYZe+bDWlaE+4Du+IboihGgVKiq5JQonWAj7ww1B/9Yj1aewQ5SB
         KYKEE72C0TqHcbCnA0IYzD9A2ZCX+L/HI7BXh/zJwRxRhNBvZY/p4C9dUxG54rhINRmB
         9cOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=d6FDebMWjBtfyK0g460tmOAYf0uEUarjYi7SLHlQCJs=;
        b=TIsVs22xBrku5zXfivF4eu/nTfn3/Vy4KzpNIp0KXQUtWg05v4j3/YjdIY+5sOKrJf
         KcMD6tkRx9KZT/QKCTfzAcgb1H+fOzgKO8BT0DP94wemxEQNv31PDs/QQ/7WFVkxY23N
         MDQEzM5WVJ1vygyWM+ZGdNWa86JulsqH6PBmuv0mIhZIe6Sy+GgZ2NmLahtQ39IM/itg
         BkifNESvgutBd+GuuqGnN8U8ksDVgFaAgQfOY2IFTQW0Ob359qT7GJOFWwr3nVUnINt+
         Nn2b9G5wY9DGcRS0NsfdQWoz9L0WLUsRxUNuAsmGyMWTsaw8X4y5nKTHj9g3N0ebtqkc
         i5KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=zp2ap7btoiiow65hultmctjebh3tse7g header.b=DvN1oZol;
       dkim=pass header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b="D/diO4iD";
       spf=pass (google.com: domain of 010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org designates 54.240.8.22 as permitted sender) smtp.mailfrom=010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a8-22.smtp-out.amazonses.com (a8-22.smtp-out.amazonses.com. [54.240.8.22])
        by gmr-mx.google.com with ESMTPS id u5-20020a0deb05000000b004702fc7c59fsi2542240ywe.1.2023.01.04.20.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Jan 2023 20:17:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org designates 54.240.8.22 as permitted sender) client-ip=54.240.8.22;
From: "'Aaron Thompson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>,
	linux-mm@kvack.org
Cc: "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
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
Subject: [PATCH v2 0/1] Pages not released from memblock to the buddy allocator
Date: Thu, 5 Jan 2023 04:17:21 +0000
Message-ID: <010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@email.amazonses.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
References: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Feedback-ID: 1.us-east-1.8/56jQl+KfkRukJqWjlnf+MtEL0x/NchId1fC0q616g=:AmazonSES
X-SES-Outgoing: 2023.01.05-54.240.8.22
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=zp2ap7btoiiow65hultmctjebh3tse7g
 header.b=DvN1oZol;       dkim=pass header.i=@amazonses.com
 header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b="D/diO4iD";       spf=pass
 (google.com: domain of 010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org
 designates 54.240.8.22 as permitted sender) smtp.mailfrom=010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000@ses-us-east-1.bounces.aaront.org;
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

Changelog:
v2:
  - Add comment in memblock_free_late() (suggested by Mike Rapoport)
  - Improve commit message, including an explanation of the x86_64 EFI boot
    issue (suggested by Mike Rapoport and David Rientjes)

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

 mm/memblock.c                     | 8 +++++++-
 tools/testing/memblock/internal.h | 4 ++++
 2 files changed, 11 insertions(+), 1 deletion(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010001858025d78c-8d8b175b-8d52-4bc1-9c93-311868a527a2-000000%40email.amazonses.com.
