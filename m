Return-Path: <kasan-dev+bncBAABBMF64KOQMGQEIVA5OFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DA46660970
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 23:22:43 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id e11-20020a63d94b000000b0048988ed9a6csf1585698pgj.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 14:22:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673043761; cv=pass;
        d=google.com; s=arc-20160816;
        b=M6i2Rpq704TxYHeVDpAgEjfhusVx6/NAq/Q64FHADqm3N4eMvGFNSaUx89q8bkQDo3
         ZwZnLC+yIS6NIi0qdN/U+F91+GrgmP/Vy+/viOZhJZGg9jhUOuyXJWHVG/fDBb/D9JhF
         Heni/h0NgcEa9LVWzElxR9xhRK4O/S+Vad+pgR9OZg8EoztgbDUDVOXOUsnL5Ij+3CVG
         9pqdwzm5S2CSa2Y5O47jhWegTDSzgX6zQETeA5RTKwiyYgbn/STadnmP8UxqaZb/nEwv
         5IuVeyByDxMOBXnPYVFNCxeiGt/LKWbhhxsSvb+yekwRkS6UUfxos02NxEkRI0J8+s/7
         Iq2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:mime-version
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+69dSFfKN/HAQXJkwVExvWc1g+wPzBFl12KN/OjPyCI=;
        b=Sp+ER3/ZrK8ho9Qvg7VGShcyuov1iN9WvA+wwq64aSEP37mb9ZtNgw6p7tq+vEcofY
         llvjwa1gE7tFbD0vytOTtsiBNh37xQTO/JdZo2e7Aggdn6vmUOA3k3SRq9LkW9KZ18/f
         pyBlQdXaLq6OIPZacXW8efD/bivQdevmAVyzUeFdcVHC4DFuAEa3MPj9wm1QYG9UwXRw
         WTr5/UQIlkhYLceaM79AcsHh2wtBLQ2sAvsqQTrwQYmpB2tl5xWLevOXPzub4ZPk78gp
         r8bBA4omVpdZReB8LRqzwgnECAUAAc07M3g2A3dvQ8m/h+FPtH9ONq51LOwJHD8Ckv4b
         xLIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=PzJxcT0U;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b="M+/LshSr";
       spf=pass (google.com: domain of 01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.19 as permitted sender) smtp.mailfrom=01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+69dSFfKN/HAQXJkwVExvWc1g+wPzBFl12KN/OjPyCI=;
        b=iZG4zQ/FezWQ18WFDOVSiJgHg3cBeAXrTkITiqVazO3wE3ZAzsR8v84KGWPrcPFsaU
         j2XhTlQkC2fcOKkcTq7P6Uhs12lOCGWhogiLGlk+q+wfEScNAeeH2YbpiHNWibXhYReP
         GPWL3gO0bBlngrPll5rpG14Gyl98FAMTbe9z97yPqRj4DH3Dii8i03bsILUMgbO3k/1G
         Dn5GhUsHafrfKeXY8TyKgm77FOdpRZxca6MGdOekP0bYPsaVICcvhkjOFuzAje68rCvL
         UPoxfysBKDbw58ORqJ/zn+N72J2olVyCYWbe4soDm6fH/fVZuWEjwkatIgbivGquM2Vy
         8RcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:message-id:date:subject:cc:to:from:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+69dSFfKN/HAQXJkwVExvWc1g+wPzBFl12KN/OjPyCI=;
        b=eLJLMLJW5Vu/8x4aKXglMcyoBp1jxqnzjpE0ixLzmRVk18y+/LOQu3VXTx3h9NcECW
         ciqS9zZQ9/LKJpm5RLevXtYPsHiPAm5FP+lNrb4GkgGyvusouQWDrm0O1YHrsXJB9n+H
         1gx0z9xW8deEviLwqQeS29gY0q22FWl7bVWWANsV8gSvd/WGjbNjKYmL/vqo6mknR9p4
         lgHzKP2kkFRxxR9umKBIhf1a/i50GE7utWjrZL3FYGbPQhULREHE9S66KFzPcTxAhQ7D
         n6f/tmCEE4puNgCpjhkUKR7Oacp5jC8aRbaWOYApAg7QTooLWHzBov/vVYBiWBHPdi7j
         lJYA==
X-Gm-Message-State: AFqh2kq88zQlA5Rr3jDvMj9921zE90SrBBUxGcR5tWjkS9zjVV55TpwH
	bvwCzJCGTaNtU444mBrLIJs=
X-Google-Smtp-Source: AMrXdXt3l3uuiZDxMLsHUCNHnklu5oC3B/wskDs9lGN/DLvlucUHdqR/Y5vpIq7ATVD3YwSKifca8Q==
X-Received: by 2002:a62:79c2:0:b0:581:1ca2:3e79 with SMTP id u185-20020a6279c2000000b005811ca23e79mr2782516pfc.6.1673043761078;
        Fri, 06 Jan 2023 14:22:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2693:b0:186:9fc5:6c01 with SMTP id
 jf19-20020a170903269300b001869fc56c01ls426221plb.6.-pod-prod-gmail; Fri, 06
 Jan 2023 14:22:40 -0800 (PST)
X-Received: by 2002:a05:6a20:9585:b0:af:dbe9:4466 with SMTP id iu5-20020a056a20958500b000afdbe94466mr65352943pzb.31.1673043760433;
        Fri, 06 Jan 2023 14:22:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673043760; cv=none;
        d=google.com; s=arc-20160816;
        b=yir3zMrUPpJR0M68wExrALrnyZscPAdnbijP3P+V5LuzjDlNLsNFPwfCWdYM/JpANy
         pGDyZQSKRJSrrpPq7wSbhUyS8Eh09kOKamvcvj+BEwL7/56+ATYKTJ69gu+bV26JxJK8
         gP72ZHG6IXyNWNEXvO/dzqEFU0FHWEYHbylqFVbMH3gxMBJ6abV224HdXT3qlgcyPSCe
         KepamXk+jItFyIP8lckBH21KSHEtmwUxbsK1wILqJ3X0a1ShvKxujZn/TUx5SWnM6RXF
         HMKGfJvoCFqRM28M7sjLABfRjepxC0mmF1FMzhqMzpW1xEc/frYc/goEsg7rSFfBwDBu
         9u2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=nlAYKJhIKQIaJGqJZ7251SFQ9ZUo3QPvvxzqDQ/vCZE=;
        b=fylDvdsm966k7iNcO2tiumw4wZrwEkSMCXs8JEtl5AMLMCsCVraHHTqz7QzvXKu3g5
         aswFcerKdA1BHd+CXIXsC7NTONILn5haam84hgOGLKbXe1JaVTWEgFunMBBZwYo3JU8I
         voYHb4Rf/Ob5z9iQnxQl2CN9SpOfZZvddE5om3xZlXqx/HEIGr88OfDTsvGFYnGNr8Yy
         ZayIoDKwPexKuv/zZ10RfuxS0XeZHAfWDL6D3GzNx2pGf4gwOgx0FMWUj778oTB5Xskc
         fK0t8+33/UUPp4cHprf9xRWJiqKEHA0XudyCqzce2LARZYUBkvn8wewQbOFzyCPxZdHL
         bngg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=PzJxcT0U;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b="M+/LshSr";
       spf=pass (google.com: domain of 01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.19 as permitted sender) smtp.mailfrom=01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a27-19.smtp-out.us-west-2.amazonses.com (a27-19.smtp-out.us-west-2.amazonses.com. [54.240.27.19])
        by gmr-mx.google.com with ESMTPS id f9-20020a639c09000000b00478b9f9f81dsi177454pge.0.2023.01.06.14.22.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Jan 2023 14:22:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.19 as permitted sender) client-ip=54.240.27.19;
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
Subject: [PATCH v3 0/1] Pages not released from memblock to the buddy allocator
Date: Fri, 6 Jan 2023 22:22:39 +0000
Message-ID: <01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@us-west-2.amazonses.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
Feedback-ID: 1.us-west-2.OwdjDcIoZWY+bZWuVZYzryiuW455iyNkDEZFeL97Dng=:AmazonSES
X-SES-Outgoing: 2023.01.06-54.240.27.19
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h
 header.b=PzJxcT0U;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b="M+/LshSr";       spf=pass
 (google.com: domain of 01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org
 designates 54.240.27.19 as permitted sender) smtp.mailfrom=01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000@ses-us-west-2.bounces.aaront.org;
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
v3:
  - Include the difference of managed pages in the commit message (suggested by
    Ingo Molnar)

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010185892dd125-7738e4af-55c6-43b6-9cd9-d52dfea959d9-000000%40us-west-2.amazonses.com.
