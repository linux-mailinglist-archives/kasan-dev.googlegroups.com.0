Return-Path: <kasan-dev+bncBDDL3KWR4EBRBC6DRWKQMGQEDAF4NOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id AFA26546950
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 17:21:48 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-31384ac6813sf57373947b3.8
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 08:21:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654874507; cv=pass;
        d=google.com; s=arc-20160816;
        b=uIvLaz0Y7sVGiB3kP6jJUaoJ9sKUcDqT47BKYgQA44AeVSg1fj4xBJwm7rUaIStPy3
         XMjTI0ICYFrs4ulTNr/4HnCrkwaczrbVtaMxXU0Ow9xlPlnpXa9ngxm+/qDjTH+mfHsd
         f3VAHyuwvPA7726WSBoh8+FO8enTPoxrWuy1cnO/D19RgG49LVmR0EDvgD8E4ETIfzcE
         6ftS1fiCEWxMU2Hu6xQkhWZnUUvbgu521+eEnwkP/QSbq/WWKbilwuVB/s8Vxzff+7xI
         QBaVgbIWo+grTLj7ibQFhWgs6Wdxy8id25eywfZJKxBYzhMtgaWT/GAlp9XKpZwZ0F4H
         V8XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BXe08XKhO8dsTWRcjaNVej1QJFlcoZpRUnEXwRfQYyo=;
        b=ORq+jHIOHX4xDAzwUacoS41IlT1ySKhmSQk9kPaOVf59n+7nLwwu0XBcf3AfHe33mK
         T77nwddXz/hqsT3W9N70Q3jSs/Gasu5ghsLMj50EKArxRZoe1YVqL7ookPdPvvfMh7HA
         LsaYWZm4u8huynRcrjB535yXTO06RTLi6gh8MYG5xpaRm5LZxvohpB16682O2fYQ+j/E
         DCFqGbcjUx6u6gjbik+Ajz+hAh5096CvZJU7EdTjTBB8A+L5T8G+N1Ex9H75CHWRKa7n
         TSZA+Zu1lfb2wtsTgXHbIlR1Eke079Ydu/UPHBLISQkSFarcV7dLG3sGOngs5GALtR+V
         0OKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BXe08XKhO8dsTWRcjaNVej1QJFlcoZpRUnEXwRfQYyo=;
        b=Lmk97jwxfEgeA8GE30RByQlapnhy0/nw5/EIHewT6+3nAQFEDHbHlEakmGFscE1Z5x
         R45PbKrPdRAmNs/WTjghDgv0XRZFU4X1rs0p91Z7W6k0XVRDcSNTWrfZxWU2HjfO3eDR
         V0+G9cXPFc9NoIBLDZTBpFn+/kCd5X6wqMCB15K7Kr7ZZO+2TUnwwUQSMiOblUVwg97I
         /QWB4HKGbooxcievS5tWmx5tKv/+A0tlaJbie5mtu7mHKpGdC4YcBt9hKIdpkhhQaW7P
         J5psKoKgUvZLFeOKUhyx9VTtyETvGBBuUu8zxTyxtZLAdTI8zo0giTNheDWAgkem7MbX
         xPYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BXe08XKhO8dsTWRcjaNVej1QJFlcoZpRUnEXwRfQYyo=;
        b=zkZdqO5yIrCioustxvSxCfSFDTSlzmWtfG67ErCkOXkzbazZtgtwSqIwWmOqhNFu2R
         FZ16mEsl1/nFLjk2D1MwBtMEssTkvnlBVnRAt2fRruoFF76W2lUU62L0xHrpw70mpr5L
         kKnU1fpNUn5+9qadmQHQTfwbBGkhj/zb1AgWeNV3gKO4Otsj+MrYr2SjlIy/E/mALvIK
         dEKPABcks+AQ8sm19q47r8oADssm2cBNEnd8ewXPfqZRQq5udz8j2yYL9OYk2z5+A+vk
         k329wykcNxRS70mzV6memDdhI3ODdyVDlx27shr6PZH9mHOZN+DkFNDamm7z9QxVw8w8
         VWYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ve3/rgYKzw6R0kKsR/AnUPByc7nNrz/mGkB74w+KA817sAflT
	ItBiCNwrEdjTtg5gNrEvQsQ=
X-Google-Smtp-Source: ABdhPJxeAfE9d/V3mCDmnbdgON8mNhHNnu01XEfXZO2QjeTDiO4PydmcD036zW2oi5JsEWyxNFxtig==
X-Received: by 2002:a0d:ea97:0:b0:30c:8771:5096 with SMTP id t145-20020a0dea97000000b0030c87715096mr50901107ywe.304.1654874507474;
        Fri, 10 Jun 2022 08:21:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:721:b0:64a:b88e:63c8 with SMTP id
 l1-20020a056902072100b0064ab88e63c8ls5642017ybt.11.gmail; Fri, 10 Jun 2022
 08:21:46 -0700 (PDT)
X-Received: by 2002:a25:c88:0:b0:65c:dbee:a969 with SMTP id 130-20020a250c88000000b0065cdbeea969mr46955652ybm.636.1654874506796;
        Fri, 10 Jun 2022 08:21:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654874506; cv=none;
        d=google.com; s=arc-20160816;
        b=lit0OtvOn0b7piwMzf///9+g2VTLN7qEgnz5Q/zx5pPGwnB9ctp9tv2yhA2tfXaCol
         WI0Agwm6Yhkzvq2cq3JjC98MAeDHk1G4rQwDCV4bwIhzDgvKyfLGH+e171IR3OUZGXVF
         snxOkSeLaGAUYNoPGfS5kcrmDqDOrX2/q5sXtsBsWS8PQB088zYkPIHswi9un2nRn+RP
         Xq/9pTvHmNYoqv4cZFHPVoQdLdaQKYbh8ZVS6urqPyYZR0kOSZNLMRuLRXWeMe/xqDd7
         RN0k4PAPbTWqUKAFFaS2T9p9v36LSC8XsX5O70UAowje8cIpa4Dbb56qP4cUZdcFMX7v
         jwlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=vYiGl4x+g5MzRl+C860KyvPiF4ftEEAJjboNUqqcGL0=;
        b=SYgYBtM/4kc3LeAVkFUiYdyB2YRE39HR0VEMWnW0ha0tfKz1Bm/XwDx5qYmBCjFU0m
         tiMpA/CubfzPZA9J1iD8nuY5FBks3aCKGBdAihSreTss6FcleMlwlzSffZOpkUoQ1En9
         GphcerfRZLVL+tG1/070IkmYrBgPf/9huiK4x075QmNz8gem++Q44wojUXphjG/tt60p
         e8cr7XbBRd9lXbbr6OtiixYCoCqgTYDng56xzK+I7NnobSO1LuOPd8gCTZ/SUGvRoaXd
         zehuADta1j7QwlkZvHPbJCCmwWM+qHvbehCMjQoZ5SxtiiT6VJhkd4x0aqePvjyFhwtn
         b29A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 15-20020a81130f000000b0030c468b7bd1si2297896ywt.1.2022.06.10.08.21.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jun 2022 08:21:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 662DE61F18;
	Fri, 10 Jun 2022 15:21:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E3BE8C34114;
	Fri, 10 Jun 2022 15:21:43 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and page->flags
Date: Fri, 10 Jun 2022 16:21:37 +0100
Message-Id: <20220610152141.2148929-1-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Hi,

That's a second attempt on fixing the race race between setting the
allocation (in-memory) tags in a page and the corresponding logical tag
in page->flags. Initial version here:

https://lore.kernel.org/r/20220517180945.756303-1-catalin.marinas@arm.com

This new series does not introduce any new GFP flags but instead always
skips unpoisoning of the user pages (we already skip the poisoning on
free). Any unpoisoned page will have the page->flags tag reset.

For the background:

On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
kasan_unpoison_pages() sets a random tag and saves it in page->flags so
that page_to_virt() re-creates the correct tagged pointer. We need to
ensure that the in-memory tags are visible before setting the
page->flags:

P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
  Wtags=x                         Rflags=x
    |                               |
    | DMB                           | address dependency
    V                               V
  Wflags=x                        Rtags=x

The first patch changes the order of page unpoisoning with the tag
storing in page->flags. page_kasan_tag_set() has the right barriers
through try_cmpxchg().

If a page is mapped in user-space with PROT_MTE, the architecture code
will set the allocation tag to 0 and a subsequent page_to_virt()
dereference will fault. We currently try to fix this by resetting the
tag in page->flags so that it is 0xff (match-all, not faulting).
However, setting the tags and flags can race with another CPU reading
the flags (page_to_virt()) and barriers can't help, e.g.:

P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
                                  Rflags!=0xff
  Wflags=0xff
  DMB (doesn't help)
  Wtags=0
                                  Rtags=0   // fault

Since clearing the flags in the arch code doesn't work, to do this at
page allocation time when __GFP_SKIP_KASAN_UNPOISON is passed.

Thanks.

Catalin Marinas (4):
  mm: kasan: Ensure the tags are visible before the tag in page->flags
  mm: kasan: Skip unpoisoning of user pages
  mm: kasan: Skip page unpoisoning only if __GFP_SKIP_KASAN_UNPOISON
  arm64: kasan: Revert "arm64: mte: reset the page tag in page->flags"

 arch/arm64/kernel/hibernate.c |  5 -----
 arch/arm64/kernel/mte.c       |  9 ---------
 arch/arm64/mm/copypage.c      |  9 ---------
 arch/arm64/mm/fault.c         |  1 -
 arch/arm64/mm/mteswap.c       |  9 ---------
 include/linux/gfp.h           |  2 +-
 mm/kasan/common.c             |  3 ++-
 mm/page_alloc.c               | 19 ++++++++++---------
 8 files changed, 13 insertions(+), 44 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220610152141.2148929-1-catalin.marinas%40arm.com.
