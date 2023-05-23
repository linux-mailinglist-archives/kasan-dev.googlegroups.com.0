Return-Path: <kasan-dev+bncBD52JJ7JXILRBJEYWCRQMGQEYVDQGMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D6FA70CFAD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:43:18 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1ae40139967sf65953745ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:43:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684802596; cv=pass;
        d=google.com; s=arc-20160816;
        b=TE7BjTgr6KxYSKPLBj5Wt9VlaUEQfDagKR/KydatD7u7pdYBQmls2eREZUYiWeDoUl
         MJFeOPyIPrcXJeH4iP2Wjycie98TeefqD0n5Eo1hnTKztFlQy2KUOtN1Hp5C1CuaK1P1
         MPkEmVhqW1tPfUckTavffvK8Op8iLNdZYlhFuVwMpXnuzuM7mzCzr7r8ThMSVI0rO6KC
         ZfbpM690dLPH+U4f2wQodCkwxDEVJFpbajARN0PEspDU1rq2EQgaeEcAxZ2bfh36yzNM
         7izS1+2AseZ2Q+BJ+OgCUx30aCI5bpukt3Ii8gqWffInF7NMhcnUFnsgV/c/4ccJUX1l
         XRRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=g3n58Q/IFPw4aN7e9yCPUpJxrhpt9CdZSwPsmzwseeM=;
        b=LnTNoypmM+UXuAW3od+WS7Tby8t7p/Vcrm6H4ipX9v0SN7mj9IMPQn6Krazq9pku7+
         5tveNmQYkl2wUSI4wtc59PHOGY1s7Qr4WQRBbmM0ntfApfrOL6RDnF5mxN+t1PV1v9Fc
         NJxSQoCOa9KY42Niu29nFErrg5UJd7FJmQZrpNrQvFOvfqzCOOoEkTOUdZirTXXOWo6i
         QYrC7Y4voMxDVss62k5NqePaMViqf1lMpgzLDtxxQ8hqMpxSzECwX2zXA8HYvPIz8U13
         XWn6gmch/iSQyi/h7wkfEsZQqiljMFgSThzrejpaGM4iyQJi3p6NQc0ZrCBjf0lpjm7J
         yoiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=JF9VmGvn;
       spf=pass (google.com: domain of 3igxszamkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3IgxsZAMKCRUAxx19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684802596; x=1687394596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g3n58Q/IFPw4aN7e9yCPUpJxrhpt9CdZSwPsmzwseeM=;
        b=DdwRsVC1r0fZvI966ApgCpGFAvQb1tucCBIt40As5NCC81HMt9uHFZsvML8iIvKim9
         7ZOxfG38HuF5UTXKO+LUQKXvuI2UfbZWqXUcmO+nD+od5/Pb55qUBsCte/3RqknlkkVg
         T8D7dG5vd3CimQu3ly6cUtoQQBBb6UqxsO0U5cUu+jGqO7rY+O0z6NWu/rloJAxC5dj0
         zC/eNYujMhMYfPJ1sSw1WurdcGgH3Psp9ufDnqcfNZnOlMkqTq0Qi6U/Yo+w5h58U1GO
         0MCgkcrMQx+zBpTAlGjFshtJTE1mqQnWdzGyZHViQv6kBn/XpthxzXcgpvNBpiDoVGL5
         ioRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684802596; x=1687394596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=g3n58Q/IFPw4aN7e9yCPUpJxrhpt9CdZSwPsmzwseeM=;
        b=lYONSgiJ6JEJFl4TT7V/gmrMhHdOOFaURATziiKjFZWwviIappXOZ8haiwbqqPwYaz
         witrn0vBLyovemVLv+/goS1KxNDP6RzrhnbETtzfLl8dpO0+7l7opgzWU++MZfzQHCXH
         t34C1Hq9w2/ydz6kSn02eauC1liBgyiOdanLQQkke+PV2BJNsnxNSWhUef4+WKgeqbVg
         /jtkiXlwW6a07sQyS5mDbS9kbCRRu0mz5SOjOIsrCOhHHLvC/uILKYWjTgJR7B27J351
         n5MDpTQplo2RYR+MQPgt1ZkL8d86eIslet9mckMYvWfgiG+XOi6SwR2oKVqkdx7iGs1S
         GK6w==
X-Gm-Message-State: AC+VfDzzjO6Q230f6AD4ieH6UzgWoXwkSqxiN7Rewv5WjSFQan2CQ0K4
	StT6VCheEIlm+u5KmujTf+U=
X-Google-Smtp-Source: ACHHUZ511P3Oqr9ZI9pkrPP4k5bjxJbUoyFGXIwldDtpmAmX2lp5S1tiNEi0KdBNPaEAtPIgqA1TnA==
X-Received: by 2002:a17:903:70d:b0:1ac:618a:6d46 with SMTP id kk13-20020a170903070d00b001ac618a6d46mr2860281plb.3.1684802596418;
        Mon, 22 May 2023 17:43:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c8f:b0:255:54c5:7e7b with SMTP id
 pv15-20020a17090b3c8f00b0025554c57e7bls1974886pjb.0.-pod-prod-01-us; Mon, 22
 May 2023 17:43:15 -0700 (PDT)
X-Received: by 2002:a17:90a:6506:b0:24e:4c8:3ae5 with SMTP id i6-20020a17090a650600b0024e04c83ae5mr13058665pjj.28.1684802595617;
        Mon, 22 May 2023 17:43:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684802595; cv=none;
        d=google.com; s=arc-20160816;
        b=hqLuWgrXgzB0CvCd7ZDQ2mXCWN9jTizt2QOR0dhBsT8WMfjA/+oXSCMt7ZfDHTSrIw
         NoKxLWq4Z7e23bu97stRHW9A3oZ+qaBt6XcHvO1Wf9q+LscxmCARKS/iSQX8yoeQuNIL
         38mMhZQ8vda5fKDToOMvGo5S1FklIbVuS9Un7mQm+qgoSVdPikCJGU4yRFTEOSXNag3T
         hq9222HVZpepwoA+ISF60RxAcbnx/JHhgzWAsDaFNONSc3xx16M00Ic5p8o7GbDid3MJ
         R38VryA6xq6EVmlE4NQWPkssG2Sqvr151cxj6AbsKJFn6c87f0YMkGztcA0EG4znYnDT
         7H7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=SK35moxCE6AhlCZl4FimQ53XrewZjdQKUPUW9jfTNhI=;
        b=vij7tRteh0ddD+H+sZxAZ0e6iYb+t0QEeWSTCII8n66X4VJUnveZIaOh3UlGWVR67E
         sjSgDoKUYAv9edqkzdGX8gk0y1f93y6LsgJQ/5hGjrpBmdtATuCsVOhRkOU598nEc5kJ
         cDkffh2fPlUKhCJystgXillRCUWZljpJx1u7YmuSedr9hXPsrXtDDb53t/ypZBipcTh5
         ocXvjDTWM7ynLwECHL42eb0Zkx69zcIYLyCVPf4xkSEfhoyO0LeybAnyOR2beiJDEHNs
         RBTcVKrKgdiFyrTvtk++xycLD3QkFXwHje0jyt/JOltIP6/tMKImyzWx6HmYip206sXK
         sqZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=JF9VmGvn;
       spf=pass (google.com: domain of 3igxszamkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3IgxsZAMKCRUAxx19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id nb2-20020a17090b35c200b0025548f2c17fsi46222pjb.2.2023.05.22.17.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 17:43:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3igxszamkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-564f529a663so19535157b3.1
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 17:43:15 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:3d33:90fe:6f02:afdd])
 (user=pcc job=sendgmr) by 2002:a81:e508:0:b0:552:b607:634b with SMTP id
 s8-20020a81e508000000b00552b607634bmr7917763ywl.4.1684802594841; Mon, 22 May
 2023 17:43:14 -0700 (PDT)
Date: Mon, 22 May 2023 17:43:07 -0700
Message-Id: <20230523004312.1807357-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.1.698.g37aff9b760-goog
Subject: [PATCH v4 0/3] mm: Fix bug affecting swapping in MTE tagged pages
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=JF9VmGvn;       spf=pass
 (google.com: domain of 3igxszamkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3IgxsZAMKCRUAxx19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

This patch series reworks the logic that handles swapping in page
metadata to fix a reported bug [1] where metadata can sometimes not
be swapped in correctly after commit c145e0b47c77 ("mm: streamline COW
logic in do_swap_page()").

- Patch 1 fixes the bug itself, but still requires architectures
  to restore metadata in both arch_swap_restore() and set_pte_at().

- Patch 2 makes it so that architectures only need to restore metadata
  in arch_swap_restore().

- Patch 3 changes arm64 to remove support for restoring metadata
  in set_pte_at().

[1] https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/

v4:
- Rebased onto v6.4-rc3
- Reverted change to arch/arm64/mm/mteswap.c; this change was not
  valid because swapcache pages can have arch_swap_restore() called
  on them multiple times

v3:
- Added patch to call arch_swap_restore() from unuse_pte()
- Rebased onto arm64/for-next/fixes

v2:
- Call arch_swap_restore() directly instead of via arch_do_swap_page()

Peter Collingbourne (3):
  mm: Call arch_swap_restore() from do_swap_page()
  mm: Call arch_swap_restore() from unuse_pte()
  arm64: mte: Simplify swap tag restoration logic

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++----------
 arch/arm64/kernel/mte.c          | 37 ++++++--------------------------
 mm/memory.c                      |  7 ++++++
 mm/swapfile.c                    |  7 ++++++
 5 files changed, 25 insertions(+), 44 deletions(-)

-- 
2.40.1.698.g37aff9b760-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230523004312.1807357-1-pcc%40google.com.
