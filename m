Return-Path: <kasan-dev+bncBD52JJ7JXILRBJHUSCRQMGQESAUSZ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FB1D705D0B
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 04:21:26 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-76ce93a10f3sf20772439f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 19:21:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684290085; cv=pass;
        d=google.com; s=arc-20160816;
        b=sUgC1xEH8mrZbnFWNpL9w4gLqD/YvCOYOD8rfIOKpx0LOWkWOjrDljgengMaHhtPT/
         C7RQtvUURs0aJ4Tr2oOeQahc90/xX6Y6TLgiahCX55VGW28NC/fDi36AI8bnJiSl9Pr7
         cojrd3/e2RzNo7UEF/dop1BxG9dfOI5nekY+PbqOhFAN91OVpH8elaEHYh39rh36Oilq
         H2trORvBBJRYleomzS8vaXmAK56gDI4G6HC3/tnqLaLA/DE9Ya2YKUFIpSHC0IF2Tnra
         wOTOg+nzS9O55NaiAN1Uo6BIzhebP2/wbDlfPh3qNEo2yaY5LFqiWh2QCYK+lIJQiQrW
         3JIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=0ExG9rugq71ALXby2NrWO3JhO2SmI2x2dm+SWnUY1qU=;
        b=Bxl3akBjKbMMEB4RBXnTeK3XsVF77NYhlAPzNfSgSBz7pCVhvWnG3DhqsaUJrwIYkh
         zWch+Kn1zBsIp8HN0VzLhqvk5EphoNKm/qW6rewxEd/BzaYsjOu2OA1cD9QQjKE3gbKI
         DvPNWAX4fwGJJS1sjLB/5ms61MDdHtT2W6wOZib7vYGhDBjlGc4IFV4ViNI2hvvVSNoR
         9pftDKpm6gFZ/mbzX8LYuEuLXYZRk0268kyKAXyCLeccgB5VrmA9Fzqf4gZoHddly3WH
         UyxCbJjdTOmvqGGe4eQ9RPXkLzmpFXASrlT7mb8FcX0tEKA85gHJjQXmabsXQf6+bSQc
         AJew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=KUAjUFSP;
       spf=pass (google.com: domain of 3izpkzamkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3IzpkZAMKCVI9ww08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684290085; x=1686882085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0ExG9rugq71ALXby2NrWO3JhO2SmI2x2dm+SWnUY1qU=;
        b=NEmSojSobLtEXKWBRwk8jtAmFTJTVcobN0zwF4VniBDvHZd5KJq33082f+UD2KhtJt
         35krU7K6xxyBWUsD8fZPEd6jnXmabFzr4a5HZwWZZHo0z97nI5EvdnxlUGh+UJ1CEpCv
         ln5mEkRMXFfEyoocT9ye3eUcBly9urinErUiwn0D8FISybyhAXJdyAYm3jdcHcMQfbwa
         hym/u2YNWb0H66eHFH1og8Hhf9buHB8PbG+7/CigrSl9f4OpJZweO9src8zXZe8iRWAa
         428gN+tqDzotwMOYwzNIwF2w+L7LJCtaVRk1Wj2TQjOjGQHr42ydr03g2ifO3tzLPuqY
         7bRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684290085; x=1686882085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0ExG9rugq71ALXby2NrWO3JhO2SmI2x2dm+SWnUY1qU=;
        b=SbsqYb3PIwGmRxN2XaoPel9E/i1/wgUCb93rgJmKgz0AuVh7RVC6ubLxCGxES/yQqR
         RX3Wu/gn3HCyVSXUQwn+Zz/GYjsDl5t4D/H4S9prOd0WfL1LItSdgS+cJCE3fZyX32PM
         DYA2DThsTfPl+k48JZh6R8Yf/M4x3JKSSiXdPfsJ9iSSCd2q1Y9DjtfdGwxKNLdP0qub
         YUVG/6B6fsKOg76oxI5EKGsPLmHycGwOCA0Vr2UzWa1P7jzKAtiLjIEXtWeDKNE/3qQC
         WdOlKUgBZ/TY3pBfsSpTmeRBQs57IyCfdRymzcPI3EENJNVGTQNYjMjxPKD7VB/nhAhp
         av6Q==
X-Gm-Message-State: AC+VfDwWp0U3+NNx+WEfVRWGqsvN3T12yrTmy2PPuLNWgn55x1Q7uJcD
	ARS+S3VEYV9BfrXWFaWRTFw=
X-Google-Smtp-Source: ACHHUZ6oLkgKATHrL4/59D0EbbZv+fYSmfFe0KUYpvtoEKFvCpjadqcKJ1bIWDA4UVrtZBRmInghjg==
X-Received: by 2002:a05:6638:2150:b0:40f:9ab9:c438 with SMTP id z16-20020a056638215000b0040f9ab9c438mr13172221jaj.3.1684290084275;
        Tue, 16 May 2023 19:21:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8e4e:0:b0:337:7bcb:d328 with SMTP id k14-20020a928e4e000000b003377bcbd328ls269120ilh.1.-pod-prod-02-us;
 Tue, 16 May 2023 19:21:23 -0700 (PDT)
X-Received: by 2002:a92:dd01:0:b0:32c:88d9:af1d with SMTP id n1-20020a92dd01000000b0032c88d9af1dmr941154ilm.13.1684290083771;
        Tue, 16 May 2023 19:21:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684290083; cv=none;
        d=google.com; s=arc-20160816;
        b=x39BR8AyojWt5MPIeNPpL707nklcc95dIXpOX9EpexV87H3G5269KGmzcPdnL6i7dO
         Gj2Vck1XzD7P01CwLxll+xEQyujSQs+pz8bQm+fe2fPTvEfII7gEBEWDdPxmq4aYzujn
         IzPvk/tN4KaO8SpY9GM32k9xIwURgvr0Dg9WlmvS2K8HkMGP8LXJBk6G3IjfAvJMSINa
         6vKXBmTHr/z0QsRXHIUZp7Xj2Dk0VcT/NRHXPU8TRQIRYHg7ILXsAyXZz/2kP8AMCcXf
         u1n9eb7NAFV+wCa4L/6FWul/i3nZ7u+jaPGub7nyVF3bHgEFzVWzCrC74s5hFE3woTTi
         yOHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DbvIotRGfeUI08jv8AEiwlw+JO4JY4xCfZlRx6U3EOo=;
        b=tm/zhGsrft4sjJlv7lotLbk1QgmirtBIwg90XCFNr2K+9kS0S0GDWL5lsBZZiL0t6j
         N3dWcCnkzMqaERphmwfA8Hs/MGv6ZGxSryHO4JdYACCq0fLFmrRTadIjLks8H3e+ESYt
         NCHreB+3FxoET9xMoGXnSD/F0uOKFAvSCtVxUc+Db1wHk3p/OBJ+ijJaSzC77i5EIdxg
         vbIv38cTU+oblwDqgMd2fNDcx1B1u/5e1n8L8A/jaLsrmpq1pfjb7P+zWtgSnM/iYooA
         gsgdyFlXEaXhmWq0fs/KqJCRtoxLucXCDYhR0DUGNz2GcWxyEocDMPHdbdlsRPeAeLB8
         14Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=KUAjUFSP;
       spf=pass (google.com: domain of 3izpkzamkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3IzpkZAMKCVI9ww08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id j30-20020a056e02219e00b0032e1027cbf4si1985397ila.1.2023.05.16.19.21.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 19:21:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3izpkzamkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-ba7831dfe95so226919276.2
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 19:21:23 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:b3a7:7c59:b96b:adaa])
 (user=pcc job=sendgmr) by 2002:a25:7708:0:b0:ba8:1b23:8e66 with SMTP id
 s8-20020a257708000000b00ba81b238e66mr1996246ybc.9.1684290083311; Tue, 16 May
 2023 19:21:23 -0700 (PDT)
Date: Tue, 16 May 2023 19:21:10 -0700
Message-Id: <20230517022115.3033604-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v3 0/3] mm: Fix bug affecting swapping in MTE tagged pages
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
 header.i=@google.com header.s=20221208 header.b=KUAjUFSP;       spf=pass
 (google.com: domain of 3izpkzamkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3IzpkZAMKCVI9ww08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--pcc.bounces.google.com;
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
 arch/arm64/mm/mteswap.c          |  7 +++---
 mm/memory.c                      |  7 ++++++
 mm/swapfile.c                    |  7 ++++++
 6 files changed, 28 insertions(+), 48 deletions(-)

-- 
2.40.1.606.ga4b1b128d6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230517022115.3033604-1-pcc%40google.com.
