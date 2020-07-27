Return-Path: <kasan-dev+bncBDTZTRGMXIFBBEWE7X4AKGQEE6CEFCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D94F022FCE8
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 01:24:03 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id v21sf5753173ooq.12
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jul 2020 16:24:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595892242; cv=pass;
        d=google.com; s=arc-20160816;
        b=dCcQZ+gjthFGkQ2yRCTcn6MhtQ7/f5+ehIBtCN4Tkniu/zL0LZSzp0qLLWjoFwBOjL
         pLWUZIocW6b72tIv8y+GyXgLVldIzlTaC2UOSUyvUk3CxJc5EbQNYB90JiObQAtMXk7z
         UbzbFP0lhqEhXO3RFekpeAUbu14xQiJtHhnE2YCHqxzvIVTYbvI1X/o8XzU5PRklINGy
         fAT3rBwkRH6XUMzM/csVCu66Px34S/Pu2EGEAns5gg2fGOIwW2out9jIE3UsrxVVJpEJ
         r2JR1Pz0UgwvLB2B9M/DEUOm2KBFFgAphqjEMYpjIx0c8dH9vF3fJf+74oknCmJzVUAC
         Vq1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FyB80kCo9AJo3gDVY8nTr3adYk1d1ZAbfA91lotAsMY=;
        b=yPJ+KI+TlY2Z2TiFU4ZpMe0dzq5FXFUcT5Xtb5BR+JVlWJIQhQIqnbwTRdA2DJ1agd
         e0dU/yoJTcKXBog5x/5apu3r3KeFd9qJWrMPTfDpFi4akuT/Rc0OX2b//kCbSCDMRS5d
         iXMLhP1AHTg0cGIr9afBbHfKcmrlpVATCC4NRfbSF7/ekD4/XjZTHqD8emLxkDRlDY/q
         RjMSYddmKxlJAOYmo8uMoTs2Y7Rv+B7Li0X6eiuugSVW1OwWgAGcCiVuUbqipyVvPcIL
         D0xfuYyOWiPKZHtBTEMuPVmoEn0fUYjhZuFSOQOZrx5beBuX/HNiPyjhSCE+deIBPPbp
         Dbrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ADMVAtky;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FyB80kCo9AJo3gDVY8nTr3adYk1d1ZAbfA91lotAsMY=;
        b=YbBz6UxGUCEj8IfDjT4j/TWkTTDohyHRHVe932FwIlSPs6U7yhwGLWwBlv0n06eTIZ
         QeHCJwPGSTEkaGxbreXypHsia/zZsJoMT0I5AM9zak4GED2iTHX1eJN5NBj8/M83sTrx
         S9cPgAFu5dgb2THOWwBUfWRSAROWfU/RejUzJSv/UEYdBBg3tDDSkTRdiaPYC4DNpllE
         fY98VIgf3ywYYxtgc21Bxfto1+pUUqRBAdbtx0s25XstwesCjLfVLo6a1Mv9WaGd3myA
         sYRFC9BRfRKUjVQH9xcww/bupgKdWqejWQZL31O+iAcKLPEQfrurNsnibRzOQGi2gtxO
         HURg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FyB80kCo9AJo3gDVY8nTr3adYk1d1ZAbfA91lotAsMY=;
        b=EKv/HpyDjkzX9tCCexLaZnctuitwg+fSY7I1SRI+C3JShK6HRrEU6UkzNts1uKRO4e
         zjeE2PVerG/qVgYXcs65ZQj864TuHylF2V4MORbMmLgN946d8irT3ukTKEGnvWFlyg73
         Cf4Ly1poxHKLDJxfHenXtTLFT3IWCdUIAc5/jo/LwVISDRYS0kmEWcPaKHk7zRfTx8Mu
         9XpOuJPkkrxJ2JuqtNQEaGwH3CQsfOP/yrfs2z9oNTUGQOTpuQ3iidNWW4BZUUD57QhP
         jX+BLN/QLGYOW5tNCWhOoM36Sbfss9lPgRAnaImTEtiLm1czytGKWx/Tb4NXbZhN6rrV
         dXvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zxOomAqv8mubEwprvY/DGrBTvdljarKPoEcWd/uM8J4qnZ3cT
	Gsg+2plu7cINyeJ8zfIovCE=
X-Google-Smtp-Source: ABdhPJzLvZAWlR1H6lhvfrh3Pbq58nKa3fqSC9pdMQEw12emZcyOeedVhBzHjqC4JQ3aWe4uAUFKuA==
X-Received: by 2002:a4a:b983:: with SMTP id e3mr22376293oop.91.1595892242588;
        Mon, 27 Jul 2020 16:24:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4d14:: with SMTP id n20ls3695836otf.4.gmail; Mon, 27 Jul
 2020 16:24:02 -0700 (PDT)
X-Received: by 2002:a9d:1b0d:: with SMTP id l13mr22913169otl.261.1595892242251;
        Mon, 27 Jul 2020 16:24:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595892242; cv=none;
        d=google.com; s=arc-20160816;
        b=TbvrWiZvaAxnb+IdlfxB1iUQfmKbFGE7rSU4P7erbQkuOwJ2O7ckI6HSzA76oIVxA9
         zjyLhOadPydLmDYvBvQroepo2AZD3IZXDemJg84FtqBGLVYrkAJ2ZR+Cs7e601o4xNF1
         31IdSWeJx6x5pAkcjutmTm3j9GHtAsLpTD/hwlx0ix/qf5/ET9h99Nndrc8AG5fXSG+Y
         GVUEo6zlYo9Js+Nglwj1qWiOkdC3ja8tDXEqdHy9vhNBWqCOTMyHQDpU7jgoHvpSoO89
         FoKqpD7fJC9FPDOHKzCaNa9dyTjyMkM6QuSHIo2Xg2k6IyNvHpg7vyxglfkqBmxRGuqk
         7mpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=blOjruOSYjLIM1DoQ+VdEjUqJzIXwWdDciWXdcISaQs=;
        b=HznOv2seKSSQgK9w01Wz5XkiZqThH3z35xUbV/J0YV/stbqawCNbK7SiVM1ZeFCBfm
         7NXN/Rjb5HfW+CAnGCRR9W4se5dESIMbVFj/pIcqFoj3cZU/+auyT1a4Fd02eaoh8Q9n
         ieXc/5RI5ksWwb/0am17awZqGWE4FGN1U0CA+0+kGN32/BUhiKMwdW4BXTOTKi5/H9K0
         sKrgpyMfatyt6UQ8x6zsqZ3h4zDVBZUlkvqCAWe8eZ+SROjxVCCEezk8QU64Mu+/Wvyy
         RkBUzCCVx4eH01svKZQJsbwOX9+9ocxhRcs1hP4sDQ9phERbpiOCGNO7WCCNxHJdA3yC
         hR+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ADMVAtky;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r64si421123oor.2.2020.07.27.16.24.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jul 2020 16:24:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sasha-vm.mshome.net (c-73-47-72-35.hsd1.nh.comcast.net [73.47.72.35])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A1A5920FC3;
	Mon, 27 Jul 2020 23:24:00 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Vincent Chen <vincent.chen@sifive.com>,
	Palmer Dabbelt <palmerdabbelt@google.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org
Subject: [PATCH AUTOSEL 5.7 11/25] riscv: kasan: use local_tlb_flush_all() to avoid uninitialized __sbi_rfence
Date: Mon, 27 Jul 2020 19:23:31 -0400
Message-Id: <20200727232345.717432-11-sashal@kernel.org>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200727232345.717432-1-sashal@kernel.org>
References: <20200727232345.717432-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ADMVAtky;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Vincent Chen <vincent.chen@sifive.com>

[ Upstream commit 4cb699d0447be8e0906539f93cbe41e19598ee5a ]

It fails to boot the v5.8-rc4 kernel with CONFIG_KASAN because kasan_init
and kasan_early_init use uninitialized __sbi_rfence as executing the
tlb_flush_all(). Actually, at this moment, only the CPU which is
responsible for the system initialization enables the MMU. Other CPUs are
parking at the .Lsecondary_start. Hence the tlb_flush_all() is able to be
replaced by local_tlb_flush_all() to avoid using uninitialized
__sbi_rfence.

Signed-off-by: Vincent Chen <vincent.chen@sifive.com>
Signed-off-by: Palmer Dabbelt <palmerdabbelt@google.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/riscv/mm/kasan_init.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index ec0ca90dd9000..7a580c8ad6034 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -44,7 +44,7 @@ asmlinkage void __init kasan_early_init(void)
 				(__pa(((uintptr_t) kasan_early_shadow_pmd))),
 				__pgprot(_PAGE_TABLE)));
 
-	flush_tlb_all();
+	local_flush_tlb_all();
 }
 
 static void __init populate(void *start, void *end)
@@ -79,7 +79,7 @@ static void __init populate(void *start, void *end)
 			pfn_pgd(PFN_DOWN(__pa(&pmd[offset])),
 				__pgprot(_PAGE_TABLE)));
 
-	flush_tlb_all();
+	local_flush_tlb_all();
 	memset(start, 0, end - start);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200727232345.717432-11-sashal%40kernel.org.
