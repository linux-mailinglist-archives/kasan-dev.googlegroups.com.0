Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBGM54OIAMGQEPTJFGMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DF0F4C44BE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:42:02 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id k33-20020a05651c062100b002460b0e948dsf2339105lje.13
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:42:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645792922; cv=pass;
        d=google.com; s=arc-20160816;
        b=cRorBdusCJHLhpJBBQ6TvJzX80psJmfMbtgpEbw2qLnDJpvVLnGQR9z1USgYQdXuua
         DaKTopOUSueFJmVyjh1yjOk0kF6+PH8QcyNM74cJ1oLY/VJF0o52VwDb2WROTCHxiFBe
         yizCGhOvPbAnOnhb5EOcvRT0QmdAGEBuDMGbJwRcLTFGoFikuEDp/mHKvDyJItKMO4pY
         8Fx9F4Uj1tOC3eQrkbEt13F/sZ8jmt7Vn57+90+Wnldchavv4TswRbi08BGKnKyhQn4p
         JLG8oKpPdfMjWsYErjhUyn8QfAednjQ2NKGSfsVhoC3BlzxR//nKxM33j40Gnaa6g6qB
         wKGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=03NIhqWtqPehotCDTTIY0I2Jt/ZE/Hf9NYIlGskt/r8=;
        b=xbBWHc+dXrqbGxnmFV6068hfQbjb5Egmjxp+SEYkWEZEwjMdUNtwb0Ax2sCi2NLCjK
         IccjUE6k8NlJJDfHVMCVgCb8H1cjqfguWYe3C/Au5RwdIn27KyNgd19278gSKzi7lm0O
         wkhQOPhkVVDES5pMhjS+l6PdjRV8HDJc1+jFLHbrm1oGMGTHcBoWnZsm15OVXv5w3DIE
         dtOk3Q7Eswzgu0PKFV+uplnC0YsIGOpjyCXPXonkQEjypkg5DmFfQedp9deN5bG7NhCc
         oHH3SR0p9duGRY4LPyxqFLzoYpZeN51yLNWd5Xd+pe1KsMh5vi7keqcwSgUma/2AGHDu
         F8ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=nEDVxNks;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=03NIhqWtqPehotCDTTIY0I2Jt/ZE/Hf9NYIlGskt/r8=;
        b=nsPMXMMePGF+5tWhGpId+Q6z5DMuxmRCaYSMMCEABFdnykWD/ZBGszAPtp3vD3GX6j
         d3Vu44yMLtG4AXwjkRZokoyABeo9Cw3BmhUJGw2EW0oLqWlah44MytjYU99Oj5V1Mo0c
         BY46jHmoR+DDSi8XnE1ELyKfK4od7xszUSnTy05qiDDl3D76ljJ/1aZy7W+aX+8+AZre
         gpsGHBXcWKwGTX+AXWGAF/0WcQxuUUOzWCkcvxWPkuRk7ENRT7S4oYngU60WezZ2NHjh
         zi6PvgVwP1RneQkX9ql37KfnJX5g5NSSMVrwjLHZlP0aNAu/O8pibKWp1XLUIPahmA1x
         ZACQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=03NIhqWtqPehotCDTTIY0I2Jt/ZE/Hf9NYIlGskt/r8=;
        b=37IFsomASVhGQlyshBavsT5ksOZHHMgwq3L9Sx5/2oN6yUCHemplKVephbXPCq8qIm
         W4PNEGxXEBQg+1qqEsB799FqjCqqq91u7GTH7bWxCa4ZDPGPLHFuQYtYtV7h0cfIF3fn
         MX5rr6mmBI9RHdBrc7WVBtIU1l7PqzN4pj3FKRRkQC/bfH+GgL9bbcO4w5MEKnQGwpS1
         6BufZxBSJFxcBCOAq3hvX4xHX1ZduQcvo135yjGjKWIyoo0+p5s4HYdaqDnvTZ7RftPz
         KEXoVGyLVeUSsNfaIN+iHGiOfgYT4vgUIhojMWbAMw/kNdWOnVMS5sNx8MAD26XHz+mV
         0qrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306x2OWrqhR9lG/sdmByr9SFem6aQ3q4l3dRDSKGvb8mwyvTiXv
	HfWJteF9yaY6pGJRfwj9FRE=
X-Google-Smtp-Source: ABdhPJyKOf4mo8in742O0himQ/FYsbKVChAcOxz1w5AkzcaXSGMyaDlVr4cAqQ1C87m/MXx3cU1f7Q==
X-Received: by 2002:ac2:522f:0:b0:442:bf9b:4249 with SMTP id i15-20020ac2522f000000b00442bf9b4249mr4894399lfl.484.1645792921831;
        Fri, 25 Feb 2022 04:42:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:443:7b15:f451 with SMTP id
 bp35-20020a05651215a300b004437b15f451ls719276lfb.0.gmail; Fri, 25 Feb 2022
 04:42:00 -0800 (PST)
X-Received: by 2002:ac2:5e2f:0:b0:438:a4b5:4c72 with SMTP id o15-20020ac25e2f000000b00438a4b54c72mr5019720lfg.304.1645792920835;
        Fri, 25 Feb 2022 04:42:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645792920; cv=none;
        d=google.com; s=arc-20160816;
        b=nNi7X0mqQn9uy3qjDW1vy8cbhwsGj1V9zkkxF0TiDqUvzD1AOyjYLmrrhs6+FHB0E4
         S3RufnMarIlJLp0xnD14RCIk9lxeVCOYO7/+XJpiPoAapR2ABToGZRE5pnIHzzF0/arW
         Td5ewsdeesU1zd115yNWOOCDC8Isnr/9vaijGvt1tTvr3yM44AsUfaLY4ubhuPM/nV3V
         067iILpsvP0iWyen7obkA2n78MMZ/W9xzjL0R8AlJnVXyuKpT5eXSqG85q+LvSYnycv2
         MudYJy3pia4g0pdCW5blzaMZ4Z0gGw+fUJQ3jUMVk7XRrwr/ULOD59mzug1bedNmsraM
         D19Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=5wR2inrb50SGryPV3ql5qm7RIRt9i7gNq/sby+Clcps=;
        b=oQr/esSUN1RR4q11O2+BEwY919yGNmC17RgCkTiiPY/VENZUP26kN0n9mfEq7tqrFH
         1Wt4mbbSnts56GtXLVIDq4XzzsxG9v3VnhvjKAH8lLz6DUiwT5uKfBdpC4/BXNK+fOuB
         B/BPvJYQeXgbJiwC8fl1AR6/DFe5l8LVokS5blWgDOxhvumKjQTX35mWuk8dX8QJdWys
         MNuYvrDHt7jXsJGHoOOpcPKY2WfnLE9cTsZgKs0EpC3WS/YID9HR/g1RWKkq+CLjM/DD
         4HvHHXHMapnKb2ZmijHWDRjWgj+GqCyMJJqFFGSwB8zi+HJNPJEUuL6xH55LfJdLtZTY
         7Qfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=nEDVxNks;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id c11-20020a2ea78b000000b002462517709asi98276ljf.3.2022.02.25.04.42.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:42:00 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 61CE13F1F3
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:41:59 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id t2-20020a7bc3c2000000b003528fe59cb9so1269190wmj.5
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:41:59 -0800 (PST)
X-Received: by 2002:adf:80c2:0:b0:1e3:3b9e:ab6d with SMTP id 60-20020adf80c2000000b001e33b9eab6dmr6234421wrl.253.1645792918686;
        Fri, 25 Feb 2022 04:41:58 -0800 (PST)
X-Received: by 2002:adf:80c2:0:b0:1e3:3b9e:ab6d with SMTP id 60-20020adf80c2000000b001e33b9eab6dmr6234407wrl.253.1645792918458;
        Fri, 25 Feb 2022 04:41:58 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id p18-20020adfba92000000b001e4ae791663sm2234860wrg.62.2022.02.25.04.41.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:41:58 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v3 2/6] riscv: Fix config KASAN && SPARSEMEM && !SPARSE_VMEMMAP
Date: Fri, 25 Feb 2022 13:39:49 +0100
Message-Id: <20220225123953.3251327-3-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=nEDVxNks;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

In order to get the pfn of a struct page* when sparsemem is enabled
without vmemmap, the mem_section structures need to be initialized which
happens in sparse_init.

But kasan_early_init calls pfn_to_page way before sparse_init is called,
which then tries to dereference a null mem_section pointer.

Fix this by removing the usage of this function in kasan_early_init.

Fixes: 8ad8b72721d0 ("riscv: Add KASAN support")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/kasan_init.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index f61f7ca6fe0f..85e849318389 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -202,8 +202,7 @@ asmlinkage void __init kasan_early_init(void)
 
 	for (i = 0; i < PTRS_PER_PTE; ++i)
 		set_pte(kasan_early_shadow_pte + i,
-			mk_pte(virt_to_page(kasan_early_shadow_page),
-			       PAGE_KERNEL));
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL));
 
 	for (i = 0; i < PTRS_PER_PMD; ++i)
 		set_pmd(kasan_early_shadow_pmd + i,
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-3-alexandre.ghiti%40canonical.com.
