Return-Path: <kasan-dev+bncBCCJX7VWUANBBGHWY77QKGQEGUOKOQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id CFE342E8D7C
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 18:12:57 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id u17sf20919147qku.17
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jan 2021 09:12:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609693977; cv=pass;
        d=google.com; s=arc-20160816;
        b=rq6Y/XFdt6uDR4nYtWcIaFZ5/ClPITFHhTOxelMX8AmxnUmaXGsTdP8sBvhNilSJaD
         GBKyMujqAr1exU4Q/0E4fY0bq1mOBAChZietzuZi+gtlh/Sifin5aSXjt6Xqo/Y6VTO1
         BBinij4i4uJyxLXF6wq1C2Dy/F5bSIf2zZ4GZNe23TQeSdZBWAUaXTsL3pcXWWGOp3hI
         eKJACp8hq9rvlxLpFCf9HEMozg216kRr7oJ8op409mP4QkRYeS9z5dcsU4cZ7WQzAxr9
         qsJFiF5VaVol3JNCoOZAKgtTmHtS2tRVihfBwjyhCH0OmfYqkmt+vdg5TlePeqbkMDwX
         hApA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=56Ay3Y6Hn9SYNgCgAkw/6paqnL78KFsHDI60FLZ5+tk=;
        b=wW4zsqstfEGhvaT0kchTIgAR2ak+1wyZ8iIOkyNyulOnLcSidj7fiFzEQneBdWq3Zs
         Habq/5+mTTysXvoOWIFP86RZYVl8oPe1LAfM9dL7mkef2i5Z6a4xGoFpMq3Aqxc2PPYx
         Hr0jLQB1EUDn9H/vggaJ2JPcPg4uq9nGj8Zmn6xjF3QwPWiFBRpRZ1Ig5CqYF9Aq1vQI
         IHKi114T3mjvck2bpQ6Fi7S+kP/Sds8saEaMVxSAUlBzLEw+I3GqsbtCHn9u5VfozPFE
         sZ3GiconZNWM3HkbCFJtI+2+Zddi12BHsDS2zpG9nk2Kcf3Bz4D3olS16BPOg+LXBt7P
         NLXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ZscOQ6cT;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56Ay3Y6Hn9SYNgCgAkw/6paqnL78KFsHDI60FLZ5+tk=;
        b=WtVAfHMPXJuB0Em/E+VnSbSoSeh+5Q1TWJqdaH1zPlPLPnlqcHrNQQQ8xDuVK7HSTN
         DDl/Wh+J4b2BlKeDbonCrADvlqtDCXJZn6hsHfeDIYv49wj3GSC0jhSKq79JtrsjLr1E
         vTHbnA986UuNRA9XGlqqihHIGCLnKXbjFZxUIbjvY6JOhaSBsLk5IFWb2cdyjc7wCltP
         Ozs0JVn6N7TnNfIQErUMp8TRMLLthNZWk6XjPO7Om66nUtozS2HWtkEVnLU8+iHABlW8
         qJYx6Y4toZodqcZOp6cn0AzDBIylMTKbxvJCWjCyhtC4f/+0U182/E1oteAiwdxqBkBc
         xWQg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56Ay3Y6Hn9SYNgCgAkw/6paqnL78KFsHDI60FLZ5+tk=;
        b=WkaCv98sGRNKlGM1g2gW37iiElaiPd3jQ+4Z/S/RgCl4pOf4BK3ba4h08gw/tVPDOF
         pUHB7puw0T/FIy7qn+LcLlaoQwGIyIQKn2YapJxxExePPcjjnS06fhVCcUfUZnij9nee
         f2x5s2+20eUdgQqTnm2KrqY4FDr5VuCbDevCIP50wy9GnkM3reNl44xL2zatx143J25j
         f/M6Tpc6IpKad+g5GQVLRJRHCnHy9LvkytZ8Kr/uhqyBJT35EfJds+QhZjbcgVxpDlsm
         knIN3Ai8mNQnQOWNiaHas34nMKCTTuQ7SbPCO4a/6pbgE+rOn/kmQuo613tPHPe5ZGD5
         aZXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56Ay3Y6Hn9SYNgCgAkw/6paqnL78KFsHDI60FLZ5+tk=;
        b=P8H9f2zvdD3xaNXSnMhl5SU96B7rTBXlaHRmMTEtkl0X3FqtZWUE0w2FzMXP7oo68y
         qbJrjt5TN0LWdROEnvh38a0mDCjhBstuxbTmIEyAC5qpNVY7QWnNE/DS1vNPXrtNAlWk
         JcYq5jmvHXdW98psfkSITtr+XqSu4hutNDJ5e/qCbSPc1UMh8SeBySBvj5NTqXHgv6Bx
         JlXzuZOL0ZAasCL/Q2Mt6K596oXQKTTfE3qPrD9Ye3LYDe/4lgaw+5JWGJioP1/xOTIM
         7PJdEQmBTma/QEmNYe48t1C83Juj9ng6qDaVesbyPFL+/i3VziCPuxbs7XSuBP8TK7ED
         /6fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YfXvAUR2LVfRKvaVDvZVLwuO1mu8DkjwUnt03a6qDiB0zZyTO
	8ikSoSsDDsrxMrUlR4PZkco=
X-Google-Smtp-Source: ABdhPJzshG5JbMMyBiRknFSiZwXU2dFNNsmscqM6+2ufuLb2gZ2mWchGbp4nqmB4f0gJ5Kbq2xumVg==
X-Received: by 2002:a37:4a4e:: with SMTP id x75mr68953259qka.89.1609693976853;
        Sun, 03 Jan 2021 09:12:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:205e:: with SMTP id d30ls9662972qka.3.gmail; Sun,
 03 Jan 2021 09:12:56 -0800 (PST)
X-Received: by 2002:a37:a941:: with SMTP id s62mr34874846qke.49.1609693976489;
        Sun, 03 Jan 2021 09:12:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609693976; cv=none;
        d=google.com; s=arc-20160816;
        b=OpHjURQ634eQ+tnF68zMCRr5DK5v/xNXTZV27ArvwXC1U6IEQobGYpt3R61Dq3tXO5
         d7pqJ1viTHahuw/yQ3ZMfHlbm8pPaK5ga7Wrj8FD35EHNEVdpHRPaHgeVtos3Wt0hNkb
         7Y9yfVeFtEub7Nft2DkmUaNM6MkxkRb6S3V2SJqAqUtsVlTZiMLfef8FTXuHi7r0KBIt
         I1SrboaQNwtQIRyYBJ5VTRaGHiIrWGSqukeAQiJ6WqV1Fw6mgC4jHdw3A/Dl8WI0qIEa
         6T8zONJJ6hm6y/z7WfyTVrsUK7w/XWFPqZh18no42Ff1HqC28I+Mr8TL697g3Gr11tok
         GbBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zcihLP7J+zvmlqvpCHNLNMn5gBB4sRocIGyVUTdgvis=;
        b=EjRhB+n/pmXpvN3Otjx4Ym/f/YUFGXCwmydgUBF16XSUAA2JrG93w+oB9+VzCP35XQ
         /zR8BqE6ZqR8CN9EZ2KM+B+gNR1BRYiTDnyoNJppZHFCiaJuxiGE1l0MXFs/XTlbnB4c
         L2oXUMQBy/yc07ohV/dX+OIyHTgwSkv5kTiDasBy3OAz88IsB71CGBrLTceAkj1s7j5a
         TQUrc1xqPnxq6IbnoBcosTG2DZUExtmdaZCOXRvmc4qv1RYXw0JMqJ4YBl1b7B2/i6QM
         mkK2tYknmMpiGr1sqpOxPGcF7nO06DmlyF3qnoSkpWsYqCqD2k7rHlrKLVrLi2CPpGgy
         JgsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ZscOQ6cT;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id n18si3911106qkk.7.2021.01.03.09.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Jan 2021 09:12:56 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id t6so13171793plq.1
        for <kasan-dev@googlegroups.com>; Sun, 03 Jan 2021 09:12:56 -0800 (PST)
X-Received: by 2002:a17:90a:4209:: with SMTP id o9mr26729316pjg.75.1609693975741;
        Sun, 03 Jan 2021 09:12:55 -0800 (PST)
Received: from localhost.localdomain (61-230-37-4.dynamic-ip.hinet.net. [61.230.37.4])
        by smtp.gmail.com with ESMTPSA id y3sm19771657pjb.18.2021.01.03.09.12.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Jan 2021 09:12:55 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH 2/3] arm64: kasan: abstract _text and _end to KERNEL_START/END
Date: Mon,  4 Jan 2021 01:11:36 +0800
Message-Id: <20210103171137.153834-3-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210103171137.153834-1-lecopzer@gmail.com>
References: <20210103171137.153834-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ZscOQ6cT;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Arm64 provide defined macro for KERNEL_START and KERNEL_END,
thus replace by the abstration instead of using _text and _end directly.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/mm/kasan_init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d7ad3f1e9c4d..acb549951f87 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
-	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
-	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
+	kimg_shadow_start = (u64)kasan_mem_to_shadow(KERNEL_START) & PAGE_MASK;
+	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_END));
 
 	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
 	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
@@ -241,7 +241,7 @@ static void __init kasan_init_shadow(void)
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
 	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
-			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));
+			   early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_START))));
 
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
 				   (void *)mod_shadow_start);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103171137.153834-3-lecopzer%40gmail.com.
