Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBRVZ4OFQMGQEBPKKMUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B499443C1F5
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 06:59:50 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id z17-20020a7bc7d1000000b0032cafafaf79sf704604wmk.5
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 21:59:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635310790; cv=pass;
        d=google.com; s=arc-20160816;
        b=jO94e+eT1+Oi9s3B9WZkVCzNNz43hBrMPZnYd7ceQ6RImbTMewpfu1+Rgf429wqhhw
         tZV1DpMaAPz7K1HoOLpnO/eyWHQdx/aFyvuKj1yXTI3zSEMJSkIr3bq+rEqw8KpWxubA
         D6nHHIK/xCWYqQHgCMdJnXf4S6r/GyKe/RXN9/AXr/gUotMGGAjkGZMJvAReaVyhTJFI
         s5mqNojh2KRYf0gCX02hBJM8KRBiAh9gm+eFgUEcvxVV2r35GX+uOoVX6qwJ1bfMAIXq
         4qWG7ZGGs3W2idJcWRjpzafGNA6h41A9++KaPWMXKt2uaWiVmb7SF7+udEosWksDCBq7
         cGhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PbgtNdHFJlnU5JZyMFKbyOx6rDYcOw51upC/v/8nGlw=;
        b=0xCjT3K3fdWtsuZcbEYv6GyHMlVDC6EQAZShwpvoMZsdLulzOVoBE6EDSt0dCbR6h9
         VVudmyThXw4/ywVOS33gxLwIzHg9K9Iw+piorXkxvcygIaPN1wmNtBjE/AoVPv9I00Lk
         GXRWfpj45i6rABJbui2yoWfWJvqrx3qsXyI7CjEc4J2fkgJQIX7X3RfswfMejMQ6cbnq
         w1PQ5Y7IEtOGmVU4P2Y1aM0goVUbauERTMYI9/m+vAkvN5vjUayZGtwaCmHmZd3178Tt
         vOIu+WZY6XjPd7kwlqk2JKh3WlCx6dyq1s16DmLmi9Paf6hIJvJMByAkmQqLhmnpJyUI
         p/rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=c1yrvb6R;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PbgtNdHFJlnU5JZyMFKbyOx6rDYcOw51upC/v/8nGlw=;
        b=GtunSx2E0fe3pjXoCtIP0PZUbS1wWslUajeQ6EUKMnO3Cd87RhYxRpKYtffsERIdSG
         idYRUu5rrzzyqAUxhpmZbU9OfICFNyEu7dSFP7glo5qTqzO0IKWxjgJosM+zXGsf+iFi
         xXfEVdA8W0PpV8UVlbIEdcwpm98ZngLSke3FxMLnanGrXu/PfTC/PVgGwt6XwKuOMHLS
         CkPbSU91YBY43bxQuKqHVUeMxaOwyC2PbRG0W63C/QSVcy/tWQtaRcDHg1Tmy4BdKvH5
         Ps/2eX2axY31P7N1cirVEcOTJ5022iPeKBPcVR82lO2jX7jnm/Z72D52uajPXy273WdW
         LjpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PbgtNdHFJlnU5JZyMFKbyOx6rDYcOw51upC/v/8nGlw=;
        b=AE/FuwNlsQv49i3XJSBm/olC1yktI3Zxk39pM3+ZwpPLBsHU8xhewKBV7K53dW/Uyi
         M0LgyM9pN0EuS5iKZe/P2Ya3Ux/zsRpBbaVqQPFKUC3tU6bQ/MomUPzDtHkRaTJmNST9
         PRaRJTUt4N1EYNqshTg/jI/525C6242LflQLobmqmDHpdUkec5CwkF9ZDP37QfMdihlz
         xVHYN9hzQWhfLGIomDTafFw50rEOR0ZZ1XOhuyJMxOzRM0/InbT3kviGP2i/tsOhvSHH
         6uqaZuEYo4QsAt2VIvrErTVdKVwapSxf2i7RB7o6ZfVl4vSDMyh+fXX1mOn7Kt5XuD+I
         mNdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Fakp838gRej+CTSnST5CdZCP1oZWSgarcjl7A3PmB1DXiU15N
	Ti9zXXzHwdsjyexK338/pGw=
X-Google-Smtp-Source: ABdhPJzbnIafeL1PblTGYfxl2JDV2mf2mMKVVsCBN03orrXyHg6DIrN0e1I91Ww76x+hmdVG4i31lw==
X-Received: by 2002:a7b:c212:: with SMTP id x18mr3216981wmi.175.1635310790488;
        Tue, 26 Oct 2021 21:59:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5111:: with SMTP id o17ls1338208wms.3.gmail; Tue,
 26 Oct 2021 21:59:49 -0700 (PDT)
X-Received: by 2002:a05:600c:4143:: with SMTP id h3mr3258737wmm.19.1635310789672;
        Tue, 26 Oct 2021 21:59:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635310789; cv=none;
        d=google.com; s=arc-20160816;
        b=oXIZxSZfFbo5yH+5PQ+IG7gF/lA+UAHMBcsHpeTnzCROgJm4iX6nfgY3WnUj/Do154
         HQleNt/HCCDWYOdAr9dp/M3mivFrt+zqDHUEeERUwORwE5VtEUhdqOHyvBwSw56UXvDj
         BczVjCZPu9bQEGPFYukcnDo/avMnd4XR7TUUuIhAR505W0RSPFExinlEBqBZJwIXT36M
         mg/QrCEL++tJpAnLZEbAGwTP36bY5IbNsUbcYAAUCfgEVgQhQOnsXI4vFZ+9Cl66yrKx
         SVsaJ1H5JOsLsb3BLcQXqS05ZgryGgVZ0lNKxl3aF83Qjm6m22hHmYF9LE7IgpQhO59H
         SNZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LTVtpyKftoE0IH0g/BXOTfVkolo16F3nizMPYgvUIg8=;
        b=aQ8qDNjEbIC3ZhL/PCPkkFleQg/a1CxI2HGG+Q30uaA2ghX5Kh7/MRQtDVL6A/hb51
         N50xRkbbXgpU7/OsDq681Z3uE+U1jmYvil/SniGvXLSdadDQHScc//01XEEkUDLVXN2S
         Ou4L29fLLqqsZv2j2A0yH9f0cL7Lspm0vDW/OxY8ZqGndrCtw9alkib3y5BKTymIMhea
         ycmgZqnnMDt7AfX1Af7bF0zkwjfw95TopTEDKYhipCoLp/gUy24Jl+Rdhvj5jMbpY3Fh
         ciRfpNGv8Gjy/70B337SRZyYqNywxBvhSqG5wDbsEdsbJwRs9KvYTHUrZlAKDmxQk7/f
         DDWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=c1yrvb6R;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id o30si340238wms.2.2021.10.26.21.59.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Oct 2021 21:59:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 5C0C13F17C
	for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 04:59:49 +0000 (UTC)
Received: by mail-wm1-f71.google.com with SMTP id i187-20020a1c3bc4000000b0032ccd252cf3so699656wma.7
        for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 21:59:49 -0700 (PDT)
X-Received: by 2002:a7b:ce93:: with SMTP id q19mr3460077wmj.98.1635310788756;
        Tue, 26 Oct 2021 21:59:48 -0700 (PDT)
X-Received: by 2002:a7b:ce93:: with SMTP id q19mr3460062wmj.98.1635310788623;
        Tue, 26 Oct 2021 21:59:48 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id c15sm20432877wrs.19.2021.10.26.21.59.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Oct 2021 21:59:48 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH 2/2] riscv: Fix CONFIG_KASAN_STACK build
Date: Wed, 27 Oct 2021 06:58:43 +0200
Message-Id: <20211027045843.1770770-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20211027045843.1770770-1-alexandre.ghiti@canonical.com>
References: <20211027045843.1770770-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=c1yrvb6R;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

Now that CONFIG_KASAN_SHADOW_OFFSET is correctly defined, the boot
hung while populating the shadow memory right after the call to
kasan_populate_early_shadow: when calling this function, all the shadow
memory is already populated with kasan_early_shadow_pte which has
PAGE_KERNEL protection.

kasan_populate_early_shadow write-protects the mapping of the range
of addresses passed in argument in zero_pte_populate, which actually
write-protects all the shadow memory mapping since
kasan_early_shadow_pte is used for all the shadow memory at this point.
And then when using memblock API to populate the shadow memory, the first
write access to the kernel stack triggers a trap.

We already manually populate all the shadow memory in kasan_early_init
and we write-protect kasan_early_shadow_pte at the end of kasan_init
which makes the call to kasan_populate_early_shadow superfluous so
we can remove it.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/kasan_init.c | 7 -------
 1 file changed, 7 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 8175e98b9073..8df937902630 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -175,13 +175,6 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
-	/*
-	 * Populate all kernel virtual address space with kasan_early_shadow_page
-	 * except for the linear mapping and the modules/kernel/BPF mapping.
-	 */
-	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
-				    (void *)kasan_mem_to_shadow((void *)
-								VMEMMAP_END));
 	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
 		kasan_shallow_populate(
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211027045843.1770770-2-alexandre.ghiti%40canonical.com.
