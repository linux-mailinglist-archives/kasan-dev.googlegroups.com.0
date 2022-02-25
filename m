Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBVU54OIAMGQEMDJ3CGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CDBC4C44C0
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:43:03 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id bn10-20020a05651c178a00b00244baa268b6sf2323757ljb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:43:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645792983; cv=pass;
        d=google.com; s=arc-20160816;
        b=bI85qdQ4zgl31OSeDHfIAYFBfxBU1Wn/0syes0tL++qmMJ01EVYjVkJIQdcGWTu0Ql
         VWNZHPdENlv+lSmUlbCWFO1w5eM1cNYNr9SGW10nuqV8H1tURg7Ygn8q7iy/Of6t4iFg
         Z88zl9x2jTVEH1b+8Rfl3+UVGOBsI/O6RV8QCYo/rbWt/3K9hbRV5ACpv+HnGYjSryr+
         DGyX5FtZ3+MMD6ASlhwrl0ziJKdlbTnmmDjQ1Hr0dOERzlO7DRrV4fUCrfCzRKGMHUNC
         2zUn7XdbNv8JeBL96S6ToCRxFy605lEDCSNbpFeFCmlcYE2b1i8fehSB82iXcvDGAIkC
         m7dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=NDCxL87tmJUZH/nujo1rB+R2jUWDi94IBVDGlZU3S1c=;
        b=TlgG82Rbh+Wm9+jAQ0vmTWdoqyEBV5/Kk79oO+qg0vjGZpSMwEFJRxN9LcWnBwpiKz
         Cf5wJil6KxsSqlsB7AH1mEY0zVRZUx6T1PNv9IEZISuvdCT70yIAtbRQrIM4ZHMBG6/r
         cCZWzaaI4lAZDGuUhZWfbAABKFP1Wtt3yZDxFcRDA5Ml4ufYevZ9Vc2g2lYPKvbTBpkP
         tcnws2MrblrZUlN8ZNBvPiTC7KlOPozVtPPaAU3jTy6Jp4a2LkogJ+iTG/hr8qbjRN3s
         9rIJ4PwHEYgP2Ah6clagctAtHMbY+I6gOxbI/dFMcvJyDk3Lx0VvpXCl56qYQJMs56zT
         +vvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=pM0+kpRW;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDCxL87tmJUZH/nujo1rB+R2jUWDi94IBVDGlZU3S1c=;
        b=E3U5+IeMri66/mzOWMYeVn/97hO1fWQQPRbJoIWnkP2Mg4F85idFwBRq7KydemOFA3
         lEdSTJTaqdpmTZRFwjrMw/p3njl7aBqgKeVv5vFP/0siNHibjn/A8g7xuWJjksnErx6v
         85nvTQvWm4SH0WXsEtmEddJhdGHNpbmjG9VCEG3EYKjwiT4nV+pyn5v7LjepFTTyZKR6
         3DP10+aE0VX+Sqeyg9MA+rGn60PzvxOAc9wjT9DjpOW2hKuGCEC4JNNBWX+OA6Edensc
         1j04p5bBemOnDn4ugx6BIOpost9EGrUO7+Qhfp9/qwXUelcPWcEWV8RTdxF4R+9LDnDR
         w1/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDCxL87tmJUZH/nujo1rB+R2jUWDi94IBVDGlZU3S1c=;
        b=ZPsKSfhO1WP0Xl4Y+Gv/a7WMAwk0DRPEDWQPhOrckTP8Mp6qzopXYe3ovoRv87XgRs
         Z/eYdhMigciAxr/APC9Mys1PnVal6YHWAtWhtpqDer48xlTtTZDGQV3Ix9fJimoKtIN2
         pYxEwVYHLP3/tQGP/cXF8dQfAoSNHb7qbakFUFAAtzi8ItlWMHVqoBw4Mgei7XUXsckB
         zWC7AdCoblZk1fHbS4xgw1XAoC0dn3Vor3b4raAiI6Ni8U0aTqaWkUb+YbixyHTfJmo8
         TFqxMf+/ScJaSexCLbRo3cKoA1wYihFjtPICAjwl8cHiKXCCTHz4rdjfWmrWB+0gVUxu
         k5Hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ExBHJJ9HcICkUO1EE7739E5Aix9V2XCjZjAkwJpX0PW0XcG/o
	A4d6jW+vEYU/9O/2BKoINxE=
X-Google-Smtp-Source: ABdhPJy8bbyd0LRDJIJy4zRig/d9/2ADr3LJ1oufeASBMJ8IeUIvMljmNRO2gVHXCcdxasdp/8U3dw==
X-Received: by 2002:ac2:46ef:0:b0:443:3c30:a372 with SMTP id q15-20020ac246ef000000b004433c30a372mr4883371lfo.626.1645792982887;
        Fri, 25 Feb 2022 04:43:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a54a:0:b0:246:420e:ed3a with SMTP id e10-20020a2ea54a000000b00246420eed3als1136363ljn.8.gmail;
 Fri, 25 Feb 2022 04:43:01 -0800 (PST)
X-Received: by 2002:a2e:a404:0:b0:246:204c:33a2 with SMTP id p4-20020a2ea404000000b00246204c33a2mr5264819ljn.324.1645792981874;
        Fri, 25 Feb 2022 04:43:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645792981; cv=none;
        d=google.com; s=arc-20160816;
        b=jQg1f1k1Au+LCDr7jHFSCE2ldO3SzNTeDXApiie74zOZ61CvnELQh1FmD05ZtSR67q
         Dym77Z27JwB6n8U8JEaR0avmuic90NJIgSJ6WvdALw+oIZXR/pzjbrq6ZRH9RLGgnqKN
         bcdi6CCbM+6rMjKxkJmx0GUXS5lC3HPXzJgdEOefLUvbCsx7PVUBiFckUq1/TsbcWS+E
         NufViasdP7wjIik9V2Cok/nl/i4qo8/xL99G233vmJjLsL9b6GlMC6uodlOyFdMncjGq
         t3BY3TStl9515cb9vipv0XJN1MnByTahHdd53PyMQMiK7tDu61LkiGn2a8XwkCLIXPc0
         k0XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=cguSXJTSK/jUGjEgH9bI1vq5RLn1H9fQDOjhSSVs79w=;
        b=jDWrxZvwtNy3YPLyHffin31Pn5/WFTQPVnE5VaQTABLVk0GTnH/+eUFUciGI51MHip
         RFLGKLfcG6XgWHMUeg6h79T3cu9jTDLYzWcQq1kQ3snvzwlntp2NOmCp5QO5MOVudWNq
         MsQgj8C9hpPtDzRqKd4TDuO61lFCGNMH4d4ybqWTK/uFJJsUgMyI+VOpxYkZrPqJRYYj
         YJGNc1VPT9BM1odDIJ0AKds4+nNhtB32sONGhlh/5w9A5DFAKmpCVdIEof2qP8mJXhLE
         QqrQkre1xxrxTFKk4nmn8pe/a0pYW3twY2pCNpkqCYl/PAl6/VXfprLuLJUcmgpIogu5
         Ns1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=pM0+kpRW;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id o11-20020ac25e2b000000b00443c501a389si116278lfg.1.2022.02.25.04.43.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:43:01 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 53D143FCA8
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:43:00 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id l31-20020a05600c1d1f00b00380e3425ba7so1257782wms.9
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:43:00 -0800 (PST)
X-Received: by 2002:a05:600c:3483:b0:380:edaf:d479 with SMTP id a3-20020a05600c348300b00380edafd479mr2577995wmq.20.1645792979760;
        Fri, 25 Feb 2022 04:42:59 -0800 (PST)
X-Received: by 2002:a05:600c:3483:b0:380:edaf:d479 with SMTP id a3-20020a05600c348300b00380edafd479mr2577978wmq.20.1645792979554;
        Fri, 25 Feb 2022 04:42:59 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id g7-20020a5d5407000000b001e2628b6490sm2248342wrv.17.2022.02.25.04.42.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:42:59 -0800 (PST)
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
Subject: [PATCH -fixes v3 3/6] riscv: Fix DEBUG_VIRTUAL false warnings
Date: Fri, 25 Feb 2022 13:39:50 +0100
Message-Id: <20220225123953.3251327-4-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=pM0+kpRW;       spf=pass
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

KERN_VIRT_SIZE used to encompass the kernel mapping before it was
redefined when moving the kasan mapping next to the kernel mapping to only
match the maximum amount of physical memory.

Then, kernel mapping addresses that go through __virt_to_phys are now
declared as wrong which is not true, one can use __virt_to_phys on such
addresses.

Fix this by redefining the condition that matches wrong addresses.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/physaddr.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
index e7fd0c253c7b..19cf25a74ee2 100644
--- a/arch/riscv/mm/physaddr.c
+++ b/arch/riscv/mm/physaddr.c
@@ -8,12 +8,10 @@
 
 phys_addr_t __virt_to_phys(unsigned long x)
 {
-	phys_addr_t y = x - PAGE_OFFSET;
-
 	/*
 	 * Boundary checking aginst the kernel linear mapping space.
 	 */
-	WARN(y >= KERN_VIRT_SIZE,
+	WARN(!is_linear_mapping(x) && !is_kernel_mapping(x),
 	     "virt_to_phys used for non-linear address: %pK (%pS)\n",
 	     (void *)x, (void *)x);
 
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-4-alexandre.ghiti%40canonical.com.
