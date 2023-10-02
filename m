Return-Path: <kasan-dev+bncBDXY7I6V6AMRBJ545OUAMGQENKY67GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D00207B5620
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Oct 2023 17:13:45 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5334e22b2dbsf13318447a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Oct 2023 08:13:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696259625; cv=pass;
        d=google.com; s=arc-20160816;
        b=MuHHiL+4gkqVxgbDz6sJMTHqFwUOeoX9Nsy74cPdJ31Clx2tNc7uz60OIiOHsqGRmQ
         KoW9wNLctPA7hddZR2IvfI0MwYPLaQb6P2gdsc6AuCcLGaGvz9d8Z5lytYKlyETw1ttM
         3NJylfVbjiBFMBC+l4wUMWqAbGR3dGDgsoHj3cjYb9WbXYv4l6zm6mu652tPqaOESn7H
         8kouM+moxp2J7pMR4hFpxTcCZVuulXCEPhcZgyzK9+uO8mHb6g+PN1FP1ii7+e5QkQCL
         pel9Vlz4S2KphvvIN4rUf7N6DVeNnywbR1YZbH8fXEOb+h0mgVgfnkIHDgA3JCB6WDoy
         l1qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Eu+PIQL18RM73By/I0koBQss7l0WZrisApwly8E09Jk=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=BVY1KK7uahsuFh40/wVfYi3tAHiq1EkB1h5J6KemxZ0ytSnsc4IJU59ZHtCh3ZZZMp
         /eDfzAtvA50y9Q8curB2PUNqSiiSXKWExJs3jABbXV5Vqi+csCtdON5LngrWaPIMVsQR
         qf+A52BqCg5bpLEO5UjNu7+zlPkDm1b7uECxlaQ+BPFaYd/U5/Vmpk09S5ZDteRrwNo+
         j+CgnY1c7uW5GNaxlDk0X7DApDxRgHFg2qPrBU6U6gsvfYjLQwWX3BC7AeNsRRwL5b4x
         hcQz2uyo+wGJRXSN4FlKM3/33F4gtFPw02YLYm+bGwEKTtdv+oK3FSVVepTTW7hkagtx
         BU3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=K4Lg9Y5H;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696259625; x=1696864425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Eu+PIQL18RM73By/I0koBQss7l0WZrisApwly8E09Jk=;
        b=iFId7K1c0WCh89+ks78NyWbOaYR5pWjNEDGw0AZYjjUt3fyohVLvk5xSkN/pW8KQ91
         +lX/40sw/JAZmWtzrydmV6oALNNj0qdMjq0eItqX240GJTlyP2HuBou3cYatRZD7wusc
         0QIV5J/8EEOkbH9l3t9Q9M8ZSvdSFvVK7/MDexeW4B5QAW8mAZWdu6qQExxwG+P2x0oC
         3Qs6lQFDFfzkdWb3dJ5vedJ1NtCqzE+MsqPTJYfkDFychsFDBGCTie1eX92ZpUGPA8rF
         hCDwoZKPsFPTKEQTS48UILypkjZ+Zp8Mx2ZUdjxYX9o371ttycuQKUiaDFTK2fxEVStz
         eKSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696259625; x=1696864425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Eu+PIQL18RM73By/I0koBQss7l0WZrisApwly8E09Jk=;
        b=bDZEhFrfH93AN05fkEmefw+DoQSst0HmgIHcN8Quo/CCNcPuCMpZm69tfEnfGOCryS
         HIl2cLWLMat+15AwF+yTtQiGJyepBKxP/O8R3s5P58O+bmp7nZnS1/5xQ3rlrD2r3q15
         r9yJb9IwQc3AhyooN+lnv4x1iVRvrXJZ1xEYs1HassCqn9nowQE3YxFMGAQR0DjVmR1p
         ZiDDcqC31ZgHeW46U/ja+b0NDDZe1QRmTmJv+tm9/MLUzEDWumuJTN7WKrq0kAdB5kfv
         1pYFeq7HsUD8KWNz7KmXbxkLPymMc8mBtZLzWwmGGpqk3mgSg7Xa1pG1jy5rI0yVsKfp
         6OaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzi6oyvQh7uNR0aJ/JmKB1q/lVqmvnnOtAGXD11JX/Waf7vp7Lq
	aO0dSM2zzF3Kuj+3GJK8SMduTg==
X-Google-Smtp-Source: AGHT+IGxoPqCCsuaAH/bQvAQixjwjlDKA7n1jDP2N02w7DbETRXmXWIKuWNzba92iuMmjz+m7AhraQ==
X-Received: by 2002:aa7:d6d6:0:b0:525:5ed2:abed with SMTP id x22-20020aa7d6d6000000b005255ed2abedmr9543855edr.30.1696259624077;
        Mon, 02 Oct 2023 08:13:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f1c:b0:538:7645:34d2 with SMTP id
 i28-20020a0564020f1c00b00538764534d2ls384752eda.0.-pod-prod-01-eu; Mon, 02
 Oct 2023 08:13:42 -0700 (PDT)
X-Received: by 2002:aa7:c991:0:b0:522:580f:8c75 with SMTP id c17-20020aa7c991000000b00522580f8c75mr8962314edt.17.1696259622127;
        Mon, 02 Oct 2023 08:13:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696259622; cv=none;
        d=google.com; s=arc-20160816;
        b=zJPyFy/5HW1aoBqA+mKJYQiiymbh7a4osoTqfAmTiAyOSrutiLQ+n4vVNK3X9Rp698
         TSU8Cqct0udAzk4vZwVSSp++ed5ZGlt3QgcjJNPcTOyCT3DOFpDPYZR90404XDn7r+Ll
         8sODunvhBu2ktkEvpEEHNKfiM9s3npj6cFCUShw3aSvfV2TCEZ1c2Oxp7pirVBY5lZHY
         jH6Y84fx7xYsfvWPv0st/Yjvzc0mndcwZOWmPPfvpU0hqUi8tUszAYAFZYMSD7nJ69zR
         RA87BcBDACHTxDxLK9inOWWYi9nBfJV2aaolyD+d3cyJ72+NTMuifiqnRgWH9KdynFMU
         EIew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PKlKP5/9RI4UDE4Mv9BGz18R+1865OFX4ZcGb0PXpPY=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=05bZNF2j2TDW3dlgGHYjhEcXvt5oeJZICFvFjeWjHzTJSxYvRvvie4bCE6mlLYFIGi
         3qstnOoOQrBz+nj2bjBJLPRy72ZiZV4ua1wClXA2ne/CK7KBrreIRM+IWVdUSN0MMvY6
         RFAuNe3OzVDPUHRBJr6hNFiLiZPZNB35Ro7D26Fi3XpJKfLgMkA5pvsQZNx+q/GJo/hA
         ryZL8JHZ/jDEOnNClDUrOH4FJjtZa5nt1MDYmgUy4KR2GOl/KKzLeRz5FhSQNhmD1K8y
         sA8DVXrLcBfrDkVW7FEtlLxadFlrfZr96d4SuTHNeCF/djKLy9Zkz/7F8hpedaqXqn9b
         HnjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=K4Lg9Y5H;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id i23-20020a0564020f1700b005381936ef68si422042eda.3.2023.10.02.08.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Oct 2023 08:13:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-405524e6768so145726105e9.2
        for <kasan-dev@googlegroups.com>; Mon, 02 Oct 2023 08:13:42 -0700 (PDT)
X-Received: by 2002:a7b:c8d6:0:b0:406:5190:7d07 with SMTP id f22-20020a7bc8d6000000b0040651907d07mr11349388wml.17.1696259621727;
        Mon, 02 Oct 2023 08:13:41 -0700 (PDT)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id l5-20020a7bc445000000b003fbe791a0e8sm7509731wmi.0.2023.10.02.08.13.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Oct 2023 08:13:41 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 3/5] riscv: mm: Only compile pgtable.c if MMU
Date: Mon,  2 Oct 2023 17:10:29 +0200
Message-Id: <20231002151031.110551-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231002151031.110551-1-alexghiti@rivosinc.com>
References: <20231002151031.110551-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=K4Lg9Y5H;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

All functions defined in there depend on MMU, so no need to compile it
for !MMU configs.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/Makefile | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
index 9c454f90fd3d..c71d4253a171 100644
--- a/arch/riscv/mm/Makefile
+++ b/arch/riscv/mm/Makefile
@@ -13,10 +13,9 @@ endif
 KCOV_INSTRUMENT_init.o := n
 
 obj-y += init.o
-obj-$(CONFIG_MMU) += extable.o fault.o pageattr.o
+obj-$(CONFIG_MMU) += extable.o fault.o pageattr.o pgtable.o
 obj-y += cacheflush.o
 obj-y += context.o
-obj-y += pgtable.o
 obj-y += pmem.o
 
 ifeq ($(CONFIG_MMU),y)
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231002151031.110551-4-alexghiti%40rivosinc.com.
