Return-Path: <kasan-dev+bncBC447XVYUEMRBXHXWGBAMGQEW4WOV2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BC67339D16
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 09:46:26 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id j6sf8840922lfg.8
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 00:46:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615625181; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sj9bCPLrzxRNNbwEhZVkTJjB42rwalqoY57uap+wJVuisTNRpIhZq/Ez6BdiZytXCO
         D4OAE7eBNS0JSZN+hKoLa9txKYNeUnKZ9xV9ALIAL37IMN8kX4IQ+XzDRucV5FemPRrc
         fWiECbGJrYsCLC20MNO8e2P7wd0yyTdBvLtvR7a0P7FmcAEKBr+7/npws+1WvKRvfXmI
         bDzpltxX/N8bR6iuti5QiM8mJ1gWZKXGS9uajvJkskUp3VkvcG58ulOaC/PHqL6vNG+P
         WrrPRY0zWTkKO/s2++o/fBj0wlXkYM9X/mKsPGtN4yWxk5eB8u2b++L65Ry1th8d57Ju
         cD9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XsMtLOfL1VMZN4Q5w3F9xVry/I1G0xRWuqQ9h9+mi7Y=;
        b=cHAzIZBxZa0dJRAn8uXkzJA758clCQUhqVfOu9WYBzEqxOcGaQrV8zUDKfIdMMUBvu
         T7kaPV0Gpw1LG4bws+iSN3Ffi6iPBJ4ZSFOuPtqFKYwx6744n4cjl7WUXwUFKpSnJw3G
         0zVhQwZMZu2/euoUWaaOt58vL3XzB8xbDmTPriVa1a8TyBef4Dbx7KPRhPxH/JFvkI0U
         UFk0DG8e/tKq03Lm5jRqOgL6tEcH2JV7wwWkdYbMyIL5xyn+AW78b8iVzBbJETkClbwp
         l4gAPOXMqbvJgqRJJzx7jCSviKS8fK+3dJ/M7cIXEmFkFtSoBwCbt8ZCMxrydlP7hsxp
         cxHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsMtLOfL1VMZN4Q5w3F9xVry/I1G0xRWuqQ9h9+mi7Y=;
        b=JXllMTdXGfbCmPXb/N8ocafze0m4dwfdZ5+EZbOxUzmCZF2J+G9PJUamL9jT1raQSR
         nPywutRq1LZScANfrULu2/H/VDKDYPLwgKFJQMBmiyDy42Ik6c5vVQgQkw1OZq6E9vx+
         VNh9rLkTBxagaXDy7gz0bQfXJPel3RZDabPNNMmyoOR/kpZCBxxAiyJojRz97f87goAQ
         4XXr4zRUL5bZHBgkTnelMLSqLh/jtlhbdyZuXhWVQD65JKVcUVdxBM0o6Rtop4ubCuax
         8gCJmEXcPW2Ua3xFTHAKqrH+Yyb8nP0Nsi0ZNqCmdYL8KZub93PAyynvpSAHKuZ7xEXZ
         Qc3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsMtLOfL1VMZN4Q5w3F9xVry/I1G0xRWuqQ9h9+mi7Y=;
        b=KNwjmzos3nb+IpXEdc1Hrb5vpK+s5ckWXutyiuFjw0kPkhArUOyy+ewRkaX7V7v8aE
         r/6rTC3jM6hVa5l9BdKIvaMpmC3obGSnAXi+OaCYAY7xgvZnj31BWKff4NI9gDHYdWBn
         MilLe3/qY8rAM56zOFST79VTiUBsJMp297NxmQXRAi3vsq6OpmMnC69BiHErhJv9CE3c
         PonBFedDC4drTXs35iigO8JC85f0i+ykg2VsgSK4byarHhYnBXvcCinfWDswvKUj6M9j
         VsvKkxFDYDe1M5Kn3gjhCSGlsKvhhYlTh8worOS+rifeLVatJaqN4itf0b1pcpRmrlwq
         Eh2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335I0R6qe31qF46W4ZxRiP+AJTR+JM6UV9hoTIKoxiDQ4dxLzb7
	DyH+uolDqrGupYqOocxdPa4=
X-Google-Smtp-Source: ABdhPJwZ+NUsWRC4voIE6FgsK0HTHwLlhZC67gbdh4vQkZ7KoC63PCIXMtrEPMNS5H8+J0+INEVANQ==
X-Received: by 2002:a2e:6c06:: with SMTP id h6mr4886163ljc.154.1615625181151;
        Sat, 13 Mar 2021 00:46:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls22278lfu.3.gmail; Sat, 13
 Mar 2021 00:46:20 -0800 (PST)
X-Received: by 2002:a05:6512:11cf:: with SMTP id h15mr1939098lfr.39.1615625180007;
        Sat, 13 Mar 2021 00:46:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615625180; cv=none;
        d=google.com; s=arc-20160816;
        b=q9U7UiZUgF9hnZfCoIs7O4eam688ubu05bTLJA5eAXHLwV5p2L6KD1OlVacnlRAQar
         62QuhIL7LvNikNdINNBWsN4ZGsPyixzpuYnES2h6gbeqitWqhdPTYkad7qOmLD6G7Xgn
         3U81tN6KAUoB3k8SZoHTBNl+4mPG+3x8ssUP5c0k3/oItdxHTfFW1H2m654J0MGECCM+
         FzrHahlc4VtVWdLakuxRxRFnZp3UYwR4+d81t6VJuc/wAyklQtSmeHZVfgtRTh0jAxxi
         xdI5aa+yiRH/Ch41Xq/fp+huKFyJXVvaP1R5E/lnQELuMW3cD8XcAqqjqvzx1FWfb63Z
         yneg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Di0j9Fmdz2pkuGSuMTT3DRwRu+d43uTG9S4d5kZrBw4=;
        b=xRcNvH9709oHV8sUVnZw2yXTe1tCcyysy6FLNm7hURGvA7SJDyk7peUaNXqLvVvUWC
         t0vfSU44gyWHKWdkxIz2l26BVCpIUqtfRcHuX37R3uY7sjxJ02YRfWhOXekqxdH7TvRb
         p1xCHJ2B8acPozniUER7brsTiUkD1AOso/GdQywqJtlTdUQsGiOcPq8Nm5TI3Jo8/iPv
         obbio72nY4H8xfQs0ZsWyFKb+wRqIt0jXJdwCar+PJNO0pGm/jO7/r3Gsywfah7t1mJv
         dkA8MuuqB4f1KbgASsRn954GpuIUsWjZWMRtqB4qSF51dMZflDeJaxAZ5HpXQQKOC5uP
         Zc6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id f21si340058ljg.6.2021.03.13.00.46.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 00:46:20 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 7EC3A240002;
	Sat, 13 Mar 2021 08:46:13 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Nylon Chen <nylon7@andestech.com>,
	Nick Hu <nickhu@andestech.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alex@ghiti.fr>,
	Palmer Dabbelt <palmerdabbelt@google.com>
Subject: [PATCH v3 1/2] riscv: Ensure page table writes are flushed when initializing KASAN vmalloc
Date: Sat, 13 Mar 2021 03:45:04 -0500
Message-Id: <20210313084505.16132-2-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210313084505.16132-1-alex@ghiti.fr>
References: <20210313084505.16132-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Make sure that writes to kernel page table during KASAN vmalloc
initialization are made visible by adding a sfence.vma.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
---
 arch/riscv/mm/kasan_init.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 1b968855d389..57bf4ae09361 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -187,6 +187,8 @@ void __init kasan_shallow_populate(void *start, void *end)
 		}
 		vaddr += PAGE_SIZE;
 	}
+
+	local_flush_tlb_all();
 }
 
 void __init kasan_init(void)
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210313084505.16132-2-alex%40ghiti.fr.
