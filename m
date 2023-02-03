Return-Path: <kasan-dev+bncBDXY7I6V6AMRB7P36KPAMGQE3FHS72I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 33C85689152
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:55:42 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id y26-20020a0565123f1a00b004b4b8aabd0csf1903144lfa.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:55:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675410941; cv=pass;
        d=google.com; s=arc-20160816;
        b=tmmRZenZoo/FJXpDpqjjLCXhS0uGONp8fnAVs0DpwP4sw7i+7I5un7EYNJuI+e8S/x
         9m2kOAPx9cjWW1+CuxNO/EDIjUsObwW5brKihHcZvOl/JpBQYOK8LgJZ8vz2GbyKqE+C
         T18uooRlPhmD8vq9lSVxw1pGos5s+WmZ1YkKCaPRjZBxoxEfO7Wp12HWnSSz3ZSBCyQx
         W60L53f512XAeSoAiUMeErdQYLJvS7XwOJiC6cuOkeunzr3zPMoGwSFfdAvnCb1KmPOk
         ppHaArUCV8d+BPn13+53Mm2lgCduNX/I7ydOsfLPUoYs6rRk6EHMBfEgpQEjwnmtunhw
         03Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FPWWKlRVvsIBt+W9bohHo7sN5q8HciFcQEvxfiaMK9E=;
        b=dWY9BhjIrLvjo0/s0hqIx59EAFNDRCdHZtCn68goGnOB2J4iCyZwURCwAuARj/5gKe
         /lwaeSjFlU5O/OrAELkUEIvbtRZ3//Mn6seV5qUynnIwRSLpkXHVOh7LwrmKskRqXpv1
         o9Xuv7+6/oiLGiXjFoONu41wUOT/GwkDfcqQ5xAI2JbSWG8ues58qtvLzVwDsu+IjEdN
         lq7xwR1yFA6YzzYa6aFKYHruo3e8IquVJyFSpD0/ERDbyIbpVpKb2UcdJcaokPSsTDoJ
         rvm7KScuemPr+jmxYOSL/+woYi/N4ap9k9PbGgZUkZF3qzCJZtpePeI/b5TwPSpDQ+IR
         Cu5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=RNbsXzhK;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FPWWKlRVvsIBt+W9bohHo7sN5q8HciFcQEvxfiaMK9E=;
        b=Rip+FRk8lIv3nU4VESBNz1/ACr0cjWtZ9NgQxByfXiqdsxBhDKQiwffeX0Tct1CK/Q
         A51ke3QRA8oB6ZaoUyKEPlPpPIyCVAx8NPCsXE00ZssP7i3dXf6aT7H8Oni09EC7c8bC
         A4ui8lSxtkrlFYwLYHJMjD+j91nK+jA3W2TRhLJDRwdLa1wpNl0gC0wEz1Tp4ScNhS0+
         /WxyVcfY4gkVxKV8618gUrIHWDmkQE6FoBELs5Y0BUte2KlbgWBDb5TITnE5UXKCa4d6
         j+lVyEUyHkA0i94MS9bOJGss22+aXoV+EPTEwyqUveh+EuOMDgW+SxzHl42fOi9gY4kG
         E2Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FPWWKlRVvsIBt+W9bohHo7sN5q8HciFcQEvxfiaMK9E=;
        b=IV531ciDdClQqZZs7/ruMaBPIrs36YUTM0s8Fm9TDwrHDGBd7v10Ql8C3Xrxg+rox1
         RIhuTUpd2tfFunaQGE8SErMj3zK/BBZ7o4ymA81rh8VYeZlZoh7KvzLnIdcmEZpBrm7Q
         4OX5AxkmWE0FFEkG8qQgnVvoGSAwhu/CEdb/sVS5pIlVy99zzC682XKTBaUloHOll6XG
         0t1zzBDO3o5nBX/u+e+f0FzAlsEFtlsnNeDpHo0ZHppF1G1Xv9eEI6XXTQwtvZiKGApf
         LZlewW/0xCIklcKWjJ7PIjAKqU+nHbu8jUcSUZf5+zz9JFAwYgFjKHxzVtoHKoK2CDZp
         EvMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUMmXjJYaB/JPJXFHdtekNGlxg58uoN43rkeeMhd4CLHFhcC9fT
	HH9BXAeXR9PZSAYvexDCtkk=
X-Google-Smtp-Source: AK7set+qp2Bs5chf7ayGQ84thBrZbLaMVKc6ws60/8xsdB0DYXiynotAg6nd4bhzWOSVe25S6x6W5A==
X-Received: by 2002:a05:6512:21b:b0:4bd:5210:bd97 with SMTP id a27-20020a056512021b00b004bd5210bd97mr1254663lfo.25.1675410941444;
        Thu, 02 Feb 2023 23:55:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10c9:b0:4d5:7ca1:c92f with SMTP id
 k9-20020a05651210c900b004d57ca1c92fls3002406lfg.2.-pod-prod-gmail; Thu, 02
 Feb 2023 23:55:39 -0800 (PST)
X-Received: by 2002:a05:6512:23a6:b0:4a4:68b7:e736 with SMTP id c38-20020a05651223a600b004a468b7e736mr3500181lfv.32.1675410939251;
        Thu, 02 Feb 2023 23:55:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675410939; cv=none;
        d=google.com; s=arc-20160816;
        b=CxUIO0Vj5TgWIIJWI8hS4MFIytwbC+1CW7AJR7ZtknIke2Pt6yY518Exc722Lpqqr+
         sxhkStnW3dJ6Enw/0V6MXzyEx31pjbKbS+JhlP3XmfkhVyp8KjfiLv3wyLXZRMvSxLv5
         O1BwzculpGJjTC+oso5xjYNs8YSG1gAAlI9L2xSaEol7SU+sPTryyPh2vJW9MwhKRxk8
         5vWUWAezAD6fkb8VHkQI6Sl4a8y6XAkBABn2C9JD7vDjd+qhgcGjyaGbTk3L1K926/qg
         NEbSg1ZZqCBTd13lYa3nBA9yr44Vib39x1Ae/yZiYDPtDrzCvSLSxESyR5Zh4IBzMQ+A
         /4rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VzLCWkEIOjhYvr7p7s7uKUj96vyQiWAZD9+xORl+Fd4=;
        b=uq1OxXZA2Tkpkxf5+yvqY12dPvwPWJpK4Z+Pn3O9yPDLKhd40zlyHpcjQr6jOtNHQ0
         oqZm6juEeH5FwEGUNk2SeBVisOCemiAeDQ7Ad7C3kiXccKm88Bg4cmQSyMUa9JWn1lxu
         IMQR5vk9lG2wHctZczDmanTjDzZkMPFar8crN5bydzWu4c6fK/wlYsG79qw9w4mQ8EmY
         AAxG7UJMN4NWRnC2qCQRaX2pBY/VLNt5zHhkfeV5mVXpAvYtw7QQ4zhhjGZfukdiGv4n
         pKLXpBfR3zQoFjqHP+bQO2nxCzhCfXwMxg9fkTRnygqO2980y0ftMR+3MTSbo0TbwRVL
         jwGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=RNbsXzhK;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id k15-20020a05651239cf00b004b58f5274c1si89279lfu.1.2023.02.02.23.55.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:55:39 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id hn2-20020a05600ca38200b003dc5cb96d46so5392079wmb.4
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:55:39 -0800 (PST)
X-Received: by 2002:a1c:6a01:0:b0:3df:de28:f819 with SMTP id f1-20020a1c6a01000000b003dfde28f819mr4504287wmc.15.1675410938775;
        Thu, 02 Feb 2023 23:55:38 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id q9-20020a1ce909000000b003dc34edacf8sm6820254wmc.31.2023.02.02.23.55.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 23:55:38 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v4 3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
Date: Fri,  3 Feb 2023 08:52:29 +0100
Message-Id: <20230203075232.274282-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=RNbsXzhK;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The early virtual address should lie in the kernel address space for
inline kasan instrumentation to succeed, otherwise kasan tries to
dereference an address that does not exist in the address space (since
kasan only maps *kernel* address space, not the userspace).

Simply use the very first address of the kernel address space for the
early fdt mapping.

It allowed an Ubuntu kernel to boot successfully with inline
instrumentation.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 478d6763a01a..87f6a5d475a6 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -57,7 +57,7 @@ unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
 EXPORT_SYMBOL(empty_zero_page);
 
 extern char _start[];
-#define DTB_EARLY_BASE_VA      PGDIR_SIZE
+#define DTB_EARLY_BASE_VA      (ADDRESS_SPACE_END - (PTRS_PER_PGD / 2 * PGDIR_SIZE) + 1)
 void *_dtb_early_va __initdata;
 uintptr_t _dtb_early_pa __initdata;
 
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203075232.274282-4-alexghiti%40rivosinc.com.
