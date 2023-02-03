Return-Path: <kasan-dev+bncBDXY7I6V6AMRBM756KPAMGQEYX76JBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8414268915F
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:58:43 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id iz20-20020a05600c555400b003dc53fcc88fsf2207323wmb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:58:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675411123; cv=pass;
        d=google.com; s=arc-20160816;
        b=D/CMEYOIZsd7tj2RFiqauMYKYPL83qELwjAn8WCOXxSqwK/wjczxMvF6dF7nMSHkAZ
         v0fwGlXs4ponqPLXP9151ZE+yAHNpkDHA9wzo4dwkAviclv42KjZQwAJ28dPZ6JAoshY
         Xvh9gqziienKacz3q5wLU0owfXi9J1rtkH1l8CNVXrdiTbbSV3pVrbe9l4DruoBiFiKT
         mJHeCo3D4BXKOy5Nbyc/8dtHpoBTE1sWsdTwUMqYDCuUEEGNVGmioVjLd43GqKI12RM7
         qdyQCT6gf2OF0gmFImihr2VytZHW3KueoCYB4Nz83HpOxvJ0I67fXk1Lj4Av2bjrYm1E
         Y2AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QNELJk+ntvlH9D3rytucxKBy0RoEwK/qtEt+A0X1LwQ=;
        b=jC/+57zecZUu3iF9It+Q2A94H1rGAX+lCTrNzH+dS1p4Efnt8r2pN7FEAMSUPZYmte
         ZhZ1WNR8f/RkjYFzpCAUm15cx6oQ4P1oqDnZfmSAKB0SyXUKR143oRh1Br1oAOsXL6np
         LMU9iw4pcee9EeOvfF04a2JMZ0OEdsETCViWGYTM/RLC2cA/HP49WscYceb1NvexdPRZ
         XudY+BRn+SRXvH43BadvhsnpNMw2B/bwmtTlXKHhjYyi7B8lJDQLgh78/oUrikBg9Pg+
         c5gvIlVEFioZma4u1KlBb8FxFtqeRJWm0NGRzc6IQFfjR0HYLLXwwIvLDz41tBiwvZ0w
         u/Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=zxo+RmsR;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QNELJk+ntvlH9D3rytucxKBy0RoEwK/qtEt+A0X1LwQ=;
        b=e7VVyaXkUGDKJDjpZNR4JKV0AFoXop2st+ag7GPEtBr24QirkRhkAMkFOA0nJM70Zb
         aj5jPbZ6G1Pd6KR+7Q0w+f3dy4iQ/PODehMZp2RBScVuPntj/MyLAotjoXu7lM3Vb2vN
         jelSml8pgWz/8qChFj9am2VsopagZu71TS/OQ8jAXKkEpHH5SfwCkjQ0Ac84bVWS+Wn6
         E/qzmW1oG/Ggx6Lt4kKVXZ9vAzfqDqGEijUfYSPb+dOnmTNd4bxGxK3jfmbX61vfG83I
         nu6yt8bXlkeefvpF2SO+efYsMQThX6Pi7jg+j+S674j6RR0MHohi5P6v7oHtwPZbJneV
         4uaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QNELJk+ntvlH9D3rytucxKBy0RoEwK/qtEt+A0X1LwQ=;
        b=BgxSWSvHz5OU03LcRHPOmq3PvYzOsTf3f/AvG0HYMJ6pl2uPtTatd7JvkpjUjADsFQ
         FFrvh+qgHmRyv6GwyDrwj1idchiHimkA5tJ1Xw8R2PLQ00vTHjYBRhhATFiYDQ4sYaL3
         KbnDp2stamrssThO7S+VTstoXT5/jyJNYnxXrbCyYeZX9T18R/WFhrnQqhCo49Qyc5mn
         tQhudIrl60TP8Ia5GDaGPoXAvQAreyuw9TAG8wlOjIvgHW87FArUaBybUtvL6+zmR1PL
         uNB/yzpYLuSX+04n5QxmlKrbLthPLXXGD18F81nfuTcIQ1n7ogXcpe/a8yXKkaAQRjdg
         UcEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVA4v6puLuK9ehl31hWdf03xBL1O9kC7VBBRgEe2W8586TIalyF
	zCirkFnCRFlQ62Gj3y8PXDM=
X-Google-Smtp-Source: AK7set9nxcWMMZtzTJ6tmEwOiosZhBsWoqeE8FD0suWF+xaJlCW+oQ96QMjS1VjacdTdXLsscZOLpw==
X-Received: by 2002:a5d:4dd1:0:b0:2bf:ad7b:ca90 with SMTP id f17-20020a5d4dd1000000b002bfad7bca90mr506267wru.131.1675411123220;
        Thu, 02 Feb 2023 23:58:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c17:b0:3dc:5300:3d83 with SMTP id
 j23-20020a05600c1c1700b003dc53003d83ls2389269wms.0.-pod-control-gmail; Thu,
 02 Feb 2023 23:58:42 -0800 (PST)
X-Received: by 2002:a05:600c:b86:b0:3db:eab:a600 with SMTP id fl6-20020a05600c0b8600b003db0eaba600mr8438804wmb.7.1675411121995;
        Thu, 02 Feb 2023 23:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675411121; cv=none;
        d=google.com; s=arc-20160816;
        b=tExEuJwGhoqxnqQ4FHu/8+IvjDnYvLxoQYj9074auikWGQIviRZmFVokcLcH0YL6Kn
         ZHJQoC06XnYGGFIwCbRDVOLYVjFSc3ppES2FxPspvCLgc0g6Wo2TZ+mJThXP75SyNhwG
         97Feouewcd6HjkWkUCi86K23r/U80aReN9cJdGTE/lafSe877s70108PYNyVg/bzQ7dr
         46rO9qRDrgeZd3pA9GdX0ZulEp30wWGMa4o72NFYCg0Cn76pwwr/iFnw5W8bO3isGu+A
         Ut9cVrJrJ+ucpKdo8s1aGpn1Bn6HfGIHIKzf3JmYrzLGXSt0wuw+YUbOGCbjEvcwQ8mz
         LHtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=871OGCI0aHwZZE6OKggKudWipUlPKXToB5Kn7OlT7Ew=;
        b=pCsC4laF/A1380WH7JzKp6ZdYt4kO1frTQSSfymBrjiq4mBY2HjwJOk+ySf4i1l/LC
         LLzPlKJS3+x3YRTi/MetbLMX/44oUQph/yQ5AoG284hPCyon8Bu0CHaqWeYJp2qHzz9z
         MjhPPNnkpqLc5lgAXSXvEcMgCDzc5fwVa++a8wB62qOJnI/kfDXT+0+tPuJIu2R3A/Kh
         LdtN57+nxNz54hBfpHboQxMBN6EneqOtt4A8tIESTStDTJDRRTsa9zu4mN2O2OIDPbkY
         yUkTVKohcjsPaE6l9AhMLOwfsLGtOMGMPjt5C9w72tHKofAOuFOQifMeyf7+w5PKPRs9
         Zkmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=zxo+RmsR;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id fm21-20020a05600c0c1500b003dc43c78e98si735890wmb.0.2023.02.02.23.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:58:41 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id o36so3216300wms.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:58:41 -0800 (PST)
X-Received: by 2002:a05:600c:cca:b0:3db:1919:41b5 with SMTP id fk10-20020a05600c0cca00b003db191941b5mr8877209wmb.21.1675411121802;
        Thu, 02 Feb 2023 23:58:41 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id v17-20020a05600c445100b003dc433355aasm2034857wmn.18.2023.02.02.23.58.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 23:58:41 -0800 (PST)
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
Subject: [PATCH v4 6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
Date: Fri,  3 Feb 2023 08:52:32 +0100
Message-Id: <20230203075232.274282-7-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=zxo+RmsR;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

If KASAN is enabled, VMAP_STACK depends on KASAN_VMALLOC so enable
KASAN_VMALLOC with KASAN so that we can enable VMAP_STACK by default.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index e2b656043abf..0f226d3261ca 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -117,6 +117,7 @@ config RISCV
 	select HAVE_RSEQ
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA if MODULES
 	select MODULE_SECTIONS if MODULES
 	select OF
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203075232.274282-7-alexghiti%40rivosinc.com.
