Return-Path: <kasan-dev+bncBDXY7I6V6AMRBAE4R6SQMGQEPO67TBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 35173746AF6
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 09:45:06 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2b6a2a5f08asf50571661fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 00:45:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688456705; cv=pass;
        d=google.com; s=arc-20160816;
        b=LuWYprawewcb5UCKqEGKPZExoiRp9kF38ahYxs83wMMC/V996Iy0hP6VTk7bCBxcXv
         VKaNKq3Fj9dFR0lacKYvr4IcZzTjYWCYC1AbfFz5JndP4HaFY+yPhz6Qdr+VYPlHAqTw
         GuHmsz1rfNHBHGlt3G2eXyymMLQSwlYLK1qUUpRgHfnqYDixanndxQd72b5EcN2/EYMR
         nPBnWX+sm3SKcyF6W/A8azIJ54WUr8k4Sxs+BfeL6+NC2b1CymH6/ErH6X2v6gS48I3g
         4L/xPjvBsoZ+vv6qWlIRt8XWzySRj+DD2evki7xhxtqUEMLkQ7AHd3Mqbwt5jeWgNtmO
         hNhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Z8KETd0jIEgEgdI+H5J0BbsOmFB/7F1YogttA50gnYs=;
        fh=m9ijO+OVO+i4OWgBkHjDlhjqlShxzWjvLNAu8k2zcyk=;
        b=TqVtMGtrYR1nkNiZoR8qGCvar8upZiS4Fb7seEbmZ2RnyQHiU6fnPb/g5ao7CzuE7C
         PIh/WZwN1pqogO2FPMY3+r5vZGigoBznQtN2N07nf2nogwtF8qxyUDtuUUF9QAomeBRS
         CY2QsfNheM07S8yDaBLD3YBaKOwZPRRKPYY3NeFidfk3EoxwyP1OmbRukwNOttNTt+Ig
         xXpFpjRN3HjWE76D7pMayDb7fOeVBBiAD5TnRV6PODiKqEELuYrrd6EwjIKUSkITSc1X
         KSVDnuM6Z3sQ2YBMis7lUONwL6vIw8mcyW7OAFJpNsEFsCbTEY3XanoKPTGzDg7UDQGi
         cT8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=YBFkVrQU;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688456705; x=1691048705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z8KETd0jIEgEgdI+H5J0BbsOmFB/7F1YogttA50gnYs=;
        b=pUT4oiQxm5SWSoQfbI+nyj+KXO4P5OvzzTimAqQibrHzUEck/BxFgSomJ8nrSv18N7
         ZkMIwjsr0NkRq7/ds12N7ujIloZWSihtNBofbi0ZhuMHyLQ8y5xtWdFjLoinGPuIxoXv
         nh5jkmLP7uPhE6KWdfa1gY6PYfIjFBFRv4ZCPAZtWY14TYCQf9UVXpa7croNsoRVydnL
         xqHnatKB3AX63pBIb4NfJZts/gembextsPTYje6G1GuitzaaCFWEJICo9QpIpz6BGqGX
         NHhqZE0seyEQfWpRKBNcFmX2CYcAN78Dpyuv7pNzDyn164Th/sNN3JpEuT1KdrC+SIF4
         TFLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688456705; x=1691048705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z8KETd0jIEgEgdI+H5J0BbsOmFB/7F1YogttA50gnYs=;
        b=dX0usBuaA5xOJ4ZcwlCJVrfbIL36ag2CXlr1JBM7xiDKF/gXo4JbvQdGjGklGQsu6r
         hJHwOmD2ray4sC8SGlsM3kLtidJfvArzW6y1J152tT5OJMCcFgzktuDenXpRadoSV4y5
         zJHPPO7DEmfN3dnIifG4Jj3Vy/HNv1ckzjMxV36Z8uhacSwNoeoj/cBDbCRT2HsikIY0
         gnEZ5xw6+Id0AVFHJj6rcF+Sf1rOUlOwm948RrW2Awk3jTnTE7/Xdx1cBPB15jG4YDtz
         iRmQP6aIKybD3HG4+UfylzPDnD51FjuQ35cVFg6tXLmAwEXwwe3cozb2HCpL60/4hQNe
         b0uA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbci0r/5tbj6hXs47gjzfEUFRt5QZpGWY+WgIEj0E+pU+CHXHK6
	vVpmUk3dV5TKLplLIJNxbY4=
X-Google-Smtp-Source: APBJJlHTjOdK/3l1O7oK1nPCLqZSceO3fhYLFQs2SZvxyezA64zTkY53nRJVBnTDZCEVutPeCrOzGg==
X-Received: by 2002:a2e:9059:0:b0:2b6:b611:64e9 with SMTP id n25-20020a2e9059000000b002b6b61164e9mr8255813ljg.52.1688456704688;
        Tue, 04 Jul 2023 00:45:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc14:0:b0:2b4:5723:d64c with SMTP id b20-20020a2ebc14000000b002b45723d64cls2800113ljf.1.-pod-prod-06-eu;
 Tue, 04 Jul 2023 00:45:02 -0700 (PDT)
X-Received: by 2002:a05:6512:3c81:b0:4fb:99d9:6ba2 with SMTP id h1-20020a0565123c8100b004fb99d96ba2mr10413343lfv.24.1688456702859;
        Tue, 04 Jul 2023 00:45:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688456702; cv=none;
        d=google.com; s=arc-20160816;
        b=P45pLKCyedKQ97ytpOkyvckFSBhkQdH4G+wJK2NwSEuFZk/0spFAS/HUrLSvD3C1V0
         p4bZ911drfO5DZudIXmhChMSUmz1FfwFV95X8eYVWei7j5UZaVz0+guZVKyQ0LJYBRbG
         ZdXXYwehyLRYvU37uM7FDzqy7YTPSMJNsh1fY+xOnPBE9hFjMkrxFK4dcQU5HD1WGVcd
         99sqeFKH2I8cUl7oTJW6prAIaUI9A/Q5kkVgsyyOUHPrKAz+Euw3tZB9kx7UH9Osd4iX
         DwW6vGx/0X5bw6cdE5GOMTlMkOCz4mm+hvycN8gHTnm+dKeAUZxpCdM9A8KxWBUpK2o2
         gI1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=da1Ya2LZv3Pi8isMeSjt68UFYCIa9e30GSmEnk1v2WU=;
        fh=oUuWHtRXdl2pLIjz01E8JGLZlmXaVN4XvWpM/JVdRmE=;
        b=yjfC040bWtKMLjh2/cZMG9Tq0o4T9vSdSLDRNNULoCHppFhhAHkx1WWxQ3ptK6xwLW
         52WQsVqAtBnzfwq8xo236SwnTh5BjkMPLEh6vWEGk91wqpZGpT/gawQfDzGQ2qghAAcm
         Iuwx+UpvD9eKnqWyj6q8WomwmyXLioVfYe7gIxmqsPobJdIdw4K01w/w1KEPj7vUZpUF
         mNCC8eZsDY+ara8pjJTIbCq2qoFxzQbnkDaEKsazzJqkdcihf+ubBk7rHUv8Lf1HgneJ
         vyi2vyTwcr38oxUPydAYpfNAdiKFByby96svdTGykeLMux8W6PViJ8gv5UduDrppSe0s
         AihA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=YBFkVrQU;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id k33-20020a0565123da100b004f85862d867si1497921lfv.9.2023.07.04.00.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Jul 2023 00:45:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-4f875b267d9so8292923e87.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Jul 2023 00:45:02 -0700 (PDT)
X-Received: by 2002:ac2:4f0e:0:b0:4fb:8bea:f5f6 with SMTP id k14-20020ac24f0e000000b004fb8beaf5f6mr9893002lfr.34.1688456702503;
        Tue, 04 Jul 2023 00:45:02 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com ([93.23.105.195])
        by smtp.gmail.com with ESMTPSA id a20-20020a05600c225400b003fbb06af219sm17455668wmm.32.2023.07.04.00.45.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jul 2023 00:45:02 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	=?UTF-8?q?Bj=C3=B6rn=20T=C3=B6pel?= <bjorn@rivosinc.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 2/2] riscv: Move create_tmp_mapping() to init sections
Date: Tue,  4 Jul 2023 09:43:57 +0200
Message-Id: <20230704074357.233982-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20230704074357.233982-1-alexghiti@rivosinc.com>
References: <20230704074357.233982-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208
 header.b=YBFkVrQU;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

This function is only used at boot time so mark it as __init.

Fixes: 96f9d4daf745 ("riscv: Rework kasan population functions")
Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index b88914741f3d..435e94a5b1bb 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -439,7 +439,7 @@ static void __init kasan_shallow_populate(void *start, void *end)
 	kasan_shallow_populate_pgd(vaddr, vend);
 }
 
-static void create_tmp_mapping(void)
+static void __init create_tmp_mapping(void)
 {
 	void *ptr;
 	p4d_t *base_p4d;
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230704074357.233982-2-alexghiti%40rivosinc.com.
