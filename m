Return-Path: <kasan-dev+bncBDXY7I6V6AMRB2V35OUAMGQEHCPCHLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D65C07B561E
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Oct 2023 17:12:44 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5042178944esf2769918e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Oct 2023 08:12:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696259564; cv=pass;
        d=google.com; s=arc-20160816;
        b=o2Y1kBg/I85EAhpgfzQPm1/jRA3kSF7JpcRxxb8uRV0Phzs8Vi2/7eGZ6bd3XXdwXq
         ogCQChxWZSTpXj1FAwHbUwa0TI7Xf0mC1DK794ZfTFStKyLQkJBsJNl+0xf1/N0itTsD
         fxnhcRMfLJKUqn/CHKUyXDUtP2H9lGmFlYGcNhwmUUAWndTmtLvEkx9oDYTjIsNYCTfM
         IBcxpDVHqWniH57CLPMwuJXUckr8XrbYL24uCNRwt2CpEmeey7sMa6RA5mosPhHszjGc
         pJicNqYxvap+EUSR98bzd0IuLFriSzggoh/RAxxaoY0l+UWqqrQnBFYvFfVQTS8+6pIv
         qYdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bHi9dZIaI2vYoUrkMFc+WeqXtbiFyOWqZP8OU4kGuzU=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=ydNm74kjiaOJF5950kI1IWZfP6/1Sm+dcFyjdUnU5TT8WtU9P5C46v/oY3owbtypxB
         vAqassAhLkuBDYkba1cqfDKoUPwQzKpdC0yVbsMbaw4lEWs96MGzO+KIgECoKNmrKSvj
         3Y2W6v24PnMztRqzcXJ65hvFPwuCuwqGHLGnjS0OC0VECJcNHgb7Do1g9rKHHMuj+rnM
         sdUOOXf7/qfOglw6kw6Ay5aJGbK5oBUmlfCx+JYMYkn4bQW8c0XO7R1UdHFwqPHKt2nz
         7waVhKNMI19X1Uhg0RYYpzaR1/XyXB4sX7zlNGyYMFYOd7jWUi1+682QnGWWu2LZ8tGv
         z9xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=0BR0sy98;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696259564; x=1696864364; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bHi9dZIaI2vYoUrkMFc+WeqXtbiFyOWqZP8OU4kGuzU=;
        b=VueEEATTC55VIvBxezWCoN7UO8N7+idHo6g7rTnmLQxr3Jp7qaDSDkHdUzzThRhMpH
         s/hc+ge2M9T+fMTaUQHusrTffIPO6MHqr4Ba9uDjFWJfv32EgjOKC+qbtc5uVG714IaH
         KBL7yDe4OK9Na5DGAvk8UR0c8wbAjZgFIacVjBrEpx30cb3NZS2+lo1ZCNMmMBsVrMFd
         v7VQG+POan2Z6gijCvjXNQZZpVcFvWlGvvsPxt0nus9mQTJb6zdij1PTgFUlTu3rQ/by
         F0kmg0XmiV09HZOT62Qeg57rqbxcsYgdPXUl9DVS0wC1NUlGSGQwF+D43CUKOTjHk/d+
         +JVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696259564; x=1696864364;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bHi9dZIaI2vYoUrkMFc+WeqXtbiFyOWqZP8OU4kGuzU=;
        b=jq/QC/JqjT51pbUIEDSNCmcnGTzD9ORYxoxADJYGlmDZ4fWPzERjAtmE6oHFb4ZUSw
         J4x98z+9xyGKM4Nnn+a/y9r1c1x7Pa9AYbRdCesqKjnfOPibHXoY/R1QtamoErTjlBmk
         BaSlNvUy/uJMESWyUeJrXAkHSj/AjyEu2zUuze+C1b/NauN4rFsVfmLk+OH0Q6X7pDj9
         Za31/0cXGOgoCrBvSfXCudZN3WUHrfdVKkmY7I+ij8j354QNNxbKcNSpi7osc7tGQQBp
         cl2ZdYgv1HtTDrq2SywbMv2BlampR3SW7a8wm2+RgaSp0nxKAoCGhHbp9XqkdSipYJbR
         J3Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yws2PA8Dz6gI3GqWq5QdYCzbv8r3rveTerpqVavNnNpY/14/hx7
	2zc+KirwcJx253lNPhJc7MY=
X-Google-Smtp-Source: AGHT+IGIVOhlqxg0N6xjN9WuKFZOAc22nas2ryU2aa+1VcaEGkuB7OpNp7KHtaHMeN16rsDyUVzU7w==
X-Received: by 2002:a05:6512:3bc:b0:503:224f:9c55 with SMTP id v28-20020a05651203bc00b00503224f9c55mr7344361lfp.8.1696259562707;
        Mon, 02 Oct 2023 08:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d06:b0:505:667c:be15 with SMTP id
 d6-20020a0565123d0600b00505667cbe15ls1163604lfv.1.-pod-prod-00-eu; Mon, 02
 Oct 2023 08:12:41 -0700 (PDT)
X-Received: by 2002:a05:6512:1192:b0:501:bf37:262a with SMTP id g18-20020a056512119200b00501bf37262amr9840445lfr.32.1696259560990;
        Mon, 02 Oct 2023 08:12:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696259560; cv=none;
        d=google.com; s=arc-20160816;
        b=CIhT46Me3kVoFxq824daOXMGaPPS3U9JSZanQEt9+l/Yh9DJMJM4mhuC1cDpTvjFau
         sgg7dKzu7No3RSgYPvYmg6PPDdDOAXIaBUKorKIKIdjRj46CjHMFAyEP+vDp8J26R4j9
         3eZ5T+RYWUZy0E9Y57CbNGYeFhv7Nf93vyFSR1ecnjibFAtd8X20tC/SqW8wn2FZPvCx
         Q8jsat0wUs/eRAqF2jV5OUX7WvlbeXmGo5hEmoH/P+iVLl7qN1TOuQKGgDPAp3yN6pz6
         En0oVXuDARSSJjaw7NnVHG260XyHPTweIu7QT1FWCIYzXIXRUpdpBdf2YEhNBMtmbqT/
         yeDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WAROWeuegt9axYlR2gFhUBC1uOuBg0VWiNfGep/WqRA=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=lyUjuz3Gct4Uz8DiRy+SBRuk0wECJbIVIt+rB5qFnnVxlcO8KJ93t/dWUfW+AXN2A4
         Lzq4Ni/S7bk5iP8WclM6yCubzfnwG776ZBsvwGFuZeMtAywpl/v7UzV4Pjs8QdEf1Xsr
         UdhcBzlu63y/xQI1a8gZcG720lsN1hbkgQJZzQE1lc8dm69KhdKqR1ckdHCq1KhANprR
         jamN1SY1/KMSa7ezHa/7floYKpbsdWUw+fBOXsxKc6jmNpOWPKcpqwltWxrTJx/pn+Ix
         e1fopQOIfl+Gin0IB27s8bR6Eoh9t5dML8psCQJ7qNvPKSayZqvAdQyx9cMsd0S6Q4+O
         rElQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=0BR0sy98;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id f17-20020a056512361100b004ffa201cad8si1635443lfs.9.2023.10.02.08.12.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Oct 2023 08:12:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-4060b623e64so19761325e9.0
        for <kasan-dev@googlegroups.com>; Mon, 02 Oct 2023 08:12:40 -0700 (PDT)
X-Received: by 2002:a05:600c:5022:b0:405:3f06:d2ef with SMTP id n34-20020a05600c502200b004053f06d2efmr9800701wmr.4.1696259560252;
        Mon, 02 Oct 2023 08:12:40 -0700 (PDT)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id l5-20020a7bc445000000b003fbe791a0e8sm7507939wmi.0.2023.10.02.08.12.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Oct 2023 08:12:39 -0700 (PDT)
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
Subject: [PATCH 2/5] mm: Introduce pudp/p4dp/pgdp_get() functions
Date: Mon,  2 Oct 2023 17:10:28 +0200
Message-Id: <20231002151031.110551-3-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231002151031.110551-1-alexghiti@rivosinc.com>
References: <20231002151031.110551-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=0BR0sy98;       spf=pass (google.com: domain of alexghiti@rivosinc.com
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

Instead of directly dereferencing page tables entries, which can cause
issues (see commit 20a004e7b017 ("arm64: mm: Use READ_ONCE/WRITE_ONCE when
accessing page tables"), let's introduce new functions to get the
pud/p4d/pgd entries (the pte and pmd versions already exist).

Those new functions will be used in subsequent commits by the riscv
architecture.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 include/linux/pgtable.h | 21 +++++++++++++++++++++
 1 file changed, 21 insertions(+)

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 1fba072b3dac..4ce68bcc201d 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -284,6 +284,27 @@ static inline pmd_t pmdp_get(pmd_t *pmdp)
 }
 #endif
 
+#ifndef pudp_get
+static inline pud_t pudp_get(pud_t *pudp)
+{
+	return READ_ONCE(*pudp);
+}
+#endif
+
+#ifndef p4dp_get
+static inline p4d_t p4dp_get(p4d_t *p4dp)
+{
+	return READ_ONCE(*p4dp);
+}
+#endif
+
+#ifndef pgdp_get
+static inline pgd_t pgdp_get(pgd_t *pgdp)
+{
+	return READ_ONCE(*pgdp);
+}
+#endif
+
 #ifndef __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
 static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
 					    unsigned long address,
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231002151031.110551-3-alexghiti%40rivosinc.com.
