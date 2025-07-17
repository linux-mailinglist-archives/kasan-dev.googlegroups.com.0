Return-Path: <kasan-dev+bncBDAOJ6534YNBBAER4TBQMGQEYPXBIRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5984FB08F47
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:18 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-32b378371b1sf5677111fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762497; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sloq+56W4WVXyHGbeAIzwzegDoMyCnEifFP3aMPpPelLl6dfYI5qUxmYG6J1z6bThA
         jv3cZrnkH6BEUv9gpm9d31CEP0eQKdCnxzOxVEI5epvNZzd0dyD5zYaSrD3Ik5chs8z9
         SgLZyB1jkk/kvocYkbl1uA6RZwrjoWvWKNQFcFikfDiFEPl9DZqQ/Oif0uT4sH5/Ssw1
         GyukGAcgj8HsVv/zMqImRd4BNtRgeJkI615PJebshuWBBD12w+3Fav8OeiDDcAmGp/em
         nsBlBfysC1omwgLMr+Y8Un3SAeqJ9mztva6N4Oi/3KzMl33DWKCGhCYDcDIy3lLb/ngR
         F/Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=JO/KJiU0ROMEenxr6fV05dTBSemqvkRNCP0OnetdKy8=;
        fh=rIctw3pG3QkQDX6RSuyb9c60sQ2rK//jFx+SG095t0U=;
        b=Mr8ibBDAnNc7V6gsTbUas+72xwtwGuEpKkejc/UUOQNdSeJrTU2oUi7ONS8F4PIg0o
         VgQk2SMAqfuXtqBoK31gNN+5AE2BTyvPQQCfW2GuSfNghhffj4QKHWoxb7Xzyfu2Ee7I
         G5MSTC4VerB0kGyPTQ3NeUkZbP3b5HZj9M8tIvgTo6nb1X5pNZ7/JeDunRDQIfXl8nhM
         wo5FjtOtFLiQpJh23IVX4TsDFebwd88pATO+6IP6Z+UEnPRfJG12vAPj8LNp0qQytlaP
         UoSBA290LZQaO457FrECZGYRo87NqaKGehI3k4Zo2xsEiDwcXejrEqjZHGwJqGwIqvW5
         815w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="anDj/0rb";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762497; x=1753367297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JO/KJiU0ROMEenxr6fV05dTBSemqvkRNCP0OnetdKy8=;
        b=KYeOTAtbblehkzBJVFxcUVQ4iknD4Php46Zhb4+mrk1OyCyVLOFe+EFdHbVzNAJL1T
         UXeBLEsy49TsZIO0NNnWw6lwQ/KxLtM3Oj+GUO071nRIPDyJZqBkTW5F73TEDTx8qKqr
         YsT66fyKaFuhL4I8C2fiAVMByY47VyAEdooFPitLUzzJ7lbnPFUdnf7xEw8ku93CLytm
         yz04vIzhf5wFrr5XvYk8rkV2/bmTHpAc++YokROg8NPOcE+Hz5PKARUqWQF0ZN1y8E1M
         aSd4n0ZIb6iP9gOeHoNr0QufytaGYFHRH6dckzS0eHDrC1BnwNHICEs/TctNXhDEJ404
         MVHw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762497; x=1753367297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=JO/KJiU0ROMEenxr6fV05dTBSemqvkRNCP0OnetdKy8=;
        b=TbuOmOoohf9qjahZhsozw23T72QmJnQ7b2UlEQr+Toz41T+7/TeAkhbVc51htjdBM8
         aDcx6yYzRYKpQADPXEh+st93tcDC/RA+J+MsV6aRtxQnAFP/mO1UHqJTo4qpK97/V8Hy
         unim3ofdGoqE8gExywtc12IXx9B+qpIC2Ykg8o8u9B9TevWPPLvLvxrXacoDExmiBjU7
         q0BSjG28gJBurCLQBGbVa/IT1n6x7jeFHk+YkfdIyVRC+WuC5QXGXPrwPUOnspELpgOS
         5w3vRrp90LchOnppYAPb5MMwOFny+vr/Y9H1LZ7rdCp2/P0L925Lr7YW26TpkVPnRI37
         sZNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762497; x=1753367297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JO/KJiU0ROMEenxr6fV05dTBSemqvkRNCP0OnetdKy8=;
        b=gaRT9Vk1aqWNzALJaDZEVjtY+H3u51RsECmGYDShn/c/nI7EcTu7XBT0h+hfkgl1cI
         dnzDqbtPB+mBpA5//SBfrdJ6AkcLK3Ik6h2ExJAq8iPattTa7re1YTADra9NPcfIT0xq
         /LBjsfc+ZZ92OPFtEW8KdZP8K8AKGOOEniKYNUnwOz6CPpGW5hdQRaWb1Cc1Am97tcr/
         sFc1TXe6b2TUdXsKod1pFVXV/kVD8NTm9oeVtX8vm6cBTK0KveCuxxo2n/WqNNO1dsTT
         hk5GzKO4aejwCO3h51lCaAHYXoWkQ9VaNs595Ac7xB0OyVbBrufExMpYt8RRuFFpH2HN
         DpqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLWwdDxXekPWexOfxPVyNdA2D2ykrHe2xVOHSVX9FWDwz7rPMnypQySEFmYuEbShWjvl3xww==@lfdr.de
X-Gm-Message-State: AOJu0Yx7t3rR6R+ESXvXc3GecQEwMSBJ3uxitVjd8O2i1QOzQLXvlQ9t
	wyKnXMKwyHcTJ64aaYaG2HU+nj8xM+JBJm4cLYMqbNq6mrBXl7ZlvkjO
X-Google-Smtp-Source: AGHT+IGBFddxJZIQ4AVLY6hxu03IHQHH7v156zZX14Gy455xRH0Q2c0bjT2HQMRMVtxO+YnEOnr7pQ==
X-Received: by 2002:a2e:be90:0:b0:32b:9652:2c04 with SMTP id 38308e7fff4ca-3308e50e728mr23394351fa.33.1752762497329;
        Thu, 17 Jul 2025 07:28:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2o0VKRCUSdCV8XmA6b1D791qAb37i+1OZXoMw0bggWg==
Received: by 2002:a2e:aa1d:0:b0:32b:2c5f:c18f with SMTP id 38308e7fff4ca-33097e7fa64ls3512011fa.2.-pod-prod-02-eu;
 Thu, 17 Jul 2025 07:28:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHevqGEx+zTRchtgA/O03Hp102bAGOUkScK5sl+50inGrp3NGIHAfmVraII7um3cXSMUEcKjm0U8Y=@googlegroups.com
X-Received: by 2002:a05:651c:547:b0:32a:847c:a1c0 with SMTP id 38308e7fff4ca-3308e1c625fmr22882321fa.6.1752762494291;
        Thu, 17 Jul 2025 07:28:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762494; cv=none;
        d=google.com; s=arc-20240605;
        b=dPl4KYW1LF0Bs+ynB5IzEFO6/L3qrruq1/gjJxg3WHEWL25zNDgmuhJb9w0xHgRdZP
         J3eGA1ojHb3ibl3BfTu1W0l/jTz1+Ry9jODuCAFqnv973N2JWX54c/4IiKXK+fG3T0YO
         nkxHbZEi9T0IRe4anw0Fo101oscd2nU8jM2L0lSLR4E7xsUhLx6/mN9n3RrIyIZZhmJ0
         +ND0e1XO9qOeubO3+Vyv7u+c1NuTDyCDf0uAcMKnz0xq/fpilPCjjCoM5pFTWvfegPtl
         j4EwCAU8RlWsmsuNriVXS3ZwLTX17ah2STJmrzXT8UUVv/0JvVvbEiYFV1s25kVlHU4Q
         86FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xwSPw6gFzDTyOsOkroA5OTCCxXe2CzpjscG8NASBaU4=;
        fh=ee0tbF/jqILtmiHD9oNOMPt+ZtvIugE4+Qm5qbOpH/4=;
        b=C3tP9KA6lUdkVaNnVxA7aChOHmNxdZ4QWmY2GwjPSXieIDXv1ZzWDTKJLBqw5qQ0le
         rmd4zVnGaGlrZzRNiZaNeGRneCsPEFdrzplaSSRvsj6CcANkDIM3RSFv1lImF9p0C93M
         xHRTrSPdlH4cC0d0di8s2ahnYkRU2EC+nAGARPUP9f4ORBq1owyq5ipLqaj80RS1h1lt
         kULi+TshtDvFGwj9SB7+PV/gVbPrxgh0N4Cr22g1R9mvIAg8YIT2hsfq73HPxE97uVvy
         oWOQSgQs7LsNrLb2Nc8RQGjLFckPXTu7fzDIKhCtSyc/tLOLlqSN1ftXL9D8BDIAJWIC
         RkGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="anDj/0rb";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa5d91897si4720681fa.5.2025.07.17.07.28.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-55628eaec6cso934925e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV3eQn3WzN/d/cYv6nlAwmyZH7fJ8YuAnIz5Hztv9PjFgqA9/ejpWTJxOfVhubeySFg+LKarO0iY0M=@googlegroups.com
X-Gm-Gg: ASbGncuOSlq3qBOuFjJ6uiqQ5SEsheWHmDt3WqizMx5YFehzql1McsfnjLScqW7rOwU
	ogC+FMIUl6gSy+GW7U5tz/HTBu9W9m+4SmTSDHLw7p98g4sBVkr3wjh2Ixz+fRCC3O3/EQCaMPb
	qfMAEXM2ULiu2D40s7mqfOULUE8WF1mfKlfFqvQs+nzdgvalCUlVshwi9qsDJR7FO9dCobDwGBS
	qPpxtkqLurGx0b9EnKioi8HG8Z6S30L+jdKtfX2khwB/PxMzbja8UOw961NxiYLC1hbCL668/kX
	x1W/SuCgA2rmRtecNUpOzW3FFfNsgNNWZ1Qr+TcrWYvE2WPsWcH5iwN051PsmEga1SJU67dcsQN
	5m+yow4gnUrovv8ea/06IcKVGmIzaDNvo8tWOgSEawa93FaHOhUT3E9fGIjTjUvnBbZ8x
X-Received: by 2002:a05:6512:3710:b0:554:f74b:78c1 with SMTP id 2adb3069b0e04-55a233db3famr2128904e87.43.1752762493542;
        Thu, 17 Jul 2025 07:28:13 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.28.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:28:12 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 10/12] kasan/s390: call kasan_init_generic in kasan_init
Date: Thu, 17 Jul 2025 19:27:30 +0500
Message-Id: <20250717142732.292822-11-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="anDj/0rb";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since s390 doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, and kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

s390 sets up KASAN mappings in the decompressor and can run with KASAN
enabled from very early, so it doesn't need runtime control.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/s390/kernel/early.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
index 54cf0923050..7ada1324f6a 100644
--- a/arch/s390/kernel/early.c
+++ b/arch/s390/kernel/early.c
@@ -21,6 +21,7 @@
 #include <linux/kernel.h>
 #include <asm/asm-extable.h>
 #include <linux/memblock.h>
+#include <linux/kasan.h>
 #include <asm/access-regs.h>
 #include <asm/asm-offsets.h>
 #include <asm/machine.h>
@@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
 {
 #ifdef CONFIG_KASAN
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 #endif
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-11-snovitoll%40gmail.com.
