Return-Path: <kasan-dev+bncBDAOJ6534YNBB4EQ4TBQMGQEJDCV3EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E055B08F3D
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:01 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-451ac1b43c4sf7262965e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762481; cv=pass;
        d=google.com; s=arc-20240605;
        b=SjLiMysHMJ73DN1j++YXh61uQN0Ov81E7iUuR9Q6zFb9wBsD8GlInXDkFXZEkACuI/
         7HJw5V3cXxB57eot6d6jPPs0m7tudHhoTNAO1o5ieJ2JHNXTi0LVdjLTMo9lcYOR814V
         Mpkz1jtzQBORanNeh0EB/FHjMUyb69fRFUspH/AGpEKqGYtsDSeAyW37wbhk2cYmHmsk
         4EQbCCsSgMuKtMmKt+Wl0FVB5U67GJjWYyUOiyDcV+0lFGfSoU/glzfvwRH96YDTXLm9
         G2NgXcZSAaF6qlqZ3Gn05xNMf6oAtKFIuHsReGU/5y6XZfrV3Y00W6aj2tlpss06MhuT
         qclg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=CxlJOzG3y+F90WB0fHucOoQFaZtEY1RXS9eKE9cITDU=;
        fh=7cXZlj/UK9YudHU7+snJGr42aGzMSyUMHdABPDI8rj0=;
        b=KQxmwmCUJY68fBOXH1zU+1dcuyryWLQ+04bf4ERKWeyGv88uqO0nM4T/4FsdFo8FEN
         w1tExa9f+/F6KAhbq9qWVJDqlDH1JOoUEYnThJKkEk6GpYw4vwDdlb4yotduZCtQ0upR
         BEPxo1ZC0uW7ezkrUYMAmtT8kloItD5QKJiUHVN9k/eLH4xO6gQINnc4J4xUdaLkqe/0
         Z5jFIDwLo/asrfSXudKJq8BnC+S8Vwlk05msMPzhFHhQ6/bMAC7Md7+YbvBWZzZpFyvp
         Xaw8KLAHGRRBxFgFmjzEJR8/VtI0DxjjDfR1IgypqilxCsgXLSHCvORR1OtWl71BDn7a
         L1Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="TSHE0kG/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762481; x=1753367281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CxlJOzG3y+F90WB0fHucOoQFaZtEY1RXS9eKE9cITDU=;
        b=fB611+Eo+mr/PlVODiDr6JIGUeYIs3Kxlg3lBkK2nv5keDEJnsJ89Sru2RsgC6imJQ
         wh8SlVO1wEpYT3i2WPwltn7KaoMybxLfxCgf4cpZMLI5wK1T4t986408q8oO2Evc2uGr
         aUZOSN4piMTgkpKwk/IV9qREfux08yNHvGot3w9JZezQBQftrTGw4VvIQIA8xN4Enerk
         zJDxqpUgPsEad8vYGwfzon+nKwctmy60yOiUUdvBtO8eZpVkpPwxtTKs4dxpMHy+fjAw
         W9CF55JV88FYiNKIa3VxzyARLghreIGdkWLe5OcL+pgdV+X5xgDyEHRIaYCAGsj0KoYp
         C9Tw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762481; x=1753367281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=CxlJOzG3y+F90WB0fHucOoQFaZtEY1RXS9eKE9cITDU=;
        b=ZpYzjhFF5ygElQhM93IjIjR29dAWfbzcRGqzcfKaHOsefGg89eC4qQILiEBO2u92zL
         wsfdST5XY9Vd0s7PEg3ty1jHZCVaqQPY118Mi/4rX3VcILJLjgEK7y2xd3uvzZc0rWsC
         JmbLEfVLDZX05fTfAGCqHkPxOOgUTncQ8rQvLiuP4xAgNPjUBHSY0VWVPSdC5aPH8jCa
         2QNilAjfcnw+la25sw1qajxh/yExxBoePPg1/zijyJ1N2y5W75UlNNc2nhQFWOrwLFDn
         7cKCFMsdBb3R4iiBVL4ESghUILYsLDC+3FUsdrVPPMPhZwr/ud3MTCBkeJWbXaILH8vp
         BeNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762481; x=1753367281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CxlJOzG3y+F90WB0fHucOoQFaZtEY1RXS9eKE9cITDU=;
        b=LO/fYY71esuB1zsJMGPiEpdjq+IBBOjDl4bkteBN2kN7UZ11XnH/n48ptVBJGogk3q
         b9KMOpSZ5y4pmYPm5g0UIg3g5wItZtT1vj8S6TqtNYAzr+yjMiEf6zK69kMxaz+J17iz
         luHxtk8GtX3/T+QRi+PA3Hvgb9XCPnzzbAn2KyE9Zf8/dUEPQAshuDwE58ki7/CTbhz8
         +wbMO/jdJ/dGL1vb9MuaAHAjhCG3dtu3XkH+Ml8nt7VFMVmoCj4IznTQ8DkVk6qr0KVs
         +ZfcWLeg+O9k4fB4fxxNO0VFxamuAWju0IPqQ6vWQIO6Oy+g0Hygltsk3SMT3PtAbHmV
         3yuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXP6q8VYMNhwpDsfVY4/0oUR3S2+G7mmBUYYO2vzOr/7gNbX5qxP4hvawBTX3cJC6JEQK8M1A==@lfdr.de
X-Gm-Message-State: AOJu0YxJJW70ivC5hvcBg+4OwyesL2e/fQFjP6Xrh2Mkv1JVmJHM50F1
	qA34HJn4bg4rPAgm7ONY8eK7j3avRlOozO9YTB1/Q4WmUaMzFZqd+KpV
X-Google-Smtp-Source: AGHT+IHOyO0fAYS2nhOnHDQFKD0DVp5vVfaPeOcyr5rGmaEwWJ8cYGM5NbySbAT4fj+Nh/gq1ZYKMQ==
X-Received: by 2002:a05:600c:8b70:b0:43d:46de:b0eb with SMTP id 5b1f17b1804b1-4562e047122mr78350305e9.12.1752762480802;
        Thu, 17 Jul 2025 07:28:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEu4gXuqJ9UIZezcnSmrcUnap8K2oOzIPIqXrPPoGMNQ==
Received: by 2002:a05:6000:22c4:b0:3a3:69f3:7921 with SMTP id
 ffacd0b85a97d-3b61377e17bls585664f8f.2.-pod-prod-04-eu; Thu, 17 Jul 2025
 07:27:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/A7uadHyZtttzg0y72Td0QijPwgeUBKUiyk/DbWGyUpbYHtT0MZ1jsqUnqh7JS/q7DY1SyLAdap4=@googlegroups.com
X-Received: by 2002:a05:6000:23c5:b0:3a5:2208:41d9 with SMTP id ffacd0b85a97d-3b60dd8781bmr3803377f8f.40.1752762478100;
        Thu, 17 Jul 2025 07:27:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762478; cv=none;
        d=google.com; s=arc-20240605;
        b=a4oU+VuMuqroRXiCi1cnkO4moSTChklVrVlFMz1wFi2jeiUZuKaPoQTVHYg974SH5/
         fWBXkBdPD3oIVCxgZ0mYovJ8inlFV4YUXAgyfk0duTXpsllciHdCNSIKAunZpnGB5Qik
         dTLBjpr/nBsvuJO38uhBjeODryqnFCCI1X/0FjfuBPBl8jKv6yypJzhy/nVv17x2QaMm
         7n7UzbOxlAnq0nCrZBg0oQP3GbCw9kajZpDLZY/kR0BQdSWM0Xf2SXV4BFnaHlayV8zD
         XLWi/qPLCQCot/fE4UUk2+jE65K8L96EEnfZkBj2RBgXBts/r/pTB5nywwdAJk44dWlt
         PPwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tj0938MKzJL3dLX2pSfruVoI7qA5XRt5dsqIl4I0tCY=;
        fh=5WPTxprzEpACBwcnb2IMylRQBCTWyXgSHXCgJoNiTh0=;
        b=Aky8FZ2s5bKvGIodKUKzi2ja0xxmWDsr3IRdHkFKTCwvChbdWxWVMwTk4aDkMnANk3
         xAKBZwK/9yuIp+RygFUigAdCQw3io38P3BO5cW2Au1ImDFJRRcVmX1EpUIFFyqNIlgEf
         wWNgloybo5C9zTtBJOhCVifqrIQY00JkvGwNLObCFUOcDzrJZT8dGeu/SUm7K5W+0xGf
         Uiii3IIOStJo9WvrbDbmaBaTIR5X+7assPzoEjf4DMWnE8r1GVqSUtEYK0XiHngMf1Kg
         I1+YWIMvrON8c7VQG2at3h8ZUKkGlIdcV69Lsf2rVB3nYxHcHNabZRgRZj+QqvZ9DrW5
         jT7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="TSHE0kG/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b5e8e09053si217245f8f.6.2025.07.17.07.27.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:27:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-5561c20e2d5so1339169e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:27:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWdr5PJ5bKZkkC/hZbx/E7upwkNl7VvZja5sCCLAyxHiFb4WHH/SJbWGrYQ8kgggWVf/zkihopJc4g=@googlegroups.com
X-Gm-Gg: ASbGncsaqEb/SdQ2OQpvzN9ZJPlL8EutsZUCM/CtjU47WsFxazLJ3lHTEuKyZErej1C
	uCSqxa9aGQvaPaEspa3rF9TQ5xqfevl8vl2EEPLyQTdVKi/40IKdZrg2pfmL9ndpcyjfeFuiI+S
	lffhSfNtFtbLKGg9JoUamACJnOxr3ZWYM3IP52HBHBpQcAFXBKUUGbihdjz8KcaoIr3H9YElXAt
	o1tnYXWAzk8n9AL1doATUpsU1pEuVYvg/NgdagzxxuOjg3ooTwdUg4UUT6QNnXancBjKs5DGrmA
	pnwfDh5McSAbR/rtJYC0s3e3bilLytntrQFLvTpT+Bku6DUorCgHcbdVW2u72blTabMQBZopxRP
	NzSRbCTUuUwrcqFwJvIcVRMTxyB9Y++Y9nh+7st3HT9s0GVoOaFnSghOLusMbYDjXTnDlDNKKCl
	It3j0=
X-Received: by 2002:a05:6512:360e:b0:553:d12c:fef7 with SMTP id 2adb3069b0e04-55a233137ecmr2448163e87.14.1752762477204;
        Thu, 17 Jul 2025 07:27:57 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:56 -0700 (PDT)
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
Subject: [PATCH v3 05/12] kasan/arm: call kasan_init_generic in kasan_init
Date: Thu, 17 Jul 2025 19:27:25 +0500
Message-Id: <20250717142732.292822-6-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="TSHE0kG/";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134
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
and prints the banner. Since arm doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, but kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/arm/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f70313..c6625e808bf 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -300,6 +300,6 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
-	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-6-snovitoll%40gmail.com.
