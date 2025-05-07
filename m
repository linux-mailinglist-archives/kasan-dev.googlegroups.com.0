Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFMH53AAMGQEOGMITYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D6E9AAE5B6
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:00:23 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5499de68535sf3658575e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:00:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746633622; cv=pass;
        d=google.com; s=arc-20240605;
        b=WQ57KL6A6Osu/QL7qbaNemYUxev53dcdDRO/7O1vlkwuQbv/bjzjRH+7uT6UJq6OlO
         2Tdj6QnSngEoyYqPUZHmb+OcSnr7kQkASzuzsyWXGhQzM0Xeh9hQS+Adf+7sMVOu7Jan
         5721gO/e5wo1ikJ+dSWhEDNuyHli0alzxceWh4h2xysBTQ1VvEpQgSfyhg0yNt/d8/Cf
         B0OQ9vAzOBH9e3ewSyX08rder4fVqF38gQR7F8yGJMXgET8ADEk0vsfbav2z9PDcT+u1
         QouIseTXIIbb7otPlSVhzk3VGIoJqL1WxBkYe/45ZC+X+chf1OdqVzo7SqJRfgR9L8ag
         or/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nuAgMpkbvYSJcs50k9haCICQBApil/laYkfKyEcFUtU=;
        fh=QRI/se+XL8hffY5ZV00MdsLrlZwViAh9ZLozVRMKOoU=;
        b=KQCT98ZBmTt5m+eB9x0AzpZ4BlOv2iu/uz19KXdXm43GNJmnSqxDJJFZyXHqRp37fu
         dF6CkB5HHNFD3uYUffNdlWwMqsCf/5dTiO/UDOHBrG7idoIA7HF5YNvPwvVf8CZlmlQ9
         95a28sdi2SPKKUTF/LQkpWpLbxr+iH7Qf8Vie5ot6FX1rDm9rBswag/tdNLX1vUPzuRx
         3+Y4Jpg+yxuNl9yajj6hO8fkN2tOnBUaSVgjW85MBzpaonwf8hEdbMkw8A543vaPdZ3/
         6jngEKPECGBWPt8Gm/f1BLq1nm3Z1dtJBgWG8Gu3L15UEonA518fWyegZqOeDPmBJ3h9
         o6eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="SgZt/bOA";
       spf=pass (google.com: domain of 3k4mbaaykcvay30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3k4MbaAYKCVAy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746633622; x=1747238422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nuAgMpkbvYSJcs50k9haCICQBApil/laYkfKyEcFUtU=;
        b=R+rhHsxSt0XfVB9Ty7gRG1H7RyM3wHFfpGjE1JDSkdU3oxuQjkmNNBf+98E2UU6qbA
         E0znBhRLm+2KgPixTAq/mmYnMk8RFrLSrGMM3KmzRQIHYQtGXxLy/oX+Se5WSnIf7IYO
         FrMuPY21A+Cf6ezj9rbR5ghF7YAshbdJ5mR6Q+yaGJT0o4nPoQ1iBXdGM5zkYeBrGc7R
         qHefyWClysFLNbPGQSM00KWu/jhWwEkltegoAw3Gb/pziMMsze42bL6MJXERQFLQA8wJ
         pKAY039sBrqE93ATCaTo5BDApY6XFc5Ug7q2V3Mj/DDUvEoNAxA+6yRy7fYlKL6JSRZ8
         EgiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746633622; x=1747238422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nuAgMpkbvYSJcs50k9haCICQBApil/laYkfKyEcFUtU=;
        b=JkJxTMIb3xU5EqZZ83Wf9fqLynVXDIMCmK2UO9qazvAljolipx/OWmutz8uT5Zn2gZ
         WQcsVcPS2GjoS3dO+nAQJfbWaMf1Lsl8GK+CRCMB2HA1rI0QsbU2ZXp0NzxUpzM/4Etj
         sRS4Gz7TqV3uvPcZklt51aW0xadFefHmKOo7SPV/ca1A6duaj9zX/hygZq4rJtaR8sdF
         clYl0n7iRsqd8fXr6LREnll5AAHsjJ2ExMBBlcPe+PYkAB7zcJAgvob+uWJFNrDRYD58
         wjDC1YcXyQbOHcpzISPhqzP5vZoKtxWjP5ZUKiHg/VdEzmxwRAnqApYnutANz99UZlha
         VuCw==
X-Forwarded-Encrypted: i=2; AJvYcCVh8wibJdoGfB34SG/fhbLG48pHLprmbjO6U2R+U6JzVrylVxlTbK5FEbFOgk+OQslvFEyfWA==@lfdr.de
X-Gm-Message-State: AOJu0YwUyjtabg3UZlPokkzesZUsHieC80jekB7m0XDwCsdFNJsMLXn0
	nI5ZqLx7/Hr1I+elTDBZKad+VZotYdVHiuEUA/OaqD0A/xZYd775
X-Google-Smtp-Source: AGHT+IEsTGWl59A3AT1E8kr3gqqChsRYszZEQTuVWCIfifmuMYRDpcZk6GLGzkhNomduO3CHaLOIag==
X-Received: by 2002:a05:6512:b09:b0:545:1193:1256 with SMTP id 2adb3069b0e04-54fb95f52c1mr1361495e87.1.1746633622362;
        Wed, 07 May 2025 09:00:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFjRh/Zn8qnrnNmXav1rQhNrEzxVL8Xzt+T3YAR1AmL8g==
Received: by 2002:a19:e04c:0:b0:54a:c871:6d0a with SMTP id 2adb3069b0e04-54ea675f2c7ls313578e87.2.-pod-prod-06-eu;
 Wed, 07 May 2025 09:00:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLLEpjoeMk1M0ZYF1w568WlqHpUmTPRjBex4eA6yDAxyhwPy0lHKNNJkvN6+z6HnU1oUZE7cCpyQQ=@googlegroups.com
X-Received: by 2002:a05:6512:4013:b0:549:4ab7:7221 with SMTP id 2adb3069b0e04-54fb9649083mr1596438e87.50.1746633619660;
        Wed, 07 May 2025 09:00:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746633619; cv=none;
        d=google.com; s=arc-20240605;
        b=d6oaDRCJ4XRSSNK5rNIzrNhAHRNG6vyG7XFEAAx94LtKFBOv9Y2MabB3tuXT43PbOY
         gmv/H1gZTpZ42TiY9xEkdTIgrpXfeYZ7+8ugV5W+Khx/pwCZFBrtv+3TRMCpRt763uYW
         SrMunonQCTNotvpW/OnbMYbus/T+RsxiSI9K/MJ4x/EYp28zDFQXwh8alSciMghzHXAp
         G6gCsBtZuRcCon4EDElXH3FzBHS4xiedDG/QH3EqkUQ6edrlFNbOlUiSzo6Hz0LJ0B7/
         OX+4kvvwpHxIDahQubDSEMS5xao0ZCFQljE2cyYtg+1hexmYAgagItO87kSpj6n+3g3H
         gknQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5rEhFIo2GHvtRIdrC/41qErpe5+c1Mj4STAx/upI2S4=;
        fh=ey6vcPqi2bCq1bsChLDe0uo7pO7SZx0LJ3PhDKUvRLI=;
        b=MWdJtLO0VpR0NpzaycDqA0hHpqk1TR6yvomrNsWoxF11mcTlOpChINgg/TF++YX1h2
         ZmpbiDlByIzlZSOCK5cJP1e2TNDaAEbtRJn9tO9qccd0rtxhcU1Jz5U89TxpDY3Mcfvl
         aGowNszXcZ3ErvALjgi9qFoE3rs+7gSM5V7aqmghY7jffOmyHx0DNQz+oUO4+1ZVdtVt
         31lzo8n+f7GHYEcgemI8/v6w5J6QIc1NY1rd+B+4s6h2IyjU6HfPrLOH0reqzzZ0LLGN
         j0zTFfKlFSOCjwyUHNcb24S6Mb4disGdo5OwRUOlUvCw72/mdcMWH4U7w9C6kHYEyK8Q
         4M1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="SgZt/bOA";
       spf=pass (google.com: domain of 3k4mbaaykcvay30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3k4MbaAYKCVAy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54ea94c8d6csi148774e87.3.2025.05.07.09.00.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:00:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3k4mbaaykcvay30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-acb94dbd01fso87140966b.1
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:00:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZAlxQXV9Ua0CA/xxW4zUU+vkf5UoDQPByphI/O0BaTd9wK4xKEs63WJu5qF2pjBtTebd8anIvwl4=@googlegroups.com
X-Received: from ejcji21.prod.google.com ([2002:a17:907:9815:b0:ad1:ec98:13d8])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:d14:b0:acf:c:22ca
 with SMTP id a640c23a62f3a-ad1e8c8cb88mr411905466b.1.1746633619050; Wed, 07
 May 2025 09:00:19 -0700 (PDT)
Date: Wed,  7 May 2025 18:00:09 +0200
In-Reply-To: <20250507160012.3311104-1-glider@google.com>
Mime-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250507160012.3311104-2-glider@google.com>
Subject: [PATCH 2/5] kmsan: fix usage of kmsan_enter_runtime() in kmsan_vmap_pages_range_noflush()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, bvanassche@acm.org, 
	kent.overstreet@linux.dev, iii@linux.ibm.com, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="SgZt/bOA";       spf=pass
 (google.com: domain of 3k4mbaaykcvay30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3k4MbaAYKCVAy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Only enter the runtime to call __vmap_pages_range_noflush(), so that error
handling does not skip kmsan_leave_runtime().

This bug was spotted by CONFIG_WARN_CAPABILITY_ANALYSIS=y

Cc: Marco Elver <elver@google.com>
Cc: Bart Van Assche <bvanassche@acm.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/shadow.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 6d32bfc18d6a2..54f3c3c962f07 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -247,17 +247,19 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 	kmsan_enter_runtime();
 	mapped = __vmap_pages_range_noflush(shadow_start, shadow_end, prot,
 					    s_pages, page_shift);
+	kmsan_leave_runtime();
 	if (mapped) {
 		err = mapped;
 		goto ret;
 	}
+	kmsan_enter_runtime();
 	mapped = __vmap_pages_range_noflush(origin_start, origin_end, prot,
 					    o_pages, page_shift);
+	kmsan_leave_runtime();
 	if (mapped) {
 		err = mapped;
 		goto ret;
 	}
-	kmsan_leave_runtime();
 	flush_tlb_kernel_range(shadow_start, shadow_end);
 	flush_tlb_kernel_range(origin_start, origin_end);
 	flush_cache_vmap(shadow_start, shadow_end);
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507160012.3311104-2-glider%40google.com.
