Return-Path: <kasan-dev+bncBDZJXP7F6YLRBYUW3CSAMGQE2QTSJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D22E73C23B
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 23:15:15 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4f76712f950sf856795e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 14:15:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687554915; cv=pass;
        d=google.com; s=arc-20160816;
        b=H8UX4+06HZ1tUawnIVr1P6zwQfzUSkd1ccVg73YN6HTB0ofCJfT7S5el/tw2nXEn/M
         Rn18eyCAexGv8QPgvlgMCA6x02QiaAfTTOwc7b/g/jfLnXFpgyA6uEKy/754LW/clsT/
         4cW6p8HFBkJUgqBaKCXSiDlb+6NZAkaR/VlS3goDbKg0qA3YGWv2PCM75Cygt2Z1GLFH
         s/lr7wwgxVlN0uo5imNQLPOok4BSXXeGZlQzXLo8I0qsmP2OFqHhWHE9PPpr0p3mq5RR
         GZo0q2+SkP+KbNuQpvJxEhcsZ+we1GPUILj5yprUS0kD3MP6FdjuG6U21Pt3Cgp6z2rT
         WBUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XT9664aBEBKt8GIaayduP5TCDXknnJzZzFso1GYdCqU=;
        b=DduKYGWpzsCrF5nfVPN7fkj47CokbKtIfzzKMnPed2v2XpsjKWqngBEOB6KklO8pCM
         eXn5YNvwmdEiRAfSaPjIthoGIi648NJo0H74MXdu4AdpAg6jLqSw3ECyLBllpGmKqLfG
         cO3RU4mGLc3LW1uKI4Qm4ZulbkgFyQmmecANXS3hFdCIaHWsbROhgonjYOKunYsQeZAf
         3WlZX2yphuiYY7CSRfscGLEbqLMv9/CKFR0k8PwWEzcOztG5ofFR2pUNv65VAXI9LLFK
         Zf3H+CAlTfh4b/n6Fqix2qzfNeKiRbVu5L5msK5xgNMCh/dUIn2nNVR64tyifsx7y0aq
         fBFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=A7nI+7mm;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687554915; x=1690146915;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XT9664aBEBKt8GIaayduP5TCDXknnJzZzFso1GYdCqU=;
        b=l0CWxXklR0j9zL8TVVwhhMoHlT5NXMWyc9/FesdeWkr2y+1ZQSfrSh8og4aFnNJjtk
         l9SMGNNIHa7GdnAfN48CSmNikNweM1AR88ujTd3VzsEW2u75fUGsm43NUvFZTJKjry4h
         52sQ79jtqtc1cSjfDeZrg2zT6zBG4ODh8jEJY38kWx+JUs4T6oxX5Ie/m/GXHs0f/E50
         Qq0qCoNLKvEsLAtEm8luAWXoX+wrqwv9Nh+hYXL20Q8iiq8wxGid4l5ALZ3k3i7pricc
         JxA3iay5oh9joBBKVbLWwbpKDUA8AXLOwZrZl7QetbMSs1CKwbqN8imZGIz1MvGZIVRk
         cuiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687554915; x=1690146915;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XT9664aBEBKt8GIaayduP5TCDXknnJzZzFso1GYdCqU=;
        b=WIS+t2USYwFXGUNt4okvKub1XfHNlT4R7grxP5PxU4VeohSJmZ9nsThWs5m6qlwDo8
         yJl5BjIxIW/+E7EGrvYm0woA+Y2ZPpDOR3iqCMjX3xFjkWXi9WRZAQDKuoUVH6LlaJap
         oRb8nmWCViyRzNEpNG1O3mTdFyyRq9Tsh9sby3/vEtERkLVwQQi8RSJhP/ePf9fW9096
         AlY5d7nBGZESVq3CNZz0YxH/fRJR6hQPG4P1n5QxZdP18WxZDDX6qR04e9373lGQqpl+
         UZy5f16xn9XVFpI6RTsxO8+v4s9HGGPVdE3U892ElgBXWOQfyN8f56LaQSA8EO8u2PrP
         IzoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxN3RRTiBMcRQM4Hp3pYg6sdgOzOeZUCalOVfpPyMxZOqkRM0ay
	3sMe+T3qjMy/RJQSvZTLraM=
X-Google-Smtp-Source: ACHHUZ7gX4BkBp/qs33G0leqkHxPUa6i/sygEnnAqeo5vhDRFOMy+67oPfeSDTrYI3zqxeBDwnbsiw==
X-Received: by 2002:a05:6512:118d:b0:4f8:5dd2:21f5 with SMTP id g13-20020a056512118d00b004f85dd221f5mr16934966lfr.67.1687554914356;
        Fri, 23 Jun 2023 14:15:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5e54:0:b0:4f8:673d:6c01 with SMTP id z20-20020a195e54000000b004f8673d6c01ls1069546lfi.0.-pod-prod-03-eu;
 Fri, 23 Jun 2023 14:15:12 -0700 (PDT)
X-Received: by 2002:a19:710f:0:b0:4f3:d682:7b1c with SMTP id m15-20020a19710f000000b004f3d6827b1cmr14201035lfc.45.1687554912581;
        Fri, 23 Jun 2023 14:15:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687554912; cv=none;
        d=google.com; s=arc-20160816;
        b=nlXedk2NYn23ntPVcI4eHW1ZzLsinhgyJKmd1AgIQRJGNGMhhGe5lfz14UKraTT1iW
         YS/te5adh+FCmZ+r2ZHCjM+FdwM8uLA3kg72vrGbeAYN64HL7Kz6rZJnejYl+oogHebH
         Rngwp4X1mbGpboAMC5mBvdbQ47gUSJYYPZlQNlhtCj9l39H1y3QD3yh9HdzRfOLtlpRQ
         sMyBeX3mGj9D+Jnx0TSqT35swvxxj5i4u+Qtk9+Xry/mlfA8td42RApiTsSPGMv5wS18
         wjkeAqldSnqhw+XTPrEWUdRnrchljz2NVViiXBnxcUGObkxR4sgcYm8VeeS+WEOyQcra
         9NjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wXbBUetUKejFi8ORS1ZEmLv+CVaFu9wgVarZrNCtRDg=;
        fh=OYPk5F6oFlY7JcywgF8It8VTSZdtQYKVtptLL44VnkY=;
        b=ZhF/AiGEzW12BqET3dI9gxSA++L2YfvQ4fDeTxRnjiqBDCTz1TthibAWkkLoKDO5QV
         aMYVFTuNR83bcXKolMtphqwDXD/ASn1TltJlAwCN5OsmSpVvwEahCi4Of1c1pU+Zqfqc
         aX5u1uX9UAP7SEBXZblMFuHO1c+QaOot4p8yLCHeM0bfPyNrgm7EJMibeJ2lBL0Z5xPL
         S33lCrvKMkAcsSbsYOUIL6pD7/AKcRX7bE9OMDQlf2IB5Ka9AtSkB8rbyz4Gi+SmcWvV
         v3q8zyDkfGGR2xdefYxLh/MT6m2b4RThaRzfb0td3qecG9odnGpSIiJaEFwgNuf28WEv
         +6GQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=A7nI+7mm;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
Received: from mail3-relais-sop.national.inria.fr (mail3-relais-sop.national.inria.fr. [192.134.164.104])
        by gmr-mx.google.com with ESMTPS id c31-20020a056512239f00b004f76ab5e91asi9415lfv.10.2023.06.23.14.15.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Jun 2023 14:15:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) client-ip=192.134.164.104;
X-IronPort-AV: E=Sophos;i="6.01,153,1684792800"; 
   d="scan'208";a="59686175"
Received: from i80.paris.inria.fr (HELO i80.paris.inria.fr.) ([128.93.90.48])
  by mail3-relais-sop.national.inria.fr with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Jun 2023 23:15:13 +0200
From: Julia Lawall <Julia.Lawall@inria.fr>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: keescook@chromium.org,
	kernel-janitors@vger.kernel.org,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH 17/26] kcov: use array_size
Date: Fri, 23 Jun 2023 23:14:48 +0200
Message-Id: <20230623211457.102544-18-Julia.Lawall@inria.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230623211457.102544-1-Julia.Lawall@inria.fr>
References: <20230623211457.102544-1-Julia.Lawall@inria.fr>
MIME-Version: 1.0
X-Original-Sender: Julia.Lawall@inria.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@inria.fr header.s=dc header.b=A7nI+7mm;       spf=pass (google.com:
 domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted
 sender) smtp.mailfrom=Julia.Lawall@inria.fr;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=inria.fr
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

Use array_size to protect against multiplication overflows.

The changes were done using the following Coccinelle semantic patch:

// <smpl>
@@
    expression E1, E2;
    constant C1, C2;
    identifier alloc = {vmalloc,vzalloc};
@@
    
(
      alloc(C1 * C2,...)
|
      alloc(
-           (E1) * (E2)
+           array_size(E1, E2)
      ,...)
)
// </smpl>

Signed-off-by: Julia Lawall <Julia.Lawall@inria.fr>

---
 kernel/kcov.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 84c717337df0..631444760644 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -900,7 +900,7 @@ void kcov_remote_start(u64 handle)
 	/* Can only happen when in_task(). */
 	if (!area) {
 		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
-		area = vmalloc(size * sizeof(unsigned long));
+		area = vmalloc(array_size(size, sizeof(unsigned long)));
 		if (!area) {
 			kcov_put(kcov);
 			return;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230623211457.102544-18-Julia.Lawall%40inria.fr.
