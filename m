Return-Path: <kasan-dev+bncBAABBOGK3GMAMGQEXNKZBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C9D635ADAA3
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:08:08 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id bp7-20020a056512158700b00492d0a98377sf1981919lfb.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412088; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Dk6XMSuczmtPYXkQUzHZ6nWnN/grW/04RZ8sH/cCF++624Oe7Poeox2izXlHODpPC
         bAjNB9MCxsF8PV/UZWa5iLnziZwb26gP8LpK6gBm1azZ9BgbJO/y64AzzlpHtY827OlJ
         tnYVZQ0OAku4BMhx3LmN/FBNwtL0PjebyrO6QrMgYdCGWB+4cX5claDE3kY6j/kn7gRd
         pVkgF7RMehFowmaS47Wwo+KtcFag2u34aoqYbQnqus+XdwcXYUJv4NOFlESZzThNG6l3
         Mv848FnHsESb1nKdmjC3TWLL3HODRnjXKfKAFjIRcOsiBp8jymk6fLSDxOiGGDxHUe33
         DFbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DLSr9ByuI3HU2Ppz1mVBa+P3mtbLLHrMxdTJJmBrac4=;
        b=zgeOPI1DvcjslLpQAJypC/iDxBuj5CKxspQ36VSgbLzvdNSELbWDgE5KW3Vh+gtdvi
         jwOLERBXEIb218ktPGDI8zEQCQamuoGvGAfdfVfP4sya43uzcerPHw2if4B6dTmLKzzt
         tkJ7oM4x18AYtFQv26is2Pm6H25xzoCQTix24i8MelfVD9OIo70T4U720Or0f03lWWgy
         /0Att1FmnwGBHIYdwLV1/2WPVrXcG7glzjBlUMkpBwEDEsDrQ7Mkj4W7ofUDpcnZVT9x
         DTkO+Z0rtnimcbSM7aRHjyVvmIKSPaHHuQpNjybPf/glKOc4YOb6hpS2KhdsiTuflVmy
         mQvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MhZf34zW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=DLSr9ByuI3HU2Ppz1mVBa+P3mtbLLHrMxdTJJmBrac4=;
        b=KOIeLe0KT/7Sjs/H/JQlW2mWdTV07VMulH9ExZ6eOheFUcIN6Ej7ggSQOo4fHccK/0
         TXnYtKt6XdpbJwkahoU5+qDfKQZxJIn/SOxJQNC6Ow6Q4PcVvq+L3yAmcMAJxb/ehBUL
         fH/RExr0VQnnI9CZAmlY4mYO5tVdjs0ieHPuST4cQxKntJKhSlfrfXhoEPKoZaRLlwvp
         szYWALwFNwDwzx0aH30k8/UoHShQTuC4qD2qUJgEjJbK26IhBdeGqpiDyjWO1n2HyXUW
         3XpiCXNMOubZLcLHw2YfgwDqyZe/VzbzMaDBVCQHgquzr5u+KbTwKea2igZRBwHHcVXm
         0a+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=DLSr9ByuI3HU2Ppz1mVBa+P3mtbLLHrMxdTJJmBrac4=;
        b=kozEfGXH8DkAJEfCc2MOxN3QZr/UZBp7zwajLbpl9mQpGIhtlDiBkDF8CYdray91+u
         rC81ixjoqa1D55EeX1sGzafmZvtQu+4RpWbc08V/s85suYj7HghW36FthNkdMSHXSVbk
         k5xlEQcPCh8YUMgSnwFMoEg02DqWmGb1EtJtI1R+WrkVFhrcZvb6+B/bfS8xjqOZfOY2
         DIwB4hchn5Mxqo5W6Gszxcp32vg0d/j/mq8FYTMobkEH38sQZPr6y9c8ROHcj+D4SCVD
         X5Tp29tKHDpZbDUtYeunP/8v7s5VuENv32Q6Da9C/bLPubVfmoWzrFpBzaBp8ir1MYgy
         jLyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0LTJAZ6jJedGngejfc7PEP0l7fZ9+CGL/6oNsWCsb9IIcEmVy2
	JXEjyDGO/a2YhXl782iZdzA=
X-Google-Smtp-Source: AA6agR5VcecuZJTVqrCDst62PJVEpLeDSy5+mf7UJM2GhDn+EeZ9t72371c/ivzSJbPzKPK2KaY+og==
X-Received: by 2002:a05:651c:33a:b0:26a:a0de:d6e3 with SMTP id b26-20020a05651c033a00b0026aa0ded6e3mr220046ljp.397.1662412088344;
        Mon, 05 Sep 2022 14:08:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:150f:b0:25f:dcd4:53b4 with SMTP id
 e15-20020a05651c150f00b0025fdcd453b4ls1717922ljf.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:08:07 -0700 (PDT)
X-Received: by 2002:a2e:575c:0:b0:26a:9f39:b3f7 with SMTP id r28-20020a2e575c000000b0026a9f39b3f7mr291029ljd.315.1662412087529;
        Mon, 05 Sep 2022 14:08:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412087; cv=none;
        d=google.com; s=arc-20160816;
        b=THP+IALRUjfD60eOpyvglnjrRPF1cotBdyue44aVzjfqx+c2LOa022FgBxMSXRkePU
         gXJoeaK6cdj2MeBEnLT3muYbCnXOXJKfeBVRgxMfIC5MgbnLZLTX+Yr0BZC4BZxSuXSW
         XTJSgtzsYaC685VnDXHxBlv/Jx+otnmEBglTqn4E31trWNx7Typ/tyllitbhPp8YdvWA
         PPzDRAwsaIA/i0nhvvGF7I2NoAXTuBszLF1tBU5fkSrSbfq6OHY/ZYx9ZU6QCw49a9OF
         u8gRATDNyYaDkAEwuM84dKiS4WsHnHgZTH608NNJ3jjOiZvLaSpwdve80xL7kLxiD/GP
         jfrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7s+y+NnFVR6SyFemhnOS8Di33idWzWChFcSyQrIGTFc=;
        b=bszidsJgMQJeYKbVhSB5VviclkqbfDN7xn/IAP2edvYnTDSjaEsJuQEFekxas3ckFW
         NQRdRHU1pfEYm4gW2v3NcPmMG1bcEyRZuTjRuzaaTNNSN40lwCTtCRyhmReeAs4MEsMf
         amWVhVtMn+1HPReGM6q3qgf7Leg1gQgPjgu1sxxcv1GFhujz7zNcUKOh984DOsFusiax
         5D65FOrNJHZk0BzKHt1Egz29OO6J3XrOmXthmlLpNMMjf4fjtfaOwmMg8oEqh0EPJijM
         Q+GfDXIi7MDEl+snY5AJOC2C1yQhLLNjr70NSXNq8xnd0ejmRDtM8t+lz7QGAPz6LhMa
         KQ3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MhZf34zW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id n17-20020a05651203f100b00492e3b3fd98si421772lfq.8.2022.09.05.14.08.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:08:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 16/34] kasan: only define metadata offsets for Generic mode
Date: Mon,  5 Sep 2022 23:05:31 +0200
Message-Id: <d4bafa0534facafd1a23c465a94261e64f366493.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MhZf34zW;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Hide the definitions of alloc_meta_offset and free_meta_offset under
an ifdef CONFIG_KASAN_GENERIC check, as these fields are now only used
when the Generic mode is enabled.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 9743d4b3a918..a212c2e3f32d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -98,8 +98,10 @@ static inline bool kasan_has_integrated_init(void)
 #ifdef CONFIG_KASAN
 
 struct kasan_cache {
+#ifdef CONFIG_KASAN_GENERIC
 	int alloc_meta_offset;
 	int free_meta_offset;
+#endif
 	bool is_kmalloc;
 };
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d4bafa0534facafd1a23c465a94261e64f366493.1662411799.git.andreyknvl%40google.com.
