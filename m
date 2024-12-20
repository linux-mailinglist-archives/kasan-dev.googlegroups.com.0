Return-Path: <kasan-dev+bncBAABBA7HS25QMGQENNQ7S2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E6C39F9930
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2024 19:12:22 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-30220c5ca63sf9848461fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2024 10:12:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734718341; cv=pass;
        d=google.com; s=arc-20240605;
        b=ewhdkkLBrOInP5eobAfA+32mV0HZkkHmSvhcSlCxtkXDVpWHLN2ruQQDRdxF9v5JR2
         rvsfFvFyvghCmVCPCpeJYlCMZDdgpFHY0cvZ8+VbgDhQiPDQBSNMuXrOnw8K8DHzBmCD
         +zEa7Ze0uMKkpod77YS3qzzwkB7i1VaeKeL/3y6GAkaSk4AqZ5ocI4ShDkXZfXXzYkZQ
         pKhHty1njkJ6GwmXWz8QRi3GSzfwet1eeDi+yeiGxVaDqJz8OhmNpqezYq2EWbEatXbz
         VjQ3qKxvX784EkJ7rYQcN0k56mDAJSFTK96UtX9VmsFeI6ljta6agJhLTiAK+en+Xvg3
         e/TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=nMTc8eeQeZSRgc9/UGpl3cUcW4XMkBZg/DRiTrV2BQI=;
        fh=O+f8ZExo3GCsDHOlkXvoO18ccmAByDc2fp0FdpXYDZ0=;
        b=INbSqKdehXXMO4jiC3SVTB6GfeJsMrBnQ6lI1CRf8lXBsXuqPKFavbZ3mr+Cupw+od
         PY/CQRxmetImQPMG378uNGXUrJZVb98byPsnV1VpkzTBtZOsqXUcGMTj4FCIOiY6fZBs
         vyK5Nb1pNoc1c0ygz36YSIKROl+f6nNJ/dGDw3ItWUKOlfd+LCAN7lwosWUtQLf6d7SN
         F+SIA117LM4ErsSyKlzuZNtGSWaYHEMo4NKZ0hRQjzJgQ/Bs48HHpNJsahF981GzaTQk
         UG1PkO/nF4Ldfimw0/UGaKx4WhOIMAnQjiDCmGCAuxwzCGdeqQ/nKHDwkJblILarg2vN
         neZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=ttRXrq+n;
       spf=pass (google.com: domain of dominik.karol.piatkowski@protonmail.com designates 185.70.43.16 as permitted sender) smtp.mailfrom=dominik.karol.piatkowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734718341; x=1735323141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:from:to:cc:subject:date:message-id:reply-to;
        bh=nMTc8eeQeZSRgc9/UGpl3cUcW4XMkBZg/DRiTrV2BQI=;
        b=LApb/HQovR8KMV0DuhJGbKGprXXxCqwGCbrvJDWQSKRWMfYL0v6c8SrYrTYpK1dAEg
         X8YBIdWxabTV+uAlNyNc2XXR2hJ0GtlNDQjpVFFLWm5mU3KAlA60r6ReGZju90Xb4gpx
         W0Rinvv7nu47ZiVe3uYI4evoOuyM60S8AR03Vo0KbF1+Oqcj90B1EkKcGq7QtSby7Spi
         /6YWzhGjmjy7ccQoOjK363BjAm42uZZzMa9wkaX+tL4hCPhA5GqpONW/dnvhdbzeqx/g
         USmGxQgCOt35uJ4xc1zNB0WJ4e32QJVQVZqPc5SIWjbJiI1XcrgatAoU/mf+uZjtClqd
         lQ4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734718341; x=1735323141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nMTc8eeQeZSRgc9/UGpl3cUcW4XMkBZg/DRiTrV2BQI=;
        b=gA1p5IJL1JN1sGp/yT2mG8Zah1KBmTlRxQpcrwc8/OpTsEHMJwt9I6G5cUXoPFp+N4
         XV1ODgJw5IycjmCF2gl4ZvnNj99j9lL2V2tEeNAGMm28CEdwO6oAovakFCQi7tuAYUwT
         oJ7MO0QaJFmpciXkhUt4i9GdDDjd2LUgj+PzYI0jxDsS5uthqIgoaWRjgq+TqazBMDWp
         yP1ArGJdAfN2z3WacrC/rWYLJOMAA5JZ9tshL0FUOJ3uAd5jAuFSYsoohgdP09BALPFS
         XDjqIdWLlvOVIGsiCHJNkD6glM6WxBb5DIEUbHdA0xSQQcgBdks3swdNWSQkmeMGwhwl
         qatQ==
X-Forwarded-Encrypted: i=2; AJvYcCVK0vb7xIjoirf25n6CVSHLA+nnvgnjQHp11jiSg+YYFtl82PRplJh14rTOlXCFeSwULC4UPg==@lfdr.de
X-Gm-Message-State: AOJu0Yz23MnijAZNjzxNLPIde6sM7jthmZoJh+rP4T330qILVnPgXJa1
	T1l1iHssEvWPRKZ6S8XbreWZWkp/A+2OYSZvp8ylHiVjOJd2jyS5
X-Google-Smtp-Source: AGHT+IFmDieBGKJybBwv1hZj9/xxTAC4wzVHcNd0zOeL4uFbY0dbzmwRY2P2XWfhkhRnosbAee0U2A==
X-Received: by 2002:a2e:a70e:0:b0:302:16da:a03e with SMTP id 38308e7fff4ca-304686299b5mr10147511fa.38.1734718340346;
        Fri, 20 Dec 2024 10:12:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a550:0:b0:300:40ad:298f with SMTP id 38308e7fff4ca-30457ee4fb3ls696051fa.0.-pod-prod-02-eu;
 Fri, 20 Dec 2024 10:12:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW7aMLw81OlqZhIRF0W9th0V9c+Gk7LuHrGbF4t1SJss5iZo+KypEEPNMVbd2vk7nu5t01ET4KeDR0=@googlegroups.com
X-Received: by 2002:a05:651c:1404:b0:302:27c6:fc77 with SMTP id 38308e7fff4ca-30468627985mr11947551fa.34.1734718338315;
        Fri, 20 Dec 2024 10:12:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734718338; cv=none;
        d=google.com; s=arc-20240605;
        b=Yde5NxotCNnJQwji87PM1BOjqa+Hlrn26YrBC4nDHi1vsXIoFspT3ZPK76fT+aGrRd
         VDCcsIqm9bX48j6Q9rcVaa5wzvQpw9NljBApXlrsEMSgFfghhDuoK2miwAawWDBHN0hz
         OqIGvgOYkTnzvvi7A08N0J7Cb31ER6Hy2Za/w4zMbt9lACf/I/0Dazrx4hrDYD8FhQb7
         1V3oSR8zyR5AxHg3xKaD7EfzkCmPLcXhMjQRzgmbCGMW2y2Aj36jQtekZo+F+FE6rl5K
         5b/GEXWhSphT/2DegWeZZSBnLq3ASQJIVUBsqLpiWIoWVqRxtppXo5Btv8wUWkDYH+OV
         o4kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=HjYP9Rwh99nEnlEjfrVYd4r7Z1QIfkP+zQmJqUvsWtY=;
        fh=PFsiLl0XssagXmEuFcn6eApD9DcP48sjcHwOnXqWk3E=;
        b=XZ9h8XSdhn9O7qyUkzt/l4BAWO5X9mrmpLS2b1oL4k1Zeyt+IPEYh7IyIqu1hTEa3a
         HuwKHfR4U/cbLQMQamgHGbNZNZ00ZkPaDW+mQlhwuF8i8t107uT4e/4Z0gJvDvfdcMq4
         ZOPuGEqMdUSKZ54cRXrEAA6QXKoFTmsR3dpWiz8Hqppy/O9iqAqyS0Cow2SYwroxBpMj
         /VMTTnZ8EYbyeKbLd+uqsqIMwUH9zwN4RDi6/tLsfzHl6AyDpTA8yPXE3gk8Dz3b03OX
         HtM/Dif/CmsEEbMgVhjhzxq9pJFqLQBA3L9d32cQQ2et7GXdpD3PZGCgak6UdD+Vf1BS
         MJYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=ttRXrq+n;
       spf=pass (google.com: domain of dominik.karol.piatkowski@protonmail.com designates 185.70.43.16 as permitted sender) smtp.mailfrom=dominik.karol.piatkowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3045ae02e19si1481541fa.4.2024.12.20.10.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Dec 2024 10:12:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dominik.karol.piatkowski@protonmail.com designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Fri, 20 Dec 2024 18:12:12 +0000
To: akpm@linux-foundation.org
From: =?UTF-8?Q?=27Dominik_Karol_Pi=C4=85tkowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, =?utf-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
Subject: [PATCH RESEND] kasan: Fix typo in kasan_poison_new_object documentation
Message-ID: <20241220181205.9663-1-dominik.karol.piatkowski@protonmail.com>
Feedback-ID: 117888567:user:proton
X-Pm-Message-ID: 4d29920fe1e53f819977b39b14212cd01872cb5f
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dominik.karol.piatkowski@protonmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@protonmail.com header.s=protonmail3 header.b=ttRXrq+n;
       spf=pass (google.com: domain of dominik.karol.piatkowski@protonmail.com
 designates 185.70.43.16 as permitted sender) smtp.mailfrom=dominik.karol.piatkowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
X-Original-From: =?utf-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
Reply-To: =?utf-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
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

Fix presumed copy-paste typo of kasan_poison_new_object documentation
referring to kasan_unpoison_new_object.

No functional changes.

Fixes: 1ce9a0523938 ("kasan: rename and document kasan_(un)poison_object_da=
ta")
Signed-off-by: Dominik Karol Pi=C4=85tkowski <dominik.karol.piatkowski@prot=
onmail.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 include/linux/kasan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1c1b3d39e7b6..890011071f2b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -153,7 +153,7 @@ static __always_inline void kasan_unpoison_new_object(s=
truct kmem_cache *cache,
=20
 void __kasan_poison_new_object(struct kmem_cache *cache, void *object);
 /**
- * kasan_unpoison_new_object - Repoison a new slab object.
+ * kasan_poison_new_object - Repoison a new slab object.
  * @cache: Cache the object belong to.
  * @object: Pointer to the object.
  *
--=20
2.34.1


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241220181205.9663-1-dominik.karol.piatkowski%40protonmail.com.
