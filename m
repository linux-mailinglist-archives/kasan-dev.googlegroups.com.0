Return-Path: <kasan-dev+bncBDQ27FVWWUFRB75CR3ZAKGQE26ETQBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 41F5815A0D0
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 06:47:45 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id r29sf771540pfl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 21:47:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581486464; cv=pass;
        d=google.com; s=arc-20160816;
        b=pHnOQJkek2zYBpgAx2XHpoCopjC6U8YUjW//zIoJaK6kJkEezM0CVbBw0aEYCg+MYF
         0UJ6nuTVVqZ7G9CSqYsz142zwY24kNyQJynVToUK4XASMoCaRaPRvqYPm/pzN4so+O1j
         mpcYKIj7xrDGK62AUHGY6IYbwkp2RJAvMFhXVjxDlW+EnVZO0G5pVkm7RZqlOjW1aiOH
         CMrdZyRqU/Qh5VyEe+UdLc6dTEry0JaVEZUjRDLuBx8AL6QIGr1ZMOu9UE/FF6b1hBIu
         4aqrbMpjy3tFnmt5hgRfzq8GTerH4mwzWEkDvXMUpsE9U3sI0xTUMT9uuHUeXSvCycOU
         H41Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9ZLhwNs/KC4OXsHsVBu1VS46OvBPxeXQzVhmD0e6vYY=;
        b=yB/I90+4XD5lIjFl0wZY+xZMxz0q3uGlBQeC2RWJEb7rl08XtuCW+7TOxdw8p7BbcQ
         9EDRN6xp+QomUPbOLrWLg8ZikxRDfhxOdpLV3h/RH6g6eDcDINWftsRF1BGWh40ha+Oj
         M+TFYdwnxDvPsU+HZVPO6nm7PGaJSe4HUi3PO3q2sNQuDEJMNdjlhz6wjJdkGUEf7a0W
         dd1UbESENWIV637bs6OrO5iiMrNYYGvOx925VMWIQikFgjXiJwFKFwP73K6+Pm5+gCX2
         KuVJtzQBg9KR2XZSIg7xePDik+tIfpon7YXDML1WCJI55QJWnRo/i6DNaQ81iO+nD73O
         wJcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Y5zCrsiJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZLhwNs/KC4OXsHsVBu1VS46OvBPxeXQzVhmD0e6vYY=;
        b=ec7CoFcLo04mwW01o1LgK0/3DDdNwzviNBgbj2wgFKay8pwG2MknyL73UVNlZl9Eso
         19GPgoTHslseVl4HwzVayeUFLX3+iXA7r7CExF2W/9GGw497+z7wAQURKRumAV1hOCuD
         GDASPAqd7Qi6D+aIqxGVq0Z2i6OMfKMcRAyX6BNCfJOXOU4fNl0pf0PYd7xRZWa2O4KW
         1fYDKxIqQTaf2HKMCMQCGskKshdLaRU2Hc0GOWShmebBMumQ+1QnBkLiTdOTV04L9UJY
         wtcR91Un2II8zKz01PUIOgupChbw6N845L0qgtbD3Q4nuY3eBHdNJt7Jpev2Go0ORpzy
         +fgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZLhwNs/KC4OXsHsVBu1VS46OvBPxeXQzVhmD0e6vYY=;
        b=IwsK2qk58VovvgQviD8/ILBqMoUSoNLv3nmKYrETjwL4MVLIUv6o42ZmFso4fijDRg
         WkvcdMUUJahZ+nCx+3OqAonkQeczeTbpmhl7ERVvPSeeza2GxKoUrvMnFEotcp4UQ5nV
         i8R1ALORx8Ryi68w/5uIQZAkEQHEgoDFYxjby5t+IHm5+Du2Zt1aQHj1QT4LAuIABuaC
         5IC+9dmTUC9Q0KVlbARbse5vMaPqt4zMwum2nE9DSM46ASjxN+8mPaAoq0z5e4TgYQO6
         rWA+TMCJWFVJB/R2FwTAmd4q1CUVDpsay5bA8/yfXOn7sibycvFwiAW2VSJgkBMk0sN5
         GAhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW2Rqi79reQZZWCiBhz28QTQyxT4TeUE2sl66YNXnmzL4WIQpEd
	+a6E7TagZtkFDrcxwXgAq1w=
X-Google-Smtp-Source: APXvYqw9yWhF2up4pSruTUwIOh0LUNfuMEKa8HbelnRkbokuv15X5bsdNY52BvSGJFvWJnXiSklM8g==
X-Received: by 2002:a17:90a:8a0c:: with SMTP id w12mr7967335pjn.61.1581486463753;
        Tue, 11 Feb 2020 21:47:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:567:: with SMTP id 94ls6784751plf.8.gmail; Tue, 11
 Feb 2020 21:47:43 -0800 (PST)
X-Received: by 2002:a17:902:9a09:: with SMTP id v9mr6500859plp.341.1581486463325;
        Tue, 11 Feb 2020 21:47:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581486463; cv=none;
        d=google.com; s=arc-20160816;
        b=FdpjyRAS21235CewFwb45jhELzdIrOoGdWZVEL2fADH359BisHvjOrhkOWtIFn+wql
         ZElp1T3SRNO5fBMteaEpD0h+xVocCQvOTVOj0JEq4lND/9fKYpsPKeQ8JNe7woOpTHm4
         ApdhIpJRkhZSwWvRCP3flYAAFVQICT4RuhLrKdKvtn3e+KWKSHGkp8Tvg5GPVRlzEhkM
         tBafYWaG/wNqTCtG0jyw8Eqz2w/pduX5WwVS0nVCTg07zyNZNo+2jgkAueqRkMTnVSPI
         +LC5GHx0U67mJRBOSvjpdDvymTttaRaqdGUVvqRQvUlat+6w4fPxSjNQETpWW9A8nnqB
         lCtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jwvqhmbLPpvanCf4CYPj6H756JJZayFM0Q320MsSZZo=;
        b=wJlpzusF02T+mLLNRkL/wmjOaDDJTm/bR8SknGtKbrNBLz0/LJccyHQeocBISZoVmS
         OGaRr/IN3SbjijEHGrZ95Xxwa3QUvqsma4bxmGPxBWP/scouIDqUfluNBChJ78LyGPTg
         VTXTK4FJX2jwlLmxG5jnxd95TVS7cpWCu2MphOEvhYO226cZEa3WWEz3Bvd1mHNEJnYM
         AGUy4Fb3JB/hyB5UY/uz/FRaT/RdgYX5QirwJaV+LBf2Ykm4F0w3c2F2/7ccZZhXqrKp
         8zOHjsrhokxOALviuVZZoxe3bZitR+6LMUQdvBpINIDiynjFoNMURptYrAfpCGR3AfBr
         SHJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Y5zCrsiJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id o23si50414pjp.1.2020.02.11.21.47.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 21:47:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id b35so468715pgm.13
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 21:47:43 -0800 (PST)
X-Received: by 2002:aa7:8605:: with SMTP id p5mr6770773pfn.87.1581486463072;
        Tue, 11 Feb 2020 21:47:43 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-65dc-9b98-63a7-c7a4.static.ipv6.internode.on.net. [2001:44b8:1113:6700:65dc:9b98:63a7:c7a4])
        by smtp.gmail.com with ESMTPSA id q12sm6250115pfh.158.2020.02.11.21.47.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2020 21:47:42 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 3/4] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Wed, 12 Feb 2020 16:47:23 +1100
Message-Id: <20200212054724.7708-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200212054724.7708-1-dja@axtens.net>
References: <20200212054724.7708-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Y5zCrsiJ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

kasan is already implied by the directory name, we don't need to
repeat it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/mm/kasan/Makefile                       | 2 +-
 arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)

diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index 6577897673dd..36a4e1b10b2d 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -2,4 +2,4 @@
 
 KASAN_SANITIZE := n
 
-obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC32)           += init_32.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
similarity index 100%
rename from arch/powerpc/mm/kasan/kasan_init_32.c
rename to arch/powerpc/mm/kasan/init_32.c
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200212054724.7708-4-dja%40axtens.net.
