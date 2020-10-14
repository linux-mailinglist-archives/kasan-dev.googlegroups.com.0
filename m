Return-Path: <kasan-dev+bncBAABBWNUTP6AKGQEYCUCPMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F52B28DF80
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:00:42 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id v12sf359625lfo.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 04:00:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602673241; cv=pass;
        d=google.com; s=arc-20160816;
        b=tSn7D/Qyt344a3Wkx6K592tJxH+SEpuwD1fCnN/kEq7YqRasKPNcIj/Kc7EplhgG20
         Xz5VYFtb4gB7z79oE4HvbTPdhmdRP2xGXSSs1sp2XtO6pK4V5U/AkHHZnxzc0wCHkQOY
         c04eX6pRAt4md79LSfFq9pUW6RVLbRi4pzCmCxQQPTNDd9PfejkWfxyaNbbbBw4F1kNT
         nT2xhFUDnbYa1CzCCPElyd5L0tOpruSiVZy1PBKPCPMnL+nLL1Dp6jxcYHihop5Rg/yF
         gNJxNM21O0ya6BIn1goE5S4yuBLepaQtzlq9Anc+kj4TrYkws456CAyeJDscIB43pKQ9
         eHfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fACdCj35zs+UUmCNgwcw++5Lg+9HKVt6SHlTiPFMakU=;
        b=hxFqMGeUBZAaQfNIs+HONwfNydCjACycAeKs2ff0/MCeA51TBDDcdPl0deWZNrB1Rw
         1WafsDWzMu9tR/Ivm1YtT9rQxSHe9OXXN9rH/w6K40IajPUlimaQI4C9jWJyvGXCBlme
         Xxy1fW/342CjheVdir8UHLO+YSXhBevqqtuybgLf8m/O5LYlEeYauju/+CX8AdkjwP5j
         oO0sFCVNqCP8FLuZJJJ+SjYGwAPWBEqIdLJijdpCbXExi9l2zgnGVvg1JsQlzpiEskqr
         Ejv2XcyZjgaJ8KObkjLCg+f3C0ZPlZaJGI5X2euBCH8bLp24hTOqkMbEc8bE/rr+LcdI
         vmgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of afa@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=afa@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fACdCj35zs+UUmCNgwcw++5Lg+9HKVt6SHlTiPFMakU=;
        b=fxgAc/rCKF6B33GK0HkbCV5F7OujYJ6cNEXyR9XX6qiJ8+P1E6oyQBmKa4bPDOav45
         hu5OIWNip4XDsgXkY7sgULAs2Jc65EeKJnqvZh6WKWyRqIpMSqrfcXeXkdDXgLkMxKYK
         AS9SeENMz5gt1yOzIBlLAj5NDDtmD4+Y8NKgF3+d+D76OG9qHHYXMenAKOKmoPb/ONKl
         OoHRjAdeWBpRI8EJjmUBzHMAkYiFRcCSCDWlGpCRD0BQ7d26/ItM10pYZNC5gxi/RZlu
         T8F580/NOFFwjnSLTqlE3W6gnAaUuOP9WKLaRVUib5SfdDY4Jsnqs9uAkKMxCQEUAS8/
         OWtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fACdCj35zs+UUmCNgwcw++5Lg+9HKVt6SHlTiPFMakU=;
        b=ULZMjJuJb8dcf0w7m6O8rhB6WByTglvUgNKWSnyQh/45xNq4eqt24zrVmOxjBKSCff
         5tkVHSBtYIRrIiSHRdKPd5DnD5xATFfWbfRtqilM7P8eo/+p6ULlcivBzsGdzrIcffkr
         OlNM80OMZXsLdOPIHkajwSuSIUVYF5xvJmTAIrquFs58B1+tfhuR8WQJlnc86VGvLcbJ
         qC6nLHozkmNvljsHObCNKQwtPxxTn+OXc9QpgfJ5OmSMgSI12rkvLi/a1v7YjGcwytts
         d3zPhiLCOSnw+ED9WjaegJqaVKEaBqB58qKsePxAbGx45OiqadVJjhCPVub6wGaFudOS
         o4pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329puBjx9JQ8My7g4qVj8zXqxF6Zgoa6v2VtZ7kPB1kByS0Ir2d
	MG8PFORgKMwRBFY7NrSBlyk=
X-Google-Smtp-Source: ABdhPJxTXh2gF2kLK/igS4K5FIWqMGhdU2EReJoc96bDIgxa95TsUHP0AT0VQlR7BEFbpQJ9qGGJBQ==
X-Received: by 2002:a19:3f57:: with SMTP id m84mr118416lfa.17.1602673241587;
        Wed, 14 Oct 2020 04:00:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a86:: with SMTP id p6ls581754lji.0.gmail; Wed, 14 Oct
 2020 04:00:40 -0700 (PDT)
X-Received: by 2002:a2e:3016:: with SMTP id w22mr1505825ljw.248.1602673240657;
        Wed, 14 Oct 2020 04:00:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602673240; cv=none;
        d=google.com; s=arc-20160816;
        b=JVlN25p+W7jlXlNq9wVBJLpDwNWDTv1CyvUrXIM4SLpn6h0r7iXiS70JeHdojGHyig
         sepnl0CNqL8i5rBc6thvwyVh6gOIaJCb5jMDVeRvTgwTE2wJ2GqjHquumfxT79c+teYV
         BKjp5RpsGXoS1B2LkFIkff/QD9WIotZYw4Tt7LC3SMe97pHg6YgSF/f/1agARNavhgay
         H5Q3UznW36pAqRD1crqriNMF3Xhe4qcS9FtKjDf1pGYRvNUDD+9Qi0+rXPQ1vvZAfUCE
         L7ubJy1QGb0rqRlVCLt2vsH0CG5oywGqYAg/hPY8uIQ5HH9UgT8GqDheqp7INh+NdnaM
         whQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=g3b9figtQY583yqsVtNWLlsDuepdYRyZ/P2LT3P47jQ=;
        b=uCkN8PHqTo5ZOKJhr42LDWk4jBv7a+3jDiCNmwv1riobYBRACsrrqWAdOoH26x3GPB
         yIEeQ2+Mr6TjXyFFUTD8qfsO2tDbLpiZp2ZnMCHu4UghF8oM2mcpNgEjaA+XEBC8pOFp
         J0aqTJ7P9s9TTYpOOThrhUqOZ3gDgP81RQH+vpBn+oE8iNUvAt+d51BWo5OJZ1x5mv7z
         km/DIOPWJOAIlRDIIXdWU2AtmLpQQ+uCb3YrFFZEBrYDEbO3XLXcSaFGpfULJ4tP45Ae
         3LePLNsXj+9FOfTONYGzunPYzQTjKoIYLGkDmLjo+huI6BT46LEyfNZRIWtx/KxsutsY
         CTZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of afa@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=afa@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id b4si57964lfp.13.2020.10.14.04.00.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Oct 2020 04:00:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of afa@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from dude.hi.pengutronix.de ([2001:67c:670:100:1d::7])
	by metis.ext.pengutronix.de with esmtps (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <afa@pengutronix.de>)
	id 1kSeWI-0005e1-4v; Wed, 14 Oct 2020 13:00:34 +0200
Received: from afa by dude.hi.pengutronix.de with local (Exim 4.92)
	(envelope-from <afa@pengutronix.de>)
	id 1kSeWD-0000ZY-RO; Wed, 14 Oct 2020 13:00:29 +0200
From: Ahmad Fatoum <a.fatoum@pengutronix.de>
To: linus.walleij@linaro.org
Cc: ardb@kernel.org,
	arnd@arndb.de,
	aryabinin@virtuozzo.com,
	dvyukov@google.com,
	f.fainelli@gmail.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux@armlinux.org.uk,
	liuwenliang@huawei.com,
	rppt@linux.ibm.com,
	kernel@pengutronix.de,
	Ahmad Fatoum <a.fatoum@pengutronix.de>
Subject: [PATCH] fixup! ARM: Replace string mem* functions for KASan
Date: Wed, 14 Oct 2020 12:59:59 +0200
Message-Id: <20201014105958.21027-1-a.fatoum@pengutronix.de>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20201012215701.123389-3-linus.walleij@linaro.org>
References: <20201012215701.123389-3-linus.walleij@linaro.org>
MIME-Version: 1.0
X-SA-Exim-Connect-IP: 2001:67c:670:100:1d::7
X-SA-Exim-Mail-From: afa@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: a.fatoum@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of afa@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=afa@pengutronix.de
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

CONFIG_FORTIFY_SOURCE doesn't play nicely for files that are compiled
with CONFIG_KASAN=y, but have sanitization disabled.

This happens despite 47227d27e2fc ("string.h: fix incompatibility between
FORTIFY_SOURCE and KASAN"). For now, do what ARM64 is already doing and
disable FORTIFY_SOURCE for such files.

Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
---
CONFIG_FORTIFY_SOURCE kernel on i.MX6Q hangs indefinitely in a
memcpy inside the very first printk without this patch.

With this patch squashed:
Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
---
 arch/arm/include/asm/string.h | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/arm/include/asm/string.h b/arch/arm/include/asm/string.h
index 947f93037d87..6c607c68f3ad 100644
--- a/arch/arm/include/asm/string.h
+++ b/arch/arm/include/asm/string.h
@@ -58,6 +58,11 @@ static inline void *memset64(uint64_t *p, uint64_t v, __kernel_size_t n)
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
+
+#ifndef __NO_FORTIFY
+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
+#endif
+
 #endif
 
 #endif
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201014105958.21027-1-a.fatoum%40pengutronix.de.
