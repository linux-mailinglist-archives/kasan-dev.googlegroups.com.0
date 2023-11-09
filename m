Return-Path: <kasan-dev+bncBAABB5X7WOVAMGQEB7SOWCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DD0F97E6E0B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Nov 2023 16:51:19 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5098fc17ac5sf685018e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Nov 2023 07:51:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699545079; cv=pass;
        d=google.com; s=arc-20160816;
        b=D1t/Xtq2zGz0OlY5DWSWLPYace209wfsXpHv/9GIULsrp2uOJPkZiXiZw+wumqlplg
         ud1HBnMq6O2Adr6Orkc4nLJomeDt8o5aany4l7+V/8d/+dAnDQV6JQYlL9qi5qpbaKsk
         v1m/DZRxRWR0WG0/hkLdIpX3SOlbyiXvIpAXrIMlEPvoD6BYozeFGAH0oZ11grWma78j
         nlHXleywIkvHcQ3bQSAdftneFoAPbAYhJG576ChGmgbeAZ/74UTkiAXOwdLM7vQLdl81
         p5gQlRTi/cJCgSU8I133TKsXBCtDagJNXBdZsFfyp12XBPolrM0KXLQN5tzhw4bAc17p
         jMDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=0G312KU1SLNiRyj7ydyd02OmlH/U1+MI+zR/4CLwIt4=;
        fh=s83eWP35m7qf2ShTBn5oHosHNJ9J1JpOqAmcwAMYcpc=;
        b=sBMMTLKcqetqXOEhe2+yBSTHq5cIzhHrMJxz7bEwL19HoafLdX+BXhMICpCLQoqc2M
         iZW8EPOQQp3pkcIvRetCtcJbd8JOutRZ2zVQ3GasBdgbr/AnYB6658OktjQi0Z4wXyAM
         N4HIkiPbLuoH/DM5V0YUmtq2hWIqbrNwTUXnv/ZlpdDZlmIxlsE1CD9MeGCfhC+Pf8O+
         6+BoQJJ6JJth8qBQRmUkJktNnipvaWPB/VceAepMFng/YrrlAGGYL0CU71oJsiqxZMWs
         FAUtTNgGjYMsKgoEc8s+8lI/X7g6OdK9SqJGjSofvWpjQ0OBleMJEo2/uph0g5751pMk
         3QPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="N/TXfWMy";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699545079; x=1700149879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0G312KU1SLNiRyj7ydyd02OmlH/U1+MI+zR/4CLwIt4=;
        b=adyij+GWRkTB2JfOIpBYmTUQWxbCeadCBxHN4LzhHXG3JJ0F1m2K3PBW2vdpTZKtnK
         ix5SYWc8hSvTVpBx+r5KvsDNixwj/0MPTCvdWCVwmIescfrpfq3JOGT3dVT+CTLwaGnn
         JZ0uNW2vBf7ARMuovy5aNRRzyz67EHMY+I73UaycV5UuFDza41Uu7XDZbkmh/8SEDB/X
         fJn8fgI01Td24TojhKTpPryPetDV1M/7rxQxHlFdKhy+Crnq0R0q471WUBoQHqqL6oG7
         UqUSrBX/g9GMPMLsBgfkhJ9CXpgUbEooKkfkEJxv+9ACJkcTE1u7gUOsxbqvj9yYbCs6
         Gn2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699545079; x=1700149879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0G312KU1SLNiRyj7ydyd02OmlH/U1+MI+zR/4CLwIt4=;
        b=mWvrouNw2TLpkfx3A4qwA3O1BKWmMk2QqNKpuiyIusgKL2IhHQTRAXdloATQIom5UH
         96280NMp6Bx3MXdUlEjoX+rtydoE0PCvQXC0D6U8z/179rv2OpEpr8cL1lzcBa0Wd5Ep
         7Yg0q7HbomW5/egylbgnx8bcsBo/F5r0yReEj2k1K44lJym16t0cp8WkeYfGA/MP+a4F
         hJMtIGJpxXymNOvLKeL+1EMbs3Tlw8EvUEhwaJQSiJMW0Avfa5Vwv3FZvO3JqL6+OiqF
         x7p7e8CwsVwqwcA8UE3cKoVDKm4sYlckIpZ3nLYx/RfvwOnVJFcSI9TvFYgtvhjpRa6P
         iy3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy4feSSxHZvFuPRiwia5Sce7ZwTeoGhyAfp/91QONodqDBLeqVq
	iy9MBhPyQ+ROOYHOiVRKihY=
X-Google-Smtp-Source: AGHT+IHooGlXRHhDeLiDdNiaoUELIvImmEAj4gCI+9DfWFr6YVwGOdnAsOWbmlvK9zgcqlCWubzc/g==
X-Received: by 2002:a05:6512:470:b0:500:7685:83d with SMTP id x16-20020a056512047000b005007685083dmr1882683lfd.48.1699545078624;
        Thu, 09 Nov 2023 07:51:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d94:b0:4f9:5599:26a with SMTP id
 k20-20020a0565123d9400b004f95599026als282865lfv.2.-pod-prod-08-eu; Thu, 09
 Nov 2023 07:51:17 -0800 (PST)
X-Received: by 2002:ac2:4884:0:b0:507:a40e:d8bf with SMTP id x4-20020ac24884000000b00507a40ed8bfmr1725049lfc.7.1699545076585;
        Thu, 09 Nov 2023 07:51:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699545076; cv=none;
        d=google.com; s=arc-20160816;
        b=hKtKTd9v2VhRYrQXUq2bXeXpGE11KY9iVadwBss4P0RQu99zGpNMQrc+DQhS5fpdbS
         vawLfWR1ht2Lfou50YWj48xBSvyArcPyr3UJ0eL3iYbCmFgY5idQriV1F22ZHO6kX70d
         deOyDs63aR37oYPTo5Geujs611/NTm7gIiES1IhfSTaY71E4gJ+TI3lxN3wTmQj9Pas8
         TduK1pbVmbJ5+tQAaiZgJ5HR7i3dojnSmiPlQCFG58u1aNb7FFXyZp6geYyr9QICCAYW
         c2ZcG91oDD+BnWQpeRr2jsPmf30CvoTK4JaU/EL2kIsEFZyg6tM1TdwravMAl//nr9qQ
         8mcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gkUWT9gaMxgFhLHKiecgnCwkyltpAf99XujgPjq88yM=;
        fh=s83eWP35m7qf2ShTBn5oHosHNJ9J1JpOqAmcwAMYcpc=;
        b=or7vGigiCvVdXTm8pMmRtUdcSQqP6Sv5GYscjSvGMVk69jMhvfFIxiHfHpLMF8Lgdi
         vMD7JZUWY+a5yAmZR2wi/wl2jVve0g6H6dx9ASViNOu8YvsGyinF0FlEQco76qJmlhbY
         IWKVTtxEW/suk0L+dJzE5tAwaI11XQvbBTJ+LGVFDNuC/YFTlM1jxYJey9AoXbQgRr8s
         XMqkPv9acWW1yapVIC+l/7+Uhgqjy6Cn/FQRrMJ6YDPgNq0ZTSn9sguY1Qfz5dbQ2GmH
         L0e7YFcInt6nNqEi170A4DkEo/EADKe42VvpDI8pw4+SIIDbKSa583mvTwh4wBqX1oVI
         u2+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="N/TXfWMy";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [2001:4ca0:0:103::81bb:ff8a])
        by gmr-mx.google.com with ESMTPS id e8-20020ac24e08000000b005091220c8c3si956399lfr.8.2023.11.09.07.51.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Nov 2023 07:51:16 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) client-ip=2001:4ca0:0:103::81bb:ff8a;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4SR5z762ZDzyXQ;
	Thu,  9 Nov 2023 16:51:15 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.885
X-Spam-Level: 
X-Spam-Status: No, score=-2.885 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DATE_TZ_0000=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_MIME_VERSION=0.001, LRZ_HAS_SPF=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, LRZ_URL_SINGLE_UTF8=0.001,
	T_SCC_BODY_TEXT_LINE=-0.01] autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id JcuZfT6noPOB; Thu,  9 Nov 2023 16:51:15 +0100 (CET)
Received: from sienna.cit.tum.de (Monitor.dos.cit.tum.de [131.159.38.165])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4SR5z66SBszySZ;
	Thu,  9 Nov 2023 16:51:14 +0100 (CET)
From: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Subject: [PATCH] kasan: default to inline instrumentation
Date: Thu,  9 Nov 2023 15:51:00 +0000
Message-Id: <20231109155101.186028-1-paul.heidekrueger@tum.de>
X-Mailer: git-send-email 2.40.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b="N/TXfWMy";       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates
 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

KASan inline instrumentation can yield up to a 2x performance gain at
the cost of a larger binary.

Make inline instrumentation the default, as suggested in the bug report
below.

When an architecture does not support inline instrumentation, it should
set ARCH_DISABLE_KASAN_INLINE, as done by PowerPC, for instance.

CC: Dmitry Vyukov <dvyukov@google.com>
Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D203495
Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..935eda08b1e1 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -134,7 +134,7 @@ endchoice
 choice
 	prompt "Instrumentation type"
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
-	default KASAN_OUTLINE
+	default KASAN_INLINE if !ARCH_DISABLE_KASAN_INLINE
=20
 config KASAN_OUTLINE
 	bool "Outline instrumentation"
--=20
2.40.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231109155101.186028-1-paul.heidekrueger%40tum.de.
