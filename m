Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTFZSLZAKGQEFZGUJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 223E915B616
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:48:14 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id l19sf1923119oil.7
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:48:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581554893; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5JX04z4Ym/PNX1OKReqcLOQ6mdEMPD1jtVHAYnRH9y7+TKEpAzdxNlX5kd6JkPYQq
         aTLI/S365+qw4kcjmTNwqH4TcRD6sTcpFUNY5sNrWuifEgnPJ86TehgRYfMpg/P2Akmb
         LNxIZ3CzYr9cunisxshvosvpPrmOhWExXtH/9hCiFv+5fiI01vsWfWvUk0i1sUb0J1Yj
         xmb66HTMZSK+/B1eyyDDORkdowp632byVP2JqE3fEV5aLtsqdbXGr+lxFZjmk/uZvQgr
         lc+1dJmDegQ3vxzSMaw1pkpz+96nU09hGvf8LqCvesxdnxoqvd6OXyaTzdeXwRFrjfGx
         Xcgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9TySxcSXlNN4o3/8VzkecNvFw5EuzMzy/VjHCuoFYao=;
        b=Fs+2netmldZdBTX1Yk4yO2Vnsn9eU6XpEIP/vHMVhv8AdL932rKjZa4JAWG1pELO6Z
         NYICAmAPTBhZXBNON1rOF3qq/8v7Iz6Y1xoTVJjChSOvH/l5Le6tReCvMZvAT+WK1AjA
         HHMeDuDTXXlFAcqw5g/YxVuWsFI9HbhnKfa2zoUGZbJr+J1iVf03O37n6adsKMctQn8Z
         QIk4kF09l0dK9LBcZz1QoAnW5SqE66HZWhh0eh3tSm/wwZrNuFCWVd4p832pQWsUp7Gs
         ufVr+8/Pzzv293RI0dnEomHYk+26oKDP81Suu7VzYZ/FWjAfRQMys5C6EAadtKOp+0IL
         CTIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="W9aXQyY/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9TySxcSXlNN4o3/8VzkecNvFw5EuzMzy/VjHCuoFYao=;
        b=gfPoNT8ayqaMw5Srs3sXUe50iKrODr1f+yg0ysh84GJDPPNptAPdSI2zAeoGnR48OM
         ud8B1w3GsugdCkEjacNP2NmDuTXyJ60C9iN/9xwp44TylaEFru7IaycWo1WxwBcafZ3v
         6kLputh2PSfA5n76SD5bFeNcUkf1KjjNr+CrTJOekBH4qw4GPL6vtS5ZtRX3jLVTyKvZ
         78ek6mKKA19PSrPG5d4g3rFtNQJKlbJm+Dt9QYHD4JJY3IjdLNV7krVU+elFi+/1T4Zg
         rxPuKu8yPwqeWOSv8J9wzZtus7P0/vne2qVwaHVSRwolStjcZe9T6prTkuTz7K2kwqi9
         OGkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9TySxcSXlNN4o3/8VzkecNvFw5EuzMzy/VjHCuoFYao=;
        b=tentrYI3zZgpfKV1lZfq5vJVaqrxSbThsfLjbm/OpoAP6bUsa9qrojla3cHm5iCOQY
         uFNffADQFShalaW8czjJtJh2qlXvsMf2R076AQ3mIvOehJdl6o4OsHnQ9tu5b2tb1Ujc
         VzyWfoXy14FunI2LomBG+CAqLvKez79khOh6jA2fbQocaemQmZF6I1kUlPpjzfNnbfb6
         HzAL16vGeySkxq8zFRuVXk1LtRrOMj4sujCBXhObauiO9MHBUSBXBXewhcajjv5yYB4j
         9Oo70XIcYYFHDlRY3c045aR386eB32Xe8YIqHGtzNoAy6+OQ9fNnhQrOIviKX6uZ1kHM
         U8Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUKCYI5FmVZ2R8W3l6rD5DtCGruvJHWS48hpsnvShHS9w0GBFTG
	CHE7eipQT+8JYHedi3cLXmU=
X-Google-Smtp-Source: APXvYqw3OYrC/vZRmyltkBmM8xRvSrV64QE291cS/WEY4D+7GJOY3fudR5IBzmSDJOIyRg9dFJ7VZA==
X-Received: by 2002:aca:e106:: with SMTP id y6mr1271533oig.131.1581554892896;
        Wed, 12 Feb 2020 16:48:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:649:: with SMTP id z9ls7100334oih.3.gmail; Wed, 12
 Feb 2020 16:48:12 -0800 (PST)
X-Received: by 2002:aca:b2c5:: with SMTP id b188mr1250777oif.163.1581554892539;
        Wed, 12 Feb 2020 16:48:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581554892; cv=none;
        d=google.com; s=arc-20160816;
        b=I/ckLYCadesB7s9UOy2jB4xYzBjGa6091aiGltNPBi/lbW6yHLsrwpOeRXkTUUY2ob
         gQPaYFVj08LO1GpI6Dm0A+YbB5QtrtynqDGNjqrvmpUf3TYYTdDFkxu3JjyVUbiQUK7J
         tlsakt8SO+d3TufBU3vfcPkAdiFZxHlW2bRZueX2PMOl5HRPDCiX6DnG0SObM8fFmXRM
         Evza92tGMomEZEEUrJI8dcAUhnIS4kZLsrlGc2Z+A3b1OX06MaGO/1Mlfu2y5eXHgNrY
         VnVxfvFXfrps5H2xrQ03pO9jr+sVDlAnfC5+e+7Qg+o3FAb3fiazeKIVs0sGhXxialUD
         w27Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jwvqhmbLPpvanCf4CYPj6H756JJZayFM0Q320MsSZZo=;
        b=0gh86ZDelmVmyA+h9QIAB+A8dKdlolUbaCA1OgWPSmzxVSFJFMGHxrZm19Ev8Vxokd
         BVUqB0JkiGRAFYcYLr1FLq1VcIumbj0Yu2Ygbtxj4uCXpcrMBbfBswJPOvQntr57wEWu
         jGPENAbegagNResN9nPb58uKb3A+PCInWNqyDq/nt/Euf8DyXwsrLVxFXG630TWfanP/
         aG7AsHbSNFZiuoCKDcho8uipAXaUqpM2UK32tbiQhsMPZsQyi3IveELrJedXoXFAEnV6
         rcMymCaIYCvPRqQzAAGxtE5NK2UVEDh9q3sIKpxs+n7G8Hw6HSrTeK0F5gxnBpWianNU
         u6DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="W9aXQyY/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id b2si41561oib.5.2020.02.12.16.48.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:48:12 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id i6so2108575pfc.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 16:48:12 -0800 (PST)
X-Received: by 2002:a62:ee0f:: with SMTP id e15mr10920842pfi.256.1581554891854;
        Wed, 12 Feb 2020 16:48:11 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-f1ea-0ab5-027b-8841.static.ipv6.internode.on.net. [2001:44b8:1113:6700:f1ea:ab5:27b:8841])
        by smtp.gmail.com with ESMTPSA id l21sm311099pgo.33.2020.02.12.16.48.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2020 16:48:11 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 3/4] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Thu, 13 Feb 2020 11:47:51 +1100
Message-Id: <20200213004752.11019-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200213004752.11019-1-dja@axtens.net>
References: <20200213004752.11019-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="W9aXQyY/";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200213004752.11019-4-dja%40axtens.net.
