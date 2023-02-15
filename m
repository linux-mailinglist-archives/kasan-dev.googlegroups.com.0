Return-Path: <kasan-dev+bncBCTLRPPPRYMBBXEKWGPQMGQEZZFTU3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id E793B697460
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 03:37:18 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id c9-20020a63da09000000b004fb1a5a46e9sf6657310pgh.20
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 18:37:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676428637; cv=pass;
        d=google.com; s=arc-20160816;
        b=OPHC/EhMCnEdJP8FsaVv43QzB4s9an1yvRyubDqDa0N9O+EuPjQjfFn0M4epFvtGGv
         kviFN8D/O6F+koWYru1uaJt67VbFjRFfj+bQ3u6t/5a3g862ilySikkifOKqgD8KOEHL
         XnCsrc4X7swFmk01e93Leq+nqnNxtQ9yyDi84JGvcOKnYkDS0xuyezbGdLYScehaa0nm
         iGUvdvyPf3raycB7aRqQXjT621FX36+K/XpE03h3aIetYux3bG1K1fGsrc7fIFOhEnDp
         wabOexl2KTxVHq6APayNHHj+HPn1hdrmmdYlqFzuqIIaF8c/2QWt0NeXZWfQzPJFxqmu
         uNGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=AwErHHoR234dyuYIYj1YS8QhXBTHC8okIPsuzAZCNaA=;
        b=n5FsIOEDTUit19RySFz9l2P3yQCMTEZf8bwY8QJKsjgF40C1dDeXfrha53yVBPl1bQ
         e6Aiox2GVRRCTNV+F/ksZNNtA9oRLwElRS2dbsHdpa9eDX1GqKY46puZ/GaHFsfD/7Fx
         GKPBwU3/bX3/dFoebf/wTXnIO7Pq1qHXkTN+A/zMY2+AtGrz+UHIlj3fVLqvMDLfNMFJ
         8P1BCaksZOALxs5FKoq+JtSY8f1pKyqZhn/y/kxl2cQmoaE2EVmLBgHHmM10zCFJKrxr
         rzAP/MLmOBx+5zpkHohOW3Ciu2AIg0pHknw5pMfu9/qo5opcy7olQwOn3ebQ8uZIbjJx
         MyRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bewilderbeest.net header.s=thorn header.b=aVyUaHtF;
       spf=pass (google.com: domain of zev@bewilderbeest.net designates 2605:2700:0:5::4713:9cab as permitted sender) smtp.mailfrom=zev@bewilderbeest.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bewilderbeest.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AwErHHoR234dyuYIYj1YS8QhXBTHC8okIPsuzAZCNaA=;
        b=R4JJq8OnkWIPmnpr1ygdAXJmnp00A+mw2jVCz6zUuX9grUa/gjykRt6e1FC3D7bP6P
         4DwycnQ7r4G6rPn1uCBx5O8jFwzbA/xfMYgCwTFv3XLNoRrimQgPewmGYibTsRru1iFG
         6rWXMDLR5h8WwdIECWLTW2ZfAWxlhD/rPtwGO3u0oe7LMKkQicBR9x4LnoGPp2hUjXLh
         +h1vvMak6KNVend/K51yyCnztiVyabwk9EZwZmbwY67iy2+J6Sq2wawu/zfZSEl6A5OI
         ShmrQpIToBi31jENmvJVdhp3rBMh4rk33koD1Fp6mIP0/q0wnIkmRo9DUTkIOUsMp9Ji
         z17w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=AwErHHoR234dyuYIYj1YS8QhXBTHC8okIPsuzAZCNaA=;
        b=i2STTV5ZsY4Yf4glZ6Dub6SbUkL30T3hn35saoBIiNTo7EKV77TrlMlJsw0w4UnW+Z
         6iRg1IKY3JsxDr9RLgOnh16XH6rEq8pkasyTG0+vyDLTWRT83EuV0HUvQq9w6zNXmmo6
         42qGpOhcuR5EwSPe2DYYXygRlpHqu4tOqd4m/nytIdi2lzw0C1bKa9plyoRigPYkttAe
         MhPzVrK8WaimicjWykq6twQ6Hk5TYJnvQ14KHRwS6YE4Ta9hoCafaTYDPkRVoKHAI+Zm
         eMJlQcJA4owE66WsrQOAbbAP3lLKk8DJzCnmgNM3Le4MCniLnwpCqBPg5x+/ljQgOif8
         iB+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX9zh9TDfH+hVs4jQnnntWKUOxX5xCsgoWpKC5jb5BdJe0e0k6J
	lVAZneXV6lmRx4omRPJ3wJ4=
X-Google-Smtp-Source: AK7set8aRGDffpaJ4F1eHT/MFKQ9enCOzlZ7PK2qpguNQi2rG886r9CCgGh8Zen21xiGR9cHyrjrNQ==
X-Received: by 2002:a17:902:c412:b0:19a:9ba6:6521 with SMTP id k18-20020a170902c41200b0019a9ba66521mr207606plk.5.1676428636862;
        Tue, 14 Feb 2023 18:37:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3912:b0:234:2ef4:2e9 with SMTP id
 ob18-20020a17090b391200b002342ef402e9ls753063pjb.0.-pod-control-gmail; Tue,
 14 Feb 2023 18:37:16 -0800 (PST)
X-Received: by 2002:a17:90b:1c09:b0:234:27a4:fba2 with SMTP id oc9-20020a17090b1c0900b0023427a4fba2mr1038656pjb.18.1676428636084;
        Tue, 14 Feb 2023 18:37:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676428636; cv=none;
        d=google.com; s=arc-20160816;
        b=aC6+X1lFDS4J1ZB4bH0mLxkzN7T06WDJfkJ7OaulVc7RpvcxTNDpNNmobNkT77j7aY
         NFkaVv7/lIQdC+yy11ZgI8fcoJ33d/8dlDAJXSHlPcuaDbfUMVUv2KqNkJchKIKUmMeS
         Sg3HHWzWhup8abSybpLlJDhmsgB5C/f1lY/7R/ag5IeHoQA9ZCU31AaGJM/9CCdpOma+
         TImQsSo83zeh4UUh2L2nIqKh/H6l+8tZMI05PdoXE+1s1onPKaiqfuIBAtnFi6If76LM
         p3bu2nm0oZVAAjqfHx+F+M5xjvfVNZrDTzHVMVopk3+KW0udkWaR3/Q1T811fEQY46QV
         stvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=af7ZZHxNFz5At1W5VcQd3z15hu8uNlmxF78QrinEHLI=;
        b=uA/TSD4r4+do/D9jItP3zeKL2PsGH6ksVBMFwwkWh8xub8F/tWaKQvqvTpktTKkWH3
         4W7Poi9LHDQ2MCo51Kj8WPDolebmOal+o1rcJ9sj82Z9SBPZikW+j3nxy9uil4L5sCct
         DA5Y1NVHNxiWt1UGPUxzuctCmuIdJWbJJE5jo+9utpga475xjE755UT+Vkr7Botl92Am
         dkm5jNSyqZCpeWJTA9Rk0yFjmTjI+CubroX+7IeYPcXc9KxOAtDGV3ONiobYDAoGJw0R
         S+8EPDASw0axZuAkBUgIpLkYRQM76x6RZlZLxKIEAXaFL5Y8vTsvp3VoY2+sdzqzOAn9
         GDZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bewilderbeest.net header.s=thorn header.b=aVyUaHtF;
       spf=pass (google.com: domain of zev@bewilderbeest.net designates 2605:2700:0:5::4713:9cab as permitted sender) smtp.mailfrom=zev@bewilderbeest.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bewilderbeest.net
Received: from thorn.bewilderbeest.net (thorn.bewilderbeest.net. [2605:2700:0:5::4713:9cab])
        by gmr-mx.google.com with ESMTPS id e17-20020a17090ab39100b0022c4c6f4b8dsi53776pjr.0.2023.02.14.18.37.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Feb 2023 18:37:15 -0800 (PST)
Received-SPF: pass (google.com: domain of zev@bewilderbeest.net designates 2605:2700:0:5::4713:9cab as permitted sender) client-ip=2605:2700:0:5::4713:9cab;
Received: from hatter.bewilderbeest.net (97-113-250-99.tukw.qwest.net [97.113.250.99])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: zev)
	by thorn.bewilderbeest.net (Postfix) with ESMTPSA id 78EE282;
	Tue, 14 Feb 2023 18:37:14 -0800 (PST)
From: Zev Weiss <zev@bewilderbeest.net>
To: linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Cc: Andrew Jeffery <andrew@aj.id.au>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dinh Nguyen <dinguyen@kernel.org>,
	Russell King <linux@armlinux.org.uk>,
	Sam Ravnborg <sam@ravnborg.org>,
	Stafford Horne <shorne@gmail.com>,
	Zev Weiss <zev@bewilderbeest.net>,
	linux-kernel@vger.kernel.org,
	openbmc@lists.ozlabs.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: [PATCH] ARM: uaccess: Fix KASAN false-positives
Date: Tue, 14 Feb 2023 18:37:06 -0800
Message-Id: <20230215023706.19453-1-zev@bewilderbeest.net>
X-Mailer: git-send-email 2.39.1
MIME-Version: 1.0
X-Original-Sender: zev@bewilderbeest.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bewilderbeest.net header.s=thorn header.b=aVyUaHtF;       spf=pass
 (google.com: domain of zev@bewilderbeest.net designates 2605:2700:0:5::4713:9cab
 as permitted sender) smtp.mailfrom=zev@bewilderbeest.net;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=bewilderbeest.net
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

From: Andrew Jeffery <andrew@aj.id.au>

__copy_to_user_memcpy() and __clear_user_memset() had been calling
memcpy() and memset() respectively, leading to false-positive KASAN
reports when starting userspace:

    [   10.707901] Run /init as init process
    [   10.731892] process '/bin/busybox' started with executable stack
    [   10.745234] ==================================================================
    [   10.745796] BUG: KASAN: user-memory-access in __clear_user_memset+0x258/0x3ac
    [   10.747260] Write of size 2687 at addr 000de581 by task init/1

Use __memcpy() and __memset() instead to allow userspace access, which
is of course the intent of these functions.

Signed-off-by: Andrew Jeffery <andrew@aj.id.au>
Signed-off-by: Zev Weiss <zev@bewilderbeest.net>
---
 arch/arm/lib/uaccess_with_memcpy.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm/lib/uaccess_with_memcpy.c b/arch/arm/lib/uaccess_with_memcpy.c
index 14eecaaf295f..e4c2677cc1e9 100644
--- a/arch/arm/lib/uaccess_with_memcpy.c
+++ b/arch/arm/lib/uaccess_with_memcpy.c
@@ -116,7 +116,7 @@ __copy_to_user_memcpy(void __user *to, const void *from, unsigned long n)
 			tocopy = n;
 
 		ua_flags = uaccess_save_and_enable();
-		memcpy((void *)to, from, tocopy);
+		__memcpy((void *)to, from, tocopy);
 		uaccess_restore(ua_flags);
 		to += tocopy;
 		from += tocopy;
@@ -178,7 +178,7 @@ __clear_user_memset(void __user *addr, unsigned long n)
 			tocopy = n;
 
 		ua_flags = uaccess_save_and_enable();
-		memset((void *)addr, 0, tocopy);
+		__memset((void *)addr, 0, tocopy);
 		uaccess_restore(ua_flags);
 		addr += tocopy;
 		n -= tocopy;
-- 
2.39.1.438.g79fd386332e5.dirty

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215023706.19453-1-zev%40bewilderbeest.net.
