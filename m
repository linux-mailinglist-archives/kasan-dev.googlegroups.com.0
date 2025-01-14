Return-Path: <kasan-dev+bncBAABBT74TG6AMGQE5P76Z5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D1868A10A5E
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 16:10:09 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-3023936c474sf31569151fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 07:10:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736867408; cv=pass;
        d=google.com; s=arc-20240605;
        b=bqygQsSVRndFJQIcQHMkjuRw947TJSBBVG99W3f6JH59fNDGHp5DkDdmj7xCvhsjeb
         bKLdsDiOuH7Ree48YQTNpyAUsRicvvxa8jWLtILCmjmIqzxiMD/4lxsB+dHm6ArlNzdE
         P7CTpzPZ2gVtwjIm6LtuCvpPTo/GKZRcGEX/2CvN80fHeGK3I/NDmuKwoFMiTK7zuL3S
         zRdAZqLQpOSSB0ouIs6mHKC3Vkotczl2WzMcW4lwFeOqnpRsfx1Z/iUZ13nm0Q38QZP1
         vmjuuZ8cfYaaMJaqp1u7k3iIUMXJWnL0Mkb9fAbx50tZaxV73x2wFr3ktCzJ0VrV648O
         17WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=gAdYiVZr2o6QTFagXckf0dC5/ghv3hbPU6c8yebnDWY=;
        fh=43mWdPKtxv2rM5upLvLVxJ0GkOiMqgg56A42zqEQmeU=;
        b=MPPuEjIbt5FBHMhhUov9CJEgcD81QPokCJDEXzuagJo68/CM21m3rVaQGl3SHTqTNS
         rrhQuuPOCaWCqXXK/A/fW4GDz6G2HwtpEX2vphtqoHgAajcbn0JVBWX4zmLLRuo4Pfnf
         eCc9ftK9k3i7+i+8iBu67nwZ51UGNhYpGl1g7k9nbIt5qS5I8ICcOHGXLQS1CXi/LcHp
         JM2F9dtJXOPVoFEMwqfX5c17mkkLv4n5B4D5d0JaiQ7QZJVMjmsc8QPDsnk8knbR0cYw
         MhznYDN3koC2JYsX+zg+xIslQolv7xmsMvh+iaCPitVkks8S29BBzxDvUlcBLuAFwwoU
         iF1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XFnOHu1T;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.179 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736867408; x=1737472208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gAdYiVZr2o6QTFagXckf0dC5/ghv3hbPU6c8yebnDWY=;
        b=DAcTAJqHg3Svrg6DvgbcfyH0UwJzwkL1f31dve55gJ4MZ259xDSEPd5n6mIi2iz0O5
         HujDqedQlnEHAt/w7oy8Dv0XLhmwBuxNahRehcwOuH5k0WUrV3wX5Y5cPZiR4sxGW6Lh
         AgwUtM4fmNviWPPV8PVhAID9FDPIoufOYrwVNaVHsODS83/Wibe8aHqLWSa9alF8yBGl
         uxuKGmtifUzADa4w1ph+GmjzoZOhPp+rQyc+c7o5hvGZgIfwKpSaDUECK7hgG2B/ADZQ
         oIim6b4s3sYN3V8chIbcdQ9NU/cKNmT2/leuVuUO/ZvGV042Z3sfXH452xXpYQ+FsIqb
         vp1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736867408; x=1737472208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gAdYiVZr2o6QTFagXckf0dC5/ghv3hbPU6c8yebnDWY=;
        b=E74lQxII9rebmLU4F4E4TJFu6qz7MnldlxEZJpHLrFme5Yp8BGPi8sBvULsXmDs0sv
         boW4Jrr+Dad1xf3vyLAkOjxga45sSGkg6DnRhxr7qGFtIFVuSat+loJEZQu2XshpKroY
         jY4ONQJANmAaIFEACbeF56IWaQUdpgvjjcB8FIi+zrpqnNAJdu6CoG9vTWaIY87ZJxmv
         +yLtvPIQVHzq9Hq7WFz/jwIRzWSFmTCmPlUn0Bt6teV4kkAZJFLDY2PhPHLX5uY+wU4z
         BObeQ8R10H6fotDyYW5QUTvJdlPxKUd0vofczfIPK6nWAvqL/U60OPBY/4TJ9I1uOsJW
         sYCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8OmUBeXCNuQkNnj+KCBqUIOlfnPCyQDzlkDxk2PM89a+vXL04R9tWFpAmGOHTLAEwwSOJIA==@lfdr.de
X-Gm-Message-State: AOJu0YzQLCBjrTOpMjBwOwC9gB4RiWx232F4FcKiniA0kUeOmGYAyHSN
	8GiVZg11eCdmPUUJ3E581ukEpWK+eafX1OHAGkw2Tb6vPwGAj3/e
X-Google-Smtp-Source: AGHT+IHvrxJkopCvAqejtxG0c6IEmb7W1uttHgTgCyoNsCud0E0fbsti3DtpFXj3WFtEg0Kb9y00rg==
X-Received: by 2002:a05:651c:897:b0:306:26cf:1305 with SMTP id 38308e7fff4ca-30626cf13b0mr20686941fa.35.1736867407769;
        Tue, 14 Jan 2025 07:10:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:864c:0:b0:302:3859:eebc with SMTP id 38308e7fff4ca-305fcdff0f6ls921201fa.1.-pod-prod-04-eu;
 Tue, 14 Jan 2025 07:10:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWn0n/qtPNYVU3VzkBotmjAm1DKzZe+NqneMPonXGlW8ToNK1Hwp2JaJCYFQsUt+4zxYQI5wMX0qt4=@googlegroups.com
X-Received: by 2002:a05:651c:1a0c:b0:2fc:9622:794b with SMTP id 38308e7fff4ca-305f45a4294mr79615671fa.24.1736867405772;
        Tue, 14 Jan 2025 07:10:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736867405; cv=none;
        d=google.com; s=arc-20240605;
        b=SOR2Suc0HkhwimVFPR2XuWJQMzUqAQIskHm6lFG633ZAPP/RrUXDDZyrVtd7YYrKx2
         jGJjxKDbMmLcRa6DgOq+J0n2XMjPzazxEbVEJPzZMkP0cngt8bSSRe9emRsPYAeIvyaZ
         sCWkaX4rzOip6qF4sOvmMvYDkd99saa0CpNqnYUoWn004/28BnXTEJaw0ttBnZgoUmdv
         u8tLrijEUWR3MCa4IxL4gNfmHuf4/1gjrUqLaQBsNpZHohBbs0X1/WLGLlFZwZJzOse3
         xXeET3iNIDqEGwOLmGTR4QUA6m+84gTG7iK8MkuThxHz0oQ2s8UxhMNIl1h9Y4Gqp6cY
         V5lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=D5/zilsgyJRj4sbTAa8LKZAPy1Gx5YuP6bFyTKLkgZ0=;
        fh=JFq/eZK8JHF6utRa265LQQsEKSEfbHrhjf2bY/xbzPQ=;
        b=I2CHGWK+pXy4fElmAUdPGL+id8Kr6ctcqPDFSmsirJkCwRBzwIo/zn0yAyOL3Aq6t3
         I0A6OfN4H2Atp7AKREIyZD8FbAZ32oXQ+CGOuLRnvRcYESCpDRsqWtHZfCc2083lW96G
         4d1R5Z+znucH55fOeC1NkY3XQ1cssSXRNpmRBstk23Z5DUIe8cB4R+IDnQFNMyG8U/TP
         cUJdv94Ppqk2qvuCUU6A8t/brPNCJVZCsuKoh2aOLzOOkKe49l8A7NOjT3/Cd8hzTvFl
         UJMd4RSeCSKWmrRqdqPwEBFs+3bwUPs0hqY4WdF693o8ueNtDDowldKN7up62SXry5sm
         id0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XFnOHu1T;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.179 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [95.215.58.179])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-305ff19d6aasi2180401fa.5.2025.01.14.07.10.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Jan 2025 07:10:05 -0800 (PST)
Received-SPF: pass (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.179 as permitted sender) client-ip=95.215.58.179;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Thorsten Blum <thorsten.blum@linux.dev>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Thorsten Blum <thorsten.blum@linux.dev>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: hw_tags: Use str_on_off() helper in kasan_init_hw_tags()
Date: Tue, 14 Jan 2025 16:09:35 +0100
Message-ID: <20250114150935.780869-2-thorsten.blum@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: thorsten.blum@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XFnOHu1T;       spf=pass
 (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.179 as
 permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;       dmarc=pass
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

Remove hard-coded strings by using the str_on_off() helper function.

Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
---
 mm/kasan/hw_tags.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index ccd66c7a4081..9a6927394b54 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -16,6 +16,7 @@
 #include <linux/mm.h>
 #include <linux/static_key.h>
 #include <linux/string.h>
+#include <linux/string_choices.h>
 #include <linux/types.h>
 #include <linux/vmalloc.h>
 
@@ -263,8 +264,8 @@ void __init kasan_init_hw_tags(void)
 
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
-		kasan_vmalloc_enabled() ? "on" : "off",
-		kasan_stack_collection_enabled() ? "on" : "off");
+		str_on_off(kasan_vmalloc_enabled()),
+		str_on_off(kasan_stack_collection_enabled()));
 }
 
 #ifdef CONFIG_KASAN_VMALLOC
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114150935.780869-2-thorsten.blum%40linux.dev.
