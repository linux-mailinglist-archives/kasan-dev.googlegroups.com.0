Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB36BX2IAMGQESXO4KDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 246524BBA2B
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 14:36:48 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id q25-20020a056512211900b004422b53ec42sf793163lfr.5
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 05:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645191407; cv=pass;
        d=google.com; s=arc-20160816;
        b=tdoTBAH3EME/MgpNFugoVE1Bwp2eO0h0sJJ0CxYS/27YdXyTIsdpAl8+1BCYaqdvbR
         kixydxGnmobc3QDwLH5FKqxykcLG+7H4gAoXegotScyy7LEezbsm4HjhwRFtYd+dvwXC
         APVyjsFhXlDLMnob8LoF6ger/2zGI7l5DbQBqr8lUp/KOGZaYttQ+a91sQOKt0L5MMOe
         KqeachuCcBxGKbnVgDvLO1kpxvSITV+MnpCgG4PZdI1TG14wWaKV7Jp4ed02yFN+D4zm
         OHEK2UedQHfTVFakdx+Rek4eTmzOksCSKZ6kM8S5gOlvP17NwIlxsarFjfHesFgpV69f
         dbgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=ZZ7FNraeHV3NXGdWoKbWDGpB4dYtKVOTp+yk5hnMA54=;
        b=Zcj/zfR6z0SjKFC+uic06sjD7BSAitU5IDMeEv2GzWpew635tWHis7DghWW6UP66tk
         48GAtBGVhF8lLIqx5ECNyOcBBljZPINBZ4WiPbBXl+SLQyB+i5qo6RVnqGx+vJUt9Zfj
         CHO1AdmrwgLQ+KsKdeOZlfO6ZlmiQmqqFECbdTEsRY77lLFycxqsERai8pVEb0X2qwHP
         kmsQ82kbNWCCxFMOGcX0nYbPa6Ob1utayetBuI8O+e3Ii5wq8SYsqJ51IihccNFMtdio
         b2Pu2Lv7vtynMIvA5XX1pzMRU8JwrgqVS8NV25Fy+2zK4f5XUITrUt/6v5uvqvo/IkZY
         ErVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=g4ClVBKo;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZ7FNraeHV3NXGdWoKbWDGpB4dYtKVOTp+yk5hnMA54=;
        b=inWpe804DhZyGFg9XJy3P8TAZ0o5wVMegvN1Y18AFHpgUcbysOiKBQt+vytMg2Pp5y
         ckTk5lRkd44FujnoxUKIAlyfq3wJHOUGcDUGC5YW+uMS3d7mHSiCca7fasQZUY17hwaN
         RobMX36wSqfuZNqCOR2/HM5IcnxPlk+8MTZwrJJoltiWCtGf30RrAXIml4H7xCbiFP9r
         W9m+atk1K5dogHYMZ3g7ir4A89acch3jmVd4QJpyWLJBgUQDYY7Jr/NJwFBBunAj8uWb
         0Nb+GEZLXhULm7nU6nBf7N5LTs7/wNhpUQBDCuZpRXvpxJshBUiC24+jp9/U8jAq8+Oj
         BHcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZ7FNraeHV3NXGdWoKbWDGpB4dYtKVOTp+yk5hnMA54=;
        b=yHd6jJOp09bhd1eQFdjU6pMLecKDKIfgei791RA71JXgdEgNxf1vColwUfXoUcu4bQ
         ZaROnIDrkPZ2yzdWmTESmS8m9bkxpjhpyc5v4R2hq9+gwSl5FQ5NAZHE4li0wx9EwS+n
         ugX1xYw3JZI+BS5WYfFQat4ykRt832f9pqU1KEJQIWzLjDi9p4Hxv3Z5hD4at75qoY3n
         d9mP4or7gTTMZe4wc3u+3uVs1H2N+UO2bsjwOwdLoMbJIwn2gW/8IOZXwdwBaelEhR1H
         XJ6R/bzlsNezzsTiq9CqgO55ZSzn6Oolo+3q/F13LohT+LLAAV5djz7GvO/UK1dFxvv5
         3o1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LKf0MUTBroCcoLhhYciyyLi7SzKj587xMTKXcQw7kTP8Tbykc
	Rv3t+lhUWHp8Mh8aHLHjnU0=
X-Google-Smtp-Source: ABdhPJxUGbDuiXjFR0td2+CvW7DgLeya1WOC59pqx95pGr9JA+gji3n3q+Frx/jL5q1FPZThTlRMXA==
X-Received: by 2002:a05:651c:2c2:b0:244:46c6:48c5 with SMTP id f2-20020a05651c02c200b0024446c648c5mr5985545ljo.64.1645191407550;
        Fri, 18 Feb 2022 05:36:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:443:7b15:f451 with SMTP id
 bp35-20020a05651215a300b004437b15f451ls1082645lfb.0.gmail; Fri, 18 Feb 2022
 05:36:46 -0800 (PST)
X-Received: by 2002:a05:6512:3455:b0:443:5dc0:a32d with SMTP id j21-20020a056512345500b004435dc0a32dmr5404059lfr.38.1645191406540;
        Fri, 18 Feb 2022 05:36:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645191406; cv=none;
        d=google.com; s=arc-20160816;
        b=cwFzKPsIEywMGt7AQGE3/m3+CPFeHM4lvBLExa2WU5Lct4S6r17lDRI/0ecrDu0lVG
         /mPHTTR5v5T1zRfqyyNoJOrUig2nR3jfR7qHjz0VkscP/fPbDMpA+z7K3e1HHJ50h3Xu
         J7hhqN70LgyeFVPW6bYI1ImT5NwFPGLzbVYbHHzyavd9U3m/btXgnQc3itSemBtwN7W1
         Fv50F5W2hTKMtD9IUaomQNXciKnIau+vYSIsiPmxeJ3R6pspyxqiuud56O9YDJvnSyml
         pqoRV2Tj8MNPtRQXzXeqsW+CL9nPrCtzH939bnZClKkfQM8W1XTwumvEnLO0VQQ7PEPE
         213w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=H/bO0aBxUyDz5Z1iaHc3hPM9Zt6+vPNG7kqFlweb1Sg=;
        b=tdaGPaN7+NeKjAqqtbWXi2D/6H0jLYjDISBrxXaWV2n6PQ4+g9y8J8ynPlPHZPLsXZ
         XZ4copPycs3bbwnSU5T7ON+VLR5p2mZdnJ7lj7tmN5+fnXeXBnGE1fyrLSGWDZr50MPg
         bTel0iPCn9DjoIBhIA4nnyLnXVa/ov07itna3zAX2hTTx/NMkGx65IljAMVOUDqfAQpd
         zKQR0nwZYScVwmcpGLVCSTwNnF/boy2GcweK7inljYN+iyB1KagKaGEm4H6vMXFhVuQh
         R1SybjSVLZrYzvIeNeEOICbjv+soSsa2uViZvQKdNzSa/tHbbYFEQ9T0/YJUvvFTjawJ
         uZMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=g4ClVBKo;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id o5si145384lfo.2.2022.02.18.05.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:36:46 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com [209.85.128.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id C9DAB40300
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 13:36:42 +0000 (UTC)
Received: by mail-wm1-f72.google.com with SMTP id 125-20020a1c0283000000b0037bf720e6a8so5933827wmc.8
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 05:36:42 -0800 (PST)
X-Received: by 2002:adf:c188:0:b0:1e6:8ecb:ea5a with SMTP id x8-20020adfc188000000b001e68ecbea5amr5888272wre.711.1645191402135;
        Fri, 18 Feb 2022 05:36:42 -0800 (PST)
X-Received: by 2002:adf:c188:0:b0:1e6:8ecb:ea5a with SMTP id x8-20020adfc188000000b001e68ecbea5amr5888255wre.711.1645191401906;
        Fri, 18 Feb 2022 05:36:41 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id z7sm4146155wml.40.2022.02.18.05.36.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:36:41 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes 1/4] riscv: Fix is_linear_mapping with recent move of KASAN region
Date: Fri, 18 Feb 2022 14:35:10 +0100
Message-Id: <20220218133513.1762929-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
References: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=g4ClVBKo;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

KASAN region was recently moved between the linear mapping and the
kernel mapping, is_linear_mapping used to check the validity of an
address by using the start of the kernel mapping, which is now wrong.

Fix this by using the maximum size of the physical memory.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/include/asm/page.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 160e3a1e8f8b..004372f8da54 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -119,7 +119,7 @@ extern phys_addr_t phys_ram_base;
 	((x) >= kernel_map.virt_addr && (x) < (kernel_map.virt_addr + kernel_map.size))
 
 #define is_linear_mapping(x)	\
-	((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < kernel_map.virt_addr))
+	((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < PAGE_OFFSET + KERN_VIRT_SIZE))
 
 #define linear_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + kernel_map.va_pa_offset))
 #define kernel_mapping_pa_to_va(y)	({						\
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220218133513.1762929-2-alexandre.ghiti%40canonical.com.
