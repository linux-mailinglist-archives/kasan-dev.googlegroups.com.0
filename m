Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBZ6CX2IAMGQEREBRVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CBA204BBA2F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 14:38:47 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id k36-20020a05600c1ca400b0037ddae32528sf2857194wms.6
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 05:38:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645191527; cv=pass;
        d=google.com; s=arc-20160816;
        b=yThV0rfho9uH+ZK1S9o2uIYlrCBX1hoTstv4ZjYOdACd7C8u142jYTBJqKxXqyRcW9
         fxXmW4IP5i0+dPZhCVCmI7wnpdw2Y3F1RuOKjDB+TBrkm56G+XnULr7VRZyOfsNXiZLK
         kr6MrufwNge0Rpw1FTrsp0mD/+d6hgSe5vzoLWxQRF3RE7cSaVVZoThB+nZ8BGfZwqna
         KGvD4sQyMs1LXP3q9mSUu0ywd1oVNKwQ6WbDgT6ZRqMLomE5+M3tmtrWROKAMfOy9nmR
         8nrwb5e1wm7pTFr+mq2RV6/nViamuhYGuWBHx9WUC1D+wP4Av28LAGto2NEU34qie1Pp
         ZOcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=9mTCHBKGDGzi/WiI7IGdxJwiiNK2tpaXDhElAKHlU1Q=;
        b=HMZ9/wTCBC1tGFwtoNjWhuoPHSPg36fIai4qFIDSoIkGzfbsXTexMV9pS179h0eAD3
         0wOvcBYe+57GWl3b99dVSnLYnrOp1YAIm2b1zax/VQEbJh+cXwpz/A7yho8MeF5mOrCF
         IWpFTD3yPnoawwy4X5T5UFsHlB5yLug1ZtZcddyEiGL1LSwNZyCZnA+wIe8Awvqt0tXk
         GYPktpRCLH1iCQ84Rt9xN9s70aT6IbvMVus7GxxPaL+msNH6fgN/4Sm362QlQ7u2Uie+
         HuV2LV2FPLB/JVyzXLMrA/did/mrNRazicbzf2xzrNTbFeTky7UArsFv701mz0hkaLDG
         +FHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=tE6HaCik;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9mTCHBKGDGzi/WiI7IGdxJwiiNK2tpaXDhElAKHlU1Q=;
        b=RYOEpFWzkoXgYzsnzWOi9thAR+rXpOI/KwJ5YEz5BPF7LMasfL/qyEUpJC08x3JBkY
         YB6t8FSt14wT/jcmKu0TWMfmvavagdSu33D2nNM0LAld/wQ6dEt4k7KYELIcJegkkfIW
         nbXtcjFUJoSr4JeiM9s7lhjDe9YfTarr7MkxzNprGhN7xNud30BuVGjNQORCRmXv2OhL
         jG4OZox7E15aGzX6DPlfMVaGCJdn534U96TdBL2IRUYQI/l6wVV2MtMi5+XYXWgcI7Wl
         Z2Ejd69QozThPEKG9W9EXRQb2liTujpMpqHuzYX7F5HTueF2vf3M5xkKVZLZPp2bon1B
         M/KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9mTCHBKGDGzi/WiI7IGdxJwiiNK2tpaXDhElAKHlU1Q=;
        b=YHlLSTirt6T1uGVSPLGO+wbWqBp1f/fYzRlaO7cHYBv0cnUdgbGEpPdXqysojD+zcj
         C69xKPAOvT0NtYvDBielel4LAUJsvXwx1Tdu8SHOZ4MjQiALpgqwixiyzZ8ofHdT6WIx
         MmFpKzEkWkJ8bY4CvDEQ9cEMQwXvue7/aSYfWxnUTmwRWAVCYYBYGBEHs0Wd4VQBL2cN
         lMQLFxzd9b44IThfaNU/0/KiMGRVVbQ2345EppPX7IbCZT1kgEktyVcpdtvDE8DPGuW2
         RvFCfbHQkpLH2LFDoN2EcUkqklzTd+fhV3yWN3/nChK9NBPvbe/VqGpuAc/PdpwTNIqn
         mrjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rp08n4nHSmfFnQ1THxw1b5NGw+z2AN4+mG8rP9uqxEEfEE9go
	vQl3cVQNBwzHqcW8D48Z/Mg=
X-Google-Smtp-Source: ABdhPJy1yqAeR8mfiVNh0U8ao/XZjY1gsfRb04gplaeJqZOclr4Q2yNERaWZh9Z1XhXSR4s3Pw8EHQ==
X-Received: by 2002:a5d:6b8b:0:b0:1e5:2d46:d150 with SMTP id n11-20020a5d6b8b000000b001e52d46d150mr6196462wrx.380.1645191527565;
        Fri, 18 Feb 2022 05:38:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fec3:0:b0:1e3:3e51:b38d with SMTP id q3-20020adffec3000000b001e33e51b38dls328469wrs.1.gmail;
 Fri, 18 Feb 2022 05:38:46 -0800 (PST)
X-Received: by 2002:adf:90e2:0:b0:1e3:f5a:553c with SMTP id i89-20020adf90e2000000b001e30f5a553cmr6016682wri.476.1645191526753;
        Fri, 18 Feb 2022 05:38:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645191526; cv=none;
        d=google.com; s=arc-20160816;
        b=tda32g2fcmmtHl8US8ddNA6lNjb9U7szfwkPiCWYe4qwH9JBYfsYP70ffAgphkhCnv
         1GvwLB7OyUx+o1ygr7yzf2eahV/GpIGdS9G3xYX0+BEubju+ultjlukn5ShxL1DZjrh+
         qNOOYwlUHz+u0N88nYvIl88CUYyTHOZEQGv6nj8bRaNM127Ii4j+D2hiA+YP0ByzEa3j
         PJd6a72KrN4/vZLQdk8/ruml9POIqXI101gu/+DmYnQeIJaNcmbKP5HYB9m729KI3Z24
         WVvhSS3D4Y3UHpWbN1DhUMkJUzI+SGw+11hFkqDcDQNEBZUUiNROuqH6uEMQ4eSbf/Cf
         WzGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=cguSXJTSK/jUGjEgH9bI1vq5RLn1H9fQDOjhSSVs79w=;
        b=jnsWRJ7JRFzd2+1l2XNbALW/GLNXeW3sIdYoWaVC/4VX9YrmcVVgvQjxeHGtyCAOjk
         +CrNg5XgAXCIXQdpzxOjXwC/YqSt+UDXo5do/2c9IbDquXXkif0afzxehUxCDfQXTqY5
         blPvIBVpFd89fS3GWaIDsiaaF0yZVmf2KRsrs2Skmikvl4u4YjL4OVGVkAlstlqFyS3S
         7Oqn5oXBgXI5xyHZ806D1V9rAOrPd1RDUF+jSAivoRuS7LEx3SyvJicHcZzMTgbePhpe
         +oqBtPa/97NOYXWXoHMuDI/zBnxNM1GADO1xh4J9r4hb7BNCc0tzYt4Nj8WKWOm9/eUy
         Ov4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=tE6HaCik;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id z15si274465wml.1.2022.02.18.05.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:38:46 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com [209.85.128.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 7F31B4004C
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 13:38:44 +0000 (UTC)
Received: by mail-wm1-f72.google.com with SMTP id j39-20020a05600c1c2700b0037becd18addso2860379wms.4
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 05:38:44 -0800 (PST)
X-Received: by 2002:a7b:cbc6:0:b0:37b:c56b:9eb9 with SMTP id n6-20020a7bcbc6000000b0037bc56b9eb9mr7250939wmi.17.1645191524257;
        Fri, 18 Feb 2022 05:38:44 -0800 (PST)
X-Received: by 2002:a7b:cbc6:0:b0:37b:c56b:9eb9 with SMTP id n6-20020a7bcbc6000000b0037bc56b9eb9mr7250929wmi.17.1645191524072;
        Fri, 18 Feb 2022 05:38:44 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id g5sm4282472wmk.38.2022.02.18.05.38.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:38:43 -0800 (PST)
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
Subject: [PATCH -fixes 3/4] riscv: Fix DEBUG_VIRTUAL false warnings
Date: Fri, 18 Feb 2022 14:35:12 +0100
Message-Id: <20220218133513.1762929-4-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
References: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=tE6HaCik;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

KERN_VIRT_SIZE used to encompass the kernel mapping before it was
redefined when moving the kasan mapping next to the kernel mapping to only
match the maximum amount of physical memory.

Then, kernel mapping addresses that go through __virt_to_phys are now
declared as wrong which is not true, one can use __virt_to_phys on such
addresses.

Fix this by redefining the condition that matches wrong addresses.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/physaddr.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
index e7fd0c253c7b..19cf25a74ee2 100644
--- a/arch/riscv/mm/physaddr.c
+++ b/arch/riscv/mm/physaddr.c
@@ -8,12 +8,10 @@
 
 phys_addr_t __virt_to_phys(unsigned long x)
 {
-	phys_addr_t y = x - PAGE_OFFSET;
-
 	/*
 	 * Boundary checking aginst the kernel linear mapping space.
 	 */
-	WARN(y >= KERN_VIRT_SIZE,
+	WARN(!is_linear_mapping(x) && !is_kernel_mapping(x),
 	     "virt_to_phys used for non-linear address: %pK (%pS)\n",
 	     (void *)x, (void *)x);
 
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220218133513.1762929-4-alexandre.ghiti%40canonical.com.
