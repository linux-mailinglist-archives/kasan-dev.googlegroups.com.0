Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBDXVZ2IAMGQEP5XF2WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BB5E4BDAC7
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 17:15:11 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id s22-20020adf9796000000b001e7e75ab581sf7547370wrb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 08:15:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645460111; cv=pass;
        d=google.com; s=arc-20160816;
        b=JhYW+Xe2u/TFyYnc4FuvYtXcAO9Mm4v/yVl3RZ+n9pIsc/cgJ0ztQn/vzr/GJkhaNK
         HvXyjmCr9Nd8Qna+zlr5lX68LInhxmspYYtAcOgqBUPVBzec4ZtR4qUsBs0yVXNH7nUC
         m7Db5oY2RhH+l+ljhZmlG5WTlox+vy3RCogsqvDx7BDYpVA2Uw63XEkFssQOb1CrlCgt
         A9fTdInPTUr2VpQN2z1jdP6mZ9f2jEk+7Nzdd8Xf/fmcV4DB5zzaZ/juS8qhjcoOS+ne
         R4UQltt1GYxb4c4k6bxd5vOH3SyCefGxkru9sBc/akuOFHhlFva2qMoFlcfFOgGE3Z7S
         aerA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=kyzjwliZN1VsjPJ4+GsyGVuv8bzU1kQhR3Hq9bMZ0Nw=;
        b=vTp3r958tuhKCPWyLVPDRA5WF+5EN9OsVIqnOhYBAsQURwycAs/naKuxgZseSczwrp
         4ueRy6np9qsw7G847YHNv3a2oSKo/SNUPlrndC+nltZquNoFMkAAjsxqwhaJYnTaSS2x
         AQ380QsO/8YcSXBJaHUI1wh9h4ZhF92oEW1IBDXgz5DAL9X9rwujdRQlUmDXpnQKBN8t
         d0tYRyflIQBc37NkNsIVDIKIJMHKQTbjdEi1ZvwIv1COfYMIXJsHfu6S4BQcBAxTiFZM
         3p/2/gN0jyETxTs+JeTUdP/tA3V1OCqVVcpAA94eQ3mtILyVgrz5fZGjUWyfDMEQVbQ6
         CEug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=VN7Dhyua;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kyzjwliZN1VsjPJ4+GsyGVuv8bzU1kQhR3Hq9bMZ0Nw=;
        b=I48FUodu6aHB/wwrtmxIX+nj2LSzfy95fLg92Vl6eqXE/igCw2dsGDHwQVHpqXAkpO
         cfkXvcEHHtVLufmRWfRn8/h013uf4SdXJDJX3jY2oqMijBVNXsj5ykSqAPBTtVj1PA4f
         XqiK+TmVunfcu56vMN/1PioglfA1zxN9eL8Qv9kR4nNmiS5dWcx7t2e03mFgTEoRjSn5
         sB+BRGx4R9pQb73gqZaSyiQJ9TV1IUQoWF+vmbNuhf3AXkH48pmYOs1AM1tcLuB9Rk/e
         BzCmTUUcr/JKm4vpjqshq8LpyMEA2iy2384igLqKHDAtHWBJumT8FRjCLOHY3cX5+5/4
         WY6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kyzjwliZN1VsjPJ4+GsyGVuv8bzU1kQhR3Hq9bMZ0Nw=;
        b=4eiLAcSDeKdZT4Vmev0quxloLhu1PN8WQI5OZUSAZZQqRRX4jX/bKUbSyiX5uHN4xZ
         khqMLJRzmogqpQMN5k9k5vqrPShP1m549mitrQUptvOGG8qXF41XBAfZDe1JiTIVs7GR
         EXOXYW62G5d7+C45rU+zqZgP+WKUXZOQ2IBYzBhC0JPdEg9sTwEBIVjCNqzdFUZLZUHR
         FSZFL/Lmkcmi02O7WkC6FSGhYXKbEhk6I47mQw3gvOPKWy9ZpH3pcdWUczkjhAK3YuqI
         gnKDKpYUhkNMaJIua/djqcqpZHhNaowC9w9NHquTm7+IAqVzDSAWZ/mplxIbF+lS9ySd
         FcZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314ZqtPyenoJaFj+4fZmo4CGG2IbNHv6tihfihCLaQZng8vHJVn
	JLEbhVFcW0bpDvtSKW4roBg=
X-Google-Smtp-Source: ABdhPJz5t2lni7ZEzNXOJomcha1Zcggg1Pas6ZhnrhmHpXNX8M7MsUToF69Ldiuek/Ott9URNGf2aQ==
X-Received: by 2002:adf:8122:0:b0:1e7:b111:3b92 with SMTP id 31-20020adf8122000000b001e7b1113b92mr16770017wrm.695.1645460110907;
        Mon, 21 Feb 2022 08:15:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls259553wrc.1.gmail;
 Mon, 21 Feb 2022 08:15:10 -0800 (PST)
X-Received: by 2002:adf:e5d1:0:b0:1e6:1109:5a11 with SMTP id a17-20020adfe5d1000000b001e611095a11mr16364963wrn.641.1645460109975;
        Mon, 21 Feb 2022 08:15:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645460109; cv=none;
        d=google.com; s=arc-20160816;
        b=rWBmykIu2l5yB/vXTmMdXf0zTax7/rhwvJEWCBoj3DZc4IhXvGqCHIZ4diw0SefN+R
         CnfmkFBd7gSMyCJjlketG9bHnz50eTvzb4IfL83oEAcB6UlLoqDFd4qST924NaPagHcM
         qc8IyVVhpg8WFWXEGG21Zl56NL3uacPzJGAXk7aaFoUQGufaesxpZo636ymG87YcT28b
         2eSXP9Zx5ge5oSNgv0wmmX0/zbDKLKwsjGfmELUmwcYySgfYsQyB5hWiql42ZWbHUGE7
         bXsYl9wJCra40+dWp3595iJaMAMVNUd4QpcbT/QAgrQI6Vl9GWJ1JXS15jwtQVHDNwqL
         OU0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=5wR2inrb50SGryPV3ql5qm7RIRt9i7gNq/sby+Clcps=;
        b=TNsYIVlWlXbuAu8S0bM5MeKZO5gYRH7XUodAx+A93uyyGPx06lBmzOv5vLhTbjJWdw
         0aE9HxO7tPx43vWowq315zJiafVoJQboYhER0JqrSkBsSlBniJSMLgwhzrPN+gThvfsp
         +y70kvg+6G4F5jMkj1iPO5/0/9lnb9CBYKXuflF3MHOhwWFGHqpQYdHXOMTEX3X8NxTB
         ZhYfFrtezfNqpe0mr/6gzE8G+AuFzGeEaw6RB42GcpWOKplHg8Y4xDpSh7blzQojZ9ec
         1h1vAEZKBiYARtp8bFFYcnJBLLDCUweGFKgDMSgqMpEYN++G5QHCwOecj06tuko0kY0J
         RQvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=VN7Dhyua;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id k39-20020a05600c1ca700b0037bb8ca0e20si251999wms.2.2022.02.21.08.15.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:15:09 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com [209.85.221.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 4E8C13F1DD
	for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 16:15:09 +0000 (UTC)
Received: by mail-wr1-f70.google.com with SMTP id v17-20020adf8b51000000b001e336bf3be7so7625847wra.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 08:15:09 -0800 (PST)
X-Received: by 2002:adf:e952:0:b0:1e3:39ed:d990 with SMTP id m18-20020adfe952000000b001e339edd990mr16495591wrn.215.1645460109057;
        Mon, 21 Feb 2022 08:15:09 -0800 (PST)
X-Received: by 2002:adf:e952:0:b0:1e3:39ed:d990 with SMTP id m18-20020adfe952000000b001e339edd990mr16495579wrn.215.1645460108908;
        Mon, 21 Feb 2022 08:15:08 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id 3sm49978552wrz.86.2022.02.21.08.15.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:15:08 -0800 (PST)
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
Subject: [PATCH -fixes v2 2/4] riscv: Fix config KASAN && SPARSEMEM && !SPARSE_VMEMMAP
Date: Mon, 21 Feb 2022 17:12:30 +0100
Message-Id: <20220221161232.2168364-3-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=VN7Dhyua;       spf=pass
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

In order to get the pfn of a struct page* when sparsemem is enabled
without vmemmap, the mem_section structures need to be initialized which
happens in sparse_init.

But kasan_early_init calls pfn_to_page way before sparse_init is called,
which then tries to dereference a null mem_section pointer.

Fix this by removing the usage of this function in kasan_early_init.

Fixes: 8ad8b72721d0 ("riscv: Add KASAN support")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/kasan_init.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index f61f7ca6fe0f..85e849318389 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -202,8 +202,7 @@ asmlinkage void __init kasan_early_init(void)
 
 	for (i = 0; i < PTRS_PER_PTE; ++i)
 		set_pte(kasan_early_shadow_pte + i,
-			mk_pte(virt_to_page(kasan_early_shadow_page),
-			       PAGE_KERNEL));
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL));
 
 	for (i = 0; i < PTRS_PER_PMD; ++i)
 		set_pmd(kasan_early_shadow_pmd + i,
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221161232.2168364-3-alexandre.ghiti%40canonical.com.
