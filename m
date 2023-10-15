Return-Path: <kasan-dev+bncBDA65OGK5ABRBEUWWGUQMGQE3O47JZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9686F7C9B78
	for <lists+kasan-dev@lfdr.de>; Sun, 15 Oct 2023 22:26:59 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-406710d9a4asf27692945e9.2
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Oct 2023 13:26:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697401619; cv=pass;
        d=google.com; s=arc-20160816;
        b=ikFWP092V7M3Wu/Y5Gn4ViclL97COO1QiwQAtvGQGRt3rGNWGUnP/DnyG908u48hy/
         EoNC39WipT0qRkZbgmG4qZp+qUjEKjyA4eQO/Np2+bCc6UZ24k1mGjZ2wdSvwoBZIv1m
         J+UurDOUnkNdd7WaS6vxBKbFdfswB4JQaKa3XpCEBqZ+MdfLq6UH0Oe8/sEwvuDUkh2i
         eX9t+GLHCjPzs0Up/sWteQgSNkNPNKvAvxXE2pkqVqlmHfgIoE5t2rhiJ5/DwZfzoylZ
         TnWx9IsRXAQujqqGxPxV6YCQE9CI4Vz07ST4tFSDDVm55pOWy+UVORTbVHQ3ZDOhfokj
         eTFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=oF+PmZjcuDLUMbBoQBp7voxRDTr8Ryecbc0i4u+4X5M=;
        fh=8wIzoGKF/8WwnpUbhDb2usV0+hxy+4E6rjXfhoczKno=;
        b=LnphdLYl2RwzHFlO8KfCqiIFYvF7qo/jkEQsw9aEvHrxQ68y39pKUTs0nKipsnDCBr
         O3j5lVPGZo+UOPxLUa9wo9+L5ZwcPn2JUR67sPEHajpIzWsIN1Ync1ceRJGWbenfJNPg
         YEyjeVWE/7Qu1vGo2+xs6P7/dlsIEA/FLtFwdnFn6nz0VGsXzqdDsxotHz8VvdFZQxEJ
         XT1Acg3aPMy74LHdkHTufjzQooi/pzhx5vbv60Cfme1474+XhNKiIDRW5LKD6hh7wGF1
         jyI61k0ohdraXppfiP56XT09YIhccX+TdiuBq+cEIFmuyBBn65W5gDpHpmLC9wnXfvbY
         H+9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y8vmicA1;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697401619; x=1698006419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oF+PmZjcuDLUMbBoQBp7voxRDTr8Ryecbc0i4u+4X5M=;
        b=ctpfMWUZKk4dnGkOrBBh8Bc51DT6AECAmC1GDKskPNCZU4Y4ERXhiMN1uF/CRfELws
         tVw3hhtdwPTuG1ixK0BpB4wotHs/jzMuwc8g2jLhN8yTpRLvwjY7KpjOwVVvlCmjEe65
         P6nAFEqIu98SF/eWzly3ytCXcp8S+l0x+1IRpPHMb1BXdJ+ZO3YLW4vP/ZGELtyaKwYs
         bu3j6aNaNt9ksDJElHIPmEI/oefQXICTOVQln0dncySnRrdreXWCgUwrgrgnf4YRW1/R
         QtZTWZrL6SNIi8O3FLRyuscSX+CASmonJNKoEt+VnczX/FbwaiGw7C1Wc3uARXb8xLC7
         liMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697401619; x=1698006419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oF+PmZjcuDLUMbBoQBp7voxRDTr8Ryecbc0i4u+4X5M=;
        b=KFG//oUpGWmer1qYntXrv9UWDHa+5psPp82RM93ziG+3V/QJA6Rv+VRInDgzfLD4W8
         y416aU+uAY0x304UT6ySmUxUmaIOHyE2wvKDxHMFrap+gK54e0cP3nCEem2c9GcaAP5T
         ke7AKC3uvvPLkDTeaBaQxNZTXY3CfbH8YEcTtZ8GWNi9u2ASMQiGKFQqKFRiA27Pjrpw
         7UWDnnvdbxj0pEMpdhGHVRQvnvfOBrnYy7LU560sIMwbu95GNdooW/5fDF84OnzDk7BA
         RkS4uoYh9VakvwnCeXz2/hev4vShUSUzT2c2lbAChqOhybWrHpZVROp4P1gpWcOKNbGW
         UHhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697401619; x=1698006419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oF+PmZjcuDLUMbBoQBp7voxRDTr8Ryecbc0i4u+4X5M=;
        b=cbWKDu74zK1Cllt4OkIOUJhBYiLobDTeYmyOWElhR38uP7AKewbV13Zu6ijPYqjow4
         6AjfTiIaZwHwBcfGwizfU3BxB1iBX7C3/zagGhWegttLqfZG2VlRd24EhbCzm2Qbx8bA
         wm3Xi88xNbBZAw9+HpaXyJKEuzQ4GpHMLCclfQCvxBe3Ksrfp2LFhmSAn5GCGDz1a9o7
         QhCphnHWe7hHxHBaJYKBs9DkER1nCPr2bgrWLtS5etEUC+LB2k85Rf9dDTZPRSyrcNjU
         eqyC9M8RoHFAXNlSZVmlB2PETDTsTPkbCCCsWAk9BJqAfcWpmoFO+TgndhrGsoYWac09
         8gfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxTdrAr4X2uhuvuAzOea14Q308ol1u6Eb6dBo+h1SfUSNewBKDm
	R+iaqOYH/I/UfDzzfeW/PrU=
X-Google-Smtp-Source: AGHT+IE7TlhcW0bia5WG6DBaQojHVYVsjcN3u3njBRgXn916UBdElun0i+Xfq6u8Cl3mv5FyeoMQXw==
X-Received: by 2002:a05:600c:b91:b0:406:84cb:b014 with SMTP id fl17-20020a05600c0b9100b0040684cbb014mr26746020wmb.22.1697401618480;
        Sun, 15 Oct 2023 13:26:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e8f:b0:406:3989:98ae with SMTP id
 f15-20020a05600c4e8f00b00406398998aels690268wmq.1.-pod-prod-07-eu; Sun, 15
 Oct 2023 13:26:56 -0700 (PDT)
X-Received: by 2002:a05:600c:2050:b0:405:40c6:2ba4 with SMTP id p16-20020a05600c205000b0040540c62ba4mr27135189wmg.5.1697401616799;
        Sun, 15 Oct 2023 13:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697401616; cv=none;
        d=google.com; s=arc-20160816;
        b=0M1Oh21mK1sSbghGI9tAqaZRAd1xWFgaS38RGMfE8doDVFYptLlP/9QuH3xGe57Quz
         WmuGPgOuQpLqybZNR2vKM3xoTZLJnGnH1EqQO18okTSJEbP4VMacZaDLeXdpwVWJshQV
         6Ag/BYrCkyuJnqZqEmzlc0d82SKRL4FvDfBEaJ9IInRm+jg05GMEgw002HyoAaDOZnK7
         uInoe603okphpC66lwFea+gpCL/abtmkcSvY+f59iTUdRRtDdLaJ4ysPxib5BAcdRgqE
         TLJ++JtPDYYxmpknoxiG8bTRqDRGlcFHJyELj4fTL3TY02O0Wcaln0DqwXow090z9DSG
         nVJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9mJQUt7Wf0+dPq/8JTeI94cIlxhXMv5ZBTCjETmdTqU=;
        fh=8wIzoGKF/8WwnpUbhDb2usV0+hxy+4E6rjXfhoczKno=;
        b=f/Qp1hIVWuS7rwixsUee5WWD8Q++WaDKfe52+knROgKw2nKnZRHzEjyEzxKtznnR8Z
         fTTrB6KQtYpx3yn6d4Y/wPMxNFYjVWndlYvgdIwDAXAr77Oe8ULgoFeDh6E7SxDuvSly
         hvRX5p1uqEFl7EDBhe3FhWpeRO26jypbbLt0Wa2zR05G6aWE0CE727GtKs7jissXxKiZ
         PxFSO4ryU+J50GtHdVINgiavGUzi6SYyVUc0EqSFMidwMYrPuxi0UScCe9T2/LPK4X4x
         WfL2PT8umsOVekJ61490oYoM4XKXH1iVlK38iCYFOcA3dPM5lxQr5NuJmBmx+0uUeHGt
         O2IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y8vmicA1;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id bd7-20020a05600c1f0700b004045b3248b8si177942wmb.0.2023.10.15.13.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 15 Oct 2023 13:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-323168869daso3686056f8f.2
        for <kasan-dev@googlegroups.com>; Sun, 15 Oct 2023 13:26:56 -0700 (PDT)
X-Received: by 2002:a05:6000:1189:b0:321:6936:c217 with SMTP id g9-20020a056000118900b003216936c217mr26180665wrx.14.1697401615768;
        Sun, 15 Oct 2023 13:26:55 -0700 (PDT)
Received: from PC-PEDRO-ARCH.lan ([2001:8a0:7280:5801:9441:3dce:686c:bfc7])
        by smtp.gmail.com with ESMTPSA id u1-20020adfa181000000b0032da49e18fasm4303429wru.23.2023.10.15.13.26.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 15 Oct 2023 13:26:55 -0700 (PDT)
From: Pedro Falcato <pedro.falcato@gmail.com>
To: kasan-dev@googlegroups.com,
	Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Pedro Falcato <pedro.falcato@gmail.com>
Subject: [PATCH] mm: kmsan: Panic on failure to allocate early boot metadata
Date: Sun, 15 Oct 2023 21:26:50 +0100
Message-ID: <20231015202650.85777-1-pedro.falcato@gmail.com>
X-Mailer: git-send-email 2.42.0
MIME-Version: 1.0
X-Original-Sender: pedro.falcato@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Y8vmicA1;       spf=pass
 (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Given large enough allocations and a machine with low enough memory (i.e
a default QEMU VM), it's entirely possible that
kmsan_init_alloc_meta_for_range's shadow+origin allocation fails.

Instead of eating a NULL deref kernel oops, check explicitly for memblock_alloc()
failure and panic with a nice error message.

Signed-off-by: Pedro Falcato <pedro.falcato@gmail.com>
---
 mm/kmsan/shadow.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 87318f9170f..3dae3d9c0b3 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -285,12 +285,18 @@ void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
 	size = PAGE_ALIGN((u64)end - (u64)start);
 	shadow = memblock_alloc(size, PAGE_SIZE);
 	origin = memblock_alloc(size, PAGE_SIZE);
+
+	if (!shadow || !origin)
+		panic("%s: Failed to allocate metadata memory for early boot range "
+		      "of size %llu",
+		      __func__, size);
+
 	for (u64 addr = 0; addr < size; addr += PAGE_SIZE) {
 		page = virt_to_page_or_null((char *)start + addr);
-		shadow_p = virt_to_page_or_null((char *)shadow + addr);
+		shadow_p = virt_to_page((char *)shadow + addr);
 		set_no_shadow_origin_page(shadow_p);
 		shadow_page_for(page) = shadow_p;
-		origin_p = virt_to_page_or_null((char *)origin + addr);
+		origin_p = virt_to_page((char *)origin + addr);
 		set_no_shadow_origin_page(origin_p);
 		origin_page_for(page) = origin_p;
 	}
-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231015202650.85777-1-pedro.falcato%40gmail.com.
