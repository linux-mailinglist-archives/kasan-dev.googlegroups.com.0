Return-Path: <kasan-dev+bncBAABBT4JT7CAMGQE7BEB5KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 04D93B14221
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 20:43:30 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7641e7c233csf2277813b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 11:43:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753728208; cv=pass;
        d=google.com; s=arc-20240605;
        b=kODCZrS9VTfQQxioGNlUJ/CR/ITCYiHaeDVA6NSat3RcxMLPcQ1IRyOyV5DushWoDA
         g7NGhXcO0nHPbafArrWroGRppBeBvKcDJEiG1tUnJnREQidR+xt6xRK/g4FCvXKAH3Hj
         uN/UT+t9x3reGKeEZZ+D5drDRUQe9ya/FQkIHKe7pHBDb30/qP1uJCl9YCJeurHhDZBZ
         C5zCxi1ahFAzaTkVvoAiLD4Xjid+VUXTGVF4vDrFIsCnMhhkG/P4ZB/Lt7a660lLeake
         tIr0pRM57Y4rbYuIQ5ps133RIsqdcZvSeomrxaa/3PhJU2216Z/daLnAjUn3GMSB+//0
         PMdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I7xQO73lYWM1JzTOG8+n9sxWvtnHZKUuJLxhJ//oBBg=;
        fh=6DqDlwS3rt1vWS6aFrmzRPE4sryadWH86vHJnPqZn1Q=;
        b=aiDIgqBC0NrcJav9UKXHuZbFp4JtyU5TaJaB5ZIR5cWONNFjK4sNajrGzdQW4lIIPw
         42/bLi9OGmv035n+ZxI0FyM8xa4X34O4FpGkSqGcLW9v0Z8zFk1NzgVYf4kFl1TKKWHa
         mffVqjVVdQCb3CZ7gv6bj3yL+lRYuzhBiNKk21JJwGuyTza/gF4qxLOkGRg2gd9XIVjR
         9OcK6RdBxPDmivgWAys+ryyQ8CSzaQPRPdVf91PiMstRF4aoTRw72Rs5eTefvB4N8lH0
         cTz2vyeawwo5c9m4YFvHbo+psXVOzRi7F5E/KVZgIFILHNrUaVyHeMU8UmruBREWyRXn
         cDFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@utah.edu header.s=UniversityOfUtah header.b=TmbQg43p;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.47 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753728208; x=1754333008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I7xQO73lYWM1JzTOG8+n9sxWvtnHZKUuJLxhJ//oBBg=;
        b=M+KjHW2kQWnuq5XxSc0u+eZ9rleFirvSHB5PSc6NPUznSiH2T3zRqtBMxjAzlj6tak
         KjxPSmJ98GZzO0Syaz9KsG/nKtLGKeZL1iTWNsSqjeVc+I6YE28hkLKsratW8dtEpAdE
         p2O9B9PbpnA/JiCcX+igD3BVoDuwcQEVWZFhKVX5fIXo/4NAWrVsdrMql5AFt3M7RLif
         A7LA8GNRdex4G82NdO7VIln7HEDAm/VHGpCG3PfxSMdFjJPnlmaYbh6G1M22ECxopHIw
         ZzNNKMGIVofCz0vKb05WXPEIwAiseKfm7krsvrWEY4r3GmHRbuM7sMq678ubfct7mgTV
         kU3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753728208; x=1754333008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I7xQO73lYWM1JzTOG8+n9sxWvtnHZKUuJLxhJ//oBBg=;
        b=g9Zfe5H3AHsqggen0l65YWTSjLVvcMgPOBJk46RuSLa7A58I70Nu74R83wIcY/7wjc
         DiBZ3gwqbS4xpzDkxp5ch61n9KbDIr6ddJvT8n0rA/Hm9xEe36DwB1CXXr0mSlWS54BO
         1fOizeLdDswyQxF45EjMznx+2y+w5UtGN1ZIhIsONWOSzHiWqS/cruVbldGSntSsOuAy
         qGldYzH+pJFz1+DXjO2xG8H7yGrbNV47QToafC0/BmlhDw7Ta3xoqrIDq/BTPriUlMUK
         OyE+0d6P9of+d9wt2abVCFfCFv7hyIA88DquWIJHJV/0SWJfoyYWLtfDGmk6TvbYMpfl
         A5Vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSWQKVIn6Pu6DfxBfvJqmd+KKGm7mzCiS1ftNw/2KbovENrVxOcr6KmFDb59kzF+TOGJcv/Q==@lfdr.de
X-Gm-Message-State: AOJu0YzRJZ6By2GG9CgRgC3FIoQSecZ7ny1SQxJU3dImADySzVI4yo2K
	FZPPUHnW1Knrn97K25b1QbkuM8idbIPDh/CgzGOtb5rJi0V95+ppovTF
X-Google-Smtp-Source: AGHT+IG3xM0gfld5A6qHg6W8Fhnj9PGd1j7cOAH2ao3GBH1nK4rDts1HeelgNE/V6rJZF6mxpzB34A==
X-Received: by 2002:a05:6300:218a:b0:239:1625:81ad with SMTP id adf61e73a8af0-23d7018ed9cmr18471288637.38.1753728208049;
        Mon, 28 Jul 2025 11:43:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcTrKWbtvLQjGjAzbL4jgF7ZZH/wCL8rhyDH3qXIWAfAw==
Received: by 2002:a05:6a00:4603:b0:732:d98:9b2e with SMTP id
 d2e1a72fcca58-7615fe9804fls4691740b3a.0.-pod-prod-04-us; Mon, 28 Jul 2025
 11:43:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWm+T8Bhdf0PvF2TeTsUMi3343YuA3KRgDaU/PRUQ4d2DWk58zlTr1pMMb2NTFKA/YN83CG96+J9U4=@googlegroups.com
X-Received: by 2002:a05:6a00:1950:b0:732:2484:e0ce with SMTP id d2e1a72fcca58-763389acafdmr16454982b3a.17.1753728206055;
        Mon, 28 Jul 2025 11:43:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753728206; cv=none;
        d=google.com; s=arc-20240605;
        b=eM3mcnElL7n62vlamu9AQn58x0BuKptdtEPJi9GGpGHOYookKRsVzy/kuXyWnYz6ti
         F4Z5wI/oSrnifZrhzXKVftI6LytIMnqXbF/vPwTzkN7D1sffSFlx6fQSPjAeu/Xzu5gu
         eMoaC17EPJE84RvRGV9WtGSejfsxyoQpmQblwB+Xo7YaSvDZAiTCa9GJikK730hB3xuJ
         i65FxgO/jbN007Px9CijgIe4h+DwGmYbj1a2D2effYTXpjByy2z68lLs4P2SZr8DK/Vq
         ZQp4MGNOHV/ob7D64z09vzTail9+OQ69lN2LS3ojBds4AvFs8PAqC/ka9bQPOcrtbM5L
         h2zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o0wY4fs4tIY954jyuvMzrD2KLgWvnR6xXGiR2gyMuMY=;
        fh=Spr1FW9jGs9z/q/FiUd9ELvZNQivoYeLPzx4dkbEjbM=;
        b=FdHKEMCNL853esD70vPxMG9DIgJVogSttke8hd7N/xHFYmqqHaZcZoiuvunUI6MiyO
         QuWC8AGAiegj2MIZ8cs/nEwAILjyTtsD/aVJqOBHSw21GCEFDfYs80HOHPxjNbYSE/Tw
         ZTdJcdQWcALnsBfhelTbpDxY9KxwjNxTWYaHInu1lNvEK0rzmMevD4y580/q/fPEfY7+
         yacMyjC/UAdnvSxOvq64hBz/YEshVhNtKlp20nmcBBJK7n/ni3nbLd44pQ2dY+NbPuqA
         idMmgjRSTBgimg0nHWjIXvhtGmrMcaRi8Zu//FDD3kdPUfvlO0YKC229wTTsx7LmkYdg
         6qnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@utah.edu header.s=UniversityOfUtah header.b=TmbQg43p;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.47 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
Received: from ipo8.cc.utah.edu (ipo8.cc.utah.edu. [155.97.144.47])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7640b6c0e8asi311537b3a.5.2025.07.28.11.43.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 28 Jul 2025 11:43:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.47 as permitted sender) client-ip=155.97.144.47;
X-CSE-ConnectionGUID: Nk14R2r5QbiSUWohi0GGzw==
X-CSE-MsgGUID: A/rCkRQdRFCd9E7CeEuQWw==
X-IronPort-AV: E=Sophos;i="6.16,339,1744092000"; 
   d="scan'208";a="78049462"
Received: from rio.cs.utah.edu (HELO mail-svr1.cs.utah.edu) ([155.98.64.241])
  by ipo8.smtp.cc.utah.edu with ESMTP; 28 Jul 2025 12:43:22 -0600
Received: from localhost (localhost [127.0.0.1])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id 049CF3021AE;
	Mon, 28 Jul 2025 12:41:13 -0600 (MDT)
X-Virus-Scanned: Debian amavisd-new at cs.utah.edu
Received: from mail-svr1.cs.utah.edu ([127.0.0.1])
	by localhost (rio.cs.utah.edu [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id IJQq1hn-PunM; Mon, 28 Jul 2025 12:41:12 -0600 (MDT)
Received: from memphis.cs.utah.edu (memphis.cs.utah.edu [155.98.65.56])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id B14813020EF;
	Mon, 28 Jul 2025 12:41:12 -0600 (MDT)
Received: by memphis.cs.utah.edu (Postfix, from userid 1628)
	id 58C651A02B5; Mon, 28 Jul 2025 12:43:20 -0600 (MDT)
From: Soham Bagchi <soham.bagchi@utah.edu>
To: dvyukov@google.com,
	andreyknvl@gmail.com,
	elver@google.com,
	akpm@linux-foundation.org,
	tglx@linutronix.de,
	glider@google.com,
	sohambagchi@outlook.com,
	arnd@arndb.de,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	corbet@lwn.net,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org
Cc: Soham Bagchi <soham.bagchi@utah.edu>
Subject: [PATCH 2/2] kcov: load acquire coverage count in user-space code
Date: Mon, 28 Jul 2025 12:43:18 -0600
Message-Id: <20250728184318.1839137-2-soham.bagchi@utah.edu>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250728184318.1839137-1-soham.bagchi@utah.edu>
References: <20250728184318.1839137-1-soham.bagchi@utah.edu>
MIME-Version: 1.0
X-Original-Sender: soham.bagchi@utah.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@utah.edu header.s=UniversityOfUtah header.b=TmbQg43p;
       spf=pass (google.com: domain of soba@cs.utah.edu designates
 155.97.144.47 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
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

Updating the KCOV documentation to use a load-acquire
operation for the first element of the shared memory
buffer between kernel-space and user-space.

The load-acquire pairs with the write memory barrier
used in kcov_move_area()

Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>
---
 Documentation/dev-tools/kcov.rst | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd..46450fb46fe 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -287,6 +287,11 @@ handle instance id.
 The following program demonstrates using KCOV to collect coverage from both
 local tasks spawned by the process and the global task that handles USB bus #1:
 
+The user-space code for KCOV should also use an acquire to fetch the count
+of coverage entries in the shared buffer. This acquire pairs with the
+corresponding write memory barrier (smp_wmb()) on the kernel-side in
+kcov_move_area().
+
 .. code-block:: c
 
     /* Same includes and defines as above. */
@@ -361,7 +366,7 @@ local tasks spawned by the process and the global task that handles USB bus #1:
 	 */
 	sleep(2);
 
-	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
+	n = __atomic_load_n(&cover[0], __ATOMIC_ACQUIRE);
 	for (i = 0; i < n; i++)
 		printf("0x%lx\n", cover[i + 1]);
 	if (ioctl(fd, KCOV_DISABLE, 0))
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728184318.1839137-2-soham.bagchi%40utah.edu.
