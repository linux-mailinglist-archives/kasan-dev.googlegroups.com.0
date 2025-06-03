Return-Path: <kasan-dev+bncBCXO5E6EQQFBBGGU7LAQMGQESBXNWTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 066B5ACC17D
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Jun 2025 09:54:02 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-60eda092643sf668948eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jun 2025 00:54:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748937240; cv=pass;
        d=google.com; s=arc-20240605;
        b=IOXwIyUqmLY3BBOPFPddGYpdQM2yPHcjzHSfnHcTscT1tE2a7eA9pXr5tMntK3Yhgq
         U+yTHc8hU+tys05vOPmJzEDaU7sPj6OaEahRsQlNxDZiGJNo97nM/G/R13qZXISuC4sl
         CT7DOZleDTd6Z594bxmTXCNsr6D9VhKIpKVKQjA8EaJJY28fH/cTwNtePQpAqArE/MET
         F1uWKLDT18RGsOhGa6Y1ValegxBkohr51I9E+hhQxE8M+CKzgcnskSB5/Tqp+hY1VByo
         +X0N2Ldf1LnyZA07qKs/mNq+l9EXREtBzpFksAQSh1HUm2WAYC4QSY+as9LVMQCa9mtG
         JveA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=NMT6TSr5Cqh+xPnUlHQpTalw5Q6MKOqRT4IIGgPdgqA=;
        fh=q1MLBD9rygE9XC5xXbRjWkWqV5l8T33I6LIR2MG7ZJM=;
        b=lzoPS55uGLUk/eFaqiNKGodOa24TM2lgpbFq+7mfPrF0zsF1ngGhBKCp11Aj4CGVXR
         qLgK0rbjv081bV1XQwt2PgCuvvrA5s9fvCO9GKHFB10RHY5Ap2JHZn7wrNbL1U0HwtDZ
         FNjR3d7RhLMeZtPJ8TBSZxan5d3Tmr8/2cA1N/HFraCMyceasY7JC2SsaaLLxt7dVzOT
         63L5z5l9niimKN29YVoW9WAaTyFj4FLcHKgzCWsozrVjDyW900XhQWXV6DFPCKT7XxC0
         9pk4VIfZ8u6oURH+omYAv0MhVWoTAhfG8WzDmyoUptYZSXGxetOvOPRZjbd/gcqt7MmD
         TUYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dE0h0uzC;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748937240; x=1749542040; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NMT6TSr5Cqh+xPnUlHQpTalw5Q6MKOqRT4IIGgPdgqA=;
        b=dXgCkQ3uS4j/TVm/e+P7TXGZM6MA7e3XgN+R1UCL/fiyDUzTcEElWOzdNXELHfelfG
         heZABluoT88/Jew0LlizWks6PAddrkCLFMw3fMyzruHNxNgyyTuGWgz+QXwJkDVEfeKj
         7hR2DbX/yV5hityxx+VAvdrGBAhZHyqkFe4+EzB51Kq+qLtnaNAYf4KjJQPvtdiBkL6u
         9z7gLfZCU9ro8tvcXeFicgZvzfdz5CFIhNanR6Tlgl4YPwZgL0QSvEiJ8He5opRRTMf7
         owe7UmxC5Ve68fzEwAKOpP5nhTpuk1WW/SKIrMFzu5ycIU0VKtwK3SuU1qR0qCS+y5qe
         mzlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748937240; x=1749542040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NMT6TSr5Cqh+xPnUlHQpTalw5Q6MKOqRT4IIGgPdgqA=;
        b=IxNDILmj8i7d0e9tZrJQc/4sUwY35SRs7pa01hErxvta+7LmfR0/wzPY73ZfZQhpSO
         hSR7rV/uk25I6qKf7bp0mnvtwp0wHA98in22rKScCoY4bp0U75Gu6HbfwPtOc9hrErTJ
         7NdDWPY2VxmzA4jK8Ukp78MNR/LfVAgY41dlZpLI5Xsva2fAvM9jetpjSQ5Eof29lZc/
         VgX73qij5TujZwcK/Cvlfz+7ZXbMVuq25xEKJ+AYR9c17xzX4Sbr5qmNqMt6gZ+tgcpm
         2272oj3fSDfBBMxU+9cj7FBEtyPBLlF3zY97LYZB9KrPAP3OQS2umwxKvSBqO/5rJ0WQ
         WS6A==
X-Forwarded-Encrypted: i=2; AJvYcCV57PwtzGyf27lIf7dh7gBLo89jjS7C63a4NqgQFfTEVz7T/z8I2oO5z91AJT5XLgliUwKLoA==@lfdr.de
X-Gm-Message-State: AOJu0YxS/XIrmTw4tqcgb/w1i47yBvrHzq5oHDAJ28BBQ+rYfhME29Fi
	fMhiUEG4Pj2Zk/uL2YtkNxN+fSci6hB8zrDxmOGSdPR1PbzryXEKENsL
X-Google-Smtp-Source: AGHT+IGKjUR7B2WZFZs7XesJDiAAobl1AZQH7jvfLPLFCoctuO8mWEBvtreSl+kD6GhEDQcMI7VAvg==
X-Received: by 2002:a05:6871:114:b0:2e8:7505:638e with SMTP id 586e51a60fabf-2e92a5281d2mr8611142fac.39.1748937240302;
        Tue, 03 Jun 2025 00:54:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf8z6EOXqupKka4uAV00sDghw8QFqxihrqkfMeCeXUYrA==
Received: by 2002:a05:6871:3a09:b0:2e9:9118:9e88 with SMTP id
 586e51a60fabf-2e991189fe9ls447036fac.1.-pod-prod-06-us; Tue, 03 Jun 2025
 00:53:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEBiCHQ5qQuw4ATcNfVLZYBg5/hnjkxOcYtBP+k5TiMmH3RSj5y32GLsBWvxjftzZ4RdBYh2x6uDU=@googlegroups.com
X-Received: by 2002:a05:6830:4981:b0:72b:89ca:5120 with SMTP id 46e09a7af769-736ecddf2a8mr11982721a34.8.1748937239384;
        Tue, 03 Jun 2025 00:53:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748937239; cv=none;
        d=google.com; s=arc-20240605;
        b=KjQkbwX1nRpfKMikSXjPsAMkYB71QAq9WqFgYEN0a7Ttru0B+/P3tBSRZCMExrtZw5
         vu40+z9KW5d+7+F77liV52xR3Ja6A7/1dNrWcXRqj9l6TIF//bzmPrL5YOKgICF2Z/fq
         M+eKyWSfw4HXq9v0F7Yu+MuclEdnTmGN91eMyI/EgzLjeX5ybha54mJ3kgb2vZBaqqg4
         2npAiqR8Dk3Sy28i7tBOE+Le6GsdWvfziwxsaeqNbt20eJD/rUCXLjvM+1m6dZIQ72Hv
         xuCY3Fuo4TgLB1D6OQlSfcgguyXKtXq5V5KPTVPazjRnPeeTKkcBeE8pJ93I6fWpaTts
         It1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=XHlpZ6yXs1QGWCa0BEJ8mA8fm3K6FZHfO2615Yf0eUs=;
        fh=KsK0vEuDGbn1Yk++tb9nMdSBttiYjTNnrIRT6E6BM8k=;
        b=VDdPUcskqA0wQASq2nsIIJSEZmEkFFSRNJMXEHZf+vxlpqW3SEcR7TdEzyYZ5TXl+f
         +wqdImXV+0Zsra89aGBdKDoKHUiMi12BcYLW3qzKAgobQ3xOhT43Lp7lw9nidBBxTjaY
         UYsqKnD9IDYXZRHm9HpJQFFuR5jHVcDluP07H04AmeVtXxVY8wNZ89RZ04jANsH8Qjsa
         ET7aKzionIov/QRSyCcGUAcwj/Q2SyMFj916o/UpjaZS7EmezC8QAJkxPE/KJzc1XQbK
         6dpeS7srjwjp7Fn5j1uQhpOheplVjrfyk5Pom30DXoFAw/PZlmxHj8Gtg7BlIR3rNcpa
         p65A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dE0h0uzC;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-735af9a48d6si533755a34.3.2025.06.03.00.53.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Jun 2025 00:53:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id ACF55A4FBF2;
	Tue,  3 Jun 2025 07:53:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5044BC4CEEE;
	Tue,  3 Jun 2025 07:53:56 +0000 (UTC)
From: "'Arnd Bergmann' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kmsan: test: add module description
Date: Tue,  3 Jun 2025 09:53:07 +0200
Message-Id: <20250603075323.1839608-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.5
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dE0h0uzC;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Arnd Bergmann <arnd@kernel.org>
Reply-To: Arnd Bergmann <arnd@kernel.org>
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

From: Arnd Bergmann <arnd@arndb.de>

Every module should have a description, and kbuild now warns for those
that don't.

WARNING: modpost: missing MODULE_DESCRIPTION() in mm/kmsan/kmsan_test.o

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kmsan/kmsan_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 9733a22c46c1..c6c5b2bbede0 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -732,3 +732,4 @@ kunit_test_suites(&kmsan_test_suite);
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Alexander Potapenko <glider@google.com>");
+MODULE_DESCRIPTION("Test cases for KMSAN");
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250603075323.1839608-1-arnd%40kernel.org.
