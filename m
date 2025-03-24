Return-Path: <kasan-dev+bncBCXO5E6EQQFBBCVPQ27QMGQEO75AM7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id EBC00A6E0E8
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 18:34:03 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6ed0526b507sf13206416d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 10:34:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742837642; cv=pass;
        d=google.com; s=arc-20240605;
        b=B4RslDn+rPoo+iP+ALLXUNVPaWFW8E7Fwc3MBOWxHE6ZirBMzBLPzl3ZsGP8XnmxNw
         mwXeOe8fyvpXvVN8yWBs2wQXAJeRCdmW25eKDUUb3Dy3eOT6Ve/cvSaJ6eLq3TvEyrvZ
         Nv83Pr6vHDHSAA2eW2Y37wvCpV47iF3BywTPoNVTtbtEHj4IxNOcJP2Jhcxrnfr/hZ7w
         ELuwMFv+HF86XbBz8/3hbVXDRdEG2zTlb1G6bz35llJK8rV1nQqZMFaMSDQ8ml5tSfU9
         ek1fjmAYoiOxBQBXJw5vmtw0lveTA1pfWlJrsQG44N18KoM70MFJlsqzXXoxS/yfNj13
         PLnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qSp5i60DJ8j98EAhw+Couk2l+Uc0jwjF0sc/rM/BZXc=;
        fh=wqnZmW5ia4S5wTTo/jsus53+ENsO7Dm8c6uVSHaE9HQ=;
        b=Zk+Z8XaMr2jYjn33JNnIFxN5j6oG7aStaEGeov3CpDBjf5FgPkWvgx27YXld+85pIM
         rZT9FSMd6N3NqYM53gznw7IT+EjfugpBKe7wyXdjpohWLNvo+M40I4v1uHXODC8DFHsw
         Fo1D003jdTnc9cuOP4fQoPUQVDKfkVz7SnG46cCodAVl/pkzWAqo5nC5BfGtbmYSNJfc
         h8NwevbmIsgbZXjcIhZpC6moC+Vk1Zeyea2TcNAAPtBljEUtvoKkibFSV6XOrZqBEfRd
         CfDnoLl/lIQn+2vK5ngNbNCATvkQOLZOjIOBX4yu6nHq5h7Nrb5bP6AK9LV0FWo8vL2m
         WrzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n6GzLTNI;
       spf=pass (google.com: domain of arnd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742837642; x=1743442442; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qSp5i60DJ8j98EAhw+Couk2l+Uc0jwjF0sc/rM/BZXc=;
        b=VEMyl/TgkWbiAyTX4ojS/9uG1bF1Ugts8PerKv20pnGZBqM9glrQCchF5ktJHCiMb1
         GtIckIUDhltfpQeq4mxmDW7tlV8PwJrZjIVZcorVeWMp2w1QMeZgXuRbkP+j1Xvr9cPT
         cPuUgb1gd5y9yyYD1lZ1c/0JmE1hlwwGOv1nlb0/BVfjdMjICWwsECKh599ApUxq+ZUT
         5n+bL4LTz4ulMw6EiZ0MmGV5yB/zjc0RFu1r6SvOY4sA9WYJraTGuwe2q8mjgT8lMSAT
         gRu3nMTazVrPkyhSTHexRdHYao5AAobXWACxX+8FCQonzNLfjq4WnaTLYtxQ/e4GsfQr
         FTWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742837642; x=1743442442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qSp5i60DJ8j98EAhw+Couk2l+Uc0jwjF0sc/rM/BZXc=;
        b=U/UP0gd2zFAMAFL9LEuYw6GJe/9Gq2ryXLHeJDeH9/li46l/W7lMBiCdkem05TD1wd
         YKDzQk7N8dyIwN+34rFzjoHX8U3AUtxSyDNgbYWkBIiryw4YuPtecpfXbgenBsy8W6FI
         5nibNK6euY6DlclhTGMe3KgmfZwW4uQ5KAKPdBtt9me5DmvIytzA1cOrrl3FfsAerCrv
         LBMBJmJjbPEvAsicU2AewGOIc4T5Z5UTqDlzA7z4YDndrdvACzxRwsumjHvHMT5uY+ek
         BlOupnYJy+QHa8qz3OH/MN1/Wn1AVbmrhJYFoDOebyS9BltzNtKS/0wgiF7hQMjSiPcO
         VKAQ==
X-Forwarded-Encrypted: i=2; AJvYcCWwxuFpIRcm9IC8xkpEAm3wnyWPNrYY6BRnfHJasH6dCayItuTOGa60XXmT5DuWIcMtWcoQgg==@lfdr.de
X-Gm-Message-State: AOJu0YzzymXj+E9JZ5/A4Ivv3V4YsuWEgRR8ijiGsdN00tZfTdqPabRs
	3uUJ/YMV5jhV8ECgFw+FkaViDGtDM4Xz6Uk6m9vrFzjlvuCjrpXL
X-Google-Smtp-Source: AGHT+IG7Ne09Z4hN5QyqC9BZ0QlpvDK9/tCdAzX9lCQkLbnDSXJ1Gs+AEzd1KnySJQrQZ4YgMEMfaQ==
X-Received: by 2002:a05:6214:202c:b0:6e8:ad15:e0b9 with SMTP id 6a1803df08f44-6eb3f2c7b65mr182529546d6.20.1742837642362;
        Mon, 24 Mar 2025 10:34:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKInS3vWkPBAKr4dGqwFKWpXkK+/my+rB//q2WMBl8eEg==
Received: by 2002:a05:6214:3981:b0:6ec:ed67:455d with SMTP id
 6a1803df08f44-6eced6745d9ls21067776d6.1.-pod-prod-07-us; Mon, 24 Mar 2025
 10:34:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSf5rGjkRTGivO5ZQoC0J72wYkpC7pD1plaHckpYLNV0XxYMXA2KhCS2nhXNfbRIQufRR9laWGGHs=@googlegroups.com
X-Received: by 2002:a05:6214:5006:b0:6e8:ff8d:cb68 with SMTP id 6a1803df08f44-6eb3f33a93fmr200701516d6.35.1742837640668;
        Mon, 24 Mar 2025 10:34:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742837640; cv=none;
        d=google.com; s=arc-20240605;
        b=YWlwFsET6PLezwCZg/GC473ZFPdkUrroDdc63A5BWbGkw+XvUno7ObqxFtQALbEPf1
         tR5ruHQVp9uykrVlMDqoAwqqw293vgPBfzKNbQTrZxzOr8pGboVAqEwBRFcVo9YWlh5Y
         z9O1puzSBdLMUzmXFz/EiI7BkRmdTxIwyOWJRnO9jXskZIo8ftYOakCjCS5oPhYnHlXG
         cWs3WZmM9dP5yCBZ8UX59lZgIztmK3elu5Opcg59E40Y4UFhZ/WOwRi/rzPDnLJ96kmz
         vQfxBNaV916cASsgoiy67HjfhgbRb22Bor6ti/jjH5/UB6UleL4iQI9SAS7aO5sYsc1U
         7+0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D7MpDpns2PwK3ZVBump/eXbUxlP8m19qEaMo5OFkiJ0=;
        fh=6fBrwWmcq6eZZNPf2i/fbBaVW7u3D2m1qhi2W3rJWyA=;
        b=NPYciMeO1SVR64p6Hf77f8zfp132sakTq6typ7X9cpi4amgKs5pcvOUn1IibEk/Z1F
         rkMrV2aoJi//9x/AoY9Emrq9MvTcUGz2DfpdyLiFKNu28lMrInwUcZkpKOEB3+0XlpyG
         6jJ8bx4zDjNMsHhLzj0Wkts4js2BtP/tBNurFEmjdKCjq7rl9IFnTJrse1WLHErWuYMg
         BrqB59l6flE+UhxcUG5FnXX1cTKkk6DmGfArdkzTyql0Q0yxHKPd9hs0IYYcBRzuz9nt
         vsz5bHoA27P3rGTIfhXjrkg+E8fGk827Wq8ttlWKA6Fw6X3GgJhT/2twp45hOUgBUU99
         I6dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n6GzLTNI;
       spf=pass (google.com: domain of arnd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6eb3ef3ab1dsi3557316d6.2.2025.03.24.10.34.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Mar 2025 10:34:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6463F44766;
	Mon, 24 Mar 2025 17:33:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D8BEBC4CEDD;
	Mon, 24 Mar 2025 17:33:55 +0000 (UTC)
From: "'Arnd Bergmann' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jeff Johnson <jeff.johnson@oss.qualcomm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>,
	linux-next@vger.kernel.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
	Marco Elver <elver@google.com>,
	Nihar Chaithanya <niharchaithanya@gmail.com>,
	Jann Horn <jannh@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 09/10] mm/kasan: add module decription
Date: Mon, 24 Mar 2025 18:32:34 +0100
Message-Id: <20250324173242.1501003-9-arnd@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250324173242.1501003-1-arnd@kernel.org>
References: <20250324173242.1501003-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n6GzLTNI;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass
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

Modules without a description now cause a warning:

WARNING: modpost: missing MODULE_DESCRIPTION() in mm/kasan/kasan_test.o

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/kasan_test_c.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 59d673400085..710684ffe302 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -2130,4 +2130,5 @@ static struct kunit_suite kasan_kunit_test_suite = {
 
 kunit_test_suite(kasan_kunit_test_suite);
 
+MODULE_DESCRIPTION("kunit test case for kasan");
 MODULE_LICENSE("GPL");
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250324173242.1501003-9-arnd%40kernel.org.
