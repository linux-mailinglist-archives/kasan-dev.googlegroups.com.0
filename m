Return-Path: <kasan-dev+bncBDHMN6PCVUIRBU56Q65QMGQEBO7BLQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB8039F57C3
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 21:30:12 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-385dcadffebsf2702547f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 12:30:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734467412; cv=pass;
        d=google.com; s=arc-20240605;
        b=dnx8f7ku9ofLyVsqNjlzBUmRVfOnaTIsR4UUTTGWb0GNig6ZfTp9gJCabE/C9pnwRd
         lWVvYgyNhMTQLn5ZociPTfdVCh53NCfhmlLKaCM/dv8UXitK5+bSsb++sOCWA24TMyTO
         uDCk+1/v8pzKKOnENvk98xkNYF3aAaMmE/joOVqFNphvkEY97zepAV1tHb9FzzzIvEMY
         D1ZQRwsSwjfp+PFyG2V7ktmSQJsZmHkbRHFWslXR6GYtzLrqrCyCSeJu9O1iXoKVFPgd
         HFjAStQX1sjwxueObuSf85TxyP3hRnXo8KQKsrcMckTDFcDvHjsxWEFDAA1f7ouMC+g4
         rtNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UPwzllvptHm4ETY40eA/2O0iyziSfU1/E3NcmF1fn9M=;
        fh=xDmFBr6VJZfXufdKDAhVm/RJApEHrSONi5rZL/kNnII=;
        b=czD4Tb9cHiW1MVDLCXftaOYc/Ov+uTwts+xoDdJPoh1F7gO46xQRPlQbXjBbDdIEg3
         UrmbfT7RnDDcB6h2SVV3Xv5UExxHo2Cw5R5ovvXGzSGaHucfMIX4UzY6fDByY1sqU6Uu
         a0pDtsMwzQC8bqyE7jdzodJGo8q6CZ8X9IgroTafwBbS6yeFdGLdWqFNFJslB0s/HZZd
         UUtqM0hPJXtLTFzxvSOFfKzBY+zxnBOkHaAKca6dMXe8VYCaE5m5xHSLpUDU365/iS0S
         wpsyT+ZmolDS+EPlqdZu8a+CnouXfFzFxrErJ0mKJ8iq7W9aHoQr9I6dyNr7ttrDHsQT
         2USg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=A6tL8XjR;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734467412; x=1735072212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UPwzllvptHm4ETY40eA/2O0iyziSfU1/E3NcmF1fn9M=;
        b=hyh09Q0M86oyftebYkDd5CzAiYPSC2xd2eCE5lgEqKzI1w9DPr7gcbct8TXPGl8Cnu
         IUi2LJED0VjSqE7/J/qjLxSUmJTACntKOIcxS7GvLPuGQ9mnB/9ighWYwtT1hlmW9bbl
         JmrpdQMa1/cKZD7U8oBfThS+HhBuue2gbSY/I9Wt35M34Fj/eStbVFGG3Ba6zdArQsyy
         c9xrvixFgOdOh6i85g0oReA4E1s27rkrOSBc5ah4y1hLtnbQSNRf4kBF3hXZNONAXhVz
         rTbfWXd+3ZSsRFRZKQUDXdMuGKum4P2dJOj5/QKAzDvFVJcJYuW2HUgTQdIgWmeIW9+9
         IzMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734467412; x=1735072212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UPwzllvptHm4ETY40eA/2O0iyziSfU1/E3NcmF1fn9M=;
        b=DzXmH1JIy6MkWavEwPJ3iuvlwQ91XVjFsDj+13RG2D1dvMLmI5DNLa0NGMAn77Gin0
         leFo3ocqwEW2DcAuk/IfmMn3URYbE2OhzF/DzCkwDkA0pZNKDoMC9kNFqFRw3oKaPpta
         wgZBjalND6zIcicCBQXVCeM4fzEDVdoqbY0L8WKXHtT9qQdYS6pwkIp5bmi3RJSc+4xq
         7z/WNAkDfaumeqRZjngzv5SvJqXGINxeIgu1TV1ZsDtolCL78fcLPgGE4dQS9UpMslj2
         bF83fcTKv2ujN0jkYv+DyU1+MexgZkmfVkb9G7i4Ffz20dlG4pUHzCY0fAoY2KeDjZny
         EbAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbziVLJEMrM+or/nQggZnYieskKDQfO7z7RS/TZpGZeyu+MZInNWu4en/dd+AT9Es18DND0w==@lfdr.de
X-Gm-Message-State: AOJu0YwO3wxJMC1MnXN17JdGBma/TE7A86pAOtyOsv0MB+YYbonWtfJD
	/LTOYFfabRjTzYecPmxYBeNMBVzXX6oDWH+8bhhKFObqct8mOZpc
X-Google-Smtp-Source: AGHT+IHfVllQgu1zb5I28qCnF7UTDdb8uTRwCiLGGNrT573zM+KJn6golgtt3ymIbCb388e/oajA7g==
X-Received: by 2002:a05:6000:186b:b0:386:4034:f9a8 with SMTP id ffacd0b85a97d-388e4dae6cbmr175511f8f.38.1734467411548;
        Tue, 17 Dec 2024 12:30:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:4b04:b0:386:352d:5e9d with SMTP id
 ffacd0b85a97d-388c3b4378bls438406f8f.2.-pod-prod-03-eu; Tue, 17 Dec 2024
 12:30:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXSkFKk2D2BGNDHSau2cwtQ2Vpj0L7EwoWt3QfJgyFtoxrBVBhTqmV0CV6pS6O57s0xLTu6HgUt9D4=@googlegroups.com
X-Received: by 2002:a05:6000:4913:b0:385:df73:2f24 with SMTP id ffacd0b85a97d-388e4dae6c0mr182857f8f.39.1734467408812;
        Tue, 17 Dec 2024 12:30:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734467408; cv=none;
        d=google.com; s=arc-20240605;
        b=MCxTWe1IkbmKTBI5ZWPss+guZ4ChEL2htZK0S10Yk6xjPVxnp6dzgFGxchKtNCNWRi
         6gY+gwU1wIVnQtIEg7odcWqJDI8YFjy615EtBCsOoC204xaOFm9dCyoe5TEMFfkjikpA
         3HSh3mbq1D/V9m05WMtG0gal3ptniVu1N/SKZEJQENsFlfDCZDDSKomjm6m2WUsUiKFG
         HYqY0uWXmIGOT1N3ubGbz1nsVZwiaXTggajXgxILxHuZukMQBhOu8BU7AQwKbH5v6Ymx
         3sTUGtA6hLsToASyQWgG14at7KCrf5EB4pbDVN1oZZbGMb349Rrg58eKV90mpvwspttc
         e07g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2AjmcsgTzx3TIo/NiPZF3pU4weuGY3iYJ3AIwf8Kn/s=;
        fh=k2Z8B0SyaWkPc5Fxzj03jgfC6ikcy0wx+bFc5bYaPPs=;
        b=Jv/5M4BNsyBXjbjnm2mfRkuaLDb0ej9qRZRKhEnuw617vpqRf/BANBt7GeSzo85cyK
         2OaG6kLrn9hzz4/8k9KHAvdwSMJM2WHa1jTeaA5QvPxUzE4XhTzLLkvhY74sv2Z8wAGx
         1ZmhJemqHRBH//khNYLYqKYCBuRv39GqLVTyQhWHJVAD02CCCaSbQShgd0h0WFyTpwxg
         6wXYuXJhoiDLrHvwd/I7zbKnRMUBwmzGhL+AYDgglG138dvaD+148CfBTuXfMbDzXtaF
         0SxrcuvA4Tog+TPHiugXCtb6n1nqtJtY1x24GYzUORbWEKKm53SWaOAiaWxp9G6y+pky
         Dy7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=A6tL8XjR;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4364b05564bsi998755e9.1.2024.12.17.12.30.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2024 12:30:08 -0800 (PST)
Received-SPF: pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98)
	(envelope-from <benjamin@sipsolutions.net>)
	id 1tNeCk-00000002NwX-3MTY;
	Tue, 17 Dec 2024 21:30:07 +0100
From: Benjamin Berg <benjamin@sipsolutions.net>
To: linux-arch@vger.kernel.org,
	linux-um@lists.infradead.org,
	x86@kernel.org,
	briannorris@chromium.org
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Benjamin Berg <benjamin.berg@intel.com>
Subject: [PATCH 3/3] x86: avoid copying dynamic FP state from init_task
Date: Tue, 17 Dec 2024 21:27:45 +0100
Message-ID: <20241217202745.1402932-4-benjamin@sipsolutions.net>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <20241217202745.1402932-1-benjamin@sipsolutions.net>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
MIME-Version: 1.0
X-Original-Sender: benjamin@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=A6tL8XjR;       spf=pass
 (google.com: domain of benjamin@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

From: Benjamin Berg <benjamin.berg@intel.com>

The init_task instance of struct task_struct is statically allocated and
may not contain the full FP state for userspace. As such, limit the copy
to the valid area of init_task and fill the rest with zero.

Note that the FP state is only needed for userspace, and as such it is
entirely reasonable for init_task to not contain parts of it.

Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
Fixes: 5aaeb5c01c5b ("x86/fpu, sched: Introduce CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT and use it on x86")
---
 arch/x86/kernel/process.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/arch/x86/kernel/process.c b/arch/x86/kernel/process.c
index f63f8fd00a91..1be45fe70cad 100644
--- a/arch/x86/kernel/process.c
+++ b/arch/x86/kernel/process.c
@@ -92,7 +92,15 @@ EXPORT_PER_CPU_SYMBOL_GPL(__tss_limit_invalid);
  */
 int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
 {
-	memcpy(dst, src, arch_task_struct_size);
+	/* init_task is not dynamically sized (incomplete FPU state) */
+	if (unlikely(src == &init_task)) {
+		memcpy(dst, src, sizeof(init_task));
+		memset((void *)dst + sizeof(init_task), 0,
+		       arch_task_struct_size - sizeof(init_task));
+	} else {
+		memcpy(dst, src, arch_task_struct_size);
+	}
+
 #ifdef CONFIG_VM86
 	dst->thread.vm86 = NULL;
 #endif
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241217202745.1402932-4-benjamin%40sipsolutions.net.
