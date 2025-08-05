Return-Path: <kasan-dev+bncBDAOJ6534YNBBHVJZDCAMGQEHTQ5CMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 809D9B1B65D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3b780da0ab6sf2448331f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754403999; cv=pass;
        d=google.com; s=arc-20240605;
        b=dNHPq+2jrRrmiwrCGoeJDpUvn9wYeRHiMkMmKSQQYIteaYGtSUk1ZXQcezscdHajfZ
         8J3sxJC6lkVexFZNs5yzx6/TigvaSayQKVAfn5zWXI+dKVIq7AiCd/4yp49u0tOQhf+G
         LEvJuUgOOYWDl7MS7CzcYc89JqNRhhSdGshwpQUUK1860PAeJHuBJXnJXNZe3lz+XNgB
         ScF+KxfwpZ3pFzA83BgGdXc2xYMqoAe5uG84qS5fD7Zy4LqblWiaXssrPiZxuIBdZUn0
         th9tbpvKBzQZhTy4msqkrW8d3bzQxX6aQGwZJw5q8cktQKfjhBqXE6wCkImTSiqPnlTg
         B5dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FStq2+Mlpwkcq9pjZTsfmff+VpIvLARGQoE4//aetF0=;
        fh=yJxP71nlAyid9dsJZ2+HNmghihXDV/4BkTxGeZycKWE=;
        b=C1tYI1Zs1RbuizRnMFFrhh39MD9AgcVvJ2PEuIGZpeeFwC2Jw5nO1WeT0hjiyilJ/I
         QKEQb/SFgtvHWxCNVTCIsNscNoDbD8IVxrCtIFTE5cv75Xxnhpj0kjO/lTzj0Nfps7/b
         F/sAM8loBNsm/GkC+V9DNtxFwuOZe67RdJHZ/gFHtytQyb1eAHKEYfuiGjYyLO9ql0Hi
         SChmUPLsn4S6kPdL6cjzrOWiI0FKPxGhgxOG2izhJkCcPRuYHXPQLVdgd7fymHSk50To
         6nDp7Wv2aWJec7UzKgxdXISHiTy+yHgNYx/IOUAWZlyDfimKtcnRtaaAFrv318mOaTRL
         P6jg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JPw33Bzs;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754403999; x=1755008799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FStq2+Mlpwkcq9pjZTsfmff+VpIvLARGQoE4//aetF0=;
        b=CVrGZSh61hlAqhUkoaWBFs9QqrlTGbeXsP2/wKYFlJXxJ0Msm4vviB8ZX3mX3vK9fj
         3Umo5++BPGb6JrUTDe/Ve373FNpTIQMfo/HL8ddweOK02kt107S0b9B9NzFbLHo36xot
         ZCQGeZpqDjfYgDVIxx628b4Fu5PnJyDzFesIv1IcAy40PQFVF7wk/PLCkZVHrVPyI/ZN
         2FEg3Vd9ZJmOeZL6uxQTmfaUBJXKg2MRhAJOrGXZZcVbL7tJ0Smdf0CTf2JIt4da+JHi
         3yOVMTNdvC7Hw1Mg+pZzFwgcaiTiQa9RUNIA52XHk8nz93D9BeCoWcB7rXU9BuGDQge7
         1Lpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754403999; x=1755008799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=FStq2+Mlpwkcq9pjZTsfmff+VpIvLARGQoE4//aetF0=;
        b=QmaQB6a9zdw9tXaoK3ooJkcB4wfvOpGWz60rK7CtseDbPlpW88aPYjQAssK9Psdg7x
         fvEN90hEeK1AUv6VPkO5XUI7/dKUKOwrbk0jQtR14PbdcU6kl9KmD9MLj4V4hY4mdCOO
         8GgKTIUPtc8qlrL1Ing7zZcg3S8SVkleaYCYQOsgN1FJ1xSWOk2hJpw7q89cbCTVEqeS
         xmVzqzWkXuKdDptvnuoNeEH9xS7WMjCX57dRAgmMT69/k6Bu9+nsZftm5cyev87tjgcn
         dOAr/eX9AYlxncZpZuYmAAUX89YHdPWwpZ4pmrO3BvknRfaUMWjBp7EOARIbd23m0cFL
         /sSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754403999; x=1755008799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FStq2+Mlpwkcq9pjZTsfmff+VpIvLARGQoE4//aetF0=;
        b=LP6QHNgaETYnLsD9AcOk0Hp54wmPbPbSi2jB0b0B19CooBqDBYr+un4N9jrp9yEB3I
         lNG38vXRmgml/GlwHrdapX/8gkygJqk0+a0ewuMecFbJqL6zslIROfbTArA8VIIuJb70
         u3vKSdfgP7VcmdW+n1IUcJOfrGFKTuEPYtLwYOptyAE9+0ngzeIR2v6+7k004ABcz7vx
         /Bn7o1nVKxT2zju9NyjgKb2m5ikfgqRklAT0XiCVbnmiadit88XS7ZiezN9NkY9hiShE
         B+MbhsdcZugjMMgix5o05Xcq2VnRtq4rX/gQLzk7YTqsyQJAB5Myc6IAOnBThMs9edrY
         CnKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpkTv2GtO+7J6H36zBCSWzvsmjMUUWIXbePfthjqbUn2SsvtF1WRHDJ8HIamPx8LkyCw79WQ==@lfdr.de
X-Gm-Message-State: AOJu0YzzR1QVQl7qDvrzi36IHSRDpmUGs2XsaCN0bkIKPNgDGCg/vdkK
	88s5rWxp4+qUssiNN1eJKvVwbUl/ia0Lh3tYvdIj5HTu6r7pw7zbgMTj
X-Google-Smtp-Source: AGHT+IEehx+FaiO3ab/qaQ5ko7QC3aShebxKcijuHpAki99AqnAPcI5lcqr8eTfy+N2N0mOG3CE2Ng==
X-Received: by 2002:a5d:5d0c:0:b0:3b7:8735:9469 with SMTP id ffacd0b85a97d-3b8d9469fcfmr9430557f8f.10.1754403999055;
        Tue, 05 Aug 2025 07:26:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcoBxP0efm7z2W0iSn3ritfpgUCz/1HevzNq0pZrVCpRA==
Received: by 2002:a05:600c:34c8:b0:456:241d:50d1 with SMTP id
 5b1f17b1804b1-458a810bbdbls26437145e9.1.-pod-prod-03-eu; Tue, 05 Aug 2025
 07:26:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWT8now37RRqi6pxRMK2kAr1LauowFpI0Y74pSXQ8UNZVK5HG/80GFxl1RN75tRh5oV7/WnNltrem8=@googlegroups.com
X-Received: by 2002:a05:600c:1554:b0:456:1514:5b04 with SMTP id 5b1f17b1804b1-458b6b316a2mr105233355e9.21.1754403996392;
        Tue, 05 Aug 2025 07:26:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754403996; cv=none;
        d=google.com; s=arc-20240605;
        b=gEv9XgIftPVBQznGrQIUedtmcplNA4MaL1TGK8Ixg3p1VhFqHyOccTH9tpqBn239lW
         hpPguWnPDuakJCAg1YQqYtVTGf9mJ8IJgg1UwTLkAj1fAc/aRGbXjsX42aTy3e3A5jK+
         P6HEOklH1OG7tUzPZBBx5IfH8pw/P57ti8xre1+DpfOTQzVFghVloxl8RUpyK78sX3k+
         kVet7eqtb6uppCYLPrAyt4yzLzLRV5Nocix7K8CzT/iZ3+RL6ydvaQISPNU3RRnsbLNY
         7GkD5bRVzMupQPKK/GhYdqXIZsJxjfWf7NY9yNVw0AMxVTrcBJjwJ93XxmMx+Fn9EDBc
         zyfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vUUI2xKZlk5/jtNpSyx53EShjk/LU4/amvgKSzwK4wM=;
        fh=YeIi5GVXxwtPtw8ai0FGu2Xny9/CBW67z9QU/PCTiaQ=;
        b=RxGfGcfcnESH81m54AC3Odd6F1tzRlstmL4rjZb8iHhh1ROkrRp2BSWu29xcLcJ7jS
         pzDNEC6FKbQP8CACZdGD5dGiAaeXf3SrpkvbGI6qcjUlEkKhufWtOKYoKs+AKPfCB8fa
         7XP1H9kReJoRZRBEKHRS2RZOCP+Bp4U5bDZbEaMHYiDxnSl5plYs0JygbhpUxtZHzZT+
         4A45Cm6PWZHqd95PLufacnMv7T27T6JWhWaiqLTpZsvt3nlFhRzR8by2hsQqZI6AK/Gr
         eujL7ITXaRdatHYwDPviCzqpkCkEMa7tfx16WbISnAk59DZD7MC6gmb9Io88GurtU/k3
         2g3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JPw33Bzs;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-459e1d0a218si557645e9.0.2025.08.05.07.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-55b8e6eb691so5020890e87.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXVC++e9jRxI332BKOSw9tWphF5ERNfjqwNKIXX6G2XSQr5mVe++sxW3JAbn0bq0sKHMQpSsnS8Hp0=@googlegroups.com
X-Gm-Gg: ASbGnctIMGAiKHtwE6w5XV+f3/W/+73MJPGDk10ZR0bo/un+zJTUcgYMPUfJtZfk5fQ
	TmhGGjxVzbPle2DYbBDvTrn0/3ZNY5j9ZllGSBshTPaXj5mN8PjLK2fo+t4Zutq7bS7JW3ZxomK
	axFnpltYPponZDVsFPpP6JYr+vxLXBfqyeg0+KUBGGXK+pUEZ9EPrlN8CkjA4GnWMuFCq5zq+yc
	BAAVXNQ2eYEsRK4Ln+DY4srvSRHiFlZa7+VsZyriFXvaF//JcY5k76yuds0ouDRhdHSwU2OYIl/
	fyB5OyJy4FkSrv35h5QNglfBdasV2aQBuY3fMF6tXqTLDixwcPzraXp9ggiuRLo24ZDDOYK6QNX
	snnAmpEbIw+iacoH6TWhIbqmj53NgOOMnFV9jzPaygaN8+J0YJHI7Ev1j6sX4j7UPXF9OGQ==
X-Received: by 2002:a05:6512:228a:b0:55c:ac98:edb6 with SMTP id 2adb3069b0e04-55cac98f040mr114526e87.12.1754403995715;
        Tue, 05 Aug 2025 07:26:35 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:35 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 3/9] kasan/arm,arm64: call kasan_init_generic in kasan_init
Date: Tue,  5 Aug 2025 19:26:16 +0500
Message-Id: <20250805142622.560992-4-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JPw33Bzs;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization.
Since arm64 doesn't select ARCH_DEFER_KASAN, this will be a no-op for
the runtime flag but will print the initialization banner.

For SW_TAGS and HW_TAGS modes, their respective init functions will
handle the flag enabling.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/arm/mm/kasan_init.c   | 2 +-
 arch/arm64/mm/kasan_init.c | 4 +---
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f70313..c6625e808bf 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -300,6 +300,6 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
-	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 }
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45dae..abeb81bf6eb 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -399,14 +399,12 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
-#if defined(CONFIG_KASAN_GENERIC)
+	kasan_init_generic();
 	/*
 	 * Generic KASAN is now fully initialized.
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
-	pr_info("KernelAddressSanitizer initialized (generic)\n");
-#endif
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-4-snovitoll%40gmail.com.
