Return-Path: <kasan-dev+bncBDAOJ6534YNBBAMO57BAMGQECZ2N6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E1DAAE7E11
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:27 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-553decb7e3csf826366e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845186; cv=pass;
        d=google.com; s=arc-20240605;
        b=Un0vNqmjjH3u2lVQ7BMlrjUQNQfPcqb63SzJl2QP7kDNgZw2sVPof/VCed0RAn5tUr
         mVWzp5nh3PmTORCT8LzMt4xrc0Pgi9O4asbngIH+QiP1QJtMqBsf9q6EUZQgMEcZuQ8n
         Pnj9Xg5dct5taUGUZiFr9YfN8oiKA35g8L+VD4qyAnFcLF2Ij7MSCtvGhKCmLidbCyaQ
         b5Sx1Gzpx1V9GNxjPmxeo9+woBaCo+eIy5xy6bml4TbW/H0970XF3NL/yvmKqelT60V1
         bwGyqEE6hpKP5+tPl0CdLzB0ouXy+Y0eZ33orpZU/1hejp4rnw/jRZz1OH4lRZ1KXdUq
         SZsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=+MzuOykkx43BjVN4kRodaX6di8dC7qHBhoZ0mN65qeo=;
        fh=kAwKGzRZq0S/oVJyeiuLM4MkfXc39SzVVUdA6f00Qzs=;
        b=ehD6ZnDUjkEmBssNe3dJT0jyf0PUkUxfxG5e+sZYM4m8svKBTGECRjSt1QQIUQFTa3
         mo9OeBdE6zP7fyPmH+0O2c7R0r49odx6RbMmuWWsiw4GZZjYHTcg3fDC8Lj1ZqCkVR6c
         fDZghmoSNIJ0FMp9HcLn9+FxLK53tmeszfOd5mvbmP83piyUY4I5e5Oy/bfJFCQvsUNy
         254fI4mVoOpCL+5LRM94DCTD8mWRqMNlmLhoD/55bQeiJ8IrVfuF29qWdjprPVGt4OF9
         8AOqbd5toxpy+WL2sHszsQcABfbvF/PMtkSna+/oa/GujvzyY3agXVRQcY4m7ufKBx8L
         09wQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DSiR9hzi;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845186; x=1751449986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+MzuOykkx43BjVN4kRodaX6di8dC7qHBhoZ0mN65qeo=;
        b=GvptxuMSfSuoU7qiHfJMEXcpUN4bbgGN9O52qmL8NDRnuqE0y7R7ed7O88QV8rNtas
         /G0jW6YREWTSxmhoEuF8Czg/6+owjB1RRcUCPxOwslytueHGj3f2hDZF0IEW5yqtRvs2
         8p0nBRdiaT7/imwGx159fVUdhP59o7rDDGURiU/JtNj6m4nKV3AyghGdyE4Ekl4cLZRA
         T53eFGgN7lMTOMme+4n06xtfx8YA6VUX4EhdE/u76sI7JLjtb3Q8b+9V0dFNMSUJFJis
         dIvZjIbsdvVJdxTQIEfNlBha+fYQc8IaoUrHDrJmzvmqKZbqVVRQNKvSF31Edme/DWZj
         1jtw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845186; x=1751449986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=+MzuOykkx43BjVN4kRodaX6di8dC7qHBhoZ0mN65qeo=;
        b=N3laKx1HTkSyuoYWSv6Q38d7RhttfBzxd/sTCdm7w7XnQhhaN2ktJSg/Q/1CPlDKWm
         +ZUkfqg+cuFJH/Nz8SVYWIh6PNRgV91pyrSQ1OMFa1BoWdcK33XlF55ETzhOgxEiQPx4
         e+iygA9w6igYoYqqzU/yh1pR+qe+mSfizi+uLCqB5pbekEKd88iUmaIgZgSdYy2vVwZ3
         KVCOSn6rI+b+6yJiNkhPP0lQ+v4WS3KlT7ADaj85YLzGsZ/RereGyLBZnU+x+gfRCWpi
         VmWK/Cm+xt4YhTMnVm18NeSfgakKKr7ZEdGwd7OQFHLH9M/dSXWme+ytKaby7VNgvHXO
         sQ5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845186; x=1751449986;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+MzuOykkx43BjVN4kRodaX6di8dC7qHBhoZ0mN65qeo=;
        b=fZSemoRw59wjPo6i4Pk8JrykRNPe05XH+0/fOIoYI66WlRcqhoXQQniLu8PJyzEwun
         QVNW17IYgcx4VLyzRa3AZMHMzxiQTL7U6JeSnDXNFTx+7GzomfpMadr0Y6xoSFXyXFQK
         k9VkxtxHfWBcds/jch1gk6UKK9+fX4n3xyRsdRWI51BgrryV9PO8RgzkLm3gT2SitcFa
         JvR1nLlYAUuMiW/B9WTBG/g7RssvRlAF3G7UnKiBd1EmqOArPEVfcBGe6YWRfttq06H5
         3113JoTmx8tRQ8t04+4kvRyk7J63aY8Po8Y3CU+lAmN6NApZFuikken2lrjbkUkvVXp8
         Zh4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjti9mgO5PwOhRw843uz8Fdhv2kAGZ7pLE2pXTwu1zQOalD0c6ail7z8CwjsJoak3hqFT3Ig==@lfdr.de
X-Gm-Message-State: AOJu0YzfMN0KDgNY4KPamrnORqQir88KlbeHBiVSqN2wRWFot36SjNYG
	w18tLMKzLDdclFaM/h63MVXZrqEs78OkghT0ss13TM7XytjMyox86IQY
X-Google-Smtp-Source: AGHT+IF+eNm2zxFpAs1cUf6kv9Wo2JB0cEWAGirbRoWw4JAWRY6V1ZtawSlWGfDmNybswyUEYjKkwA==
X-Received: by 2002:a05:6512:31d6:b0:553:adff:87da with SMTP id 2adb3069b0e04-554fdf8823cmr658938e87.29.1750845186344;
        Wed, 25 Jun 2025 02:53:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf25bSMEwYhtt+IJBz89cN/uzpK5spsfiDi7K/Al9M8zw==
Received: by 2002:a05:6512:608e:b0:552:305:9fa7 with SMTP id
 2adb3069b0e04-553db368150ls1501194e87.0.-pod-prod-02-eu; Wed, 25 Jun 2025
 02:53:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfyAVZZVmbBHypsRN/nDenW2jfBj5dBmjKylBZgh779CWKKQGelUIj7NoIGqKn2EqfnBfqXl619OY=@googlegroups.com
X-Received: by 2002:a05:6512:1194:b0:553:2450:58a6 with SMTP id 2adb3069b0e04-554fdd33085mr655532e87.1.1750845183814;
        Wed, 25 Jun 2025 02:53:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845183; cv=none;
        d=google.com; s=arc-20240605;
        b=Z/fbsFRV0T7VNiPpUr9Xm7xo0//BOrMTC8ZxQYd7cH+MJEYbVjnPkK/O8CsbyDeSIk
         Xq37X6H1AjB3UaMpjnxDRkZFVEG62qeMMDrbQ4E6gpLb+tE7KDaUijWZIlMbcnybvI/k
         zcOfxfYR88kPvj5tPsfbqE5PWUAgQMsH3BjminTUUrgBAULCSFCGa56+8XhdTm/YpJEi
         WuRAiQS6/NKGKx/K42TWSN2zwFDCTeWYGDcxstk3XPhIpZ9xUQFtjc8O5aqCwFYuvGZh
         j9UQSTgSrJyEUcUEnxkDbK59O9xxxmtFn3WoyxWlFKj0pgINVNeYtBQsMvY+pzNOi1iR
         24qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=m8+Li4ZqAZW0QY7sIIldmBLFf6VQ+4AeP6Iv95ugt8g=;
        fh=+wksigCf/K+fDl2SwWjxVN5hV/GIiXNkOBcwUyJ6YHs=;
        b=YSudvIZSFfndBHqN9EykJh2q3l5AfBXL7IKPO04SitoznmvkDiLPAlX21m6WR3+khf
         3US6ir5lMcphgKQDZq4RTZAA0Cvfpo7X+/RKzPIQqhVmd8J3Q1c6VepWP9Uvr8JPiFZ1
         FSoJUJ3ct5/W+7Orobq8PDtBZqt5fUKYcTi6EsEN1ndr/zw4yupCxpxZrYF4ulJI713P
         Oqs3KubaJFI2lRPSaa7AIRNoYxOwGebtwLU+rqDgU45zcWrHzj9tWF4RFcgpwi3LwQrX
         WNS3R5lhxpJJcrnTZwvPOGo61ppQBjz0U1pZ1EEKrnsc9ytHoTFmEqqRhoeGMN0punRU
         e7BQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DSiR9hzi;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e41c8e6bsi216492e87.10.2025.06.25.02.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id 38308e7fff4ca-32b3c292bb4so11582841fa.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU8+5/aBvkb05STIxHqSiSSJ2WXxFzVq2CGTlRmoMaU6kXlhnDVjgh6zzxNN6oEXWDOnPieQOKPPL8=@googlegroups.com
X-Gm-Gg: ASbGncu9PlMA2qPeM9ZilUASQOQCNCGNHYpIO+giO5o4i8drs7Psc5kzgXgZAdV17kB
	ZXs4TnptDGaGmKOUYN17j6zTKtyvEvSH7cwCo/38e+GwJ3lChJmmmb1lPYD9RVBfDBho8MC9Ctq
	DnIdbZK4QCmRlvbSmnY2y+7qtnHbF4cWOogWu8OCQS/VuKtsrGgE45WEibMz/dtPpOyc6s42GaK
	SMoQPEQU/cSHd4btoUR330yMu5upDgftuHMoR2klie9Co9aMmyTrG5zVyZvad3+ZR82OJuWEFO2
	HeWrN1PAsq+upGgt3kRyQNnGhbuqhG6VATGhifmNOZJ4rIDpNoExqqEKyoo6EGlpZErMtFcf96e
	bhyonH0U1AQ80LnCjdYrvF4jk167VAw==
X-Received: by 2002:a05:651c:e11:b0:32a:714c:12d1 with SMTP id 38308e7fff4ca-32cc649716bmr4987311fa.1.1750845183165;
        Wed, 25 Jun 2025 02:53:03 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.52.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:02 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 3/9] kasan/arm64: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:18 +0500
Message-Id: <20250625095224.118679-4-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DSiR9hzi;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22e
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

Call kasan_init_generic() which enables the static flag to mark KASAN
initialized in CONFIG_KASAN_GENERIC mode, otherwise it's an inline stub,
and the flag is enabled in kasan_init_sw_tags() or kasan_init_hw_tags().

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/arm64/mm/kasan_init.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-4-snovitoll%40gmail.com.
