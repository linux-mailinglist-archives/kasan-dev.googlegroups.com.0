Return-Path: <kasan-dev+bncBDXY7I6V6AMRBYF4XGPAMGQEOQMUTVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 95AAF6778E6
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:16:01 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id k3-20020a05651239c300b004cca10c5ae6sf4796333lfu.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:16:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468961; cv=pass;
        d=google.com; s=arc-20160816;
        b=jLQQOJqdIZ7mG2NLQHuGmSpie0rusUTsDsjXuYZac8LY9I0UB+6fRA+/LRAqhhMX6W
         Od/OQqGlHDClkt5DIa7hRioPEgdCRIZcFJRX3OSW6WcPxqw0D0xd3Qvycc1knBhUzFMS
         tV7jINoDDS7BT5cyg/z+8X23X56gJM9fBgoyjAvtKP8yJW4U9P9XZQPezkUPh3oFeMxb
         tz0z6mARPHEUThsv6JqfCz2MaFoCYUnyMCyZfw3rRkoxn8Y9025JxDEjqBYjHIIarMMz
         MHEr6DAB+bX0OYtp6d7PmmKklT3w1+uOpzPyKwLmjbYUtgReqAJ3YD1iRp7ss5pS8MVl
         GAWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9PDEit4i7L6JjTC6LBT2j8UWCxAXKXMsIGp99JOQDLU=;
        b=h00eqTjM0NBE0c4EM1BhTN6GMAHvWpz77BJmk2sEGXEpLxHpwRzbF9sxkzVnAh1Uak
         F2NB+AeSKSsT6gLCjJLFZnqPg60cL0Zb+LShPJ2WBAJWYen1uPdGirLgPHMf4FEvog9e
         4Xve9D3CLxLtmWD+xZU6GtqwtGQjEzdaOOrVFFXuYgnENhrXBuviotf3H41bu60/wLZ4
         Ody8uYjfKSvuq0zgGGeDvcRkHN1UMRkev9hQNNzPJQWuKDEFZAZ13OaT2ZykRYL7IFHy
         EUyIOMxpfXwrNUCvvkKrqph7Gm4L1DpsWFhKztF97KT50Ti6wpWsEtPoXdCh7NONBqMY
         mm/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=rf0Qwpy9;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9PDEit4i7L6JjTC6LBT2j8UWCxAXKXMsIGp99JOQDLU=;
        b=FLEmiUXZD0K8cIS3INXEDgIwXJ2gGb+KYHQbyP1CGhOWOHLsOZVo1lO838AzhJExo/
         6gW5ZHUBibV0IrVZ2YsTxuHYcdb49oYZYYXc2WnEutuh6lW6lcOHuFy+a+tNXx7AJerf
         iJmEOLlnVlIPTyoTD7A84HRywp5AVP6/1YosesTauU/zKh9OE0zRv2m+ly/4fktQIyRO
         X6n5XXysDpRudgpcOzSTq+q5JV2thpYLEG5uDC/k7bKigAafMgAdzzz+gEXYmqOAn/30
         DbEBpXP/g+Jz4rPoL7iLWJsRcdv7o2sOsKGuSdoR3UBAEsLL6+iakV763xVnxv0oN03P
         RrEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9PDEit4i7L6JjTC6LBT2j8UWCxAXKXMsIGp99JOQDLU=;
        b=gS29MSJ0YYhqnY+hlYrh2OumO964hkS79zha5J5is7h4DJh1U84+XeF6gNyhJDfpxx
         5jnEfJa3Qwahe1+++b1hZ34jeFXLdufKwrBOaCbDqadclHqvTRTQh1x5X9f9/h0Heaca
         ndNKvTehKj4nLSENNRDBPHCblk9d7jSXp7DJWTgHvAAMhumZeCWTpbmVio6f394dKYwZ
         GkljuiP1TOVoJUu5bRFRy0GaheKQDxqfjsCgPQUbgS0M83QSOq54zlhIYnH9116uQ7hd
         WlDxwQ9BP+X10wdcN8TSjCwl6F84j91WGSKFJQ9R8LkFYRggi+g6mdD0MhsIruvvztow
         OIgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krRQRhLE1yXpjq0C7zkh73eP5C0OgCAtgXyx1eVC261E0APtFPz
	tQWMV/XQnS6WfqQfDAdb7EQ=
X-Google-Smtp-Source: AMrXdXsnNiEcX6j7gkbilw6Q0i8JyRSXlkwoMzgpnUrR5CNyl+Bx+rKcKftnowd7+M/3W5hUG0dF9w==
X-Received: by 2002:ac2:44dc:0:b0:4d5:72fd:5348 with SMTP id d28-20020ac244dc000000b004d572fd5348mr1872248lfm.88.1674468960983;
        Mon, 23 Jan 2023 02:16:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314c:b0:4d5:7ca1:c92f with SMTP id
 s12-20020a056512314c00b004d57ca1c92fls4109213lfi.2.-pod-prod-gmail; Mon, 23
 Jan 2023 02:16:00 -0800 (PST)
X-Received: by 2002:a05:6512:2527:b0:4cc:6e3a:32a3 with SMTP id be39-20020a056512252700b004cc6e3a32a3mr7260283lfb.25.1674468960025;
        Mon, 23 Jan 2023 02:16:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468960; cv=none;
        d=google.com; s=arc-20160816;
        b=gAIDrT0qApM6ii0MN/obiwsltm/qL2I4KDruxw0ZlfZJDna8soobEi20hABN/Ne0ll
         PdRSh9MLLxodob97UTFVvci1JN120TzGjV/7wUQQiv4nkvjg+EyK9A8xy6FCZ+TRuw0C
         tGEwff/gNSZgZ9/dY6fVP1/lVs926xisteoQU2Dlwc1S1fYelZ2p93M+ohwQRbJ3Ucej
         LlTYOy3lCrNzYitzeIxfmZTzR22wiObdslxCahfQpbrAg0/d4zQDJG6Bm40u+xYTuFxh
         H/2rMcDa1gaoyNQn8rTR7rm0V3qleaOdf47Qp//gD/eTw8I2vL22MKOMiss9lzRHUL3i
         kEaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=871OGCI0aHwZZE6OKggKudWipUlPKXToB5Kn7OlT7Ew=;
        b=B4IdJqHF0HozszJrvrqvCgXA77qTJc8gN9eWQpiOTXg7g6EyXa1BDbYmUrmqlRSbKl
         iJNHBBNzfymJM2Xq3z9tGcI3Hl/1HMDesJqYVDEthIhXkPEf/+z2955iZNTKSg0Q4F/F
         1k/IGEXl9Szd5eBTtCkaHeDU/cDQ/yUQhUMs5kDoY3txyh+wPj89bpfz4YqA2nD7dcc6
         vGUVRkj6aUs7groHQMaSt8nEkSaft9pWxCHD6zLdbnYXOQ3T8aAJa9PX+qc7tixuXRRX
         bTHdc/2ZeqXlDaW44wVsMxPaAWhghKZAOTYTFaV26Bgew/1z7ShvcLRWdvrP9xHaEiCA
         EAJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=rf0Qwpy9;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id k5-20020ac257c5000000b004d1527c0905si1218864lfo.6.2023.01.23.02.16.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:16:00 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id q5so5613051wrv.0
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:15:59 -0800 (PST)
X-Received: by 2002:a5d:4f90:0:b0:2bd:d542:e01e with SMTP id d16-20020a5d4f90000000b002bdd542e01emr21625059wru.10.1674468959652;
        Mon, 23 Jan 2023 02:15:59 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id a10-20020a056000100a00b00297dcfdc90fsm4296040wrx.24.2023.01.23.02.15.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:15:59 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
Date: Mon, 23 Jan 2023 11:09:51 +0100
Message-Id: <20230123100951.810807-7-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230123100951.810807-1-alexghiti@rivosinc.com>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=rf0Qwpy9;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

If KASAN is enabled, VMAP_STACK depends on KASAN_VMALLOC so enable
KASAN_VMALLOC with KASAN so that we can enable VMAP_STACK by default.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index e2b656043abf..0f226d3261ca 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -117,6 +117,7 @@ config RISCV
 	select HAVE_RSEQ
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA if MODULES
 	select MODULE_SECTIONS if MODULES
 	select OF
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-7-alexghiti%40rivosinc.com.
