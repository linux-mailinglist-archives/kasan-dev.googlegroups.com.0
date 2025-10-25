Return-Path: <kasan-dev+bncBC4Y5GGK74JBBW7X6PDQMGQEOZTTSGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D6C5C0987F
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 18:33:50 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b62f9247dd1sf2543287a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 09:33:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761410012; cv=pass;
        d=google.com; s=arc-20240605;
        b=lPg2KEEGMkZZGNNFdm1EjVk4mqnJdMHjzIpiIQNo9RTg49FrYLhsZJCuGfvO2N120u
         vYONHl1l/GBxZhtDjME+Nho6iL+6zGEDOpLW0mJUVvcGRa8m5ZBQj31hWG/4WIZcgauT
         gm/PFfqqLF5VYSa2hJT7NWp8UrGSfDJjO15xE3iq6b8sW8PKfoIsoZopB1hm01gC3X24
         htSRJiUmeqa3KJdhoQTbn8llGW97Yr1jyFVge095oVTxQAGgBzwld1g7vp2wiF7jr5ZS
         6uzhxHhbO7x6Th6PJ3kYotXzrNhSZ2LZaBbjaYZlApUG4DD987sA91A9FO6Tl6udAvZc
         RBHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=/5UIK0a5TqSuxxKZ6S0Zlwo7LRHsaGyzqXex0sWlwSE=;
        fh=8CEUXG9vplyxg38+lWg5PoNV6e1N5VeR726qc+ovNlE=;
        b=ME4UtYAzypx8YQXTLJ8cXhF30FLPQKKk/2T1Qxm6/DcMv/M8f+tFlgx2e8BqgjtAcM
         EtgTkPqj+Zu7PKjq6n95yH1T+Rz/2w5p026oKxDUro9UgqnI6t3/qLrttwPAiraddTeu
         MmCGkp2jHqJC+mKMw41K70EyCu166dUbRwKPR0Z7UqwhLCb+eG0Squ2oGEcpWJF4sOdu
         oI8CEyf2eh9HRbqinlBKsYceKQs6PwVrIK51mjmhci+ppM0asUx/YwujBq6KtSpR/Kk+
         /FQgSayUFcA9nDQtUuiPUi8m5R35hzmINB88cKHj4dXGfleMSszZPY25lIgvqDTVoImk
         GTKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bKANgm5w;
       spf=pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=yury.norov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761410012; x=1762014812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/5UIK0a5TqSuxxKZ6S0Zlwo7LRHsaGyzqXex0sWlwSE=;
        b=EmiHigeTvacdMYgQATlYa+P4n7rrQ7+bgDOg8BoZJp32XP18em3kRmajQ3QH1zbNFS
         XmVIDOnlmdSkkxTrasf99FLyt0woEbtbaMdjBswLE28HImYgAacBorsB4DDFTMzD5Qq2
         a64uf1rCkR+rT7J4WJUMvFdwZtc6kG/Jj/YzFIG+Y3D1uyqaiePiZdZtRJCs18WoGmGZ
         Fy5kpyyIsRrC/M2E7W4iw31qY/TaVJDvFxy3JnRurpYrAx95U5Dgu0PGMahXUkyIoAEE
         4FEb/NwQyynHC9t6G3t6ZRynd0nzUkvQTZZceMeP48zex9a/bVrtrSRoZoSw9BaRqd5C
         AE7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761410012; x=1762014812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=/5UIK0a5TqSuxxKZ6S0Zlwo7LRHsaGyzqXex0sWlwSE=;
        b=HMe1bYj6KmoepcUQ27NeZpak4LwwhQwPrqhbGWPJWidH7bmPZT5yYKkcOfS/dP8dGQ
         iDO4JfCuDkfPN/GNhE9mqJzatPkeWKOzPqFjfmL3Kp0bKCThbQ1WOeHMailZN1GquQt7
         rgx8+b6ZbwixKILPlU6EVJFlooR2UiDKKsO2/lVIw2lD7ZV42mu2nXm0gqqy8aMTRbPF
         zOl3MoQlaCd58v4UaEfF+eVhGp9/m7elAva+ykRljNKha5fl+pTT95Y5OooEWZgBSTJ7
         5NIy1d0EIJjJPUAh6+ji8qFTJky5tQtPZvuTjhLd45RrvFWTBtJiO/Gn4g2UdQkPSTli
         S4fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761410012; x=1762014812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/5UIK0a5TqSuxxKZ6S0Zlwo7LRHsaGyzqXex0sWlwSE=;
        b=X4nPxIiAjsKY8SE64VGhgvNhO4XxzWdDIJzH55j34qN9at6k5MhV4lO2FoTlYX8/Xb
         ImapmLnZ0sUdYUYdcGFMFTsrgezHqGqkiupbXhcRJdykipbhWFKqVu9KYa0rsHepzFfW
         vaMl1VP3W+8+RFTuaGY8qBTm9rzLAoLt7cW0ngZ4g17kynNUrUV6ec0KntNYXpSb7sVr
         js2NU99U1O2QPjZbRlEGmSAtIKn8CfhEaqhG/79QcJrQBhy3/rofAqRSi8Q12uu4whOt
         l1MRkpIuTGV8Drq3gZEvcfiHEsVVt6C0y16zXnKBzaWQW6uMoAyJkqQCMEQBlv39+7mC
         gLlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/0N4nCtVTA4/JBj0+jeA1+Bk+BRgfbaJUDuZkv9vQ4Y1MhpSKG6wWp7Z8cpdsJBolbp+v3Q==@lfdr.de
X-Gm-Message-State: AOJu0YyX+mCOynK2iYKwpu5TtA7roEGTiqxIL8ZWjsecrsRaMG3Gta5M
	P6Uff2atLVD0/HgASL3Dy9MX/HPKjUVvqgdR1agG2WwW5QDSTodpkApI
X-Google-Smtp-Source: AGHT+IE440MxmL2rYi1MCFgHnOB2hg3mm81g7a4hYofxrsfDDx6e/gfEZStFeB7RqNiqBD6p/j50eg==
X-Received: by 2002:a05:6a20:734e:b0:341:5935:e212 with SMTP id adf61e73a8af0-341594526cemr2743391637.18.1761410012218;
        Sat, 25 Oct 2025 09:33:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bTUhSE55+50aubAzw8aMq9FeuSnuwXTnlGx8df7iYj5A=="
Received: by 2002:aa7:93bb:0:b0:77f:2c7a:b121 with SMTP id d2e1a72fcca58-7a2756cc5e3ls2629859b3a.1.-pod-prod-01-us;
 Sat, 25 Oct 2025 09:33:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWewSUDZPiIawO7MP7CjuWnJCJc2O0hpZGY20Q/TDGJKIzOhNlkul7iaFGs8qXbaThTRDxJ+TQNAtE=@googlegroups.com
X-Received: by 2002:a05:6a21:3391:b0:33e:a4e8:56a1 with SMTP id adf61e73a8af0-33ea4e858b3mr5916512637.40.1761410010567;
        Sat, 25 Oct 2025 09:33:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761410010; cv=none;
        d=google.com; s=arc-20240605;
        b=hXJyMry94SqQApFPQFiGfNyAHvxzVql4U+BwjdMtdb7qCIwIA/3TF/vAfVGygCnG6d
         fzBk3y9DgNK6BNXaoT4v7xQqqGtUxSc+NE0PD/D6ZJI3/E2rD1aPNIv8rDvgpmzFxx+Z
         7fOvbt1g+bk8gmzuFGegZQNbFjSFldn23n5FDBEKsQMIMFziQfhbr/IezAVT9WzPROl5
         xOiLanwxemfE6P7Oa82uTViQPaahRkaQ0f8su4QWKRRLQBWGsD6Zfx80wOAlz14Vqjca
         rtr4Vs9NaESbpfjg2wZIjba58gamrneoS7l6AdnulxI1ljgaxkYqaJxT3WRDGKgq2mdZ
         X9mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QSGBaOZhD7YMIGtASkoY94KR31YSs6yG4R1SCYeYD08=;
        fh=lTpAVK9a+0gbiDolYpnDNJul3CufmO3vStiuD4BOrkM=;
        b=S2INsR4z84Zl4zRDlanS4CKos2d7bsIP4m4tTvrVPK9EB95ym6uKoNpKNZYTuu5Drl
         bWAXm317GrEhTL0FB1hi7ANDM3l2R+/M7pPCM+9ar/gah+K++jC4vtVxtuZ3RkhXggXS
         a/xpnfA/rkdbM339KSZFZcyTv3xpJJA3uWyRDQK0mrB2Z2FNXQ4ZmnGUtAKb9yV6Fr9s
         igPEBkfzCnPCGUGy0SBV+jkmrn/R4PLc+n+dCdVD4s+mJycwQSiLD16aRdMls5SK4W6e
         sry2wd+QllZr2+d7njdBR3vPlcrt71MtLRg48jojp6DDvSu4fAZHUKxAu7GaL3vRGdR/
         L5LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bKANgm5w;
       spf=pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=yury.norov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7a41b62d6b5si43997b3a.8.2025.10.25.09.33.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 25 Oct 2025 09:33:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-87de60d0e3eso31616316d6.3
        for <kasan-dev@googlegroups.com>; Sat, 25 Oct 2025 09:33:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUX8xA4de0U3zwzqeKiBVT57RnJDDqxgtNysLjksCCLZUUzUjKe1jtUXplHnlwYxQbvA3Dz+cdKNAo=@googlegroups.com
X-Gm-Gg: ASbGncvZQfZoFLlAPFw5dv95twkvRbMkE2mIfKLknNLsamIG6W3+uhDmfH9nm+XsgIg
	psEGoQXuoTntI8AKhfSz1rX+nai6WxQ4PyFNdWXwTgpt48ULNC2TD6Ga+UQ2TbNc143tpeFOiGU
	DtCcxRx6V9muZV5O4hyK5YqYl6h6wpGrZNgYxEACaJCIqHkED+40UUUBz8NFI7m5n2GoX9WfC7R
	Ri6U7aK/J+ld20JJ0otXhluTr0Io8SAzcvOdcQ5LqNPsdvQBb94vIA8oqHGog3X+eoh7l9V3A48
	sQ/frr6ZDPxmeoAXJeL07K4WsT16t87YoYySRiMXoj2JqmYkGz66WESQAN+fjWTp1UpA4oi0lsD
	lh7QVhw69GPM7j/oF/FEqRkR691EeJU6cx4DUJbWTna3QmuNYUYG2EwghMePjDDsX1fpYiZPaCr
	LMcUd0ZCs=
X-Received: by 2002:a05:6214:e4c:b0:87d:fef8:6155 with SMTP id 6a1803df08f44-87f9eeac1bfmr115745596d6.52.1761410009628;
        Sat, 25 Oct 2025 09:33:29 -0700 (PDT)
Received: from localhost ([12.22.141.131])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-87fc48f64aasm16321246d6.27.2025.10.25.09.33.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Oct 2025 09:33:28 -0700 (PDT)
From: "Yury Norov (NVIDIA)" <yury.norov@gmail.com>
To: Linus Walleij <linus.walleij@linaro.org>,
	Lee Jones <lee@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Cc: "Yury Norov (NVIDIA)" <yury.norov@gmail.com>
Subject: [PATCH 16/21] kcsan: don't use GENMASK()
Date: Sat, 25 Oct 2025 12:32:58 -0400
Message-ID: <20251025163305.306787-9-yury.norov@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251025162858.305236-1-yury.norov@gmail.com>
References: <20251025162858.305236-1-yury.norov@gmail.com>
MIME-Version: 1.0
X-Original-Sender: yury.norov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bKANgm5w;       spf=pass
 (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f35
 as permitted sender) smtp.mailfrom=yury.norov@gmail.com;       dmarc=pass
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

GENMASK(high, low) notation is confusing. Use BITS(low, high) and
FIRST_BITS() where appropriate.

Signed-off-by: Yury Norov (NVIDIA) <yury.norov@gmail.com>
---
 kernel/kcsan/encoding.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 170a2bb22f53..3a4cb7b354e3 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -44,8 +44,8 @@
 
 /* Bitmasks for the encoded watchpoint access information. */
 #define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
-#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)
-#define WATCHPOINT_ADDR_MASK	GENMASK(WATCHPOINT_ADDR_BITS-1, 0)
+#define WATCHPOINT_ADDR_MASK	FIRST_BITS(WATCHPOINT_ADDR_BITS)
+#define WATCHPOINT_SIZE_MASK	BITS(WATCHPOINT_ADDR_BITS, BITS_PER_LONG-2)
 static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
 static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251025163305.306787-9-yury.norov%40gmail.com.
