Return-Path: <kasan-dev+bncBC4Y5GGK74JBBKX36PDQMGQEWRCFWDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AD37C099DB
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 18:41:16 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-89e83837fadsf343782385a.3
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 09:41:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761410474; cv=pass;
        d=google.com; s=arc-20240605;
        b=ULXwfJC/HPHJ2UK6oqQHqcwy8WrN5XiAhg0YcGm86V6fIfDXAp945FWPrFUFW+udBT
         hrii5e099bNtyUkJBN37Ptk8g/3xHPjG+X2+k9nYIEEoFZzI3LSac8mjV5IL88iqesPh
         joQMc8pBugDu7//t1+B3q4lOm+UaULvyNkWVeFcBeEpmnAo89URiicr6OywdgZIh999W
         eaybFqIoO7UkoLzaHhFlw4UCDdswzcpqBQSvmgZH5RInj6Cdedu8mm2u/igmQPwvGhG4
         kQ3Gwgvszrbk7McN31ZPwQD3rtRREfkaGkZIKQkbryoiCsL4Q9ejat3sordzPLLIdKCS
         dQWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=7KdUlHCDZnHK+dQkEnSxV71WATmT/EQAFCnDWH+L6uk=;
        fh=9/6+pPHvj6B4q0Q9fTQolw2V/ms7yqy7qHliSejCpks=;
        b=JoDJbAuAzhuEdSdcWRtiA6S27RUp8YBADjYtjN51sPpBFf2336MMtA9O5IX79kqlo8
         by75te76pxEZpvTgbqTEgr3E5yQJwIWwsnHIdCIXcNIRwBO26NXSpC6Mc5jCBGtnCxrm
         mv6Wk+TLpF4Kjk2qDglhVkbU58fWd9vjWnrou9/XlW30usQcj8RpzwH9/8zuvuJ+WC4I
         wIzrwDAlxf0L9KEVvA4oTHDBDYa9D5tZBW0yRfXUF6plGUcuXy6J1dZt4YCe5NdtcOPG
         uI2WDDZMjxluF6tmOBDbdpnxNND/jUGv4edpgCeb6+ZbSBdR4vrNPQVD0Wg2ZaxA2cGR
         /Fxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TqVq167B;
       spf=pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=yury.norov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761410474; x=1762015274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7KdUlHCDZnHK+dQkEnSxV71WATmT/EQAFCnDWH+L6uk=;
        b=gYeV/BJRL5o+Q+LDLKA5XB3trvobHBaMXFIZyxrhpbiKh3HvU97FlmQ9qqAtwdRz1L
         OsTEt7yID6vxgmJXsv46R3nqEsiGcDpSym5azZaY2I8ZYCfAtW09BZCb7Ld27+QerAkp
         S3NfOEiVDsKEFR9ZmA4fnMK8hmAc2RyjDH7kuAoIU7an/IwGzQoFsVM5w54TnGACx0is
         Ir6p2xH1RU6L3snqtmx4uCTWxGUmXY2n6zJSSMF+en39NL4Dw2n+JunjUaSczsqQ9dOs
         DuUGETKSrJ3BoeunSJWrInu4KTaWBnhaoiv2s9WOL48zqJGjKz1T2Ww2SvTVWEm+tZpO
         PAUw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761410474; x=1762015274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=7KdUlHCDZnHK+dQkEnSxV71WATmT/EQAFCnDWH+L6uk=;
        b=hXQWqKZMmdOLcFjZW3t1FACnr8HVODusFnUu6CiUK0KuwbxZNRy+JeE+GXe+Q/YqOo
         v3QQGuJ/usyWlgGqVGz++Rw6qel0Eb9Wd1GGce1cpbVRAFMoujo7QGtjjn7QTdf3bJQ2
         /BxxNVOuV8h2//MpxZ+icCyzdekAB79Do3OAmFuwO7X9pYjKu11/e74eKTEJ/bYxLfGp
         9RyfeiC4uI5n+oq8FmpiXX/pFtb+TgT1+xB38EaH3eDmK1zCjHM4MBupEb5ICOnv5E/Z
         /BQ6ZVkk8Wh+BJck29GxI87IRm1vOlq1nH56ac8cMTHQELyUiOcBrK1ysx7+NrWLiVZJ
         8Ezg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761410474; x=1762015274;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7KdUlHCDZnHK+dQkEnSxV71WATmT/EQAFCnDWH+L6uk=;
        b=V7zfo6AOaLs9pfhRHrshxesrVNfH/E4Yy3eC1pNy6+nvug9jIV017FoCjRysPQCb5z
         /6QKoB2RnT0rfgJlhLz+FtR2dzQ/DlIeY4jg+e3xnCTzEmUGLVUc7Plv4RWIsPPt8lFo
         Cm/HJxAClzR5f7qjhOHZ2Hd0IvgyIshwDhNUXNPANbV/37Vj1j/fIvo+suXVo2fyz2AZ
         8/1zXxUc/hspvfDFwGWR29RLZ6DxdilGfCRmMDdUhIF0c1H7mW9sxeAYndoGYeRHSrp6
         Toj+VQgjEZba8Sv4tlBY9CSDAnt4N1SLW5lGE9pOoK2l4FtOY+RX78YmbLuOoiQD+r37
         4bGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUM//jfg86Pf9YaYwZxuj2UVaJqxMNra5cXhcvPlYyVPtYz6BjTAE84YmNicdkkg50hQ3cDlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw80SKzh+ruk4G347yxzX3Cap6TBisiWuA47cdQXIw6MZreNdQb
	9Py7GspJerPFUUunqfm5xHQ5BDSU2xIZrnpcZLB5O9/4XmY2wU3NUiFs
X-Google-Smtp-Source: AGHT+IEqOlbAsiXU5Sf21VzDVKufLUFjxHsivsaUV85OX/sYM4ylFNCSYVz9j1Z3HSxY3pV1cxmSUw==
X-Received: by 2002:a05:620a:28cc:b0:85a:4bc8:3d42 with SMTP id af79cd13be357-89dbfc9c949mr736144485a.3.1761410474408;
        Sat, 25 Oct 2025 09:41:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5X7Y4HS4ERUk9NTbt213ZRsL8THuEUP5spflKFzaE/hg=="
Received: by 2002:a05:622a:507:b0:4b7:a98b:51db with SMTP id
 d75a77b69052e-4eb810efd1fls54045471cf.2.-pod-prod-03-us; Sat, 25 Oct 2025
 09:41:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMq+KaHC1AvHPxAcNzegyEso5Te6umPxm8J73vgL5zE0vapodfq2oZExAcwTVsAbVniAS0DEyzKxA=@googlegroups.com
X-Received: by 2002:a05:622a:2612:b0:4ec:1005:6c14 with SMTP id d75a77b69052e-4ec10057007mr18636971cf.80.1761410473485;
        Sat, 25 Oct 2025 09:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761410473; cv=none;
        d=google.com; s=arc-20240605;
        b=cAETYy19+jz/8LV1cYXJij7B0QnXE/YjR765QT29/JWM0rZxLGT4Y6wwn7yemkExvQ
         3ylERpYa44ZdZOfbUgu07ndcAzVuSeFnmpi5aGwDiADndIZ7W7TDCVoD9DfJjc/xutdF
         J63WCjGYpCBLbnmGyXSDduaDUIdPsGtGkn4yFwNVpLcRkPSSY6tlyh0Oz5TecCmgFVYz
         +c+RS1Gynn0WD6/8V5K9OtjAuB4nl8MlwYrruqOk8IDDyqH/XG0putdb/F+Bn+ppvCq5
         a/wRCCIuLYMwG9mIfJlGtcDoffR3DMyL7V/3nmyd6+/pOvSSUDZc8i5L3xIsmkEkMwU8
         ZEow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QSGBaOZhD7YMIGtASkoY94KR31YSs6yG4R1SCYeYD08=;
        fh=jq2CxKFJYpfPyRAie/iETaLRE+vkEv6d1ofGLYWjn1E=;
        b=MdjCtWqEnJ7oE9BN7nH0wsKZ0VfWQRtivrsrs5TXZNAD8A3ltZ8Z61Pw0xLPEtIZaw
         VUoGmxt3SJ6JBsOvMiJYKScr5o1G10af1dd02V4VGqqnC4+/HKcVQZrFk1c/g9lXJR0E
         2E2qbvur/gYvDQGvqnZfL7t7L/h8Rb/weyQEh6rapWHEULiJaZHAXKJ0K4p8oHhyuOB6
         GYfI077hzLXtIL7NL9byG83WRL9f90OVWBj9vgLeec2qO0HKxuh6WWddSvM3LuyZJTMk
         YapCYGTNYmX5+auxxqPF9UZ1J4mWLx704JUyn57NNMHVnApsWqEnujq6rFV6vZzVJxi5
         nCyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TqVq167B;
       spf=pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=yury.norov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4eba5163a72si398241cf.4.2025.10.25.09.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 25 Oct 2025 09:41:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-87c237eca60so25684366d6.1
        for <kasan-dev@googlegroups.com>; Sat, 25 Oct 2025 09:41:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUV1EJCzoJ3UGiDEy8KWUscN9eJ9RmJatPbZMwkIB/liPdQILxv2bEZftgXcM4w1JGcWq6LPn67vc=@googlegroups.com
X-Gm-Gg: ASbGncufhnYTLD5S4uY1tbZJseVgTl6FSKavgJOUXtsl+63ziBgwIVVT3lU7sMKA0bl
	6r9JGd00oco5j1aJRPdwBtoe6fn0VMvdXRRD3bCHvpErKbHVPq1k+3Tui9ihwKI9w++jhtVE21R
	QoJFtNXbCJHRnXoDG2aIPWddGG5ZrM3rpARDTvpfN0iNNL2IlWgIbO3YDxEXgiMJJ2Z5CUlxB4P
	iJ8Qty3xCDbBbucIng5ZwLRrbotgOEwTMTMtBOF2pi3Ok7HFX9glostsTeTVRmApZ+7bWno4DI5
	dH9FKjZEE/YJ9Kyt4FTEjC1r3+iliSmsAC5IOBhtDl13L2k3fArLwq0viqpApxnK26Q+PpYSXdm
	xMfXmP7Fj3gwLCvh8fJnVBM4TAt1PGMx1+EZmoeaZiBzUYCqegPRfVhA9EyC4YrvEzWDJ93ZiKG
	Ke/Wm3RKM=
X-Received: by 2002:a05:6214:da9:b0:87c:20ae:68d2 with SMTP id 6a1803df08f44-87fb636016dmr79581736d6.1.1761410473001;
        Sat, 25 Oct 2025 09:41:13 -0700 (PDT)
Received: from localhost ([12.22.141.131])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-87fc49783eesm16403966d6.44.2025.10.25.09.41.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Oct 2025 09:41:12 -0700 (PDT)
From: "Yury Norov (NVIDIA)" <yury.norov@gmail.com>
To: Linus Torvalds <torvalds@linux-foundation.org>,
	Linus Walleij <linus.walleij@linaro.org>,
	Nicolas Frattaroli <nicolas.frattaroli@collabora.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: "Yury Norov (NVIDIA)" <yury.norov@gmail.com>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>
Subject: [PATCH 16/21] kcsan: don't use GENMASK()
Date: Sat, 25 Oct 2025 12:40:15 -0400
Message-ID: <20251025164023.308884-17-yury.norov@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251025164023.308884-1-yury.norov@gmail.com>
References: <20251025164023.308884-1-yury.norov@gmail.com>
MIME-Version: 1.0
X-Original-Sender: yury.norov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TqVq167B;       spf=pass
 (google.com: domain of yury.norov@gmail.com designates 2607:f8b0:4864:20::f34
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251025164023.308884-17-yury.norov%40gmail.com.
