Return-Path: <kasan-dev+bncBCSL7B6LWYHBBL4HXHFQMGQEQ5UWEWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D2524D3ACA1
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 15:46:08 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b6b64b843sf3215263e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 06:46:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768833968; cv=pass;
        d=google.com; s=arc-20240605;
        b=PNpTXF3QAjTX+fDCmdjp7hUoMTKUvebEy7FLtx/4mC52Vb0+fhaHafgjdycMnVUkYT
         qzEUS99yPPaAqUoViy6KJweFs2mk43sqTms5Xb/Q77PmN33fWvIIl97D3Zmb1L1Hj9q7
         UGlfq8GFCU/RUHJZDAEeDKsPiZJKZoivVLPcriiMY6f7y9R2zNdzWs6jiyTruFV/YUE9
         ddqm42aiNnsX4E8vZ9SV2+MXmZUYZhy3WzioxIrqwCPTUvne+VB1RYJdlw6NvEBikD2u
         37dS4lDg4hvtplSAs/KaUqucyB7AUwFVgmFAW5E8D8ciDmZruBpya9zODHQDCpNM47T3
         nwFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=v7vPKBy5UhqIMRNMsfnJai8LTWD4+1bgSCPFT23JP3k=;
        fh=StME/VabXXxQ7CfgnRx0oHK8n81fDJISX2I+w90nDJY=;
        b=L1EixbW7jdQfE+3Da7udH3IZn0pubo+7p1ZmiEoQkfHLKA6RAJotijcsTAcYANRPkJ
         3MVgmVSLRjsNR7sl4v81o6c4coSnPYsP3m5644WKQbMVNqYH4LZ5at9D7PfyXBUXhnhx
         6L596Z5almjfBXaymtoXHlofjCrFgiGMKvrrKSu5+qJ5WTaxNp8CJA17ROsfi/7z3O91
         MtVW1eJNO0Swt2kN+alWBoMp7rDDtSqUHwLVQ0SeGKF0LTG7bKKVKhZ5zRTinp/+0Lp4
         rmqjKf/s385MiiJpXzqxTSU5zZ2kj+VaN0XDJJAbTst5bbvYulwPVDI9zQiLBpQFMXxO
         8Glw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kXqJxedh;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768833968; x=1769438768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v7vPKBy5UhqIMRNMsfnJai8LTWD4+1bgSCPFT23JP3k=;
        b=buMiOCjBRWdtF2Y7gdROm+zMi2lxcXfNDjHLM58HUkxyQhk6MGRRyneMPKqltrXzbn
         05E1rjVAFNWBt6cmq+eixNSCW11Wj8DVghVrlghHCLsmjbg8Gw7o27adYKiR7NbiDp89
         4bvgokRVnuTLe1SfqdyZf3vV80fTqQzYGQ7Nxo8yMr8+uoB96f5GVwn3DhprEN0SAGns
         Azk0LRrtwcPll1BfnlVUWuT0rmyxt8mPXMSt+Cmpdgx7SNY7ATk3zmOl4Y2cAUgaZvVE
         7YBwoWPUGEG12jIV/KHhPDpAuGw/PehrOly/J7VrRFryJRrHB3nBQcGjPJw4bMMnVYcX
         FaIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768833968; x=1769438768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=v7vPKBy5UhqIMRNMsfnJai8LTWD4+1bgSCPFT23JP3k=;
        b=hycOsiMYxBu6vt6yUzsG7CdUbEtSekzkRDUhYlWcM4xmAn0FFWVJIf+lfzvjo8+A7G
         5Uh2cUAxHz/zqegnyGsi3u3sYMArO/JmXnyDxFCC0oACJIBRwG86OZ+PZIkoVr89UwoJ
         DsUr6iasFw7R5tqINMbyAAx1TxNsbvCpaAZvBy+ZoAEjn0bLNeVuqDmy8F20wL83hKrm
         uyPU287Y92KDVCh3OYZkUTgs8QO/1gWIqx0vq1BtASjWZ2/FNaI4UgHcPu2mTCut5wia
         51Fx2aONokzVTz+PWYX8+h/+Hnes0QgLIoYpBJARcm8oekJ9R+VrTVGYH9TuuBECgeDH
         CMVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768833968; x=1769438768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v7vPKBy5UhqIMRNMsfnJai8LTWD4+1bgSCPFT23JP3k=;
        b=r+om3gp9lf0P/KlEXC3VaQUr5FIkaoZPaywxzvDHecn+xHkOydCodRTB1tttHwkBMB
         tpAUj9f+MSbfc7rnfovmlhwj6WTK+hJ22JC46U1Ix/eEsvQUI1mb+KzcFqaocojm+9I4
         CdE4z22loMJ9TqibXSAF4YWJUxt44kakUKc0mBn3s7D5xs5W7OlG9NgJJI3S2dwgU3fb
         Cn115povT5/ZFdXihMuZ6vSZWtaN4rBl5r7WaQxBCmO1EQzLapxW+gGR597JI37gdts2
         8SebG76WJTaEHigBnbsGiz3cnfB/K6GUQDOOU+cS0Z+jlZExPW/4vb79SD4OXxoVWfgB
         0hqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnrIFO9bP/ZhvKuhkoLY1Y8iLZ4eE6XG79zG4bObD1VWZAdpqy/YjhLz+ocUW4FzLo8bCgsg==@lfdr.de
X-Gm-Message-State: AOJu0YyceFlXWFE14xD6YC74DyroVHtzBum/yA2RRUetpNt+6Avprpr8
	sA4vdpUz2Q628g29Km1yrzs6p0Q8J7u0pd/0RcxRzUv67l8oXtfHjDHr
X-Received: by 2002:a05:6512:ac5:b0:595:909d:1af6 with SMTP id 2adb3069b0e04-59baeed6387mr3338259e87.28.1768833967883;
        Mon, 19 Jan 2026 06:46:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EmPVC3uOxEyVZPj+Gpvd0tp/oCTWjKN4wYKnlKj2I5+g=="
Received: by 2002:a05:6512:3ba6:b0:59b:6cb9:a215 with SMTP id
 2adb3069b0e04-59ba6af8459ls626159e87.0.-pod-prod-09-eu; Mon, 19 Jan 2026
 06:46:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVf2VPKxOFLhcgjXDrEApwA4EC31sCw3xRSWIGR8d4gvrwOqnv4mXHkC+lfpCNcE2Biky3RJfwdd68=@googlegroups.com
X-Received: by 2002:a05:6512:23a0:b0:59b:b17d:9852 with SMTP id 2adb3069b0e04-59bb17d98c8mr2942383e87.1.1768833964582;
        Mon, 19 Jan 2026 06:46:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768833964; cv=none;
        d=google.com; s=arc-20240605;
        b=JYxICv90uzRnQJ5CTYsvrFFPaegg7ta2b36HJi+grxdltXtDJaWXnNQOSYaJbHNXH/
         UjmbZ43+cNMV6JlS+camhuBfb/lgbHOBY8biKTWHBf3cFe2Q6MVysk0DI9QT4qdlr/4n
         2evjpqsK+FrQqQ+PUWiG1XTPE0CoWAknhtDy3zly1ngmARrUDnTD0pjyI+cVFBWIM/x5
         2y9cqU95GY5dW8W46GmJVvFj7/hUoMflhNR+CvYCGhA+NmClSspz8zcWjoawWwI9bosU
         diZRV+dI5azBJkEC61yf8pV1Pey3+8cUfOfZvKxgu5+rlXGJ6q6eaq9uBGMd6HxLHwsY
         uhmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fsjvsl9QLRbiT7Kn7hO3fVpNzPEyahcgYF/8T1qgI5c=;
        fh=w0mJ08UBFm2bccfTukPVgwIxqKJ3jXUwgiuOBzES+TI=;
        b=a1pooCPgKZJ1B/hvaJSrw+VzZ3Chd2MvEpaSdQzfEwVH5Vx7x5CKiOmYqklydY955B
         9wiCnKZdMJ9COdI4xKs8yAmkMMyYMkKv1JojQoytbiTtjf+btKe6HB7pJK6tWlp79Gn+
         NOEcEFiochM4pRB7ggYzbKuSEPdcysgUKZCmHbNrOGsfF/UJNQaG2pW+Jyzobm9RtxJA
         V+Hr2722c10uUF90vaTsIptU79C3UzHhH/Jj+1lOdm/qwG3cg4AtUt6mpwWEc5qkbkuh
         2fUPF0m/jRGS5gJg7QEirgyY/eX9svuWNDbtvD1wrNOfz8GjgpiFdqDl1rmj9lHxhiE9
         ZniA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kXqJxedh;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e7914csi1701161fa.9.2026.01.19.06.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 06:46:04 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-59b75f0b8ecso476102e87.3
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 06:46:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWEbdyUJ/FRqZVdQFNSrMugtuWwMJlv+G0eLHMh9XDrFxlo2lZnnGirlkKaADFIxwSOYkdBsMaQRWs=@googlegroups.com
X-Gm-Gg: AY/fxX5jxUZJLTCmtX7cXfH3A6pukuq2RJgXGtKgCXkkfx825CayatfwhIdEohLa/3f
	v2Gc3c50Xvhez4IPt0RUThM2zV41+zLu+P7CP5gpHpXGqJCiUjzDpUlSae+0iPhKAgjNQTJY8M3
	ehy0uM2BdoPtNRYjUcpBMTqmok47mSX3/QCNYGVrms7eOJMmUAzGCQIzxMqzUcrBqnuo3h8KchD
	AuNvPYXDUB71vGB+ahxjOOp7AKXo/KvOkvJ+3rOvvfGO1Vv0fZvl1AZzrnx/nqqNywafLnFdvgX
	sjduTqdcfxUczsBf2+UXUuEIp2dt4LpTpa/5Rw6kiBfiVbxTaGrNF4wb33BgiJvFLoq+My5d7vt
	Y9JpLXpLa/NWXTvfSM6LREvn5GdkcT/w/ZJ1rhcxJlPPwG4SHwqLUc6Ij06vN8BV7WANNdLTWmk
	Wicfm53l79MkzHHgCf9D8RDh8=
X-Received: by 2002:ac2:568c:0:b0:59d:a4ed:2309 with SMTP id 2adb3069b0e04-59da4ed238fmr294405e87.1.1768833963843;
        Mon, 19 Jan 2026 06:46:03 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf33ed36sm3408385e87.18.2026.01.19.06.46.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 06:46:03 -0800 (PST)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: =?UTF-8?q?Maciej=20=C5=BBenczykowski?= <maze@google.com>,
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Uladzislau Rezki <urezki@gmail.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: [PATCH] mm-kasan-fix-kasan-poisoning-in-vrealloc-fix
Date: Mon, 19 Jan 2026 15:45:09 +0100
Message-ID: <20260119144509.32767-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
References: <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kXqJxedh;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12f
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

Move kasan_enabled() check to header function to avoid function call
if kasan disabled via boot cmdline.

Move __kasan_vrealloc() to common.c to fix CONFIG_KASAN_HW_TAGS=y

Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 include/linux/kasan.h | 10 +++++++++-
 mm/kasan/common.c     | 21 +++++++++++++++++++++
 mm/kasan/shadow.c     | 24 ------------------------
 3 files changed, 30 insertions(+), 25 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ff27712dd3c8..338a1921a50a 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -641,9 +641,17 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
 		__kasan_unpoison_vmap_areas(vms, nr_vms, flags);
 }
 
-void kasan_vrealloc(const void *start, unsigned long old_size,
+void __kasan_vrealloc(const void *start, unsigned long old_size,
 		unsigned long new_size);
 
+static __always_inline void kasan_vrealloc(const void *start,
+					unsigned long old_size,
+					unsigned long new_size)
+{
+	if (kasan_enabled())
+		__kasan_vrealloc(start, old_size, new_size);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed489a14dddf..b7d05c2a6d93 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -606,4 +606,25 @@ void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
 			__kasan_unpoison_vmalloc(addr, size, flags | KASAN_VMALLOC_KEEP_TAG);
 	}
 }
+
+void __kasan_vrealloc(const void *addr, unsigned long old_size,
+		unsigned long new_size)
+{
+	if (new_size < old_size) {
+		kasan_poison_last_granule(addr, new_size);
+
+		new_size = round_up(new_size, KASAN_GRANULE_SIZE);
+		old_size = round_up(old_size, KASAN_GRANULE_SIZE);
+		if (new_size < old_size)
+			__kasan_poison_vmalloc(addr + new_size,
+					old_size - new_size);
+	} else if (new_size > old_size) {
+		old_size = round_down(old_size, KASAN_GRANULE_SIZE);
+		__kasan_unpoison_vmalloc(addr + old_size,
+					new_size - old_size,
+					KASAN_VMALLOC_PROT_NORMAL |
+					KASAN_VMALLOC_VM_ALLOC |
+					KASAN_VMALLOC_KEEP_TAG);
+	}
+}
 #endif
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index e9b6b2d8e651..32fbdf759ea2 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -651,30 +651,6 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
 
-void kasan_vrealloc(const void *addr, unsigned long old_size,
-		unsigned long new_size)
-{
-	if (!kasan_enabled())
-		return;
-
-	if (new_size < old_size) {
-		kasan_poison_last_granule(addr, new_size);
-
-		new_size = round_up(new_size, KASAN_GRANULE_SIZE);
-		old_size = round_up(old_size, KASAN_GRANULE_SIZE);
-		if (new_size < old_size)
-			__kasan_poison_vmalloc(addr + new_size,
-					old_size - new_size);
-	} else if (new_size > old_size) {
-		old_size = round_down(old_size, KASAN_GRANULE_SIZE);
-		__kasan_unpoison_vmalloc(addr + old_size,
-					new_size - old_size,
-					KASAN_VMALLOC_PROT_NORMAL |
-					KASAN_VMALLOC_VM_ALLOC |
-					KASAN_VMALLOC_KEEP_TAG);
-	}
-}
-
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119144509.32767-1-ryabinin.a.a%40gmail.com.
