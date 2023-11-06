Return-Path: <kasan-dev+bncBAABBPUQUWVAMGQESZFRRSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 25E9C7E2DBD
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:10:39 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-53fa5cd4480sf3797232a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:10:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301438; cv=pass;
        d=google.com; s=arc-20160816;
        b=USkyi5M/+nYd4K9UBV/p/a1uBWTK41MkQ6uhM1AXdB7/fYTb0sRaZckKrk0a4/L9MC
         wOq0+LgXk/v/C5NwVYgl6Dj/f0rmzdlKOlL8nkSdG5T2Gv3atDwe4xDLQqVva0WOi/Rm
         yt2dh3rtM8XMH+daoeTvA+Z2hMQesdp3AUzOUxolx0Y3h51Vz0d59UKDdlOhFHZXY3Um
         WtJzMos8aO/cYBrPRgl+W/kNJ/WB0AP2RgGoI+QvvZwxyBUY9VjII+QIf3V6kOiWUeb1
         NZ8E13r8vlbma3gQWFk+R71Ft88FYGKYaWxmsmb+QSCailHoHCNaskS8gH514IKBFmY6
         nkBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iTIB316btVMdJzF5ROBGpAvZuZohkgPXdfQiDkgLNIo=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=NjfO4IGvtjBSPi1Q8Y7L2DxkJ5sjuOtI92BrYF0+jLgc5H3rBKb050hjjDcYnJ2s8V
         91vRIU/dDKnhjNyirJoFhA8if7y2K1FvGI3X4kcNNZjHjtwyKORLPlNtpQPPeFJbg+Y/
         vUYJBzX9MSMTcdkuZHuh3pkwOFQ7GJ9076G4x5Xx1AcIGsprvjrQoRorRILrWtMbmqom
         +R8LvtCi0R4SsjqvSk0Pz7vAYzJL1h865qJb5BUnjqbv3jS81dlFZTxP+K7PsBnCx8/Q
         q5R5FzJzhdvSu7zRpH4QlDtF4HCljzWff6DNAWG1COYSmqJQEmXva7YpEZJyYCo7lzZR
         qctQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IRiR9duy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301438; x=1699906238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iTIB316btVMdJzF5ROBGpAvZuZohkgPXdfQiDkgLNIo=;
        b=lUGxvW3bVjyqAOfZ3ZCM7pD6EzV95nmRpDOUHfBEO+Dzyg7waPmg9eMtL4XdeZuTCw
         wrHTMZGkTcoe+aTmDCwbNf2z5QaZ2UmQ5wI5aPJ2qOE4YJwntum/Kczvmi//EpuFM0n9
         gB/bP5q8BkfJRxDCFXfQAzyoyPQy8lgJ5OsPkBVKg0QlXQloauL3AZ/phbeODR5LpiYg
         ib75NSyIQfyJRViE9Vv93ygX+q1Gv2Jw1OVFcwtmx1lpSijt75AtznHXDCEWEX4mYG+P
         2223aZqH/FQ+fmaSyb7m7DGuEeGYVGqdbXW/s0De6FqlWQrQwpdYEPXD54jx4YD5IydH
         SemA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301438; x=1699906238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iTIB316btVMdJzF5ROBGpAvZuZohkgPXdfQiDkgLNIo=;
        b=HTzFynSAhJRpRjGKpc9Y2rnra8TbTkR4+lna3jX5HYZqeX82HBFioQG/qB/tAmSvlx
         C2TDfXpHb5G2JnPkVwocYXMb0vRXR98pROPAJucR6DTkUJycMOdcsuXGcqrXdIm+7gHY
         MpV2zO/CEGWqhpgk0ImZqK3FBTUB7UjbSy/gffm39IFVe9gamdq0PssZLJznxvLo4ndJ
         pmROhVCatVgGZS0T1SpDzqbCGVJSl1HeHOeM/l/V4cvmatj2CaMt3FHlQJ6YqkTFPe2D
         ytfUQT2+qZNCg4VS6BycpvninNt2g+GiBslB3GeYxgoZgMOsxF2XaAvkYt2JQnI1SZyj
         2e9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzjIK0rSZvwq/8odHHO6GGVgAgmcfCLPNLbkOWmLyneZcnAhYGN
	ffYSlyZZIL+H14SOWOeEPwQ=
X-Google-Smtp-Source: AGHT+IEUU/1Zw3hrXj+1Tgqwndel6s+l1sbDzNa/aFPuQ50RO32PBP/4g4iUTS/yFCKp3OONk3+D/g==
X-Received: by 2002:a50:8712:0:b0:543:7c94:a879 with SMTP id i18-20020a508712000000b005437c94a879mr15792935edb.29.1699301438665;
        Mon, 06 Nov 2023 12:10:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:453:b0:542:df39:bcf2 with SMTP id
 p19-20020a056402045300b00542df39bcf2ls441935edw.1.-pod-prod-01-eu; Mon, 06
 Nov 2023 12:10:37 -0800 (PST)
X-Received: by 2002:a50:9f4e:0:b0:542:d8a6:bf14 with SMTP id b72-20020a509f4e000000b00542d8a6bf14mr21011915edf.33.1699301437103;
        Mon, 06 Nov 2023 12:10:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301437; cv=none;
        d=google.com; s=arc-20160816;
        b=k5TtH82mZ6dKvOVo0vA6qZ8+LYEYK4jYirR9MyAusaPXXvNByZlRWBYTfQav/ZBo1Q
         uWiElSkiLrz3yQNt+PIpQbu/a/bclJE2Gp9aXI9XXGZoiyskZS6Hqev2wuMIaJnmNrdN
         YBgD/HSI/Is6fOCXgYWYcaN49aY5CSAJCIHa+hHMaqteVgUYxS1ExyzVEpfQzNDCCoKp
         +ogZNDXdTtODMMGW1jCbCApTOTyFWpmY7lAZ7VF20KRslFEq0T490ak/FKcLLC4dVab/
         +UHi6bSboeLDz8qTkJotdtr93PSqEjhZNbdNc85nG/aOiSWZxBnuIfq0ennIjkdebvEn
         5PYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VrpDyLzZeYtu1H7+z0aR/HPyxv+dwo0N2+jHNRcNovg=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=yyfRiu44cH6UmZ8Ca9/QbKlYw0QnEcpv5fSwskZl6M8HBwngAoZkmrHd8gigu/4jkj
         PUaam8Mt98lVC41zKDYKBR7mAfW6NEtnhvyJ42hpkbxvs2+LwuVZTRbR/IpNGle+n+Qj
         FHomYKbR6Pf2PYKAuFAbhSKPXYI9mUSFBtHS+USaB050TJIyF07IooWluVGSGFG2//FR
         q382Gp99tSuHatvCrrfSqQ2omUUdROZU62JdY+CK1wPz8uBMluGfm2ZmLytvmvfPNteQ
         UNxVyWM0Jj3Ith1BJHW14hXlGJ3kTpWLZ1/u50ORCdTDvfGdPN9e7ZaBNl7N5nqxMem3
         g7TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IRiR9duy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [95.215.58.177])
        by gmr-mx.google.com with ESMTPS id n20-20020a05640206d400b0053e90546ff6si557761edy.1.2023.11.06.12.10.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:10:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) client-ip=95.215.58.177;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 05/20] kasan: introduce kasan_mempool_unpoison_object
Date: Mon,  6 Nov 2023 21:10:14 +0100
Message-Id: <6b096bcf531f457b13959ea99b1e270b96d5ca34.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IRiR9duy;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Introduce and document a kasan_mempool_unpoison_object hook.

This hook serves as a replacement for the generic kasan_unpoison_range
that the mempool code relies on right now. mempool will be updated to use
the new hook in one of the following patches.

For now, define the new hook to be identical to kasan_unpoison_range.
One of the following patches will update it to add stack trace
collection.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 31 +++++++++++++++++++++++++++++++
 mm/kasan/common.c     |  5 +++++
 2 files changed, 36 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 33387e254caa..c5fe303bc1c2 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -228,6 +228,9 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  * bugs and reports them. The caller can use the return value of this function
  * to find out if the allocation is buggy.
  *
+ * Before the poisoned allocation can be reused, it must be unpoisoned via
+ * kasan_mempool_unpoison_object().
+ *
  * This function operates on all slab allocations including large kmalloc
  * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
  * size > KMALLOC_MAX_SIZE).
@@ -241,6 +244,32 @@ static __always_inline bool kasan_mempool_poison_object(void *ptr)
 	return true;
 }
 
+void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip);
+/**
+ * kasan_mempool_unpoison_object - Unpoison a mempool slab allocation.
+ * @ptr: Pointer to the slab allocation.
+ * @size: Size to be unpoisoned.
+ *
+ * This function is intended for kernel subsystems that cache slab allocations
+ * to reuse them instead of freeing them back to the slab allocator (e.g.
+ * mempool).
+ *
+ * This function unpoisons a slab allocation that was previously poisoned via
+ * kasan_mempool_poison_object() without initializing its memory. For the
+ * tag-based modes, this function does not assign a new tag to the allocation
+ * and instead restores the original tags based on the pointer value.
+ *
+ * This function operates on all slab allocations including large kmalloc
+ * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
+ * size > KMALLOC_MAX_SIZE).
+ */
+static __always_inline void kasan_mempool_unpoison_object(void *ptr,
+							  size_t size)
+{
+	if (kasan_enabled())
+		__kasan_mempool_unpoison_object(ptr, size, _RET_IP_);
+}
+
 /*
  * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
  * the hardware tag-based mode that doesn't rely on compiler instrumentation.
@@ -301,6 +330,8 @@ static inline bool kasan_mempool_poison_object(void *ptr)
 {
 	return true;
 }
+static inline void kasan_mempool_unpoison_object(void *ptr, size_t size) {}
+
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 087f93629132..033c860afe51 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -441,6 +441,11 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	}
 }
 
+void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
+{
+	kasan_unpoison(ptr, size, false);
+}
+
 bool __kasan_check_byte(const void *address, unsigned long ip)
 {
 	if (!kasan_byte_accessible(address)) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6b096bcf531f457b13959ea99b1e270b96d5ca34.1699297309.git.andreyknvl%40google.com.
