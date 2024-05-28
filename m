Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3XM22ZAMGQEXOY3IWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 297828D18DF
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 12:48:16 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3744ef545basf1462955ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 03:48:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716893294; cv=pass;
        d=google.com; s=arc-20160816;
        b=QF0NaDMVZ5lfKRzWVvGWkEjT5ePY7i9sowR08sMieHBANLWCmtk7MMr5pbivP44UP4
         7JsAsjoc+5R0eMi9tmw0FTVwpKKyP45jeP2jK/ysLrNCdJaTBudjRLrWc+pEttt9xqGs
         cn7J8bjdPFqCW8wse5BcSH1eNNnnidBFWjFHCrG7uNSPhpKS6Tll9IGJKHydTt3VRsBd
         9TZHJgiAuWHFfZ1yK+4knS1oOaGlBEaAIXKEb/LoEe8hW1dDXTz9e72BHzz4C+pjV5o1
         vHk81VcRMkGDRdrAlGPJpY4qr3vJacih/1Kp1HcJ3cbDU10Ru/PHe5453XjB/zIr2gnx
         5m+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=U8vFB2wy6dnKCZdT6g/3nWEuzP5ubbDLGHC8QeJJgwU=;
        fh=ad2KIxzoBZ9KrmvWpNt1enfcmVJ3vXgvW+HyBmm92SQ=;
        b=WO9K+CWL6EQGrGw01MahEMfAfXTA2tNHoSCuBdV0MAMdlxgcy0TGJIpt3JfY01VCEQ
         Fd4j+5uFJ94MuUGWS3t8Z7Emqy1mBuW9tXonpcqfmd//366l+PPKHvTi6M7p5R0Hm6kO
         ATBEvx1M5Y8i/FMt33vmXhj7FHpgx7W6TzVgaRLM47nRBs/bl4BwDwLN4bTJKJ2NBLsy
         KTl352y3YQ3qX5ZbGNAryA8cTOgsxUK/sRL44ZLzzrWWonUmk6yIunjIhv1xc05mLo2k
         7BJ9YRL93+iV/R3dfnuQtUb72bkO99ZfXZoDgcEKqRp78OrHbVRxL2I6nzndrI+ATZ1D
         fYdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BJJRnVUl;
       spf=pass (google.com: domain of 3blzvzgykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3bLZVZgYKCWkNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716893294; x=1717498094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U8vFB2wy6dnKCZdT6g/3nWEuzP5ubbDLGHC8QeJJgwU=;
        b=dxTr2aOHVbRPnoXnPcwT7TztDTrfCvWiffYqdgmrfZFPKJ5cyaVl1xhiNt9wAW6jYB
         kkqsav+/4G7n/x7YS/2X8UlVB6yKK3JNYnjuI3Is9sbbl2DTczwJcg/676B0cY7y+spQ
         XYoRSzvuDW6UXocc+NtskVkoJ3dLdNjWCGVXnkKVJvU1SmbbUOUyHzRtpklEifhE+Lqf
         ozE98wWV9EOF5HLfacZNXwxZKEEZqk/1Dnj04wdzCUFRrXmBJlwDKNLpJcaRkyl509bY
         CO5dUwAUG2Yy3mKutr58SGWq8hIl7lOKVy4OoGfHSh2/uHBC4V7Y8nwTnQ/d/l5NYdC2
         cP4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716893294; x=1717498094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=U8vFB2wy6dnKCZdT6g/3nWEuzP5ubbDLGHC8QeJJgwU=;
        b=mcp0W/41JhFdUnj6uuz9EOAVUnUbk6puXp46QPYrgs0ErbAJORtpwpBCAzvaPhrwjX
         S/e3qQ2Uts+1GkNU66kakpsKTamZeID6jMriBJwjokGVbt8FDvu5wiViLNshyScHPBB1
         7tgtoDmz0ske+1aekfzAclLH1hgHa5wYnO+xoRgpjX8erBryh0JHniA3+v0+bUa0bZjb
         xcN8VeXIgmEHtxgWRyYNRbN+on1Q3v2NX/r6ygzArJYIPUGOhIL3+UT+0K0eBOFSRHBm
         9DtvmJwb1UPj+KDb6YfvoYyfxjkr7Kdf9Hu/umIhQX/ZD/Ptsoo1fUBkY9HJ+pERYvpO
         P8QA==
X-Forwarded-Encrypted: i=2; AJvYcCWpCaKDRkGAD4zFS44Pgs5blcd3D/mFyTntOqWXnAs3ESndL4zEbACM4R6wyYcii6fI+PpfOJ77TCVY+2NrMCEt1sQhl2PxRA==
X-Gm-Message-State: AOJu0YxKbaUdNjQYZo/EhdfLHukPHWZmx2lGkpGQNG/PIbQqIbP+g9/Z
	+l/b5Sgwmr0POdKYjHHAeSK6h8hR75D6WfbMCSDLwpcLa0QIRMwJ
X-Google-Smtp-Source: AGHT+IGE/mcSVApOjK+0RO7gooaKfLnxJm9vjVa0KcPdOGDNr5Uy9FHVTlo/a3Suvv/qGPMp2ncttQ==
X-Received: by 2002:a92:cc52:0:b0:373:784c:3708 with SMTP id e9e14a558f8ab-3738a7b0a68mr5267435ab.28.1716893294724;
        Tue, 28 May 2024 03:48:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:168d:b0:374:5c2e:d8a with SMTP id
 e9e14a558f8ab-374647d4384ls3983595ab.1.-pod-prod-04-us; Tue, 28 May 2024
 03:48:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW66Le6/vUpIPVCT7OsUKq73zabza7oWyOeBirCTv+MjuzJWD1dds429esYnjwAUeIwoBa8haHDejBP6ZduWuq4Ky2AJFkBT/Qgdg==
X-Received: by 2002:a05:6e02:2161:b0:36d:bb54:fd6a with SMTP id e9e14a558f8ab-3737b315d45mr126525835ab.18.1716893293881;
        Tue, 28 May 2024 03:48:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716893293; cv=none;
        d=google.com; s=arc-20160816;
        b=atAcBN5fWIFec7XnT8JmkYwHUL/6D09tsI8LXQ/x4PH2L+FjHfqULoJXY0faueAtji
         I2WqTdkNQh4NAvaho579OJPw0AW7hWEUqwfsBtjOJBm3mJn7XKdMc78LLZvXq2eKRm9i
         VRKpZ8zqn0QEQlTBQGnkID3VpJePFuv6EkHXQb/qESQHDfOD9cdUgpP+wRLFjfRFwxLX
         IyQhc5dphDG+lD5xZ2u6uqGaJfRjlU86aw99c6VChqwQBrn7IYnkoHa0Hrl6JKYnRWak
         gzfcrhQqc1GtLcrEhupVTBFz7x22fAH3s9OhWU4f8UbvwHCgeUyAsUmW0VaonwpHLx/k
         S1aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=168aCLfPuYgGXMseZYgeOmJsf4bgrF3NmHxiEDuMCbc=;
        fh=V60VCDewQtCsZAeDB/RvglrBbQrmNowJLh/sm2YZvl4=;
        b=SKYwwCSfG6qmqqstyKFmhqo+Zgz9q1ICZVL1Jm8jChAbHBQcK+MrygcfHrsxaIUKYq
         L6/DYKjl+dKwKlGm3NFvQLzJjTHJ4Ef8VSJQRcP/V81NRJ+vI/s/nAjNos/BvJFfshqX
         5Ea9ejiThtbwk3RVRNxYjoJTLMyJ1939YVw73c0TkhxRkSneAfjOg2z5r73jsLao/9bJ
         gryyZi+WxvIXQZjXBN8zGtJU68/JnQVuJwRVGTkrDcD2VXSYNOZryknRJLq9omnCrbAg
         X3kpggeLqpjHsO6QX///H+fV8HutUnTRgpzOoDChGepeC8J3ULSkStD3sFhRhtwuehs9
         FABw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BJJRnVUl;
       spf=pass (google.com: domain of 3blzvzgykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3bLZVZgYKCWkNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-68217d3ec2esi667136a12.0.2024.05.28.03.48.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 03:48:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3blzvzgykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-62a1e9807c0so7795227b3.0
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 03:48:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXluonmLcIGJ+2jv1IwnjcQtPbwvg2sSyZr2Q+XS9+Kb4pJKk0U4k6BGoII80U1tpczRTsBIz+HBc7RmYwQosTv3v28ssGzCaHkhw==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:6416:417e:596:420a])
 (user=glider job=sendgmr) by 2002:a05:690c:600b:b0:611:5a9d:bb0e with SMTP id
 00721157ae682-62a076284d6mr32629097b3.4.1716893292893; Tue, 28 May 2024
 03:48:12 -0700 (PDT)
Date: Tue, 28 May 2024 12:48:06 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.45.1.288.g0e0cd299f1-goog
Message-ID: <20240528104807.738758-1-glider@google.com>
Subject: [PATCH 1/2] kmsan: do not wipe out origin when doing partial unpoisoning
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	bjohannesmeyer@gmail.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BJJRnVUl;       spf=pass
 (google.com: domain of 3blzvzgykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3bLZVZgYKCWkNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

As noticed by Brian, KMSAN should not be zeroing the origin when
unpoisoning parts of a four-byte uninitialized value, e.g.:

    char a[4];
    kmsan_unpoison_memory(a, 1);

This led to false negatives, as certain poisoned values could receive zero
origins, preventing those values from being reported.

To fix the problem, check that kmsan_internal_set_shadow_origin() writes
zero origins only to slots which have zero shadow.

Reported-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
Link: https://lore.kernel.org/lkml/20240524232804.1984355-1-bjohannesmeyer@gmail.com/T/
Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/core.c | 15 +++++++++++----
 1 file changed, 11 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index cf2d70e9c9a5f..95f859e38c533 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -196,8 +196,7 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 				      u32 origin, bool checked)
 {
 	u64 address = (u64)addr;
-	void *shadow_start;
-	u32 *origin_start;
+	u32 *shadow_start, *origin_start;
 	size_t pad = 0;
 
 	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(addr, size));
@@ -225,8 +224,16 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
 	origin_start =
 		(u32 *)kmsan_get_metadata((void *)address, KMSAN_META_ORIGIN);
 
-	for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++)
-		origin_start[i] = origin;
+	/*
+	 * If the new origin is non-zero, assume that the shadow byte is also non-zero,
+	 * and unconditionally overwrite the old origin slot.
+	 * If the new origin is zero, overwrite the old origin slot iff the
+	 * corresponding shadow slot is zero.
+	 */
+	for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++) {
+		if (origin || !shadow_start[i])
+			origin_start[i] = origin;
+	}
 }
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr)
-- 
2.45.1.288.g0e0cd299f1-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240528104807.738758-1-glider%40google.com.
