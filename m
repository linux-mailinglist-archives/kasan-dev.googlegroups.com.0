Return-Path: <kasan-dev+bncBCMIFTP47IJBB64N3S4AMGQEMVU4Y7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE7D49A95CA
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:24 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a3e1ef9102sf52563915ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562363; cv=pass;
        d=google.com; s=arc-20240605;
        b=QOn70tmMuGrDUUa2zbAaOdUTCLR5rujCsYO3rfivTT02rdjd7fvb4t2CJbicDLm8BE
         LnF1M3QtC/4aV2f/znEYCQ1KEtix0tHkYxVLUtVN8n1qGtuACaqz2Z0yhP+D+vfDRvi6
         tEahJTdNLhjx88NnKsuGAjTnUGZ/V9HHvTKdVFs2Nkpx6vc70ohe21UaAmW2LspELiFe
         bRCXRRd3N8C4lNshwaRE9y7BwRF2Zqbic2AFTtbB0gCRnDf+sHPO1gqVJGqlmLkGDpSL
         UTZnVUVyx+wpZKkn+QhqefiaYZMWJiaQU0fQ083MnN2P7eXhAtWFLDyG7gpwlyuTIs3h
         0Yug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=T5X2IM/rBFlEVbnT7IfSWEQswAABG6q+a5gNrSrB6PY=;
        fh=lzVGR8sKuMNy9F3lqhG5a53/3FDY1BHByZRYpX60iDU=;
        b=cXpHGEoT+fwj58HZ7OgOLTtlgF6gP60IEzVO5kprp6Gn/emkw43pOmS4Jkyc51LQTr
         PmVbBN3ykxx/XsS+T9Ttidbm8NqyuD05WnZjLfiN5oH8tbYHmoTrPbbqGtb8IyHkXQpt
         ZAQyd8WCfik4MLiiFxg4M3dzra9+g6ZcaU3SJ4iaPpKmZtzDEIDveD0z9tIeWpTI7IRy
         Bx9kNnb7Po5vO44mOYCSnA6URMxSBBIbD08hfkJaArOndjGyo/sNkUvSRlOn4c1biDtE
         UVHOGBQUxqc2S/Ri3uvJ56LIJ8zzil6VcDDElkAK+KRLeqeZmzXb49eCBtAs+HNy2yrM
         3P9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=hsbPieU+;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562363; x=1730167163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T5X2IM/rBFlEVbnT7IfSWEQswAABG6q+a5gNrSrB6PY=;
        b=AfJqzxyhnDrncJTTqxUCbHggxmnOe7W0eTwy5Es2KD1XRDKoIATM9WQ2ZCaS1zO/G2
         xOim4n/mZiAbWPFtzctzG5kUZ73HrpsRYhSjSOokEkmglApabOIgktxchZMXeKJJqD0j
         tMN0GX3dYk+FtihaeR//r7JTmYT0Vh1JMaKhbWAHRFkx57GWZvKsifxZLVuWFmrTCava
         fdnx29QA1+fAFSvXN7wAagb8J2meSenH9b3r9hiiXNT68/Cr0rqG0XNatsQFngX8T+vR
         8gn9xaExP7nQJix3mxJWOkraHECS2NGWubd39TqZ8iA94GW55o2JChAyNcuKK8SjP0a2
         VBgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562363; x=1730167163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T5X2IM/rBFlEVbnT7IfSWEQswAABG6q+a5gNrSrB6PY=;
        b=tf5OQ/nn4AS+OesTyK6iZQFr+H7yEc7WNzpB0/CiCQe+8+OGEnC6LwmqdibpPMsnY2
         gGjv9zI/ywrU/c9YrCdg+X8Ws+zVNCsv488n3FIi/g0hW/vr9X8/Ffa82/+5YIj6Y279
         pJhktl/cMKPhujsY2dyy+E+WNWCAvrsF38MqVooaxUCukvsIP8jo0kxAnjO61OXtlZB2
         v/fRaxYs3R4DRiVvz6lhxFcZSz4cD6wiEz3aUAUOkKzVJAqHYWQSStuuRZQ5YJqQoz4+
         /YqUbvO6/Eudy3kMjSF2Y85QvxIzlcyRLDiGrxOAJiZ9SWibYZclSdEsInwVlNl7vhVg
         SwvA==
X-Forwarded-Encrypted: i=2; AJvYcCXONmT4S0kyAz9KBG7r0WZn1480nsZ/3YHP/xcy2GqEVKC0cy/LOp5pqH2llm94jKgxJBdAtA==@lfdr.de
X-Gm-Message-State: AOJu0YxEVyEtXth9/GITbFxGgQUPlv7c8VSvPnHu4OJhKl1xk+3kix8X
	lECTM9aHVAfcMIF2+aRbOPginBLDClwU3HStFuasjePMc9OeZP2c
X-Google-Smtp-Source: AGHT+IEIg/Fm9aK/3C1IeU2s6jSMbAKmdIltb+yC7N/tw4eYQCNBBHi8A7CquYGWH2+rb/95fCwQDw==
X-Received: by 2002:a05:6e02:1aa4:b0:3a0:90d6:1f39 with SMTP id e9e14a558f8ab-3a4cd663348mr7474435ab.2.1729562363234;
        Mon, 21 Oct 2024 18:59:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1485:b0:3a1:96f6:f0f2 with SMTP id
 e9e14a558f8ab-3a3e4ae3683ls1272535ab.1.-pod-prod-02-us; Mon, 21 Oct 2024
 18:59:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGk5XUpDJ9EooQ09MuPQcGno3cjkF24O9kqK9N7f7E7Oj06f+zoM7BoTs/iLx7dWrEEmzwjDvZaNM=@googlegroups.com
X-Received: by 2002:a05:6602:6d0c:b0:82c:ed57:ebd9 with SMTP id ca18e2360f4ac-83aea9773afmr120734939f.10.1729562362450;
        Mon, 21 Oct 2024 18:59:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562362; cv=none;
        d=google.com; s=arc-20240605;
        b=IM1PnOC2cabkdWTVfy6+t8HcQBuk7EvnMUmxlbqld04zyXnTVBaOyP6FHp5CYBO8L8
         8LH+uEw2TeinC6qvdYI5AeigX3wtMSVfEKiuRBqllPEX/VlblXYEUmVa9g691My/HiSe
         zIZnoaK1WZCqTTb5EYDVZciB++cSf5Fm64BbBAEcZ6SxDf1/wC3pi+rKmejSOJ8lRSoT
         WiTFnE2+0MsrtUl0wE9GoNo+7pD9GDvf6OLkhc4lle65PLD2c7EVP/k1TFHxRLr+X8ic
         P4aBglp2/Tbu1PI7qILwv3O1dV6cMYNRU22CJBJNg9wekEgAgArRuLMO/x+MwXquGP6C
         wa6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9FnCjcC1/gsDOd6L8rx/6dcUkVYp18eK0+PNRkpMvb8=;
        fh=8uXAaPhexTGeqPkX1fl3wzGLBk28MuC+1bfAB+xX9uE=;
        b=cYTgvx9SQFtAWDGj+j5XQTvu0qvXwjS4NxbkDd53WOY83+ZNkkJ4vrwiFexzRYb1Ny
         /42QxHxdJ1dPI8OFwgkjjrDqLzpaFgV0hZxggX+m+syidA6mveftdoDboPhT5ZladCML
         bZIVzK3nabZ7Pw7pyMe1sIBZD7auDnID5jsqhWjVjwmFrFo8/DiNvllgcdnBxUbxSEqI
         L3Esm6YLT/qqTej0YCdXKRz4dR+Y8bYD+l7QK5Sjcgm4cNIbOqhqI5qHpBCLVUmiW2bo
         So64TUiQHRZpJPlNmXjEUcO6PfEBXgXM6cKJCbVU2llbgGGjnAbBe1tyZoyfXnH6hbLd
         3GmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=hsbPieU+;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dc2a2f6605si168818173.0.2024.10.21.18.59.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-71e8235f0b6so3938472b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmE7+hLQH93pR2NDO1id3Wsd0odyWm0mW1BCgskA+TeKc6hnWAvMnfSNyZq9oOPTdsyrEpVmUgZ9w=@googlegroups.com
X-Received: by 2002:a05:6a20:43a4:b0:1cc:9f25:54d4 with SMTP id adf61e73a8af0-1d96df0ed05mr1060384637.38.1729562361689;
        Mon, 21 Oct 2024 18:59:21 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:21 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 3/9] kasan: sw_tags: Support outline stack tag generation
Date: Mon, 21 Oct 2024 18:57:11 -0700
Message-ID: <20241022015913.3524425-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=hsbPieU+;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

This allows stack tagging to be disabled at runtime by tagging all
stack objects with the match-all tag. This is necessary on RISC-V,
where a kernel with KASAN_SW_TAGS enabled is expected to boot on
hardware without pointer masking support.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Split the generic and RISC-V parts of stack tag generation control
   to avoid breaking bisectability

 mm/kasan/kasan.h   | 2 ++
 mm/kasan/sw_tags.c | 9 +++++++++
 2 files changed, 11 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index f438a6cdc964..72da5ddcceaa 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -636,6 +636,8 @@ void *__asan_memset(void *addr, int c, ssize_t len);
 void *__asan_memmove(void *dest, const void *src, ssize_t len);
 void *__asan_memcpy(void *dest, const void *src, ssize_t len);
 
+u8 __hwasan_generate_tag(void);
+
 void __hwasan_load1_noabort(void *);
 void __hwasan_store1_noabort(void *);
 void __hwasan_load2_noabort(void *);
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 220b5d4c6876..32435d33583a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -70,6 +70,15 @@ u8 kasan_random_tag(void)
 	return (u8)(state % (KASAN_TAG_MAX + 1));
 }
 
+u8 __hwasan_generate_tag(void)
+{
+	if (!kasan_enabled())
+		return KASAN_TAG_KERNEL;
+
+	return kasan_random_tag();
+}
+EXPORT_SYMBOL(__hwasan_generate_tag);
+
 bool kasan_check_range(const void *addr, size_t size, bool write,
 			unsigned long ret_ip)
 {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-4-samuel.holland%40sifive.com.
