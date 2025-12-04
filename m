Return-Path: <kasan-dev+bncBDP53XW3ZQCBBANOY3EQMGQEBW4RURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id F22A7CA3F64
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:22 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-6430d2da172sf57691a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857602; cv=pass;
        d=google.com; s=arc-20240605;
        b=jtnR9DxXgIpx8eFVJNeXu4iCwD8ZB6X/UBuPNPX03Hzo4PkYwPSR2r5uyDVHxdjKww
         ce8Wtec1oxTYVs3DN+XZ06u51bVGdcnz8fmgvBOFRRasLXhbKReyS0tN2dapjSbKpEcL
         98zMeW1B8Pq/m6eEt9jxVa3+PmWK8hjbSa+CsEbC2Q2ALLlHPDPRarBWdwiGjBqrdMqk
         oEZEG21ns1XhgjGufUbYz9z8dmGM6iyUDbqyhtIbRr5/DzAP2qfu/MfU1zUMCFSpsc37
         KlkPZQNZPLKIGqxLdT9fUILTZpNg7oi/rqVm/MnNz+bmfZVaZg3fMEOtNvXYE8Oj+gxb
         oKrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=YfnKsgHFNVHL97HWwhffBuzw6C+/sw451o4d5S+bV3Q=;
        fh=TA5diJoteVBxDKIYRB1yRpZ0UuJjGVg1mxHoKVYOzHk=;
        b=LZLlHUVjwZe6usXs3Q6s4MpTDK2t+D1eJzDOIzKS/Whzml4FPoEyX33aOM3SBOFETM
         v1BlBkkR94STeJZPrsojxA8fDCNjqpmEhX0dpMMBr0GjYFzh6vsy+GMoA6Xf3rMFuSxP
         oiQ2NuBVpB1Z058yTGnyvhl1p+2VE5gjwu9IDBtAyrteDwWk1Cvik0JDep5CkrmahGpi
         2cvGB2GBI9lofDmpqqdS6gIYoeMz0Cbyd7lafvzZSm+bc1IY99oh7W9LCBe/x0cCqnhe
         MHBoDMPc++rsoTkWzRhvxNjvpexTjbMg/9f+YkiY7V7ekIm7L+JWqND412CNSO8A1dty
         dPlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Fu+2/7nI";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857602; x=1765462402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YfnKsgHFNVHL97HWwhffBuzw6C+/sw451o4d5S+bV3Q=;
        b=whLTLwkIoWpW/NWlX88RXLCU6j7LL5QjcHr9P0fYVqjMfzrQzv7LkDI7UeBDhf/oed
         /GqVkQPsnrH07B2JkDlhbe3uz/TcbxEIJ900lDnYVhqvwCn7iRn6SNoU1xFUcGBbiPdH
         e7ulkm5acO9/2sTII3Xdc62lJWOUg+ZbwpD3ukgxlLFYIfXl+0/uaB/3jtwCyC9IxjbH
         62GC2QlXjgAuwHCnfcyuWuz/NYBeDhX4EArvy1HR5+v8DPdZFjB9pOJMgr0TBiMEci0+
         9DzIqbK0btkuY4zacDIdShCs31D81IuHufZK8ZaeHI02r1YauuHOx+XPZymS+A6C0nbX
         nHeg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857602; x=1765462402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=YfnKsgHFNVHL97HWwhffBuzw6C+/sw451o4d5S+bV3Q=;
        b=BvosOdoCor1uEdQcJEKk0MvXlmgb+lLjX3S8WUTR4OBnfn0BGPHOJLdtY7CUARP/Gq
         GAiJnU978sDhgPMolArCrXNRWzoYuQQ1DOa3Zrssdd5J1ZKgd2hrk8sry7ObbK4SB1p0
         UILh5eBtvVuMGRRx2Ai4DnefWZcXhTRBtdeBlU6CkUJmsistB7v4DObRIZQVHq3J2DV7
         vBEe0UNmx1giPJK1I+5x8dr/rQ+BK1r6ZVXf/Uu7SgVGbhF7GiekNHK+qwcAyKptnmlU
         i9mj4iQA9BvkbUXgUkOt69aGofc4DA0ZEvXmIf0BPQIsHm52dR0W4L/G0cbc8R/UoPRc
         uReg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857602; x=1765462402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YfnKsgHFNVHL97HWwhffBuzw6C+/sw451o4d5S+bV3Q=;
        b=bsPd31H1Gq5dq9ANHHJyFgF9dyLxJpdlX3IbD6veJX2UQfUFD5cnQARr0UMXW35MqT
         V4Z1VfxtRQgf3JhNOMguZj46r+SFFiVfqmtJ0a2BROCtfIYTHXuN5JEWhqrDsmO0GGEr
         M/R0lmu0oPI1lpFHJJj4S4yrb/XRpwTJv0HbkO6AFLrX3XJgQABVEe/oI0r2B7d+zt3g
         c03C36L7WduglC3uXc6DiPsx/qBnvAfpHKSUJRaljihm8io203x7Huksxd2pHqTs1YuZ
         Yfvh8VprUXfFRxtFTKzWQKPMRRoZUHWKW2SAWbfYP2PqnxX8rVLTRWW/apNGO+Jlsj7u
         fYUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW30HG0V6IwcAGOQtqK8AyNhlu1XXahC535Du+OWbIlHfQQCPVrwLDK25BZQoUHaLQuThLVlw==@lfdr.de
X-Gm-Message-State: AOJu0YyBO1rx3bs4PRyosN1RC1CHjTQ28ScjgikNZlN3740CF5s+spgu
	oOQlCh0hQlgONyBYuknJivbGedwtBTOgcDfJJAUxG7xEWQ24wHtKiBsQ
X-Google-Smtp-Source: AGHT+IHIlcAKrw/eRRPPmBk1uRRigtPD6CTLUjN8IwhiNpgf41PVdmlLOYnyix+Sioe5nOZfF4iDAw==
X-Received: by 2002:a05:6402:430d:b0:645:5b52:2b04 with SMTP id 4fb4d7f45d1cf-647a0074480mr2710347a12.6.1764857602283;
        Thu, 04 Dec 2025 06:13:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bu0oOrOWnAXD7JySlxd2sFPrbMrwlQhtfnrAoS+sgtgg=="
Received: by 2002:a05:6402:f15:b0:640:cdaf:4226 with SMTP id
 4fb4d7f45d1cf-647ad5b16eals696739a12.1.-pod-prod-09-eu; Thu, 04 Dec 2025
 06:13:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXsQVQtdglffCXj0uobS9xGzL/dLph95/rIPzLrjprF5Un1OO9+xDxu1u6NL6FC82P6BOgO4uRAc2w=@googlegroups.com
X-Received: by 2002:a05:6402:5213:b0:640:ef6e:e069 with SMTP id 4fb4d7f45d1cf-647abd896d4mr2552166a12.1.1764857599242;
        Thu, 04 Dec 2025 06:13:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857599; cv=none;
        d=google.com; s=arc-20240605;
        b=Fyc1ffKHwN1apitf6+ji84U7eao05N5LQchaMYPc3AhM/CqTggURQjC8RP0OmscI2j
         BHopRGMdf7cA9osHDjiyKet53kamPYsmFqnbh4K9jvOF7jqgm/H0+DJNap+1mY21ueJO
         JBCE3QovrA62ONTJztBf5xvzfWak8aXLhbfA5PHX9f2ttiOluXVunZ9Rm79BMg+75sje
         9QJWUSrURgV2Y4wu753jIeWp+hoaXItMpv4F9JN9zEM7CFsjFf/r1WTrg7wPhyl11Zql
         i2qdtlTpcgR1Xyhk1IGyyrMETfyzDEVigUYaNzW4L7ZJGAjyFZmooCSR68M9tRAr9vaY
         k4FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sGnt8bTKaac1K6msaRLVltkt9xGbtE5aMKqhuya716s=;
        fh=DJaqOzPtEgAmMksiOeFTxjmXVHObVes2gBFr+4NJLqU=;
        b=epZliclgLyofg34YxgRKPCBZNdZbU1LFC7UqNFPNks/n2M/Yy/GgBZCc5Bb+OGOxH7
         Wm0+DHdLaIsQcq0L2jRcc+kCi0quT44SM8MMLDVO7BJ1om93NuEOyLSeb7GcRpEvoujw
         BvKBdVwfA8JWiS514VWFZhqRfI8kNMUxQCg9nmJ+AH/lVABNwQHypyZo/0H2c14hn+Ky
         ZZpBOTvwRwQELZqAM3haSwnyvAPYQSkRYDoTb5Q7t/BbbPQRx/YT0AYOfp62rylipmsd
         ozmuaSfxQx4n8Ge2qcyZkV5ccCZYCtiqpVATN+Ygomr+In9jFZ9oZCKyr9A76guMf1N8
         Ue/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Fu+2/7nI";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b2ed8b0csi37357a12.3.2025.12.04.06.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:19 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-42e2e77f519so786485f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWMpbNRtVXezV/M6iv8YyZGFUqGLY6sMv1pNhGcmQexIJG4aR1bAV+USZ+qzclqFqfH8f2BX8yYSxk=@googlegroups.com
X-Gm-Gg: ASbGncuKPP7TTqq40UaddG4Sf+SuqDTRiwMVXBjdWbv84oPszB6mmqsbfNDMr8TQyD/
	/bk0sZEZNbHZa0xijKqMM7jcsYApHwiNmEwIueuO3G2hL0a48C8+Y3I2kCU4Tn8+67V/8nCnbIg
	O5lex59wZSpLA0wpp2hgBg51Dps3rEEj4iTlqVHkNlso9hEAzHaer7NkBJa6Ysqqpzo8ha1page
	NzHHKVte7N03qgRS2GR4iyRI2gyKrfRLpAz0QDkEPQrOLZ3tXEf/ZGgRde/9NYdIn5MXMzhYbNU
	srDwZABTnSozRCjV9FOrg4RkEC09QPic6ApFX25jyWyMRE4KVgoGE+NDlxmvjNbNwq4cULTnrWy
	vQ+OanX+8iPprG8gzU6rvU1YVfMK/V8OWp/i1GFSMLqixfwyaOGBXaJfyBwjnf5/zEaENQJpbFS
	uFpzukJypqwpxDKu5kXqLF93FwsPp17z10RbGbU3wzeY9oHDRtte2iKRWh2i/se6R6Mw==
X-Received: by 2002:a05:6000:2510:b0:42b:3a1b:f71a with SMTP id ffacd0b85a97d-42f79800f02mr3172811f8f.23.1764857598697;
        Thu, 04 Dec 2025 06:13:18 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:18 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com,
	Ethan Graham <ethangraham@google.com>
Subject: [PATCH 10/10] MAINTAINERS: add maintainer information for KFuzzTest
Date: Thu,  4 Dec 2025 15:12:49 +0100
Message-ID: <20251204141250.21114-11-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Fu+2/7nI";       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Add myself as maintainer and Alexander Potapenko as reviewer for
KFuzzTest.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
PR v3:
- Update MAINTAINERS to reflect the correct location of kfuzztest-bridge
  under tools/testing as pointed out by SeongJae Park.
---
---
 MAINTAINERS | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 6dcfbd11efef..3ad357477f92 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13641,6 +13641,14 @@ F:	include/linux/kfifo.h
 F:	lib/kfifo.c
 F:	samples/kfifo/
 
+KFUZZTEST
+M:  Ethan Graham <ethan.w.s.graham@gmail.com>
+R:  Alexander Potapenko <glider@google.com>
+F:  include/linux/kfuzztest.h
+F:  lib/kfuzztest/
+F:  Documentation/dev-tools/kfuzztest.rst
+F:  tools/testing/kfuzztest-bridge/
+
 KGDB / KDB /debug_core
 M:	Jason Wessel <jason.wessel@windriver.com>
 M:	Daniel Thompson <danielt@kernel.org>
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-11-ethan.w.s.graham%40gmail.com.
