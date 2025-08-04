Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBBMPYTCAMGQEDJVSYOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B6DEB1A96D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 21:18:30 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-459dbbf43c0sf5745065e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 12:18:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754335110; cv=pass;
        d=google.com; s=arc-20240605;
        b=NtZa5cco199zAMso82FE940KZ75CWdquLETYjxj+24Hyk3AFo/QlunF+mYyGxHL1Se
         6c1eGVI21y64UXHo0N8YwqY3P9Yaiu6duR1AtLr/SfR07uFRkmL60aEffZYMtpZeZiSF
         pdFBZWa9hr1M14MresoRbm+d/dvYrrUT1BqpsmuWg8S5OePJhGBX3mjf6sXmhouCgcFL
         clh34QM6x9ncXh5s13HcUOUmzRShxsV52s6pqOVl01Ll14VixlPk1rZCjwX/7AufxN0B
         lzWjq8QyI9mDriEkKFvfBqpY2ceeZ3PW2WrotH1sorvj9qPoXaItEcJZXmpfiUi3QY6Z
         0yYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=X2WTS3otSPkVg92pBeOKBdV9s6xmJ4kdgaDWTTiE8vg=;
        fh=l3kMXHBi4WboLm+teE5y2ct56s85SXNES3crYsXuotI=;
        b=b8oEkFrhh5lJOgJH2USfVhXh/xON1o6ScP8mmSEf1PADJxfW8K/GzmrFwBMiuunb9F
         BeIanurjvXzHrhoctsuY/GVejGFHR1OLm3Pgy1gVuII+0+Q8SiR6kGLNagOgQ8JgH3OZ
         xhXSHjQwGgi1BFT5E6m7ibskmD9FMoStGik65ANYfNPy33QkZexUO+nThVz6GihOB9cc
         tEepJ6YBL54BkCjJkMqIg1xaDAJM33P+wmX/7aLZW/69rsl57t8WhWaUNdWY4PGtaDJi
         I8W/iWd6dzL8qXtK/TDVL8M3Z7uIuFFpGcEpOxAg610kFZwuRSFPZ4U8OQFbxJFGTmkJ
         zG1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PNwZ8KNS;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754335110; x=1754939910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X2WTS3otSPkVg92pBeOKBdV9s6xmJ4kdgaDWTTiE8vg=;
        b=LBZ48gn9u9e3P9GlBmnvyJ/g3QmnvwxSG7EKEpvBV0g0gYq1xbcau/VEX3z7/QkODO
         dH8pryjwvm3v0sDNY/OfMjTSthCc7/51gjXKwnC3wgUMEOJBbY+9AD8+pvmGk+R8lZrZ
         0tZoBK8POEW7BMPTZSmUv6RUeuhsh7a0Dtt+CnBwuXIsVxIyCo5AW/OlM5bWZxm+GPot
         MMrDanqmENlpzff7aJk19KkMvT8BJGCmK/SYv+g30uOUvnnjIMhmzwB655o3HLRXb3/o
         09S5vE9UaOA2P4Ms29CIdyP/4dULoky/RJTykvMor7QtFeLAvZuwPTV5pqVuEmIIiceh
         tyuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754335110; x=1754939910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X2WTS3otSPkVg92pBeOKBdV9s6xmJ4kdgaDWTTiE8vg=;
        b=Jm3Gs1IKySvocVaiKwgkQg/QcGabi+3etGFxkT5wnB+Zx7wAEoM1lFYyTyiQWjZyqD
         j/jh/NayfM6VOqhyEXAJplEPS4Kvq5jWiVMkRmZfDdNSyu42cA1+zrc6OvuHfvfCQ/Nm
         m9ohOrTY3GJlfnZBDqxwN2YJES5QINC1sl1aMRqZjyv8B/DPtCj6bMuwDlcryhxl7Mo4
         jUb3s+GQriLleFg89qnRlmI2QWhoAGVbIlAbeamMkrx73n6Q1lWA9HCcKnRuXhA4c4QY
         0sETBiW5IyIOrqhwZDgH0qyMfIi+nogqdWccaU7NWFPvVNijo4jvxY6mMMNainbnalk8
         tv9A==
X-Forwarded-Encrypted: i=2; AJvYcCVx7LXygeynNVXDZiYETiVQPanEfMU1JVEkK8EsCvBqC84kr2MwHWznbiVahN7SrFprZW4emw==@lfdr.de
X-Gm-Message-State: AOJu0YwiJfTqnF9Sb9hrfOkRF/l+d1PT6ZrbTYylvTCQObF8HQ63mB6y
	TtGMb9+ajNZ5M+pQI1D91SJtHyjnQf+ZlzTPj6pdYSF/7cWQ4Q9CzqHz
X-Google-Smtp-Source: AGHT+IFhGunCgPRavehREGA+qO3rjULnMUCo+V5CkP2JJ/HD2iTXVzP99kNJO6pM3DH4T/2R33xmKg==
X-Received: by 2002:a05:600c:6748:b0:456:1d06:f37d with SMTP id 5b1f17b1804b1-459e0d12436mr6355635e9.16.1754335109701;
        Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKVPuJikBgLjeaxmnYNDg4VM1np7prtDEV2551EN9VnA==
Received: by 2002:adf:a38b:0:b0:3b7:8b53:4ee0 with SMTP id ffacd0b85a97d-3b7951e3185ls1144129f8f.2.-pod-prod-00-eu-canary;
 Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXujKModMKS1jjmXOXIgOlUjuq8gIaJJO6CYsFxrKLxN4GO2c5mKfykijMJ2njvYAly3eti4ucmRuQ=@googlegroups.com
X-Received: by 2002:a05:6000:18aa:b0:3b7:931d:37a0 with SMTP id ffacd0b85a97d-3b8ebca4df1mr487455f8f.9.1754335107120;
        Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754335107; cv=none;
        d=google.com; s=arc-20240605;
        b=D+m15G/4SWdb1QDvr38mMXq3uXdhvWojJZxxjjJb3/qFwWnnBfg5KFhsBAOB/QJDS/
         7tw4/gz31orA07VAfGUdeVDj812DG6nu8eqzLm3RKopgstDwYmEjleboNBJ3+gcnAlIn
         3mDPagRqgTg3bo2HsD1+4crr/7m7R3HTinl4BMFW9iSt70gRNejrp5bf7ZIpRAoxFAVe
         0YR5XG/K1EyqapI5kKCzwBQnOLQJ7SCtZUEMxoi6Lg07vRIPITtoFue5AU+ivxO0MkKH
         3SduJcvmuqJNx6l2Ja0mDThiTNX1eI/P/xZ3nQx2eArnPgpx8SXjnS6/x3/13lTY22oB
         w+FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=UiTfAb9cnMOM27iD69XKZ3u4igfynQ6rP5nLGl75Z/s=;
        fh=MRL/neQ293dG3u5uygjN++e55wGjOGqW+fKhGqF3tss=;
        b=MXFX92MJ1IRJQj7ICuq0kCRbQ1ShFQhXW6Vx+/ABLhMTMtuZQZWf7SXV4/hwoLD+4h
         yQT+ICJUukIFYDjQIzMQUNR7jmESQYKdZ+AJg7rEsCKiV0TCiXkCP4e0k5X+BSgVgNQ/
         B4oApD17b0nUwUYpAEKl1RCfBkej5q24PdQJZnRVjyZW0mLp79idbOmSxWtrkdVCr6z9
         ISdVRr7yvE519bTNOSfcK9rMZvW4/A+YjsDfE8bg8XPA45TsNtlO1LRbRBOJJW7P6tiQ
         2fb0X3aHqZDHNm7lFnHBMbsNvSPm/Rs3xsqA/F5AYQ9kKXiPzMVrS4oLjkzAYVPW32di
         m/xA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PNwZ8KNS;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c3ac122si133021f8f.2.2025.08.04.12.18.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-458bf57a4e7so155e9.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX8hqmWpfWCdtKodyQ41mE4acuYezQZsGVyF8XrvDokxo1VHClRBeyEEunIq5GjNXIGaTUuT+YudWM=@googlegroups.com
X-Gm-Gg: ASbGnctoC6ZsNoxFYmxZEZql2cyTZicbJx6bzsolwfD0BnydN35S8u4gFcquSLJt3hI
	bqQu5mjJTuGtjroIWK2Q+e11WHSD2Z2TNchb3XRvEVeZBeG7rCWzKrljpzY6TPm9rrtourwTW/D
	JHXqlt8yxrNq/nU/2Tv0Lb3RgCmqgJodA5vZddapdccKZbdi+d/dnGsukizEv4wiBHhfF991ISI
	MGGcCv86myzfsWjiw4tuiKJyUoeMXwNuT10sJwbgdJ0HEEAWth3kkMJdQA8uyrPsCkZQaKPeP1T
	gPE0iONrENGcYRASYK8/xtQgKLaNwXeUF2KFI3cDE3Q3p2s0VQvgKYwms7IurS4TeIA1zG5kr+l
	mqzeASar1Qg==
X-Received: by 2002:a05:600c:444e:b0:442:feea:622d with SMTP id 5b1f17b1804b1-459e14ef635mr140015e9.1.1754335106255;
        Mon, 04 Aug 2025 12:18:26 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:2069:2f99:1a0c:3fdd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3b79c3b9386sm16502103f8f.18.2025.08.04.12.18.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 12:18:25 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 04 Aug 2025 21:17:05 +0200
Subject: [PATCH early RFC 1/4] kbuild: kasan,kcsan: refactor out enablement
 check
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250804-kasan-via-kcsan-v1-1-823a6d5b5f84@google.com>
References: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
In-Reply-To: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
To: Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>, 
 Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1754335100; l=2094;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=OF7LyNhIL1EOuOn5pfi758khliHdObXKjDRY6+iPVTk=;
 b=Nj7lWb06h7SXCifoXeKMs0DUlOqOdP4H8VnS8Otq1aKjtHh/Kl7wkBiRiTwimSc9Mb/vQL3wz
 G/GTNIUIiYQAgciu1KMGaY+kSTClICVFU5L25WqzmjcvA+7+WE4fbAH
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PNwZ8KNS;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

In preparation for making the logic for enabling KASAN/KCSAN compiler
instrumentation more complicated, refactor the existing logic to be more
readable and (for KASAN) less repetitive.

Signed-off-by: Jann Horn <jannh@google.com>
---
 scripts/Makefile.lib | 16 +++++++---------
 1 file changed, 7 insertions(+), 9 deletions(-)

diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 1d581ba5df66..017c9801b6bb 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -52,14 +52,12 @@ endif
 # Enable address sanitizer flags for kernel except some files or directories
 # we don't want to check (depends on variables KASAN_SANITIZE_obj.o, KASAN_SANITIZE)
 #
+is-kasan-compatible = $(patsubst n%,, \
+	$(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-kernel-object))
 ifeq ($(CONFIG_KASAN),y)
 ifneq ($(CONFIG_KASAN_HW_TAGS),y)
-_c_flags += $(if $(patsubst n%,, \
-		$(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-kernel-object)), \
-		$(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
-_rust_flags += $(if $(patsubst n%,, \
-		$(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-kernel-object)), \
-		$(RUSTFLAGS_KASAN))
+_c_flags += $(if $(is-kasan-compatible), $(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
+_rust_flags += $(if $(is-kasan-compatible), $(RUSTFLAGS_KASAN))
 endif
 endif
 
@@ -94,10 +92,10 @@ endif
 # Enable KCSAN flags except some files or directories we don't want to check
 # (depends on variables KCSAN_SANITIZE_obj.o, KCSAN_SANITIZE)
 #
+is-kcsan-compatible = $(patsubst n%,, \
+	$(KCSAN_SANITIZE_$(target-stem).o)$(KCSAN_SANITIZE)$(is-kernel-object))
 ifeq ($(CONFIG_KCSAN),y)
-_c_flags += $(if $(patsubst n%,, \
-	$(KCSAN_SANITIZE_$(target-stem).o)$(KCSAN_SANITIZE)$(is-kernel-object)), \
-	$(CFLAGS_KCSAN))
+_c_flags += $(if $(is-kcsan-compatible), $(CFLAGS_KCSAN))
 # Some uninstrumented files provide implied barriers required to avoid false
 # positives: set KCSAN_INSTRUMENT_BARRIERS for barrier instrumentation only.
 _c_flags += $(if $(patsubst n%,, \

-- 
2.50.1.565.gc32cd1483b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250804-kasan-via-kcsan-v1-1-823a6d5b5f84%40google.com.
