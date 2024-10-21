Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYEE3G4AMGQELXRL5YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC3C49A6767
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 14:00:34 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-5c947d9afc9sf2705171a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 05:00:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729512034; cv=pass;
        d=google.com; s=arc-20240605;
        b=VLYUyTbsUwHRWfIkz8YrHJnIHelVWRDuOsvmAvA0bxNOuppQ4Bt2K7rAo7UmiZVjN9
         rdw5kzrHu3yLb4wCtlQ5NWNXyA1PkD+1Y8PHg6e3h5MSfOqK8aTKQnSZvzuJflbELf2Z
         8z+FzXp0xABNzekX67pocAM0Jxf2ElX+/4m3gJyulF10crBo5ywXl0xD8gkqv9DZzLxv
         gVa+lK2tk3NON7qDHsCO1faybbkRvomNwXQCk+EsoDcVO+apVLx8nuFpE1cWsu9qSjNY
         20wWKa8+EKdcqvj7rvAPoA6Tg0MMnGge8MczFOQm6qF68jnk9bxboattbyr+o3gM1nfk
         GO9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=/PJ1gKNlBRXu0XtoyX0pMpZJaPj13jHwI3j0XEbS5FI=;
        fh=+368T+X9w7ekRHjtOBW/buNFgLO+bBA7pSCAZlKOsFc=;
        b=OPt/ImHzz/EbheOUuNN8Fih+hC4/HcXOLGuX4VtqTWBHrRJOhe+ABq1KRmQuzmiBt1
         zdXzD48lovsJbHZdZuz9oZ2RfNINdbOWtkvqiOXEAwuG10RpOVYVC7DhAUghvSZ2ZAgS
         B63y6uXHVuRofhpMYy4xeL22aj4SxlVImVNbPwg4gwpdcNV8SeoSySyeikOjZAiHB0NU
         PRJRR0PQDLdffsXNYhBJOwoM9zNGlGI8ksyI5mKPMR52quhE2E6bmQDCs7ibf/pqRiWm
         iFywSMpEVK8knHtdVEocyGHHrF/n7ySvC1RRsEmqlNWYnoZp6qNHkv8oIo9fqqqHy+SA
         Nqhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=agxGEn3A;
       spf=pass (google.com: domain of 3xuiwzwukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3XUIWZwUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729512034; x=1730116834; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/PJ1gKNlBRXu0XtoyX0pMpZJaPj13jHwI3j0XEbS5FI=;
        b=U2nlGR8gYoNe2Var+JJ8dXFa9CC50c1ckMXg+zOpk0JgZ5U5ogAKenm4hCPQOOHfCd
         WQ90ygyw7kQQqLMkm5hlIjZD6y9thQhKZSPa6T+t36qB5Xut015r3a9e+x6KZCldNYj0
         Vk58zlfmoXGitFc/+CPagm/5ufzUSpRCh0CrrdO0qXEKUyLj8s7y0ORq1zLbTqKN8ckd
         FV//NVpip87+8m3bC9kUXNhgqMIXnBkNa9BE2v+k/Z1mqm3riom2apHdLmgmDthnQZEW
         M49ENTYPHYgg2ME2SQsJ+xbVasGwzL2R/yp2hSIF3vpNHcwl68WTRiNU11265bHq9yrX
         9Ftg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729512034; x=1730116834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/PJ1gKNlBRXu0XtoyX0pMpZJaPj13jHwI3j0XEbS5FI=;
        b=sheL3YuCUGyYwNxAZTJWwZD/GfdCQzx7Ft5nPjQDO/vJpwxgGIiIoEVcDdU4oiAkRS
         P4HfcTxMelIUUybNHsn06TV0woVfJaMRnVSxstIkjl2swNiE2T8zw2ULpgVufo2FymvK
         dk0f35PKMpoguq6V7MEoqbpFV2ZE/lIiACmphVfdFGTKyu6NbfWXsxCqi7JDVv4CK8xF
         LxghBbsbFQapGBauWNYNVZnhFvnHsdVh9CR07sbwdE1ZwetVv2NliwqD4Cd5iCc3d7V8
         vdqg8XFeD3aH5nLPNaoynUSmjwNsGh9X4jZxOkom+TyEP7mMM91CniqUVsXuZXRWOpkc
         GhqA==
X-Forwarded-Encrypted: i=2; AJvYcCWRKK5jisSz+3HvoIXvRmqo7qvlFVqtKXh747m8od6//um2meNH1Ed424vUwlxlXVv0lIkbKA==@lfdr.de
X-Gm-Message-State: AOJu0YwfM5qF712bhYdWUPM18HaEgFV5syIqeiD/qwl4rKvuJ41vzIrx
	Nl4pliizogNrU7XG4ysFgZKYtcnO7L22fzWbJTfhsHLhw9pEr4Fm
X-Google-Smtp-Source: AGHT+IGfxFpmp8A1VP0DSoYm0rcpHgZa4eW0dvYpClDhYOYY71ZGltNPDfXOpBF0qWq6tNxeZ683YA==
X-Received: by 2002:a05:6402:847:b0:5c9:83bd:211d with SMTP id 4fb4d7f45d1cf-5ca0afad4aamr12063434a12.35.1729512033161;
        Mon, 21 Oct 2024 05:00:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2692:b0:5c6:a1fa:16f with SMTP id
 4fb4d7f45d1cf-5c9a5a2b5dals65065a12.1.-pod-prod-03-eu; Mon, 21 Oct 2024
 05:00:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/96pf1Iu58EWwqMBeBH/KuslE1IvYBCelRXtWYIT6U5KuX1Eb9J4pGSUBDig1sCXGoyGlXcCXvmw=@googlegroups.com
X-Received: by 2002:a17:907:7ea3:b0:a9a:14fc:9868 with SMTP id a640c23a62f3a-a9a6996a599mr1394201066b.4.1729512030618;
        Mon, 21 Oct 2024 05:00:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729512030; cv=none;
        d=google.com; s=arc-20240605;
        b=B0LJlwl7QmidnF0qks9n0M+sjHkjijhbz4GIbWz4nEYxtvBKI1/5nrpfCvVDPFmt8S
         DmM1Df/Zw6SAjUUO2VZXX1geK5hBFfty74bsOnDKzXkQAR6R8RvBusx5OMOxM43xldbG
         YBx66kObixRQGjTlZPvW7MIYOjzCa1xUnF2AOY/1ITIgJyt2tPaA9Z1QmBF9F3TAPDYV
         nsuBBCe9+/DNpnzU0Xi24JnEm5s92D0iZwmgFuMfQHlFVuUYEh9KjHl1+WtzwOowjidB
         EwTjJX3524Mu4sgz2WSTsnC+Z7GTNGp6iOx8lf2RFDX4qnBNUetZtpfLCscQymgi/ke6
         rKfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=lpdvHkmKazBU3FnaALiA1RaWjop5m9wz4SmJnth5vPg=;
        fh=vzOcpIZHBqFC4qBhN+lI85EXc0fqqjsXVVDUkXl3hpE=;
        b=HdSUk+VLusqUj0vvsxmviHktSSBwERPv92O3D+A3mWoi+Cm/xJjo/YMiYuP3bs+8E1
         P1muoEGkUiUL9jQ4FcNy7ExjjHEfX38Wu7nvNOf7e/rOeIb3GQOEDgySLYiNiTs7bbfk
         rwKKuG6Tme//M9uQM6LDEVmOiKGNvVuY1oevHj/Vwpkqefg0t8m8N5Bg6l3eIxFetFb2
         vZbszf20LXCU8l5WnZvtvf6L4IpqVKO4FKaFXkdCguQdkH8f/89iXb4fkFIkop5uA2F8
         zhx1NCaaWkgOKGEmM0bEZ6+eWtUX9amMOJT9o5bkXcRbLeOyKmaRYCbLByYpmJW3WASH
         3Bww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=agxGEn3A;
       spf=pass (google.com: domain of 3xuiwzwukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3XUIWZwUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9a9131318dsi5208866b.2.2024.10.21.05.00.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 05:00:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xuiwzwukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a9a2c3e75f0so285135766b.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 05:00:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXjek71iQvM+G4fkIypPCTeVbMa0owpRmN0wAF705YkbaRjLevdB9xbOvzkgAFt89+FCKMKT8JtI+o=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3103:a9bb:c02c:c514])
 (user=elver job=sendgmr) by 2002:a05:6402:3585:b0:5c5:bcaf:43f3 with SMTP id
 4fb4d7f45d1cf-5ca0ae87bd1mr3010a12.5.1729512029802; Mon, 21 Oct 2024 05:00:29
 -0700 (PDT)
Date: Mon, 21 Oct 2024 14:00:10 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.rc1.288.g06298d1525-goog
Message-ID: <20241021120013.3209481-1-elver@google.com>
Subject: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Will Deacon <will@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, syzbot+908886656a02769af987@syzkaller.appspotmail.com, 
	Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=agxGEn3A;       spf=pass
 (google.com: domain of 3xuiwzwukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3XUIWZwUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Per [1], -fsanitize=kernel-hwaddress with GCC currently does not disable
instrumentation in functions with __attribute__((no_sanitize_address)).

However, __attribute__((no_sanitize("hwaddress"))) does correctly
disable instrumentation. Use it instead.

Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=117196 [1]
Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Pinski <pinskia@gmail.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler-gcc.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index f805adaa316e..cd6f9aae311f 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -80,7 +80,11 @@
 #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
 #endif
 
+#ifdef __SANITIZE_HWADDRESS__
+#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddress")))
+#else
 #define __no_sanitize_address __attribute__((__no_sanitize_address__))
+#endif
 
 #if defined(__SANITIZE_THREAD__)
 #define __no_sanitize_thread __attribute__((__no_sanitize_thread__))
-- 
2.47.0.rc1.288.g06298d1525-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241021120013.3209481-1-elver%40google.com.
