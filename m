Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBEVTT7CAMGQE46GAGRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4601B142B6
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 22:12:03 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-ade5b98537dsf518834666b.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 13:12:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753733523; cv=pass;
        d=google.com; s=arc-20240605;
        b=kjWyz63R3Qp13BxDtB+1QmJBCKevHaWPB8wDoI3C/9aCZsferkUrHVrzi201UhzaFl
         Ar7Yrm394am2TxSlbeaRj1b4oPGoVfrKHWes2yc0+f9yesTSRc3bsLWqHS+AjdubEHwP
         GT2zTF2s2nHV+rxvqpeW93isRwo+uiloFUND54q7dxoRPHmFLarjD66IxNGrLO0mzwWS
         sn9G0bGr1Ej2qurIZOQQm18VesU7JZ9pOv07IuDCTO6i1yhE8OuCyOtv4wmmT4W6s5Rm
         bHLpPM90HLi+Zrc9AiFsqzXeObHwe7VbWaO91uIcln0v/uvBIqiDtTkvyMRbZvFYhO6k
         UQZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=vCvZUaerGBueGpoJIVxorGmuCfye7M2nlQ4smbOUvwE=;
        fh=8qKlhpyEhBikK1HIRxdeLAdaTnlIrIp8+7vZ7Jm22gs=;
        b=TTc7ga4r7TjW4rUZg6QLWqoOnMwEl6Od8e4PMQRJ+lTsQvOtk24wbvwt5VvjB+Mp3s
         QIsCGyjqwAq303s0hw4zJoCQMVpDZ2PVD9UOgRHsa9SPBp8kUPrUAGgWq+hRdz6MIV+j
         TstPNHqS31A/GY+CO34wKiNaD6UzoW2oZu9RUFRG6Rk3e+toFcaP4hNe4p9NsK1DBmq7
         U0TrL9O+nTTspM+yyBWbSIlgn1g/rSGn38TmrlfEzkPi5Hdt+RfJWd9XxCAl09QTZuR5
         u6rBovK1eZkp3iJhvEmoAzHCwJ9bgqaINXjy3aPbJq3ZvjRe70wqZVkH8ORUTuHnz/xo
         Onyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y5Y4Bjoi;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753733523; x=1754338323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vCvZUaerGBueGpoJIVxorGmuCfye7M2nlQ4smbOUvwE=;
        b=djqCc8kSbSf/11zGuqEGlyI7WEDHycowsAgrjpENcoi74cqhIcVId3r+1Xra48DBBy
         eQMI7EiR/PRLISPvfD15Zx7w/hhw/xddSLiL0na03VmeMlTjutxRTW7QYas0kjKy8eeF
         er9g9GbPPHYvV8loUILhtUeNaWFQTIJUDDphjIKni1Gy7zzmhrzKcRdhNGC8720SxdPs
         QPx+xCK0pHic//CYqkYXxLohE2dadYPOSeAhFfuXxaOzPsiBZnnux6B2BYl53STKRlld
         lSQ+PRjPY2RV9Os3kF++qUsUlDrUz43XCmf3aK56m1H7ts3K7Yk+Rjk9PYiQORcL+Chu
         N3rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753733523; x=1754338323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vCvZUaerGBueGpoJIVxorGmuCfye7M2nlQ4smbOUvwE=;
        b=guiR8OIszb0z/WRAPbhpVBULUTJaVtnUWJtetmExt+rEupV66Dvl612rFAMXb2tgTS
         laN0wqv3vy11sVN6mEJX770C4oDgaAF/jvxL0tZPA4wgvDbeJ3yAW0zdWVHf7vF2gyRc
         Sss/Yug1XbuTgxsXglG/D6JHoscDFK0JDbhWHvSbDse0+1mpVe//ZxONRWmxQq+Slm7C
         AncE98FQRQrhbrUnjd5hJVC5pqdkM/UHXGyW+SuNmToqW/Wib4Sm/oi1thx5cKyukkNC
         Y5c6KPM4k9r6N/JIsNs4aslsJjLn2K4Pkr0v8JCD81aYzPe50BVDnj4BBQ5uoOTcPfxH
         XRbg==
X-Forwarded-Encrypted: i=2; AJvYcCUYaoMQFyR0hK8OE+EMLxTyhw5yQb9l7Zpt1rR9QTbL09V5MDQeCIS8jBHJ6BVs/2TUjuVGXg==@lfdr.de
X-Gm-Message-State: AOJu0YzuDmKV9vsYd7pyiLOZe/TEz853sUEuKxoRnHk/q9zal6djFF8Y
	qwrOQ5o2/SWU5sGp/PxPbLpjb6VbRdknz01PULKwyg1vLuhZhd4pUgE6
X-Google-Smtp-Source: AGHT+IEHUSL7JLu2yCDuCMJluxaUAQ40K/7+F3zmvJmR2TLieW2tQNO4Z3ugv9VUWbqq1HUwCojGCQ==
X-Received: by 2002:a05:6402:562f:b0:615:4236:5902 with SMTP id 4fb4d7f45d1cf-615423659f5mr2980431a12.18.1753733522959;
        Mon, 28 Jul 2025 13:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcjLw925/o9WPAvRyBswMVMaJeMJkKF7kQM0AUYfbTV7g==
Received: by 2002:a05:6402:2356:b0:604:f62b:4112 with SMTP id
 4fb4d7f45d1cf-614c0ad4a0als5036128a12.2.-pod-prod-06-eu; Mon, 28 Jul 2025
 13:12:00 -0700 (PDT)
X-Received: by 2002:a17:907:2d94:b0:ae3:b85f:6eef with SMTP id a640c23a62f3a-af6191f02b4mr1484872466b.42.1753733520416;
        Mon, 28 Jul 2025 13:12:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753733520; cv=none;
        d=google.com; s=arc-20240605;
        b=iEVoCV67Fy7Cn+L3GncF8InBqx5HltWBeX5mxaLQJLRMWf/ssdfrzxZzlwDhp4Eo8U
         w/uGZTjRu3zt8pYl4vLN7lX5IwPRaEvkMhv0UeKjMP7MLsCVh9n9nP7l/ax+PjpcRxJu
         r/Sa/MnGVxZwETo6Y1XZBZTHFBYKWVoM+0vnJ/C7349wLqDaMkc20vezvG8lwZdIKFad
         nokaBQNBlXqeUjyoVbGU2Y3PfBuHCx0E0fXr4TNYzxHBQyL2IHYOqI1V5Arz1wAHGZBK
         qxfPD+Q6tsiR5iYRLdm0dW3/nTTATWrhKqLHVVcHnIExYKkIlulNemWkK33PqvPXm6/a
         3ZiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=s0cHzSvxGHBD6anMEro7maJOsM/+ZwrFtNd3kS/G7GU=;
        fh=2PrAEiz3NiBwc81TSmX/60ggqnD0YUz3V+yJHqVlTxE=;
        b=UVaFEWnGBYAD6DaOB6fHP7e/DH33bjf20nXJmTyL/qN5zqREj0wrrVx8rmZSs1vuNr
         IFdP29WmmnA4FQ+edo8Kge364bFkqVItPM946YzcErh8NvCfOejFAwgzjP/fGtLVixWy
         JH9ft1To7qizAFR+BIDIz4o2+Hg7fsTmDnFLaG5VN7CZA2vC4861dGe8IBZy9V+c6CH5
         u2hpiCn9K8av8/zoYlaqWhGojDGMi97UBJfXuWjpk8gusQ0f1WqrRNiPrpEFYmRR+1pl
         KKTtZGycdU8EzB37LvSb7WyNU8+NPYgnOlFqKbth5hp4S2Kw14avQjtKGFQfj/eBSVi8
         paFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y5Y4Bjoi;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af6358b5b62si15128666b.1.2025.07.28.13.12.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 13:12:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-456007cfcd7so2995e9.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 13:12:00 -0700 (PDT)
X-Gm-Gg: ASbGncsb3Vp24BMpnt+6aEqfTiJkqIDZ2POLjxklTCkdzIt0KLRh44KKi4EJA+iQ6iW
	30Br8XcUzjGfTNfdhbq6p/YWzNlG3U1hbwXkBnk1r95BnjCxtcPx5ows4x4pZeVhrFMdNhCUBtC
	EIKvNrV/YNPsD+/lYzohh9z6IvpssXazfSIhvJMDDbhx5Rkkb/iS6ZEjMuYCn8jntWRP5AW00jc
	wwVhD+OcO32UDr6kTwn1wJR7+TjBlgfZQlrzn8MmEfhu/ZP6DiAU2jb92u4XYelVNwDqTXij9M6
	E+BJWZQ3O8jS6825gM2C1YnMArdowp6T/4ev6/mQqMfVe6+Do4Lm1TimyI47EXdLz8Kt2sZQvuC
	ayqs8nQMyTg==
X-Received: by 2002:a05:600c:1c8f:b0:456:e94:466c with SMTP id 5b1f17b1804b1-4588d6faea0mr193425e9.3.1753733519713;
        Mon, 28 Jul 2025 13:11:59 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:ec3e:2435:f96c:43d])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-458705c4fcfsm167139575e9.29.2025.07.28.13.11.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 13:11:59 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jul 2025 22:11:54 +0200
Subject: [PATCH] kasan/test: fix protection against compiler elision
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250728-kasan-kunit-fix-volatile-v1-1-e7157c9af82d@google.com>
X-B4-Tracking: v=1; b=H4sIAInZh2gC/x2MSQqAMAwAvyI5G6gF16+Ih9SmGpQqrYog/t3ic
 RhmHogchCN02QOBL4my+QRFnsE4k58YxSYGrXSpat3gQpE8LqeXA53ceG0rHbIyWm1aVxlDdqw
 h5Xvg5P91P7zvBw59gk5qAAAA
X-Change-ID: 20250728-kasan-kunit-fix-volatile-d2b9f6bbadc7
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1753733515; l=1506;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=Lw44dNghmCiq28TogKJdMlT60+fsL5APY9+7UOE+tB8=;
 b=C6lZbcU2X+AJW0vETjhTQhf3UGiePUoutVdYlhO5KePE7UNaPnUOl8JEhfpjN20q0CI8rf9es
 golCyt2pFHDBgyH8gSS+VI4ja5yi+aO2ecmGVWz3fDq3wNJKKFrjOeH
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=y5Y4Bjoi;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as
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

The kunit test is using assignments to
"static volatile void *kasan_ptr_result" to prevent elision of memory
loads, but that's not working:
In this variable definition, the "volatile" applies to the "void", not to
the pointer.
To make "volatile" apply to the pointer as intended, it must follow
after the "*".

This makes the kasan_memchr test pass again on my system.
The kasan_strings test is still failing because all the definitions of
load_unaligned_zeropad() are lacking explicit instrumentation hooks and
ASAN does not instrument asm() memory operands.

Fixes: 5f1c8108e7ad ("mm:kasan: fix sparse warnings: Should it be static?")
Signed-off-by: Jann Horn <jannh@google.com>
---
 mm/kasan/kasan_test_c.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..c9cdafdde132 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -47,7 +47,7 @@ static struct {
  * Some tests use these global variables to store return values from function
  * calls that could otherwise be eliminated by the compiler as dead code.
  */
-static volatile void *kasan_ptr_result;
+static void *volatile kasan_ptr_result;
 static volatile int kasan_int_result;
 
 /* Probe for console output: obtains test_status lines of interest. */

---
base-commit: 01a412d06bc5786eb4e44a6c8f0f4659bd4c9864
change-id: 20250728-kasan-kunit-fix-volatile-d2b9f6bbadc7

-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728-kasan-kunit-fix-volatile-v1-1-e7157c9af82d%40google.com.
