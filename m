Return-Path: <kasan-dev+bncBDA5JVXUX4ERBSGW3DEQMGQEYHGEANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 99271CABBB7
	for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 02:35:06 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5958fe96529sf2360118e87.3
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Dec 2025 17:35:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765157705; cv=pass;
        d=google.com; s=arc-20240605;
        b=aVVY1eNqOXVypPpZRIgoD3s1FyYoXCEiXypPbTGpP4MtYkdPHjtJZAWLXju6CaXSks
         stXRjTl4Lk916PInnXZ+fG9R1QH7UTNWL8bfLTV52ax5qBaM+KlYjP4+8rGTybR2RVDK
         3wYmVwxVN7KGApcI8lgEODbvUDaSGcaXFq7I7UqLJLAgJkgYA16CPTge0MdhMD92AdwK
         VwVZ94+maihNUZObMdcYtuGmAg3BsVpix/QZndRe+RVlsYFIVkeVwT2xj8JLKimlWe9j
         JYK6juaJpHOtwN3mAO5692l2ADZNyoWtPhu8US0SzSl6YLD1TNYvmPFAXMOMh/FoouVp
         ifbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=D188fre9GdfWRP3Nc7BN3sxYbY+aDXjwSNWbZ7CDKso=;
        fh=vf8rGRMWLgtlRwbr9ifEUKKGI+Fh40HuNHGL1dWCJ3U=;
        b=N3J4O5XooN0BPw3VU4W+lxc87nY90SnTfnx+6oxMBT2zpSjAUk233SWIfOSPD1jhIR
         7kFWzM5F3qL3+PfiR6SyV7ptsSfmF9QwS0Mr8rZRY5lSZH0hWyujud8aWnr+bJxSM+l7
         iVnyMVrn7a0gnEYp/57abmxGr2hRrJ+kRbaTfivbXdnXPtRm2P0QNdTvCfEH/On0YG8s
         d2VAKtI8VaTHPiJ0NWqJk1B3B5XC38tSFycNQh5aAsL8e9d5d+b4xCrFiCGNRnxTDT8K
         9Y4Ig91avX7pw3BPJoTtqqDHP3bTWZA5pbsya3hMkycG1RBCPS4YAw8NcQJGVPltol51
         Pd0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hTOBD5tN;
       spf=pass (google.com: domain of 3rss2aqgkccqtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RSs2aQgKCcQtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765157705; x=1765762505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=D188fre9GdfWRP3Nc7BN3sxYbY+aDXjwSNWbZ7CDKso=;
        b=wPrCZH6qujz7+4bF5l0YA0VZSZYgJaABAUhaGzlbBclZnwTa/r9PsMQynpCT4nHYJx
         TDAPWpsRSSJUTu+L/Q17bwpznK1cpUc9z5jTBrz031U8XPTyF+r3gSxHa7abnfRtFuoe
         YEq+j7VT+EdcPuDgl2e9sA3studIoun5FC2vPKFECyeSULLzAsvLx/i35gTjlkl07CUl
         n7KTerBPwMVZQFCT2HvsZIDIVD80WpC8QSGEFanhF4rdo0XpLn0Ph72nUvGotuS+Xnop
         15OY/vACrE2NP02uR/Aol00c83eOeGlhdyS5eq3XZvjC5+7DQvcsScAhSWtB080A3bKM
         zXGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765157705; x=1765762505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D188fre9GdfWRP3Nc7BN3sxYbY+aDXjwSNWbZ7CDKso=;
        b=Bz8d0hMga1IaejvcOTJiOoZF+Uc745IC8wBdZOIed6ukaBLJ/yOMJJ4CIWiDaKEvFB
         CUTcbnU69A2Sr2F1PLDHp3KkwpdTwYMWUA7DF4vqZGvTl422rlXYeGgNw9z5CJYHkb1k
         A/d6hcFsvoAOmHbVfY9OCgZzHG2xbpty3cnBDF9qt6QQ8bnIaVx1my/o3RWzx7wyj3Mt
         OEnekhboWuEppsRw424hXSuFtCHxNxRDqNimi5QLjmix3Uo+A9pGdybXD3yA8nWCc46q
         7Ry0fg4quzfVINSGbq05LN2FirEIX0xsbm6kzuqTF3zdg5Um7ZPQB3nbI1CTozC8S5Eg
         eUYg==
X-Forwarded-Encrypted: i=2; AJvYcCU1Mq1Ib/aIis7/00I0atJKOmp14452SSse3I+lThH5jgZkCJwrp2JCw69yMUsy6xHZAn/a9Q==@lfdr.de
X-Gm-Message-State: AOJu0YyxjHYMYHnqFVEOvgZM7uO/n3JF6L52wHwck0VMdUPBd492l6BR
	N0MIqB0PEb5MR97v9FTIYk+1jMGiDo/1jRZOlrWbN0jwMvIsVEf/LBqP
X-Google-Smtp-Source: AGHT+IGl/5WPTzl7JEjwXyyb87CpW2cY8RmqkWTurQ1bvcYLyfZh4E78gsxn1qoQC0Op0CdR7nk6Bw==
X-Received: by 2002:a05:6512:2248:b0:592:f27d:75d4 with SMTP id 2adb3069b0e04-598853de933mr1694584e87.45.1765157705209;
        Sun, 07 Dec 2025 17:35:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZgEw3tdm4UJK5Kx9MsX6LyROVJkamdcd0uncwlet1Lgw=="
Received: by 2002:a05:6512:2509:b0:598:df84:48c9 with SMTP id
 2adb3069b0e04-598df8449e6ls228337e87.1.-pod-prod-04-eu; Sun, 07 Dec 2025
 17:35:02 -0800 (PST)
X-Received: by 2002:ac2:4c49:0:b0:595:9d6b:1178 with SMTP id 2adb3069b0e04-598853ca8eamr1602537e87.40.1765157702250;
        Sun, 07 Dec 2025 17:35:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765157702; cv=none;
        d=google.com; s=arc-20240605;
        b=bEjCfL18z1eKzKlyFLpKYJEiWABIhWHrdxEUrzb1BWzOMyvefyuunMNvhCcldL+rvk
         Wk58mnBfovUoNSpns65ssTdftLMS2W2hHZB4aul04JyzzbecByXY/hU37J2kJLKqJjAZ
         vJ76erqJ+TI5lqwFr7Mvd1BwsNPrTebzjRGEyXqxIJKLYoMCZ5PwPFaKY/PmaeRuV0kk
         ijdGdrZwNDPlTdh5WX7LF0Y37lQXhUWkLpQB1emAEJk5FavU1oGH13jYVREapAcCs4TS
         AVj1nY/5wmZkUjiSXiKQveAeGkUE9n6SMPA5o9Pl9u5Cs+8ydFY/RikO4xew0rYo+0Vf
         CT0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eBtkJjZbx1I9UXTOuE2VVg0l9FPIfLrBbeb691OK32A=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=UXfwpVDEng1bL6/aTaSZoPMaoDD7Rze+zAD6nqoajWV2Ht/SRe0E1gN6qL3FgbBAtn
         VhOiInsP+WMxH3+s3Mwnd3D4YKF3Qcc132wLSY/CbFh21/l+PgWXkhh+wdghxdrYIPTw
         PbfJ450sQUFwjLZwqQhB1A0ppVJ0NJs2sVLYrWXY2QjP7oYQi5usexCs/LY07Cpfrsba
         T4eI54cTo5aw628XclnV6BojeSUrsiQbviypoIkmi+WDyQJFwU392FYqYY9bIGjJ6mQY
         2ZZJTKG8UbMgApLot/l4ZYqFO3tc4T/4decuLs470WrF8frR+BOaEbXbTommGdmzalDL
         fSHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hTOBD5tN;
       spf=pass (google.com: domain of 3rss2aqgkccqtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RSs2aQgKCcQtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-597d7b1a3cesi134743e87.1.2025.12.07.17.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Dec 2025 17:35:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rss2aqgkccqtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-42e2973a812so2154503f8f.0
        for <kasan-dev@googlegroups.com>; Sun, 07 Dec 2025 17:35:02 -0800 (PST)
X-Received: from wrod8.prod.google.com ([2002:adf:ef88:0:b0:42c:c2d6:2a4])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:4301:b0:429:ca7f:8d6f with SMTP id ffacd0b85a97d-42f89eeb0e1mr7707623f8f.15.1765157701430;
 Sun, 07 Dec 2025 17:35:01 -0800 (PST)
Date: Mon, 08 Dec 2025 01:34:58 +0000
In-Reply-To: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
Mime-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251208-gcov-inline-noinstr-v1-1-623c48ca5714@google.com>
Subject: [PATCH 1/2] kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hTOBD5tN;       spf=pass
 (google.com: domain of 3rss2aqgkccqtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RSs2aQgKCcQtkmuwkxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

The x86 instrumented bitops in
include/asm-generic/bitops/instrumented-non-atomic.h are
KASAN-instrumented via explicit calls to instrument_* functions from
include/linux/instrumented.h.

This bitops are used from noinstr code in __sev_es_nmi_complete(). This
code avoids noinstr violations by disabling __SANITIZE_ADDRESS__ etc for
the compilation unit.

However, when GCOV is enabled, there can still be violations caused by
the stub versions of these functions, since coverage instrumentation is
injected that causes them to be out-of-lined.

(Note: the GCOV isntrumentation itself also appears to violate noinstr
in principle, but it appears to be harmless - basically just an inc
instruction).

Fix this by just applying __always_inline.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 include/linux/kasan-checks.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index 3d6d22a25bdc391c0015a6daf2249d6bea752dcb..9aa0f1cc90133ca334afa478b5f762aef9e5d79c 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -37,11 +37,11 @@ static inline bool __kasan_check_write(const volatile void *p, unsigned int size
 #define kasan_check_read __kasan_check_read
 #define kasan_check_write __kasan_check_write
 #else
-static inline bool kasan_check_read(const volatile void *p, unsigned int size)
+static __always_inline bool kasan_check_read(const volatile void *p, unsigned int size)
 {
 	return true;
 }
-static inline bool kasan_check_write(const volatile void *p, unsigned int size)
+static __always_inline bool kasan_check_write(const volatile void *p, unsigned int size)
 {
 	return true;
 }

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251208-gcov-inline-noinstr-v1-1-623c48ca5714%40google.com.
