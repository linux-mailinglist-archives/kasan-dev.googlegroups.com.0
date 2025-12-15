Return-Path: <kasan-dev+bncBDA5JVXUX4ERBIN677EQMGQEKEKQM3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D69ECBD538
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 11:12:50 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id a640c23a62f3a-b7fe37056e1sf23359266b.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 02:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765793570; cv=pass;
        d=google.com; s=arc-20240605;
        b=hjskLNvms2hlv2ot1FJeMiAWxDuYbYbtHdND0Ft6QCRR9z5yu5Kr6TS/oDei+RoYQ7
         E7R46ZX8Om4KSlTcliaF1Z2OgDpTyjG4016j3iH6fWE9mlxxdLObQR9w8E4URVxm020V
         hT3VPKUJ0SidpApiL9O6zmfd5oJE30YxO9uRhA2FJNxdd/NGWk7MfDfxTS6wtISVwnly
         WUD/465VC8ykO7qWBqrjcWKtVZxmYMKhE6fkfkOY5wbHT4f8Zt6YalDQ8uQQwqAAoPCi
         AUZco98GbCWVcUw8YOk1BiGcO/F+IAeDp8Syejs2NjOhzZ905y1lFMJOI3Kd/ExIseoY
         OjNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9Of8DFSAiEc0jdZ51JZBGHllJ+zRXL3iaNLdk1E8ek0=;
        fh=s/TvO0iTHOsto611jZzq91Flf3vfsvW+sS49FzuzTv4=;
        b=J4zt2vNCCttxOLlqlxatSuhmzCWW+Z6VVtCro8zZ5/vujxTJMUpF7cvdE1PV3ugTwH
         H93+fvSR3yjM9p427bkFt1IpXBr5MfyVP2wQRUKY0fM/36mCHK5td/VpOnI54tnd6+q9
         qUmDskv18eu75d9XmvbxMSvjmd6uHKvZhnOmvIui/NCKYq7BzPZEmth0VHNhPIQvnVBR
         P3e1Eb7T1Sg6+QwiWFVQ1BvlraP+iac0gzrZoRNh87QON5uBlghZZmzOi4rI0iJXrQb1
         heN/e7pv/xyT7pXy8+jMD9ODaZzq1EraQHO4s+oHUtW7CW646KZIQKTmblIzSaLRqGwS
         Fekw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FWYqmVDa;
       spf=pass (google.com: domain of 3ht8_aqgkcs0sjltvjwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Ht8_aQgKCS0SJLTVJWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765793570; x=1766398370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9Of8DFSAiEc0jdZ51JZBGHllJ+zRXL3iaNLdk1E8ek0=;
        b=Y9TUkTz8HdRxLO6PGC1XuMvycYe83ihK4PZwbH8BgNHCz1Itq7+sQL37vZaYhoX49r
         16YU1Ag0AAxZQ9+Er2MB82FcAMpK91SqcWWUjMzVfSby+5eex0S7K0wMQbANPbAl+6Lu
         c784rQDldRsCF0gpnNEGFVcZydn8pvs9Hx/O/h9lH4K6Qfvzj0XqpoDAsJthJGYgW5w7
         SDgXSIxBu30mLL+TODvnbwJAukgfn8fy2CjpYdUycSbA474zxgQ4yNh/Dg3ol1fa2Qef
         pNANwHPg/fAA5VXrQNy32itwSYJYfjra4yYhx37uSqzWucajiE60pKAHQa2/7SMk0dIT
         bFlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765793570; x=1766398370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Of8DFSAiEc0jdZ51JZBGHllJ+zRXL3iaNLdk1E8ek0=;
        b=dtRzdQK9aCc7eKYNNrxwbZck55nN61Y8xR9M+KkHmBHi0kBfxWgK4DkUyiiN4symQm
         bWhaNPJzHzCO0W9hZiX7cBVISyA8KAi6CHbbWf/BGM0jfZzdql+rqViYytMvLQ5V6VDJ
         EohlQ1Im68Il5ImVyp/CkeTBNhXdnZI/dxHfTwJ5jU8EyGS+/O/81mTJcInN2B2XAvX0
         HBCSLraQ2Jhy/SJxDOlcTzMj8RNsBDmXzqIHZcOoEGSlM3eubiSCE8ccyYBGnKqaDODw
         VGbpgflxDO50mxkB69SCJRwk2sKwqsWIu7C8mAue35ExL6J15pcOkyL6e/4WEtd0Iy2S
         w+FA==
X-Forwarded-Encrypted: i=2; AJvYcCXjGF/4U2iSkm29JIVdqIh/tpHHbfeI7E53IUk9dcnnxKatopTGjup0xtkKinCJuADKG26ucg==@lfdr.de
X-Gm-Message-State: AOJu0YygYHcYJ1z6klluVlMkcJ9TFOEB4jv27FJy1yaKfJRJP3bVr28h
	MIPix5bnqQd1IMHSZIklJGgF8n9jeKOF5NGjne56LduAVd3/ap+T7CaH
X-Google-Smtp-Source: AGHT+IHUF0QcJkgNPmfjxX0h/dCANUPclIn/NauFxpqo3/ILAHqcw1A9ifHmFrBsJlTfZmDrLJB6kQ==
X-Received: by 2002:a17:907:9404:b0:b73:21af:99d4 with SMTP id a640c23a62f3a-b7d238c605amr1077629066b.24.1765793569623;
        Mon, 15 Dec 2025 02:12:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYKVh14jIYWgkM/9T3SPSez4PIkNg88MoyFf+Rx6JVxtA=="
Received: by 2002:a05:6402:7d1:b0:643:8196:951 with SMTP id
 4fb4d7f45d1cf-6499a38f90els2614746a12.0.-pod-prod-07-eu; Mon, 15 Dec 2025
 02:12:47 -0800 (PST)
X-Received: by 2002:a05:6402:254d:b0:649:cec4:2173 with SMTP id 4fb4d7f45d1cf-649cec421efmr2841500a12.9.1765793567021;
        Mon, 15 Dec 2025 02:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765793567; cv=none;
        d=google.com; s=arc-20240605;
        b=IurqrsLl6Rjr0B6J+EpejX353AUHAmdXhwwF56XOYwh3pKJuhqIJfNpxoLblTxmpOz
         7Sych2TUZYnedOUn8jd5bz6UrQkAV7XQZKoJL6nyrUKQskduZerHinDadeKNb90pudZx
         RMxlj+yp20Z4iI+CwpCtZqTZ9vqCEfYUn6jQgJl2sJV0YG8yUs2TGiWMDWILdhbR7/th
         +FVRgabvD4uJ02AfogbxnXXYSL5UmFqgJSemRSxhewRfpD60xzWEpDlwU2XRCsvXORm2
         sV57lYbEFeFs3YflCZu7rtuj3rEusXfXfOKF2vcCwDYxO+tFXV0LLQgAvtgQ9EOr2P0+
         LZaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eBg82DgwaEqXYt7FN7z5QKnLiVSgwPtdomNA9XrlWso=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=JE4y17MFKvNCcnX8hx1RKi+Ne+iA/Zd06hWEI9OFVgcGqLXdy1g/SpZs2qWIiZEldz
         jGJsjDvclgggehB9wcFPQ+J2nkguDEeqLpiOqyywslBG78TYGSdp9Ig0V69cBBfhbGM/
         30kzmBTfWKN99686rJLc77ib0QAHcdq+M1J14CXOaLUgSUvG959DVB+mrT0pKwDsz3w+
         gMfG2JZuOdZ5MhooNzjvmrJ5noB21HnolMvYNbVDarglBza2sqO0bex4qkT3NwAfo1pp
         +e7TCU7rkD1HsQcSDSanBhScvIKvSlYmIEbHtUMOExKCuuWB8a4vc2TAKTVqVkBu6VNB
         cmkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FWYqmVDa;
       spf=pass (google.com: domain of 3ht8_aqgkcs0sjltvjwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Ht8_aQgKCS0SJLTVJWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64982042339si236007a12.2.2025.12.15.02.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 02:12:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ht8_aqgkcs0sjltvjwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775e00b16fso22531355e9.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 02:12:47 -0800 (PST)
X-Received: from wmpo35.prod.google.com ([2002:a05:600c:33a3:b0:477:14b1:69d7])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:a08e:b0:479:2651:3f9c with SMTP id 5b1f17b1804b1-47a8f8c57e2mr96731575e9.14.1765793566702;
 Mon, 15 Dec 2025 02:12:46 -0800 (PST)
Date: Mon, 15 Dec 2025 10:12:41 +0000
In-Reply-To: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
Mime-Version: 1.0
References: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251215-gcov-inline-noinstr-v2-3-6f100b94fa99@google.com>
Subject: [PATCH v2 3/3] x86/sev: Disable GCOV on noinstr object
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
 header.i=@google.com header.s=20230601 header.b=FWYqmVDa;       spf=pass
 (google.com: domain of 3ht8_aqgkcs0sjltvjwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Ht8_aQgKCS0SJLTVJWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--jackmanb.bounces.google.com;
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

With Debian clang version 19.1.7 (3+build5) there are calls to
kasan_check_write() from __sev_es_nmi_complete, which violates noinstr.
Fix it by disabling GCOV for the noinstr object, as has been done for
previous such instrumentation issues.

Note that this file already disables __SANITIZE_ADDRESS__ and
__SANITIZE_THREAD__, thus calls like kasan_check_write() ought to be
nops regardless of GCOV. This has been fixed in other patches. However,
to avoid any other accidental instrumentation showing up, (and since, in
principle GCOV is instrumentation and hence should be disabled for
noinstr code anyway), disable GCOV overall as well.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 arch/x86/coco/sev/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/coco/sev/Makefile b/arch/x86/coco/sev/Makefile
index 3b8ae214a6a64de6bb208eb3b7c8bf12007ccc2c..b2e9ec2f69014fa3507d40c6c266f1b74d634fcb 100644
--- a/arch/x86/coco/sev/Makefile
+++ b/arch/x86/coco/sev/Makefile
@@ -8,3 +8,5 @@ UBSAN_SANITIZE_noinstr.o	:= n
 # GCC may fail to respect __no_sanitize_address or __no_kcsan when inlining
 KASAN_SANITIZE_noinstr.o	:= n
 KCSAN_SANITIZE_noinstr.o	:= n
+
+GCOV_PROFILE_noinstr.o		:= n

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215-gcov-inline-noinstr-v2-3-6f100b94fa99%40google.com.
