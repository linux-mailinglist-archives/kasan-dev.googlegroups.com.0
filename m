Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP7RXWCQMGQEDZWLRYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1841C392C1D
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 12:47:29 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id a8-20020a62d4080000b029028db7db58adsf178909pfh.22
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 03:47:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622112447; cv=pass;
        d=google.com; s=arc-20160816;
        b=m8XqHmlzX2Yrv0HqrFc21dwnqoPZ3QSVE4auk2WSi1echeKjmpyRgEQcfa8bbIyScC
         gGw4WBYysICQoqJsqzrXaWxBS7OrkGJE9hOXwTELB68eQJgAb4vTFOetV6/y5L8tqLDZ
         T6pjc6+JM21EVeLZ7nyLk2p5n2huPOkacVoZkiMxVqhT7EQK/2qaa9UD18Wl8kour8IX
         70ERyrjWoinHqE93Y0zmLT9hq1w5xp30irWGps3+ZfkviRMtLugN9wFA0Fz5d1YWEQJi
         0MftiCASJJQA48AcA1WPc7pfYmf+4mXS0+fXoMKA3E6oW9TPSPS6+hiAQ2N7fIvWzfWs
         MF7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=J3vgkDDk2aZnu1LPHoAlDzmfJyXCSK5Kw1zCPRadeEk=;
        b=GXzFmLvsfROoVnGg+yO0PT7QOndUqa2+bl7iW9bV+rDP2bEfyACwjJbUFBAlhtHLDX
         Zu7Tg7GmBsPNbZVuNX/vosVJ/hWV+xxH3R/LxlsynZX2W8qJi9UAMqobvCsGXU9SkmJ1
         aD1hBQ4K9K2D8BcGxQCw6fOpJwh075kMVV8y91q8cufcnCi50mJMSw1jr4eHytjmF58p
         l3vAEaIF7xyC5oCfnjSJIs4DAW/hRQbPazVA8jd6ehGBPLROrlFT6gxk7RcbPdE1Y8Yt
         COyxcgiUc6WzDwAnAvmivCd9Ws0DHa4KZr4Lw8PMmHlvRzz7kZ8hxkiKIuKPc5zeNq8h
         T9fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wU3SwKlr;
       spf=pass (google.com: domain of 3vnivyaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3vnivYAUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=J3vgkDDk2aZnu1LPHoAlDzmfJyXCSK5Kw1zCPRadeEk=;
        b=btaF0Esptvm7d718dofFc5n30X1Sl9xJdx1siV+PhBcgMGSmXmgtf7CTCSnkMOE5mM
         LIokYF9wN/8lQA9TofDEZQFKx5kUj1jn4ei8E+hCoRJnVy2QCNDGKhUmGCxj3xgM2TE2
         onK2gMwl2xauNqnwla+wglE/JfYJStke+ILMa2N4WOmPITWSLX18OW7+laWMxCxffUSS
         ISzGJ/LMDC3sDT3+UWtaDKilC4T3OepL6Ju2OAAfZSFsTVG00ZIP1fN70Pl/psw1pX0S
         ARf2PZ/P1d9oh8L3J7U3cCcEMUorpvKvgeQ5uvmaSDDeyYwd0ZBcuhUegpFiEu9Pb9sj
         MTFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J3vgkDDk2aZnu1LPHoAlDzmfJyXCSK5Kw1zCPRadeEk=;
        b=O4qVlpTieoDT4d7qps8U0m0iirN4JBLFR/hLusaxycFJUo1saxkBRK/GUzyTJPM8wu
         7lLav7XCAV9Ll+nOwAvC8By5c44z6PbfQEdxN+mjd/AeRad/4kJR4DZ8oDUwlaJiaZkp
         ZeGwy3euzB7ACZTT0Tla8fJDTxiA5fvdnGLhLGKpwmrE8JcADbOEnfG87FLyYLAz9Zsw
         2pFm99U+J8ft3uII8aLqHS7ETJEQee7ya5ks+mALwRrpx2ZVtHVANp8TDPNngWdgiyd7
         KU7UDwyCXbXcI/E/qv7WJxbNGDg0lccsZQ855Gww9bSQduu8aRQgZ9ry5/iXP7ld1Xys
         sKDQ==
X-Gm-Message-State: AOAM5323L+ngAtwXK2UFa60LUChVEv+GxYl4BUly4DAC5ZW6ImlLKc8+
	8DUaipBU3H1l8n8fSLJM9m0=
X-Google-Smtp-Source: ABdhPJwHEVVHpSaiu1kKfCYrlCJ/AC5asSjThzLjYSb1Mzc2tZ3P+mOZe7e2442VzRmTGcuLpa3sPA==
X-Received: by 2002:a17:90a:c096:: with SMTP id o22mr8943679pjs.231.1622112447764;
        Thu, 27 May 2021 03:47:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:a210:: with SMTP id m16ls269762pff.4.gmail; Thu, 27 May
 2021 03:47:27 -0700 (PDT)
X-Received: by 2002:a62:d409:0:b029:27d:338:1cca with SMTP id a9-20020a62d4090000b029027d03381ccamr3133971pfh.25.1622112447204;
        Thu, 27 May 2021 03:47:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622112447; cv=none;
        d=google.com; s=arc-20160816;
        b=QNzSCKMy8b5bIJEtzcmwaS7HbcaOUeVZOnwGy70Ql1VRVPOh8gDw59cRu+aUMnL44D
         7LtJpyRunJ9m2UpaeelEKJNPzDQ1YRqLTSLa1UHp8fC7lUJn1/QqVWinvUMnqfOWGT26
         GQ4kT4TcShmJB4uNFOBlMUDNWc2fR6xskQIx6c2xm3RaLIutGtOSkth1nALyo1IOoYqH
         M/LlEAQdXmnKMiwQdB+wOoXlG++rHvQSPJy6BvSzyo/4fZWMw4j28yCAAwr5gzIADfS3
         X5Z7W7ruHpWPKt6jp/YYLZg/rG6hAKc1dvdee+28Qe9ZtHCEC7OgFvMwewh50C74QOd7
         WFGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=WO9CaFGqiJFMkbwzjeUNBHkoPWoyOI+XUu9S7NdEwwA=;
        b=BiEkaPllCJ4FeGr8Xbh13Y3v8eOkeMX4ec/ezp/vzGpUZN2LJTwtIyOS+e3Z53eEeL
         bo+YUP95oCs2gfbkpkSbzy1dIGrkJYb1zQdLMmd5f6lmeOSxZFbPF5l3stSnQlA1NDHU
         s+nBUHo1XZBY4/3euXC7FmsGjOptHrFsEW5HwcIN5lHD7hL28VWPLXxz76s8ZmY04Xxu
         9MYpGasSGd6mYfwkuMH0sR2mHGgUNgwbBabeu6PSQNFLr7EYAsLo8eZJNfNzuHlvGCad
         1ZLyuMXJin6j5/FPosmnY1GO1Ez0iIsYG7BtSwcGFTKCR+OIV4T5Xq8S8Gv6xyIc/E+e
         iJJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wU3SwKlr;
       spf=pass (google.com: domain of 3vnivyaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3vnivYAUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id i3si163609pjk.1.2021.05.27.03.47.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 03:47:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vnivyaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id o14-20020a05620a0d4eb02903a5eee61155so102283qkl.9
        for <kasan-dev@googlegroups.com>; Thu, 27 May 2021 03:47:27 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:74ba:ff42:8494:7f35])
 (user=elver job=sendgmr) by 2002:a05:6214:391:: with SMTP id
 l17mr2896057qvy.22.1622112446596; Thu, 27 May 2021 03:47:26 -0700 (PDT)
Date: Thu, 27 May 2021 12:47:11 +0200
Message-Id: <20210527104711.2671610-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.818.g46aad6cb9e-goog
Subject: [PATCH] perf: Fix data race between pin_count increment/decrement
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@redhat.com, acme@kernel.org, 
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@redhat.com, 
	namhyung@kernel.org, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, dvyukov@google.com, 
	syzbot+142c9018f5962db69c7e@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wU3SwKlr;       spf=pass
 (google.com: domain of 3vnivyaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3vnivYAUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

KCSAN reports a data race between increment and decrement of pin_count:

  write to 0xffff888237c2d4e0 of 4 bytes by task 15740 on cpu 1:
   find_get_context		kernel/events/core.c:4617
   __do_sys_perf_event_open	kernel/events/core.c:12097 [inline]
   __se_sys_perf_event_open	kernel/events/core.c:11933
   ...
  read to 0xffff888237c2d4e0 of 4 bytes by task 15743 on cpu 0:
   perf_unpin_context		kernel/events/core.c:1525 [inline]
   __do_sys_perf_event_open	kernel/events/core.c:12328 [inline]
   __se_sys_perf_event_open	kernel/events/core.c:11933
   ...

Because neither read-modify-write here is atomic, this can lead to one of the
operations being lost, resulting in an inconsistent pin_count. Fix it by adding
the missing locking in the CPU-event case.

Reported-by: syzbot+142c9018f5962db69c7e@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 6fee4a7e88d7..fe88d6eea3c2 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -4609,7 +4609,9 @@ find_get_context(struct pmu *pmu, struct task_struct *task,
 		cpuctx = per_cpu_ptr(pmu->pmu_cpu_context, cpu);
 		ctx = &cpuctx->ctx;
 		get_ctx(ctx);
+		raw_spin_lock_irqsave(&ctx->lock, flags);
 		++ctx->pin_count;
+		raw_spin_unlock_irqrestore(&ctx->lock, flags);
 
 		return ctx;
 	}
-- 
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210527104711.2671610-1-elver%40google.com.
