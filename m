Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL7YW7FQMGQEWCQH54Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 015EBD3A353
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:41:05 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-38305f09475sf22012641fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:41:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815664; cv=pass;
        d=google.com; s=arc-20240605;
        b=a6lNQrQyGm+AI//yzFZ2btY2ubZAG7N3YPT9meKULRT9FiLI10CaKl1R8+z/b98JLT
         +NlI2sZ4B3ycZW56CnJ+S3X6ye/i/2gXwsK54WaSZECMezOZligWnxc+XY6+Wl5QIp8v
         O7U8bwiA9wSZ1OkcOBGhPw133BBTsEHWCM6lmJ1deo1bDOvzxJWg70nnqAtOA0ev4J0U
         NSJAWdn88zps3heF/IozUociTDnHpDahJSrGnRyIOUgPgG+VgNkhH8Fab4wyEQN7SGxE
         C9Usbl+8p5jiw8wCE8Fwr7vWZzicm4gImIJmkE2HYkpA96voUcG+S8Ft8hBXKTVDUWMk
         JpYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jl8I721Yyuf2QftejGF4HzFHR3VRnHxX0pUfoeE+yMU=;
        fh=Mz1qkKuZcpSZgrrvCbQNr3FZ5J6LlVD84kXtOTXCP8s=;
        b=ex10IEYpCml2x+cAjPN33s1rZa9OHKmmXDa0AW2k0QAw5sJurkepbMaW/FzI58t3ot
         XJAkSnhZhIeD4iC0Pge21t+PxcjUocKOMALct3PtxQ1bP7VRh/1shYRc55+ZpNPPnypp
         lLbBHd9VMWCv2Kjxr8VWA8PU3t37zZIazNX8AkSGhsRYxnjxe2LZ/S7fKN1gp2CJif0K
         XTiG+ZT90XvByOCTArJB++lYoSIFENujppNo5qwqmY5noS3huPTowNDU3+Fy8FE42XuT
         lYfmM7E3j008r7oBoGoYoogf2hKXsIGG+iQJAH3zEfIAv662XMqLSUOElmg2zBWaWIiU
         vIAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Yw94NdTw;
       spf=pass (google.com: domain of 3k_xtaqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3K_xtaQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815664; x=1769420464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jl8I721Yyuf2QftejGF4HzFHR3VRnHxX0pUfoeE+yMU=;
        b=U1WJE7+aqwl4xtF39AZE92WPZ7QtuVWm6MiDbx8m+FZHC/hwG5uKIJaZLRXKZ+CyKf
         xC4G147Pi3VYu/hJJQJbjF9UGl0Bzp0YVRB4KbJAUF8/1hw5/McnejMMddwzgTKsEFHP
         ABE0i2LnVsoDelEHPE4AvTf19WAp/WoWsWt5DpgwzPxdIaJ56hMdHCn+OlTLDji+F19Q
         z0LvlxrQYeetS+CUHNJ4InKr5Hw372irJmO/JyJK4fQR2hf6GekgD+nN1llkKnvktXZq
         rq4ek+pRdMNGJqDqRDzgBGf0eIQFkZGtK/Jeb1wMpBDxhO8KOE7R/G8srXWBF0SZIf2H
         50BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815664; x=1769420464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jl8I721Yyuf2QftejGF4HzFHR3VRnHxX0pUfoeE+yMU=;
        b=dDe9ncrsfdcnoMBjh8znNP/ADg8HTlXx01UR+4e7m+oAJ3O5cVXk1E6i1JWcx0s+8m
         JYgfETPpvcGWSV+pDLIFawkjY/16Mys9QjTjY7Sq+0BSO66g5nXHAEB/2IrtbyVAuOE6
         ZrTWmJdKigSuLKL+aBnm/D7LrxZoveV9ydFPbbwVqcmNxFUW1xgoijKgePtwixiNkmXt
         HCZ9dupsi0mLc31h6q+M12qDnHWf8QZaCEvZZYMggwRqa/GIi5e0ey1hjCmD/8vC+l3y
         Ka9Xm3QYXcS3gkiPv0HqT4IsUIphF5BM4hZo0e6rJbcIlXqGBUzN/OUW3XaOAEjGbJwn
         KbTw==
X-Forwarded-Encrypted: i=2; AJvYcCU2cSNb6WxUPlYCctfbgZVPayf1tR8PKLbhbmTydYjuFgeN7y120S78vV2D4oiphEb7PXPRuw==@lfdr.de
X-Gm-Message-State: AOJu0YzZ6IM+YcPpgIRGFjValzYmZGcfIl3ShEdMIoBFSmy4gBZzxbaF
	HM996Fbe46/aXa5YlFmJ6d9sgCycCFlvtY5EIWxOkr0sjdBwKuouO4bK
X-Received: by 2002:a2e:a905:0:b0:383:20ac:fb60 with SMTP id 38308e7fff4ca-383842de819mr37259111fa.29.1768815663891;
        Mon, 19 Jan 2026 01:41:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HYgy/t/CdNRet2yWyuAcrWRuG1idoCmsaKwjWp80caPg=="
Received: by 2002:a2e:9e0a:0:b0:37f:b03b:76e5 with SMTP id 38308e7fff4ca-3836ee16cbfls4070001fa.2.-pod-prod-02-eu;
 Mon, 19 Jan 2026 01:41:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUy7muJSIMpD+D1dsERurjMgEf7JL9D/3TqhatmBmJgHxpy3zTaI1/hT12sNIkVMGgdF1FvVnponBE=@googlegroups.com
X-Received: by 2002:a05:651c:1ac8:b0:338:8:7275 with SMTP id 38308e7fff4ca-383842a1f4bmr26646881fa.25.1768815660424;
        Mon, 19 Jan 2026 01:41:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815660; cv=none;
        d=google.com; s=arc-20240605;
        b=CXmdkwAlY2ClxNrNVfWzSqHp7BDZKoVo66pwDxRX+9YHd8GlzkwJXhrOmNyDc6fEvr
         C4e/MvspqgBJ6mCI1hhxIkeG6IikgtaLnXZdO0nM3cp9z+2ECetyh5HwqPk01LNQOT1N
         1ClW7H7VpuIjPApRXiXRG7ph2do4VdN72aeGfH7hjG6VhOIMEKRAxo/JIus85e5cGVYm
         14T2yCs95kiDGI7Kdjv6HlUcgbjf/LFNDQjYKbj4blHc70G453tJSD6HLR+p7wFd+giz
         d8eNArRaqr9XBhy5o3ZYEl+fncqmvupuOTAZYVo5W1flmLYKrBnpd5aSe0f3QrXuDCRI
         PGNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5O5shuIyt2OF6tzGpJJeUtztHqWv8B89x7ZKRetoFcY=;
        fh=T6rnms85GkAUUzoaHNRUS32TeJiox//32Clj2ZSZUQQ=;
        b=MmQ2WBqhC4D0Kdw4S1XdpEnqQDdu5jOkM2PtosOHSUfdFCm+tNyi6PrM48QD4ooUEA
         4b2YWrWe8QA8/lLNMs9xkmenI1hmMyPmmdJJXelb4pHd7dW+43TZKzOiOiWzdxDyjNY5
         9P5WTnGq1TREopmTI/dass7BXfnVKAZofrzIuN9963sxVegNfe2iJ6xmULKS4jXxEYGq
         kRDzfkxumHahMvvXEpOGf+buuU/TIQ6gHQd387KuDEC5+fuLxKdTxOAamOBQKpw/Qnk8
         vLaQg9byzigpDY72pl8BozY9ambcSAjATv1/OJo2THzFRurpLFuxyvdNS0Hrh+YkTomD
         2E0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Yw94NdTw;
       spf=pass (google.com: domain of 3k_xtaqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3K_xtaQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff92si1922281fa.2.2026.01.19.01.41.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 01:41:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3k_xtaqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4801ad6e51cso33506725e9.2
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 01:41:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXbvUjDfze4bDP2S0OpC3GRZMt49pZRdBBQLhQ4Wp8UF31iiCBsJ/uiCHoSHQfsHDKduLjHww7ZYdQ=@googlegroups.com
X-Received: from wmbhb2.prod.google.com ([2002:a05:600c:8682:b0:480:3842:3532])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b81:b0:480:32da:f338
 with SMTP id 5b1f17b1804b1-48032daf48bmr41618245e9.14.1768815659820; Mon, 19
 Jan 2026 01:40:59 -0800 (PST)
Date: Mon, 19 Jan 2026 10:05:55 +0100
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
Mime-Version: 1.0
References: <20260119094029.1344361-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260119094029.1344361-6-elver@google.com>
Subject: [PATCH tip/locking/core 5/6] tomoyo: Use scoped init guard
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>, 
	Christoph Hellwig <hch@lst.de>, Steven Rostedt <rostedt@goodmis.org>, Bart Van Assche <bvanassche@acm.org>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Yw94NdTw;       spf=pass
 (google.com: domain of 3k_xtaqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3K_xtaQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Convert lock initialization to scoped guarded initialization where
lock-guarded members are initialized in the same scope.

This ensures the context analysis treats the context as active during member
initialization. This is required to avoid errors once implicit context
assertion is removed.

Signed-off-by: Marco Elver <elver@google.com>
---
 security/tomoyo/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/security/tomoyo/common.c b/security/tomoyo/common.c
index 86ce56c32d37..7e1f825d903b 100644
--- a/security/tomoyo/common.c
+++ b/security/tomoyo/common.c
@@ -2557,7 +2557,7 @@ int tomoyo_open_control(const u8 type, struct file *file)
 
 	if (!head)
 		return -ENOMEM;
-	mutex_init(&head->io_sem);
+	guard(mutex_init)(&head->io_sem);
 	head->type = type;
 	switch (type) {
 	case TOMOYO_DOMAINPOLICY:
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119094029.1344361-6-elver%40google.com.
