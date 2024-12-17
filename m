Return-Path: <kasan-dev+bncBCXO5E6EQQFBBPWLQS5QMGQENDU2O5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 613D89F44EE
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 08:18:25 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2ef8c7ef51dsf4130810a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Dec 2024 23:18:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734419903; cv=pass;
        d=google.com; s=arc-20240605;
        b=cdc+xYv6Jv5Z69q4Zlq/svCw0ksQFBWBF463oM8AIQ71Vc+fIbIjDYH/ARJjUvXWAX
         q9UdIErEbf5TxDpWJkWjr7osbMbiNBtNJWKe2P140mEO+2yq9CG2OrJgpY1JeVbNq1+d
         sAa/sZuCPyE9ZJavQjirsGm0moA773XZxmnn/IkhBDMzWFvugqFlqk9fT3sjcx0aT4g+
         HW03iFlSN1IyUzB8AovgUVfSR1AyMjq5z6nOvHn2anGcYSvGXH1Zh+zWKOn2O/1C9mQ4
         DmCtI7N61d7pfh0t2O+y75y7Qa8QDrxO1wkfDjQTT4ES/uj9qkX/u7Rd9ZQOhttUJpyK
         P3bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=fpno5F9qICBlowoHcfFePoGcb8z7DMmKnjikuusRYqo=;
        fh=Hjffl/DjzyEITkVlyWVud8EmJt9Tug91rhrecXigjcg=;
        b=JB6Z7s1Ua6Og4OoGbin0vwO54AZJy6g+shbSDSN0DGXT0AX1RTRoMbc9vShVwq+Fi8
         QEf0sLVeLWvoJm/GqcsMRf2WIgfYEUD6VzjbdIjiQKJxjpueEuZ7/hZsxgZLleV9YDv9
         gswXRQVcEmyNACTZl+0269jFkx1SqtGYyggT55V2JqD3Vr9DvEXPp5X7TpoFJcRKYwVd
         pOBT5Gw6sXj2nDYqFfDrG4v/3WviX3OafEhvBkTbrqbHX9fAYW0qjFwQzs4YAs+WwWIu
         WuqAOaBh3rQ36TB9tBvDIbAlpjLbJnmwrNm73eVw1rAtCcdpIIuLY40WwmQs1ALm3QnW
         khTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lFQleMFq;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734419903; x=1735024703; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fpno5F9qICBlowoHcfFePoGcb8z7DMmKnjikuusRYqo=;
        b=vM9jlOEiHsq9FF4l6yfRPP299MtUkQCXUNUJ05p9kDFUI3aNWuv2xQUvAnIZLGQpXd
         kZ0Jv/5/bdMFZ7wfDG5y/lsDcGppNAMrHgsvpjMbJgGmx0xipVe9VAWRYuZI/++75U0C
         pfmrZqhMnogZrAjBENo0n5onidSxBD0DMGVhI5RZWNDwCijsUWedm0gWqZyCnfupeeLk
         3izm8EMTbO4XBh9kfxVUImvyQWd7WzWtMF3DG1kiuIUlG8NyhWOY8QdOv2Q5V2PQWffr
         JS1BeZuwrzrUGOKAf718BCW0jn+3GpDhjDFSYdfBqBzTYqJaqMF59pb/0VBw/n9JSOir
         nYcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734419903; x=1735024703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fpno5F9qICBlowoHcfFePoGcb8z7DMmKnjikuusRYqo=;
        b=POvlh5Kdr52l3Y62uqLbRDWwWahNbGkgdjL4rBvVi5Tp2K1KDY0P++tlICPWG3JWBS
         jm6nsSpAFViKSWEehB3uJ/KD2cc4V5EbYf5sU+XYkJFkQquJfeH8fsyLlUAzI7T1nAf2
         Z2zS86ZnsZhmn487DEOLalXWNhVIxxVdH2jO3KmKq5dzth6attz/36Sg4oYkhby2PBb4
         0qVKql2/eeaEbpE6TlsD7D1dvn5RDMHTAz175F+ePaKMBbqyAxaRfINeMC3oqlnuix8C
         ofAeCiCEGw0OI8dSsKQ6euTV7fOfBKNvWAbqea2pB1YVwChWRwuX1iq3qFxanlU8c4nO
         Axvg==
X-Forwarded-Encrypted: i=2; AJvYcCXFgr1D+kb5P5wCoMtRi33Qz2Z4wy2ek3U2G+3K6MlW77MbfpPV8uU/30/rRUbk0S/u+tE9YA==@lfdr.de
X-Gm-Message-State: AOJu0YywnZV6ugyQMHRDffiz3aBPdsEf21u3ZRE2j0r7+rey57WGXUrS
	Q9yXX3efVofkSF0Wnopu/p23Q1szynRIX4tY8nVmC+OwCaLaNd69
X-Google-Smtp-Source: AGHT+IFQJfRquKRKWuVJ9xqpd++zmXOfpzIwXyhUXMuhz9eMJnmA7eLmEBVTc+rpFBB8dyN4scv3nw==
X-Received: by 2002:a17:90b:4d06:b0:2ef:6cbd:3c0b with SMTP id 98e67ed59e1d1-2f2d879707dmr3333076a91.3.1734419903267;
        Mon, 16 Dec 2024 23:18:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad87:b0:2ef:9d30:13a0 with SMTP id
 98e67ed59e1d1-2f291a1763als738767a91.0.-pod-prod-00-us; Mon, 16 Dec 2024
 23:18:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbR/lR2B5mRWCFio+iL8RbzTovgc3gX3P581l7dW5Y2rAJUCm5Y+4n8EpfgTAr1LIP+3AImB6H+P8=@googlegroups.com
X-Received: by 2002:a17:90b:4ac8:b0:2ee:5106:f565 with SMTP id 98e67ed59e1d1-2f2d888bc82mr3179906a91.16.1734419901374;
        Mon, 16 Dec 2024 23:18:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734419901; cv=none;
        d=google.com; s=arc-20240605;
        b=f2RBj1VkZkTrvQ1zT4pXebbyNm1BPZeSH2QLWwrWXxakqgGi/8CmzdZAzMEXvw5n3o
         sCBEEv6JbLMPIRl0Tc5RSnFLWql9xHi8gAQIRlKaeMiCPgMx5KfkQh3E4qX0YS7MIpZC
         xX0lih+XphsM9BWH9ClWfOZLPClqH136jjjXEPccegyLPq675aeolSDSqgD1n8J1evrL
         RYQ8ecfsI33qSYZNkIZfa/bmojFa/lt1/iLOLOajapYNvjfYzZtr5md+I7iUEH+1hsP4
         bkwssqzKtk5c9GMuTfXsX31Da7MmgQSrFj5Be2+We9YKC81Fi8eVFP0Swp5w+EVX1QGK
         2n2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pGC/VAvbGSKjLlSNnphtkOlRQ0ua6h7CPj+fmvqVWUw=;
        fh=gGkJO7S1KMg4ChGcv1U+ICSDaY9aFh4WnR7mj+Hjb1I=;
        b=Rq3Qs2N6MLhb4Xku/HLuwxTW1M+NnYW7yM5dDxdgDsIVqqZJeidI7dViZpz9ePzEmZ
         Y6vnBUGUcsqbiJKUm2Bx/4S8jpLuqjCtMnCSPa7FEzvnyMk8ZzajPkzWPY5w2x4KZrVC
         NSm67oeXszwfwCaSen0O0NRr+yeIQ5w/ng//mjqjwTi9ihPiIoADIOK6xXX0ZyOT2BaW
         FUvXQyGplRq7uTikQpaa8LdDXueEIwYUH9dATCVJnahEYRtxqHlXuQrYVXPp+3qyEWyq
         q5c03oZ+EeLzYKhalkRLQwePJLYWYf3xs942s00tmGQcPmBbRCoVNlxEvvEISUsj/EdB
         PeRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lFQleMFq;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f2a20f88c7si551423a91.3.2024.12.16.23.18.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Dec 2024 23:18:21 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A571E5C5ADD;
	Tue, 17 Dec 2024 07:17:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 56FD7C4CED3;
	Tue, 17 Dec 2024 07:18:18 +0000 (UTC)
From: "'Arnd Bergmann' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcov: mark in_softirq_really() as __always_inline
Date: Tue, 17 Dec 2024 08:18:10 +0100
Message-Id: <20241217071814.2261620-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.5
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lFQleMFq;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Arnd Bergmann <arnd@kernel.org>
Reply-To: Arnd Bergmann <arnd@kernel.org>
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

From: Arnd Bergmann <arnd@arndb.de>

If gcc decides not to inline in_softirq_really(), objtool warns about
a function call with UACCESS enabled:

kernel/kcov.o: warning: objtool: __sanitizer_cov_trace_pc+0x1e: call to in_softirq_really() with UACCESS enabled
kernel/kcov.o: warning: objtool: check_kcov_mode+0x11: call to in_softirq_really() with UACCESS enabled

Mark this as __always_inline to avoid the problem.

Fixes: 7d4df2dad312 ("kcov: properly check for softirq context")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 kernel/kcov.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 28a6be6e64fd..187ba1b80bda 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -166,7 +166,7 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
  * Unlike in_serving_softirq(), this function returns false when called during
  * a hardirq or an NMI that happened in the softirq context.
  */
-static inline bool in_softirq_really(void)
+static __always_inline bool in_softirq_really(void)
 {
 	return in_serving_softirq() && !in_hardirq() && !in_nmi();
 }
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241217071814.2261620-1-arnd%40kernel.org.
