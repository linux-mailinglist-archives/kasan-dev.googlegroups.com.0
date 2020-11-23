Return-Path: <kasan-dev+bncBDX4HWEMTEBRBONN6D6QKGQEN5ACGHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 85B1D2C1537
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:25 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id g18sf1425289eje.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162105; cv=pass;
        d=google.com; s=arc-20160816;
        b=zHubNYY2VjWUU33djjoLjWiABfdIwtPHAaDtzyYVt5BFNnCSxIVGy6KNGuwmarKl79
         AtZOB2u8w9v6NJ5rE41SUHIoS5WjFDlfwQO76YiBGq1JqeAD0OZTh50SLCa5K6MRYQF/
         V9otmreEq5B3NgVka1fRpiQ/HPQVoE8AqOH77Fpvg0fR35TNfHbtx6Uhgc7cjj7o2A0M
         dqqcLq/g7ILJ1n3jTRRc/214retwPU+tPuKuuDhh4/IGtI1+7uTbxnIzb3vX8T4IT1Qm
         CPhRUIo0I9u7WpfeK8Evg7HilAsKaLemup21cWs3UfZZ7CzREq5ZzSdiQlMlC3z3xgWe
         VTFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VLX7ng2LNbW8ILv8+xHDPv/Wozw41SE+/FbC9V1LJvU=;
        b=0cY4ho1XbXTVR1i5K4GoOqE3LHjGLii8M9/ZN6P/3sHe2iQI9/6ZLhlxBY5GmpPWLM
         EKTxkwSs76oi5/ngeZ+xrKJxYws76dskFU3EzrpvfGOkoMAx0bY8N8mNOsi34s0gNuzq
         HRq1NBAHykpB4xxtQiwvyfWbzKtIQJMEuqRIch5C6ICvUw0TWPOvqhn401ldxaNRRvui
         JsO1zhO6brxOipKuYZvRXbM3NkvRA13kBWgEwyKNkhPA1KZ4sthkbkN3Z0pQpMNnjK98
         sR6WxI0RJoCl6LuISxUbh0SWR1uOQTAfn2WlLojuCEDjLn7kPy0Px4YAEz8WXKQFKrOU
         pcpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tNrLX9o0;
       spf=pass (google.com: domain of 3uba8xwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3uBa8XwoKCdk5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VLX7ng2LNbW8ILv8+xHDPv/Wozw41SE+/FbC9V1LJvU=;
        b=JB/k0fu4qU0UNIwjpGxkA5/+aiWP/p3+K8PJ/YDXO/J44NHvloVFnYHuwWOZ8CFKK0
         KXJcK6hosSFOCtZaTpTi2rO9F4LXzO148Ty+Lz+keHKRTIEp1ihYvlkkEbtpEg3WyWmq
         xAjziwh81Bz6bboDlyncj62+jXGYBtnTJsT8WjmaXFwWFrXv5OAdhleOeg8rjE3JQ3zY
         0c3ORiK1pda4zNAEBhudgY0/Sjk90AN5nwgfNTLmdbY3CYRRfdvIwk8yqHB4N5CFlisU
         OUeVn/ku2+1TBuZ/c3D/6CaJytSrGuWZGEt8oGmuzaeqgL9Qlrnm8CXjTcw1VIig2Qee
         Eh3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VLX7ng2LNbW8ILv8+xHDPv/Wozw41SE+/FbC9V1LJvU=;
        b=Gc+i0Lo2OUPRiC4VQr16IXMhyQAP3zDh6h8+FbjPsNDnPo6xBbxJUNFOAW4d6W+g1/
         rjWYdImzRUfQ7HpSHNfcBS9i8TYh0rg4ZFduJc2CJ6TrxkElUVaT77vy9tKG0CkZOBmN
         D583hOEMC3RlHLW6VK7BPEre+UIfxfPOYfBfjyx6BOp0xQIzcD58KSAg+CRMpoYdlP5z
         mnrt75Tm8NRF++nsBEwBf8jQaRK+7bLAPaWqjjVSWQDKY29LJvYyWL2s9Y7xzvmw2Jd7
         7tteDur+fYwgWyTmhph1liYc4i/Jj3HheIOPhSP2JEHfGh3tKBf6/AhGVw523rxqWaS4
         QH/g==
X-Gm-Message-State: AOAM532d0QLVyxHie3geklZ2AYpIg+iD1K3kC48dLqCFMAFAoOOTe66g
	/lNNPKGcD0PAy4v9+nPPyRA=
X-Google-Smtp-Source: ABdhPJyqlF6ndEbppEEgTq1VZlI8ovFVQiAZ588Jw7RMTn/Xy/S4ojtEr9oNSW7cbuyPh5lONx3UUA==
X-Received: by 2002:a17:906:13d6:: with SMTP id g22mr1244851ejc.240.1606162105315;
        Mon, 23 Nov 2020 12:08:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5591:: with SMTP id y17ls6577570ejp.5.gmail; Mon, 23
 Nov 2020 12:08:24 -0800 (PST)
X-Received: by 2002:a17:906:6947:: with SMTP id c7mr1188329ejs.533.1606162104475;
        Mon, 23 Nov 2020 12:08:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162104; cv=none;
        d=google.com; s=arc-20160816;
        b=SGCETcK3SKUzgvXgDo4M61xZWPoY6tmghBNzOYPEnSNT1CMj7ptceoyYJr2UfhcQfI
         sLsGykSmkw4jBw/F4P0jB4Xf/YM0UYCwP8zBvAyei+GWO4BZ9ziwoQCXQNzwS8yPU0RO
         NWiTvYizNZLCN1Ybv+tIjGgumpauFo3zeilGlFM+Btv+Pbc/kOnAeWYOAk2YwNuXdq0r
         bni//VhGu+JjNTdsbMYjS28uRZ5XntyqXdydL41vq/jxI6zYjj2DGHf82uxMZy/5uMMX
         6WgeGne6/UeTA/731wXiIuejv6Ee20znZxEaO1e8D0oVUXQ/5tyuYddV4MbgEGqqSNMX
         LKQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XfXa1jt+0lTuh6OgRbLfYhhuoSJQhOjqmzv/mbzZDEM=;
        b=AYWrn5MUbQIn6Yyf/sheDSooRTWdCUKV1TI6C7P77utOSM7lLbFtoP1NvZQgeWHdq0
         OgWh24x2zeinM45+9rEtH8mA6WzamklpyNJgQv+CF3S9tZEmcKaAW7CvK0R3GVxSnx+s
         /+98HMndlCaxYEDK/KMWCfAqXcjQ5GigPr3fK4G2lr8pbG8Y4DW2/EcVXfpykP1LVqxb
         XlE/jGyHwElIa3Wac2L7AAARJz1DRwQxlbqG1hwjSel4dw+KEsMVTrjk54G6k2CIPVuj
         lD7Kj3491QU3naVB3r8GXP8g9K+ePPJ8Jngo/BxWx5qnTYqyHtwkglDgS2BK+zk5KcIh
         vUeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tNrLX9o0;
       spf=pass (google.com: domain of 3uba8xwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3uBa8XwoKCdk5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ck1si344743ejb.0.2020.11.23.12.08.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uba8xwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u123so101353wmu.5
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:10cd:: with SMTP id
 b13mr1469712wrx.220.1606162104203; Mon, 23 Nov 2020 12:08:24 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:26 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <0c493d3a065ad95b04313d00244e884a7e2498ff.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 02/42] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tNrLX9o0;       spf=pass
 (google.com: domain of 3uba8xwokcdk5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3uBa8XwoKCdk5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 8fb097057fec..58dd3b86ef84 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -146,7 +146,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c493d3a065ad95b04313d00244e884a7e2498ff.1606161801.git.andreyknvl%40google.com.
