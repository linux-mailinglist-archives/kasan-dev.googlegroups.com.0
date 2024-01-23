Return-Path: <kasan-dev+bncBCF5XGNWYQBRBW4QXSWQMGQES5QOWXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2593483791F
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 01:29:17 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-681998847b0sf72586206d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 16:29:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705969756; cv=pass;
        d=google.com; s=arc-20160816;
        b=am/4+rOrvUmJr5WhVVHg6Fc4pzdtSn2OuSatJcwsAvRiBYcVYVqCj59p4zvwHd8UQr
         cjkaqF9iNeBMqeKhLmvERtsYr9FbQ+NA8RGShT+Bc1FPMfE1pT3LDoQ9wYHk5VCGxn4t
         cML8V9glLSOU3Uaurn07zf/nmYl7yZIbRP7wC2iPxxibOIqKD5sUYy3u5ZmjOhz+IwEA
         sRt4dsz7F2aKjoQsBc0O1/MrbV9xaPExW1dIW6QHx90Jyyss7phW/0egpRRS+eT+YkE1
         8DlsVfdsPP0M8eszQS1t5esFlZb6N2c80HwS0A9VJCWGBaa2hOG75+E8Too+MlwAEoaX
         kdBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xa7IF5kqVMB+ahLp+eRInOTPHUF78YamWB+alLrQlO0=;
        fh=exLHg1h0eYU2MHAZaFzjrfWqp+NFsmL6zpHEechfWyI=;
        b=mab85awjUSzIQPb6cmzjju9Guz1fC/d8GCLnBIIl40ItMaC+7GjSxnPiB+9SofjCFY
         YUUWL6BeEnWpjqZjkxVThqikTBrhHQMkosCl6DdV1w5TyWxsev0w5SAt+6s/tHRINbOW
         scYlO5GfzJSQs06uSjLKUiMZG8k8QEg8lyNTYONy0Qkig1zlSkbIdRSJrRAVQELuujIN
         RfW6GUQBH1EI0+/gBaf/7ONl2CVRB8zfTuHoFfma0Wyiu48eIvlOV2NakYsU2qwAj24B
         Z+MRUVZrAQks07SdolAh3uBernqIibKfrkWh00cZhe104KWMpByuxYTVt5qrLXI2ux8w
         Wg0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eJ+fKxfh;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705969756; x=1706574556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xa7IF5kqVMB+ahLp+eRInOTPHUF78YamWB+alLrQlO0=;
        b=s6XUdKJLWuHi3Bu9oVGemjXCNCGBEm5pFIkV4ooH/Rzoq2ugk9MhjMw10uiMrAFBVQ
         wr7ICrcXutzkGlJ1M1IJ2lvoS+enMy8p5XJijL+DDFbI9yubmLlcLcTA0rB8JdrZSAQ+
         eyMlAun3YrBjZC1A+NtNvjQtITlEe7SHeN1c/whv9aaR0L6eoRlN7n0RXenbkT6z7AwM
         0QnhzhXamyKzhmt5i3SN5qgs3jWtWyXcNmBWYbmWoDSPIAUajGV4Ky4da9tz3Q9MnP4k
         jtN2ihGH8lNJdIDbQGj7H0aJC+zZci7sCKK6UptVxlQf0w3YXGVHWIk5r/ANShL3Kk2t
         5cgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705969756; x=1706574556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xa7IF5kqVMB+ahLp+eRInOTPHUF78YamWB+alLrQlO0=;
        b=YBSt6VYst9Fo+oSsIidhVVhfu7nwqrnXB14HpXNLX4YOGpWDSjS8D19Ztbsw/MDQ+S
         GOXGWxl7clvU7PmRDfVE9L5n7vxx/CE8t7qpFdiMcexeMPvDn/pmx/oesr0Tm3tV9QwM
         HAJYGDU9i3fffR2BjwsaWylNAdvjh2aKzMDKNQQaIsMzZSx924D9+EX48/t/pzFqL8R2
         iEtUSt1OtSyySSFMxH7GMyKM/GC30NiySpqPsupOwIiIOkdHB/F2izwVr37/I1qCQB1/
         CM55AEOuHS+MKj9PFNO+2qntZdwofkZljr09rfpC8NToePFj+hlQxHie23Rsg16I65hm
         2zRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzZLAwGEda7x5NJJgADFD8yHqINNGXLGxcdQyrvVES3iEuSFIuX
	IDa+xBfoWnWGbOCA6ASoAlURUjJC71+tQXqMctR0rTcjzxMvW2qe
X-Google-Smtp-Source: AGHT+IFZV2Q2Lxww3ejGJMtPJyJXg0B4XwkA44US5JIDAI1Nl6/bDFx6FR6o9fvL+xlCB9H1AMzShg==
X-Received: by 2002:ad4:5748:0:b0:684:d2a1:990f with SMTP id q8-20020ad45748000000b00684d2a1990fmr99744qvx.40.1705969755820;
        Mon, 22 Jan 2024 16:29:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b3ce:0:b0:681:972e:6948 with SMTP id b14-20020a0cb3ce000000b00681972e6948ls1576081qvf.1.-pod-prod-00-us;
 Mon, 22 Jan 2024 16:29:15 -0800 (PST)
X-Received: by 2002:a05:6122:1d47:b0:4b2:c554:ccfe with SMTP id gd7-20020a0561221d4700b004b2c554ccfemr3554921vkb.10.1705969755247;
        Mon, 22 Jan 2024 16:29:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705969755; cv=none;
        d=google.com; s=arc-20160816;
        b=u0FPKNREhTfQG9xxTmm/x+o+PUAptV5TD9IpGXCqsE+GAX5Q7nkJj0gyo7F1Pc/WGW
         hIaY8P4AM26QI05N1BkxiIWXcQunxYzS1pPnVjD4RliSJfrHawQ0m2buZimqzv9TS0ud
         FlUcBt1BLGIEmvVPB7ydVdGHEfmKeUBzFU4h2DD7Ikq9IaBaNJ/Texhac/3svXEC1irg
         TWv+nkgw8rEoQz0MBWOmgPwKkMkpROy6ADzcIFI/ei7/RpSVUjOV9nphcaGZF3BT+Qgg
         iFGwGBQmA5GqjybVhnmcGxK//T/ivYhz0Bczi0sI9ON8htSgl93882+lsg2Cwqr+TGoV
         uoTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tNWz3k2XvGRlF46qJEs9zgm+bcxMnCT9t6UFjEF9Av0=;
        fh=exLHg1h0eYU2MHAZaFzjrfWqp+NFsmL6zpHEechfWyI=;
        b=HC7UY2KAIv98EA2IEqlYKQk/LDY8wEzTvANtJOxy1/ha4mE3YmHnsnXi+u2JhF85/k
         RXVHX7yThWzsKSOhZUC9+UGPf6iaFqOQRovRgWi9JW4vySUHWhjBCy0jzWJrwvD4JjmD
         nHLUvgHui0yw9kESrVdWwfze67r6x5F/XR/1cVDDNYMto7HCu9y8roV+8KYMcDJ7CLz4
         G/NVJnzi/d93Ub+0H7wvXNSVyMjMLacv6fRptmlhwtThxJB113eZ7OjcE98l3wp2LN08
         L3qdC3QiKYZTrRAIbBVdd/MJN8Dx5M/WNEFd1AE9q+RFP5ruhExMsLxjukP4aOVMoXP0
         PNXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eJ+fKxfh;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id n64-20020a1fd643000000b004b2e6e4330asi2899618vkg.1.2024.01.22.16.29.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jan 2024 16:29:15 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-1d75c97ea6aso8724375ad.1
        for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 16:29:15 -0800 (PST)
X-Received: by 2002:a17:902:76c8:b0:1d4:52f6:e046 with SMTP id j8-20020a17090276c800b001d452f6e046mr4743580plt.58.1705969754414;
        Mon, 22 Jan 2024 16:29:14 -0800 (PST)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id m20-20020a170902f21400b001d74ca3a89asm2622159plc.293.2024.01.22.16.28.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Jan 2024 16:29:08 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org
Subject: [PATCH 55/82] kasan: Refactor intentional wrap-around test
Date: Mon, 22 Jan 2024 16:27:30 -0800
Message-Id: <20240123002814.1396804-55-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240122235208.work.748-kees@kernel.org>
References: <20240122235208.work.748-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2504; i=keescook@chromium.org;
 h=from:subject; bh=6qOMhh3G8d7Y+vBH+FchTOnAwDno8ofs9WTRkK8e+v0=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlrwgJb7T0nkCbfHMK37KL55oiDeDfmOiEx7q5q
 XThjlEKQk+JAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZa8ICQAKCRCJcvTf3G3A
 JoqqEACE/4PoGFKLHpVkenKHgiwQeIuxCim9QWJGC+MdId7RYwearFTzkOQl8zglCUIZNl7fW9d
 KYyBu2j590qTJ3ins8G5kTpojs3DwiSG7NIjlDCuYemtfGOEDj4muFXpG5DpNNB/SXKfge3xXDy
 5WYmb/fU/J7+bo64TYtiSNKLR2K8Gp8i7ImUFx3yHYAWZufYCVg181wkAjQdVE9QDYyvZ7sGJoD
 mZvg2FSl8NJ5gNh6/n8lFHjoebiowaqz9rHfRIb9H0ruQMkeqFkKXhx4aTH16qMPf0eWME+Y+7J
 ogiYkcB141OqPEDQ2iR46G4NeG4lrsoMCZKzlBhmUT7RxPtYuZcvsCqZSAzAa3UF1RWmwdNOHWT
 QKCM3+s+mU5c7hXehiPzTXpwMMhUbnuW9WVWuFQzVH5K8RvofBCN7bnZZCKdDAoEN9Cc/sKYxEr
 q/BRzB2azJPyZ7AETk4B2xCLsuXEYrgz4hMVtO0QV6idTMpfIjNn4IgVm1nNoQUli5kyJqdcnf8
 gpz7+LeZbIwoIm4heS/k35pUDdcJOIRgPHC9zHqEIgxOE5/Jcu/+iMwplKoCiC7xP29btiDDmns
 OugXywD0SNhQjOaJt1krhL+j3HJZvwk7kx1o6FV+/GJoBK7sRO3WFjkmaJ8winj+Z4BPzvkMYuJ +inWzkA20S9t7Pg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eJ+fKxfh;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

In an effort to separate intentional arithmetic wrap-around from
unexpected wrap-around, we need to refactor places that depend on this
kind of math. One of the most common code patterns of this is:

	VAR + value < VAR

Notably, this is considered "undefined behavior" for signed and pointer
types, which the kernel works around by using the -fno-strict-overflow
option in the build[1] (which used to just be -fwrapv). Regardless, we
want to get the kernel source to the position where we can meaningfully
instrument arithmetic wrap-around conditions and catch them when they
are unexpected, regardless of whether they are signed[2], unsigned[3],
or pointer[4] types.

Refactor open-coded wrap-around addition test to use add_would_overflow().
This paves the way to enabling the wrap-around sanitizers in the future.

Link: https://git.kernel.org/linus/68df3755e383e6fecf2354a67b08f92f18536594 [1]
Link: https://github.com/KSPP/linux/issues/26 [2]
Link: https://github.com/KSPP/linux/issues/27 [3]
Link: https://github.com/KSPP/linux/issues/344 [4]
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 mm/kasan/generic.c | 2 +-
 mm/kasan/sw_tags.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index df6627f62402..f9bc29ae09bd 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -171,7 +171,7 @@ static __always_inline bool check_region_inline(const void *addr,
 	if (unlikely(size == 0))
 		return true;
 
-	if (unlikely(addr + size < addr))
+	if (unlikely(add_would_overflow(addr, size)))
 		return !kasan_report(addr, size, write, ret_ip);
 
 	if (unlikely(!addr_has_metadata(addr)))
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 220b5d4c6876..79a3bbd66c32 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -80,7 +80,7 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 	if (unlikely(size == 0))
 		return true;
 
-	if (unlikely(addr + size < addr))
+	if (unlikely(add_would_overflow(addr, size)))
 		return !kasan_report(addr, size, write, ret_ip);
 
 	tag = get_tag((const void *)addr);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240123002814.1396804-55-keescook%40chromium.org.
