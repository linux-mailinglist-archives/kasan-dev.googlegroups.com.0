Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXW2DXAKGQEITBB6WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B2725102C1F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 19:57:50 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id f8sf14114449edm.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 10:57:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574189870; cv=pass;
        d=google.com; s=arc-20160816;
        b=f5AScnK/gB1D5EyFt21Jy3YPWwIxIkmt7nT2SZxDdrIhD5rLvt+0YvYp07Hy9T8TJe
         uuXemSrTgYqy626OXKIg8aFVZ31TpPz5sO51y50yfKk212zGP+9ZjbmA8OOuEa64WIW4
         Zh3buu/83ybSTurnnPFZHcUHH8BNSAfyzE+JI0o8Srp+B5zRFIa9zu0DD9eaOOpxFUd1
         bu973a6w2GijOkzVuh3N6QN81iCwOZvMyLS5zVxAD2j5fLpcvDHowhRusA5nvNqDM4Q3
         ywJjFpAzYFftyeZyRAgXRcJKDgexHsz+W3DjUIVk5L+otQ530Un7zU49ynkisI4b4QIq
         7Z3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xePZhc5wIGKWqwLDL/vbRcPHjgf9uqGuzy9yEdb1HiQ=;
        b=IySWLB0Y4tz1eTYGqZnhoy+cLoThkKOqYE3q0GKUqqcVc6YVtu5Oph0bFsUac9nQkn
         dE++7S/t768LdRJYyDllAW2PchVLRYvjo9zxGJziudQOGkW5inpxpXATA7KHkdH2OOMZ
         CDEmEfCSk04ev1/jyBR24im29n1nR4jZjKyKJpSWLX+OmTjlJ7K6GSnC6miJptyDvt7y
         1jUWPZdj7wRPJqzZILO3dcndFSy0bPpRBuAS66vTmKbHT00Ra3Cqym/LNSnguD1PhlNj
         CHW/8HODK03i2ISUgQTEZM1jkTnigacPv6VMRIxQm3feJK6SDU74q2boqOOY03iJriOj
         Km4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VVN/i5s/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xePZhc5wIGKWqwLDL/vbRcPHjgf9uqGuzy9yEdb1HiQ=;
        b=thMYACx9KBGRP4iIl1FRAKBGFuL4i7jR+17mHzEcaUsx4qhocPZRzjluOAnD/z5FAV
         0MI5A5mKCz+b6US87anAQTzUF1xC5B6jfEuZ/sqsuGIEti9GnRVDSTVuhMm2poXax14U
         HFqDsQUwWCPOlIPQtBAwJfBVhCuCI8wfQYq2C2wtmVRCFjhAylLGpxuY04RKENI19nB5
         DCErS7W6KKU6J6QRRDG6Yy81BIvv81KkBoGxtoaBHtP9Crfjbgo6cQhW42QAFXFqN5Uz
         8iCLU5wM30/r8cXFwJa+FljxZaK/U/AvdnDF17senEaAzgPLio9e4Zh6soXBlqxI2fei
         YlSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xePZhc5wIGKWqwLDL/vbRcPHjgf9uqGuzy9yEdb1HiQ=;
        b=KJsaP5t5y+Dt83xTXuW6SxeSq80gFCL5g6O4qKstA3XW7FmfoJ+7ThhfC6aYaBYcVa
         eWhzwKnDEA+myI1cglCMTE32uYtRRVny3rRLZ4ig7Vf3GvklCoI9i++F43jG/nBWFWjx
         1v7/iqBKy9G0dIusby34kp5kc/Lw/TapKKEjnBvY156OpdAdqeMREN9m3Oa/oz3OGxAg
         TN5kXS7X15stTzYc3sF/+GJq/zCjgK3RCXPTsMIYIC+ajjgYiZ3BUWcc7T4JAhCuZ5Sx
         y8seVLQmdyZC+SxkYgJA3EE5LIzrnmVg2uRIu8FKjAzMlNsNjV634P203CZ9PeWax8fS
         I7Rg==
X-Gm-Message-State: APjAAAWkDp4TZbjco0M3GRBSTXFD36kOguq+x+4RzCXK5k0ALvpo8uHa
	cnEl+0sQCI0Mf0lolrtSDrA=
X-Google-Smtp-Source: APXvYqz02gQMVopjhi8PA/Neodlaz2MnhySOlGOrk3b6pABjA+VPBE6A2vEOqrwCWogbfa7hIvZ9Vw==
X-Received: by 2002:a17:906:7c5:: with SMTP id m5mr36459679ejc.231.1574189870425;
        Tue, 19 Nov 2019 10:57:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b245:: with SMTP id ce5ls7993399ejb.13.gmail; Tue,
 19 Nov 2019 10:57:49 -0800 (PST)
X-Received: by 2002:a17:906:95c1:: with SMTP id n1mr36544107ejy.158.1574189869774;
        Tue, 19 Nov 2019 10:57:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574189869; cv=none;
        d=google.com; s=arc-20160816;
        b=B4on8XYJkHtxg/lKEQrDrv2gKo41U/iHjwwvCt8Riv6gPYRHXqOUpRqKIqihOoCH66
         kbtODZo6oWmgGghwJi5oLwvQW3h4jAQCWbuPYWtDfCRTK4C442gbzo8wm3w4gzlGw6YD
         MWCcJVdfXzOxcvvT9fdFN9NHOlA6tbI9ffnwMZ1rGo5KYV/lB2GLBcQkKBG9C/v7m8gN
         ISgswLkx9RAakYfCLlfrGjIgV9cG0t7lv6VkUk9yWdlPld3xJ4AiuxyGZKW9gyLTivsl
         AsNSYIsUjJJ5jsl74Bd/qEE9zSgCEk0jti83v4B1I4f2x9cHYOVKRCD6OnCl4MpDztER
         HekA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AlF55tHmwaf4MqjtYLnLUKyMqEVxUolFQJuCOS0Pms8=;
        b=bHIg86vqNUYRWhoRdvHnx56ybblrpjJU6bFrBWTzM7ePBmp/8/aHy+5hc9A2jpuc32
         R0ZB1QyZ/flWsvxlzVB+R/ALf++4qxh2nl/ySgmVu3Oq7amYc9qAA4GmcgBViWHccJia
         ObUs8wrhVVFVj398NCy70k/+sxeLze74KJ1zZoC0mu2gWoXScKQ05aJ+JzFd9WCtY4vQ
         tkmttIVSj7tm6IdT8ov1bUUZEQawYKZdcKIja7wltkEqcfquxFuiBfreshBwQWuFijnK
         +qEOMv0WH9rzVlM2K1Ibc6Ys/6siNSlhEEYB4Y4i2FOk7x4Uks+hd+sZ15CTF7BK4daF
         2Uag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VVN/i5s/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id c28si1258772eda.4.2019.11.19.10.57.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 10:57:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id a15so25183246wrf.9
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 10:57:49 -0800 (PST)
X-Received: by 2002:adf:ed4e:: with SMTP id u14mr40406481wro.132.1574189868998;
        Tue, 19 Nov 2019 10:57:48 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id 19sm31875516wrc.47.2019.11.19.10.57.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 10:57:48 -0800 (PST)
Date: Tue, 19 Nov 2019 19:57:42 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Randy Dunlap <rdunlap@infradead.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Linux Next Mailing List <linux-next@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: [PATCH -next] kcsan, ubsan: Make KCSAN+UBSAN work together
Message-ID: <20191119185742.GB68739@google.com>
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
 <20191119183407.GA68739@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191119183407.GA68739@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="VVN/i5s/";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Context:
http://lkml.kernel.org/r/fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org

Reported-by: Randy Dunlap <rdunlap@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile | 1 +
 lib/Makefile          | 1 +
 2 files changed, 2 insertions(+)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index dd15b62ec0b5..df6b7799e492 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -1,6 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
 KCSAN_SANITIZE := n
 KCOV_INSTRUMENT := n
+UBSAN_SANITIZE := n
 
 CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
 
diff --git a/lib/Makefile b/lib/Makefile
index 778ab704e3ad..9d5bda950f5f 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -279,6 +279,7 @@ obj-$(CONFIG_UBSAN) += ubsan.o
 
 UBSAN_SANITIZE_ubsan.o := n
 KASAN_SANITIZE_ubsan.o := n
+KCSAN_SANITIZE_ubsan.o := n
 CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
 
 obj-$(CONFIG_SBITMAP) += sbitmap.o
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191119185742.GB68739%40google.com.
