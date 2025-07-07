Return-Path: <kasan-dev+bncBCKLNNXAXYFBBL4LV3BQMGQEDYN5PWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 559BAAFAEA5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 10:30:40 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3a6df0c67a6sf1653082f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 01:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751877040; cv=pass;
        d=google.com; s=arc-20240605;
        b=aTAiedHexBJUX3mlX0IcZ+VrMN8PlPxpGMZkFXSIhUhHoZajti1bWqo5g7pMnj1On7
         O7pP4CIKxuguRKw6aHX3+Z9j2mQn5vnfgw5Zo/QaDXMwpZNYjSyN2UVK4WesdDtQA0GS
         zjwmE2oqs7NzYfcNL648yZfbYkhcxSnqHQJcYyareWyawP2dt1QpmbHzeVAo/ejaws0T
         I9t6gbj45WuFLA9TkJoxLI+Jv/zeMcI/7Az5fOL83L8MCQd51Rp6XtipLx0I1QhwknfT
         pPfC5R8jITaJwM69ITygUItZNOEiT5X8L9zKvvX6yJboQx8X/+8pYl93nDiiMA9SiwI0
         WPSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YiNHSiLOdpesAj51vRBnIA8JcVV00V27wHQEL66Ul5Q=;
        fh=gZIjhRjzcFAore/ePnVzbwasApjUvvogzx/hSB10unQ=;
        b=jannAfnx6ZToQW1ymB4jMOHHztfMobjTPRPSrgLdyt+kqSS4lTEYj7DqS71LdxXLjT
         9+qibcQuAYL4wE3Gsy6ryfRpWjT9p//nq5Az/hqQsiueaf0naB0UXKHpa1hrJC4WVnIq
         VwkqrBwm0a/20B4U/UTFe7Qlg7ya40MmhkF06N9m9T+tLynelAa18k/PTX1el0xl08QJ
         Beg9ceN88bWcdmcJjBRCap9o8LcGfk6NS16HUz+ZEWv6yb869ZoTHJkbfNYN0i/9Ljgl
         Ep41Ou03c6pEiF/WcOYQDRwtGj2/unyp7eZkXqJI2L56rxtDSdjUtu2rbTj+Ru5EgbiZ
         bykw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="GQkePXi/";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=1JxpmRK7;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751877040; x=1752481840; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YiNHSiLOdpesAj51vRBnIA8JcVV00V27wHQEL66Ul5Q=;
        b=OJqf/vsSrZIlSLdkGx2UqLkuLxXWTjL9rsrgHrwGB8gxR8bCudJjrDz9iB0qpoqXg3
         PidiDRyMEfFnkaG1YULcW4xjPZCnuFQhVQ3Hydi1KZ63dRKuIAlrQB1aO5cRhjCUkud1
         iXR7lpbQdMobaIyx4Lf0Hhuy3yfekuuWxw3Bp8fCazQPjRrj/WFbv21y9gEdQQhps4r+
         NBaJljwdXo1U6Xv/OFAF19+rwWbJoZHKSTjUqHFwjLHAcXG2K3axAQI4J/D9ICOUkbLf
         E+C5FTR6LYfygpyjRbVhxClZEmSA8JyPgUBVkNk0UIDNzL91Gw2R70VIMUdFgexCXfwy
         B9VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751877040; x=1752481840;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YiNHSiLOdpesAj51vRBnIA8JcVV00V27wHQEL66Ul5Q=;
        b=Q6m/eQdUJOGEBGsp8MkVSDf6cxGzP2CvUQ8BzQWtOSGWnkmTn8l9p9YNCh9SyOhIcW
         XzSmKeLpQchOpwBicPJS/qe3y4pjoVHWSe0OsS4NsOQ1E5b7q95Uv/PA7NG69H2AvfRO
         OaE5Axk/Ma1rm543reoRVWS7CzbVBJwn7iyvcHrKb2IUBQ9OA1LgxMzyjWhz+m8ISLnv
         lcx6hkJZaHgaS0R7k+oVrEMzav/22yZRoeMNOz7jlgiQQj5jEuKLbMlOLLAv7Yy1gPLq
         QrlY9UsrTx0slxhPS7cdRAX8+jT8RIOVNF2vY4aLV5aJ+81Q07bAJThfN8PxyeaiXhJY
         AnAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUviBgimo69ikcb8Hck/8qGtZ5QqovbCm7aG59gPuOETjFVZHuaJaFigozwu3UfMlE0Sy/GAA==@lfdr.de
X-Gm-Message-State: AOJu0Yx+xUfLuS2ZWfLcmo8TJzScKtlmWZPZiwUpaDfnpzOuMUIj9Grn
	YoEw0BnCffhugfO1NQfSThmaVMcK3Zy3Qv6hmCR7NoYdLh1l+Xs80dui
X-Google-Smtp-Source: AGHT+IHa63XrrRGtTv9hFWxT5B7UAGwByO0qnc0xD2sj7c6QrdCoJO1rKzMnakcCXp+sIeXZbi47fw==
X-Received: by 2002:a05:6000:24c9:b0:3a5:541c:b40f with SMTP id ffacd0b85a97d-3b49700c57cmr9011328f8f.9.1751877039563;
        Mon, 07 Jul 2025 01:30:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZ4smGO6qz/J3TA2zciW8fo5EEG1HACrGpSAGna/aWJg==
Received: by 2002:a5d:64e6:0:b0:3a5:89d7:ce0d with SMTP id ffacd0b85a97d-3b49744b9fdls1290726f8f.0.-pod-prod-09-eu;
 Mon, 07 Jul 2025 01:30:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGbhq5B7gucFd1lqvP3MvrjnCVoghg4j3iCyvYWf6PwcA4AEyR49O7mbMpQBVPmAm42MApnELwwa0=@googlegroups.com
X-Received: by 2002:a05:6000:2006:b0:3a5:2cb5:63fd with SMTP id ffacd0b85a97d-3b49700c452mr9384999f8f.10.1751877036452;
        Mon, 07 Jul 2025 01:30:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751877036; cv=none;
        d=google.com; s=arc-20240605;
        b=O73DuSUcEVuqvn7hqweqoivqhIEI7mLP6GF4bYblejHVR0F77BW5sElvZswEO3yvdc
         UWXC1xZTgAnCDOCIq6cLMRt7igUlSoK0ZPfw0UMsVA2tVX7yIQFA0w1jFEr9ai/VGg+G
         on7D4haNE3nJOOplJCqq9BQXUfs3nwvPkHnw6s4GD1MWRvhUdqjMrRmzC/tIGCAn6Dc+
         fNoIR1jyO49M2CeljKo8uDEYP6HMap9jf/Oq94LmtOYu54SobPWod3++byPZ0gMoKvKF
         twcMO1+s7C55XrW1J66F+OJNvyS3W370krKR9MjJueKjliJNkNu0D5joM8p8cs1XB/8v
         /KBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=pneG73bg/LVzrOhRvixJzllQbSTiEbr5I7XeAi0I1XY=;
        fh=1w8HeWEvSlwODmpRGh4OdOj4E8TW8kP7woR1B7ALjr4=;
        b=bAXV5AggdsjzXLQyt5zRwaRhzBIVXq/HL91lA6pZwpMmF2tN0yu/uExu9tVAKV2Tpv
         xmO3i3SX1AusgCR+DDlKJV3+m3RimkG6zA2tpYP6OK/ZIpRW22+C2zUTaLJdtZ3U6xNQ
         5jDGIql4gA32RTTF13Xvh1tyMyKz6oE+kcu0+Dj8d53L/23gqMHCWYm7WtnIfbXsRFfo
         ZPASL97WNO+QKbgb7EWCHP+tMqEODMwdgrklVS8kgAWgjlVqsPPQOGZFHBI+t3s48EMD
         95zHlqJYK3mc1QyC6z/3uRU7MH17FvCr0p4L1ol1d6Fx5qhCtuCoQF5gbyJzqWQ9VIp+
         RnbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="GQkePXi/";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=1JxpmRK7;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b46cff5ef9si241237f8f.0.2025.07.07.01.30.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 01:30:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Mon, 7 Jul 2025 10:30:34 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	clrkwllms@kernel.org, rostedt@goodmis.org, byungchul@sk.com,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <20250707083034.VXPTwRh2@linutronix.de>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250703181018.580833-1-yeoreum.yun@arm.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="GQkePXi/";       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=1JxpmRK7;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2025-07-03 19:10:18 [+0100], Yeoreum Yun wrote:
> Below report is from Yunseong Kim using DEPT:

what is DEPT?

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250707083034.VXPTwRh2%40linutronix.de.
