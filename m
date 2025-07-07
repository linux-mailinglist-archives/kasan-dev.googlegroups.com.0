Return-Path: <kasan-dev+bncBCKLNNXAXYFBB7MRV3BQMGQEYPJBILQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BD37BAFAED7
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 10:44:47 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-553d7f16558sf1962486e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 01:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751877887; cv=pass;
        d=google.com; s=arc-20240605;
        b=ir7zboJ/tBTl6IIa1TjdqqjH0odbYAQphpTnsVZmbcojEs2/GkE2pXcdb3wviEF2kY
         f8BsdFensAX3BEYbjG/mIw0GSdFC2jQJOggZEuRb0bbD5N7PTNAk7FVdhD6ndQJMr4Jb
         ik+e6HDSooone7TAbvwoYu8f0c9oTs18f6viCD5KoOE0UWRxkk58CFZNU2k7jOBxoHlI
         lEtqpuPIsQTviauZzOIE+5iupL3mbfqr/F2ndmle2mF3jqY4Up0i47TZVuCQGYtF9Gif
         qxygVEJdswjYPfvWcuuEf/+1tt4LtMUdSC29n4T6I5/yDZ1QTVSAKYfxZvGit32anOP3
         6NXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/H1bNePvC0YEHCJ4QogFNOLEnP4PMkH6sjUugBYaX6s=;
        fh=xe12QLbl/IxzHTvWXf3aLohIJy2naRAhy1+Tb6Pk4+4=;
        b=cdvK0rxF4kU/1/M1Z4Hhg1INKb7QcsJ4+fLauElv7ST/gNfRPmuX/hVcFRLgm1rQed
         enxEnxsqmDKmtSZjvr02MwiaaKuVtdhoDnRHYtc3DHkbe6Vnv+/TV/zbD04iwP8hhTUT
         9/19uGhAhL9kj5JuC23q2riMwdkugYHWfViW+S2bOBjePQyUCnevYcDPpb554xDefM0N
         Bii4yN4nMQReYUHd+MIOnR6y21GTu8GeTo/ItVnbAl4u5COIpNTZom3PYHZT6TMdHpVD
         9Nt/BTXW2KR6LbZ/1WyuQQTWGsghRDggd3boVfwD+HdqEqs2o86j+zKzvmqYYBNxCwJ5
         VCbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=t+4ylqAF;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751877887; x=1752482687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/H1bNePvC0YEHCJ4QogFNOLEnP4PMkH6sjUugBYaX6s=;
        b=HxPuOf39goBhDukpo9rCiasrXTlit8XxyT3t2XhmRFJ97cZE02oyvrFRY27sqIMngF
         g4S3I/9p2nkfLVoHDUP9/WAb+AHebhJ2mIK1+kDJlZ2MslYx2T/UQ9Gfk4v+Wwrvx5MM
         ymlP1itrzUkY+DmHN3y0/yn14g2CvTHyrgOTjIWtofSvBRou2oF+ZiIj2QlKy6OPuH9d
         hwAtd69qw2nczjvwNmSYeoTOM1gCLQBm4m/5HQwlUirWJIzlEIvr7oe7E5FUzL3jsDoJ
         4WEa2DnB12KsvAmRx+mmnViyJpyjQhilpKuZbBldJhq9eWciAPmrTXTueU85phq77+pm
         6T+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751877887; x=1752482687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/H1bNePvC0YEHCJ4QogFNOLEnP4PMkH6sjUugBYaX6s=;
        b=WWFNNzboq8aYe2Zrw5Ox+0mydMdHX9T6RTU+0mT0OlxzPZxUDSpeU1cVpcCGOYHFeB
         9HgZyp8z11Psp8wFNxeKuo7YS/I+xTWMwEErk9eArmbxnn92K2HN6RF99Rya8r/svto7
         phwsaQv3BBWsOxkaapj7S3dx8qhAX0tf9Scf9k4B93OcE0DdIdJnKCLwq/oBCFwqXf5y
         AWG9bdFD7s9UJhkj1pCMWc7XEwkW+td6/W7aWq6SIS6GDNtkoqBh2mPjkEyu/IFGhe5H
         sOtFmMXXcgNJdxCTzESRA4NWXZ4CvvU9oXs2dCaPj+VyruXuEYWkNrIVQ/Q4YZfNEOO0
         mCQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEX6um6bKIaBEPslPFTjJwsTPaNL38ssMAxQH7pwBFAFXnJRluSI9WjGTzR8tdD0fumwpNcw==@lfdr.de
X-Gm-Message-State: AOJu0YxdPXIH+AUhOLfQoWnipu+wm8JNvNFRMmLGOUu9nqe9QowgPMRy
	QL+27w8V0OAab4Q54i+BZDYK53z+xBQPE/PAKL15GTviuDY5323owA/E
X-Google-Smtp-Source: AGHT+IGqCFiov/BQQYJnciLFdiHEQPsP6in0VLusyo/N/z6kWzky3RtzVLNQQ3uZTczs/bts3nCUWQ==
X-Received: by 2002:a05:6512:3c94:b0:553:aa32:4106 with SMTP id 2adb3069b0e04-557e5556e89mr1651567e87.23.1751877886529;
        Mon, 07 Jul 2025 01:44:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfl2UE+IMdbcY+D0LIuBI6pb9GRGgWbJfOCqGf1+1nHcg==
Received: by 2002:a05:6512:440a:b0:553:d22f:f92e with SMTP id
 2adb3069b0e04-557d3a40dcals568114e87.2.-pod-prod-01-eu; Mon, 07 Jul 2025
 01:44:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXugufaLfypqCsuRWZAYBzkUhfC/af4wsbc8CYFFmDhuMMClnhKFBAIhT9rhnH3Dho56aPQdPlLUb0=@googlegroups.com
X-Received: by 2002:a05:6512:12d0:b0:553:5d00:be8e with SMTP id 2adb3069b0e04-557e55949c1mr1906953e87.37.1751877882988;
        Mon, 07 Jul 2025 01:44:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751877882; cv=none;
        d=google.com; s=arc-20240605;
        b=V0urTYC60JlFIe3CJtQii635hiqCSv+bAIeIt6pj0XX3RavA0u5MVSCVm3cJbZkzoe
         ilxUwgqcT36PRJMvEr4ljKjqneL1Jm3O2LxxnYY1I0GC+/06WcJo6GUoi90hXq3AkZf6
         P0eGrid2P/M1rbyZYWLOrZd0fSygLRCaVJhNWaIt+1di372GFEusoUmBWBw20FlBviZl
         r8n5Ibv1bMYIFs1qnTLq/sAjw2z0dO/pzj2rPeqCQYpD316soo4ELolw6FWRFgQeICyU
         +uhK+t+EvZPWeZeJpevjM68vCADfYxf8um7FU19b2lxAZzs2lo+JCjhO8is3VT1bJ5iG
         8SPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=fm2v9rBCIXUzUrmt72RQoSJ2B3nGVKZtSeUnw7U71lE=;
        fh=1w8HeWEvSlwODmpRGh4OdOj4E8TW8kP7woR1B7ALjr4=;
        b=S2GGAB2CLbX57PgxIXGp8jwGcRj201YzUQx7TDuV6tGxA/C58e+qLKPWHvX3QMIhEG
         AFLwZV1g09rnNN7sbL1HUR0utB1UTpEYTq4iM0S9vri5iCjaEz24zIqJa5bFcxmiV6SO
         FHLoN6HqOGkqOJb45SbngvEQDzqkWW0JWe3E/Wx19qRd3aHNY72WS+CDUVIm8rPVk/k4
         mN4Q+UjAUajq89xaRiZeYH56/+mQWpUAGuv6/GoLww7hJbdY7h2z1vH4K+cP3dMVMXfA
         A0+r0PgAaxCPszWYyawxvt/cTmlZg4iUaeTWMLlQdqSAXd27JzZJWDCEeB1MfCzF124R
         Uhrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=t+4ylqAF;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-556382c29f4si128250e87.0.2025.07.07.01.44.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 01:44:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 7 Jul 2025 10:44:40 +0200
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
Message-ID: <20250707084440.9hrE23w0@linutronix.de>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <20250707083034.VXPTwRh2@linutronix.de>
 <aGuGcnk+su95oV5J@e129823.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aGuGcnk+su95oV5J@e129823.arm.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=t+4ylqAF;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2025-07-07 09:33:54 [+0100], Yeoreum Yun wrote:
> Hi Sebastian,
Hi,

> > what is DEPT?
> 
> Please check the below patchset:
>   https://lore.kernel.org/all/20250519091826.19752-1-byungchul@sk.com/

Thank you.

Would lockdep see this if check_region_inline() would have something
like (minus missing exports, just illustrate the idea)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e76..c74e8e0863723 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -171,6 +171,11 @@ static __always_inline bool check_region_inline(const void *addr,
 	if (unlikely(size == 0))
 		return true;
 
+	{
+		struct vmap_node *vn = vn = &vmap_nodes[0];
+		might_lock(vn->busy.lock);
+	}
+
 	if (unlikely(addr + size < addr))
 		return !kasan_report(addr, size, write, ret_ip);
 

? Just to understand if lockdep is missing something essential or if
DEPT was simply enabled why this "bad" accessed occurred and was able to
see the lock chain which otherwise stays invisible.

> Thanks!

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250707084440.9hrE23w0%40linutronix.de.
