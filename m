Return-Path: <kasan-dev+bncBDZKHAFW3AGBB3EU5GTAMGQEZBS3LWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 160E677BD33
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 17:38:22 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-51dd2c2422csf35866a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 08:38:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692027501; cv=pass;
        d=google.com; s=arc-20160816;
        b=wVr9l8Itx/9khCZGey+L2STrSekLiT+KWrZuD1bMbxVfD5YOO1lA84RvnGmeBbXCwR
         pbEj31+RNKEiVS/KKK80L4zYJS7smx6gpfE9TriENBTrhSqTDXNJugNGJ5dBhliTpqd7
         l5ITUqTM7cK8GFm0hMA785FWnfX/ZODgVB0JoxRFfruauhPw7LFW4TAhMWXapLBPZ2rc
         e4mU4Rzt44fvTT5vXyLJTodp8JHilDrktltMkri1xkc9GuZv6qKqy0JdYw+ga2dcUVET
         BNnYpMxIk7SBIjhgFFiQeamMYV1C5q1GL+x0QOzX6YKJRs1+Zs8W5DLj1h7khkCIhPI2
         DQrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lsJjs2whMIA1VuDwKI/bw9qI1jrPXELcQY6OMhlcLn4=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=CDYAZo3ksWaHE2sKXqM+LkfkHHE5m/Ybji4qFib3ZEuk00gX5jKZLyEi7C16d4ry/P
         Sha4v9Q+kD9eIXnRAkx8KjY1L/8B9HQzg5BYa7M2l+0zSadtSUJB70OtQGVwKo9u00Jm
         sFOXVNP5dX2pr/Ybd4/ktk+Hk8LLfkFVDkoqudqioZn+3v937s5gcBS295QKbvHtsUo2
         wVhjGilnyT3gAPJ3Zm3+V1RsIDI4gISsc49vhp62vqL0X64JmBk8ySDyEtNm5nne1kjs
         AvD4cuj93mmtrzwCY3BexvRmHKq9h+qnhKxBx7x5ojnJqA595fgg13vLBRoynWT9WuEV
         jkfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="A/TMt0C9";
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692027501; x=1692632301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lsJjs2whMIA1VuDwKI/bw9qI1jrPXELcQY6OMhlcLn4=;
        b=IwL4/dZOY1rZgNMgaqtNMdyPKrHU6wlxmWIF8cMkCJBOWqDhtNyyeu8x7oPfxV+GDc
         k/JqfGJK4SzsIBBDKt7svs78tV8oX89VqbdpPJONhV3HPQbOyGwYWvENGUrdXCqHieQZ
         eXVT+TKUw/BnZkT7H98F7b/vhpAi9uwq7HfgBg7WuhnvxK9MXeyRMR9yJgNLiV9wzK13
         f2ubRDJSkUFqyyLvqAQ26EEvqnVknifWzEtmYfCX9CevBbgLjLnQPrXJm3AzhKBH9kq2
         sXEX5c0N46Bql7Btan0mZwo/1zxQPzgf5zWI2+0lYV7i3lhyJQ2YHB21DzpE6exGz3fH
         S8ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692027501; x=1692632301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lsJjs2whMIA1VuDwKI/bw9qI1jrPXELcQY6OMhlcLn4=;
        b=WUWoxZEoSdDyNHormmpD1sZaxWWKmUPVBiyS3tWL3oGquZd9gvkykvLx/KTnZAlPa2
         nWCi4GZnw6pJ8UksmsrorfTxK/mHEQddX3T6fcmr5r5QnqKqBMkoLjWg8zdQ5bEk6GgE
         arRJyRtnjh2GlB4AMvZQgLHMAHnxGUACjC5gBW+zAwabIxr9A1z2/mmYQI27W3HFqKqE
         iWZ5oUq6Nc0h0jMOG55XJVl6CxOIWZCEMcrvgLvGD2j4ipF+cMKtUB6uAml5qN/c+keu
         5SYYvxIMd0SSJdlt9SkEcgACYCOODX48fRLcS7m69bPnEe6ccN1ouZbmMBI1pQHL8pV2
         LNmA==
X-Gm-Message-State: AOJu0YxK5bUSYKZs6UU7+nxlTQ1ys85L8hgXqxYbi62i7jh0PZNBrfKE
	Z5+bQdrJSP1XwoMEsUexcBI=
X-Google-Smtp-Source: AGHT+IFHLg4k+dsFgEfLQEruwDpeuXHlAe25Q90SgBlZd+rwpE/FZfoLRYScIiF8ETab9BgToelZ9Q==
X-Received: by 2002:a50:d486:0:b0:51e:16c5:2004 with SMTP id s6-20020a50d486000000b0051e16c52004mr270442edi.6.1692027501188;
        Mon, 14 Aug 2023 08:38:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c6:b0:2b9:7240:6371 with SMTP id
 d6-20020a05651c01c600b002b972406371ls174916ljn.0.-pod-prod-04-eu; Mon, 14 Aug
 2023 08:38:19 -0700 (PDT)
X-Received: by 2002:a2e:97c8:0:b0:2b6:e6cc:9057 with SMTP id m8-20020a2e97c8000000b002b6e6cc9057mr6978531ljj.51.1692027499368;
        Mon, 14 Aug 2023 08:38:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692027499; cv=none;
        d=google.com; s=arc-20160816;
        b=09lpzBO5MHlhafzpPONYAr0ZQIVw+8PRjhIPkbY+i8KCWVuyIqfZ9h9ZykUPD4725m
         9v5jVcpPqPudrfa2iBIKSKl1mg7YVFAly2cEFBE3TeLb9sW++B+wC+LZHXinQOQSpogn
         SKi/5wwn/2rATeqiY9EwYVxArsc/v8Vsz+aoVspijOX4nLVEYgVg32O7fBJCV2fd2Mzo
         1lBI6MntZ+kXjv1gV26pVpCUu7kCTIqp8MqKG9dWvDnWzvr/LnUs/la5mB+Wh8n1ObQF
         XHx6qmbvPUedfOnRuNhFSoe8iJO7GtfHqdNz+2tiLgiTl51qyszili1UhxzXU0pl9DhM
         4w2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=g7YUilbuYTdRmZ3qe67ox4CEWBzf91CquwKUvJGpbcs=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=pWEfK6wt6WNSihlTjiFysUnKt06geoBeTBao09EpwglgjA9Qhs7jAYG46XVsxvOGks
         JKI9bmq0jhnQnnO3bG23v/pFUBA3ncY9M2xv8g9SNZKAmm1spU9lyPFXc7eeaPWYKKfm
         HMBp1iYHS5az3cnzwpR7VDRy2IGHo2g0ewDC2sGpWzDKEx7fBXZtBwAkJkORal29Vs6D
         PicXfLlshGCvE5Ll7M7VctOhhPaXRO1WHGIVv5R5IIfLrrzLpcvvV/CkThLrTLmXBIHG
         kv3nC+Myj59RHg6UEZUmqbz4EWWt0sD0FF0J2vGW2KNFq3b5XQMg4ziVz/v2jv4oLgyF
         fSWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="A/TMt0C9";
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e11-20020a05600c4e4b00b003fe2591111dsi1239290wmq.1.2023.08.14.08.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Aug 2023 08:38:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 226721F45B;
	Mon, 14 Aug 2023 15:38:19 +0000 (UTC)
Received: from suse.cz (pmladek.udp.ovpn2.prg.suse.de [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id D993B2C143;
	Mon, 14 Aug 2023 15:38:18 +0000 (UTC)
Date: Mon, 14 Aug 2023 17:38:17 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 0/3] lib/vsprintf: Rework header inclusions
Message-ID: <ZNpKaausydIB_xRH@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="A/TMt0C9";       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Sat 2023-08-05 20:50:24, Andy Shevchenko wrote:
> Some patches that reduce the mess with the header inclusions related to
> vsprintf.c module. Each patch has its own description, and has no
> dependencies to each other, except the collisions over modifications
> of the same places. Hence the series.
> 
> Changelog v2:
> - covered test_printf.c in patches 1 & 2
> - do not remove likely implict inclusions (Rasmus)
> - declare no_hash_pointers in sprintf.h (Marco, Steven, Rasmus)
> 
> Andy Shevchenko (3):
>   lib/vsprintf: Sort headers alphabetically

I am sorry but I am still against this patch?

>   lib/vsprintf: Split out sprintf() and friends
>   lib/vsprintf: Declare no_hash_pointers in sprintf.h

I am fine with these two.

Would you mind preparing v3 without the sorting patch, please?

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNpKaausydIB_xRH%40alley.
