Return-Path: <kasan-dev+bncBCT4XGV33UIBBO5QXKTAMGQEUTZP5DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C10E771185
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 20:43:09 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-63cfc4ebcecsf33096976d6.1
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Aug 2023 11:43:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691260988; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/ctq4/fz78vTVQSQ5jup8gh/L4KbphiNoILoFwLobIvKan9pZt34vCeqJdYgvTWZW
         4vBOXVtx60kY9Aes7QeqDmsaeieU2RGqYeXR62TjY1RoGTpdwaVE/+bE0SmQ570SibTw
         wy7bd+3y2QIVrDQ+ghPj9eSHysFwz0gEjktQtNiYHqBrhzW+IrpNMvw8wIX1hd9KQ1EN
         kilAioaHaBg4XyOfmccxEE/XBDiS0lR/0ibDMZ4DI2Ab07W+h/A0EiuPMyxFbTk2QUGE
         7oguydhL+REPxokUSBpyNlO9LakNbTRXrCEdq9MymOrPmWMkVuFaYKWWjgOuJ/Xafi3O
         Viqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0v4TpKOV3khWV1m5OmWRYSuGVBmACl3TBPQRueDJhxY=;
        fh=B4Ws9PxCq3MKxqO3lfHoEeZrf7ET0qam4mZMu0vV8PA=;
        b=c14UAqu+JogAj1PE2RjoUrApZe95prxxNCP0s3vO2Nh4619ajr0X4GbUxDHJuWyvDV
         ESd6xoiQYHI7g1gDwanTCcgK+5fVKOSGba3fn78Ctdc9dtCMGHi5LzSy6y0OBA/2f6ph
         NupGo2vihmeaF9dceNiIGAygn+R9ay1TnmF+2HJ36N+H7NidFcK3IiVcpOynrN/ukau/
         TulIlwdcNnC0DNTK6loZX7t5OlPF/y4Nldckhyp8HlKOYs/XdYhJPxPSFCRenCGZleiK
         N1JM7m2VPhLWGZp/kr0uKo77XBM/wOGg1VJ+Ob/41ddcGIEQGJiZaOZc3F0cpPlurzaw
         p04A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=BatuvWtb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691260988; x=1691865788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0v4TpKOV3khWV1m5OmWRYSuGVBmACl3TBPQRueDJhxY=;
        b=J74AfRK+CZo2JorWUDvESBpO4l/+JR4UKzy1zMwmPx8gZPf42hqFuBz3rFvOrQor86
         hPdwLYuX4/htG41ZWys64Tzh385blzkjM0Du5IpFlu3G6VdMUhBm4ZhzbSdEeiOahGM2
         rEafJ4BkHZN7PR6+SovduWzRxk/P1AwcRGBPGj3z7TUybs2HFixDdOsEtoAv6aPQg0ZM
         V46+8LL05PU9Ojshzpb9WzW28CBi0D4IyuytwZUUUSuRX+LdpmU0LY8t00RTpROygkxZ
         Dp08/vRgppniuujkwX9DSOzd3o/1LiZ/p6Odpn2iPaJielsPUCprvlcUectehP3FvL3K
         g5dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691260988; x=1691865788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0v4TpKOV3khWV1m5OmWRYSuGVBmACl3TBPQRueDJhxY=;
        b=I4JQNQeWOLvR/4CcRP1Lg501Ge7Y8FS0zxcGhhPl8n7x+1cRHyIFhKmIR7ySsuhI4A
         RN4jbjFMkXhelVLlOdsQM5xnqyzizlidzVKh+WlnQXaj+xUOuSFC4X0gznDKe7wwKQRT
         Eo5WtNVgmpKuOTIlqHY4J43LBSYd0oc4WWkMVg0Z0LkRz0pdSRZ2ydz9Rug4lHvWTMA5
         6eNZolr9nO7/jrnhDangQm1eN7fO5mu0uDHbkvzBF4C1sbejsasZB2IAUy1oZbCwvbvQ
         iqZ8bSK77XeHshkABwDGPQDHx2BLkhNcRY7MX0t+nhbE1T3mnsxfX/te7NAlYo/IKhQ+
         jthw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx8I1gAvKpofzQFw0i3Vst2NG+Z17XlazFaKA+MCUYBM0dJc4pn
	JEJQUtQ/aA4VA85ju97KsrY=
X-Google-Smtp-Source: AGHT+IE5lMARVAnGYC/s+6cDkHk3N7A1Pf8fB5TaxfrGbUKL2FEjPdqLNxcnhcBkpPYO+djHhznOoA==
X-Received: by 2002:a05:6214:4291:b0:63d:419c:5916 with SMTP id og17-20020a056214429100b0063d419c5916mr5133173qvb.35.1691260987970;
        Sat, 05 Aug 2023 11:43:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8bda:0:b0:63c:fabe:6ea1 with SMTP id a26-20020a0c8bda000000b0063cfabe6ea1ls1391176qvc.1.-pod-prod-01-us;
 Sat, 05 Aug 2023 11:43:07 -0700 (PDT)
X-Received: by 2002:a0c:b38d:0:b0:63c:ee64:8b98 with SMTP id t13-20020a0cb38d000000b0063cee648b98mr4937678qve.13.1691260987183;
        Sat, 05 Aug 2023 11:43:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691260987; cv=none;
        d=google.com; s=arc-20160816;
        b=pkVR4pNN8WO7KwqFGv9USMCyj5XN6OH4WaTH1wzoBwrG4fnF9CqmT8fsrnDdYuhZJ7
         wfvEISvYO11zF9Z8VvB7QbR4v3Xntz6TfylpE9Ttcv3WWKdflVpJIC4HobrG02KmJzvD
         5JTS066a38LZp1OwYxE93S1cniz363RvM375nzLtkxQd1ZwUEoWzW4SYdFebwcMSN6Da
         EKUbbe7qv56l5fm9MskMQpIiMLWedUEeXcKM1rTpCuahF5nnstv8dUjwU9bv95wMTDsa
         kjki9jQ4TF2c9Vrnwd4y+hYVjiYxipUyF/MDWJ5x1Cazq8TR3+HwHxwHo1vOlaPjUBwS
         OVUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FrE94bQ7hxXi5tHI3+3R1qIzLlhtfinvJDjnJmEmVos=;
        fh=B4Ws9PxCq3MKxqO3lfHoEeZrf7ET0qam4mZMu0vV8PA=;
        b=dqfMURkF+uHlhRy+Xzoi5msuG6uAHmsPu1P50L+6VniOInHkDyiTauwpu4gx69UA2G
         7565dLx7DjZKdpIjCuE8pzYqcdFaKDyWCXj7emDaGFH1hUAl6Y4t+9SgT1plUeYTqd9e
         fboQSrOF+9G/yxn2hLwAqYCqXuyZg6DjizGW0aAYFdOl7ZFEfY+OVH/h+16ZqAetdE7j
         XyD9McORi97Iod84PZ1MDXxXCOPYC18F9Aub0fxXYDbpxoAvnrntUQaJ4rK1PhWPOLq5
         rUSkj3/YowLrfzhdPPRzvZINnU1ji8mpWezNsA7emt4wJqykKf+Ts46KIn+8i/xDRUy5
         ikFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=BatuvWtb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id f16-20020a0cf7d0000000b0063d18d62704si558455qvo.1.2023.08.05.11.43.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Aug 2023 11:43:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B17CA60DEB;
	Sat,  5 Aug 2023 18:43:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1A49C433C8;
	Sat,  5 Aug 2023 18:43:05 +0000 (UTC)
Date: Sat, 5 Aug 2023 11:43:04 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Steven Rostedt <rostedt@goodmis.org>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>, Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-Id: <20230805114304.001f8afe1d325dbb6f05d67e@linux-foundation.org>
In-Reply-To: <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
	<20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=BatuvWtb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat,  5 Aug 2023 20:50:26 +0300 Andy Shevchenko <andriy.shevchenko@linux.intel.com> wrote:

> kernel.h is being used as a dump for all kinds of stuff for a long time.
> sprintf() and friends are used in many drivers without need of the full
> kernel.h dependency train with it.

There seems little point in this unless someone signs up to convert
lots of code to include sprintf.h instead of kernel.h?

And such conversions will presumably cause all sorts of nasties
which require additional work?

So... what's the plan here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230805114304.001f8afe1d325dbb6f05d67e%40linux-foundation.org.
