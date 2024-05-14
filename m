Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEMFR6ZAMGQECCBV4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id D69998C5BFC
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 21:59:14 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-78ed2a710efsf891872885a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 12:59:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715716753; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWLo5OC+AqkEAFrfUqdraXtI2P9mVJl1ifxHfHKdRXOdpTVjq6YBr6Q8gS73ndmQRu
         +ZluBsuLV0iK2o6PW/RmTfUVts6FfNZSf48rF+oNz53m38zm6DhFgEGqhGo0T3H447ea
         ZcElIXJgsTUGeNPm9zamFvFBQYK2XTnxvmcxsZm7RzzkTjM1pVWUZG9OzDZrsEYEm1ad
         L6hVVFyPPCkv4+FMRwbQm6EaSblbodMMnjycX1fioINMWPYwla5yUxEsSZ+H/IJWja/T
         DJhFi8UBLDnMsdSEib5yh/Cadp7An0dnNdpK1yW1VSnMiMu8mF0IBCJPwwVbHNzCLZte
         n/kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nottihwyXDTtT0Mxi9SzhhaRkag4kjsGgs9Lbtckd5k=;
        fh=dH6YbxYU20+Fd85Ukx+kPRwEefYtNtP6CsnSq+WOygc=;
        b=x6Romjem9wAkfODXY4+WYsT67/WZs5XvwxlJAU4WOOEt66TqJUsmc51/60VYKOOdyd
         vv9rkcXuZ1fWYYJX5sLpxhEcZrWiK3Zjz4KjllFeZTKe+93wZo3KbdASLR6in97xWkJj
         xIEFV5RFwOhlq9chk6voECzfNqGDREoNU8rPR32rDsj9h7NXvRLM3tY6P0JhpN1rEft8
         L/hNNdRl0/Dr+rPIvIcRWG9p7GOFB1SKlKKwzLY77XkNN9WyX7D51+4HhSxcVsnIbWg8
         LE77Z/y/EtP1e0i5tRvMk6qI7iqD2/M7IJXhRVOKnMzo1l3nLH/SQpSN4JpOQV9Mdd7P
         JI0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=OVtnna9X;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715716753; x=1716321553; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nottihwyXDTtT0Mxi9SzhhaRkag4kjsGgs9Lbtckd5k=;
        b=tZbHzirSkn3gcrM5RXY1d9+LEVvVddr8EgKiLu+8i12NSzUCoXYPG46Mei1o/eOPGD
         qjy6abRP5gJSHZPg/9rLD2sOsUc9FQPVv2ykZxSlju6ZWAaw46HQh5Dg2sGuefW6/Yse
         VKaU7tz9yX7XSb3/NDvbTGll+EOimYb/YuzqS93czo2HIebaca2KyKuacf9OjhmBAuVu
         nNjiGzyQktSgtgiUsr02pKGfm9Oe6nI9LW5G7iNt3o28s14bVKLZogRx7eD2rZ08MhDY
         kaQbpRB0qLzLiKrjPIWazRQ15vgMF8pYyLuR63M+90TzP875skXrKTQ56hz5cE30D0ip
         7lpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715716753; x=1716321553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nottihwyXDTtT0Mxi9SzhhaRkag4kjsGgs9Lbtckd5k=;
        b=H7LUgq8FZIYYDcTQUWQA7Bzyp7iwUd+TUYpD7ImxU3VL88yGwlmmQZTtfkwO7XHYeo
         wW4pwwaYAZpv/qA8FF0N2lOMNIG1VnOcNC9xAqSEpV+wBwvGHYeRYdWCArjiKOm8ObQV
         1SoK8htIo0XQnrICOg7dCyJoSvTCuwn6gW+4kGv4QwX1sO3M+ESY0lT52Byro0NhguBR
         d53lFOiqh4nv6hWkJMBUrscF0wRoGYzBdhVkg9wpCQ7yhYMERne9muIV8W7AWyv/YD5t
         33sw7rLZ5REhBJw7b1QsYSJfcWxrKNlHFj3r8iqyWzSNpYPyqS0Cs+hACNwJpfas/HqW
         h1IA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2fOX2d4dlKE1CwAdyGeYJ2G72rKTTHYXaU+o5LYQ4N7HcWhNtNwNIV15kL2HQ2wMDO4akASAXNVvvOF2XuM+OCZGigg7OPA==
X-Gm-Message-State: AOJu0YwiYj7NIU31fvKqHVvixQd7eYGAAW5SrKlEBnLEYIT7b7TJF3QZ
	SLtTDsasiQEQ8mSEvmGCa8T5yfaOul5h7cXJOj+7XjyEpr0qCUHB
X-Google-Smtp-Source: AGHT+IG5PUptU7OAEiRiU5GGyeKzv+XIR+TS8CQE/XfKIfAv3pj6/UdOS5sSsJGWSLWKg0d5DAQ+2g==
X-Received: by 2002:a05:6214:2f07:b0:6a0:9783:ee74 with SMTP id 6a1803df08f44-6a168240a46mr177704656d6.48.1715716753496;
        Tue, 14 May 2024 12:59:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2501:b0:6a0:cc6b:195f with SMTP id
 6a1803df08f44-6a15d33150dls109374226d6.0.-pod-prod-02-us; Tue, 14 May 2024
 12:59:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXklITYPJzkr8SUbklqP49h3cTJkj/KetIpYM6V36rjnSG9zp+yM/ORECTOj/gWrHQJTZqS0ga8XT/67zTGcDjBOG4bq10o5BQohQ==
X-Received: by 2002:a05:6102:5087:b0:47e:f80c:d6ee with SMTP id ada2fe7eead31-48077e5b513mr14740081137.30.1715716752576;
        Tue, 14 May 2024 12:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715716752; cv=none;
        d=google.com; s=arc-20160816;
        b=YeAGS7Tur1jmfdopaLii/P511EMMZ6VERi17L6swwTStwYLsIFif/rL+7Ii34dFKgX
         SsTBPRfIbrYDWE3cFM+VK9sW5sgR/LrcouKLq8XyXdJv9ANOFR8NQSpJz0Xn1DK2vfJo
         d71ExDoLCFgmzYGMI2pbPjMwK/bu0/TA6ZGeXoCmZkZ7BsStnjYDBi2UOlEq/hWyH/ec
         vcvE2vXYvjrSdO8NnfWoCO8QYUIdsNv82XommrM5MDRPCIa5jPGd5Z9m8PPMz6sasOys
         5U0ClMF5sdw53xWxjcXOUFNdhUGRTByp2KNye92IzEeBnkhxn+D53yKaV5/JyEad4z38
         82Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IDIxmO8O4oEi6F9/Vlt0Coyv3oXpib+ejgDTpJEMwH0=;
        fh=hbYdzsTlcatAtzdktXeCUbaqeRhrFVZydACnfQr7FgY=;
        b=09wZ7z8zNofoeeaxcgY6ATzFOvjDiA+3NX+Qod5vL8uNOVABRGWV7vyf8KN/1ycQNR
         brAD+c7sZtnvJwLj9pYN8n5nkiVq4q5uBwi/vQ0dWva6uiAu+1lImFG8sIlnTYVc1+zu
         qex0orpwtyFZOGGCBoyg+8Suc2lqzyAWPe/i8dWaowT7KGhVSuidLkbClfYpAfDaKiRp
         Xwy+K5CkEQGrZKpbPbCOncxVUBkcKdC5wPV1FOeMfPFgfgf7LcREJN7cbe8MyFbVvnJe
         R8CV6iYa75G/GsYw1lHcLHZ6PKsltjELEhIbh4ubUQtilxn9N6s9zcuMq1OBnw4mrU4i
         2c2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=OVtnna9X;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-7f8ffebe30dsi748806241.2.2024.05.14.12.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 May 2024 12:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-6f45f1179c3so5681119b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 14 May 2024 12:59:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWjFJ1ykSf2oJrA1wIONZ/Vic3h2VgycmNIx3lslKtJadDaV6CNUbi7eHM9bOfuE3LBGsZ58KsfZ0K6rXvGuKXpDSrwIOidaAiuGw==
X-Received: by 2002:a05:6a20:3c94:b0:1af:cd4a:1e0c with SMTP id adf61e73a8af0-1afde0a8d6amr15225799637.9.1715716749654;
        Tue, 14 May 2024 12:59:09 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-6f5028d7738sm4031400b3a.71.2024.05.14.12.59.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 May 2024 12:59:09 -0700 (PDT)
Date: Tue, 14 May 2024 12:59:08 -0700
From: Kees Cook <keescook@chromium.org>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] ubsan: remove meaningless CONFIG_ARCH_HAS_UBSAN
Message-ID: <202405141257.3979DCA2@keescook>
References: <20240514095427.541201-1-masahiroy@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240514095427.541201-1-masahiroy@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=OVtnna9X;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, May 14, 2024 at 06:54:26PM +0900, Masahiro Yamada wrote:
> All architectures can enable UBSAN regardless of ARCH_HAS_UBSAN
> because there is no "depends on ARCH_HAS_UBSAN" line.
> 
> Fixes: 918327e9b7ff ("ubsan: Remove CONFIG_UBSAN_SANITIZE_ALL")
> Signed-off-by: Masahiro Yamada <masahiroy@kernel.org>

Oh, er, we probably want the reverse of this: add a depends to
CONFIG_UBSAN, otherwise we may end up trying to build with UBSAN when it
is not supported. That was my intention -- it looks like I missed adding
the line. :(

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202405141257.3979DCA2%40keescook.
