Return-Path: <kasan-dev+bncBDDL3KWR4EBRB7O5SD6QKGQEEYDR7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 90ECF2A8420
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 17:57:34 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id j17sf952607ots.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 08:57:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604595453; cv=pass;
        d=google.com; s=arc-20160816;
        b=mkLH8jAK/13INwczTxlo0U1qd9eum+L6dCSf7P+tW+nnHsJDo2PJb74jqdwvKYy6Ah
         ITfmoW/UWyRGVC/GfK6nz1AHgPP81UKSB37ih58NXylKN728SZ2gE3oOMCHQ2Gr7Lsm6
         6jr1JVBaB8W2hun/Qg/VpOCQwO/T3dK4fWoQd/yJqWycjo03LB3VOss8o2BlSHGEfGMm
         Qss9QjzvSjIMkZGgHCUA029xsXX8qznG9jtLRUMBuWvWHK1LtYyIqDXUm6gDbdybDQqZ
         id1s0gw5xWi6ok1dcYWF2HPEYp37/cIVky4uBo2iNyNg2g0xta5x1bGdN3OpWeI23hgF
         zoSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ggooREHgI1EbKrNscf/xh9H9Rkk9R812cak17lscFvw=;
        b=GH0I1CSOO95REv79e/+4dDfgx0dCxw7YzBrDCPP+YFzNMWPKIaeD1jZrnDV95z2aTZ
         g890KazgI1p6Epl1yYW6pz0OyNOvQeqihK+/wYEl55HCaUkNRJSZz0JoZmyC9P81wh3O
         k7P0WMq/6DPdnpqClkfVlCE7qU3EZYoHssog2zDcDqYZi1/d2k7CPXIuEm0mlUUBvs9n
         ENd/Ld1FPzi6ybAD/p1AwGwYjopcR+8RiAamM14fxAnrUEn8IO/Dqip1s1txpydK/zDb
         il7PPAJDUie7WWCtTcK7MKokn5VozfQKKh/9Od1V7CCjj2suUAJMnny2jXIFIDS9pBH1
         QVBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ggooREHgI1EbKrNscf/xh9H9Rkk9R812cak17lscFvw=;
        b=kzwHzbjBrUZCDcnY/AkDEG27cyGJ3FU1hG/AYAZcFY8P9SYK1h/mWbW7T9IMj7MXTG
         KlLeygAkm+WnxU65/MPYqQUaa94mRe900ai7R4PoYkN0Y5txgBxGS1Zvu9kDn42IRBkQ
         4wcrfSNFj2123hznsxXhMxkLI1HKEa0Nup2AgflIf433YQ0QwCWrQCA+skHFhRPbKVT+
         Vz1U8k/Ay19tr/+otODdzxyuhKKUwZY2r79So2ucLfMA8G8ghgojij3dlPtV4SnDKsVc
         pmWGQB7YSUIFgo6h6ujbi9REibEaZ0WqQjhQdohnFxGn/4cQUWWUvlCkQnlcfv5Ub5ae
         Rnzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ggooREHgI1EbKrNscf/xh9H9Rkk9R812cak17lscFvw=;
        b=fJaHGDE1P41lrUDAajJ6GKO4b9cttkp+O3UeXSnpKYO0BMjEhZA0vWmm45TqLUZZVr
         2Ku3OjayoS4XYZyRc191ft49Gi9XkFKzmuvZHE/YrTxj+caxQmZS4f2j1ULcyIEmf925
         dxsW0tjgb7i/70VGyxWYyh4KE5jxwNbUyugzgNViDBRfSX56YT8A5o9U1Wk2hy0wJPXp
         QHzZhea34Sly124QJVwQF7UajN65+e/OraBphvM6oxJYlyz8xlpnXENB2spEHh3AJIhs
         1F+FoYuhItS6xlcqZpjBHSSxVXs9orNGmjwqK/xI+U1fwMI17c+d0TEV6IgrF4zVKnt9
         DI+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YzfG8x/QlFy0gkHKgxWZs/SdoCX2rEsWpuRZ6NP4rCvTW1tZk
	JrX+UxUm12Ft577hfikKfC8=
X-Google-Smtp-Source: ABdhPJzOHyaaMM9CuGUg7XCJIlWbvUVbY2oAupR6P7QcwwYUKpspUY1nVdhpDuN1xmMk5BMsF7D9Yg==
X-Received: by 2002:a4a:bc92:: with SMTP id m18mr2473226oop.39.1604595453311;
        Thu, 05 Nov 2020 08:57:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls597350oth.1.gmail; Thu, 05
 Nov 2020 08:57:32 -0800 (PST)
X-Received: by 2002:a9d:62cb:: with SMTP id z11mr2387802otk.191.1604595452897;
        Thu, 05 Nov 2020 08:57:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604595452; cv=none;
        d=google.com; s=arc-20160816;
        b=Qg+TsPdEKBlYLwRdQKqHu8abfCRXpE+j4JjO/OcK+OB8iQWG9uqYxbG36E1x4zv1Dq
         VHjYLVpriYY0I80tPfy6w65/dQb7m/XAqK9t3E26eQ9bC0QIKFwXvJWGUn2hbYDPnf1n
         CeBU7dW2afINxPqyKb88rixvf2X/qJy1RMimqPMouv2yK1MuiIFT2KNMB1oSmfAAeJHp
         5FJePoz38H+AnuJKa5A03FyZIidx3DaygE13LQ0l3p66yrzQRoyLgNXNg5wzluTVGZKL
         fnXnTckXzkXpA6yrgoe6pmJkf2Mt/Zhq9DzKPGe1mGqbWg8/NFDUQ+gal0OE0Ckov4nc
         +ZyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=jnBn+UUyx1MJcmYKvAyoAAGptiTYTFsTjgYYNqvHz64=;
        b=BiE9KlvxVxId2v2rXTyJBiqc7qrepGKDzCZZGpbL+BU5MV+4iIzw6/PpxuaQgWCTgs
         Abk2/+GwiVsGCAw157qjYvDAnJdJwIBzJB8/l2FJB9Q+/8aOOvZEk69dEd5SglUP7GyU
         OjJHVKyDkXd6PNt9uh5jfndyzhB9oQLonaHfGGb7NlewQTKGmrKblgPFeUCzJGESPdK5
         XBhNXlVxAfj34wlSDZTtoAPRtXiCwdhbjYNlXJFSqB2FG7PN87IliDM+vpprmLQGDHIm
         pgY31cUYmIDqSlScNvKjokMZ3WjLXU+wRvEcAmJGVkasMmum6V8dI1PXQ2dGppN3pI2y
         mggQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d20si180714oti.1.2020.11.05.08.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 08:57:32 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 63169206F9;
	Thu,  5 Nov 2020 16:57:28 +0000 (UTC)
Date: Thu, 5 Nov 2020 16:57:25 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 29/43] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20201105165724.GD30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <a540ab7b9e3b908e0f4cd94c963a0cc6bb4e7d3f.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a540ab7b9e3b908e0f4cd94c963a0cc6bb4e7d3f.1604531793.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 05, 2020 at 12:18:44AM +0100, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Add the implementation of the in-kernel fault handler.
> 
> When a tag fault happens on a kernel address:
> * MTE is disabled on the current CPU,
> * the execution continues.
> 
> When a tag fault happens on a user address:
> * the kernel executes do_bad_area() and panics.
> 
> The tag fault handler for kernel addresses is currently empty and will be
> filled in by a future commit.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105165724.GD30030%40gaia.
