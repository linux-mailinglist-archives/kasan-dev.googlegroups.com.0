Return-Path: <kasan-dev+bncBCT4XGV33UIBBQUUTCUAMGQEBVRWJGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 81BDE7A3261
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 22:04:20 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6be515ec5d2sf4491374a34.3
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 13:04:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694894659; cv=pass;
        d=google.com; s=arc-20160816;
        b=0CinSx9Htbg49E2PMSnsh75Y98nZPWQwXTvMRe4c8fpDVNZIyxfdN2BoY2jXpzpf6y
         MMtn65Jo1Y2llodzABQdrl5hQ5ct10YH3NuIC91bIF4DHcjMr1VOjEZt1etSUwlk0dgv
         DVS4JcZ0I43LoEvtoYNSgUei/7cJ0qSCJsTlDc+J0UazhIE/qKMyUOl93JoMnHHI5p3a
         0HmBn/4Xe9J36yOvI4dda6vS9jujUFyJda//7bEvdlM7O9+pkoc7qmLD8lOvFcstxF6d
         MVqqk1ixJTb69OJrAiekBIgi0ub/2TuV6QbRqXtPUazMcrvZmNWJm/dNp2hDI6Q5qXsh
         jDsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=uVwrGIJIF4yf8tq0UCOv1/uwGXYLCdgVOUlgaBSF0Gg=;
        fh=+jiOPrgMk0xPx247vtgtVOR+vQEtzN0cmmRfSfBjj/g=;
        b=CAN7svQHhODP3RYXsoboQhIFRImCcb5T7llhCwvpVt0L9v8wt6YeGqTeW2wcNpVANc
         Sl3PM1kcpaPnuW2yVy0GhLu6L5FYZSKlSkYwBZDTiyE5W6lOMQ67Mw01Nw5IRzDXdHcS
         GHGb+YZ1FAekLq0rEP/vSs7t4DeOfXcZE6y+fXAWMVqjeFJ6N+cZZvmyjVeJNyX6zoPs
         WrJAqi/vn+Hws3JHt0pqfkITJyVibQWoZJkg/0zpEI6gCfS+wSvpz1gsnYUOsR/cPpij
         K7+XEKZFQALy7lqhLMlqg03YVNrMczkLWw2RH9qJPqB+DuG1tR4nGFAMhlfX4tYMH78K
         K2ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zLp5UXZ+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694894659; x=1695499459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uVwrGIJIF4yf8tq0UCOv1/uwGXYLCdgVOUlgaBSF0Gg=;
        b=XHDW76rOh3sX8JffgERnjDQjbAbrs+K9WHStf01vcwTmE8EuUjqA3dkgcT816AWlTo
         eRWGTQpbcvbw3G2A6k1zj1I8aUJR0Q608KYvQiE8XYWDPHxV+2Wn/4ou5PI/pzFU/QYU
         G5uA4yBNgXssoG/+quU5OnhbxIi+1z4eaOojglrxPSVtmrhGUvLT3Ff9CXx97Ip26NAL
         2kX7J8dw1btfDs+ig3E1EorPvjAd6yWx7h53HPIRdou7HhzUMOCk8kMl22A+x+Ni9IKV
         l/4a6h3dEjeDrIIi3Crw0ZxEk8oFxpFUQ0RDBlEYYb0F9feWlLkpiguCCMc/+biDXcJT
         u2xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694894659; x=1695499459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uVwrGIJIF4yf8tq0UCOv1/uwGXYLCdgVOUlgaBSF0Gg=;
        b=Lo2v3BRN8oSRBglCdi0hKNZMfz8FdZASyqI2fIEUQEI8dMoBo+sXnaGRn+YPpCsgLG
         QIDVXXQmdnrmDAFRoWeIboOcyGUwS47SJHbp4CNjGK+FENgWTHl1Wt90I4FLaz34sJyF
         y6GzjpHfqC7nQzBltR7TMUFG2USKkHtzuoiIS+kUmkgc/Vx/E0MLHoZIai6am6FLAh8+
         XSGV/QmiB9B1fvChrcwWG2zHyMedM6v2BpqkC9/4ul+L2JvwArbnTKHkLICfobSHb8/B
         kwa9ZmCFm5wj8QeBG1YAahlnhXtDyPhzd6nnQqAafyNZRH/ep2UnthBGjtM7Sz+1EsIY
         7Szw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyjMOLYnalszrkYupstnzETSXZfl0H31Jm4YT59ik1HpvugqhRO
	Hz1NGaGezIQ/UAbQNuyDJW0=
X-Google-Smtp-Source: AGHT+IHkceGlfRUJ+joqaPP83Cx6z7XW5UTh65gnSY9q4gEEJBZyJXogtmspX/aXWnumMEyItk/lsg==
X-Received: by 2002:a05:6830:1e27:b0:6be:fc8b:40fc with SMTP id t7-20020a0568301e2700b006befc8b40fcmr5623541otr.36.1694894658991;
        Sat, 16 Sep 2023 13:04:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:41d6:0:b0:571:1fde:ca2c with SMTP id x205-20020a4a41d6000000b005711fdeca2cls2908407ooa.1.-pod-prod-04-us;
 Sat, 16 Sep 2023 13:04:18 -0700 (PDT)
X-Received: by 2002:a05:6830:1b6a:b0:6bb:1629:ab44 with SMTP id d10-20020a0568301b6a00b006bb1629ab44mr5132602ote.7.1694894658336;
        Sat, 16 Sep 2023 13:04:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694894658; cv=none;
        d=google.com; s=arc-20160816;
        b=UIA0UnizdZUE2+Z0+DPCnbk0FofYaYmkWzVCeqR3ByhGwNgvlYoI0RsctLfy2+Wr6P
         XuQKVipF5uXAfNRDT+1jrXh5nPv20iykFYgDXbrmbbMP+1Kq6te0PglY19TLSyT7nzIu
         sChfhKHI78GhNXRcG02eXO3QloQ3+HkesjRij4Uu7hrphOjrtCX6V/wlTF3pPb++GIDp
         RD5wZqp+J9zV/E+3+DNj3XQpxH/MB7KyP5d8boCeyteGNTvhzhI+v5DPfAQHyxow+4BR
         K1iI7d0aWW+j889+r/dCvBorqZZoX8MHlAqKn9ddlc8y/ZWlwB3NOkUGdp42+TRRvarm
         GtAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BKEe0o9exEJRzCR0zFw512dU5OKfK5vlhpCyLooMkWg=;
        fh=+jiOPrgMk0xPx247vtgtVOR+vQEtzN0cmmRfSfBjj/g=;
        b=bl8m8y+uLr2casCOKPXaPtjHh6MW/1+FgTY0LGjovI4/dgsrZKXwUBkvoU82/bxy3G
         /mGHlTb2DURGnh35oMZzmdbKetpsw1To/971TLgxC9ospmM/ngmPNhIHEqFNQbx+TKVL
         8k6UUwbBGhtD3nkznJoP90FenoN1oBg3QIBXKJ5HxGMGahFxavkSWYIw5ptudbnwfH6k
         +GBLeFZWhC55JpK5VQtoZjK8at+HRYooLCGVjAsPvOMTftkRPGJYoU2nI+4PBcIolvK2
         j8uIrm/mDHQLLIPXWQouU2c8idKkNDB4YMXrA+r4s3CMVd5ZURN8VuXUYWQIitg2ogEP
         tsHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zLp5UXZ+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id i11-20020a056830450b00b006c44affd0c6si53058otv.2.2023.09.16.13.04.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 16 Sep 2023 13:04:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 942EECE009F;
	Sat, 16 Sep 2023 20:04:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 618BFC433C7;
	Sat, 16 Sep 2023 20:04:13 +0000 (UTC)
Date: Sat, 16 Sep 2023 13:04:12 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Anders Roxell <anders.roxell@linaro.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, Alexander
 Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, Oscar
 Salvador <osalvador@suse.de>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>,
 arnd@arndb.de, sfr@canb.auug.org.au
Subject: Re: [PATCH v2 12/19] lib/stackdepot: use list_head for stack record
 links
Message-Id: <20230916130412.bdd04e5344f80af583332e9d@linux-foundation.org>
In-Reply-To: <20230916174334.GA1030024@mutt>
References: <cover.1694625260.git.andreyknvl@google.com>
	<d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl@google.com>
	<20230916174334.GA1030024@mutt>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=zLp5UXZ+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 16 Sep 2023 19:43:35 +0200 Anders Roxell <anders.roxell@linaro.org> wrote:

> On 2023-09-13 19:14, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> > 
> > Switch stack_record to use list_head for links in the hash table
> > and in the freelist.
> > 
> > This will allow removing entries from the hash table buckets.
> > 
> > This is preparatory patch for implementing the eviction of stack records
> > from the stack depot.
> > 
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > 
> 
> Building on an arm64 kernel from linux-next tag next-20230915, and boot
> that in QEMU. I see the following kernel panic.
> 
> ...
>
> The full log can be found [1] and the .config file [2]. I bisected down
> to this commit, see the bisect log [3].
> 
> When reverted these two commits I managed to build and the kernel
> booted.
> 
> 47590ecf1166 ("lib/stackdepot: use list_head for stack record links")
> 8729f3c26fc2 ("lib/stackdepot: allow users to evict stack traces")

Thanks, I have dropped this v2 series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230916130412.bdd04e5344f80af583332e9d%40linux-foundation.org.
