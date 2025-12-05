Return-Path: <kasan-dev+bncBCT4XGV33UIBBAFAZHEQMGQE6TEMMUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EB6B0CA5FDB
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 04:22:41 +0100 (CET)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-6421389b8b7sf2091200d50.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 19:22:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764904960; cv=pass;
        d=google.com; s=arc-20240605;
        b=TSb0aM0TYCsDpjhBd+6C+cLwZFDgwvF6KpdHdsiB30cjjf8CYtoZReSkoVxZARKxA2
         k2xjl4xSbSC02Kpk/IN8A+09qLVt0K3b56h++mwZlzIraUbHrkop4Jb5whH6fjb2hU+z
         jz+l8CpJf423KDZLdux6xrEA6i/bP1MtDIEjqU6mW42KZR+EtHYYVvSSBtIYv+oIZ/HC
         hUCS6SUF1d9J3iH81/pWp0OKbD357BwTEJVWzVOoEbOH+jqF6M66Xk32yyyzKsqHx7ID
         fBkbYFZDy5OF5YPjpwLBDGq0nV7VMgVUd4ZJmM9RTcDuRvBbyzZXeC0ArVL3oOFbnXBA
         kz/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pJezSVQYmVFpjLX8DHq5pcgBo7x0YmcxjZXgfV5mpJI=;
        fh=B7SeIxI3DwUW2ypPf+U+sPCNPbjzaBaFE8dd4sWmn7U=;
        b=RZdO/DzdipMO6aoVZu3dODtqjk/Rh5qvINnxCWJ6h6bRzdRyOf3EMJ/p5tjBtLDPHL
         89F3iBhuKNLh4dQApyOidjaKKi2Bb1ZYC7oZqugoWjtEldcgK4wQ+cDJrnqsHeErPBTs
         AVYNIz6llqdJKy32x90XdQRzeRADsfzmd9e8r95rj0Zu5XgSifCmRK6K7encQf4SxCYr
         4c2HDICI9+Fe0rdFfXbYIH+ko4TfD0X6ZU7mhNW4KQjrSl5E89SDpO0ZD16ax0A5mXx0
         NvcFpPyUdoAO+U2UkhiWZ9HbDVTeNA0c53yJN7KClgsdTPcoJE9ni2bA4yRLn3ns5UDt
         h5pg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AXGCPgWd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764904960; x=1765509760; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pJezSVQYmVFpjLX8DHq5pcgBo7x0YmcxjZXgfV5mpJI=;
        b=ckV9WtZ4lc9kKa7d0xB3K3M4EcXQnqGg7vEUUtThbbysK0DxmLddf6EtV8W32TAAyh
         UGompWwYbxhIwm2mWAkSWOAQxXl0jWzMlCVVBu/dWpHf33inEemLUUTO4Kr4SQmUJcjr
         TDLVKtaKw9ZS/Jjtcj4HFgqYpjg+oC40BRllFJ7SwvX67tQtXPoqCdJ4jRpfOzu4oJph
         G/vYPP9YpRJtqV+Q7iAks1x2wOaAoXPQunG4stsNNOEu79CZPNP3QK0fELNtKiI8IsOp
         XC1eN2PPBcf+7UcYdvlpklGSg9j9D1wXZS9XPyxJaNMkY//1PU/bBdnu7zfdepim17+m
         wang==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764904960; x=1765509760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pJezSVQYmVFpjLX8DHq5pcgBo7x0YmcxjZXgfV5mpJI=;
        b=qeX1xRpHEyMRDURvoxRkKbMS/6Ix1naIDKoqAxCmOtrvPzJGw9gLnrajwJFMLbqgL9
         70hfinUOdt5ePrtqlZx2wk+zG06ovJW+EVE7OMbtSt+GGijLEE5NMjoM03aJNOvcRV7G
         t9YgxERr5oOt1Otaa4XvepRGzuKrMNiLTCU4f3uUSB2QfvmxqCAA7MydDr30bqQyDyqA
         yyHI50AGsUL4E181grpqqD/6d3bftpbvDXnE2YWpclvbmXSlNOXfCPVS3Lx12NJpmwyh
         GOtZdN4vWeZv9thZC83kqhPg2uX2AiH3/3ce8bfzlhDM6qmN7ySa9ZqL4lljqtKFGVTL
         HB0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhOd7Rys7nLDpbjTqhi+eeZ1Y6jeV4WbmP0FQQJOcwxxTpf9QNbBiqdA+cZR3X7FVo0azlgQ==@lfdr.de
X-Gm-Message-State: AOJu0YzuX2ZLenX8NpWWVT/8Jke5VxqK+sp1IUGGNhk68m+mioXWlV58
	ghST3GJq48w5vmr2ve2dmkvsfG7aOUj+Z6fu9srNn6ldM1yK4kVElcuZ
X-Google-Smtp-Source: AGHT+IGer2emIRESg0/PAErVWxvxDwVxH9LmTAeJzJ7Eca4ZzkPnQVuJeUlH3s2EaXu8IOBZCllM4w==
X-Received: by 2002:a05:690e:4092:b0:640:e021:ff6c with SMTP id 956f58d0204a3-6443702176bmr6294210d50.38.1764904960377;
        Thu, 04 Dec 2025 19:22:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbIQdzCLt0+oo7sPboDoR1PcECw6rSTFR1LB3XTSwzhFQ=="
Received: by 2002:a05:690e:251b:10b0:5f3:b863:1e52 with SMTP id
 956f58d0204a3-6443e7dbc69ls1027548d50.0.-pod-prod-03-us; Thu, 04 Dec 2025
 19:22:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnPASrgAi8O59Ijy0RW+cO5+eSuZgGNboAmMXn3sVVg/q6Mtcb2a5u3XF6O1i1O+KDPwx1kmXIOM4=@googlegroups.com
X-Received: by 2002:a05:690e:1919:b0:63f:a2a7:8f1f with SMTP id 956f58d0204a3-64436fab87bmr6455815d50.27.1764904959495;
        Thu, 04 Dec 2025 19:22:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764904959; cv=none;
        d=google.com; s=arc-20240605;
        b=Rmo4O78EGwaK4NVgemeBmgeCJHvgFUuAXSwfQJvXpFH0ayf/Lto3ztRO81/gzL9cN0
         +A9P2JVtl4cBcxFPmlJRDa0z6hyL6WziF92uuzE3XSnOHAI7/bsIJAwQSG7ErZBwVoo2
         4m+2AKzYki+q065rL3NhzS6jw21kp9YbMQ4rdCCtqsngWczhfm1oyelMsgFEUKW83gM3
         IhI+KTUoOWNox+RKoDfw37C0VcEvzXP0B6jkvTDo0OY0GbhDPZWUArXzfHxhogKiNKnj
         fSSvt22rQISYTf8nxvFBdvQZ4h+tsuccWHQDxp9sWYlUpqz/1F3t8alxcT8jr/5A4T9X
         q+iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kCpWv9z+Wh8E9Cjxw/WIGZUdAlO+CTPRHuUi67T4JWg=;
        fh=TrOjbJ8DbycklLzd7yCoL6LL/baXDr8jFdbJnuuVKfk=;
        b=FrZD9g0Y0xcFmeYYBcNtLVCtygZ7+b20tmGEIJ4bcIXmIDDjWZnHgvOa9hxwM8Y0yM
         asnhJxmY70YOFtV/wIQADMMWAhTx62TX41mCPTRBsGrFlC5P1neVTtpKsD6daD6ZY2Ob
         EUNICMCU9i3F3R50eSZjAaZF4v1ewaA3CiDhzBIKfHugUSLEOp+OzskGSkXyDzPd+eXC
         sKLHBcVknssF2EMWP980GKuiCQb07k4Bm8ARCnkcknLL34hPMZoyxQQ46ChWvDzUuPvD
         0OPCqDC0Xr5f+sZsaepxfFPyNzA9+h/KdpzSQzAsk6NqDooOwJJf/15g6SVgoNKhzvNc
         HHyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AXGCPgWd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6443f580eaasi98798d50.6.2025.12.04.19.22.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 19:22:39 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 8426B60206;
	Fri,  5 Dec 2025 03:22:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C737FC4CEFB;
	Fri,  5 Dec 2025 03:22:37 +0000 (UTC)
Date: Thu, 4 Dec 2025 19:22:37 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Marco Elver <elver@google.com>, jiayuan.chen@linux.dev,
 stable@vger.kernel.org, Maciej Wieczor-Retman
 <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 3/3] kasan: Unpoison vms[area] addresses with a
 common tag
Message-Id: <20251204192237.0d7a07c9961843503c08ebab@linux-foundation.org>
In-Reply-To: <CA+fCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ@mail.gmail.com>
References: <cover.1764874575.git.m.wieczorretman@pm.me>
	<873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me>
	<CA+fCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=AXGCPgWd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 5 Dec 2025 02:09:06 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:

> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -591,11 +591,28 @@ void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> >         unsigned long size;
> >         void *addr;
> >         int area;
> > +       u8 tag;
> > +
> > +       /*
> > +        * If KASAN_VMALLOC_KEEP_TAG was set at this point, all vms[] pointers
> > +        * would be unpoisoned with the KASAN_TAG_KERNEL which would disable
> > +        * KASAN checks down the line.
> > +        */
> > +       if (flags & KASAN_VMALLOC_KEEP_TAG) {
> 
> I think we can do a WARN_ON() here: passing KASAN_VMALLOC_KEEP_TAG to
> this function would be a bug in KASAN annotations and thus a kernel
> bug. Therefore, printing a WARNING seems justified.

This?

--- a/mm/kasan/common.c~kasan-unpoison-vms-addresses-with-a-common-tag-fix
+++ a/mm/kasan/common.c
@@ -598,7 +598,7 @@ void __kasan_unpoison_vmap_areas(struct
 	 * would be unpoisoned with the KASAN_TAG_KERNEL which would disable
 	 * KASAN checks down the line.
 	 */
-	if (flags & KASAN_VMALLOC_KEEP_TAG) {
+	if (WARN_ON_ONCE(flags & KASAN_VMALLOC_KEEP_TAG)) {
 		pr_warn("KASAN_VMALLOC_KEEP_TAG flag shouldn't be already set!\n");
 		return;
 	}
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204192237.0d7a07c9961843503c08ebab%40linux-foundation.org.
