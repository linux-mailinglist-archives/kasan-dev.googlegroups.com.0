Return-Path: <kasan-dev+bncBDW2JDUY5AORB57XXGGQMGQE36XFFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AACA46A924
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:09:12 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id ay43-20020a05620a17ab00b0046dcc2fb1c7sf6728452qkb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:09:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638824951; cv=pass;
        d=google.com; s=arc-20160816;
        b=gFuNcRjjzp1aLiwr8NKgkKESiB9//m5REy0+f8lZd+nmT7DncDaORJJoQP8vqtlg4x
         qHph02GrEOBDEip7AvXdcxBd3T3T4+Fkg9mCjDYqALHkDp2FmAKD6Vs7RodurZF+l6Zg
         FqwdWZ/aBOObNWY820ywLcVTaeK7V1YGvtqgzK7KUB/wvMlaMfD1wMtyLDZ+YoLo7Z3Q
         R22/7Py8vKKnl76MA2IfAwS5IMUSFf1I8+FzC/T2PBHtKWWU9P4+DlZimEWr6gKzqzZu
         O8ZVk7t2H5moBJ3v/ZUEeCa6sceQQK9siNxR/wbFOaL0uVzAwugkcKlfVUCWr3tYi/BY
         ccHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=VaAqW8oFUewrpiKT1nZf6yb0Tq6tNALDtRbX4AB/WQY=;
        b=CIOz8ad/Lileo2sVKV5HZVSwZ6Y4mAZiLfvFQ1KChlgOyv7EX70p+MXu5IwVcBMNq2
         1NS5gw6bZ5QcS8zwH//+V3jxckx1XLhGGj0OWi0tHylsGpxf+n5W9/LBQiqX8EaDjUCb
         ZAqITWSCb/fe+F4H+7W/Ft6mEdJEj6SEHxOBW8+iLf9Oso5otuuekibO69LX8KZGRawK
         +A2EpP+q3t+vXf6Ku4gQ90X57w1rO9O0ZVCP0vJfcXvGVLNh1GvHwXZq7GwO3I2dxHR0
         uWs5ujELlNUEsbsoJi1L8kBP1Fy5U/LIF7S55w1M95WFDTITgycH0PCRDikSu+xatU77
         YUkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=CD1fMPDE;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VaAqW8oFUewrpiKT1nZf6yb0Tq6tNALDtRbX4AB/WQY=;
        b=hghx+FsqUclKz3ajZcxRe0qf72JkifVnnFbrfjFfocZn53k0XCzKiWTf3O9H//aIWv
         pNDGKkKLyOsjFPTrxvY+gB4w0hMMNWKysM4hF8I/k0SW+dKqYw2o0JdcF+n7YcCeenDK
         ghyI8046krUhf6XtMenjSApqOW+Pamj2CKyhiPDxk1GkXhM2nnc1pp7voMqNYjP0KDnz
         l9m0VHf9pILY81szUznuxE69Q0gpxp211Ch+AdyCAwURBJctOFCofjygc0kYCNh+mmoh
         3uJaoSp2XRgsn+4y1Sqmx6YE/I9r34h7Iio+dbOdtQ3CZnsuSv+oEiqudAHnLeAGWQTb
         ZTCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VaAqW8oFUewrpiKT1nZf6yb0Tq6tNALDtRbX4AB/WQY=;
        b=R66OpYygX9zQomf4X38UicAbtRco9eUug6ple2mNChbRkZXmACPUTHmnmQnEOcld47
         vEqhXZEZXZNkqXyeKlnrYz0xc69XKnr4OKBsMW5pH+nXAgwKKZxQwMl8Wlm03k9q6Hka
         uwtzpocbGHfJ/2Vt59/3n/2GnD0kxoQUx6w41fN4BDMwdJnQxP43EZrEkPsGjr8d7jd4
         lUdQ3OTa9ETs7L3r7aLRlEK0Y2Iw6LOSaLZ/4U5fzeWo92/t3nsRmsvKjrhXeaq8ST9F
         7D4llgKkReekVa/ekTw4ngFkULiEJuG9lj+HOBQ8dPMy0NqAks+hfj7MBFBo6kpdxuha
         uo+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VaAqW8oFUewrpiKT1nZf6yb0Tq6tNALDtRbX4AB/WQY=;
        b=nVWCxloUO7ba4eVqn9kS7ExhWmiNGCDxo1vY5mpEt3ybcoq6t+ORPFWaqqU9uD6gpx
         f0UTR0rxnYxCY38GQqS1dsB+1OBgD5O7CSw+Gc60yD2uGgvEFhKJ9I38P8AKxZ8R6HSJ
         LFycrKFDYzrZCs3DCV9FElMy2H3c4pNA8DfYfzgciXLqxE7sa3migN6x9hg3279SlJqT
         rbBjrLQpB9998ZDX99RpIhwnfLft5naqHJwq8GplCaxCylvCj5uAwQ57Cn56H+RhaG6Q
         z5W8xSMyoLcQjJRNeQVw8sbOTEg8GhfVc4NZ3RDWwCKyuhdjqGXEsEcJKrBJLB6tHXdI
         O9YQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SantPXKmOES5fNKGz/G96GXDZoAkAOzW7xOP9Mt1e3AXJZETm
	Jjd34toKqPjHTdq+tzdO2J0=
X-Google-Smtp-Source: ABdhPJyV2b8QscWvwf7d4t5vnVoADG52k9URYf3dQZGhaE3T1kFvK2e0bHxIYBc0kk24HiFLbb80jg==
X-Received: by 2002:ad4:594a:: with SMTP id eo10mr40575327qvb.34.1638824951206;
        Mon, 06 Dec 2021 13:09:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1aa2:: with SMTP id bl34ls12515486qkb.11.gmail;
 Mon, 06 Dec 2021 13:09:10 -0800 (PST)
X-Received: by 2002:a05:620a:4689:: with SMTP id bq9mr36122027qkb.242.1638824950805;
        Mon, 06 Dec 2021 13:09:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638824950; cv=none;
        d=google.com; s=arc-20160816;
        b=axZChxVTLc51bPSJ2ticMEvatHAkPwzyyLQMXgbRt1IqdfXOH0FXQb/s4hwTL/zQjO
         p+ivRjL1UNayzLaV78xmxZoOa+CjRcS1DR4SW66j3TsFaIBUKtU7pACETW4TV8hXH+G2
         8BcCtR+gTGlzgSdDfJZ1LjfoU2TqOpeliEkzQzR4MMMbTsXFpr1Kl/T0EkZmzyU9Crzr
         WMsHNlp3SyUe/CK3pDHi8htjJUOiXQJMNDojtTI5Y1zXn6q8lHVZsMtcSUKUbJ9gEW0W
         epRSRgLMxsdCdUn7B9YbOO81M7PgrZnObD2wgNPg0C+nedDwxRMeKzSSutBynNIu7g97
         PhVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eOK4K4S7Jgnn22bwENxP9eeLDVw5lq+Zz6heR9P+gtQ=;
        b=lXvtEZWjkSGQYs3IyyuH1IqH3LhDlGDPCQtLt/I8iWxV7pd8pcuHcoD6GKqjs6bC7/
         x/RRQbEK2Pz2ITQUj8peSjfqmQWAFRbwGXWbUTEFj7Ef6MUd9qdSXSxyANeXYOTIxp/F
         hPUtD+NoWUvUupFdEp3Q9eE/MLgZ4VAkVoyJSxdk3LkKj7hb/6J1VhgD5/KdStqyYtNt
         s/cxjOax1DgbQajYK/MuCPmiJEJ1B4gEhxpd8k/mf533x8R4Z9j+GtM60VpLCn3jbgG8
         3R7b8Tgv4BS99xY61hw7Eo5epx296F7XxvhJvsC5PrYKDUCStUvSq66wLRJWnqW32uTt
         SBRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=CD1fMPDE;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id bs32si2273853qkb.7.2021.12.06.13.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:09:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id p65so14604899iof.3
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:09:10 -0800 (PST)
X-Received: by 2002:a5e:d502:: with SMTP id e2mr38326764iom.118.1638824950346;
 Mon, 06 Dec 2021 13:09:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <4fbc6668845e699bf708aee5c11ad9fd012d4dcd.1638308023.git.andreyknvl@google.com>
 <YajX7pyIK27Gd+IE@elver.google.com>
In-Reply-To: <YajX7pyIK27Gd+IE@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:08:59 +0100
Message-ID: <CA+fCnZdWhnSDqtQ+q1RUV1U1uVtGpr0oxVK5jtUZUn=W+5rSjw@mail.gmail.com>
Subject: Re: [PATCH 21/31] kasan, fork: don't tag stacks allocated with vmalloc
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=CD1fMPDE;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Dec 2, 2021 at 3:28 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Once tag-based KASAN modes start tagging vmalloc() allocations,
> > kernel stacks will start getting tagged if CONFIG_VMAP_STACK is enabled.
> >
> > Reset the tag of kernel stack pointers after allocation.
> >
> > For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
> > instrumentation can't handle the sp register being tagged.
> >
> > For HW_TAGS KASAN, there's no instrumentation-related issues. However,
> > the impact of having a tagged SP pointer needs to be properly evaluated,
> > so keep it non-tagged for now.
>
> Don't VMAP_STACK stacks have guards? So some out-of-bounds would already
> be caught.

True, linear out-of-bounds accesses are already caught.

> What would be the hypothetical benefit of using a tagged stack pointer?
> Perhaps wildly out-of-bounds accesses derived from stack pointers?

Yes, that's the case that comes to mind.

> I agree that unless we understand the impact of using a tagged stack
> pointers, it should remain non-tagged for now.

Ack. I'll file a KASAN bug for this when the series is merged.

> > Note, that the memory for the stack allocation still gets tagged to
> > catch vmalloc-into-stack out-of-bounds accesses.
>
> Will the fact it's tagged cause issues for other code? I think kmemleak
> already untags all addresses it scans for pointers. Anything else?

Tagging stack memory shouldn't cause any stability issues like
conflicts with kmemleak. Tagging memory but not the pointers is not
worse than leaving memory tags uninitialized/random with regards to
this kind of issues.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdWhnSDqtQ%2Bq1RUV1U1uVtGpr0oxVK5jtUZUn%3DW%2B5rSjw%40mail.gmail.com.
