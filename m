Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKHO5SGQMGQEBAM4HRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 93FB7477245
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 13:55:05 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id v15-20020a17090a0e0f00b001b10461f2f6sf1703605pje.6
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 04:55:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639659304; cv=pass;
        d=google.com; s=arc-20160816;
        b=oLDw3idA//tRFDZoH76FL4kPpld3mOPIf5tOHdP1kKfFDZnmipKsDOWEsI2Jcjxp5K
         34KZjnNdFEQGkKG5MigEjIHoeTLmGU+PxrfDCYCrrqxfBhfno539AONKB+6uTnC7En9p
         rDB7YYhy23KnpuT6scZ9OjiZzoywnp8nfRDzVzjuwa/8Rfytb6fwvTENwTHhtD2zH3HV
         hHgkBeOSp5ibzNDpxaCZqqTSFeIZMBAUOQWN2FfgRPC8W7Hzxw211OxlMdXnndnT/kcE
         EMOZQG6iLm3bJCoEI6LGACZwP1KjDFQpNR+y87fn5zGLXE/qtX6d/Z6M2EbXlw+PRJmQ
         y27A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Nbqfea1w2QBCkV8nJyvgb4Bt6zwJ5zmVFE8MaeUcH08=;
        b=LUexnuwKvwK5lFbTDXSddeqR8WgSHRIuaJqR0kzTTp9tEB5vZSqQE8grN/AAtMo0Uq
         3JWLMFoQaUqtRYDgr159dy5DK43yrimJFgYzBOa+vatd2GpHG49RE0hEMg5sbU7lOy4/
         rs+YgsxpQEgCHUnY+Zhnnp4tl8lh0aOS6C+4sR3XrL9nYZh9RE79X8u6Ni4I/TCNsrHO
         Y6BX4J02/NZDTMeeO92D+w2tshlspZG4P0OPRXIOvA/MbFLzBdg14OG3X8wdVuNkAu6l
         OUE1oaxOnIHZtjYT2QSejm0tO0nGtmZ2zhqfJfVWVgFF+vy/HHBH+ANrOCnhomJ0HSsA
         zizA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F0qVsIO4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nbqfea1w2QBCkV8nJyvgb4Bt6zwJ5zmVFE8MaeUcH08=;
        b=j8SYauueiNIA3wXA7GTxUqSLHuww2Ouk+SVpd8xxbIxcnbYQU55BysMRkK97+DZ6ht
         qFg14GWmDF5hnT1mNsJ99iBNodzyy6lKr43XERq4ADPMZr7h3r+u4pf7LBR6bVgBsRVu
         ippCj0oF3Ki7ChCSnHgmfhN08FsESOESZ8kyU0D+Tp3tJEWEmYNmXpfR5TFdy8cxssDX
         /pQn/9EhbPZyVLAijBOJfHR92mmw2y6WEmKh39w6gyLqpD+NU7VrPu+fq+LLKQ4IbKYw
         PVzVjMKDkA4WBsextUeb6fQQglnKasTcnYODJpn6XmHqRGYXE1Na77WScFXhL5lg55l9
         6yeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nbqfea1w2QBCkV8nJyvgb4Bt6zwJ5zmVFE8MaeUcH08=;
        b=xGMVusILUTMSwUcUHQzFXEGD95Nj5EeOdIEEhPLiXyWCc1l73EI2HDEjkcgKIy4Ti4
         xMokMtckE/3K7hUWrSXwNKsmzceawcPn9MtU6fyCJKa4SSGOrTfGFJVA1MkhZ1uOPLb7
         5Q2q6XDrP06BeHwj3A3Z0jkeaoJeiX9yEPBae/huzooGCOQcB2x1IQSUZbAW8ZeY07/m
         0B36gpvUah7zqRaQwl03zhGvVgzUxNeNtv+i5l3869yqJAVKQxJC3ac6cm43OpL+1HoQ
         pP9RYmMh6PjuJM4Fhup/iVFtmgt7slfDIsCOpdI1mbWX6iYrZY/9jj9mX8aUqiSbC5Mm
         Budg==
X-Gm-Message-State: AOAM532sYeRXmUAAsvoeOWtFDKeKw+5AtCvqEM7vioG3jVUOcg/vlW8t
	UFimhF4ewKzRiJFHr2A3uyA=
X-Google-Smtp-Source: ABdhPJxvm2JaZxQkVllETrPmUV44s6j//An92RNE01BeS0Bs7a7jQJ+/cu9/bSRwIdxywIgd47julA==
X-Received: by 2002:a17:902:7c8a:b0:143:bb4a:7bb3 with SMTP id y10-20020a1709027c8a00b00143bb4a7bb3mr16597218pll.46.1639659304321;
        Thu, 16 Dec 2021 04:55:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1946:: with SMTP id s6ls2308600pfk.5.gmail; Thu, 16
 Dec 2021 04:55:03 -0800 (PST)
X-Received: by 2002:a63:6d4f:: with SMTP id i76mr11842037pgc.611.1639659303814;
        Thu, 16 Dec 2021 04:55:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639659303; cv=none;
        d=google.com; s=arc-20160816;
        b=jhc8GD0hck+4vIMQfTwPbHM9187sLp3yOngxsYESbtt6Rzf404vFGvt1fPEv6HKcQf
         EjkcCLOe95X55fN/iBwUQXwNpkG5y6GSN/EWwec8QsBHu+uJLc39chvfy7av1gPMNlf+
         Xf3JN1yRekSDHDlwREAbEuC0nkskXcnuTz84LH/QJ+Jj6rCoE3vRRNHY9+PPoAzxJaMX
         0ok7Ant9RTMh5Vzv+rHw7e+z/c0Qi4ZkQck/1lqm7v+09Vo9lNgX2mWzH8zKZSmj3/J0
         HV//VbYY8eiIhAmGPGpyiLwamcMzbsXIb3VJyHlQ+OJsuHTYmNW+2QK4fGoQiolcnG/3
         KAxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gUxka4JklTkkHlOcWoZDOb37rmiSUPCIVM2O4zND04I=;
        b=aQ9A9SzOptEo0QnRBsFiLc1Se0Wx6424l4TxTVgGLC7g+fua+LZqMCWErR7Fx4bHUa
         6lDEOSi7Gr67J8URN9uNF0tmV5audbac9K4bJGo2QP7QwRpXtfNHu/ezZmrnjWWurTmR
         nhh5itqKYJ4lWl5ac+Rs8YbQWj6GGi0vVwLF1qfebGOGZI4EycB14ZpnLNuJIE71H9Vw
         BEDHTCFzYk/4yur9PO3TPyaNAM3EYkRIjK6SXY+6Okh29IbTl+xdExAsqZaDp5ldNRQR
         1ktb+khRqD7c9KsKwOFJ6tJ2qt7LQWgK4NdJtlfpZnfA/oXhy2+ansuL6/U252zm9O9t
         m4AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F0qVsIO4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id ls15si149940pjb.1.2021.12.16.04.55.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 04:55:03 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id t34so25291606qtc.7
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 04:55:03 -0800 (PST)
X-Received: by 2002:ac8:7fc5:: with SMTP id b5mr16915979qtk.492.1639659302910;
 Thu, 16 Dec 2021 04:55:02 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <4b39d778ac71937325641c3d7a36889b37fb3242.1639432170.git.andreyknvl@google.com>
In-Reply-To: <4b39d778ac71937325641c3d7a36889b37fb3242.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 13:54:26 +0100
Message-ID: <CAG_fn=VfGP7JT6ZJshsh_+rA4MR3gSM67CXCF7uhEQ6WGia6Dg@mail.gmail.com>
Subject: Re: [PATCH mm v3 04/38] kasan, page_alloc: simplify
 kasan_poison_pages call site
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F0qVsIO4;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Dec 13, 2021 at 10:52 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Simplify the code around calling kasan_poison_pages() in
> free_pages_prepare().
>
> This patch does no functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVfGP7JT6ZJshsh_%2BrA4MR3gSM67CXCF7uhEQ6WGia6Dg%40mail.gmail.com.
