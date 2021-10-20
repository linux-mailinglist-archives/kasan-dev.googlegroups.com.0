Return-Path: <kasan-dev+bncBCT4XGV33UIBBBEPYKFQMGQEHJ2HT4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 14004435533
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 23:17:58 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id t9-20020a63b249000000b002993d73be40sf13988733pgo.4
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 14:17:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634764676; cv=pass;
        d=google.com; s=arc-20160816;
        b=fyYgl32PGw46twb1H2Vw+DEc0QQcZb1z+dtIMXe2mitz181L5dTiSjeK5CxiX+9z0e
         YVTLbtpnPWYWhgW5F3Mc/Fy3FizoV7kswsYBbwZ7HTNMRBndk/TG27YpbIQqABOfW9wj
         yr7ioPi8f9BXC0lhogcJmsbfV2+ObLrzMb7ViGqdzobwGQ4H/Yudd9nd601pHWhgfZ6+
         Jeh3cryrABi4yzpMd7hQzqEP2H1YM0L67PHtOfbhSh1jTzruB7mdcQRLAhAfDKVl+yqj
         6gofSkw9MkyMR9NHZjv587zZI26G6XY+EalEuhB+K90rgYSry4GXkysHroJhB3DrhuRA
         UECQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Kf6ZtRN3GHcpgEAoTAZYSxx28jkulvZADLDGNQDI/9w=;
        b=MEbP9RgGfXeePHkg6RMj7JejC7fDkNW7aqmGS+uWoTTBeURn9TPYDzS7ERtpEjzuju
         5e6gOaej3nmXvFrqAlWehxwqwNKnAIUUNp3Lj7MkbB1lhVTO2d3KOHa9U6Y9KUWb8+fs
         pFMhMqNArMf4PYgd7uRGXoLJiSUtE9JncjoxFWuN4dJ6IwCIcsmqfplGFnR7xW4nhciv
         46rd/HZmErLLns4rDKruOsz1wyb+fldocS+Ya+ZxGKl60lQX+R7o9MluwgSsjwsSpUdZ
         Ebz4Tl4rEWItA8m7gpRAt01/xPlcx+d0pLCZyROm2En9znkaRz0ZuJ1qdrSWZOCXlyqN
         xdoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WgQtmmh1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kf6ZtRN3GHcpgEAoTAZYSxx28jkulvZADLDGNQDI/9w=;
        b=ZqAY5KhjHvZfTSqOZ2JhH6Zsw1iB+wXVWLJm8yGx9FPrpd8XEqgnN9kJUqO/TOvi0G
         Oxcoyxy3RPXN42HlRWmmx1zBghMpYB1P7/Q2GAqnNlueYVgCIcZPAjb/vItbGsXqHJtR
         9FQYtFp0RjIzF6azbCaRBD9GeA1WH2PL9ngjHANoPIx6Bh/SO89ukD+PPLm1EDDeUUuA
         NnnyavQNuuRqfvviXHSZlpKQOGZyKhD0H04/eQ8EdBMM3RHwBsZq30o1YkkoDUA+t1r6
         fm9Ig/23QQYvA0aGi7/86EBv8xH4XxlnXnCXZ42Qw6YuZmTgjTnosmwmYdM/isscu4dL
         8Eug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kf6ZtRN3GHcpgEAoTAZYSxx28jkulvZADLDGNQDI/9w=;
        b=oFSWPmT0wgHgufjD+oFwk7exucU8k6/ejujbHD0aHs+uehwypL5EQMbHIydmQCrjBa
         hzU8cAztQejHGzOhwT4kVNblpTTint25tHYXvHic1XCd3T7PHGc/IBmc9Fz/QsK+2Ua4
         rav+p2OkUNjVt7c0xjNbOlOqZDof59G5YKiJEFtylWkDhzlIcweUiV+SoD2hhE6mpF9B
         RhpefKOzvj7VFDTlrFZUNpfmGnaWDiVr0vl413RaMcMAKP3ZiKtS+Y098UaEcrzi+rlm
         F4frF4QAi3tiU99iBIOd7ppaaD5tVR2oClmjIB7FFoYUkPqpL2GuJ5q5BR4AXJT2VvSY
         x+ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vtlh1PeOJWMjUMttPOk0Qz8MZqVNhBfwbF7KoFakWCQutMPyk
	bO7ugPTj2wRUEsy5TlLE3xw=
X-Google-Smtp-Source: ABdhPJwQzhlX+6451IroadcR+KpFPlKC5Q7CcruFGb1JOh78HEYqBJcGyox+u4TH/f3NJZjwyBEXzA==
X-Received: by 2002:a63:ef58:: with SMTP id c24mr1258013pgk.299.1634764676775;
        Wed, 20 Oct 2021 14:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7846:: with SMTP id t67ls1196277pgc.9.gmail; Wed, 20 Oct
 2021 14:17:56 -0700 (PDT)
X-Received: by 2002:a63:3f4c:: with SMTP id m73mr1201998pga.437.1634764676125;
        Wed, 20 Oct 2021 14:17:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634764676; cv=none;
        d=google.com; s=arc-20160816;
        b=yPUg346PbfKV2uQBQ73fFzCVpFHZYvhSerQR25GtE8f5+5ZBakUYfXTkA1HfulHfF9
         JOVK8C+cCvc30yytOO3AEsGufC63DHhvfJQGixpQkKP+wepAIelQMup+WPtZmYoBcHNj
         +ABVq+UNx6uUIHxHT1wQkPyj9VJXmxlKXMZF2jbio+uMFTkWvMgciyOqzh0KOvDqDJXz
         LIqIRruglmSlqXTb3HZ78hqvSk5d3LL2A9r7OjfjQkHCt7lU9I20HJ7Objv+kOg0OJEL
         yNz9XyOA16JzZJ0fDcd2ocOb62Y3CDkZIaVFKLxaIEo0WuZdp42KeLArm5CN7BJiyRdY
         cI7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3e190nIQzzStmEyJBu9scxwdzEGJGGLVEjhOCCWwEAo=;
        b=gbjOnvO8thyiln3hxa4Hqvefc5mH80/YFuBfPUQsTTy+ynJ7cI7ntEVzVdc33T3zkU
         xiNHpxGYeQzK68aJwcA4LekF+yzLFAmMk07iGvDFuiIE+I9+iao7DGtFRWJP/LswxycK
         sAy8i/npj7YSWJJJnuDtmXqmy9UiEjwGqGJuj3UgCLEPfhe5usJDqtZ0y82anGKELOyn
         /VS8FYfeq6zbbjcDeqZOVZhdNAH/yfBpU43pyZTk9tfN95GebZSXqpFHDCAempI8UPyi
         GxYlg8pEuFDnloQejjX8xQX06FpqcOwUYdBhRwE5Xr0JFUONKLnMYLy2VVerAvjEo4Ho
         6vlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WgQtmmh1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a63si352223pfb.2.2021.10.20.14.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Oct 2021 14:17:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7FD43611ED;
	Wed, 20 Oct 2021 21:17:55 +0000 (UTC)
Date: Wed, 20 Oct 2021 14:17:53 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Kees Cook <keescook@chromium.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kasan: test: Consolidate workarounds for unwanted
 __alloc_size() protection
Message-Id: <20211020141753.6d1ac5ef251367bef260a3fc@linux-foundation.org>
In-Reply-To: <20211020193807.40684-1-keescook@chromium.org>
References: <20211020193807.40684-1-keescook@chromium.org>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=WgQtmmh1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 20 Oct 2021 12:38:07 -0700 Kees Cook <keescook@chromium.org> wrote:

> This fixes kasan-test-use-underlying-string-helpers.patch to avoid needing
> new helpers. As done in kasan-test-bypass-__alloc_size-checks.patch,
> just use OPTIMIZER_HIDE_VAR(). Additionally converts a use of
> "volatile", which was trying to work around similar detection.
> 
> ...
> 
> Can you please collapse this into your series?

Folding it into something else is messy, due to dependencies and
ordering/timing issues.  I queued it as a standalone thing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211020141753.6d1ac5ef251367bef260a3fc%40linux-foundation.org.
