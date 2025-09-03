Return-Path: <kasan-dev+bncBD4NDKWHQYDRBBM34LCQMGQEMRCQZIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 60A2BB428FB
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 20:48:39 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b4c724d27f8sf83454a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 11:48:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756925317; cv=pass;
        d=google.com; s=arc-20240605;
        b=PambkrHMNjmlgZOsJfwxSr2AuAJThPM3BXKMgqqNqvg40L4DM3VQUaGjNngVSVw8pJ
         AtGN+3T2FkbO7CwlIXJmxWoxgXYTzlSp3k+E1pW2q16RnzjTmGzsZvXhYESbz5iFGtKw
         3QY9JHrXB+jLw6hO8zmtRryfyBnIEuOn0r4ulSKd8tFfBOqVgeMPvio+L2KI6ZudBNzR
         3Xt1vH9y2B/cdr0+R55w5542OCHuS19de/x84iGbIr0gfY9e3cHXEN7kfHtLNAQFNRj4
         yizWI5ECtesZKdZhKHEVYPwyfhBZnj+eeVF3xhug29AuOPiP5wt4JkGvH3iJ2kbmGzGz
         feSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VfwmbAtGE7AQBSy971cFfhqO/zAgm7KvRpIy77EhiNE=;
        fh=xpw2tsAT+KmhuqkJRhGniy/SoS7rTyjjJNFBSQgXros=;
        b=fpW+GbLLt5EJoYdm+sKyqXnhZCnTeK4+OH1wTXW7qhJWQ16LmuoLZe10QW0cUMHfgZ
         13Yd3rxnI4ilANkAUuhaON0l4DrmhXjMJUP3AcZwNPoY447W8aIfU6q51U2v0O+xs1c+
         DFSYZEXe0KUrKpVOEw2/j+XcdMx893c2QvLV5VJmpo6jMql5m5AiNX9UrpujLhKjUQZ+
         w2U2ZsoKCOowsNvmpnV+hEeA87RsQYeILzmPrMbUbMlTNTbGoIMf4G42XIoLt1sN5lBQ
         HwdNAYpZlpXORRQ2AC9TDnoxH5ETa2SPYhbKk4j874ukujBq6X3knnPZ1q0ezRC6w9gk
         Hy8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lqCnwi7N;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756925317; x=1757530117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VfwmbAtGE7AQBSy971cFfhqO/zAgm7KvRpIy77EhiNE=;
        b=nJv1YPJXvWN6vdqKS5RD2gBsgTNmfNxKvaRg4mZbhyVS+MnYRUuRiMsakCfz7lOG7f
         VTt7VwvHAKXF1MnwIbUGplo1istkmryVTLmIpR76ZgknNdkMXUoxfWdf2gne4R1Wk88p
         xtAGm35q6xGnlZY4KNsz7XCmiWWY15BjGO5hEU7UM724GOSNgqS4MDDnbJE6p3RlvN2j
         bt+QtODOIrG+NMyFn6Jm2OVxSMxV1kw/6KfRwbb3Ju3XhYQErSvFGqO/M79MIDmj+kYG
         UBUbfBsDCWjRWEoyO03Nj9qtPBoBmYKW5VXw8MMcuRbFtNl7xYgAt1usBStnmfnJJFnh
         /cQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756925317; x=1757530117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VfwmbAtGE7AQBSy971cFfhqO/zAgm7KvRpIy77EhiNE=;
        b=NuGir4oSPbEwZ/hyWE7gZodfoC74ZVE845dbx3V3MXcT5XV0MesL6lEtYQwqHLPZJK
         ewsD+nQOa3mxUmIjHKtdWSAH/lVSwOKsduMi0ZyL3YsyQnYx5PrKcpKD4Vj12OLam6lo
         1th6CeL4iJ/OGaaOrKlH15a8783mb7bzzXhRbFuqjrLQVpPgdEgof2DlAt62geIrKYZs
         JxsAUZupniu8G2ACn0jzl274neGluqpCuF3UU6azP73Vgq9O5hi8RgzSCFoCoRt+BFbR
         Lf8ohVQzX76VPIc31pCOfCU+CwgJWFwKahwm+2mShWNyClMKbAcF8sfxsiYveaWhUePx
         uVWA==
X-Forwarded-Encrypted: i=2; AJvYcCWiEYhYoOULDCVj2hr8ZZOB/owGM/XGcNri0QTMBaTQyjD6ApNfki5guWJnUhaZD+k7hAqxaA==@lfdr.de
X-Gm-Message-State: AOJu0YxKJquVtUP0e5kNhpD+O6sRycoLAHfC0uQmVmBNpIXeGNcsPNjn
	+1qOp4UhiCJOUR2mkCL59GY+Ad9icWjDOkuIFM7JXW7qI9vFMO32cTx+
X-Google-Smtp-Source: AGHT+IHoywlCu2lOFc17uONX6SXdrbStIs2V+a1mfOJQtQ88YjglsV6jOHzhPaoz1H1F1eY9yHZJeA==
X-Received: by 2002:a17:90b:4d92:b0:327:a638:d21 with SMTP id 98e67ed59e1d1-3281531d3bbmr21707112a91.0.1756925317446;
        Wed, 03 Sep 2025 11:48:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfK8XQhlzIcS/2YiPgI+lWuT6PT4CkE7RLZ4xNJ9TZuLQ==
Received: by 2002:a17:90a:608f:b0:325:3358:2efa with SMTP id
 98e67ed59e1d1-327aacfa50cls6305720a91.2.-pod-prod-05-us; Wed, 03 Sep 2025
 11:48:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN0c2Uh+s7nnEXFp4aLcvM9AzY2jzWFQ5km+GoBgrfNWPWSHBlr8javOeJJDKqhTJZDnhDHQO8Umg=@googlegroups.com
X-Received: by 2002:a17:903:f87:b0:248:e0a2:aa2d with SMTP id d9443c01a7336-24944a75bb9mr207649605ad.25.1756925316045;
        Wed, 03 Sep 2025 11:48:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756925316; cv=none;
        d=google.com; s=arc-20240605;
        b=YwXgLwfFC8AwtGiDoDoTr0J+CFTsrr2ndeHYMm4xLoXE4tzFFlK4OhlKptWhyBYdfV
         uF5p6pC+9iDvD1NHS4WcXKGTgIyOIvjWh2gSrlcXw9hiLa2KckAzsdQjKBXeSIXMiPAM
         PYJgjk8M9GQjamSP/6SHFW61waIwQub03TGvziabLLhO5bsiKXzEODuXchA+wNRQy5hF
         Ffb9a9c4bLlhb1BAC//jtbaWzAhIC8xgGkBGJ1W3qY/8oMJTO7nLhFIzXEqQZQGgJ+TV
         Ji1a+Y+ixgAapQNPBVZHtUnUvbpdLt8m3Pcy8k/MCd9OWh1tO7N6JrCtHicmd+JOTlst
         0ZSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=w13NCpoyIz+MVs9GCJONudVeBM2fy+jIQB2hgsksJYY=;
        fh=SbMsQtiO1DqL+8IxdotI5sXIuk6SmsyABdQYgAh6dk0=;
        b=lAdXeB0StZ0IwYaFjq97hde23GeJiRUxlYj6/wGASt/+1O6b4c2UJ32NS3tfhQhkhC
         mQXmRZsiUxfyY47d8FAc3db93zWdSDtUazTNqjggcQ1E4J1t7OzUsMIEFIjDTZ0/8bGQ
         WxRuXMw3wnxW1d7NEfel0DRymb+1gAwJyAm8Gan/StEn2q28TMFJcy0Ps6aFu61HbM9l
         CJYc3CiuGqnOL1FPMH6RThCvTo55GRe4GnOJx+XqkFvg+RWF3WGPABVxzhBrgLSNdz6h
         BFCTm44c/RYW5zm2tDwc2kPuWUsMBxkXzgIG7dEED1jln3CiTLHfbhrUwZNedJ4qHnXh
         oahQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lqCnwi7N;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2490659ac10si7516895ad.7.2025.09.03.11.48.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Sep 2025 11:48:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id AE05D43962;
	Wed,  3 Sep 2025 18:48:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 118F6C4CEE7;
	Wed,  3 Sep 2025 18:48:33 +0000 (UTC)
Date: Wed, 3 Sep 2025 11:48:31 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: clang-22 -Walloc-size in mm/kfence/kfence_test.c in 6.6 and 6.1
Message-ID: <20250903184831.GA3004824@ax162>
References: <20250903000752.GA2403288@ax162>
 <CANpmjNNV=ZmjcGWvPwHz+To6qVE4s=SY0CrcXFbizMeBrBaX4g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNV=ZmjcGWvPwHz+To6qVE4s=SY0CrcXFbizMeBrBaX4g@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lqCnwi7N;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

On Wed, Sep 03, 2025 at 08:00:00AM +0200, Marco Elver wrote:
> It should be silenced. I'm surprised that they'd e.g. warn about
> malloc(0), which is well defined, and in the kernel, we also have
> 0-sized kmalloc (incl krealloc) allocations being well-defined. As
> long as the returned pointer isn't used, there's no UB. I guess doing
> an explicit 0-sized alloc is not something anyone should do normally I
> guess, so the warning ought to prevent that, but in the test case we
> explicitly want that.

Heh, just as I was looking at silencing this, I noticed a change to the
warning yesterday that explicitly silences it for 0-sized allocations
based on other feedback from the original thread, which I should have
noticed.

https://github.com/llvm/llvm-project/commit/5f38548c86c3e7bbfce3a739245d8f999e9946b5

So there is nothing to do here now, thanks for the input regardless!

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250903184831.GA3004824%40ax162.
