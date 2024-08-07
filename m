Return-Path: <kasan-dev+bncBCT4XGV33UIBBI6DZ62QMGQEPU3M42A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71ECE94B1BC
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 23:05:41 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2cb512196c1sf345759a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 14:05:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723064740; cv=pass;
        d=google.com; s=arc-20160816;
        b=tpA2gVDern7KM1HzPxnJeVsz4gZjSPaeFNFSUsW1dv/eps9rpWSJpFp27jQCYyzXJk
         z5BEW9peSQVwTkhytFq335ldek/BhvYqJlPwp69S0wK420OrfbgAnfp6vz/yi3Lhkea4
         AOzWYUorYOdvCDN4fGV5Zk7JwO5zU8QoyrcA880PyVphfLGrKRmgoZYxFkmuraKZVNvq
         dno5QbGBGAf+FhH9dflnOqkGfZqZCedh9z59nI00qU6z8OSQtHQGhr/sMiRgUZwiBhc9
         nC48EBa/qKwafu7Cf5YAhKeqd5XVuYnmW2t9DMLlrF5TVLD5/lv7xpVf/gr0QcGOD4OB
         XmmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0HqrYerRT//cf6d6uLl+sMV+wNthokBxLwcFCg0inaU=;
        fh=IA8Xf+vy7T5tlgq+D74ym74W4OlHsY4Kcx1U6OnkDcs=;
        b=zE5D4vNjWCFY1HKc7rqtcYZXVon7MeQwOGOoE8txFdGX7ICkG9W64jVynpS9eYkdA4
         qzW+enqxTW+W2EB5F2tYw95lXb1h+NJrFiQaAsqV5MYkvwG13TOuQtYi+mtBe/MRvodr
         qk7CE+sHSluk36LTcp8ZEVDrQrJqc4LU8zIup4yq7ZrE/XALrI+bft6IxML8oZFYHLCd
         HGMdk6pbeBE2XkO39soex8CcwQ6cXW3i3LTd3nIEgfB0vYDcCovRnDETdm1L6EclMzRv
         TUwZxbvnL3mdshJdHcPbiU1DVJ7MPVS9kzmyvWSgTa2s0TcGdQZMGPNo1zkzdd7uca1P
         XO9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RngPjo5E;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723064740; x=1723669540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0HqrYerRT//cf6d6uLl+sMV+wNthokBxLwcFCg0inaU=;
        b=En934Bo6BKjEkqavo0E+8seHPfB0/JuN8nvVCbqJjZPi5WI19iespFIG+BdPx4vuns
         ykMJK32KSjFePzTnonyqu/N0BNmCDeH6jdROTQ8T/sxXT7XLvLD4kzuTTrMepQ8SL2pE
         ullcSo68F9THHdRoALcov3ykGt1CA8WpD1AmD5t4eBmpf4uDKLu1cO95cgF71LxQz7us
         rydpmV1gDexF8d1sTzDZLaMfUhlB481aIZE1FhqiBk0oNXGJ7b2yxWQX9mzXhPvFLJkW
         3g2Z4Q1bVTYGiD9R6myGwcT3KsWZWMsPHAo+767uDjhuDpjT5fDJihL3co2PWbj7wEXQ
         e7EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723064740; x=1723669540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0HqrYerRT//cf6d6uLl+sMV+wNthokBxLwcFCg0inaU=;
        b=KO3IHukk92vSAl2xXYpHcR7hFXQJaeHUjVxsaUCji2CjNmtz9DoKVrNuh8Vvo27u5N
         dhwGJ8MR/ifsP8C86DpA2rQrFnGVl+exn83JF+w8geO/v/6YIsTdEn43ZPTWX+idoyqO
         opm1XX8zOXuou4L96n1FZzix3LHrUw7pwoFo5rVKLzx1aiJj0oR4zguUvV63dbUQEykJ
         i3QJsU+ouksb16HptpQAcs7jlDor/FojhLyNrynduYgA5XQfdVHCMVeyjB06VXKOCNTQ
         jsIwOsMlc7PHORC9j2X4py9mP8Zg83wm0tDDE4TRoORu4JUuJ/OQJomPFjjCDmH0Vyo/
         z9Rg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXR3kPIJgK0kYiiymHNW9h61lbwhWrMPf/gAyFfbNVAE9AovycP3isE0AZEWPABTPfyc7t9Pkx43IBk3BYHQEQUvk83UhwziA==
X-Gm-Message-State: AOJu0YwF+AO8wzVc9VbwKCK/xNkCWeUeydliCkRAclHZ1JMOhOleG4Cb
	wvklynijMeAgHtcNV4l+K/oKHkoqBXDLa0WFzGto9ONUuIHJFqmo
X-Google-Smtp-Source: AGHT+IFOYuhYNEll1JYrWf8zROLVnagQOIoFtB1ipCj6m6dj+RQP+mdshwXvq6yrkC/6cxwm+j5glg==
X-Received: by 2002:a17:90a:ea15:b0:2c7:1370:f12f with SMTP id 98e67ed59e1d1-2cff9544e46mr16735278a91.40.1723064739536;
        Wed, 07 Aug 2024 14:05:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3016:b0:2cf:e075:1201 with SMTP id
 98e67ed59e1d1-2d1bbbb399fls215534a91.2.-pod-prod-07-us; Wed, 07 Aug 2024
 14:05:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVF6iEzHBgVCTrT6bGkfb5BiqR5EbKhaE2QVZV9PzpcxKwORTiLJe1IT4s7eOsgiOfD1ht58cbovZhjbuxfFUoEM+FjOxd5SFX4ww==
X-Received: by 2002:a17:90b:4a0f:b0:2c9:359c:b0c with SMTP id 98e67ed59e1d1-2cff9517df7mr5564577a91.28.1723064738077;
        Wed, 07 Aug 2024 14:05:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723064738; cv=none;
        d=google.com; s=arc-20160816;
        b=WP0xWcYJpwiJwzSsP1xGBWEH23EC2rySaiNA0bvocdb2MUvJSA0rLz7HAucs7vUryV
         3soecoGpsxiMiBaxE538w8MEZhlv369k6L5LoOQcJSjpQdUZIL8zog1BkTO+rGX5gXdu
         Xtcu0X0gkP2z5X6yKUh8laMMfYpe0uQgpDHis5gn4wAxfurWCeprATZ4hSRa7vqtIm3b
         KCLwssXKi3hHucdf5gH9EApklFNRvg9GtlkxASsjYYAbdhkhFG+mv/J9Z6dxOs1PE4Ny
         anzRNXT8bqEVJY8GLuXW8+Pszjd6SGeUktSPCiXsmzVImw/Ck9p0zSlYnUhjEOgMZ6iY
         OTeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=745C4DP0++OKQc+6a1VnQiRdoZZyBwm3vJkH6n8K9gE=;
        fh=Za6rUTfYiYX+MiQcO/48lNt75C09RfnAaENl9l9w0X0=;
        b=OW2QAZEgKqwVeeTRahad2zv5l/9/mTdoITwBmHWaJLWrjrAmRpxSKCWC0r2ACE/JwD
         7xH0uPDMc5UUeuBl0uq/PwFzgdOl7dWKruR5+XS+MfexntvKbbZ+zvkI1WSG5htea/Y8
         RuIgWEJUsR2y7+ZxRVZpi+7BLkpG2CozMU8fDgHa+LUcRFMWOJyOUSNeLXGmcb65ocKL
         i0CpqV0ciO/bWr8WDAx0vclATHuxMpsVbxfuTm61OArSeRheY/ojVQOtcuTNRi6xiVWL
         sQITv1oJEspl9+0wV8BeDIybHsOpe28DzYmAIFMXmoAVuuGv+FvqR4r2XNEi9yQk7sqY
         yxJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RngPjo5E;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d1b376054bsi98595a91.2.2024.08.07.14.05.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 14:05:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 6C2A161361;
	Wed,  7 Aug 2024 21:05:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D3B4AC32781;
	Wed,  7 Aug 2024 21:05:36 +0000 (UTC)
Date: Wed, 7 Aug 2024 14:05:36 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: "qiwu.chen" <qiwuchen55@gmail.com>
Cc: elver@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, "qiwu.chen" <qiwu.chen@transsion.com>
Subject: Re: [PATCH v2] mm: kfence: print the elapsed time for
 allocated/freed track
Message-Id: <20240807140536.0c01593d22c6a32f9a5d278e@linux-foundation.org>
In-Reply-To: <20240807025627.37419-1-qiwu.chen@transsion.com>
References: <20240807025627.37419-1-qiwu.chen@transsion.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=RngPjo5E;
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

On Wed,  7 Aug 2024 10:56:27 +0800 "qiwu.chen" <qiwuchen55@gmail.com> wrote:

> From: "qiwu.chen" <qiwuchen55@gmail.com>
> 
> ...
>
> Signed-off-by: qiwu.chen <qiwu.chen@transsion.com>

Was this intended?  It's unusual, which is why checkpatch says

WARNING: From:/Signed-off-by: email address mismatch: 'From: "qiwu.chen" <qiwuchen55@gmail.com>' != 'Signed-off-by: qiwu.chen <qiwu.chen@transsion.com>'

Perhaps you intended to include an explicit From: line in the
changelog to fix this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807140536.0c01593d22c6a32f9a5d278e%40linux-foundation.org.
