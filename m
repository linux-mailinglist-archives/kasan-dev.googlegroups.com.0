Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXV4ZC4AMGQETUOYYCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 61A029A38AE
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:37:52 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-5c999f254aesf1356027a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 01:37:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729240672; cv=pass;
        d=google.com; s=arc-20240605;
        b=MY7o236HcGcNo2QGFtunmcBveqn31TjnIZN5ZDjp9ofJLVyF1NO8pHiQBWxLQ94wR9
         cSdC8offB2velT8LDwzwjj8REFfqE93mv5lD8OsKLa8xdXcWdAMLmDONyRuAXQ9XJlki
         iCH5UyQx6+cMGX84zmmVLKeXYoS2pOxRRLgTM0pcivYPHtRMtM4iRlYV/QmMo3CgJzXX
         g3jb6Sva08mxrY8pPvBWIJzz2XfiVBjv8LR7l6go5kMkR70j2m84YLcTMy+ArMaSBHwq
         aIpSeKpbZIhMKvuI6P9pJBZEvfYXDmoDZJQg0jC2eSLCEIqI0moIJg/iAykhz/Qlo/xS
         L3BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oA/sNbWhNxRpTSNf4tkjRT/GtbE+rrakeZVzmCA3J6E=;
        fh=+F/t49I7GmEla0SzmIwNDTdOojlX3KV6qvSE85Fs92A=;
        b=XloKM3ekPI/XsGLCQMkpZnbLUDZ4fH0Ncpatd94/UpFuKxl2ydoD0psfv5WKvbd46r
         OiNxs6lB6GzHUiT/p4Tz4M+W6xFsJqEQddgaY0Vj99AFkQG3msz4vnfVrRKIm4otFLFR
         eSUZskpNokQLuGxpRekrAo+LjN7nY7XvaOK9x6EOEz9zGTHyyKLuESYBadDTTcTfIx/e
         bRAT5siXDHRmJfHRgTsStT+mFREPBcnp2bP9v5N7c95k+BiohqiMF1BJaL3CoXo9gqmH
         Cv1oQW1zVaq+kx44c4lEe4683+GmWfE3sG75rtB67DpofqwfCnglYjL27bvpq82Hj+O1
         VBiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1m71Tg7e;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729240672; x=1729845472; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oA/sNbWhNxRpTSNf4tkjRT/GtbE+rrakeZVzmCA3J6E=;
        b=BFr2bii//+U2GNhxgjCFi+gjgmKYMPUqpYzKyJ4BDZx0VTmVo/+epdJoVlVybXSMsG
         QY6lmwhDVxkx7MdeE/VTbLJdSNOCp97S7DaxpTeBiACCbmGWxzCKc3zwN08Z0eKmkCj3
         t7F53xajMCwgEW/MpXgwyT8ehWY64rGnTY7FpSgSv8ehTf0QXuN0QwYtgo+sH/QYuC29
         LNFwWGfXUOCDodEeoSBfm+PBJNW9jZM9W4Sq1aGOO470iKejNq0hKtmWpBiA9kUNuRpQ
         /VA+Be12+G889r5Cr4V/nlttgm58n86PQ9QC44nvpYTh3y6qwe85AmHgfWLLDykZDasW
         DFig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729240672; x=1729845472;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oA/sNbWhNxRpTSNf4tkjRT/GtbE+rrakeZVzmCA3J6E=;
        b=uHxsb/jC6MLxrFjH0ae9j6B6D5rNTtwtsp2qI4p5IKZSlyrTfyQ+srgtNhAmtDV8gA
         yC+BRPIzBl6JmqzLZi6cyHwQso+qwjbQXl8Vo3G+sUGyZnl/mEkX3BFl3v3F/UkO7anh
         KPxbaggnqlQD2LSiS7k14t6n589+Ospt3TUKivhTYtl+3CDQM5Rf/FhvfhTLlT/6J/Sa
         7Z6t92NVQUWEYr1UmmN04uyq25T033b2uLTWf5THBHWUayliIXb9cF71rahpemL6MtIW
         uF8KO/gFr5vSeFuo+7/jRHjbTs2uG5N6ELp+zT5C/tbGGcJXKyuMH3LD0plFJ41fCvTD
         PUYg==
X-Forwarded-Encrypted: i=2; AJvYcCX6bJAQ12IEqEix57r0vpH4V5IZzl0FOQzGKKxquhP6i3Dz875VjnVg7G8eh+mP1+s+UFj75Q==@lfdr.de
X-Gm-Message-State: AOJu0YyxcRTkukxNVU9ScNrh66Q0TFwDmY1reC8c50Vz7d4SZw0FBZd2
	4ouJGLVvQ1Ks8yC9bX0s9AZFpFEkldQbM0IuT0rfIolx9vVavDnC
X-Google-Smtp-Source: AGHT+IGDUTEuxeQbp+un5NlmuVd2Xkz70zefKB/ou8gUeXYA4rRS2pFfIpuinSVtsqiNiiMeFEDhIw==
X-Received: by 2002:a05:6402:27d0:b0:5c9:27de:6e73 with SMTP id 4fb4d7f45d1cf-5ca0ac43571mr1301989a12.5.1729240670914;
        Fri, 18 Oct 2024 01:37:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4410:b0:5c9:3fa:8237 with SMTP id
 4fb4d7f45d1cf-5c9a5a27821ls21763a12.1.-pod-prod-06-eu; Fri, 18 Oct 2024
 01:37:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCSvulV/OahR2qMdCc7kaIz561dmfJbWog11BGOMdIYzFUfYuQqmVA0Sh/yCXm6kXhltQ4ghChI9M=@googlegroups.com
X-Received: by 2002:a05:6402:2344:b0:5c5:b8bc:fcdd with SMTP id 4fb4d7f45d1cf-5ca0ac50e30mr1182519a12.13.1729240668447;
        Fri, 18 Oct 2024 01:37:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729240668; cv=none;
        d=google.com; s=arc-20240605;
        b=BFK6DpswLk95LiZ5auctMCsVKLUncANnknMsjGmrC3NFsIm4yXyegQ4fTKtId1Sah0
         3gw0znWEYGZgh2fUhZ7kwIx2Fj7igjHsZeAoRZ/utZbgcz8Db/yJyTjYIj9waaOcuQHm
         LVXF4gptgcDNhUvWcb8i0mLJfycV32w0ypD1UY8fBO+g92Ksp2uWyCtLOpsAqhqfk70P
         pWEKacvK2VT9E025KgUSLHUuG+xh7geTq5JmDDFmlQ9GBcVri1D1gQBiZpwgKxZV3f1Q
         TlqB2zIHxr3+RM5VOrMNMV92gMFnpYV1aPABmnvnsu8k/8+3g5QR7xnO+dIt19TccFW1
         E0+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/6yd32eCbtlLyyhJU30GZ0XFgAZYNVzp9z45d5h+EaM=;
        fh=v7uMfQYasdBo/qRbh1j1oRC7qzdD6+0qbs7rximgqqU=;
        b=UyZeJ2XVxgy9jDsLFUjzhDuB3ed07cO+qVMKt/TdACIRVMlznpy/FByecOFC4g5G+W
         1t7/bYxoe6mAdDVEvrwQ6JN/mzu0bYwoYMdDDWwIvUqn2SZM/2fkRqIJMeK6SsS3CpKI
         7H8PUrO2xKOEaWO+vAVNfEdeI9X4SmTj0y+wAjJ8K+Q1x0noo9ea9PfldEcOGiANdqzt
         kLSX0lyyz74lzBmVktPUh5nM2X8+WSaVzFHA68jVt06pl0VVgmYabxxH6/b0CIfJ8aZ9
         JS6bs2qqwDkMF89xHDJO8dL8d1kZ2ZpZzc8bjnYUh//adUYAEn49JQHqvZoqWqZLEKtP
         NYBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1m71Tg7e;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5ca0b0f2adbsi18346a12.3.2024.10.18.01.37.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 01:37:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-37d6a2aa748so1213948f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 01:37:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+FQzZA4o/SUlkyXNMzOEQ8m3cOThSlAFTEkdOz0bZQw7X4HjhaV1c4oCk5ssPDkauI0b3XG8nMFM=@googlegroups.com
X-Received: by 2002:adf:f744:0:b0:37d:5103:8896 with SMTP id ffacd0b85a97d-37eab4ed1ddmr1058788f8f.41.1729240667888;
        Fri, 18 Oct 2024 01:37:47 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:5ff5:1ffe:9d80:ada1])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-37ecf027d90sm1323673f8f.8.2024.10.18.01.37.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 01:37:47 -0700 (PDT)
Date: Fri, 18 Oct 2024 10:37:41 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Will Deacon <will@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org, catalin.marinas@arm.com,
	kernel-team@android.com, linux-kernel@vger.kernel.org,
	ryabinin.a.a@gmail.com, glider@google.com,
	kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	Andrew Pinski <pinskia@gmail.com>
Subject: Re: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
Message-ID: <ZxIeVabQQS2aISe5@elver.google.com>
References: <20241014161100.18034-1-will@kernel.org>
 <172898869113.658437.16326042568646594201.b4-ty@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <172898869113.658437.16326042568646594201.b4-ty@kernel.org>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1m71Tg7e;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Oct 15, 2024 at 01:39PM +0100, 'Will Deacon' via kasan-dev wrote:
> On Mon, 14 Oct 2024 17:11:00 +0100, Will Deacon wrote:
> > Syzbot reports a KASAN failure early during boot on arm64 when building
> > with GCC 12.2.0 and using the Software Tag-Based KASAN mode:
> > 
> >   | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
> >   | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
> >   | Write of size 4 at addr 03ff800086867e00 by task swapper/0
> >   | Pointer tag: [03], memory tag: [fe]
> > 
> > [...]
> 
> Applied to arm64 (for-next/fixes), thanks!
> 
> [1/1] kasan: Disable Software Tag-Based KASAN with GCC
>       https://git.kernel.org/arm64/c/7aed6a2c51ff

I do not think this is the right fix. Please see alternative below.
Please do double-check that the observed splat above is fixed with that.

Thanks,
-- Marco

------ >8 ------

From 23bd83dbff5a9778f34831ed292d5e52b4b0ee18 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Fri, 18 Oct 2024 10:18:24 +0200
Subject: [PATCH] kasan: Fix Software Tag-Based KASAN with GCC

Per [1], -fsanitize=kernel-hwaddress with GCC currently does not disable
instrumentation in functions with __attribute__((no_sanitize_address)).

However, __attribute__((no_sanitize("hwaddress"))) does correctly
disable instrumentation. Use it instead.

Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=117196 [1]
Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
Cc: Andrew Pinski <pinskia@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler-gcc.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index f805adaa316e..cd6f9aae311f 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -80,7 +80,11 @@
 #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
 #endif
 
+#ifdef __SANITIZE_HWADDRESS__
+#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddress")))
+#else
 #define __no_sanitize_address __attribute__((__no_sanitize_address__))
+#endif
 
 #if defined(__SANITIZE_THREAD__)
 #define __no_sanitize_thread __attribute__((__no_sanitize_thread__))
-- 
2.47.0.rc1.288.g06298d1525-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZxIeVabQQS2aISe5%40elver.google.com.
