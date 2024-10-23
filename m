Return-Path: <kasan-dev+bncBC5JXFXXVEGRB64R4S4AMGQEEOICLLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id C54C49ACC76
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 16:32:28 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e292d801e59sf10860290276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 07:32:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729693947; cv=pass;
        d=google.com; s=arc-20240605;
        b=PqfJEVi4/y+nXAYuj5pHXV8F7YHUjVf2vM3vK0XWNOU0fbdVVQPY/Gbiap7gEBZDMY
         xzrxvw9nyePOcoQFVox8JKgek4Nu3IKUZskBcPAqCaGIaY1CGAwFfUp0Y5YeeWksvPdk
         C8PJ6GrU5qUcjL+4IpjsodlS1zAQT3fo5WJEGYSealkBTzNjfVnHSUi51dAVqqSCb441
         jPr+K5xVjtTPTXiUHY2EvjG4GFbYYEvDc8LNF4KMg1sWDVaqX/dkF/ODti4tkBOVzna5
         hxrI+EMTlk8ZSkMVWSj8fXHEI8puE+YURMZjnqE0gdoJu2pN3Tn+uIkxk3J62V9FEchv
         WBCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=80TVCLycE3+aVBEcmXOnr3ZNar7tmIvTPGnC4JRcKKw=;
        fh=6QBdp3dHCUjRnLLygPsWSo2/hetEzwNmN0ADD8S7jWQ=;
        b=YF+m2z04dUnFmWXM5YUHy0XFJQA9vxNZEwgbapepXlYUtIEUtRS21y0pIU3ONEORAz
         D2qn3p4w3KmFzIFaJdjA4WI8s6VhEruGoN6NYKF8S9ijBULv6qnq75jDXT5wLHvUxpFJ
         Oym0t232TCzK7B5Dr5i0H6PMuReQ5wBOPM9DGh3dIMIfK4omMu8h0QwZZ0TZxR1QJlT0
         FHPzZoykEhYnxHKi0RwTXQNneMuqycbjD8chpldwlEIgxcoWxPjg02UkSeCm+h5nketc
         MfFFmRuMFID0xD5Ep5JYDmoU+z9Lz++UF89Kub7ygcSpIuZkwp1O3Doflk+67ndagzon
         CevA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZcVPBl07;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729693947; x=1730298747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=80TVCLycE3+aVBEcmXOnr3ZNar7tmIvTPGnC4JRcKKw=;
        b=Shx+fnTL8zCD6wFaHfM8gWYbM9OhUmAzxkT5goC1hU4CQP2FOvs0mCqvO4Nzt+k2Pt
         9lrmfnetEx76fwIF80vUFgBFfal7rtpgC0JUb4IN+AjXH4esmScmegWOiXiF0uvDDYHk
         KS8KVYPXHg8jufrK9J3rAOhMT3DjQqT+RI2+S3zfPujU4VzP6R+BS5yaXNaL57b/rfl+
         Ml6QlL4BO39vzfuG3BMCYHRtY5wYBGh7kKGbtU1uw+pKSjl9Ijszzr62MjtPy1m3LjC3
         483Co/olzHC8BYeaqhwnRQdcylBPwvw0d6mr9454DECR4NZrZVgh1gnPeg8j73JhP/T+
         HzwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729693947; x=1730298747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=80TVCLycE3+aVBEcmXOnr3ZNar7tmIvTPGnC4JRcKKw=;
        b=DdQ4WKV0owwLNrn/w5QpVBPtKD/5IFsoLQ2UbQftZW8e6P00nRAtN05vLeEfUHgq6g
         Cn2OoV92+K6rD9VTy0nZSKe9SDq77smtA1LdcN94ucVbouwwYqZpzT3BaMk87DkaD4bj
         8THS/ub0v3G1Ki86yhdAbbgnd/fu81tgF+jUjnuhhkt3keeH2ymz/hHIiKQvAm03KrKK
         hz/wLwEVEod1315OckD+Vui9x0zXw5AUsmFo5wXoJlTFJwTGQgW9ferGZgd0Y52UShn1
         NVbtFLs0PHtBj/QrplXdRJuNeZ2Jiqii8ctDsiQcP+2kipqRrxv9Qf8h0V9qFN357aIS
         hYDA==
X-Forwarded-Encrypted: i=2; AJvYcCV4z2sXAQElkgEcjA1aZABcEq5r/jebqSRtMgNYbUeGmeuNurfwP41/hwGGf9BDVcphldtsRw==@lfdr.de
X-Gm-Message-State: AOJu0YzEblARYKla2AW9XQ56SJpc9EUmhQheRlh9fZnEbzHkveK3d7ai
	lm4qJhYJCw7RKz18F/nqYE6/R559LIUSqhIruM20irYetW7rF+/9
X-Google-Smtp-Source: AGHT+IGJI/YTv54Tkptfc0LJE4YEQmJ5Qqyt2b9Dae2hwBkXHkDidYCvWkRqqTUuxfBsLPbjozI8Kg==
X-Received: by 2002:a05:6902:2b12:b0:e2b:bd2e:8a76 with SMTP id 3f1490d57ef6-e2e3a6d4bcdmr2647798276.53.1729693947374;
        Wed, 23 Oct 2024 07:32:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:727:b0:e28:fe4d:3f5c with SMTP id
 3f1490d57ef6-e2b9cc5bf40ls2448300276.0.-pod-prod-01-us; Wed, 23 Oct 2024
 07:32:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMeeOrZhNbol+NpCw/+F7TU+Mn2/nuSqSYkHg+quhtq32YxlRds2OU9SEeNIZKD5BaJ1uqQ/bAXwE=@googlegroups.com
X-Received: by 2002:a05:690c:3685:b0:6db:b8ff:9128 with SMTP id 00721157ae682-6e7f1013818mr25724697b3.46.1729693946444;
        Wed, 23 Oct 2024 07:32:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729693946; cv=none;
        d=google.com; s=arc-20240605;
        b=Ddq6gBdiDKH1vliL6t65kiOWsOZswPuOKf0IbM/KiopWO9/tfajpC9F01I56r1Aq/U
         ERqaitYMxXBYafe0mgnrGaQ7bQP9BJ+/Ttqln/AVqZv4bps7cScaXxGeJLv+0DqKYZZu
         yJVFsIMFQaXOeLhizv0P/kNHCR7THZfFARaUvgFpm2tlvhQMbeZQl0DgDE8GpTo6Q4Yf
         2sM0SAe4wACEh7U56/Ny3xvsgasdxP0Z9LbUkJ5hkHbRjCdPqAJ3biPIeh5JaB3vIGFp
         htW1Xyu3SfqMs3s3WAW6fHx7nagra5DBG2kMTVZB0uLR9P6AJ72DTDaiCaK2/b+ZgWrN
         xnqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=grl0BmPmwiM3bvikTmkDlRNPN0q+6Kef1XdQB6Iqwng=;
        fh=2zoRfZ3GqwaOB86OT+ogluMCAewlKKw5Tb+NnXhkKI8=;
        b=Oa/qTmxOXAsZgk8T0USbKMTPk4gwYpKHiBH3cW44lYkCP5FWWlck6SxWoQZ1xSVy8Q
         q0JhEeb+ve/1bx/M0f8Wz3i1kuLbKy/hFJeH12ybobE3vPfPtwruPdnbl4Ruj8PQyLav
         t1cR7pm/+xWvPMlq61AzFfnDdnDCw6F1IKIAfxZeQw5FiBAjtuQWmHnEVp2VVJAq+yqd
         ZQrUj3vbPtSWyjGJNdPsPiuRwP7pVGinj32scjlTs4lkMgrIGnZ0tEND3CKE+AaQocmE
         a9W3SWvxR/dUGQcLyP5KWvOlixhC2FIBJSqcI+ORhJVomCdzQcYgpgk8IYAzl9hHAGCT
         Rrkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZcVPBl07;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6e5f5d2211fsi5762877b3.3.2024.10.23.07.32.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 07:32:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id CC950A44F5F;
	Wed, 23 Oct 2024 14:32:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7FB62C4CEE4;
	Wed, 23 Oct 2024 14:32:24 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	Sasha Levin <sashal@kernel.org>,
	ryabinin.a.a@gmail.com,
	nathan@kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH AUTOSEL 6.1 14/17] kasan: Disable Software Tag-Based KASAN with GCC
Date: Wed, 23 Oct 2024 10:31:53 -0400
Message-ID: <20241023143202.2981992-14-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20241023143202.2981992-1-sashal@kernel.org>
References: <20241023143202.2981992-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.1.114
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZcVPBl07;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Sasha Levin <sashal@kernel.org>
Reply-To: Sasha Levin <sashal@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

From: Will Deacon <will@kernel.org>

[ Upstream commit 7aed6a2c51ffc97a126e0ea0c270fab7af97ae18 ]

Syzbot reports a KASAN failure early during boot on arm64 when building
with GCC 12.2.0 and using the Software Tag-Based KASAN mode:

  | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
  | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
  | Write of size 4 at addr 03ff800086867e00 by task swapper/0
  | Pointer tag: [03], memory tag: [fe]

Initial triage indicates that the report is a false positive and a
thorough investigation of the crash by Mark Rutland revealed the root
cause to be a bug in GCC:

  > When GCC is passed `-fsanitize=hwaddress` or
  > `-fsanitize=kernel-hwaddress` it ignores
  > `__attribute__((no_sanitize_address))`, and instruments functions
  > we require are not instrumented.
  >
  > [...]
  >
  > All versions [of GCC] I tried were broken, from 11.3.0 to 14.2.0
  > inclusive.
  >
  > I think we have to disable KASAN_SW_TAGS with GCC until this is
  > fixed

Disable Software Tag-Based KASAN when building with GCC by making
CC_HAS_KASAN_SW_TAGS depend on !CC_IS_GCC.

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Link: https://lore.kernel.org/r/20241014161100.18034-1-will@kernel.org
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/Kconfig.kasan | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index ca09b1cf8ee9d..34420eb1cbfe1 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -22,8 +22,11 @@ config ARCH_DISABLE_KASAN_INLINE
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
+# GCC appears to ignore no_sanitize_address when -fsanitize=kernel-hwaddress
+# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=218854 (and
+# the linked LKML thread) for more details.
 config CC_HAS_KASAN_SW_TAGS
-	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
+	def_bool !CC_IS_GCC && $(cc-option, -fsanitize=kernel-hwaddress)
 
 # This option is only required for software KASAN modes.
 # Old GCC versions do not have proper support for no_sanitize_address.
@@ -91,7 +94,7 @@ config KASAN_SW_TAGS
 	help
 	  Enables Software Tag-Based KASAN.
 
-	  Requires GCC 11+ or Clang.
+	  Requires Clang.
 
 	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241023143202.2981992-14-sashal%40kernel.org.
