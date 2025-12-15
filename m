Return-Path: <kasan-dev+bncBDA5JVXUX4ERBHV677EQMGQEEM6ZRLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 53D78CBD532
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 11:12:48 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-647a3af31fbsf3948225a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 02:12:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765793568; cv=pass;
        d=google.com; s=arc-20240605;
        b=lAshuHNwpEnm3QTSAdqMSpPYfyUxfaNnsmEw47oXT/mJmjBe3B4F2V+KSPtwtVH6Ux
         r1WgcDavrecWYdgjASVv/iC7I/dyXpjo6NnQfmMyH/tRryZB8DuQSaS4GtpIriaIOHHl
         iUHiloeDUsfJk1/d7GRi0AhzVJ9zJjRtB/JeunnkH9VCBM9lT7Tv0oIYmg00OLX+fnrh
         KkfUaDN3DOFNI3GPJUMqekndns6cHujqiUhXcn1ZWF2Li3UhvcvQXo477kzKeJj27914
         1X4CQJdwGMlpeg0p7CoDu9vmdF4cfmEqmh4qd+ZC4MX+pZXZuXGm+CwBXgkwExb+byxy
         yw6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LneiFHIld1DMfGr15FdHqcug72dmiqlLkJAeaijiLGY=;
        fh=8tloswnEWH0guLioPbRimTz5AhVZjP3iv8/Zu7BS4aI=;
        b=ZI3/4kflKHHpWhsutCPLAYDJSYs7Slm933Vt1nV24Q7VMkczGP3hws+51x66byakrd
         VPeQd8U0hNEdrqLgh02NFVX7TZuvnw9ScdwdODzcVBgzlrYfGy4GRPMa1kEdyAsgFsPP
         OIqibfe5JTmj4sb2uE+YNCTayCj9H9NqNVHKlmsQaXJ6RJjOqoBmL5J2k1ZH3zp5UTJS
         8ApAmXDB1hcZyT3pHo9CbSAWKxS3V3AVizqaLYrEDZlAHGk4WHOTfGa0C5CuSokj91zv
         fZ6IWtgneOP4xgSU/hQk+R4bZHfx6EPBAJ0uTSu+2DVg+Cz6Nkn6zXYT6wyCFqghGGmB
         WNYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Gjg+oBas;
       spf=pass (google.com: domain of 3hn8_aqgkcssqhjrthuinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HN8_aQgKCSsQHJRTHUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765793568; x=1766398368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LneiFHIld1DMfGr15FdHqcug72dmiqlLkJAeaijiLGY=;
        b=emGTd0TUENwjxVYP83FRUjEJwzNwHGsLyAVmXl79f79R5V+PpePxM8WWhthBItfwkU
         kHaX7vTh7VmNbfe/5RdE0RWEGl2tWDLoAQnSSBst7SaO0d6iPUHeNT4D4B5hwH9RxY21
         BzJm1uX7MfkodX7wT0yH67A3u6lppTblnLQ8SPY4KtyRyQSHmtJXKACGLEGOBx5w92Ig
         +BNN6gjKS7nx5/TSRnWiJAoXsimq8P4vgFXJ5NhhhnXSqP+33tRAqE2zSdNO1DtGh501
         QoWj7cBJjWvU1s7hWrViYY8WR4nxO8MxAFab7xPak5uF3oMt2qGYLERcIkuRqJqd9UkS
         dvvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765793568; x=1766398368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LneiFHIld1DMfGr15FdHqcug72dmiqlLkJAeaijiLGY=;
        b=Z5daAJpentkr3HPyOc/xpM+Aj0ciyYHDiwe8cjQQ61AWEgH+1RtcclasRf6ZmUfDwL
         c6RzpZEbhFz8sQcqySC9Aq23wTzdIbL0D0/68F/sA2cklbdpamMkRgpoxPUfXSd82mZQ
         w4kDqaiUqO8EXw3/sywB/zGK6J5wVgsggiMqZ7qZHdxeFDkxu5f+m9PNwjTMiUAEB6am
         6VsGTkzCyELd6tyavPJGWnPu7D19TdPassKPRkH6Lpg/+CQ3k58n76gqFCdDmGMZDyrr
         JZYloh+DRksjPw4tV0RQX1y207BCf0cqm4VQaIbeIKQC7KbyPMRcPkMPOU8Jdyqmwnuy
         qBrQ==
X-Forwarded-Encrypted: i=2; AJvYcCV+bDqswIKDg7dKrv3kU0Dbr1bIO8IgJriFoTPXKUslgkid2j0NgaNicGDHzKLbBlNVpZDAWQ==@lfdr.de
X-Gm-Message-State: AOJu0YzooNH877hfOM5OPR0+GFbQYbBIuIEiKEdTSEqBbvMcdIKtnvf3
	4M3FlpLBPTM7eBVq39UXDU4n4pGu8YD14nGdFbIArVwKxUq1Jx1amM/O
X-Google-Smtp-Source: AGHT+IFg1aUgcjqbiwjLUJr4QyyUXxdWW4mM7wCRpIDD0FpcwJVgLIm5XfQ626HKG+omzhYgYfYPrQ==
X-Received: by 2002:a05:6402:50c8:b0:649:cec1:6cf1 with SMTP id 4fb4d7f45d1cf-649cec16dedmr3581176a12.0.1765793567400;
        Mon, 15 Dec 2025 02:12:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaUITUWby+iI53GQWpUtNsQgKAE66E4IVWQqx9M/HoDKw=="
Received: by 2002:aa7:df8c:0:b0:640:ad82:2e60 with SMTP id 4fb4d7f45d1cf-6499a44fa2bls2420578a12.1.-pod-prod-05-eu;
 Mon, 15 Dec 2025 02:12:45 -0800 (PST)
X-Received: by 2002:a05:6402:3493:b0:649:815e:3f9b with SMTP id 4fb4d7f45d1cf-6499b15f4abmr10202985a12.3.1765793564875;
        Mon, 15 Dec 2025 02:12:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765793564; cv=none;
        d=google.com; s=arc-20240605;
        b=i0WIy1PKunr+b/pTVQDpxwpLJEBB/7OdDf2660rFFXjY93SUeA6hALJbSY8+IUxBss
         Hao6gb24U0a9PRJV/+MEGu8Vy70uben77yaQMQ77HA1X52rqoqArx9iZRpLUafdg+ND8
         rr1JM5mRztiL0DlilNiipglmy6I61tEWmPdlsRlZ1CqE7y27KPsHg4AMRuIT/0cU/40c
         4nJs4WhQJ0WnjZEHGYm2xdLvp4S3kQ0fzF5MO1vRtSBBjZkBGf0j62HL+xZ0CtGe2Loj
         LjetQjfZkJc/+pxc35b3De4Unuzjdbc/JfTmV/ODIQswyZluyFhJEo7xft1ki944wk9M
         5Gbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uP2brnCrErMSve8D4fzLeDUYWZS9bjiXvF2HnuazcK4=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=Bo32Ez1rpgU3sjm/w21mWr57cB1SoscroEYhMEq+nKqknH4TWE6Lwl3/KResbnr2KI
         d04oVCBn7fFXzGG/TKVPqiMnTE390O0AW9O4RLrl+D7imT8bHEUOQ9ueWIU3mTB1BAJD
         3nQbnWQWQ4cEKQgAUIZqdlBcGlWJ1mgjKl2QoKogyC9LS/E4TMkFPL+bsk3QCdqkUK2M
         KBGSHcuUzMhnGMSkyEEUeDKV8oQKUBZViV0sHAPnrRKhOz18TpcWWUuNKwOhbr+qYsui
         aI/gfmzbtZssVDCqfN1Jv2pbMI2GAFggsUy2lhAy4u3k64qhY/gWE3TD8SUl0fTlwEEV
         H7vA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Gjg+oBas;
       spf=pass (google.com: domain of 3hn8_aqgkcssqhjrthuinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HN8_aQgKCSsQHJRTHUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-649820bbed2si203845a12.4.2025.12.15.02.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 02:12:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hn8_aqgkcssqhjrthuinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4779da35d27so28649335e9.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 02:12:44 -0800 (PST)
X-Received: from wmgg8.prod.google.com ([2002:a05:600d:8:b0:477:93dd:bbb1])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:35c1:b0:477:7a53:f493 with SMTP id 5b1f17b1804b1-47a9ddef66emr29398925e9.23.1765793564542;
 Mon, 15 Dec 2025 02:12:44 -0800 (PST)
Date: Mon, 15 Dec 2025 10:12:39 +0000
In-Reply-To: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
Mime-Version: 1.0
References: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251215-gcov-inline-noinstr-v2-1-6f100b94fa99@google.com>
Subject: [PATCH v2 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Gjg+oBas;       spf=pass
 (google.com: domain of 3hn8_aqgkcssqhjrthuinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HN8_aQgKCSsQHJRTHUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

The x86 instrumented bitops in
include/asm-generic/bitops/instrumented-non-atomic.h are
KASAN-instrumented via explicit calls to instrument_* functions from
include/linux/instrumented.h.

This bitops are used from noinstr code in __sev_es_nmi_complete(). This
code avoids noinstr violations by disabling __SANITIZE_ADDRESS__ etc for
the compilation unit.

However, when GCOV is enabled, there can still be violations caused by
the stub versions of these functions, since coverage instrumentation is
injected that causes them to be out-of-lined.

Fix this by just applying __always_inline.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 include/linux/kasan-checks.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index 3d6d22a25bdc391c0015a6daf2249d6bea752dcb..9aa0f1cc90133ca334afa478b5f762aef9e5d79c 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -37,11 +37,11 @@ static inline bool __kasan_check_write(const volatile void *p, unsigned int size
 #define kasan_check_read __kasan_check_read
 #define kasan_check_write __kasan_check_write
 #else
-static inline bool kasan_check_read(const volatile void *p, unsigned int size)
+static __always_inline bool kasan_check_read(const volatile void *p, unsigned int size)
 {
 	return true;
 }
-static inline bool kasan_check_write(const volatile void *p, unsigned int size)
+static __always_inline bool kasan_check_write(const volatile void *p, unsigned int size)
 {
 	return true;
 }

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215-gcov-inline-noinstr-v2-1-6f100b94fa99%40google.com.
