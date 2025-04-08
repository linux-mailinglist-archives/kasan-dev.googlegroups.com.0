Return-Path: <kasan-dev+bncBCMJDXP7R4IBBLN2227QMGQEQJ4AYHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7DC2A8183E
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 00:03:27 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-af534e796basf3727206a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Apr 2025 15:03:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744149806; cv=pass;
        d=google.com; s=arc-20240605;
        b=EGJhWO7D14L4/VWN2xEEgXbraK1kSy/rcOjeqh5q99GMDQ5oKj53qZIADdtBRZupD1
         7viStjdcxiHYahsX8FaybDtKyTUmogKsFei3QSQbqtEErY7oVb4HYk/d559vmtnL5qsv
         1QgSuh/T2Wq0mKoTuMLJyvs3/X9az++FWNPgz4QAVjOcovWxaC9cI6I7lGjg1z9bkzpZ
         MdN040c9Q2BJwx7aUI7P/acQh1Td5pvsre3FYUlg6mjvVDmMBkyKJFRpTPmS9HWf4KGk
         dtota7hPdGgHnZkpcXf0VV9Ui6XjjP5eCnlxKpOYOdOADFktOumkN8xMkG2ip8HUftOD
         G4SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=SEsmtKyyrQw2kSGlgjIn3sATuBlnUMOzbvscGLQbX8M=;
        fh=UZLE6GJsPpn7PDkdp5swKRC0eR28RYrU/ljYXST734U=;
        b=lMJfxpjcdq6hxD8/jI0MqMPEyz9GWS5ZkhC3eawdPigekJy90Q6PhlRGgYF0iC7iE/
         JHY/iz3u5LzMZaOpLEVctYSWnJnaRUQgs91zWbipsLXtpWD/w/bK+8MFOmDiAN9sBVK4
         JTDC8dJxePJWPHVr1z4CFrr7KdAu4a3sbBU5hNs435DjCkw214t0fdj4lwjfsyhUNMTB
         5zHkgbHHMfbwxafWr4oMX2eS6QTU9jF1R56IKa+qiDMZY29NTRTtyjRrbV67Fcd9rYMM
         eGMnIvDqVbQBP/MQcWCER7xGCOebkXzQZ5SMcVqdlm+m86CxJTo88+wpd/KjgZC4m4eg
         EImA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D5RtukQr;
       spf=pass (google.com: domain of ojeda@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=ojeda@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744149806; x=1744754606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SEsmtKyyrQw2kSGlgjIn3sATuBlnUMOzbvscGLQbX8M=;
        b=v8Yh21QmC9TACYCw3uX93UBN0k9+kUy5QoJnv0g89cv3gZTIkjPOVYN0wqwHiaCqoy
         oPQJLvssb2aCmBu7Dp/RGNITM0rH8pd5sUbmL0/SYOIRd1QEMAQNLKltuSRKEBSnSXAx
         jSl6ZDoBza2lnQFhiKqTJP251g+aida6DotjlewwJQbzD6XSA/SC5rcKaGqaE07CXKOm
         PO/oeoBaYBFgy8UoleOMgDAVx1QcFjlh65Bao223tXwn97xA9Kwlpu3/SJACNpxASbZC
         D6e9FbhEtBUAtzIZXlt+X536fupBT9sO0+LUTM3Td1Vgoen/AD0hsDX0akNaUld9esGx
         sXHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744149806; x=1744754606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SEsmtKyyrQw2kSGlgjIn3sATuBlnUMOzbvscGLQbX8M=;
        b=pE6rmuVtgN2iAzip+IyJE9B+9CbAfdyY9pZYom2JnEkg17ZGuW/XjoPP16LhEnhFip
         ztlB23FLHyEN8PiyoctL0rJHYBKuCDNyN3F+J1tl/+xxb6sgrvnjZxAlFNZ3oc6GK+Df
         NJEAHcw5TJaNo5uJwlyLViykelM+1VXMjKSMmYeA67aMa7j4t9CtTgBRYLGpbyff+woq
         5sP/hVBJKGsiveoTCimuoKd4cC1YC9vMw24wNXBYKjSns47bi0yOAIeuZH0QicWCYEa+
         QP0hAyFC7CK6VfV9QXMQmJjeCOEyRki0wS4hebKahgwZbyv7j+bPpZfA4jFyMXO3J8wT
         6jxQ==
X-Forwarded-Encrypted: i=2; AJvYcCWol4kAih0wh4vkR8wHuxsIVsvKRqSyCrV6FGxoniuBay87dcvHOivyPTE6Cd+eGsdfK8PmJQ==@lfdr.de
X-Gm-Message-State: AOJu0YxbBKfSaHrlAsgs+I6gCKVyCkXAw+75U3mKUfwtWINvTyDKrRCS
	LuJoUHKGnLgyVsvNXbDUnvXqw7MppNluVLH0dSHz0plUp1Vnsghv
X-Google-Smtp-Source: AGHT+IEQARnBzABcy5kchM/06xJP17K3VOmu9IiKNQrpK1ZApwm1UWITmCU43s+rRQinBeZJ6Va2vw==
X-Received: by 2002:a17:90b:5344:b0:305:5f25:59a5 with SMTP id 98e67ed59e1d1-306dbc3aa75mr1155999a91.35.1744149806132;
        Tue, 08 Apr 2025 15:03:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJhOHw3iDW83VUWM8ghGvtoQqAH/y8rjrLdVfBbj2aBwg==
Received: by 2002:a17:90a:cc5:b0:301:cdb7:53ba with SMTP id
 98e67ed59e1d1-30579d61d0cls1429331a91.0.-pod-prod-09-us; Tue, 08 Apr 2025
 15:03:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMKlslNXSOxFTPa771OkBLUpD89hI1OkE3NzNJ+dPHuHxTVp6UxGrUE8MJ6KAdjS/cohQx/OMABm8=@googlegroups.com
X-Received: by 2002:a17:902:f608:b0:224:122d:d2de with SMTP id d9443c01a7336-22ac29a9eb0mr11777925ad.16.1744149804753;
        Tue, 08 Apr 2025 15:03:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744149804; cv=none;
        d=google.com; s=arc-20240605;
        b=VKFI99tqaLlzEXKIgz1V6RUGbmnjFW13qG35juXiBtfLTN5/rstzGeglQLhITPmH3A
         Yw1ccJpTwUZ3++hTJUo3hnPXxwN8i5Izc2C7eX3v1mhD5J7B6K/X7fIAWE10VTl80d24
         7IpUq+ujbo4btJmGstgJZ0wNPUVoyEuRjHP15eTHtol/R1a9TCwurYxVoZebuRYkARQy
         U1NohVG3fu30HwGvZNUrAie7jZBXL+mlEH49ftBJP6t7+PwGTjSQcVp0O3YrTKgQGT8i
         p1ZxRxZdowYYoiGV2JZGLjkGes85OWRAqeaxgYNqYcZOwjaM7+/9IQ8dVjm+kkBCLusi
         JOOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=x95AczqtRotZady2hLrZYgGr07782D3ceNKobrb3w/c=;
        fh=BXd1oedHh7aYmHA9/FarDeUT2GEqnRkEZ4HnrhDOoX8=;
        b=MjKIu7OIRsRO5YKTLcE8mky5DRU/IvNe9PLUjoow4nLRwE6mcu8TZdaGLWU0S0CErW
         6sVZ/E7+z9lUgabYeykw1Mpg0qltiDitLQ24qZe2v3GV8M8BiYzzj6cP0meCKKLwri7E
         h5bYFoUv3F8+/S4+FWpZJ81g9AEy0X7y6b7LFVgknTZJnxCJN5vGD6KSuOou9Vrjh4JI
         3WIsxhmGP+kbPivHJviScI1cVsmff6JpGvEILwcX0x3ZwytPESOlKWAQ9OfMYF13lyAP
         d5h69wRIVik1X/k7dznjRTr+8hq/f9Hm180BCqllOPXXXKW4FcPPaCF7DYpkBwHB2Hdr
         +/BQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D5RtukQr;
       spf=pass (google.com: domain of ojeda@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=ojeda@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22978662385si5828285ad.10.2025.04.08.15.03.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Apr 2025 15:03:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ojeda@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 30488A49560;
	Tue,  8 Apr 2025 21:57:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4C24C4CEE7;
	Tue,  8 Apr 2025 22:03:17 +0000 (UTC)
From: "'Miguel Ojeda' via kasan-dev" <kasan-dev@googlegroups.com>
To: Miguel Ojeda <ojeda@kernel.org>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>
Cc: Boqun Feng <boqun.feng@gmail.com>,
	Gary Guo <gary@garyguo.net>,
	=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?= <bjorn3_gh@protonmail.com>,
	Benno Lossin <benno.lossin@proton.me>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	rust-for-linux@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Matthew Maurer <mmaurer@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	stable@vger.kernel.org
Subject: [PATCH] rust: kasan/kbuild: fix missing flags on first build
Date: Wed,  9 Apr 2025 00:03:11 +0200
Message-ID: <20250408220311.1033475-1-ojeda@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ojeda@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=D5RtukQr;       spf=pass
 (google.com: domain of ojeda@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=ojeda@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Miguel Ojeda <ojeda@kernel.org>
Reply-To: Miguel Ojeda <ojeda@kernel.org>
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

If KASAN is enabled, and one runs in a clean repository e.g.:

    make LLVM=1 prepare
    make LLVM=1 prepare

Then the Rust code gets rebuilt, which should not happen.

The reason is some of the LLVM KASAN `rustc` flags are added in the
second run:

    -Cllvm-args=-asan-instrumentation-with-call-threshold=10000
    -Cllvm-args=-asan-stack=0
    -Cllvm-args=-asan-globals=1
    -Cllvm-args=-asan-kernel-mem-intrinsic-prefix=1

Further runs do not rebuild Rust because the flags do not change anymore.

Rebuilding like that in the second run is bad, even if this just happens
with KASAN enabled, but missing flags in the first one is even worse.

The root issue is that we pass, for some architectures and for the moment,
a generated `target.json` file. That file is not ready by the time `rustc`
gets called for the flag test, and thus the flag test fails just because
the file is not available, e.g.:

    $ ... --target=./scripts/target.json ... -Cllvm-args=...
    error: target file "./scripts/target.json" does not exist

There are a few approaches we could take here to solve this. For instance,
we could ensure that every time that the config is rebuilt, we regenerate
the file and recompute the flags. Or we could use the LLVM version to
check for these flags, instead of testing the flag (which may have other
advantages, such as allowing us to detect renames on the LLVM side).

However, it may be easier than that: `rustc` is aware of the `-Cllvm-args`
regardless of the `--target` (e.g. I checked that the list printed
is the same, plus that I can check for these flags even if I pass
a completely unrelated target), and thus we can just eliminate the
dependency completely.

Thus filter out the target.

This does mean that `rustc-option` cannot be used to test a flag that
requires the right target, but we don't have other users yet, it is a
minimal change and we want to get rid of custom targets in the future.

We could only filter in the case `target.json` is used, to make it work
in more cases, but then it would be harder to notice that it may not
work in a couple architectures.

Cc: Matthew Maurer <mmaurer@google.com>
Cc: Sami Tolvanen <samitolvanen@google.com>
Cc: stable@vger.kernel.org
Fixes: e3117404b411 ("kbuild: rust: Enable KASAN support")
Signed-off-by: Miguel Ojeda <ojeda@kernel.org>
---
By the way, I noticed that we are not getting `asan-instrument-allocas` enabled
in neither C nor Rust -- upstream LLVM renamed it in commit 8176ee9b5dda ("[asan]
Rename asan-instrument-allocas -> asan-instrument-dynamic-allocas")). But it
happened a very long time ago (9 years ago), and the addition in the kernel
is fairly old too, in 342061ee4ef3 ("kasan: support alloca() poisoning").
I assume it should either be renamed or removed? Happy to send a patch if so.

 scripts/Makefile.compiler | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/scripts/Makefile.compiler b/scripts/Makefile.compiler
index 8956587b8547..7ed7f92a7daa 100644
--- a/scripts/Makefile.compiler
+++ b/scripts/Makefile.compiler
@@ -80,7 +80,7 @@ ld-option = $(call try-run, $(LD) $(KBUILD_LDFLAGS) $(1) -v,$(1),$(2),$(3))
 # TODO: remove RUSTC_BOOTSTRAP=1 when we raise the minimum GNU Make version to 4.4
 __rustc-option = $(call try-run,\
 	echo '#![allow(missing_docs)]#![feature(no_core)]#![no_core]' | RUSTC_BOOTSTRAP=1\
-	$(1) --sysroot=/dev/null $(filter-out --sysroot=/dev/null,$(2)) $(3)\
+	$(1) --sysroot=/dev/null $(filter-out --sysroot=/dev/null --target=%,$(2)) $(3)\
 	--crate-type=rlib --out-dir=$(TMPOUT) --emit=obj=- - >/dev/null,$(3),$(4))

 # rustc-option

base-commit: 0af2f6be1b4281385b618cb86ad946eded089ac8
--
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250408220311.1033475-1-ojeda%40kernel.org.
