Return-Path: <kasan-dev+bncBDI7FD5TRANRBO7GSO3AMGQECOU7L6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id ECC5E958EC3
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:49:17 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2d404e24c18sf3865543a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:49:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183356; cv=pass;
        d=google.com; s=arc-20240605;
        b=DQdlWp8lTfOnwmmkwiHKvx7w5nqz5Qsg8wmv79BzTkGf4OoD1TEWg0rfQ263qZ1/7n
         +SiSURAvft9IBEo+Sbe0qPg8Ny8nXPrO7GZZeiw6rbEhEdTtP6/mxfbiSAtFm4SSlnE/
         HikrdoCRTpis6AN252Pwqxk3Pi5byYAT0bgA8WUGXYruqyhudlqU9FLCP7x9xBtVshQJ
         sES7iqXgTv5AZNj9qKU8hHpD14VXpe5b5s0rFNooqGaLqaqwuZ7TI/ftYzPjrrGW65MS
         aOdAS2A0jTY+mZwqsmZ+wzPUzwuojaeI02V9g1MU+Lo2RdMHJTuMR/0jd5dTnr4VR9PO
         sExg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=oJas9kdbiVNP3Qod4LA1ux0W4J9XIhr0202Xyu1QNZY=;
        fh=0sr9dVE6RTYjcH2O4uboB+cj/jenMCbATg77jxnL+Eg=;
        b=d+70FYAWYokkazqSS1G8ogLpEYX8crDtBGP2yE93o4cbMDbe9TBSSQvJLJ1HKDGFEU
         IrZkLtjtU/ux10qdQgpehGt+0HxVNmdaEgSvk9ek+n59XeotkkU4YIJ0IMAOiJABoA61
         sdMaIsZLmCU6c9jCWTYjUCjZqiCgkPnUQHbyC3/ZjJlbjwYFITGLr9KuGdxMC2zkLiqN
         WNx39Orr4+idXwz5/sS1asQ3JThNyeL0Ef4401h3rwrAFmQRk/6YEtm1bpsMz4WddQOb
         uiyGV55ZQ9JvDiGP6Ljkvxot3CDMUmi5K+7PddNg/bKbv7/p+bxs9FErLaAfrSl0mKxK
         W1IA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4UbB4JR7;
       spf=pass (google.com: domain of 3ovpezgckcxebbpjgtgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3OvPEZgcKCXEbbPjgTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183356; x=1724788156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oJas9kdbiVNP3Qod4LA1ux0W4J9XIhr0202Xyu1QNZY=;
        b=ZZNiZvmowvsNzmtypZFjuWwVcKOGhs+W4q7/FAlFtDrYNQ17bdGhlak4Yd/7drKL9G
         G91w9Nf3Zat8J4U81bvSW3rtBvQq+q3ZuEfPY7OP+rkMXMY1Zt82ZME8qX5Hdius8mhK
         lJqelfZM4Avu+LfyXg52kUB7DVPb9vByW0M6sIOIfmF1kPKTRWczIQ1e1b9SiCoaHplW
         RmYyuzeszmim94QLPR7rm6RFhvb1yj+oL7ddUMeI0Jt0ZEK47SluSMaXULg/r97DGDYi
         h+1iCzrg2Q+kvhpCaEgdNiznFnSClZIcaV0+fiNF3GrvtycMVUnHg7k2lHPBXnNFnwG0
         y/Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183356; x=1724788156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oJas9kdbiVNP3Qod4LA1ux0W4J9XIhr0202Xyu1QNZY=;
        b=DzV6DOtDqIEOGXLVMjuDyYAwDPJoU2cHogBl5OT34DRbCL8wKX9TNacUg6MlRxLfwf
         cKMi5/J9H8Y32BYhMkuP3dRw8vh5UIRal2sAJq9K9q+M1cmxGeEiZGwE39/6i21BfauI
         foa3KodenuC3YP3KeiOBlrk0UFfY11ALJ7N2DeJjXePqz/wsLv18V6GKCrtncwDt87Rf
         8lu/7DieybdvMUxLk+8ZUJltfLrvXIjeR0Up7D9IxN4IAgVuWSP7mCb79DwTnIuPJ10F
         qBD/F0cIyOXPQyty8IOJGo2mJs8lSlgNz3ULYZWYZiZBERS+VQJKe2mm0bUCPS4Cxn/l
         hBrw==
X-Forwarded-Encrypted: i=2; AJvYcCWVsYYt/K9YvbsS/OHZyqyhOS3ulEgTJgAAdkuid0mxlWMKecEeH6RZoOTH1ip+HAGIbX4iyg==@lfdr.de
X-Gm-Message-State: AOJu0YyTuiiEzeHiZd81h/5vpLsXU24WMDoGp4k36zLGyz2GSAdoyQTo
	aAWzjGKQuLRaOQ+8hNg4JxSlSI2h9HrrQmxmCJEmV0KSzMjBpmYI
X-Google-Smtp-Source: AGHT+IEkD4gaw4KSUTrCayCpdH33H8ugHD8gZ3i7gd6kiOYmbx9imzeIf9cOQ7vh5keONFj9WvEPaw==
X-Received: by 2002:a17:90a:5e06:b0:2bf:8824:c043 with SMTP id 98e67ed59e1d1-2d5e9a4b444mr18798a91.18.1724183356130;
        Tue, 20 Aug 2024 12:49:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e391:b0:2c3:dc3:f285 with SMTP id
 98e67ed59e1d1-2d3c2a5aff0ls3714324a91.0.-pod-prod-01-us; Tue, 20 Aug 2024
 12:49:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWglgdZzWW/SXmwjMdXBD963YJOI7DqGi49kVWE8ks6YBI99RW5+mnW7hs7VX03s3dV1pG8t+TGG9w=@googlegroups.com
X-Received: by 2002:a05:6a21:918a:b0:1c0:f315:ec7e with SMTP id adf61e73a8af0-1cad7fb1d4bmr476697637.28.1724183355003;
        Tue, 20 Aug 2024 12:49:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183354; cv=none;
        d=google.com; s=arc-20160816;
        b=nFs0C6ZQfAmmQjYNd5a8ahk7Kf6hCsozZiilYY2lcU7osvCH8+vCfbHumofi31WUfc
         2jnz56CpP9tWYD+QU/QtaUQDfuyS2XlRKe/4WwsyH+xPYfIj9gPQRLYqea7z7RVdxESt
         G87IFlyViVkyn2fARxJl1BOH/JoMkI/Kp5KcAr1mNSiS7kfBYgKrmdGrqPaZ52qknl11
         hEtafzXwm6K5mur7Ys5JSaqs9pG+CNL7/EtFsBlklv7z2gjxy9GabUPTcRubH0ZLrRYW
         Kuq/5hTRk/4GTBT5zAmm2NaTYegFRhvuv4YJC5Ala45I2AQ1ETNxb0ypbuHjWg91gpcf
         gS0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=EZ/BWqyZRlCP7UBokATY0JI3r3d12PwUba1tdxpBJwY=;
        fh=2EJnzl4E+ubopPXYKc9edDiANGLukUHpajaJ9FyWc1o=;
        b=UBGlTo0UkSBtbZCHzkFDbVyPTT3IQOxZ9Cs+DARDIroVIZPNa1ewJBzdxRYMkZV3lR
         Ry9E8riXvCM8pOhcvS7fMD9gVdLh0R21bYDoDpZA+GuHuVSdmqJX18pnojKCYlsP9/YO
         zgupRcwkSMwcEtJXd7c0s0E+TqGoEYsvbM9tJPK1CfqmXtI93I/4IbYIwuzEbdmyZVu3
         0x1REqk/gKCePcM4qQU+sX+z41f7QWczDPZvUN/55wLvMsxKhm/k4YXJ55RfVjdhzBgD
         a5DQ5LvJQiRQjmtRYwMqky6f1lYj+fTjFPE18DrqROBQnUIWbSM121ts4OIA5qYytM2t
         SjUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4UbB4JR7;
       spf=pass (google.com: domain of 3ovpezgckcxebbpjgtgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3OvPEZgcKCXEbbPjgTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7cd71b02c10si95142a12.5.2024.08.20.12.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:49:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ovpezgckcxebbpjgtgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6b73fb4ff56so54888397b3.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:49:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUBKoQgQ8tKQkYnBJ8a80Cs1JuHasVTrYa4CUJwxeA46kO5R0cWIppAJhLkznZ27znet5tvSMBskw=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:690c:600e:b0:6b2:6cd4:7f9a with SMTP
 id 00721157ae682-6c0a09f33ffmr115947b3.8.1724183354122; Tue, 20 Aug 2024
 12:49:14 -0700 (PDT)
Date: Tue, 20 Aug 2024 19:48:55 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240820194910.187826-1-mmaurer@google.com>
Subject: [PATCH v4 0/4] Rust KASAN Support
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>
Cc: dvyukov@google.com, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Matthew Maurer <mmaurer@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4UbB4JR7;       spf=pass
 (google.com: domain of 3ovpezgckcxebbpjgtgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3OvPEZgcKCXEbbPjgTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

Right now, if we turn on KASAN, Rust code will cause violations because
it's not enabled properly.

This series:
1. Adds flag probe macros for Rust - now that we're setting a minimum rustc
   version instead of an exact one, these could be useful in general. We need
   them in this patch because we don't set a restriction on which LLVM rustc
   is using, which is what KASAN actually cares about.
2. Makes `rustc` enable the relevant KASAN sanitizer flags when C does.
3. Adds a smoke test to the `kasan_test` KUnit suite to check basic
   integration.

This patch series requires the target.json array support patch [1] as
the x86_64 target.json file currently produced does not mark itself as KASAN
capable, and is rebased on top of the KASAN Makefile rewrite [2].

Differences from v3 [3]:
* Probing macro comments made more accurate
* Probing macros now set --out-dir to avoid potential read-only fs
  issues
* Reordered KHWASAN explicit disablement patch to come before KASAN
  enablement
* Comment/ordering cleanup in KASAN makefile
* Ensured KASAN tests work with and without CONFIG_RUST enabled

[1] https://lore.kernel.org/lkml/20240730-target-json-arrays-v1-1-2b376fd0ecf4@google.com/
[2] https://lore.kernel.org/all/20240813224027.84503-1-andrey.konovalov@linux.dev
[3] https://lore.kernel.org/all/20240819213534.4080408-1-mmaurer@google.com/

Matthew Maurer (4):
  kbuild: rust: Define probing macros for rustc
  rust: kasan: Rust does not support KHWASAN
  kbuild: rust: Enable KASAN support
  kasan: rust: Add KASAN smoke test via UAF

 init/Kconfig                              |  1 +
 mm/kasan/Makefile                         |  7 ++-
 mm/kasan/kasan.h                          |  6 +++
 mm/kasan/{kasan_test.c => kasan_test_c.c} | 12 +++++
 mm/kasan/kasan_test_rust.rs               | 19 ++++++++
 scripts/Kconfig.include                   |  8 ++++
 scripts/Makefile.compiler                 | 15 ++++++
 scripts/Makefile.kasan                    | 57 ++++++++++++++++-------
 scripts/Makefile.lib                      |  3 ++
 scripts/generate_rust_target.rs           |  1 +
 10 files changed, 112 insertions(+), 17 deletions(-)
 rename mm/kasan/{kasan_test.c => kasan_test_c.c} (99%)
 create mode 100644 mm/kasan/kasan_test_rust.rs

-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240820194910.187826-1-mmaurer%40google.com.
