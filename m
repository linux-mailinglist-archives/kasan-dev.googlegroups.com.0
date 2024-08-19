Return-Path: <kasan-dev+bncBDI7FD5TRANRBLXVR23AMGQEE2SN6CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4647B95769E
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 23:35:44 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6bf7a4ff102sf76653786d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 14:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724103343; cv=pass;
        d=google.com; s=arc-20240605;
        b=SJFPFVdpKRIQTvffHDxH8KRZZtmRD2nVp2PPHoKt5cmPyHUHVSmfWbNeNSYodg8/y/
         lkysqIuW0N8+0tijJB1DGgdLm8e0XjMNtLXlpbX2BTJqKKI/u5g/E4u9RiSCDsqYEcLB
         2Xf5R3D7W4F6bwqGdOgsc0/TOPhiIUTmAtDNwl69SMRjGGQUi/ZHGBIPCF/5aL//Zie7
         zak+gsYKqT7c2MouEj9gv8riOlLDOtzDqkw1F12uzQYE0fzrHv9RrfR+DVfbKNaV9jkB
         kTCL2fyFWYv4psHPfyCkfCIK29C6U7LdUb+/h7JKJlTEAXvgM1vBTz6CAtO1/MT6P9Al
         isSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=beyIEOljxBAh+uJHj0z9Aj18L6gryFYnQfRIgVFt5HI=;
        fh=9Lp6QLxVusEpK0XmmAGC3+w6v/pSFCoYYwlHhjUdVWM=;
        b=UG4KC2I26302a03nBdBUqZmdMWCtW8CgZi2QaQ6e4LNkvbRxJFzKgdjtsjAb+r1Cvq
         m05cLDfALopvhrPwZUYsDqRoBZL8jVRMkw/ADPw4wVXQc+X6p4zMpj3A42mmIfjR5HEo
         xX0o821kMo2V4snCf9NhuPRKsAPRJHPu2kpfuo44HrYecswxf+C1UJM1QYpn3THZV0JX
         sRBFb9BntQn8va5QPxBFknePK41AXJmQYH8bCKQj/mLQaEyZAVmdylCGeRs8MiO9Kmz4
         GIrvZTU5kU/uf69t9Rf61oJELkzUl+ASbEwGQJRK95/Ozil4JXi3vHHDHIcLJnegwr/4
         KAng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q8Ijz12B;
       spf=pass (google.com: domain of 3rbrdzgckcw4yymgdqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3rbrDZgcKCW4YYMgdQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724103343; x=1724708143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=beyIEOljxBAh+uJHj0z9Aj18L6gryFYnQfRIgVFt5HI=;
        b=TfSI8F15r+o//zsZ7bTZ2nIuQSgw8njdXBio3bEOjKpprLeAeXiTWPkkePaDlsWT25
         irwjyfd+30r11+wOVmQGapad2eD7YjJMCN/TN6hEdKOuzUdrlXHra8DK4ifB7elQZ2i0
         G8nfXuZguLIw/JtsH+nSewa/wCle4uQmvi7ELh5ZDLrC9QyjoXLVppXUiL2nh70W+Pbq
         koipX+XDmQmaveGO+JxwqrpkYQkiX/zxZFjHiEK21C74+ETEkccvkRWsHaHcmTOvNBGz
         1kEYsWzskcsnAN9QwJvKY8kuz+l3IjNw6RPci4gA2V+XfupNMSPFy5AQoEibMK8ZK0d+
         lsjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724103343; x=1724708143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=beyIEOljxBAh+uJHj0z9Aj18L6gryFYnQfRIgVFt5HI=;
        b=Q8P+o/u8Glo6kwmJ6A4xc8Obhrdb/MRf4NRqKpId1wKxNrs9GRqCKEIFbiNbRReb6w
         ODLIJhZM5Eik1YtFaRskoZTJ2BMzsfbQTBSt6/Q++Si5w4d8NeH/aGPsVTkQiGCxVp1y
         7jWxsOEtdS8ti12t7iKHNabrEUssAQ6Z2NeMvTTDtEi+qjYqcXmGWeeL2IwD8G5pSe0O
         NnnzsKL1wzEvnpvUQ/xu2ewt8ELbM4ajlrxr7FvEe89aA7L1rQO+AWuFvbChCrZWiS+7
         Kl9QVUI1Xxnk9qYjiZFhdEZSCNAKnMxTpDRlZE1rtM6S88UIVYGe1l9YdtGpSrTfDzmt
         JtVw==
X-Forwarded-Encrypted: i=2; AJvYcCWVmmH0+t27VgqmZRFG2Px/DaUj7lRFHKWxi9/50xsRZCvjqSt0xhTS9nIrmXETG9DuBhHVGQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzw0pVmRDAEKqH84kIGUG8B1Elp9OzvflhzTDNAd+uAJ2QGu/jR
	RLmvqovZR9k1KAgegFaYtbQBmW4l0fmRijx2ngJUdxQrNWVOFa8c
X-Google-Smtp-Source: AGHT+IEwcJkuGHvOGqw6D1rDLHooPgfmFnUq0fpLaZlcFM/SA+GgHMmaULqVHwkh2uUImtWW78UkCQ==
X-Received: by 2002:a05:6214:5c02:b0:6bf:7d61:8b72 with SMTP id 6a1803df08f44-6bfa8a48cb2mr15420006d6.11.1724103342698;
        Mon, 19 Aug 2024 14:35:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2607:b0:6b2:a43b:dc38 with SMTP id
 6a1803df08f44-6bf6d39045fls71504376d6.0.-pod-prod-00-us; Mon, 19 Aug 2024
 14:35:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrX9K3jczsSTMMBRI/NIXQfMvHC4Bjt7IVSRkU52RGmVqIcSuzwyNhnQmyNsEsIsjh5xTMjDwgu0A=@googlegroups.com
X-Received: by 2002:a05:6214:5713:b0:6bb:9935:8eb9 with SMTP id 6a1803df08f44-6bfa88dc650mr24378256d6.2.1724103341965;
        Mon, 19 Aug 2024 14:35:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724103341; cv=none;
        d=google.com; s=arc-20160816;
        b=udRgY81tgaWPY/ImmUg8WRsm5ORwYxP7wxFekqtw3Xkal+sf1kVme9XPJtLdQoiRiN
         1uYun3ym4yZR4LOR/eLveKWBZ5BRED7alyV/Zdgd7FeSU6C1Aq1zv0QjT3yRtbkR/sKg
         P29EjFh5Dl39Scc0oB3AsGwRpOIBugH9Eo/08Mvi3mQvJWlf2K0Fa5EhEGqAHz/kyIsP
         Uqj1wYC8T9vXnttjH2AA+EAK7sLWAp6CxnEPrciQJnPDlTS7qn5JFRWeaTitEqLdJqy/
         E5ZjEabAm7pqyseftoy7Vuu/QS7WhJ9gn5oNbCAmXYUr7NuXxILE2WV2ffQ/gG552/1G
         HZsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=NHr+d6UmIU/9IG30FNpxZ6Aa0eu/YiD/uhxdbWXAtq0=;
        fh=kkas5ojjtDYyaY0/ggXRqID85Ny8h2PjzpzSe4H4+QM=;
        b=vzrLXXDJE4W2NeInqkrDkxBmm01NQzutvMak8HWcdiJizu/uRftC7eY50cSMH2uF0+
         Bjn0OiEPRQkDPKGCBHkeO/QggFRn+npjjDYNKGlZgHBfnTFwMdSnezj6FMjKLayw3QfM
         5rIkDEu+Q7xB2jIKqifC3TcRSo2rwzsGsz0p0LB09q7Q5i2gvyGAF5+ZLkguoEobhmCL
         XUWFBioTSFkTMjsm5tyQSvTWfGIUW39ngt05sr5Pmc/HlOuR0sPkvHhAzZ0pK3Vh70Vj
         +ufQztKngCkdvAvTgs4Oghjjx2/10dU0d9qGQloB2atTupcg1w9b5QYhLMtWFLIi+TTe
         /UbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q8Ijz12B;
       spf=pass (google.com: domain of 3rbrdzgckcw4yymgdqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3rbrDZgcKCW4YYMgdQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bf6ff025e9si4628916d6.7.2024.08.19.14.35.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2024 14:35:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbrdzgckcw4yymgdqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6b71aa9349dso32994407b3.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2024 14:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXCVVLDij6IAzv6bkUC1xty8gqDGPGxn4K7Z2KY3hlJonra0BSl+9ZLoJpRx6Qny5sCRaw5LJNkuys=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a05:690c:688d:b0:69f:9a1d:a04e with SMTP
 id 00721157ae682-6b1bb099b4fmr445507b3.4.1724103341547; Mon, 19 Aug 2024
 14:35:41 -0700 (PDT)
Date: Mon, 19 Aug 2024 21:35:18 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240819213534.4080408-1-mmaurer@google.com>
Subject: [PATCH v3 0/4] Rust KASAN Support
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>
Cc: aliceryhl@google.com, samitolvanen@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, glider@google.com, ryabinin.a.a@gmail.com, 
	Matthew Maurer <mmaurer@google.com>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Q8Ijz12B;       spf=pass
 (google.com: domain of 3rbrdzgckcw4yymgdqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3rbrDZgcKCW4YYMgdQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--mmaurer.bounces.google.com;
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

Differences from v2 [3]:
1. Rebased on top of the maintainer's cleanup of the Makefile.
2. Cleaned up the UaF test based on feedback.
3. Calls out that KASAN_SW_TAGS is not yet supported in the config.

The notable piece of feedback I have not followed is in the renaming of
kasan_test.c to kasan_test_c.c - this was done in order to allow the
module to be named kasan_test but consist of two .o files. The other
options I see are renaming the test suite or creating a separate Rust
test suite, but both of those seemed more invasive than the rename. Let
me know if you have another approach you'd prefer there.

[1] https://lore.kernel.org/lkml/20240730-target-json-arrays-v1-1-2b376fd0ecf4@google.com/
[2] https://lore.kernel.org/all/20240813224027.84503-1-andrey.konovalov@linux.dev
[3] https://lore.kernel.org/all/20240812232910.2026387-1-mmaurer@google.com/


Matthew Maurer (4):
  kbuild: rust: Define probing macros for rustc
  kbuild: rust: Enable KASAN support
  rust: kasan: Rust does not support KHWASAN
  kasan: rust: Add KASAN smoke test via UAF

 init/Kconfig                              |  1 +
 mm/kasan/Makefile                         |  9 +++-
 mm/kasan/kasan.h                          |  1 +
 mm/kasan/{kasan_test.c => kasan_test_c.c} | 11 +++++
 mm/kasan/kasan_test_rust.rs               | 19 ++++++++
 scripts/Kconfig.include                   |  8 ++++
 scripts/Makefile.compiler                 | 15 +++++++
 scripts/Makefile.kasan                    | 54 ++++++++++++++++-------
 scripts/Makefile.lib                      |  3 ++
 scripts/generate_rust_target.rs           |  1 +
 10 files changed, 105 insertions(+), 17 deletions(-)
 rename mm/kasan/{kasan_test.c => kasan_test_c.c} (99%)
 create mode 100644 mm/kasan/kasan_test_rust.rs

-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240819213534.4080408-1-mmaurer%40google.com.
