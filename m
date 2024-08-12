Return-Path: <kasan-dev+bncBDI7FD5TRANRBFVX5K2QMGQEGKOOOTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AAF294FA4F
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 01:32:41 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-52eff5a4faasf5981870e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 16:32:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723505560; cv=pass;
        d=google.com; s=arc-20160816;
        b=mfezd/zrmXlIkZaKiVzkGqhGM+8apVYu908vYINCPpxn+NFSgj/imZC5FWYL0cVTm/
         5ACSuUw3Ex2yk1qEA3fzCtAjwJyERS+E+nlLND9w3ugorldAetH9VF/I1GogracU5W/C
         CWGMHJjS6DGcAiSmwAEifWUSYbSsJgjygejB1nRaiPxBv5c3cymBTcIpDmvlTUW8C+5k
         iDiiREpgE+sspMTe1wEOIVyf8loFStO01KyUu99nwUCKzHzrIDDsT66iHiNKQnyyXkk0
         K0z/34lh2yZE50XoCQ6F48X5f4Bv9gAs1JLHd1nuyMvkorbs6KyNBb4QHEuQVIuujTiX
         6U0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lAKK8C1ThVJuyvmBClbDtF4r4mZyZS00+EH4KebrMGc=;
        fh=jPxlha3S8W0yiHllqMBGn3waGw7Ge37h2m9B8zmPkg0=;
        b=t6gNZkOsEnH9E+To1uFW/o+9Mx9cBTniLe6wrc7MwXtrkf6IsAECbtsmfkIWmUc1cV
         4a+CwIIV2ycd7Wgb3bKcP8lrpxK/9qsiuxBHPZQNlCpVp7bvj11AHYEIGzQ5UvnXlTN+
         dgTe7g7yvGoorvcWy1i3jFPp9BS8MNCrErPDa7s1KYUY+OH9wqjCt81FzoO8JIOtxIE1
         ZzaV46pHRaHN94I/TtrR96o1luyrQ+FJUiJUeb+ED1e5+7lM4zy01VOGH5flOfarKKdu
         GxsMEYmFyhWxPbZg8UKJiF2wa76P1QoScH9PowuwkJKjM0RRNQUYXhw0kVGLcHapPu1o
         wYwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lV027BGy;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723505560; x=1724110360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lAKK8C1ThVJuyvmBClbDtF4r4mZyZS00+EH4KebrMGc=;
        b=wbpkBSHBuIk5kb7patJfBuQPU7ReUB+j0sQ0KNnztQ74YaaYSQtyyGGpbItBPG7IbH
         2KyeupwfeuPnwB6PU8PScTjIvom4aYUuAt0fl+5TUd1od5QUexbe+/HHIpoaqCbsS5MV
         5Zhf74RAUCwvwgxxITZebwK4KpJDGM8IYpYyPA+CCUoksUQn7de2huVj/KUR0b85xQ+C
         ZAM6kMWcPMjUU3FlrG5AsnwmLRoL/Hj6YT9m2RlN2dlTTPrTKheZ2TNVaof4aONzu8NQ
         5XCLMP2sfJlcjfS9ZOBC65bIiMyr1c3kSaIfNov7UJ1Enn7nxRx/U4vy8cJFnBk+gSnP
         CW+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723505560; x=1724110360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lAKK8C1ThVJuyvmBClbDtF4r4mZyZS00+EH4KebrMGc=;
        b=lhO+cW04nFL4Ddvu2gm8Y7BRTQjHqql8z0Eaf3TrjlVpAA+aEYNBb/4SwBATOJd1de
         u9dhNbtBcfz3Mdmnl1FA3vsI4T5IyLaiHflIxgTqv72zjddC7Srw0bTXjNtGgtTmk55o
         R2h65bHbJpONFSRzg2s7EGrsuK0vtBgbJQOUtD21WAAZl9bMMKjdKzFy3aIzTwNAw414
         UHSwGZHrMX9hXGoQSWYgWiNl1SA7iAOMgaOquK983ns8RxHSypYAkXFZDY/AfsWBz56P
         ToPROMi84d4qfXNzOzDEyO9/rtPNYAq8QWimgGhg1pPcz78mLYJ3P/K5aLBWuPGUAF1N
         MeDw==
X-Forwarded-Encrypted: i=2; AJvYcCXa7YIRWvfNg1IvluxpfzFX7PGh8Eu2vlJIsEL6DKIGulicShdIa3GWTZCrrHghninknFOMoKd+P4DUBwMr6Q4W6IjFvbfzqw==
X-Gm-Message-State: AOJu0YwxnY4PrD36BaFx6icrVWfNqIEn+rkkeS5dARp/erD9h7x1J2CR
	x12cA3gBeSblqvl9M4Bb9BrXlGQeg4dYB8EZSt0rmKDPajQNGJ8v
X-Google-Smtp-Source: AGHT+IE6Bs8prZ1Bh8IZuKNrQKoIpZz5k8GrTMdft5OWmDkdDXBf+08dh5CsCV7oZLYlp/ewgNSqDQ==
X-Received: by 2002:a05:6512:3f01:b0:52e:fc74:552c with SMTP id 2adb3069b0e04-5321365d401mr1165632e87.33.1723505558947;
        Mon, 12 Aug 2024 16:32:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ba0:b0:52f:158:3411 with SMTP id
 2adb3069b0e04-530e39526d3ls426401e87.0.-pod-prod-09-eu; Mon, 12 Aug 2024
 16:32:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz2cvPJqkMgqyAdFHljBjBkpThWz0jkRWuWqZ7p50HX+4UCFI8UAbEQ4F9lvFTbPqOLypC3kwmCuthRnt2ZFV44QPGvo3+H/HNWQ==
X-Received: by 2002:ac2:4e01:0:b0:52f:3ba9:3bfb with SMTP id 2adb3069b0e04-53213649f26mr1266691e87.6.1723505556799;
        Mon, 12 Aug 2024 16:32:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723505556; cv=none;
        d=google.com; s=arc-20160816;
        b=o32saJbkCnEDp6PgY9iUuGLqjdlC959EZYNm0hOooZHXpjtvf7RBLJtEm0cwq1gpFc
         xGjx2XfHa3ETIJCLmIZgri53MhxZ6qfovEpH9nE3le5HBIngpyU6WC/XWlgSKGR+EK63
         XNIHqg+yBWFja8Lo3z7+OxtAEMdqGNKuAN138+8cdtm3tEWBquechs/NuZsuaOvVx0YG
         axzjgjg2EfS4MO8V+ND1rO/ts7xDNWeAoCGxNkb5+LQfrJqven0Bj7d9IU9brNFSpi9X
         1B5EM0b0V5od6It6i4drRFDSRVkIU4sYyM5I3oPptlZmtcCRJIgKbqZLK1LWwpWuwFFS
         YZJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WINgTrCjEBL3+Nvcrrvvezt+JSvL21kHSKavfKsKanw=;
        fh=+LVyH2NZGDMRgrdOxGdSXxtSBe9Kb7olsBEH3EThqQY=;
        b=WdMsvICrspwi8j3bI+v0sHN07fgRnnEkEFcqZuupHUBvnYqnfv0AoBClPdsq7B36e4
         jA+rUqOivTwlcWrLzBzGFv3B/R1jXP9OBTfEDUxYzsejSERswgDBwE1Dp+pVAxVmxZAj
         PhlG4jLxJKtVabB6RC/Q/DWh2HieApff5DVyb72ivfjTMSErCJS7kH0qDiFaKJEA/tLj
         TYUcDCRm6IfsUr80MyQuGmQnG5zhE1An8ZG4RM6V5uvxViZY0UItX5vHmOdp6YJBo4iW
         PDq7NPxlSdyjvTiwRUInWC318Hs8Q8ERhZbhOBJ1T6+RJrY2+zJXBf9NyHQt7GSG3k8F
         oeCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lV027BGy;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200e91898si121215e87.1.2024.08.12.16.32.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Aug 2024 16:32:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso3878a12.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Aug 2024 16:32:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXKgFOnpFpVnEQseWg3twTbM3wuJD31rZbuvyCA2SnYOmqO+3eAFrcXWGCRHX8prha7YRaAVDwWvhqu/ZbC0bcKLCCqdHYaTbvFzQ==
X-Received: by 2002:a05:6402:3496:b0:57d:436b:68d6 with SMTP id
 4fb4d7f45d1cf-5bd73d1681emr17857a12.7.1723505555723; Mon, 12 Aug 2024
 16:32:35 -0700 (PDT)
MIME-Version: 1.0
References: <20240812232910.2026387-1-mmaurer@google.com> <20240812232910.2026387-4-mmaurer@google.com>
In-Reply-To: <20240812232910.2026387-4-mmaurer@google.com>
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Aug 2024 16:32:23 -0700
Message-ID: <CAGSQo00138fombiueBM-4-OF15afzx3U63Uu17K_wvh9mkFAPg@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] kasan: rust: Add KASAN smoke test via UAF
To: dvyukov@google.com, ojeda@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>
Cc: aliceryhl@google.com, samitolvanen@google.com, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=lV027BGy;       spf=pass
 (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52a
 as permitted sender) smtp.mailfrom=mmaurer@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> diff --git a/mm/kasan/kasan_test_rust.rs b/mm/kasan/kasan_test_rust.rs
> new file mode 100644
> index 000000000000..6f4b43ea488c
> --- /dev/null
> +++ b/mm/kasan/kasan_test_rust.rs
> @@ -0,0 +1,17 @@

Realized right after sending there should be
// SPDX-License-Identifier: GPL-2.0
here. It should be added before merging, but not re-sending to avoid spam.

> +//! Helper crate for KASAN testing
> +//! Provides behavior to check the sanitization of Rust code.
> +use kernel::prelude::*;
> +use core::ptr::addr_of_mut;
> +
> +/// Trivial UAF - allocate a big vector, grab a pointer partway through,
> +/// drop the vector, and touch it.
> +#[no_mangle]
> +pub extern "C" fn kasan_test_rust_uaf() -> u8 {
> +    let mut v: Vec<u8> = Vec::new();
> +    for _ in 0..4096 {
> +        v.push(0x42, GFP_KERNEL).unwrap();
> +    }
> +    let ptr: *mut u8 = addr_of_mut!(v[2048]);
> +    drop(v);
> +    unsafe { *ptr }
> +}
> --
> 2.46.0.76.ge559c4bf1a-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGSQo00138fombiueBM-4-OF15afzx3U63Uu17K_wvh9mkFAPg%40mail.gmail.com.
