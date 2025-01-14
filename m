Return-Path: <kasan-dev+bncBCMIZB7QWENRBVUITG6AMGQEFLKZKEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B9745A104ED
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 12:02:48 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-54278fd453csf1042413e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 03:02:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736852568; cv=pass;
        d=google.com; s=arc-20240605;
        b=L+AdFfesJQe2rEvC+rGSAK86vfpcZ6Wx3gJlGOxoxGfnzfC7o5O97iSvPc1AqY/77c
         oExGiONvW0CZrUApNee5rRXGBk0yqsigFpKArc23uN48Dz92tdvtaLgqkBikf7+LMPsY
         mAbBcgTT1Y+33JF5fQCAA35nXyKG+cEHcmmijZq7V1Rv+LJAEPyDKnm8/ta+b4qSzh2O
         avocFOkFXXFNDKG3fvDFk/s8wQ0U9iEKApn/d3oAmJ31dYCDfGDMEHs4sixHynATAg1J
         Td/MQW+T2k/bclLh5Bve3VXOYW4pra82+NlAznBfPOPtkNd0XhQ2qSdRc/jDdcT25mvt
         ejJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LwoXG3Ku+YMwoo7jy5vF8LRSgTDY8Ns2czA7YDUF1NQ=;
        fh=QUZQRqEIiQtYdRr7UtEjAJ6ZZP4qIoFuPW8RNZSb3Qw=;
        b=L15Yv1K+g3YutaC8p4T1B9BB9QH27KHEhbxZ+RnAGU9M2qWcNwVsxDcW5UvtICBGWh
         kw/ttRdQ+4WCIh6LNeBtZysz+4Kg8aJwPWow0jO9DcMuAmaDgMhZfF6+xIlVB96sWwgo
         fimTVSUvWy7W9+HDIDiiUH6SNVSwNN7zuwZiFq6ifNhvmbwaKyxTnUS3wXzq9v9Px1NF
         HX+Jf+BQdw6DdiRMQ6NiQJazgJkbdnZwRluhZoFJsglO2QErDpOX6xlEBnBJXVQoK8qN
         dX5QiqdJ9iX7TZ3/zORr/AtdGSlCE6LMbwD6nJONd7SZAtmW2LR1Hwc7kzFDN4ONMnbU
         coDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=St8S6jkw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736852568; x=1737457368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LwoXG3Ku+YMwoo7jy5vF8LRSgTDY8Ns2czA7YDUF1NQ=;
        b=jIH5nLksLlSgImcdbDSbF+Z99EHXPzlLVHVtXKwnp+PuoOtVoYI4O9urNNWWcN9L4s
         +E3QiORlOuRTjWkdOYh8ojiALNtOBWDeDHNcpekgYeK59M+5JcPnD17/Ewv8g5oOpjnC
         VjLdLqrNJvw5vQLd6+CBJtp3cWL2cfDQGHflF2NSTfFJCvgr6sQRowcexaMGF3MdtpER
         4ZumdR88Aaby0hR5p/X9k+O/yQIcsyMzFCxUt/4YdmLwDfM3VB/1nCY/aszFiCSl3Edw
         uTyW2IzJKUDPHaUov2QzpCm6ZA/4V7qsQTb7yZ/Vvj7kT8R8nHso8A+H2qwSINWGJwSb
         6z1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736852568; x=1737457368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LwoXG3Ku+YMwoo7jy5vF8LRSgTDY8Ns2czA7YDUF1NQ=;
        b=wr9t7oEv0DNAIjN8TOpSW+JZ+N96RKxhw3PLB20xv8WOhatnvr4j50jJrtdIlJrGeR
         FRQVuKM822lAOGH15JI7OhaKNmVsX8/pZN4opDIf4d4wbubhrYcFqg5ZtOf8Da0yKDFs
         rQSpGxmdPlpENm9dxftQXpI1zr4DaHbDzmFFocEapJ97Wa3444tNUIp6zq3geya2KEl5
         /ptod4lPM4I7z2MRn6AjjGlboAyJjXRLRQe+s+4IVBwkKGPptRuWJ7VGr8CkkfKZ9eZd
         Qo6UXXbxoBXknHqqUiGpBdc10poy60HEBJzFjTMRIKsb6kUnLrcUm2osfjffAlZZNfLL
         PCAA==
X-Forwarded-Encrypted: i=2; AJvYcCXYuBQJqlvc2xCUGRNhjvpWURiZg9XXNsa2khpmVcDulVQ0XsNpNpu4lJ9QIF1+7QZygsVnqg==@lfdr.de
X-Gm-Message-State: AOJu0YyZHILslkGt38kwwVYCS0U1qCG9a56kvHhYfkvuIbRj6Eb8h+Rl
	Tg75n9lXusxn+d1kQtpH0MmQk8zjgVi2N0Lwf/8dKg1aQRekWERt
X-Google-Smtp-Source: AGHT+IHR35fU1GBaD/Wb63OgqzzKoli5p9pa+vxyYyh16sSpgm3Xv5wAC1hD3XXg/307uzJ82hP7uA==
X-Received: by 2002:a05:6512:31d6:b0:540:1b41:c75f with SMTP id 2adb3069b0e04-542845bf4acmr8506099e87.16.1736852567036;
        Tue, 14 Jan 2025 03:02:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2d01:0:b0:541:1c48:8c0a with SMTP id 2adb3069b0e04-5428a1b7820ls1269300e87.0.-pod-prod-05-eu;
 Tue, 14 Jan 2025 03:02:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXayMYSS2tgOoifr19P3HgvkyC3NEmlFdQKSMuEMRYEvPIiaGozbKReQWanS/1Jpr6QWOCZACI8S48=@googlegroups.com
X-Received: by 2002:a05:6512:3e2a:b0:542:2999:2e43 with SMTP id 2adb3069b0e04-542845d6a24mr8932039e87.24.1736852564397;
        Tue, 14 Jan 2025 03:02:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736852564; cv=none;
        d=google.com; s=arc-20240605;
        b=bIO5oeMCphKZIKN0CN5clbA9bFdsQN55WvQQsg/bUPi189Yyl1wMiWTo/wCcGCLvFE
         w+NztFH4gCPCAEBAnLIQvO8nrWvEFeJJyK9VAqAI9orPblH7QnpRpTgfvCoU9h8a6Czo
         D0YyscLFxKSfphQ/PuQCH08k81qb7s+4R09jZO07APTF4lZ77hWvQOa0VPLFrB5SqaK5
         RHd8AmpvPSgLPfxxisWhnB3W1Hz6xhxRrWYdEbLYj9JUPa/1C9Yq8PlrS34PxsXFxRll
         2sf4PhtUa3pLyrVRSGsfdyGcVy4929giAlmdMA1/sz1UxMYWvxqI83J6oJmT99V4ywKO
         NJwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tkDcNJulp0KAE0ecW8Wxpxi/6ej7l7BU9iILAcZFrUc=;
        fh=MdRZTo3cAQdti8DJlJHsNgtOd9htsi4pczXekgRW8uw=;
        b=eXk90Av3ktGhJO9RCs3NjBJ01lL21NXJC4g6a9rTehGOR8ebrJ6/F4tI0t7J7nHE04
         gY7kxDijO7zt4Aob/7NQyU9s+fg4L/fpXxaGjJowHb2D4/OcprUp7SdL6BX/hgmm6zcx
         bQcvBFiu2ba6E9FCboqBZNMVtFKC2omHjK4Ns9dN1ZKDzHlt9MyfmRiqFg6gzBgIHYnN
         n+7g/yF985x8URaa+ztNb5DOrw8JZgzi0ZlhDjkFuBV28AfRwck2SJN/o96+rlOzYmp2
         xKyuXz1hNi9YO6UjuE6ZFqnU1Z1CUAMYQmZGw6ZSU5JA2yd8b7USG4PT4MX61F0DiFB8
         gh5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=St8S6jkw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5428be33c6asi290749e87.2.2025.01.14.03.02.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2025 03:02:44 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-540215984f0so5847938e87.1
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2025 03:02:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW+ig4iZRqJYzJg994pR62qT9SKYroqqWTdcYQBlfU0QsHI+26jgcrylzFtt/EzC2UTYmSfjKhju54=@googlegroups.com
X-Gm-Gg: ASbGnctjoANKKXoPHXSsQ6kqvQZsFNKa8fIiGlE+xR8aFR0JQ0zORkmBAvp665UysAZ
	qrOeK22RLlDtLTdPbIcl+E50NjtsDjdO3WjOXDs7A958mFs6/ZZ/dQ+BAaAcjnF5CkHsf
X-Received: by 2002:a05:6512:238e:b0:542:97b9:89e8 with SMTP id
 2adb3069b0e04-54297b98aa9mr3302952e87.23.1736852563653; Tue, 14 Jan 2025
 03:02:43 -0800 (PST)
MIME-Version: 1.0
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com> <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
In-Reply-To: <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Jan 2025 12:02:31 +0100
X-Gm-Features: AbW1kvbVjib7z1JcHA7nqt52tIMjbajYXxACvsKxzNI1Rng2SxsEsnkK92Vh8CA
Message-ID: <CACT4Y+badwgw=ku--uJRWA94SA6bGXdtT+J9eO_VQxqWDxGheg@mail.gmail.com>
Subject: Re: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
To: Marco Elver <elver@google.com>
Cc: "Jiao, Joey" <quic_jiangenj@quicinc.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, kernel@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=St8S6jkw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 14 Jan 2025 at 11:43, Marco Elver <elver@google.com> wrote:
> On Tue, 14 Jan 2025 at 06:35, Jiao, Joey <quic_jiangenj@quicinc.com> wrote:
> >
> > Hi,
> >
> > This patch series introduces new kcov unique modes:
> > `KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique PC, EDGE,
> > CMP information.
> >
> > Background
> > ----------
> >
> > In the current kcov implementation, when `__sanitizer_cov_trace_pc` is hit,
> > the instruction pointer (IP) is stored sequentially in an area. Userspace
> > programs then read this area to record covered PCs and calculate covered
> > edges.  However, recent syzkaller runs show that many syscalls likely have
> > `pos > t->kcov_size`, leading to kcov overflow. To address this issue, we
> > introduce new kcov unique modes.
>
> Overflow by how much? How much space is missing?
>
> > Solution Overview
> > -----------------
> >
> > 1. [P 1] Introduce `KCOV_TRACE_UNIQ_PC` Mode:
> >    - Export `KCOV_TRACE_UNIQ_PC` to userspace.
> >    - Add `kcov_map` struct to manage memory during the KCOV lifecycle.
> >      - `kcov_entry` struct as a hashtable entry containing unique PCs.
> >      - Use hashtable buckets to link `kcov_entry`.
> >      - Preallocate memory using genpool during KCOV initialization.
> >      - Move `area` inside `kcov_map` for easier management.
> >    - Use `jhash` for hash key calculation to support `KCOV_TRACE_UNIQ_CMP`
> >      mode.
> >
> > 2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
> >    - Save `prev_pc` to calculate edges with the current IP.
> >    - Add unique edges to the hashmap.
> >    - Use a lower 12-bit mask to make hash independent of module offsets.
> >    - Distinguish areas for `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
> >      modes using `offset` during mmap.
> >    - Support enabling `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
> >      together.
> >
> > 3. [P 4] Introduce `KCOV_TRACE_UNIQ_CMP` Mode:
> >    - Shares the area with `KCOV_TRACE_UNIQ_PC`, making these modes
> >      exclusive.
> >
> > 4. [P 5] Add Example Code Documentation:
> >    - Provide examples for testing different modes:
> >      - `KCOV_TRACE_PC`: `./kcov` or `./kcov 0`
> >      - `KCOV_TRACE_CMP`: `./kcov 1`
> >      - `KCOV_TRACE_UNIQ_PC`: `./kcov 2`
> >      - `KCOV_TRACE_UNIQ_EDGE`: `./kcov 4`
> >      - `KCOV_TRACE_UNIQ_PC|KCOV_TRACE_UNIQ_EDGE`: `./kcov 6`
> >      - `KCOV_TRACE_UNIQ_CMP`: `./kcov 8`
> >
> > 5. [P 6-7] Disable KCOV Instrumentation:
> >    - Disable instrumentation like genpool to prevent recursive calls.
> >
> > Caveats
> > -------
> >
> > The userspace program has been tested on Qemu x86_64 and two real Android
> > phones with different ARM64 chips. More syzkaller-compatible tests have
> > been conducted. However, due to limited knowledge of other platforms,
> > assistance from those with access to other systems is needed.
> >
> > Results and Analysis
> > --------------------
> >
> > 1. KMEMLEAK Test on Qemu x86_64:
> >    - No memory leaks found during the `kcov` program run.
> >
> > 2. KCSAN Test on Qemu x86_64:
> >    - No KCSAN issues found during the `kcov` program run.
> >
> > 3. Existing Syzkaller on Qemu x86_64 and Real ARM64 Device:
> >    - Syzkaller can fuzz, show coverage, and find bugs. Adjusting `procs`
> >      and `vm mem` settings can avoid OOM issues caused by genpool in the
> >      patches, so `procs:4 + vm:2GB` or `procs:4 + vm:2GB` are used for
> >      Qemu x86_64.
> >    - `procs:8` is kept on Real ARM64 Device with 12GB/16GB mem.
> >
> > 4. Modified Syzkaller to Support New KCOV Unique Modes:
> >    - Syzkaller runs fine on both Qemu x86_64 and ARM64 real devices.
> >      Limited `Cover overflows` and `Comps overflows` observed.
> >
> > 5. Modified Syzkaller + Upstream Kernel Without Patch Series:
> >    - Not tested. The modified syzkaller will fall back to `KCOV_TRACE_PC`
> >      or `KCOV_TRACE_CMP` if `ioctl` fails for Unique mode.
> >
> > Possible Further Enhancements
> > -----------------------------
> >
> > 1. Test more cases and setups, including those in syzbot.
> > 2. Ensure `hash_for_each_possible_rcu` is protected for reentrance
> >    and atomicity.
> > 3. Find a simpler and more efficient way to store unique coverage.
> >
> > Conclusion
> > ----------
> >
> > These patches add new kcov unique modes to mitigate the kcov overflow
> > issue, compatible with both existing and new syzkaller versions.
>
> Thanks for the analysis, it's clearer now.
>
> However, the new design you introduce here adds lots of complexity.
> Answering the question of how much overflow is happening, might give
> better clues if this is the best design or not. Because if the
> overflow amount is relatively small, a better design (IMHO) might be
> simply implementing a compression scheme, e.g. a simple delta
> encoding.

Joey, do you have corresponding patches for syzkaller? I wonder how
the integration looks like, in particular when/how these maps are
cleared.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbadwgw%3Dku--uJRWA94SA6bGXdtT%2BJ9eO_VQxqWDxGheg%40mail.gmail.com.
