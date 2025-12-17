Return-Path: <kasan-dev+bncBC33ZPNHWMEBBYMFRDFAMGQEXUEAKUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 07857CC5AB8
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 02:09:56 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2a0fe4ade9esf32822555ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 17:09:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765933794; cv=pass;
        d=google.com; s=arc-20240605;
        b=ggGDv/IDltoO9oPzUt42r1hqZx7+6uFwzT5izHkByJVP8t1awHvEbqNX3W4N8GeJL1
         zknjUGYWWjBEhpPrpOVBAyxrQamwKJ+vAsVHH7jSW0JR/JCecYZf+Yu+u2xM3a64zQD3
         snPL4pn1vYiggAeCeFkwDTK4Riw9J/0hPo9BoLOpxAV56nc60mfB4iZJiAA5/3++ObIU
         SoI4vBXQJRov+bKIObI+SEz9X6BukywtuIq5/QuWuWDKwUKD2PCh/x37m2OA4ZlARiEE
         KQkRsFC/AdGOTZn25FKju77HCmFNCjqL6eOoKxIxLterwJI/hPX0oi9WMrAx+fxZV0qT
         yDZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Af4muw3wLfnasdtnPXdjM1Nld/Rw4erGoqeyoZiDjG4=;
        fh=Vodg2hMtRn1mmv4NjbLciJlmOZBwTxkfGsUpoo5L9lw=;
        b=XKJYI4WMgRDjNRpVwU7LsUbcOtDhrcXN0IsKDRycK0UawNasVWloWgspSLo7PBfw4z
         aHNgF/miFlCRZSb7unFHe/hIUfZFyu1Cza6x31YAl0mQwWV9WU4/A4K/hPG0wyKGMiWA
         r9SnWk8C0OpyM60GqiZ7i0XQwFxZVoyyCU4jSL7oxWerFj9Ed1/e1jJ9UAy8p8TZ+2VV
         4OXvZPhuDsJZ/EgFpLmGNgjw4GEYyDWL3J6Av429UZ/pYeW6N341fjCwd3haqsrE6FbQ
         6+PDp7JdDIByD6BfqdotRdJ78Q9bUrUA/BY9pRrYDACEPyi1hGenplmjRoY8FWZoD/wR
         vhIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@illinois-edu.20230601.gappssmtp.com header.s=20230601 header.b="KWCFQt/N";
       spf=pass (google.com: domain of wentaoz5@illinois.edu designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=wentaoz5@illinois.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=illinois.edu;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765933794; x=1766538594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Af4muw3wLfnasdtnPXdjM1Nld/Rw4erGoqeyoZiDjG4=;
        b=SfnCfCQ16l4PB4Q4Bj0QpcFqiMH7yj7vjb9naVST36ayD1WfmRpToqiw7gASsmsnPQ
         ZERg+63oQD+Cye6PTe02ynpeZxRqAxerD61ia8wvGB6oJuOAkxzRICpgVPrtk495ChUh
         wDr3sq5SYV7L65nNAzhpHgk5DdgNM+87VmswxkdAD77hUwuxNSaMgOwp0bIW2DwxN830
         CMxT9Thm/joBGMZ/i6vFimrDkcOxexKEj36QAbcZ8LwSF/AYppuAfToe+v6sOzZf4AlF
         0rmkSPW95Aao+o04ySRyUANvxRD8yC19noRmpWO9p9EfYVim+9fEfFTkocoCAjs6zifw
         C+qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765933794; x=1766538594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Af4muw3wLfnasdtnPXdjM1Nld/Rw4erGoqeyoZiDjG4=;
        b=Iu4+y++F34JIHGy+6Y2Fzfh0W30kxKWAmHEUa9CEOYcrkrxL3N8zHs0v6kYswQ9dLT
         mLt0DE/Ma9s+x49xO/9m34iliv2ksQQklWMb+PoovBq1qN/dPrUSKJgroBeWtj9G+Eaj
         eWv8Q5sRmsqj1/oZ4S8SCsKawufmSzsL6kBQRFREAaemrZ3UiyszaEowKLijQb+AkgLC
         jPH0qjXcte7fhQS4wfZ0Ti6piRiQaUd72OyBe3NaqmvbNS3z0GI+DDXB1dchqPzANX1h
         CkBp2i+T2LQqqcKN4yaJEPb9UTwqesqiVKCUYQ6FVWoCq9LGNvHkoxXte+kcGjHPsaDu
         nw9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmF551D/uEjgdLEfR+gVM/hGZMwiMfSrb0BBE90szxQrdRFG4Xd1bE/r259mosmIjKoSM3Ng==@lfdr.de
X-Gm-Message-State: AOJu0YxU9mPx0u2vZMkv+DYKKEuqxEwIQj0qcf/hAfOfqaXzaJwYVV7/
	GIiIndodbf3Gu+IhKuqL537pj0GkjCvX+/1cyJtuT+Gx/FT0UQIPGvqr
X-Google-Smtp-Source: AGHT+IEXIO/bsaPH9/8S0NM8IOx3C58ousIXPsUkzuIdLzRMNQpLBzIxs4pTpWIA1wJa2u23frcKXA==
X-Received: by 2002:a17:902:f544:b0:2a0:e532:242e with SMTP id d9443c01a7336-2a0e5322636mr85486145ad.11.1765933794124;
        Tue, 16 Dec 2025 17:09:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb+10+WtVu0ga2taGBSxGw8jNfYUW96yBHxMyzxlQ4EaQ=="
Received: by 2002:a17:902:8504:b0:297:e6aa:c4bf with SMTP id
 d9443c01a7336-29f2335d88bls34591375ad.0.-pod-prod-07-us; Tue, 16 Dec 2025
 17:09:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWzehEtYAYoq2fqF7x2E/gox8c4vUVhWIwZDH/NZaKAUKXAZK1X4m2T50fA/7fzKBjOn8rW2LDtXKk=@googlegroups.com
X-Received: by 2002:a17:902:ef47:b0:298:33c9:eda1 with SMTP id d9443c01a7336-29f24345b37mr140434915ad.43.1765933792459;
        Tue, 16 Dec 2025 17:09:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765933792; cv=none;
        d=google.com; s=arc-20240605;
        b=DAZDhL+bNgcALpoZ+R5H3JQJ4GzjqrL3qFw1w+KiZBEMNdeXBrcm44ydI55Zoi897N
         HY5FoFExEZu5AiL26c95afCxaiOU3dlfOtjYmaxhlzuSFqx8LIP7frtspTaFwhK6DACA
         PdEOBIoR7GSgE4atVyKU961pmEStADs9NJc2YMap52xRluZJ2LlKzGkP9W8rTB5a1JwW
         X3ZfEROhM1+09xOtssxGdBHSg9bCAXdMJ/5HPhiu7HaoCjF3kl5AWA1CegH6Y9zrUpxR
         XEE8VAXZq0FJ1b40w//kyMBiKFT4ALP9xP1P5wQOVA900wV3HtlM5t+5HFnwesq+ITbJ
         c9yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zZf/eYpssSDfJG49JiyiKh6ythPIDtWBJCMznOyLz/w=;
        fh=Or1o4bAUicGAkQw6vnc2QidJSOOs4xMXUnDUpDY9jEc=;
        b=LpN+IyQ6kpDkcf59k4dk9w0AhC+0XIA8cZVXWPwzpC0CAYpp+sHkSsL2BldP8sH5qh
         wea63VrvBldJUiyPahgUFbi4PWrHuPpbKhP4JEWcAlv3+2vkmskImyG6YyfM4Q1vDgPU
         oYicWNvGclkextu7gdgbEZQlXtGgEFFTVx2W9QCzSA1AhNJuSMfYaFhrahvWspeoKCKQ
         6TYfWPO+Amm+zcGi/RBPQpId5Pygb7e5tkU4hoJ7bnO131FZ9XNAFJWZSwNAF+ISAOnv
         gjyMzpZZtjY4NOCYVqg9Zm/JTIdSrfqSHTlS/5PXgrwT3Owwu8pXjdWoeeaLLMqh5FFE
         OVSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@illinois-edu.20230601.gappssmtp.com header.s=20230601 header.b="KWCFQt/N";
       spf=pass (google.com: domain of wentaoz5@illinois.edu designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=wentaoz5@illinois.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=illinois.edu;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a15d1c625csi574085ad.1.2025.12.16.17.09.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 17:09:52 -0800 (PST)
Received-SPF: pass (google.com: domain of wentaoz5@illinois.edu designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-88a3bba9fd4so23299106d6.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 17:09:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW7jXmD3Au8TsaYLsEGRHE+Iau0aZf7JFYgCY8U4V0H2ZpmmcG0c4VYJ/HVv6J9cd7+EDkAvxY5VMo=@googlegroups.com
X-Gm-Gg: AY/fxX4b+9Am6DKqKLHMuEeIZ4uoh8+2WCDpZxo3dnx4EoAP7MTDs5YBRVbXNng+G4N
	GgzMpWThb0F7t/743LeAkxhdRaRZ6WFmNxjkFOT+oCT1g7bjjQilUkl/5/QTRFPa5Xj9jLWjf+d
	j44FyKUZyIyLvzlXzOprb175aPLSHZ8U6fb206iHUbPYUeB2sFrJ5xE46MvR18aTMBp+y/YU/KU
	crjfxF01bbDzsnahnGdJMfOOSJTRChjgM3JT4e9nZ6WiX8cEMARNimG0EfIinNtcs3jzDcZKZj4
	dYS7Ys+oNbysUd5ws8mpLjDsHUk28PtLtIyU4mkXsVZyawsVITyuEGpy92GPxE8PLV30uDvDvZY
	iapBkV7wr0lykLT9uKr2Xqo6VhjR3CM0y8A3cSja9FdToYb9N7TsILXunAAto6gNr6Lyov0CnQ+
	UevK/VWuXBjQJwPDZspgUWY/Ui3ilhDuc9d/ZUdjBI5dAvR40igSdtDvhEGjTFjTzC/EWQ7UAHT
	rIA/cgQbRJJ8Q+WD5iz2MjkQBsOAQeYNlEPtw==
X-Received: by 2002:a05:6214:509b:b0:793:dce5:4540 with SMTP id 6a1803df08f44-8887dfec0a2mr293576516d6.2.1765933791524;
        Tue, 16 Dec 2025 17:09:51 -0800 (PST)
Received: from wirelessprv-10-192-243-69.near.illinois.edu (mobile-130-126-255-83.near.illinois.edu. [130.126.255.83])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-8be31c75b79sm290605685a.53.2025.12.16.17.09.49
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 16 Dec 2025 17:09:51 -0800 (PST)
From: Wentao Zhang <wentaoz5@illinois.edu>
To: ethan.w.s.graham@gmail.com
Cc: andreyknvl@gmail.com,
	andy.shevchenko@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com,
	Wentao Zhang <wentaoz5@illinois.edu>
Subject: Re: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
Date: Tue, 16 Dec 2025 19:08:53 -0600
Message-Id: <20251217010853.54863-1-wentaoz5@illinois.edu>
X-Mailer: git-send-email 2.39.5 (Apple Git-154)
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wentaoz5@illinois.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@illinois-edu.20230601.gappssmtp.com header.s=20230601
 header.b="KWCFQt/N";       spf=pass (google.com: domain of
 wentaoz5@illinois.edu designates 2607:f8b0:4864:20::f2b as permitted sender)
 smtp.mailfrom=wentaoz5@illinois.edu;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=illinois.edu;       dara=pass header.i=@googlegroups.com
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

Hi Ethan,

This looks interesting!

On Thu,  4 Dec 2025 15:12:39 +0100, Ethan Graham <ethan.w.s.graham@gmail.com> wrote:
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
>
> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format

Do you have any idea how this could be extended to target more stateful
functions?

> converters) that are difficult to exercise effectively from the syscall
> boundary. It is intended for in-situ fuzzing of kernel code without
> requiring that it be built as a separate userspace library or that its
> dependencies be stubbed out. Using a simple macro-based API, developers
> can add a new fuzz target with minimal boilerplate code.
>
> The core design consists of three main parts:
> 1. The `FUZZ_TEST(name, struct_type)` and `FUZZ_TEST_SIMPLE(name)`
>    macros that allow developers to easily define a fuzz test.
> 2. A binary input format that allows a userspace fuzzer to serialize
>    complex, pointer-rich C structures into a single buffer.
> 3. Metadata for test targets, constraints, and annotations, which is
>    emitted into dedicated ELF sections to allow for discovery and
>    inspection by userspace tools. These are found in
>    ".kfuzztest_{targets, constraints, annotations}".
>
> As of September 2025, syzkaller supports KFuzzTest targets out of the
> box, and without requiring any hand-written descriptions - the fuzz

Do you happen to have some numbers on coverage, convergence time etc.
before and after KFuzzTest?

Thanks,
Wentao

> target and its constraints + annotations are the sole source of truth.
>
[snip]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251217010853.54863-1-wentaoz5%40illinois.edu.
