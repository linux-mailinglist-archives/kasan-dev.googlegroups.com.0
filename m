Return-Path: <kasan-dev+bncBD4NDKWHQYDRBYEN33CQMGQEJ4ST7EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CD9F7B4111E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 02:08:01 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3f46ca1f136sf47195085ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 17:08:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756858080; cv=pass;
        d=google.com; s=arc-20240605;
        b=EwuvKh5LtFHiPdRuTFwtnGmtv5ue7sS62pxcYeQp21Qls99+7ibxVD7ocrOiu3iUiD
         e8yakzmBNG9FuoadkiuDGn15TBhE50bF8pRN99JbOwKKVUYT55RuyKjZAFUaTeFcYsov
         Ro8CWEo4CxdaG7DTUywAUSdbif7b+HjIHFuNJ+LurILVkabYIBap4B9DCeF8v5VkfvXS
         7D/AX0ub3+7zjcZ5iKKwpXZtkMeHMn7mileINuDno2YNe8BfOVNQ4ujxL0To9YOHv+pC
         ZrWVR2VGadtdePpGoOaoTDrwr2fad7+TrqzLrlpnxse8DXhWvUhuGEsxIxq4joPdz+nG
         9fKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:dkim-signature;
        bh=GDVc/iEyG87VOFPr8Rq8Db0P3djuOMu2UcGpDXOWmy4=;
        fh=1B6lBfMFnTl85y3peb8kB+VInQj2hQW8QoF7CmO2CoQ=;
        b=PeEQ8gM+gGFwzprsf3T+G/Wg4g1/Rz50/wgUTjMjsaCNXGwIZA3PCJo12PpHihkoGT
         xq8vq5cvMeftvw7k9hHys2tRGqzSOhQlb00YoeCT/rBU5QVz+ctLTo+jkWG8ULsqndB6
         hFipTwT3szCufJjnt4JklF9Se/udXbIQrr1/uOKosqLK+OI2h4EVoIC5p2O3hk03f+Lm
         0Rrjt2GLzsCL+aJsac8q2xLCpmD6lmU2p/uivLtdk11frlHk2kZN/Y/YQ2wxpXm7YEDT
         VwvD8iK/wvorPNYLNYSwIqXPp08fFBe+me0qD+D3GJ4up5GPNNwIcN6r9p3VLQrJzRmL
         6u1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bcIji30N;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756858080; x=1757462880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GDVc/iEyG87VOFPr8Rq8Db0P3djuOMu2UcGpDXOWmy4=;
        b=G2IJevJOkSSzY632xlXqnUF1xbh7pW7BMCCVyB66/IBfSYytVtdySLUJDQoIS5IImT
         L0P+sGt4ykVyb3MDcqXbYnqC2jAKdnRZZ+51htPguXJly+TGrivpoS6SefirulE8UA8i
         5RqvW1Zv6x0vRU5PDtlUx4DzZm7CgLvCnVP4YHhNsUruMWLevL/BoeflfEIh1bV4k9aU
         6qT/XoIB3qFl2fM4SMo9iP8kSinNBSgaMtUeOeSbojoTfrGBJY3JEUXj88mWrNA5vgAW
         Bx5epo1rFHgvZjYvCq0C0VxHue9gOhfw9VO3tYrumPh0bqHSEcc1IUg4y7d3DvY9aSA7
         zoUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756858080; x=1757462880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GDVc/iEyG87VOFPr8Rq8Db0P3djuOMu2UcGpDXOWmy4=;
        b=Ky9Yy1nh8a0KmhzYnISWOhgyJ8CALAl/sjFNKP/auIuJYC7WsnEfdMMNA4gXMaIugk
         da7NIBJRDEPWdZ2qhYSacfTjx5N700w4DF9MgS8SwCLmRizy52y8Z/nUZRm2GW2TWTER
         +j0S5k3ebyG7oUyG1GFPfO5DVv/t3SH0bK4Zeqf8B3ZIrXfxkHO4S6+8TpKwngmttnPI
         jvzZboVYU8zGf+5w0SA6ysG/13QC64aadVqLpi/PM+ywg9vLpIAoojXK83G075E9yDe0
         QYEnjKHVv9dvcCNvLQvHUC2vZ8B1JxTYRRipwzwsvlpBGPwSpY+E0IK/6MkE/6vBUgcD
         YR7Q==
X-Forwarded-Encrypted: i=2; AJvYcCXleQbPLxwugO5n/7oXyMDBomH/dJRNcjFg6mlkZmKtcQcLgayEdy2YhMEEihv7fHBtR+veng==@lfdr.de
X-Gm-Message-State: AOJu0Yx8EGc22ZP+4RJ5ylAu1qPUZNZj/uqkB5Q3aFtf2je8AU8gsr9G
	oaGqiTTqlz/AohC2KUgsSoOapy3AgLuYqjW+c5eGnUwZyPXnKMZDmCB+
X-Google-Smtp-Source: AGHT+IFR/NcT/R4TEer+gfI8XNQaiatMD9o+//2a/s2oI+baaTx5wOSLtRp0zIO9lS0JMi+54oyVmg==
X-Received: by 2002:a05:6e02:2196:b0:3f0:40fd:9d1c with SMTP id e9e14a558f8ab-3f40066c444mr209901785ab.9.1756858080265;
        Tue, 02 Sep 2025 17:08:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduPjU5waw92O+Kc9rMzLe0hWVWbTkS5hpaape2j+1ATA==
Received: by 2002:a05:6e02:198d:b0:3f1:219f:f51e with SMTP id
 e9e14a558f8ab-3f136fb421bls41443835ab.0.-pod-prod-07-us; Tue, 02 Sep 2025
 17:07:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwB7aV/vjTXyiG3+mr4HV9JIWhpnBVeTGuEtSnrzwGafpMvN/OdQQOWnHt7adb/b+aU90zvLrSAbw=@googlegroups.com
X-Received: by 2002:a05:6e02:144c:b0:3ef:2fe3:9a08 with SMTP id e9e14a558f8ab-3f402ab5f52mr231076155ab.28.1756858077350;
        Tue, 02 Sep 2025 17:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756858077; cv=none;
        d=google.com; s=arc-20240605;
        b=b0uBtBwXZibovOsg3bT22H+tT9R9MuZAvlEWIC8nJbRGjD14NtcoUg5J7DpJkK8vSH
         pheN4wUzrSscGDKdFN2gage9/27hv5qXw8FVB+MlZWIL7j4cur2vf74dQXbtx1HkmDKJ
         lNOxpCv9TjaweUDGiYv2ZyPGEp93lo1h5kad5EP62s5b2/eluTUZiGtwJJko++dwQUME
         pV2IOxORLLIw8OBgVw0o4aGQD+ggJsiEGryVYb7uoXhTXdJcBGKhxeFrXcpb1P0Gq9KG
         nr5xzhCVpPhOwsJGY8gA3GphyKKERvYW2BbiQtHyNJBqEaazLaCntWbfQ/b8RuXdWSUa
         qOOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3jtTMAC2/4/jIncozNNaDFzFVU5ZfO/Xa6gGAi+T3z8=;
        fh=YdeaVbMSI8S86gwtt9lanH/ydeIQ024v9GINTVQVVBY=;
        b=GQrmbI5sU9vOLr6rvw2GzB9j+efAqEKcfxBwQdloPxasOkTYfSL45BM4Z2Z2Sji8Wg
         T0mXnZA03PuHnw0Yh4MIL4JciTuiveBKxe7m/hK8kkWRwoYlYXkMNA6UmFW3VE7vxjKi
         Sn2Fi5fCrNwsRL6GSwot6fhaXpMvCq+GWvhN5LRnTc72VqnkuqG3BzNYI8hFyxNWt9id
         PGxiGwBiWe9t+Y0N/dA4l9bayX57jzzX9aat2xwpfKa7V8OQnkYzfVeVcrvaI3Sk77P2
         DEGJ2FKaksHeCx4wXyvx3Gpjq6k393pB/hjvRBB3YAXgaoac+iJWVvn4nRCRGCa3CoqG
         p+0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bcIji30N;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f658e97293si1623155ab.2.2025.09.02.17.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 17:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 88B42448C5;
	Wed,  3 Sep 2025 00:07:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CD23EC4CEED;
	Wed,  3 Sep 2025 00:07:54 +0000 (UTC)
Date: Tue, 2 Sep 2025 17:07:52 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, llvm@lists.linux.dev
Subject: clang-22 -Walloc-size in mm/kfence/kfence_test.c in 6.6 and 6.1
Message-ID: <20250903000752.GA2403288@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bcIji30N;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Hi kfence folks,

After [1] in clang, I am seeing an instance of this pop up in
mm/kfence/kfence_test.c on linux-6.6.y and linux-6.1.y:

  mm/kfence/kfence_test.c:723:8: error: allocation of insufficient size '0' for type 'char' with size '1' [-Werror,-Walloc-size]
    723 |         buf = krealloc(buf, 0, GFP_KERNEL); /* Free. */
        |               ^

I do not see this in linux-6.12.y or newer but I wonder if that is just
because the memory allocation profiling adds some indirection that makes
it harder for clang to perform this analysis?

Should this warning just be silenced for this translation unit or is
there some other fix that could be done here?

[1]: https://github.com/llvm/llvm-project/commit/6dc188d4eb15cbe9bdece3d940f03d93b926328c

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250903000752.GA2403288%40ax162.
