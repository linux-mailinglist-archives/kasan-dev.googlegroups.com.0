Return-Path: <kasan-dev+bncBDDL3KWR4EBRB6MPQ6BQMGQECQ6GESI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF2FF34D00A
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:28:42 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 8sf9565622otj.11
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 05:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617020922; cv=pass;
        d=google.com; s=arc-20160816;
        b=KkIKyEGFb0j0MYrQ4i16oFp1gfiXHrliGg4sJYGoKAjINNsDh5MKmfhIVxjQ9Hw77+
         OtHUczmuyiARwyQCrD/SMQCX2rEYnoBDQmSN8ypw1BX4/ONmT+qgUptSXw3EIXTriEi5
         yjfrJGNZDuWuR+jwBJqLGCU7SLUcCpJwlWERSEbX0fIwCbzcGjgMcbMaD1ItAvX6Rw7b
         vErKB5/wymvSejDkv9iDSHDqiPDjc/L96ER9GQIUEwketEgyxS1g5rdIyfLAuIuZ6SVK
         KYj5zXZgiAA2mjZ1vOLwV9KDDndlZ+Bgi/PMhniOYxJVopk8c3Ix5iSWzWuVi+ecImS/
         IYQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/T56k53pkoHkF+Moqw2yeBHGKJueO3lkdPhJq+65RQI=;
        b=KR/dhM8AibV5YNBggMlc0RsggoS+uXWHwtOcQKypKra5txK9YbPPZA5sbyS1P9FeT2
         wgV10Of5MHyyNW7dqFxwWPdKPz0H82hiaAORaQtSnLs4cmBwuOgNAGSCo9wuyfTwYsCH
         0CNJWWXRzOxPiPJ9qSHlwCokwm6Rn374DmFcJlD9Z7B575w2BVJlZh8PIOFjuR42RXdF
         GP4TYShgsPcAkrLgoPiCgVU3TScaPnZpbdrJglypI3hdexETRbWuJnaiFq3lABARGATk
         WC1VDvKySC2q0N3AzGz/BmjMkQzWnD7/e0TuWsU17b1RKruBRO3bhuKj51prd7tmvftq
         s5Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/T56k53pkoHkF+Moqw2yeBHGKJueO3lkdPhJq+65RQI=;
        b=npZ8bWQqrNXQbzl4WJaS0W3FYXMsCKX7gFJVy98mdFTXPWUA6fvWK4+pi0lA8ZBmBJ
         ikiD6zAGDrNsetFKibWECVGW1PAIRjJtKOSWEDHb/rCZ3AsrRFb+HZ0UaKsSqFwlrKnl
         8O2wwbSDLlNNFZc6TCnjP4InLkPHAr5xf8q4MVjaTzkcII+YSOVmnhEje536I4GMqRKc
         kNX1U8iucolCGpKUaTYxPSy+f2O6yoeNYYsRZTQN35psFWIE12/fSw+4iPlrkhvnwGwp
         xjBT5IRNWXDpYM5fpdGf9ihvBKT8F+39rdZ8VgV5C0IPHxJ9k8glx0d4s7c7vg5u0+ar
         x9Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/T56k53pkoHkF+Moqw2yeBHGKJueO3lkdPhJq+65RQI=;
        b=dH+qMjmcjQ9lj36dh3hBORI6DWEsXh7t5nBw2t3lstQn6rfRQ9SG4adQGbwF5dtlT9
         PKO3WRagXZLjcvQSqK30B64CSifJYAhfrgX9dmtBrBD7BLBgKTA4YGHLyudq8i1NM2XX
         z87muX0+7KKsdZcWgPbJm3lGgH4gDO78qFh4BfKHlS20oTmtHWK3l/CBhZ9Gfyl08Tab
         UaFsRVdsBXZx5eJ0O/7Uf9K09gXsMLFkqZ6odZdLi141y2dbtWv6JZRtvdiWR0Z5hios
         uGQeISWh4mDPIwW0BUQi78m/iMixjvDYOoPGiL95E7C6tNgA5n76N6c4QZWVoDSB8Dr3
         xiwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MoBt4ZPA3pMD2TtKXvfiPkyoGvo59w4/SKfu1X1gdKIyT9XN4
	izvQfsI6Avbkfz8hGNmPmCE=
X-Google-Smtp-Source: ABdhPJzAoJ4ll7U24uX4uVgqnFVIDp7hJ3oobrQ1Wa6j2ZqMxOq8XAFdAswnFUQl6WZc+bn1a4S4Jw==
X-Received: by 2002:a05:6830:4023:: with SMTP id i3mr22414618ots.219.1617020921960;
        Mon, 29 Mar 2021 05:28:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2309:: with SMTP id e9ls3724505oie.5.gmail; Mon, 29 Mar
 2021 05:28:41 -0700 (PDT)
X-Received: by 2002:a54:480b:: with SMTP id j11mr18098423oij.116.1617020921628;
        Mon, 29 Mar 2021 05:28:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617020921; cv=none;
        d=google.com; s=arc-20160816;
        b=Y1d3yfLDy4jgECiC52chtGhhtN9hL56TD1qCySL5Yql5OmscVFxT/1RWOYQHZne4I1
         z9fbgSJvO00AMBkhWvQU6k/M+S0AVaoiTFRsetFHSQeM6tvMyH8DQ5iHYlWRipk0M4SO
         7u2hOaocJHaityZ0+4BDhSToyihlbrbXZGUBJ2dUKnIliSa4qSTjhngZG8dgBnecReTJ
         edeTGBDHDtfR/upNvo1A03touD/sYwA+8UiLzffRXLzIp8XZjpCNYjG2esuelY4fp3VZ
         R17DLTTk2ZzdqpU9lQe1D1TO8iL0Tqg0Qf8kzBoBgpXUiXxXLSMCqu0t2UjQ1P5pWf2J
         OLLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=VAxJpRUaSbNy/FTBdDtD9zoolKw4KbpZyN1PJMWhPng=;
        b=VmboY2EQnIfjrU9vLnbAvNsuOCPv10CR0etiFU+o12xk8vZ2W1AHxdDRntwBw/DCme
         LZLlxLSzLylu71yNWpjw4nApACHp2YsGhaFQMt0kkxw/ZTk3GZbT8y2gmnihPO4cfTET
         EV+BA//VgBxMXL+4FW5Kym4tpjZG+h+//jMlFiwTUQHRm6NTUEV4icOPfmGnqEBrARgA
         o+3TpvM/K0UllHtqMVQM1g6iArBff8ZsHTcZ51w3v5eZrUinBgyDti3aU7XYdFqR3LW4
         hBCkH8fVTCMrYLcqqKrqWxtw7hsyVz4D4D7jwggV/oHw7vl3Tq2UOo9tlIpord9dYA8B
         MT1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i14si884276ots.4.2021.03.29.05.28.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 05:28:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 055C16192F;
	Mon, 29 Mar 2021 12:28:37 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: kasan-dev@googlegroups.com,
	will@kernel.org,
	Lecopzer Chen <lecopzer.chen@mediatek.com>,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Cc: linux@roeck-us.net,
	ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	yj.chiang@mediatek.com,
	gustavoars@kernel.org,
	tyhicks@linux.microsoft.com,
	rppt@kernel.org,
	glider@google.com,
	maz@kernel.org,
	akpm@linux-foundation.org,
	dvyukov@google.com
Subject: Re: [PATCH v4 0/5] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Mon, 29 Mar 2021 13:28:35 +0100
Message-Id: <161702091034.21347.12247252783807550442.b4-ty@arm.com>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Wed, 24 Mar 2021 12:05:17 +0800, Lecopzer Chen wrote:
> Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
> 
> Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> by not to populate the vmalloc area except for kimg address.
> 
> [...]

Applied to arm64 (for-next/kasan-vmalloc), thanks!

[1/5] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
      https://git.kernel.org/arm64/c/9a0732efa774
[2/5] arm64: kasan: abstract _text and _end to KERNEL_START/END
      https://git.kernel.org/arm64/c/7d7b88ff5f8f
[3/5] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
      https://git.kernel.org/arm64/c/71b613fc0c69
[4/5] arm64: kaslr: support randomized module area with KASAN_VMALLOC
      https://git.kernel.org/arm64/c/31d02e7ab008
[5/5] arm64: Kconfig: select KASAN_VMALLOC if KANSAN_GENERIC is enabled
      https://git.kernel.org/arm64/c/acc3042d62cb

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161702091034.21347.12247252783807550442.b4-ty%40arm.com.
