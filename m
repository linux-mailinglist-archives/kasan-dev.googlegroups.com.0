Return-Path: <kasan-dev+bncBCT4XGV33UIBBOMI4KAAMGQEA6ZTMIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C3F0030B2DA
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 23:44:10 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id k7sf13122157ioj.5
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 14:44:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612219449; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kwx0eyDRMw1YpJgY3b8IArU9ZWx1Jg3ulu3FYqMyRmT4BvQxJjAYhq7JVssDZj+5X5
         0EXDFgpbcKxtgFr1q+eR2Q+essDmDo0eOEZvkXtwELZLz2JTSnmZdQc7hpcwsHddE3qk
         5DM1I2JxS8EUJ7mJALI47Asg1Olrf81wzenYe5T0Vvi3dusUXzyDZFFDS+f0F1psGT4b
         ACp7S51Y7CmSol00WDTvmsOfZ7VwYkc5B6/8xpV01W69NoNF/YkvAmPE9jvBjhJmDCxt
         ptabFuPV+NiERV/KtPaWsNopcNMJuxEzPVEtL0WFB8/6YGd41++1Ttaeqku4lT0zhvq3
         0Q9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=QFAOp3ysaDfCCnfx/HP2d3+Cbsw8pBpD4UhfWP0vqp8=;
        b=oX3TWvpS3W2oQorF48/s4Cry+FQWNf8OrgJzjN+5lfavl/21bhixgA+fUlqaPY/bm9
         Si9U1Ur4FVCh06vgYC5nnPFHy6t/qevM4+prdcVnEbwrAdl02RFGdn8KH7pYyPAb20p6
         tLEsR1euot5BDjdaMDcFD0tYtLirteZtx4br+3PeLCUCe1Y79aSqLReD3Nczrw4xTJg/
         ADoetik54ZvbQUL8HcblXhVvHEerWadiSrpY/CJ8f6XUgZJxFictpm9qgH7yNGASoKXh
         WKYuzkrqTe0NeA9AJ3D8PzHXNm/MyuOhrKm6Bb3PrGJbT2EvqnjigtLEwcsiVslvH47X
         3F9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Hhq7UvD4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QFAOp3ysaDfCCnfx/HP2d3+Cbsw8pBpD4UhfWP0vqp8=;
        b=oFwUgAKgjz2vhkCIzK/WZ5JC0Y2kwZaLa6Zkir48B4to98cgLPNQFDHktzf9JsP4kz
         HvwqewVm2kfhjOeCrPsN1w1035lROxHrMGhC2yPA3dl4Losg99jw6nClI0XObzmQ15ZP
         0M5TWBFVXFx1kat3mWFHzfvKx2C8wBSl3Y1bzbzfzpFsupjl6YkxQR09pseeC2CI/N2b
         Dt+wSWs5j7c/tH4zR6Yxic+M3T88Mf3pOkFPAX1LlPRwDhHpxpoZIVzUPN1Wv5DTP33f
         qgQ+wxke47uTe9oYUJPug8fxSW/jljfWSp5fjPg1wUMRqE1pxtlM4orTzMOnxjA3DJwA
         /ygQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QFAOp3ysaDfCCnfx/HP2d3+Cbsw8pBpD4UhfWP0vqp8=;
        b=BKMcw9MJ+5WElUCwmxXOTDGRHxeiE7VD+3YRMpto/doOkc3m/WBmN5kt5yxChQ4gcL
         p4rhWJAxAqqsYuwyYY1eaeQmBxBJKuVBcQTQxKNZ77hXyWla6asHDLHCeaeKe3CLcYdI
         BMJh9upPzhIbcnDt7Z3bg171RdORODU9bqPbmXWXLP+I+oO7A5VjRmwDZ5ron4xWMFD8
         M25U+yhCgh6fQJQj7tBwwrdA9Ykh6OcUnZ1YjbZoxrA3WIMjSo7unnYp73oWQcwpGWXb
         VGo0V5itKzbiyn7zqBPvmb6DQ+stqou2XkIXBhvannyCLfjOIc8Yq1SEvErvAq10DgRh
         AodQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313CxmfSXItsff01W0q/w7AV9Cr6HOCdfXnhYPtDlur3YVcqtrX
	W/EqD2tSrIh3LizdAjMxzrQ=
X-Google-Smtp-Source: ABdhPJw1r8LqyHC0VMSDU8okletiU7mleatQ6cTSH8nfcmAQyT43BLUG8PasrQm8Vw2/xHrBt+S2SA==
X-Received: by 2002:a92:d0d:: with SMTP id 13mr14498361iln.36.1612219449864;
        Mon, 01 Feb 2021 14:44:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:4aa:: with SMTP id e10ls4287625ils.2.gmail; Mon, 01
 Feb 2021 14:44:09 -0800 (PST)
X-Received: by 2002:a05:6e02:1d0b:: with SMTP id i11mr14150974ila.206.1612219449453;
        Mon, 01 Feb 2021 14:44:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612219449; cv=none;
        d=google.com; s=arc-20160816;
        b=YT/uToV08tPXKpfIaFmEtoJK9JpUPJyYPB1hmxngI26csiTqd8RlO4Aelmi5GFogF4
         T582tIU/ZFGv0+iO+zAvSn8W95GMsz9B9ukIfpGkJ8ba1XbsKQ6FqdKaltNbdUe7mPtW
         ESRNvwtWxRZhMuCcIK4IWV/E+pyneYwQ/lUmwQLE+HUi8FSoE7eEOmNAhNVPqBHXGE2s
         riC2ztdeEanJ/enmWLGhLRerPZPdJHdmbwtr1DfBi5mXBEH8NAQAPbGqXa34nXd79hgW
         //nLNOw4AHfm8iljuWa3C4Bxxox5z298N4hx+cNbQrmBjlGMNqphc+DaG7iMGsNoL3jZ
         E49A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=h4Vomtp6OR+9llVMBLlQJzQmvoKj+I5los/zLy9yd5Y=;
        b=uryGJFba+sJtRPRrSFbuVAjeuF+qeX5p6yT0g214v8+bNm8HGnzsquwqY8UA550IdT
         JUuSNqU1IqamXD67fyxY0Z0qlM6S/Rhc65XpErOGdR2kltc/YVv5nFyADqA5kBfw3U38
         2j6G1w3wKE4xLEPlY751Sp4+juASbYJ0+thkBZlvN7LWh3Bkf9i9CmQ3shKZDrSX/dHM
         JuTX3v5g7I7iYDUt6nZmjFqYs9aKhU6Id+WGVgJbqNKVFCIExObOcZmXYhVideSmM40x
         ntfFJrjpkIoNwU404lVNEut2wg0mOshSmbs07is5e0CIdYwTg7LNMnXw7TIuS4xiUNRq
         44ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Hhq7UvD4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d13si728408iow.0.2021.02.01.14.44.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Feb 2021 14:44:09 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2619D64ECC;
	Mon,  1 Feb 2021 22:44:08 +0000 (UTC)
Date: Mon, 1 Feb 2021 14:44:07 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, Alexander
 Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Will Deacon
 <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter
 Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky
 <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH 10/12] arm64: kasan: simplify and inline MTE functions
Message-Id: <20210201144407.dd603ec4edcd589643654057@linux-foundation.org>
In-Reply-To: <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
	<17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Hhq7UvD4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon,  1 Feb 2021 20:43:34 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> This change provides a simpler implementation of mte_get_mem_tag(),
> mte_get_random_tag(), and mte_set_mem_tag_range().
> 
> Simplifications include removing system_supports_mte() checks as these
> functions are onlye called from KASAN runtime that had already checked
> system_supports_mte(). Besides that, size and address alignment checks
> are removed from mte_set_mem_tag_range(), as KASAN now does those.
> 
> This change also moves these functions into the asm/mte-kasan.h header
> and implements mte_set_mem_tag_range() via inline assembly to avoid
> unnecessary functions calls.
> 
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Co-developed-by requires a Signed-off-by: as well.  Vincenzo, please
send us one?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210201144407.dd603ec4edcd589643654057%40linux-foundation.org.
