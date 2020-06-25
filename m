Return-Path: <kasan-dev+bncBC24VNFHTMIBBBNN2P3QKGQEUKCVNEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4352420A364
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jun 2020 18:53:26 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id j79sf4558606qke.5
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jun 2020 09:53:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593104005; cv=pass;
        d=google.com; s=arc-20160816;
        b=R3h9T1G9S7B3YCbcsoKAISCAklJmaGS/WCRpW730F+qTPq3ec4zTreC3HbRypWO56r
         4JOSUcjqJY2K9yAWBLrC9c6xRrkaYnNPNcEa/L0C59br8TUS9wW99I1k+/Ohsms733eK
         YemEVZucR8WqV6C0FlP8AQ/qHs+5lwxGTJl94E15T8JL/w3OOb4MR1qlmVlcPiIvXwuY
         v9RkriOXHL+pa2sNft54lpc4WdtwkChSQNWOqdn63KujEVHXdBjU9Lpdp3ypwVJelv0w
         1VaQEJy+tYHn6VZUC0fbA0LspR5fBXM7Jjv8VB3xRknRiGdASyXojmyc/6OaFEWg30/q
         HRSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=8FbZNWIomsfZshRGBK0Ubia59ho/DtgOubdbWlXw8Ws=;
        b=ncp06Qfef7fMOm+LycH/KwZXkxsa5+jfgO9pDXTO2DU6kLBy4vmrWipkALWz8biga9
         f/RKv/AFAhUvDcsaucuQ6c/97xNGm5jsqlEFW0Hgl+IGlwOaiiCUVeKGIkOHOlQcDTNW
         ZSd51t+mY7GtSuSIFNONoRCdaRVFV87kBnZKLCW7TJnHKRhxV3bgyBHJ6rUZQU92wtIk
         jphIACGiMIbXvTq3kkWsuNctMWVsKb9PWcjPJk2w/7o50hG6p04vsQpvMDF762ANdPrs
         cAgAIEFIIhzt5CJ2HdS7npy8lkQGfP1lIWKPntAEak8DT8FY/Zb2qZWFvBu43sqFqUUr
         Ld1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8FbZNWIomsfZshRGBK0Ubia59ho/DtgOubdbWlXw8Ws=;
        b=ipAuW/T2ZdoNaRfkmkS3419jkBuR4UPgSl6zcDMKY3WwrPPay7vqGPleklsdNn9Aky
         9mQQr6GGnLdQ/XmjRS+eWpkcmtwe5CyxSEWZEVsQ8lg7L19PGtSk7buu0QTO6UoVlwva
         69QaokEj3lC8+6W3YLo7Mk6f+smguyNzUWfsFChfu3lG8M/RFM/zmdi/TaE4zWmkpXn/
         4/dGE2Bkz9ASfmGsrsaUG4shcXGB9nsxuxBGFlNUfN5svhdnsWraupFSU5mOuxrYKPps
         XNj2trG6r4ziF+EWvETRqCcfvpVRep6aPT9Cw7qIx0r8cKseigOtJNRSlCR1wsxavS91
         8sow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8FbZNWIomsfZshRGBK0Ubia59ho/DtgOubdbWlXw8Ws=;
        b=l463OiT2fz9mChndRmycXIjTFWYN5gOX9smUgXL4QAkJL9HWfUrMuqisQgldWTytU8
         NUuMd+fUTlNpI76u57VzPKFWBz6MUBx2Wqo+4zJTCxDjOXtTLbqRI14GNwXXDOWlUm1k
         3LsupzBjz/Mp8HqYUaM4D43HjM65vrtiwbYV51BArZezkEW7eMAZZgBAxnY/LLjsR45G
         N17RolNjbuIV3L9CyGlcm6UhPjvk7SvhcoRHaJvjY0gB9F6/zO49uke/q/evTJf9bnDi
         erdTdpjyplTKmkBIjHYNAzRbef/YaABnxCPe4wx0ySStFzOJR6UuvOwqQAMo3u224bMV
         iOAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TRyXJ0tjaN4nxEKx6ZCyviEuCT96FAq9T6b6ARH+Z/WTioTpC
	PdtzkuNLxBSoTtK8/2cnDDQ=
X-Google-Smtp-Source: ABdhPJwI0TwT9E8x4Po++he0DCI3h1p7Z14ruqncmZZDR7V5UYdxP+h0ByO/6aO40bdw8dT4usa3pQ==
X-Received: by 2002:aed:2577:: with SMTP id w52mr32845783qtc.252.1593104005289;
        Thu, 25 Jun 2020 09:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b5ee:: with SMTP id o46ls153491qvf.8.gmail; Thu, 25 Jun
 2020 09:53:25 -0700 (PDT)
X-Received: by 2002:a0c:8482:: with SMTP id m2mr37805321qva.65.1593104004939;
        Thu, 25 Jun 2020 09:53:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593104004; cv=none;
        d=google.com; s=arc-20160816;
        b=X1cq1fJrMKdF4BuRrKvv4LlQRF6vs4ROech0V+UNg3FbAPDB6xwmosbEZmxNNgLq8b
         CjgqU/Z0AcN03n5r8M169cm3Utz9dWm4Lwg0JWizKKfPk2bZ+u29UwtVgyPJeVG3yYC8
         QCQVg0rW7kwJKYlo6AVVX7j71msTlq1+SLxS203y38xy8lyTCfB4zp+MaEFzqFcwGcZg
         MjI7yU2w43lz8lKWkKBPdfLpZtx9ii4EDyIM+L8gjnXi3T6U4Nsbb/Hi+j8H7GRZd18k
         GFNq3pi1s9Xv2FwNimxUMvrYmevJ4g+ZcMhqLhhVnPgQuzCrFwtjslJLpq1ahwQ67DGG
         qICA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=+0JF3UzgyURfF1Uv3mN7Tl0YV1bEDsd+Cj/fbw3JGNA=;
        b=tUZQBJD5S1I7D2tcZAysI4weEq6TtCKgl3Okb3XLYU5GrmehGI26J63T+mSFxivgMG
         rdl5H+/eOoHyb+NN8ZGTNk/FAPa+Fov4HJFJP+SVIKSxZdbW/pNqGiOPI6P9/p8VZRBy
         m22sxyfaQYi+n5qdKvZSoy+KmRF+wfPpuJ8GOe2544fX0W8/wO/MSEOffnP/2RGXzW2X
         vWVs0MvmO6xbokoPBo2Nfoibf+Be6uhC1w6uCtxWKGndJFl7Tl1P58HwsW8gjkG9Us4E
         mSozwnKvYwN1DCSx4HdVj3TUNb9Czw2ITLVs8aoQNpOzFnmm4gl5YaN/b7cZToBjOfUQ
         P70w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d27si1098309qtw.1.2020.06.25.09.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jun 2020 09:53:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Thu, 25 Jun 2020 16:53:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-hJab1BoIq1@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #16 from Walter Wu (walter-zh.wu@mediatek.com) ---
(In reply to Dmitry Vyukov from comment #15)
> Walter, please pass the stack through the scripts/decode_stacktrace.sh
> script to add line numbers. It would be useful to understand what exactly
> variable causes the report.
> In comments 8 and 9 you posted different stacks, which of these do you see
> and when?
> 
I can reproduce both reports. Please refer below the KASAN report in Comment 8.
The corruption stack variable is "spec", but it should be a false positive,
because it is declared by vsnprintf() and should be valid. I see the call
stack, this report should be triggered by "pr_info("KernelAddressSanitizer
initialized\n");". Unfortunately, it should be first false positive case after
finish KASAN initialization.

format_decode() trigger many KASAN reports during booting. But if I remove the
noinline_for_stack in format_decode(), I will not see any KASAN reports which
trigger by format_decode(), then I only see the report in Comment 9.

==================================================================
[    0.002077] BUG: KASAN: invalid-access in format_decode
(outfolder/../lib/vsprintf.c:2288)
[    0.002098] Read of size 8 at addr 74ff900015447a00 by task swapper/0
[    0.002116] Pointer tag: [74], memory tag: [08]
[    0.002138]
[    0.002167] CPU: 0 PID: 0 Comm: swapper Not tainted
5.6.0-next-20200408-dirty #6
[    0.002187] Hardware name: linux,dummy-virt (DT)
[    0.002203] Call trace:
[    0.002220] dump_backtrace (outfolder/../arch/arm64/kernel/traps.c:87)
[    0.002236] show_stack (outfolder/../arch/arm64/kernel/traps.c:143)
[    0.002253] dump_stack (outfolder/../lib/dump_stack.c:121)
[    0.002269] print_address_description (outfolder/../mm/kasan/report.c:383)
[    0.002286] __kasan_report (outfolder/../mm/kasan/report.c:512)
[    0.002303] kasan_report (outfolder/../mm/kasan/common.c:625)
[    0.002319] check_memory_region (outfolder/../mm/kasan/tags.c:128)
[    0.002336] __hwasan_loadN_noabort (outfolder/../mm/kasan/tags.c:151)
[    0.002353] format_decode (outfolder/../lib/vsprintf.c:2288)
[    0.002369] vsnprintf (outfolder/../lib/vsprintf.c:2530)
[    0.002386] vscnprintf (outfolder/../lib/vsprintf.c:2679)
[    0.002411] vprintk_store (outfolder/../kernel/printk/printk.c:1918)
[    0.002429] vprintk_emit (outfolder/../kernel/printk/printk.c:1977)
[    0.002445] vprintk_default (outfolder/../kernel/printk/printk.c:2023)
[    0.002462] vprintk_func (outfolder/../kernel/printk/printk_safe.c:386)
[    0.002478] printk (outfolder/../kernel/printk/printk.c:2057)
[    0.002494] kasan_init (outfolder/../arch/arm64/mm/kasan_init.c:266)
[    0.002510] setup_arch (outfolder/../arch/arm64/kernel/setup.c:338)
[    0.002526] start_kernel (outfolder/../init/main.c:817)
[    0.002543]
[    0.002558]
[    0.002575] Memory state around the buggy address:
[    0.002593]  ffff900015447800: 00 00 00 ff ff ff ff ff ff ff ff ff ff ff ff
ff
[    0.002611]  ffff900015447900: ff ff ff ff ff 08 ff ff ff ff ff ff ff ff ff
ff
[    0.002628] >ffff900015447a00: 08 ff ff ff ff ff ff ff e4 e4 ff ff ff ff ff
ff
[    0.002645]                    ^
[    0.002663]  ffff900015447b00: ff 14 14 ff ff ff ff ff ff ff ff ff a4 a4 ff
ff
[    0.002680]  ffff900015447c00: ff ff ff ff ff d4 d4 ff ff ff ff ff ff 94 94
d4
[    0.002698]
==================================================================


==================================================================
[    0.000000] BUG: KASAN: invalid-access in start_kernel
(outfolder/../init/main.c:817)
[    0.000000] Read of size 8 at addr 74ff900015447f70 by task swapper/0
[    0.000000] Pointer tag: [74], memory tag: [ff]
[    0.000000]
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
5.6.0-next-20200408-dirty #5
[    0.000000] Hardware name: linux,dummy-virt (DT)
[    0.000000] Call trace:
[    0.000000] dump_backtrace (outfolder/../arch/arm64/kernel/traps.c:87)
[    0.000000] show_stack (outfolder/../arch/arm64/kernel/traps.c:143)
[    0.000000] dump_stack (outfolder/../lib/dump_stack.c:121)
[    0.000000] print_address_description (outfolder/../mm/kasan/report.c:383)
[    0.000000] __kasan_report (outfolder/../mm/kasan/report.c:512)
[    0.000000] kasan_report (outfolder/../mm/kasan/common.c:625)
[    0.000000] kasan_handler (outfolder/../arch/arm64/kernel/traps.c:1019)
[    0.000000] early_brk64 (outfolder/../arch/arm64/kernel/traps.c:1045)
[    0.000000] do_debug_exception (outfolder/../arch/arm64/mm/fault.c:873)
[    0.000000] el1_sync_handler
(outfolder/../arch/arm64/kernel/entry-common.c:98)
[    0.000000] el1_sync (outfolder/../arch/arm64/kernel/entry.S:588)
[    0.000000] start_kernel (outfolder/../init/main.c:817)
[    0.000000]
[    0.000000]
[    0.000000] Memory state around the buggy address:
[    0.000000]  ffff900015447d00: 00 00 00 00 00 00 00 00 00 ff ff ff ff 00 ff
ff
[    0.000000]  ffff900015447e00: 00 00 00 00 00 00 00 00 ff 00 ff 00 00 ff ff
00
[    0.000000] >ffff900015447f00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff
[    0.000000]                                         ^
[    0.000000]  ffff900015448000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff
[    0.000000]  ffff900015448100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff
[    0.000000]
==================================================================

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-hJab1BoIq1%40https.bugzilla.kernel.org/.
