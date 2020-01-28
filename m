Return-Path: <kasan-dev+bncBC24VNFHTMIBBJHCX7YQKGQEVYPTPYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E6E814B0DA
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 09:30:30 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id l15sf8185172pgk.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 00:30:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580200228; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIj50M1DqfUitmu8BnJdxlN5uSYG1Cuco8JkZ3K2sOk5CEK4FAoJKd2leCd7nuyddQ
         tqtqwpA36MuWPh4+M4Hstn0NzC2zuoe4WBLREaRtDqhwaw0XkFEcL5RWhU5ZPQvORD+D
         FjEKAuxx4sFHoStGih6UJcVRfIs1rTgabYw6QiYSOwGuZT3XLrNiG4kKjChYwoWHgWjk
         6El3BL/VF905IERwqAYJEj6K31L2lDbQKm9y+plGrwfZXfEAuXgHTLU7yTtj2X7q+hJR
         QHXArdasEYcKmj/fNTK31Z4DAJwXvrLLA1mfrISMOegrPhX0kY790hCzl0xxq41DD+xL
         qeOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=z3pwbo0z+9jGT7tBDG7SsWJiPuecpSYW1RiflkEQRGc=;
        b=fTVXUF3xaFqwXonwuK7RfzH/gpuCCCIvjlkcksoTkA0fAdce2bVDm+Mu/ZTIut2LZd
         QlPfL4wupxo72pzZ94ZDk2sZsXFRd8vA0B5gZ5AZFhJwXtCNvz9gYCQGVOIkAtqS2+88
         NSCvP/kO9GVyKbYAmiy0pMtKvoXKmYEFx4m0l7yaO5WhYd6gyevBsNFdHP43OshfqWgD
         qzboqAQebFFXW1UXvIFtfoJkEZjGn27tfpiE1uR9zfXnmq+oh8HQzqP/7SPaHDcSdPSD
         OuM1qVP3OM3K1wDNP+AgbFT9TFgDT/PCT0S+hMMLSqGk7NWwwwkCI+QCH6JP1iCEesAd
         tFqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z3pwbo0z+9jGT7tBDG7SsWJiPuecpSYW1RiflkEQRGc=;
        b=M+zij3F6PCnabmHczMU5voOOEOPBYwle+CM526nfnyG5aLTvCUZOGwkLH2JQ/PN7bx
         5rPfnem0pQLZXsw/KvmLbwIWtQoeSbc6g5pm7/zcHwjPCUwQn9kRQT09hdx1zPtGRx5W
         Bldhoor5ZcNblA84v/mbKY+8t6KNGmaIAkpM6L6dHno1u6vIqpej9ULD6jHax17K38Nw
         tCVCruCRXd69mjt3LSf9yAs4e+6SFEhPEnIegmcV2nlMb/fWZNW2DtBzQZkIjFyeEqsP
         gtOiftFAApClVZpY+x9gdUTZ2SvY9f+h/KxKqAeNdG1OMOWEwdFunswdrIxR0O9y3KlM
         HMuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z3pwbo0z+9jGT7tBDG7SsWJiPuecpSYW1RiflkEQRGc=;
        b=L0ps2b7SIsrRhuG9d6RhP25KZ8nSp/DLfJ+zfuyuucHwnT9+KIZNVySLmYfDp3UFHn
         ciL43iK5J6T7gFOGRw5eSrfzLGo58OyZOTxQsJI0qHZpPxpNWrVV10p1LyOTD+KOgJH7
         1o6V1du7zNwE1IsBFT08oLW927WQeuPaHoZRsvtizlKUlh/j15q8qjYMRA6aRuNK3IHr
         UYaldqNKUSaTI9cFpDJLTmW+zbk5y5fj2WswdcuTkGhMrYk/48Lv8QBcAjJGaQTGdRp8
         QrPgLo8UykmzGYKedeqiz6hQqhLjLxH7aNcFWHlhv3KH+Cjpr+MJIfTUf5kGSx5LKy7J
         rmhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWzyo+14NE/Fd95ut/8JBcYCC8kTXqXYiKf8Z0n0e/Sogocylqa
	jhKll9bt5aKaqXp/drpJEQ4=
X-Google-Smtp-Source: APXvYqwblwucYI4wJBrYxk5cZhzAbLvSldFL6LGbIM2CbHqkADOqGivblmf5IeSdfkJwCjeqw2AOzw==
X-Received: by 2002:a17:90a:dc86:: with SMTP id j6mr3431310pjv.33.1580200228589;
        Tue, 28 Jan 2020 00:30:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad06:: with SMTP id r6ls1040925pjq.3.canary-gmail;
 Tue, 28 Jan 2020 00:30:28 -0800 (PST)
X-Received: by 2002:a17:902:9f83:: with SMTP id g3mr18452660plq.101.1580200228184;
        Tue, 28 Jan 2020 00:30:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580200228; cv=none;
        d=google.com; s=arc-20160816;
        b=NPcUCuqHVqrqA8WQJAQ3aep0z7ywMFU/DgklSvGQOjbeWKDq0ULDEQanvgQJtWOLvG
         H1sYzG02XVVeV/BRCHb1JSZh/1ZkeD9TQ+c84uc7iwOSoX5m9SBV4iFWw8RQKpZhIXJy
         OMSQ5+zFUm8aWkL0TVW/nIsbv/tltAu7q5ER3hlpciqLudz2wXdDDzZizL8fPq94SJEn
         S/M13akXnZ/wkNfT7SvC3F5hDyC04nu43PJUUz6l8aZFqIFEv3KF9vLTPg2yC19t+0WN
         MMzC4EiN3Xn3+Tv66kZhllgmJmmVuBCH9HSkGn5sUSlU/+0z95MmHfWdabR2oMV50p0B
         /Upg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=RWFpbIDaBiJcGEjT9bjWDRS/oiucOibq8FIKA6A1xy0=;
        b=KAjxoc2QqPGO9YZ1uKNweW4MkgrzmG/vPs9fAlgmWyWOeMemBNJA/bAl0wQmLBQusC
         vIBE7rfeo4hJPcbW4ivV6j1ozyy/Q6oMlaRIMGOM2kXW3Q+zILVoSwHIN8b9Lv6faspV
         DzE7Vr2+OOokSAxvf61OS7297PRToB4NMyxqFW3LH5OSQqu2K3htSDCpGUv994U2tLxm
         DL17eGE4G2eDIzg0iAjMh4IxTFrftLtGSAzwh72Bo6BxyNcXZx+wv1JgZ7yu7znDbzCf
         x1ylGx8rhY7Od1JR81Ctm+7tRheijFhKYT7Wt4HwpyFh82c71QHGBfZxe3ISwBogxESU
         IEjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i131si578852pfe.3.2020.01.28.00.30.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 00:30:28 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206337] KASAN: str* functions are not instrumented with
 CONFIG_AMD_MEM_ENCRYPT
Date: Tue, 28 Jan 2020 08:30:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206337-199747-EbQE38SztX@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206337-199747@https.bugzilla.kernel.org/>
References: <bug-206337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206337

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
On Tue, Jan 28, 2020 at 9:25 AM <bugzilla-daemon@bugzilla.kernel.org> wrote:
>
> https://bugzilla.kernel.org/show_bug.cgi?id=206337
>
>             Bug ID: 206337
>            Summary: KASAN: str* functions are not instrumented with
>                     CONFIG_AMD_MEM_ENCRYPT
>            Product: Memory Management
>            Version: 2.5
>     Kernel Version: 5.1+
>           Hardware: All
>                 OS: Linux
>               Tree: Mainline
>             Status: NEW
>           Severity: normal
>           Priority: P1
>          Component: Sanitizers
>           Assignee: mm_sanitizers@kernel-bugs.kernel.org
>           Reporter: dvyukov@google.com
>                 CC: kasan-dev@googlegroups.com
>         Regression: No
>
> The following commit adds the following change:
>
> commit b51ce3744f115850166f3d6c292b9c8cb849ad4f
> Author: Gary Hook <Gary.Hook@amd.com>
> Date:   Mon Apr 29 22:22:58 2019 +0000
>
>     x86/mm/mem_encrypt: Disable all instrumentation for early SME setup
>
>
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -17,6 +17,17 @@ KCOV_INSTRUMENT_list_debug.o := n
> +# Early boot use of cmdline, don't instrument it
> +ifdef CONFIG_AMD_MEM_ENCRYPT
> +KASAN_SANITIZE_string.o := n
> +endif
>
>
> This is way too coarse-gained instrumentation suppression for an early-boot
> problem. str* functions are widely used throughout kernel during it's whole
> lifetime. They should not be disabled because of a single boot-time problem.
>
> We probably need to do something similar to what we do for mem* functions:
>
> // arch/x86/include/asm/string_64.h
> #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> /*
>  * For files that not instrumented (e.g. mm/slub.c) we
>  * should use not instrumented version of mem* functions.
>  */
> #undef memcpy
> #define memcpy(dst, src, len) __memcpy(dst, src, len)
>
> Then disabling instrumentation in the single problematic file should help for
> direct calls (I don't know if that was a direct call, though).
> Or do something else instead.

+Gary, I can't find you in bugzilla, so CCing here, but please comment
on the bug report.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206337-199747-EbQE38SztX%40https.bugzilla.kernel.org/.
