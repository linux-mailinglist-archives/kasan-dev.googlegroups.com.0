Return-Path: <kasan-dev+bncBAABBVF5YSZAMGQENL5B2BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 788538CEC9B
	for <lists+kasan-dev@lfdr.de>; Sat, 25 May 2024 01:12:22 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2bf5bbab693sf1334554a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 16:12:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716592341; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2u9Cqr/sUY3Zosonn2H+H/jb1rRU86lxgw0CP9xn/+RMW8O0RisMXQGWnZ9MuhhQT
         XyjnsO5N8cD2d11bKFmVa0uqibARj7FoVhqA6Zv8yWje/lnnMRUiHKD1dOhllqoYVlGz
         DyZk1GJ1gcNSCx+x/kstt1aHHxlW5LErlLS4PbJLTAs2Swmv9y+xenXFT+gxIOdMNPIn
         tG0Nk7nV9dR29u+UHhhUrdrvfAFSI9603bMdWsa6rV9Kwvta2PC3Cl+Sw67TFkKn0jb2
         suCQ+umDJ8AMxaTpEu0sLptkT4yrdIxBCTZrXqwF5SBdn/5vL0od2i4dRtiEn7U+nhqV
         c8TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=pDavtu5Bz08OajVKXqUoYkK7+Y2ZSXv6xqMZKKn+C9I=;
        fh=higNzQJ8RkkGaAF6SU3QirNQOLnL9vMhFLGFf0GVVKA=;
        b=Wvw1XI4PYa5Op8fHndj2PUdZy5XAGX5tq/MiXj6rEBGJ03sMAjqonEov9nVuXHvJsN
         kUAUEng2hB7ELCnqFIdSiKGzeU1kFMMmaZs8D/V04KYk80pCzPYBmCB21ELYAWQowDSx
         i8IE4pSHpHznAy8yKz3gTxHE7ItXnLHtSvh2E6lve+Vw3B6w15iMjICIftAlkcinhcAN
         qqg/BYDHG1q34JBfsdbB0M8ghZdBP2K+CW7xk6jX9w35v1O/qSdChVYrMMhs2Qeyqb4u
         sxZslnQGJqZ/zPtYQH8nxpxiayY4pTzyLxIAbrXpgENVnkTaEO3RCUUrmrzV+4bg4lRN
         zW/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EPb+PYle;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716592340; x=1717197140; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pDavtu5Bz08OajVKXqUoYkK7+Y2ZSXv6xqMZKKn+C9I=;
        b=f4N4L/VALkTR/M69yfOHa5vc+jgHm5CALz/n1+s8jlr8g6ZWyUrL7f5DUaQcwcEKH6
         J+/VxXQ4DYtRUbXOp/T5nGy3xo4hlqK/lhGnlTl/eRhtt+w/hhdhs+fG9cmzBUh42djH
         lY65N3RPNFGbzMuarwVz7uf4iOpH67/kd8S1XKaW+pjGb3LH+DcAjDgu5cvG9qRsnQC7
         mR5cbv/SFjO7AXWmcmpO+rZutlCppFxLsq1O/M8z+EuO4RPJ7M0SQQ4dLIwUH80jXn9f
         LajqbG4WkglJ/dEgoHrFm/mDbWo/F+LY2SHBqmSCm3LaH65sH17NEMaLcMkwNsvAyLyp
         Ju/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716592341; x=1717197141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pDavtu5Bz08OajVKXqUoYkK7+Y2ZSXv6xqMZKKn+C9I=;
        b=TQSlmCMWiwv9O84UFc8NwX7EzM+Bumybrhw/q5XMXz0avyqpShszw/IM42mSlesOzA
         GSSu8zDDmUpjhylfeGlXt4cFRsZHzGdwe9iUgxsLOk0pPLZLKHWTt/o47N8yvZXHUgIU
         oF3BPtQujQOxxb1l1Mb1CEPGFjN1gD7J2WAzBfxe5fmAzt+Zo9wqkA4DIxojw6S2fATP
         zDzzIC4WvhgoVAFpiTPUbkRNPAy/t282X+SR7dDC9uIya3E6MJw/t/lb/VcUBzR69/wV
         DHjHgk1ZEgxambrGU86kgAkP3omzA81I7WEbG9B5ATPDhq+Gm7kA4S7awckuqkgBW7lS
         AZAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfyO+NCc+KfhvsnLpB2mPoP8x4m8q0mohq+4gQ4Ywh/VdM9Xt1+TejajwRPl5tUGlPuy5w4V0kEODuRdZVlsxwZFUTC4lxrw==
X-Gm-Message-State: AOJu0Yz6ziTVRzqR5QHfLhDLaLCO3q5/31e70h4rsHuEX88XpUo3/Nx5
	o3hsnmtl6feZyb3rU1chFNUErWgvPdSsDjl6vPxe62kboakZK3CD
X-Google-Smtp-Source: AGHT+IFem9ZJKf8kldk/Q0mttAUelSYHazOelji9/OurE4BY6cF5gKEHW75aE50oDkiJ+iL0rODakQ==
X-Received: by 2002:a17:90a:8a15:b0:2bb:a88:8efd with SMTP id 98e67ed59e1d1-2bf5e185872mr3415144a91.12.1716592340365;
        Fri, 24 May 2024 16:12:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e2d4:b0:2bd:e914:8fe1 with SMTP id
 98e67ed59e1d1-2bf58e688abls503246a91.0.-pod-prod-04-us; Fri, 24 May 2024
 16:12:19 -0700 (PDT)
X-Received: by 2002:a17:90a:f0c9:b0:2bd:fa34:a616 with SMTP id 98e67ed59e1d1-2bf5e569a3emr3318006a91.27.1716592339242;
        Fri, 24 May 2024 16:12:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716592339; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/P1UwdA/polK0SbBS4RlIjE9dO3a2RZq6W/N8bdw+eRxsZSRXPCOmXTteBaLvn0eu
         aEJkCjz7B7kYMjDpymd4gM0lsFlQqT44WnDQ2+pw+CmeOR3F1fJnUlQoaRopdnSo3WQs
         zKVRkINaCMp87PRD3sZhotnaH299xIwzpL17SrmV7dwRm9njeLS2cLKvlRSfjEUd3rFD
         gtDEUP2XQ4tsSpmpYVpeucKLUgha3A/gqX7DH1yzGy2egWJdDbXnFuQV0ZFEswnHXZD2
         Qtvlhlpdp9kxxs6x5dxiStZzsO+PcKDgZF+MB+V1PFYCOvDaeHEwOQFrnPMiQMZmoPUr
         2jCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=9Otwrpy/yrWnU1I9V3pm0UePgcsJKAjg9/ZnzP/So/E=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=03WTiefaQeNGQwM4ZL6lKYvDed9/dbG+w21QWt7ZqFqJq6HsIBdOL7RzXubQIQqbKs
         a8ZdgJngQH5IjeXClfr1AmVJvFUQ8SXCFYpWdUmK8OpnHc5msHAjfZt+GCMGlAREZAMQ
         ZgIChiRHyDenRr77MI9bALmnYzsKxTI+UQ2I/ySJSOpOwGoVX+IykasAAstQtatdlrJm
         fE5HsfPrArJiKI60wXe3pvKGeJYBNLPKR1URRx7Owtbwn/koEmCHtDrf6hCzWYjjORfi
         GHllWFlp1a4B2YE1O7e8LtC7BVfa/tYPGc8L4UkcXP70F3DtQd3c9gMtm74J0LTwUgmE
         SGog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EPb+PYle;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2bf5e13b34fsi129569a91.0.2024.05.24.16.12.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 May 2024 16:12:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A025362B63
	for <kasan-dev@googlegroups.com>; Fri, 24 May 2024 23:12:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 55DEDC2BD11
	for <kasan-dev@googlegroups.com>; Fri, 24 May 2024 23:12:18 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 45C52C53BA7; Fri, 24 May 2024 23:12:18 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218887] New: RISCV kernel build fails with
 CONFIG_KASAN_INLINE=y
Date: Fri, 24 May 2024 23:12:17 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: jason@montleon.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression attachments.created
Message-ID: <bug-218887-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EPb+PYle;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218887

            Bug ID: 218887
           Summary: RISCV kernel build fails with CONFIG_KASAN_INLINE=y
           Product: Memory Management
           Version: 2.5
          Hardware: RISC-V
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: jason@montleon.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 306341
  --> https://bugzilla.kernel.org/attachment.cgi?id=306341&action=edit
config that fails to build

Building a kernel for riscv64 with CONFIG_KASAN_INLINE=y set fails when
tools/bpf/resolve_btfids/resolve_btfids is run with with the error message:
```
FAILED elf_update(WRITE): no error
make[2]: *** [scripts/Makefile.vmlinux:37: vmlinux] Error 255
make[2]: *** Deleting file 'vmlinux'
make[1]: ***
[/home/jason/rpmbuild/BUILD/kernel-6.8.10/linux-6.8.10-300.1.riscv64.fc40.riscv64/Makefile:1174:
vmlinux] Error 2
make: *** [Makefile:252: __sub-make] Error 2
```

The attached config is the kernel-riscv64-debug-fedora.config from the Fedora
40 riscv kernel package available at
http://riscv.rocks/koji/buildinfo?buildID=305900

Initially, I was trying to build a fedora debug kernel package, but I have also
tried this with vanilla 6.8.10, 6.9.1, and 2024-05-21 linux-next with the same
result running
`make -j4 vmlinuz.efi` using this config with the same result.

If I switch from CONFIG_KASAN_INLINE=y to CONFIG_KASAN_OUTLINE=y the build
succeeds.

I am building on Fedora 40 on a VisionFive 2, gcc 14.1.1-1, binutils 2.42.

Please let me know if there is other information I can gather.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218887-199747%40https.bugzilla.kernel.org/.
