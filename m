Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3FD3OBQMGQEAQESHPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 103A835F268
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:45 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id o22-20020a1ca5160000b0290126af94672asf1974328wme.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399724; cv=pass;
        d=google.com; s=arc-20160816;
        b=tjTZ4I6hxaPbxB7K3xYTujkDsxpb8V6o+bsF0mh19DmjwMEtSBcwT0cyO1R//oEj6j
         GTzln+NflfBR0uj1pQwqWqmB902IqCfGLjvicbLxPi7t7735v7Gjjhwsf+rNNDA/LWAk
         EoGh5Am4XC06+NCyOms3ffh2XJIhHnvU/4C865WRdnSnEjlF3KkzS6X0hhL92FJHZ00+
         spfXX2z0tjE5AMrNebRweTwPBVR65Fdz4FlcdRkU5U1oHeRROBUVtZhttEsr2QgULqlr
         KqOwf3xvpFGtyxxPxPIWfnuxvKMRTbQwuYweZun/bgGQoB2ZXRjoW+o/Z6sL/d3+uUrZ
         4GMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=8dXDJS9U49VCONx2oNrmDFOfgAq14buTzSAJCAW2TXE=;
        b=c716htHCHJ69fgywl848Gtz8XTIytdi6IqHjSGn9yrpilSowTbrWNgRLBPW6luaWe4
         AKtfDEL7wBddvy+KW1/Zhf4TNhWzce/z713bzzTzQZs7f5ly2235rwbwtcYp1o1B2yz3
         /RWYI1QIvCvtpKxu340j38Ncvpl8XcqZ9R53OlSLk75G09L+PCgySEwNDpUSQrxpsD02
         60x5r8z6jSnLsWlpqHt7XKI0zgikKG9g5ZvT4lUR7CnjCia4ZJtsot8JmMN96GhWFI6E
         HoMpVPHiQzLuO6OkDfrRFXkVuquuTycjB5tDBGMoSknMElXraDVA9pRmMtq8ebi43xUw
         o3cQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rmfzsKjs;
       spf=pass (google.com: domain of 369f2yaukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=369F2YAUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8dXDJS9U49VCONx2oNrmDFOfgAq14buTzSAJCAW2TXE=;
        b=o3fHmH4CRm8lSAwoI8Bdixehn6TF0i9e0v1Y1LJWJIZx849JB6w+0WI+T7RdPi0ndZ
         DZpp5QQzoMSzJpF5xggAQY/uEvhEBBsyOtUbX2ExYgsduL0S7fAuVzLkGKWNLO2c/nD8
         7XynRQ71p4MAmbgxJubOOiCH8MJgVzi5B3pRrk3LgqDaTC9Ceke9Kk8Vu2Db5TePNy+Z
         rDWO936kCLns+0zLir9lZZlvCm27LCQF15/UBXu5irljzU6dklzcD4Qm3A3kBfAr4HSq
         jyDQsgEjYKeD4sdK1tKJK5uL2yggNnQRtqxYkCmFTat6AAjHPMbFGWNuG0PzcozKKr/A
         n0xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8dXDJS9U49VCONx2oNrmDFOfgAq14buTzSAJCAW2TXE=;
        b=IOTJhnB9p5uLiN7B9yXaBuM7dUUzQPfzjcEHFrYMBszzWpGf3T5hJWRrMYd1Jia/2Y
         MMIp3dNN1853gCtLCE30oe+9eGKKIRWTdf3xZgQ9LtoHWmS+8q0btYVMc2fpm3QjZLmN
         gKPJq4MK5VrWdtx858OhG8kzPFW6XmDl+AqrJZRJplhNhr18/pbSAcM3wppJ5gKPCCl+
         lEOeRyl6oIlKbljZHn47uClA5t0+v6DeH892xAi/pPCWfOMf1XsugGvoFZAhxUkB63am
         oGfBrAan/O4BFmGjk8kt2ja7Lco8x+E9LsM6ZCd3WRfJTP/2cACwJymdB8IDxF0eTKPy
         LfYw==
X-Gm-Message-State: AOAM531N/i8vca6nBoIpX7or+G280HkfazSaB3y/6T1N0eMZKkuLnm8J
	jpXAgDzgGJuo+XRxxhCTMfw=
X-Google-Smtp-Source: ABdhPJywcLHH+Bgy3CmGI1sM910PT8Xcjx+Ur2P0l1RT4G4n6fdwI5Sf+sf5fHsZxRuTyhMatv1N5g==
X-Received: by 2002:adf:f750:: with SMTP id z16mr18828100wrp.340.1618399724859;
        Wed, 14 Apr 2021 04:28:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:285:: with SMTP id 5ls975963wmk.3.gmail; Wed, 14
 Apr 2021 04:28:43 -0700 (PDT)
X-Received: by 2002:a05:600c:3796:: with SMTP id o22mr2521698wmr.139.1618399723745;
        Wed, 14 Apr 2021 04:28:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399723; cv=none;
        d=google.com; s=arc-20160816;
        b=KdGHwtRwsudva/zHUNNgHHkwHF2Gpe2RE5Gxz+gayQLAILhAsio1KsHM91exB8NNaG
         JqhPfd/ARTTTXqdwz2sT+b07KjyApd9p6XHk0Qvyaxt4qTlnJlHywDFndj4WXRC13CS8
         rwV/1UmZ7405mRH5RUDrgxrvuXBd1aI3c7YkJbmqCPybGPJZ5npov5IBxsni4lrC+z6c
         n9g4p7Vx6ieQG9Uu5xJB42HjQgEdniZYjJsD65YRz9tL8IH4/MJyj9lYJWErKTkJd4Bd
         jhfEmdGh+JZ1qHyTya4xlj9lok1g0BxEAJVzU+Nolj+2n+FjaI9IrBJLFW6QfCNGsqjg
         5KDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=btwVZVIkoVW0S9+I18X0VVI6S1SmB7cJxLrTXtQjEgc=;
        b=FH1r0grzqP56u/nK/ccS4CKZbLnEdjcx4AkpyAKInUf5H19oy68ptiIz4XpUrUSlgt
         N3D6gYCCold8ETVMb25jp4gow9puOxZvNEiVMOoG+1XphlMpSWV6E14OMmi1UKR693J4
         z/SXDEmXO50DPpgYmp+xLpZ3FKf9n98hZaQpnDH59fweQkXwraJS1X8K8NIGjUZLLfsV
         BeLrLp0SRlrhy+CTpdw4W7qZeKm+ct2K34yV+qY+V9l19QlHSMH+Xkd9b8YcfkGdCqtN
         15k1AF/T1QWgxQG1SLnBQEaZZXP7+DYmo1gghIGcuJCluMZ2+tSQnQPGLixio479FC3u
         WP+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rmfzsKjs;
       spf=pass (google.com: domain of 369f2yaukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=369F2YAUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p189si214270wmp.1.2021.04.14.04.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 369f2yaukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id i3-20020adffc030000b02900ffd75bf10aso936849wrr.14
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:43 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a05:600c:3641:: with SMTP id
 y1mr2603071wmq.65.1618399723368; Wed, 14 Apr 2021 04:28:43 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:16 +0200
Message-Id: <20210414112825.3008667-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 0/9] kcsan: Add support for reporting observed value changes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rmfzsKjs;       spf=pass
 (google.com: domain of 369f2yaukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=369F2YAUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This series adds support for showing observed value changes in reports.
Several clean up and refactors of KCSAN reporting code are done as a
pre-requisite. An example of the new KCSAN reports:

	==================================================================
	BUG: KCSAN: data-race in test_kernel_read / test_kernel_write

	write to 0xffffffffc009a628 of 8 bytes by task 487 on cpu 0:
	 test_kernel_write+0x1d/0x30
	 access_thread+0x89/0xd0
	 kthread+0x23e/0x260
	 ret_from_fork+0x22/0x30

	read to 0xffffffffc009a628 of 8 bytes by task 488 on cpu 6:
	 test_kernel_read+0x10/0x20
	 access_thread+0x89/0xd0
	 kthread+0x23e/0x260
	 ret_from_fork+0x22/0x30

	value changed: 0x00000000000009a6 -> 0x00000000000009b2

	Reported by Kernel Concurrency Sanitizer on:
	CPU: 6 PID: 488 Comm: access_thread Not tainted 5.12.0-rc2+ #1
	Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
	==================================================================

On one hand this will help better understand "race of unknown origin"
(one stack trace only) reports, but also provides more information to
better understand normal data race reports like above where KCSAN also
detected a value change.

Changelog
---------

This series was originally prepared courtesy of Mark Rutland in
September 2020. Because KCSAN had a few minor changes since the original
draft of the series, it required a rebase and re-test. To not be
forgotten and get these changes in sooner than later, Mark kindly agreed
to me adopting the series and doing the rebase, a few minor tweaks, and
finally re-test.

Marco Elver (1):
  kcsan: Document "value changed" line

Mark Rutland (8):
  kcsan: Simplify value change detection
  kcsan: Distinguish kcsan_report() calls
  kcsan: Refactor passing watchpoint/other_info
  kcsan: Fold panic() call into print_report()
  kcsan: Refactor access_info initialization
  kcsan: Remove reporting indirection
  kcsan: Remove kcsan_report_type
  kcsan: Report observed value changes

 Documentation/dev-tools/kcsan.rst |  88 +++++++---------
 kernel/kcsan/core.c               |  53 ++++------
 kernel/kcsan/kcsan.h              |  39 ++++---
 kernel/kcsan/report.c             | 169 ++++++++++++++++--------------
 4 files changed, 162 insertions(+), 187 deletions(-)

-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-1-elver%40google.com.
