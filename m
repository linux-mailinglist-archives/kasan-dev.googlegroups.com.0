Return-Path: <kasan-dev+bncBC24VNFHTMIBBOPBUH4AKGQEKMEZVYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CD49E21B6CB
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 15:44:26 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 73sf3205432oti.21
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 06:44:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594388665; cv=pass;
        d=google.com; s=arc-20160816;
        b=BHC+LIq73cxCncSMMF1q/E24i56Y7ihiKB6m8s3X2gAanANfGhHw1Le62QMjw4ODKx
         WtW34kKjxVYEcVqJlZb+xPCme0kED1QAelYu27IW+VHaDa+LKAm+BGblvn9eR3jJY3kl
         GCMsEhsVre4gMobo67uA4Fx1RXLzhiU8ZQkNsnYxeQR30Ai5dJt4nl5HrxxN1wQP10sW
         6r8l7OGt4S3LjAxr6GY1DY4Sh9A7OR3TwAl+gqZtkITtCfJuYZU5ZCzVTlEgsrJ22JGU
         knd3I7iEGec3nDSZxExsujpdl4qg10CXlcoeL+dpI0F8Qhd6sjl2DeRLoKOWZfeVVBdK
         VjsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=KOjzJgL15szZWQrkw4M4wi/Ja1KnFGHgx5Asn2TFcRA=;
        b=He2hZuEvTd7zD/tMgBkJWZ5Pdgh4YLHy7dyy4CBeYdiA3iSzxK7UGMQsmKqdwvB7MK
         NszadNXLk1bSaRXnEBcZrMPU5mraDrjz2sxOWmN9gB7vc2ON5oOiqbmda4AYaUA3oLQv
         1oWk04TPMB0FhCqbE5ktHmWh0Bj+PVhVV6BPgrUxJk/ri7Lpjg/Nd2+Kevbr7zwexDgw
         lB5nRS4vfBHcBOG1kxFLl0QDoMCVJyduEWoYDzDeu7KbuJVOxyXwjF5cGc9Ome6sNaRL
         eWeNat7iM8L2y0lDI0MZIiYsNF9smlxK0MA4PENo4iy4YH09xAQT87S4exVqDxlJj0bK
         g8aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=q2NW=AV=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KOjzJgL15szZWQrkw4M4wi/Ja1KnFGHgx5Asn2TFcRA=;
        b=BROsKOvPA8GZOkMH+e4g9Cu4hkvi62vxd5t6uBNJ/mA5uGVFtCd+5imJGcubzMMPtM
         xRBLloXK1dAOpKPW/oWvTeZmmfznRrjV5IDaZku/UtmCYpMBbPxhKW/HA6fzZQvfW9QF
         sfzmaclOHoDZ5Ye4oDrzJ14VqTXzIyP6TumRSetWAwwaVd38G4y5k7nu1x0Dqtc7K+Wt
         AYOa5BIdVOi4D1iRSo9D4wKkq5wz/Sp/l/as/fBPp+uQkL3S252loSbbhW8IRnawiL5/
         HCLoyB1dj0ojOgKVKevN7tV8/PyAFLcrLKAC1nMxn9ws8tq5Ra2XY1iv9u74ookr6KZp
         0mIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KOjzJgL15szZWQrkw4M4wi/Ja1KnFGHgx5Asn2TFcRA=;
        b=A7xdxeUbPAbFZi5wgKiYXHKziXJw6qjRdQuqLPYc/3NidKJcpcInknSCPPaqgwXPI4
         ee4rvtmIA2t6vowN871P7lxjCPLXqsd+3kBNVhgv8jzBq/C3CjBdWzBm9jyEjsXNc4iV
         QpbVZYhCbaUSAU8DOe/QPIZwZiFr22e4/B1Ggkb1yA8DwN+9/T1vduxiw1v+IjFQq4hz
         9nP2dgM9x/TjyaHaOxkxg6qIYJvm77eIljn56UXop/4SzplAR4/zM7ug9awDPgivQrvG
         a0og/cz12KrDEYUcIA4EcbNAG5TzwZWg6YTOw//ijb+FVUfcl9h29H0HEskDlB5/0LWc
         +Thg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VxQjdpwVsxuj4Km7/mQf5CtOSL/Osu+LHgY69iOUj3aDaxx0p
	seyqsTocsv7LkUXSjeMvQMU=
X-Google-Smtp-Source: ABdhPJzJ7c9PuQFadv4hrWCeAiRpgg7w4pye+Ke6WjNk6+j535tSGVqpsCLTgdpT+PyQNuwOlKz3nQ==
X-Received: by 2002:a4a:3105:: with SMTP id k5mr59208570ooa.6.1594388665797;
        Fri, 10 Jul 2020 06:44:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1599:: with SMTP id i25ls1991233otr.3.gmail; Fri,
 10 Jul 2020 06:44:25 -0700 (PDT)
X-Received: by 2002:a05:6830:3104:: with SMTP id b4mr59117560ots.192.1594388665520;
        Fri, 10 Jul 2020 06:44:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594388665; cv=none;
        d=google.com; s=arc-20160816;
        b=PCUwSp9QJXfGFYtfV1S/2Mu4E3V2pSaKBPi64VsEGFxZpiNof0BkkTOoIkvBVvt2P9
         57Uegu1PZHmBf6/NJ/OIhxDobZ38BRkAg9DDUIUzKlSPlL6A3e/aGISW6D+88XpiAQ20
         0Qhd7vN9k+PuniVNXQmTw6wqp69cmOevuQP3hfQ/uqfClNErd5xYqXAWxMz1opg/PDn+
         1rtaX+rLnYOWBGSSypfsKNeMz8NSLNUbOJHhGq2f3G4vmbg+/E7pp7AlhhTQfE0KE8W/
         Q/0wEOvX4baA89LZMGZDZuKW91zmw+d+dUZA0okWxvFwH+3jHyOrTL+fXFFTwVqB8CKm
         U9jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=YRBsmrKe3M5f72pkV2wVWqi8fgsIPA06jICSbRNChpg=;
        b=i8lXL0wmXURxzigfnOUbKfIsfLwB6uSg46vYi0tMa9N21NNKf6CbvAtHMeGSfnYeZ8
         m2D35RUwh8aCUSQjXeeZ5IWpb5YF09XLujZXmeFNU41q0cB8CAQNj/tCJSuDEg8HIE4I
         cITvmRZjqcMo3jE4XVDEFj4J0pscgvdjiopUBoPtb7nYNTNB0ZcW9obFWjcd3czUOVLM
         T6hEZJzkiHgJOAgbJlQz/GG479sZGEhYtujmZ9ES6m3aOwCqyb2uo4JrIZqlhshfncGC
         7F+kfxOhH/+g+3hTQIsjhR0RxNi/DPgJ0QctSkcAPEHG4/z6OZwIMUUZX9ozAIWiUhnM
         xTGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=q2NW=AV=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n6si203909oor.1.2020.07.10.06.44.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jul 2020 06:44:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Fri, 10 Jul 2020 13:44:24 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-203497-199747-tTFelpoF1Y@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=q2NW=AV=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KASAN (tags): support stack |KASAN (sw-tags): support
                   |instrumentation             |stack instrumentation

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-tTFelpoF1Y%40https.bugzilla.kernel.org/.
