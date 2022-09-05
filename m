Return-Path: <kasan-dev+bncBAABBTVZ3GMAMGQEHAVZXNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 298455ADA33
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 22:32:15 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id h133-20020a1c218b000000b003a5fa79008bsf7874226wmh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 13:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662409934; cv=pass;
        d=google.com; s=arc-20160816;
        b=rCoEGnfwJwlI6UvviOOIEfJV1Txb01MxdpGGX8wz8Gdg0fGIctkgGaBa/E0uGLpOsO
         1X8WezNprJeFWVYLO//BKZAh4bbJDhlQCkXfXT4GCCKY9neHT2AjxG5lZTlf5kOKTZqT
         kh4ybRvPkayBQUizqgXMU7FoE75mimMIrF9Q7J2HuwtFTthUrBBc0kgtHDP5l/SVohxR
         qzvfMDkmfNsN8j9oVnvaH8evNq7R11BmimIu5vyx3H/4brwCQYC6W1D/VPUNltJElF3o
         XcSQdbgVv0RRORD2JBNqPZnP1B6iZhoqz1fAtleMgbN/WlL5t6uztEO0nwHrJcinD9h0
         TJ1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=sBxd6NBuj/5yNdSnhrHh4pNvwaiXG51e1FmyW++3toE=;
        b=HZ9QQsNHwEOzvhaxxta9Uu6qht0OEJ9Q3JCpWKyYOKfMK2+K8YmpXnm9IogbzB7D+n
         vtxvSOmBlBkvwVZGWZVLWMkjs+Dl6HKeD1fQQW0FSlA9fSsYXp8wts2xYLdxT0bpJTku
         FrBQt/iCAGPZXZyhfzB6M1Wc+d78DsL+aDrXBBmUfORUlpQHb6WR+KYPm642sek7EgEZ
         6+/xjGDXRvU755G5A58mcgw/Tr6wT6D2y73UXrKPqivWRDGfDsnXQZpBFC0YaffiCf3P
         LyScIuTitZy66BS7qaRYRYGMB1l/y2Nmd7TmxUHDDRGYksZPegrC7PXANiP1XCxtHthL
         pAGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KTKM2O0D;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date;
        bh=sBxd6NBuj/5yNdSnhrHh4pNvwaiXG51e1FmyW++3toE=;
        b=de/PQetV5J4Hz2ywObLWDTO44RB/k233TBTA0Ciq81DWGP3y+H1Ynu+l9Km8lUxnKo
         wjhK18LfHdeGVJGeFVHk/6QtV0YHxC2jfp0RgGBZYiHwq4FZV01BJQ9rFTxJfgzck4vP
         0P4VLrFRRMxM1UC5kMpt2cZ4i/iz7Os6/xXF0eYBKXJhQFc/xZ9cy9+idJfR+vYUnySK
         TG4UJUXZOYQWHc/3PjeyoUlGNxZba1M5UC07zrq1eGyFRV5x16UxdbUdM10EssN/HL1z
         NLJOCSB8NlGPIu2ygpVNq+zBlzvzSGPxPoUavN4KCEittzdigGhlybIAwZiF1bHuYthS
         UyTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=sBxd6NBuj/5yNdSnhrHh4pNvwaiXG51e1FmyW++3toE=;
        b=jkRkkYYM/jTlHWB5CI0n4XRUr2d136GQp+rmWT5RemD0dVlPm+57gKVQi0yFZzY3M6
         pKSOJdPqOLOGTMID4EouT3ePYQD6UwoatklFm5cBNW1EbOGqYE5H23uDn1w41QB8Dvra
         1q5dy48hiHgwnsy6j2GoIpIsJNKMa0tKw+atrmN8htDO1tFt9vmv1g6BPyHzhXrSZBeJ
         mjuQ1rnVFQeszM/yaYWN8pqDXjWxHEz1Vdu5rrDSXHYfSTsIKLaxXfPqyUZfoEM/u1Xi
         tfthS895g9T6RJDIGOZwURESgcOOeaRHKFkU62GToUm73HFWjyGR2xbKhgq2idZnzqKm
         2rGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo32JtqkmbgM4KZwa9I7PjFtLgL55LHOqsIQZwPTG0PdCepWEOKU
	HD8TdKEsUyqjvV2irj4lVCI=
X-Google-Smtp-Source: AA6agR72lzwQam9LWVc25KS5uPfSbBub2yjy1vJg013S1jEtQrlLTA/y072u7xvK6RdfzHNYJ3D0qg==
X-Received: by 2002:a05:6000:1c14:b0:226:deb1:d7cc with SMTP id ba20-20020a0560001c1400b00226deb1d7ccmr21173210wrb.494.1662409934579;
        Mon, 05 Sep 2022 13:32:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7407:0:b0:3a5:abc9:1b3b with SMTP id p7-20020a1c7407000000b003a5abc91b3bls4125769wmc.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 13:32:13 -0700 (PDT)
X-Received: by 2002:a05:600c:2cc5:b0:3a5:4fae:1288 with SMTP id l5-20020a05600c2cc500b003a54fae1288mr12037474wmc.79.1662409933872;
        Mon, 05 Sep 2022 13:32:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662409933; cv=none;
        d=google.com; s=arc-20160816;
        b=yvQMJiMTYASQeHrZh3KQKwvmBxX0k4g3SOXWvLdWBxAdg+TQ8MbtzmnyJGw1LWA8Hf
         YjDZP3WDHZa7DXog+y7KUSexigEbSmFdX6H2InzM3YT1baEVhaqbIT/n3IXxCzYhK2QW
         DWZr6+V818bxMM8E3NR4X3kpp4MiEqm2LB9sBO14spBXAJ0+REVhgQqjeGM9JRc6bJTN
         UrmBFaVWW78wn021VnH2W9+J22QO2ZLLO3hf+CN2BoStXvVCupWLXMpDRIpK+83UEqyl
         x8wut+qFH/yzDr2NTP173Oe1vhVkPnGJDiAxAIfqKrSmMxOP3+EK7NiIBnhVS0FLASuv
         1taw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=OuBt7MiyEo8zMdWVuXi1RrUTjh/p0BGz6aQpft9kN14=;
        b=ahv8UzF/STwuAPbLBFUo3KqL2Wu+1VU31egnM/zOem0dB3yvmVhxqoN7EPgfnff4Vn
         vmaF6Bj2MDqz+BeOOjVFn9ncYFX5/ULMEQLoQYLEKOkYv03BBCBvJrRq1lPLn4SjnurU
         VfIrmym94uJcNwmeBqLt/l3aekjfRUkjhIbNO/jr5VhhUwHOVStaqNgzchwciOA4Ub2p
         fl0OrbWH50+QMpVPlUrwftI8z/ffjxMJD4Yk6xxmaUhwZBT5JwS++C8niJgbo0yGbPc8
         3shERouYAXy/9TuBIOVQ5OJVixUK+wd3T2Eu0IUFqiPwyRkm83CF/EnKRztK3NpMg5nu
         yhUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KTKM2O0D;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bh10-20020a05600005ca00b00226df38c2f0si43412wrb.4.2022.09.05.13.32.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 13:32:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 855FFB815C6
	for <kasan-dev@googlegroups.com>; Mon,  5 Sep 2022 20:32:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4A9F2C433C1
	for <kasan-dev@googlegroups.com>; Mon,  5 Sep 2022 20:32:12 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 32C8AC433E4; Mon,  5 Sep 2022 20:32:12 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198441] KASAN: need tests that check reports
Date: Mon, 05 Sep 2022 20:32:11 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198441-199747-bmmegaRQCx@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198441-199747@https.bugzilla.kernel.org/>
References: <bug-198441-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KTKM2O0D;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=198441

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Checking the contents of reports can be implemented in the same way as in
KFENCE, see probe_console().

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198441-199747-bmmegaRQCx%40https.bugzilla.kernel.org/.
