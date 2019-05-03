Return-Path: <kasan-dev+bncBC24VNFHTMIBBZWKWHTAKGQENNWQ3GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CD1B131A8
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 17:59:36 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id b21sf2859692otf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 08:59:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556899174; cv=pass;
        d=google.com; s=arc-20160816;
        b=PpwM4pdhKZVRQBjwEsc7gH+MddV6p+VmNzvvtfr98kYul7jPc7/PIbKqK9zeH20Tpk
         x34Sh3GeqyinIodNW9n4tILeQy8bLYtNgDmWf1/ABxr+1uAPeHKj1hyDpIFscChWGr3k
         SupH7sFeSQGP+21trjQkvyz1PndM9Vb4VN3kWgaIB2kNOqTxCaU39LnAMzeMqGaRELzG
         n9iaU1wvIEfJdJseutuHBKAKb6W7rNrSp22Vhg7IKC2Ot1PfosAoxYOisxtcfrLQgudL
         WlnADNuIZfL6BRIh4yopCBg1Pyt7Ia2Ktm/CGsIAnLwHqyIWn2cE87KGspzVpebpEYvR
         aOwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=MrWWbTIt626KrJtt9DEJizzxTOf3r2MaDakfRU7DZM8=;
        b=cWh1vHEqXin1ADBvGcjL4CGWJM16QuKfC9p4EaZ9jIpg9AAidm48xjqTUBe6izmSvm
         zvyznoFO6SaKYXMxMOMpa+AkI0LPWRVlQo5NQ3gUuYAZImdzjjY3No+4FmxvsMTvQmom
         iPT+/sTGiJwoDzjSGqzBr+aYu2jn7f4lStWiGIKFQiOaTyUlF/oO9gQdtZnTuHtM34AY
         9IKy1wkiANOcCuVxt9ZJvqH2H06JDLRjQ4xDuOBoo1HI9l/MYsP/i6+kWb0PY79q6GNN
         WOjRZPq48RRSZFam/pUSuwQGhPWUgviv5z1C9Z1dF7dN8Mz4q9JNoHi65AdSId2xZHTd
         GmVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MrWWbTIt626KrJtt9DEJizzxTOf3r2MaDakfRU7DZM8=;
        b=KEw//I2kpJYQsIZOAg7xCz2jvsI9Zj4y+YO3wbNM7Gm5MlM491vl0llH6+Tvfbqel1
         aopowGQoQ36qjIOaWViftV2XW9mhLldgacgIEqQ5Iv6vGuFK5OdO6IIbmkrbH01V2gJ3
         xeMLlpYLyCvC7PZsFzwxihZt8A/W5uysnJvEYrpxCw6v3AK2Z1dqGSYiSEjkA9WhTMO/
         Dm90MDnUxmn+kpCaoS/Up7nRGOC5r0IeQA6w8lGTmJfEUai03dY6wTDbQHVRWZHZjCor
         JuAFHX4z6oqoynhfIoSF0JTCvgp5IAIekKUO52HqF4y2JzYxEuiiwQ8rGEXPHfKVyDID
         ZzmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MrWWbTIt626KrJtt9DEJizzxTOf3r2MaDakfRU7DZM8=;
        b=rchsYeBzxVq80pyHQ/whLnKtC3rqCDg+5dRvC1JbJGW1FzST1OFazL1rvM3s/yAA5G
         kGtIh5SK4KhYkZn3jf/fAMRk7TWhbUViZk+h3fM4aHF7PRpWw42L2PoPY3Mavs7wBzvo
         L6QKVkf8qDlfa2bTAbbLuYyE2t6Brp1k127NHtde1p2lTJKFqH4Rq3Y6qHShCjOvf+ll
         SUjRzgdxVa35PZ5OuIorGT9FfhuvhYfYSJzzexVNfN6mu2/90yRYHzTx5nESrzBmM3Cf
         uaXCPIAxQ2zVidH1nNLJotfwt6GWlyrvw/ui0v8u94RXb2/1IzAyEL+ol86E2m5T0suM
         Usdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUcwKN2ofxrpXHi1xueMRt2r2/tpgxqSPGtH9kaGMUKg/iY0prW
	ZAiy+4w9g3HQ/pL3SrxI6dc=
X-Google-Smtp-Source: APXvYqzlRj/BaaSeuCT+NctdN0yHzLOyESRrtAZ2i+G/EFTpmsYrVgUPs7Wsa7s82vjfbSM6M5weCw==
X-Received: by 2002:aca:3603:: with SMTP id d3mr6382735oia.145.1556899174545;
        Fri, 03 May 2019 08:59:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6142:: with SMTP id c2ls934250otk.5.gmail; Fri, 03 May
 2019 08:59:34 -0700 (PDT)
X-Received: by 2002:a9d:5c05:: with SMTP id o5mr7139440otk.262.1556899174198;
        Fri, 03 May 2019 08:59:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556899174; cv=none;
        d=google.com; s=arc-20160816;
        b=Q9UBm8cnTYk7DfBw+Mn137s2e5MN754AVwxbLzLE0X78p+QFdcTDo8eTfEzGvl6Zv6
         2M3+C2XSftzdmr+sRNwzvdGrtOmtSRV58+OZaAsF8OOuq78GRpSk8NUvCL7fRE3quhGw
         NNzRtvlBCGHcWQIUhEMfJdK0UGlC4sTWxFw2hhO+FXyNlV295K/tTksrqZsQKxc4uTmN
         EXfOeWnNvGGnYG+wJEOyzoPgUI99ysre34yyVb7phLpyQ4elYLhhdUfT7O3Lm+oOMw+y
         vZ8i0TGfv2hIctadGjbAgWmvHNtYxw7VBEGN1R6WVqlPjOHcgYSvxu9Utwl59TeXEitM
         CmiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=U9Rx5+d/h/Pak8VvCzpJKDPTfCSGxtEbQVY8cY6kir8=;
        b=bsOrRRWC4qp3fQHFs/JeV6hMQKEZFB3t3YVsqPWGw3eGgCkFOVC09k0lS4UDfzioCt
         ft9lzFL5pvZGswG2e7ILcByt58r4xUmbKrIwKGouws+hcPLWmRUrAxKzVwrkqaAjzQ9Y
         8I9NxZY1Nki3ZU7ATdDd37GSMxwMudUSchfsGrTm50f40pZuQl8iQxJIGB04NxLlQxFb
         yb+aYu3Qs8oyUe93uFFgh8qCi1LEGIAbrS8+hFN8d9a+m/5Ew99140L2bCg3cEaNxdxt
         qkOGoEANT9SaaPX8l75n/r6O0l8g5ibJeROXXWdt3Ye9JZ0TPTpxQc1olUxPwOs7yjFk
         q1Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id t14si164545oth.0.2019.05.03.08.59.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 08:59:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 4F87F2862D
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 15:59:33 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 40C3D28635; Fri,  3 May 2019 15:59:33 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203495] New: KASAN: make inline instrumentation the default
 mode
Date: Fri, 03 May 2019 15:59:31 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203495-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203495

            Bug ID: 203495
           Summary: KASAN: make inline instrumentation the default mode
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently the default instrumentation mode is outline. Switch to inline as the
default mode, but make sure that older compilers (the ones that don't support
inline instrumentation, both GCC and Clang) automatically switch to the outline
mode (via $(cc-option, ...) in Kconfig.kasan?).

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203495-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
