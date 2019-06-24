Return-Path: <kasan-dev+bncBC24VNFHTMIBBBGXYLUAKGQECKXLLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 34EE65093E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 12:52:54 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id i26sf9328037pfo.22
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 03:52:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561373572; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZnU6lfQKZmRPIKjw3B0P5Itgmr+S5qkm/Eipr1fiRaOz/bM3jdfx17aJ/V0vUM5N0b
         9ldxNqarhWXo4YHa8pxsKh9TzYWcHfDFAqHZQl/dirSzkp0wl9F1f1bQAqNKvKyIEQKe
         LmbsWFrr4nyGKh7EK7Uz1yB0gi+f0Zfq0PdkqWJpdurg+gC1XYc25T/QT9M7CPYYQxpH
         eBf85wQ+ijYmeVZCWUwNQCD64h4/jNxNZkVFoMYsUUbCkb2kJYOf6FhBshHBXEX0sz03
         AccbRixw5igPUN7FjjYzlpxCGT2o77nRfJVXgsxtnsqjpoeHzrzU4ukN4DOjO3+anitR
         V1Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=xl9Xciih19SWNGgxsIJCFGBgoAZq9/nJpIj5AMuDl5g=;
        b=G4SC7YL5GLBrwL98yQ6jnZwegxz+/vACnDLf7EuAqnSFkDSvxyOw+UBCez2C2JbLtU
         dR9bhCv94OnwS2pTiF7kIp+sc9EPqz6xO9lh3PvkgLo2VmpJ/l/IQnfVkFLTk5qtTbRi
         rZijI+h0TlArVWJK9UAGkCaCkQy5dwgjH+LHa9xx1a2jRSHjjOTe6UKLNGWNW8hpOLlk
         bdoO5T9qEIclw04HkehPVyJEEA+f6mnsb4foANSOKcyPAZ1K7R21c8bYIcVdtTn8KJ7c
         pRRnDtouY72n76IukWlabV6SCdalJCLqTYYJ6Y9llpuxn7LZSaRX1saAciEnyrz7/gFs
         ZdQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xl9Xciih19SWNGgxsIJCFGBgoAZq9/nJpIj5AMuDl5g=;
        b=BvIYQ0WH4+H3uGt3rCbM1+M+BVPSvcCV7lxmTPaUnz+e5irgjAMAyHYXV5HJnSR+L1
         6CS2911ItHtmVbUcymoWeXTlCrL2xEwtsK6NFmrJ8DnF/NB3We4GFZt9bmm0yu3oJFDL
         7kmfYlryy+DliZ4wayqkzVSqJmarqAQP6C7lYsjcCUbU87s9FHfKax4R+FGcD/jV5YKS
         Gb9Rfot1ohYvwFZ21Opc4uMK5h+NlzzOD2d9pvh6BfxaKnkMPjH90R6c6wO6k3u0vBjQ
         O3KVDenk56SFa8yT7+WulHng5EnuQxu0QgcEG1P++SSlIUiA74NLBugUNBFpvclJshWx
         cLbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xl9Xciih19SWNGgxsIJCFGBgoAZq9/nJpIj5AMuDl5g=;
        b=W1u3n6ZPbS+ZBx1aPkp1zTUKblecWERDDV8qI0Mjm2evS3113JhTxxPK/uReBU8sJo
         VUmSwfxozy3H8PV03h+5TxwDsc5qd9YTvex2VbFeJskkwwn/uyT6ZameMocSdJcP1evB
         oRfaeGe3ZEM921NPiL1i3F79kKtbMycQe5DKGGEm6RE9LopW59uZ5svPVcHoyIqwrp7d
         KpiTU0zO6SkuW7UbhWmKZgumzzcRVkzHJHssrFFXVEIJ5eJzPZD/QQJjdHoQxYWYtn0U
         kEUSSch9Yu2A3KQtNHPA6Auy+bYLZS7Z1mA8pTFz8Chr7ETTB4N1mH385t053Utd5keI
         3ZHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQM53V3KWQIGeSe+alEUT9wEMd6t+zL9Jx2yn49zUB7a1v8E4e
	7u+d94jTB4tlmTPQV1sHU7I=
X-Google-Smtp-Source: APXvYqzl8yth4YRbLMVlHmlhgX240oiAK1ZaYsrhvkUXP63kM0A8cgM7vPthKVt9dFoS1eu9JpvVWQ==
X-Received: by 2002:a17:902:1c9:: with SMTP id b67mr102103300plb.333.1561373572382;
        Mon, 24 Jun 2019 03:52:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e509:: with SMTP id n9ls3217747pff.2.gmail; Mon, 24 Jun
 2019 03:52:52 -0700 (PDT)
X-Received: by 2002:a63:f146:: with SMTP id o6mr31523049pgk.179.1561373572034;
        Mon, 24 Jun 2019 03:52:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561373572; cv=none;
        d=google.com; s=arc-20160816;
        b=AKBlAJiePStwStgma5VvMuXRkjE9Ac5x0cyfr2BcPRhvbsaGtaRmB/LK5b4V/8HkBZ
         tLUbjwXWNB4myynz/pIQBTHs2K5iqUfCh/m2Zw9w4/M6g/+uy/Wmw30i2NwyDb3DdbDP
         9G/zB6ZbnPn+9rwRKoL2wXf/yG13fDnBR9qsCbWNKKwyJ9XKgKTi7d05Uqy6kYANGVyO
         MP19nQDJ2xlbB9nXo7MWmVwdJ4vjJbkNwmmFao0vwwCOh20/+QzZeGzhxWK4PQZiUaTp
         3qH/KjhtqwI9p9xsI/3qA6Jn1n9fZXwbCvoNZ1vWX1di5t48bWnO6V+ZvvpjmsbR6zQm
         b8YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=tYLmjEqqrBOQq1iAALTzNMRq7he7qg0lLWxtT08CxUM=;
        b=s9SdLnAJB6LsR9zR5EeXbMFgSPsdb6FMj/gvghzUT1QCY4+9eV2MfnZXcdWcp+PYww
         7EwbT2/fNV4Kc3YLaDY+mr8zrz7Rf6wlPgmpVULLH+4psaU+6cG/OjLtcDBBmqe95Fxh
         3p1LAfxADLC6veZ8V9p2DSeIm+dDYhZexmgRBnCnoRS+nubTJrnhE9P+sp9w2QkdaAds
         Zun25beR8lPLPbb7i3/sipUWeQhLt8KI2Gf1W8bRpQrDHfhtzwpQCheZ1YI28UoRdp31
         ARqigK35fwIUiKUrirhrrF84eT8ofdGD/ZKbTJJYq+swGIEEl5AGuiTLO1EZyIb/TslS
         2OHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id j10si9679pll.2.2019.06.24.03.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 03:52:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id B8EB828AF7
	for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 10:52:51 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id AD16628B08; Mon, 24 Jun 2019 10:52:51 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203969] New: ODEBUG: memorize full stack traces
Date: Mon, 24 Jun 2019 10:52:51 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203969-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203969

            Bug ID: 203969
           Summary: ODEBUG: memorize full stack traces
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

This is related to CONFIG_DEBUG_OBJECTS but may be relevant for other debug
configs as well. We should use lib/stackdepot.c (CONFIG_STACKDEPOT) in more
debugging facilities to memorize full stack traces. stackdepot maps a full
stack trace to an u32 (i.e. smaller than memorizing a single PC).

In particular come up in the context of:
https://syzkaller.appspot.com/bug?extid=c4521ac872a4ccc3afec
https://groups.google.com/forum/#!msg/syzkaller-bugs/0T-seeO7cwc/X82YaRNWBAAJ

which contains just:

------------[ cut here ]------------ 
ODEBUG: free active (active state 0) object type: timer_list hint: 
delayed_work_timer_fn+0x0/0x90 arch/x86/include/asm/paravirt.h:767 

and then Thomas says:

"One of the cleaned up devices has left an active timer which belongs to a 
delayed work. That's all I can decode out of that splat. :("

Presumably having a full stack for the timer allocation would make this
actionable.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203969-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
