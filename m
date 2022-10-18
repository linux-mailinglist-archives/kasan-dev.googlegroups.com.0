Return-Path: <kasan-dev+bncBAABBCHPXONAMGQEBFRBYDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD3486032ED
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 20:59:21 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id h8-20020a05620a284800b006b5c98f09fbsf13143835qkp.21
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 11:59:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666119560; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ZuIMZ8LWbKCF3w8FOZSpUM0wQHTaC0lIb/iWFpfTcAAOVeaqpt0MeeRJ+Ye3gEP9D
         ezNkWUHZ5jGM5xgz4Pk7FcJNW2U/zjArQtdwh5OKFuaeCULBm07bzsZL+ziIYZF7MyF3
         CIWKVp2A16KHnQObj7FYNWE1/p2yVF5nLdNDhS09Z6YFAc+kYBqeJeUc6189yKQIzVDj
         4IJ5VGJpntkSM5kAoio6569dsXwmN88pIq2XxHOTpuomc9OKiCekaXlrTY5pMAb0el1V
         j4SzC6JNZcE0Pgcd53o9cQuOcH8IHugiYVbwccgxn5grmDdUQIktjnC50CYZUR7QX4VE
         L67g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=2ILkj2mHoSQbokMcOcUgLEyH8NWtYQ3UZrqgmnuYH0g=;
        b=eiBIAWG3WIdsnPZVuZ9hk2/ISeYLR1phlClFwHalLdVugg7RPKxVMIEga0QN1TA3Kq
         Zs0OAHpPC842hIUXZkyMZqyI/xdXDa0P7GelDujwIPtBEosCyB8D7ilHT7Ci/p5vF7eH
         gU7tNV+UCxVPBuDXVkFsSdREN52olFr0DSu225K8Wjdj2C+QQhC6ZZyL+GDiOKAajWEz
         PhceiV61uXZ/Gbiv8oqieSLEij1Lrt6ZBAOdJTx9+7JxnFDf1D+b8mhLCIBUI6kquywk
         VljOty8vC5sbWBgg4JvqoI7QUIiL/VQNJMy0JwLZ4Xv+PAxcF5ZFlkFW6iUwOz4qiG4l
         JRyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UtfIgCsf;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ILkj2mHoSQbokMcOcUgLEyH8NWtYQ3UZrqgmnuYH0g=;
        b=iNLYMe+QspSnftq5WTrRKmau5Cg6ZKXPQwUt3i56LeMfflbhXluS38G/m21aKju6ib
         LT+dvZut++0F+eoNIBp2dT854TuOwzvgmSSFp+2CIdZspPYLUqpTOp3iueOM50+wdxO5
         n3XPKm3Rj19G/Eu5/gFAc2J/82lEKhCNcW7MC2Ll2DAuwGdegxaZ738PWxPyAFza8YmS
         +5ssn9H9yZ5qNf9nXOwfJ4J4jzRwPFmw1GwN2Ad8QWyLFgzQKsl+hIHrRg8zNrSFwCC5
         vR4DJAC0l6U/dE8IZZEoehTPXjEd62XxmZqjP5dTAJbGcgPs2KsOadPDgOFRfgMKJFdK
         jF2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2ILkj2mHoSQbokMcOcUgLEyH8NWtYQ3UZrqgmnuYH0g=;
        b=TeqLQ7JexKvA79sakaTTrWjStM8fR8XdikCrtkqjs5Cnxbb43ehbn/6CDpO9c/nIW0
         F2M7OtLJrfS/t4+Wvt6yJfEvNG3Dfc/TIkz76ujHilQTIN36ivb8EvYggq/FGjXn8Xaq
         sFMC6r1X2rp/1B1OR8CPu8sQ8FpchP3Nwf+s9e3Z9zV9j/XVQqtQhBhJ32GkVqrCcUHN
         KGSKy2HnHg+cWM/bNU/yfH54C0gd11v2umr2dtsmYoN02JptpvtF23PMuSv16XF1Vb+L
         QjXlSFqQHcWBbAhTZ1+znDZ6lfS1gbrsmEK0ZpwpFAhPAASop/iOVdPpn4KCY8VORWvV
         f5Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0quW3y121HiwohYmWnk+SK++xrw21EP0BQQqJlAOrYJeBgMNTZ
	qTDU32ZOFtIcq72+0cilm2Y=
X-Google-Smtp-Source: AMsMyM6IyZJglJEPH1kk0si+/PrQRl+cp+qRTCUv/YRZTISjv/VDdGgXqQ2CdUUN64YLnmSUWLYfWg==
X-Received: by 2002:ac8:7d95:0:b0:39c:f1a5:7391 with SMTP id c21-20020ac87d95000000b0039cf1a57391mr3269071qtd.605.1666119560579;
        Tue, 18 Oct 2022 11:59:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:798:b0:6ee:8313:6182 with SMTP id
 24-20020a05620a079800b006ee83136182ls10175699qka.4.-pod-prod-gmail; Tue, 18
 Oct 2022 11:59:20 -0700 (PDT)
X-Received: by 2002:a05:620a:2723:b0:6df:b61f:99f6 with SMTP id b35-20020a05620a272300b006dfb61f99f6mr2907801qkp.3.1666119560216;
        Tue, 18 Oct 2022 11:59:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666119560; cv=none;
        d=google.com; s=arc-20160816;
        b=iyEJadJk8BBNdxEcVGDQvMAUXgipjxH/K+zmV9xsB1LtH9vUA3vQoXDeOFg6tgSy+f
         xq0yIm0I9P4Gb0ok4FMdCAZm8RorDbDEYxjBXjxvZmBUy9vHk8Imobqdv3OzB1cdN8Fv
         t+VzbSTzFXdR0vn0HmoyQYoFXjAQbC6ReD/OBx+7yyoP9we4++xYocgQlgDZvo3SM+rL
         Myb3jNipwXR0LOFEfIrsKOzlBEo3J+bnCAnrF7L7RJAUuy8WPZueYEM1T5d8L1lfjv6d
         3p+PLeeAPdh5LnSfu7qR5C2ysCxjKWfQwvEnHL+CYCT7p+s5Qj9sVszO18twBQDJqwV9
         E5/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=/jw4zjCDnrg7E/qQgAIiusRISmTiqpCWi0DOQ8wj264=;
        b=VKiTkKqR1X30jbs5Eq5tMaTG/6pdaSRyV1FMGpv6gX+f6hw2iNQVg52GFVlCSOSY/O
         l1na9DxRaZrl4KgbL7NcbvbTYFaml3qpSQi+g73+dC30blElAY+ou2ILvsOuvdWfueD2
         afmhzdASTFPROQEGhwLoWjldSlKy1HywP5ZnzU9K2IJdWiOmEeF1/qk6o9xPhnOEeii3
         axak9hlpTP6BqYgnno61ooUegaI7TIXkpNmk5slXrobOkjcSoZKs1ji1lvwgnQXJRisA
         tSjSIEsLL99BiuiTgUvKKeGoeFc6XZsuZD7yF9AyIarCYgI9BoVuOOGJHbNGFAFTJYUe
         UdpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UtfIgCsf;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 17-20020a05620a071100b006eea4b5abb0si563435qkc.0.2022.10.18.11.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Oct 2022 11:59:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C325A616D0
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:59:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 369AFC433D7
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:59:19 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 28F9FC433E7; Tue, 18 Oct 2022 18:59:19 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211785] KASAN (hw-tags): production-grade alloc/free stack
 traces
Date: Tue, 18 Oct 2022 18:59:18 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-211785-199747-PqHud8QtHZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211785-199747@https.bugzilla.kernel.org/>
References: <bug-211785-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UtfIgCsf;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211785

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
The planned steps to resolve this are:

1. Speed up stack trace collection (potentially, by using Shadow Call Stack;
patches on-hold until steps #2 and #3 are completed).
2. Keep stack trace handles in the stack ring (merged into the mainline [1]).
3. Add a memory-bounded mode to stack depot or provide an alternative
memory-bounded stack storage.
4. Potentially, implement stack trace collection sampling to minimize the
performance impact.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ca77f290cff1dfa095d71ae16cc7cda8ee6df495

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211785-199747-PqHud8QtHZ%40https.bugzilla.kernel.org/.
