Return-Path: <kasan-dev+bncBC24VNFHTMIBBKH67H6QKGQEZ3U4DBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 27AA92C448F
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 16:58:34 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id o193sf632318vka.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 07:58:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606319913; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKbk2SeXOeOML8Jm07DOZD3CLodppqZzajk2t+RxFUpnta3P/xBxyorAa1g509O9zz
         kBYQojRBGow9yCGPPuPzwgvWD4GeqTqajf7LVgY6iJjYrq7+R9qsmvQAnCT8JZdjzdxj
         x5MTQ9Jzw9AcngyCtgXi+fPacMrXa8UpNgKxIUuX5kLWZlRO+FOEz2kL2C7kz19nShcB
         PIpe86mjcOobCi8o2H8uStOQa5KskiREQEi5dP/74rGLj3gvm6EjNP0Z6OguW9DsRjjS
         dyLQ2gyyaPJEf9CnF0tUtLTwVro/Q/PrlrU4rlEBNvkzf/ZLLV2/yRkbX+fWTQygcTw/
         /jdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=bv3wc/jt6kK1E2UBzwRD93YWEPQd/fndJnc5g+Yhe8Q=;
        b=x13qnARzWoYRBQcCRNxqOxXl6BF/xi9Bn2xp/LeNja1J59K4J3rpvNWL0+asZUXe1e
         VzNIsyuTruu7iN1gL3Lid/3I9nBAUTQLQASnYayq9rU5k9SAW7XqByqzuvnHaznG9rTM
         9ZP42SJ9u3IUx6jsSG1QiHE4+IvKG4uuTba2Lo0OBoRZ4ZiY279MP6GYocOYjjpn/Bvf
         nLTx96ihsjyTZG+/y1tcublw4T9P5+ZEptL3VrSqBCFTdB6T2yRGkzZeRwm6+OXE6WNt
         FYE//M7Yt5eKUm/L9/MuGJ0Juw7ZxYOATbHBSgKeWLXhRQPnfXMWB5D2Fkp+/mmrBVaz
         JmGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bv3wc/jt6kK1E2UBzwRD93YWEPQd/fndJnc5g+Yhe8Q=;
        b=jJsqXrLgYnlZSMeaNK6/4hvyIbXaBdLVZBGDjNIt3ZRcfBxqc+3WNYujCmNAcdCXKi
         io9DsOmkjmxz6E8kQgkZCB904FoutL1LE6cxo4a2u6SkHAgdY+J6HsSuDmwxr6TYzi2Y
         52sCDWZYKiFWEgOBddPRQriXf3Uwm4YRf2cdqs3A10mMHRIYs6kTu/ZcT0DXjG7Fr2NK
         xgFOWYNEZr5/qSde2R8egH8n7FkIC/00ZkyG0wBSjGddtj0wai+/Q0MegqZHXYwtH4qM
         RkgsT+uCSb/ZfRgOlH3Q9HidnK2cH1VrCyceBRtJ0UW8nbISzQ1vrvwOAPcJ4vLXLRUM
         k49A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bv3wc/jt6kK1E2UBzwRD93YWEPQd/fndJnc5g+Yhe8Q=;
        b=YmtWth6pEyMS1w9pF0uL41qBt0wF2HZ+LlsZjA63r7y/prkx2euGEF3bwa3pROroLP
         mTSZ71+AuM+Ded6TlH4ee2BbhUNljzxDW4xk3jXoGWjZL1up88d5jOYjYmSrrXFFCUIE
         0NpcRstNpUY+aRhFxuQ8s363o8H0sEAdG1SwZkdr4js9kddlqhSkXPd8Z0hdoEihCXF0
         F7EMiPHNf7GG2p7oTbiEP5EBnlfRwy8dPpstndPgIqE0JMkDMhA7+mc5YGQbM+Jj760o
         JqKze5lNhG5eSBvF1ZFfLzNCsllnTuwF8pCdvml7lFjoSKJSD6nsg+deRJNvRIed8Uzn
         zmgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LGj6VEGKJ85STVKEOTUDF99n5pcPzfYrBrJ5qY4iT4ntHW1yj
	QvvXgnKZ6hxIQI0990nzDMk=
X-Google-Smtp-Source: ABdhPJyrM40q2KDCmfmlFMOqk+e3itJZmtOJ2w/Jt5Pk1+eMDT+OBi2WaT+9NaVcXnk2uKarF6a30g==
X-Received: by 2002:a67:2642:: with SMTP id m63mr2455547vsm.19.1606319913094;
        Wed, 25 Nov 2020 07:58:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:348c:: with SMTP id c12ls190586uar.9.gmail; Wed, 25 Nov
 2020 07:58:32 -0800 (PST)
X-Received: by 2002:a9f:3fc9:: with SMTP id m9mr3137632uaj.143.1606319912646;
        Wed, 25 Nov 2020 07:58:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606319912; cv=none;
        d=google.com; s=arc-20160816;
        b=Za4i6M0kgCAazlxL5SyzhKd3KeRXSLou5sShuiGU4fRtYTpAVG6sVcIAODFV9Rz3e+
         7LDHVnrwmEiOyPgbBv9ZcQk/+xPQubTZGrFLlqqXccUjNkzw3yan9UpO953h288jWjEv
         DHzJBhpdTYxSNAnIFR50llYGyLCXvtjEmIqnld8bSnXHFgfZWZj5Xhh011Rsf7Wo/YIc
         ymDXZ5ZXlI8hNMIqxR5VSlfqIKaV2nQO29FqMQqCRvtxYDnnNWtks+GhvNMVo2SReSxZ
         mUbSvEbx97yFPZWv1JM4ldSwI7KsrQSwcZxfbUzKCciZNVQh0xbe8OFKb4k7+vDzN7an
         Y8Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=1juKv/eNPiwJAJfmAVQ1keXbAh9ABg0KdoGN6Rkjqoc=;
        b=YO8PtCSltYxXbuRuA5tzE46UxqoU3iHiuz4KYZFhzQXs5Gyy/yEc4jVpJl2vMTnmoQ
         UMHXihHzNVTj0fGnswWa38lnt3s8YlIAPeHqE6BI7/p+g8gIsdaIf8zUXbZJiEy7rcUQ
         qgcTzZk9Xare104gdDvIvzG85BAsiHy6AXQw1oulg61f3qjaVBbJC8BjW8e+ms5867er
         nTObCwFo3PpaCzFhKtBB3PgiKCRGth/RZc+kNhKHxA0dsJx7/WjDbjyD2Tas2lgGy68j
         oiarN0Fc+VqCGc90ZkMRgQYXNFAhzpbnkN4Wsc6CsqQQo13GKc5wm4sdqjX0ICWmBbKJ
         vXAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r18si118047vsk.1.2020.11.25.07.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 07:58:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 15:58:30 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-UXOVn7y6PY@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #9 from Marco Elver (elver@google.com) ---
Apologies, then I misclassified this simply based on the fact it's WiFi
related. It might help if you get line numbers with your stacktraces, otherwise
it's hard to say what's really going on.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-UXOVn7y6PY%40https.bugzilla.kernel.org/.
