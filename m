Return-Path: <kasan-dev+bncBC24VNFHTMIBB5FQ2P3QKGQEA67S4VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id D61E420A37D
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jun 2020 19:01:41 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id m4sf4098263pll.11
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jun 2020 10:01:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593104500; cv=pass;
        d=google.com; s=arc-20160816;
        b=T+TSmAFrcIyiKrleFcABpaBOQwf+8lFXf2NZeNHyiPZtS0lX68aKkVGnNV/iAb5E3H
         KqvLQdeJMpTknLEOF0t3vK/s4RNnLNZH8KYtRv9ZAlZEfOb9rUCFGdx/vnF5H1E2IASY
         qlhp72poilHVrbKj1tlkmOnULjBQrUBOWLB2XZiuvIe3iPDV6/p1f/miLyNlhItkUSyI
         V/pPXnvtO3gxMq2KgK7czikZtXYVXuHY0jwa5QBwDiOX6r/5NkmxbpsAFfrcHZGhFJj8
         Ug0eBgvlKt5+2meMcZlBY5tYYoI67hirJ1x5pHyGYacRnLOSPU1v9grK9xQDpKfK/UiP
         BLSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=e/VsYhOo06uu+o27lmUJLlJkC+PQiEfHMLJ/3DFYOso=;
        b=wCiVGIkkVZURjTWIiQ3u0FEybbexG84617sw0VAfhsFV2jXJSIMbVFeOggbUFN1CWD
         BY/Ne9CGeBOUPjxtOGmuKmi2DgtW1cQv7AAdSaL/wSn7v4f8nTY0PblvxrHt22i11Ex5
         v97AlW2bOYA9Gz9VuXouu1oGBTv3ZmGZXg8QcH2vf7N14vZPsDFmIifGTppIx0I2+pXg
         7w++jxpd4mk1ap09O1n+iYQE4dPp7yOOrxZM2aGTiOchN2y5RbSbjqqMiGp9vWnyMao9
         RTiNu2QBTQbkcmlNw42Szh9Xzy10PIKO6N9nmooSu8EZJs4dxL5jccMWj2jOIlglXV/r
         fQxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e/VsYhOo06uu+o27lmUJLlJkC+PQiEfHMLJ/3DFYOso=;
        b=C3tzi4VJdDVY2HjjGJSIh6mBUNjsxq8TEHuz18R0+dj7mICJtWrvhx7C9Pf/dxtyxP
         hMIbyLtpLDhTCu+W6l1ZpM1UUBP86Q7qZLv7VfmidPlcv7G/mJ67D4vS+adP/hzERzde
         JEfjlGL1bJ4Q0PPkyi2ZfCrl8mq4JT9QSDG94joCne8PCwirARe5Lf1rZ1cLCi5HKyKu
         0F3q/Mzdhmtu+OqbdkdlbG/Bust6woyeQC3GkrMZ/mbGpOHKYSkEG6krsObJrN4lsxql
         5VGxSF7VCM7s6xdlVQY3jR8G/8+5/mPXSyzkb+gEunlwliWsweQtnxOThXlVlPTYAaQh
         rmcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e/VsYhOo06uu+o27lmUJLlJkC+PQiEfHMLJ/3DFYOso=;
        b=GQpHpt6kcDsz5bSXscRlxUufcVDQmMH/wKcVrpHWIi0AmGkOK82BhOr8o45FegaxCI
         bdzvGi/7Yxrr73O2JH9VqMo8c86rprmvgnitdBo5bPn4BxTFFvtrPB2Ww06x58BrL79l
         12TufjXB8XH4cjYC7S4zeDtJiIIYMy4pkiRoXcX0cTIje7rMmUIbX3myhlxG4+o16IHp
         FM7SU19fpIg/lmX6cLr+CfHfMU3LWDdOUjnygU25ZFIR+JqaPwXAMiLiGeeZcO/EulSa
         HF0LaMQ4AMoIP+wD1vYoRqtkU2D+0llmTE8sa+vdcmjn7hpy68g4SUcnAMhEGnbxuj6u
         KY9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CxwlTe++13jADNE5nYuB4OrEm6mj4onfmmxk2DIhMtjpIbUzX
	CZCRpCwVxezw5Sfy4CCkpF8=
X-Google-Smtp-Source: ABdhPJy8qU/U9QuiolLZBZ7AT/TWuWl3Q+41/3ENBBm0rUc21TSeuSee/2p42yAljP6pM8s2y1nM2g==
X-Received: by 2002:a62:6303:: with SMTP id x3mr4989325pfb.310.1593104500362;
        Thu, 25 Jun 2020 10:01:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7686:: with SMTP id m6ls2477858pll.1.gmail; Thu, 25
 Jun 2020 10:01:40 -0700 (PDT)
X-Received: by 2002:a17:90a:de05:: with SMTP id m5mr4127226pjv.150.1593104499971;
        Thu, 25 Jun 2020 10:01:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593104499; cv=none;
        d=google.com; s=arc-20160816;
        b=hIIfUuAGhZoO888BnrKqjXAv0UQ0lbufK0NHt9VaVoR6z6Iz0orjSQyuhZeT56OqJS
         OjPVRj7jCRXgrUrSnPSzJFQBYhxjhdKb9Huf2KNuC+OpXP7hDp6zCE33fZCq6SalLK6W
         7HNWf8bAwufABe0H3zYlvGIdqSnOA9xTEQpDpoZWKnGgza+U45RHRyP+kNEHO6bPge1Z
         /SDuCF+cHIqf30PddVNOUf/T0f/aphdxPk6mHNPAbBnZgSyjbBWBsjrjxgHPHPtlePXl
         lPPPUWg66ZyDVnKaCsaAIjok4SLrV5DSIcAi+k6FWhKzgTUW6LOjm8ZE6Rae+Eildhzl
         7KMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=bxH8dmiu2LtsOzXYJhfk5NOf9TpOpzdzO3k6jqTIXsg=;
        b=DFeAlDW2fN3jSo89nI4C7ConsgJlATMG3Mk+998ior3M6hmPmmWVWkDg3C60SBRMUE
         m/vDRc3k9PBvFK5qaTcSi00d2Fyv5+FZkkEepi/IYz+ar/OpS/c6SbZRfFruXZnq9B5s
         Tbx/8O/WCFj8tZx4/wVbhkWObTW72VvtmJaQzoU3+gJTBarf8xfBkJFRixmOlIUmltu4
         g84bArZo9SidSyPGXMK6BFSv90dst81+Npng7Gd3PASjdmJ6heVpABfI3Rsmom4NaTDH
         VRbG6x0Wc3PoP9cOmAkpgX0W/vZdO7Y9ME54VPxUIBH+pghPYfl93t2H4tjSQEOl9Kiz
         dxrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q13si108044pfc.6.2020.06.25.10.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jun 2020 10:01:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Thu, 25 Jun 2020 17:01:39 +0000
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
Message-ID: <bug-203497-199747-ltcsqhmCzF@https.bugzilla.kernel.org/>
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

--- Comment #17 from Andrey Konovalov (andreyknvl@gmail.com) ---
I think I fixed those, patches are here:
https://github.com/xairy/linux/commits/up-kasan-stack-tags

With these patches and outline instrumentation the kernel without any
false-positives for me, but there are still some issues with inline
instrumentation.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-ltcsqhmCzF%40https.bugzilla.kernel.org/.
