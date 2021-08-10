Return-Path: <kasan-dev+bncBC24VNFHTMIBBX4DZSEAMGQEPGNTXXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 70FBB3E862E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 00:46:56 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id o17-20020ae9f5110000b02903d22e54c86esf123131qkg.8
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 15:46:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628635615; cv=pass;
        d=google.com; s=arc-20160816;
        b=daUDaxFALOA8CK4Ct8aoa7MltNVKQuFJ5mF7PQJSSVfN3NkLtOmnSAUCtn7Xp3hCvB
         kzDlniHpViLsGMcYtx8HrqsfVCDe2CuIgyz9NBnpP1OFamQBhELaYwKA43JOpDUjVPuR
         Wljm+qfPTl+NQ5M2mYLDHO2kUZGSCDkNCJ6d8yNxWLLjw9J5hKn1HJEryc/CBUpAyI+9
         g9lEruSWlQpvV9gS3F9G/zX7soLASisb3yz96NaVYWReYjYLd0Ms5WUuXt3JIpOy4XzU
         FL5ype3iPwcxiskl47V/ZVbZmXVcYHIXYQasaoWxB6H+LkLfOLXSEmCBawOt5ColaBgf
         CgOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=iwdMBRM/QrSszEwIy7VrfoqRzScy6NF+DhEbGE98KtM=;
        b=uqpAkm1fgrzuH7jHjT1dTHpNihL+gJaNDO81aFu9K9cqVehCaOClDDETBPXHKJj3sB
         F7Hdrc2jAW0mgOtCIL4bot5dT5h4zzrvsL7YTOVLhHYaTLADybL2Yb9kVx5Di3ZELHPf
         30e142a7k+9hIK2scwJQg/R92JtNNn/OmqGkmGzp1NV0m7LEAgZvYvzlVybbe2Ug8O3C
         btXe9eE+uOB7jCkEY2+eQELCDjGKfOXxKoogcFkF4/ZNNPPYuQb037YvVmBz28K8jG7h
         oCMYOh6IKNeWAsHcgSfARZqpy4W3V12/MqXyJpPPDNbiEumgSqyOLbf61M/Hrrl4qQ7f
         EXbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WQKkvjVs;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iwdMBRM/QrSszEwIy7VrfoqRzScy6NF+DhEbGE98KtM=;
        b=EBmB0jpDyUywLoyrstdCvT3E/dBAN/zb4s2geW35RAuKZBlQGIN/jhh8Gwzr3sRH37
         1tCzhbZH0n01gTmVOo0hTBMa3ROhrZ0COqMCYCGZz+eiqS/0f/FdiEeQ0vSJBkmr8EON
         ztE/+JnGsfenziPTLBgWk+5PoaZJLF/NuDSKOLEwSEFeqfwE4DVEXgMB6iIlHAxDHon5
         d5oTWQgGNInv8ZJniWaFaqhHff1iPpuNHF3Voj2+QA0XTgmmwKOMs5NZYRo0WnSLW3qh
         zMggsbNVIvOB1VrFASNMJdQF4gaN19agR86yQzb3cUv561FdUkMlgJBxsgKFhQUy/V+L
         2tVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iwdMBRM/QrSszEwIy7VrfoqRzScy6NF+DhEbGE98KtM=;
        b=sQ0Z0KeWxtL2vAapReldOzddut0FHHVMEpgP7mZkCLltDrIboFLd6fDUZZRMgzAYp/
         g2uhiXO5cG581Ige57L6kksv2R+37kZRIGIJ2vlB82B1nHMETx20xlZgeBBcka/lPDHY
         AIqIRM8wszFZI9y5hfHGSPNH82T+lYIW10GqYu6xQu27CF0Fj28cde0w15tkYTqM5gIW
         549YFHEhYyfIjht7ceG0l6SdW2dtg1cS+gIirzhy8reAIaC/Fflm7hY+5ZR7n1YMn90D
         85zf6OrA0Io/R/FDzYeKX/Rk5oEBUgFLuXvOQKZ82x7ecKA03yhRYS+/c1ljw/UvO1hH
         QfhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QRESQVLMWiYQhDEH4jIGGV5yJRiCfVR4f3P7LwmRifuJ2MAfd
	PO3hCQfkzuFH5DZTAZaDAF4=
X-Google-Smtp-Source: ABdhPJx5rg3qTx+wl5lcQEr+aoMT1igovLleClkDgo7i3tXUhNBiBaC7+Fiq1CDCcWdp+mMAeVCWpw==
X-Received: by 2002:ad4:4d04:: with SMTP id l4mr13936645qvl.9.1628635615242;
        Tue, 10 Aug 2021 15:46:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a191:: with SMTP id k139ls281904qke.10.gmail; Tue, 10
 Aug 2021 15:46:54 -0700 (PDT)
X-Received: by 2002:a05:620a:4e2:: with SMTP id b2mr22266477qkh.353.1628635614787;
        Tue, 10 Aug 2021 15:46:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628635614; cv=none;
        d=google.com; s=arc-20160816;
        b=HoCw5soBAVKv9XFg4g63xKmq5RDh2VWUdPOa00/GltJrQEwcuTMzoYb6WWR9D4ZpdR
         MGxToN/jWaWcJMtYVz3nj4DWfcNrzGQ0hCCRh57Q9BpOlHSR4n7fG1To5MqejkLBezNz
         oQgn9hLsjJWLgs8CqGV/5ffeNkWfFhaQFnuoME3kfYeS2OpNVSQIVJffMG9PKuoXMUpX
         Zd+UTQ0e93b1/yuBVmX5snPSxQZmF0uVyKo8jnW2VZ4dJh6NsFq5abICmI9LBuqFv7T4
         3e25NmdpMUlx4RK0Xu5evQpzWPBMHUWh+pI4Or5zxELWobM2+hbAuuEgZQNgbssM63jc
         7INQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=klF2LK+4krnx6akICBhnk9NKA3tdIz6CjHlAzbgYAg8=;
        b=slXGsPvOmb+jbvFeIJWKwHCUui+JIlFGUNUJ6cI+lnNeI6dzjTxLzr0S3PAOmtdYpJ
         UnNZaeaX9Voqmmmq6XplcfNW/at1fowA6CfuNKjWpon6SFgw6lBnwI+2lUqWp54Y+aB0
         uVY03T1pIH18ClEo3e6N+XXrCvVGdLT3UfpDLss/8uiLYvi+UUEYxAtS/NWGbn8MP/pl
         VhnAMYKMepFlnwDBluZVQq2JyuiV4W9+HTRX8eXR0qrUzxRmMU8tgY9cIR/2BB5+VT6V
         9FlhLCmgzB/588M/IO5eLDbzoOvA0K/zze1MPTTIMiyp5jmk0XLCMDYMv7rI50IqGxx2
         sPAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WQKkvjVs;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si910328qkg.7.2021.08.10.15.46.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Aug 2021 15:46:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id A3DEF60FC4
	for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 22:46:53 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 9630760E4B; Tue, 10 Aug 2021 22:46:53 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211783] KASAN (hw-tags): integrate with init_on_alloc/free
Date: Tue, 10 Aug 2021 22:46:53 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-211783-199747-tYHyS62XoC@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211783-199747@https.bugzilla.kernel.org/>
References: <bug-211783-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WQKkvjVs;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211783

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
The series has been merged.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211783-199747-tYHyS62XoC%40https.bugzilla.kernel.org/.
