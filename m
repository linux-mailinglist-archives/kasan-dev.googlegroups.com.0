Return-Path: <kasan-dev+bncBAABB7M3VLFAMGQEEDPMPAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 96697CD952E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 13:41:35 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-88a2f8e7d8dsf130781966d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 04:41:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766493694; cv=pass;
        d=google.com; s=arc-20240605;
        b=lK2hyetiLR8F0sZ92S0ydS5h8R+iz61fHrjc9mVbHOQ6sOEo1MVqd8FLYypnZbiBfy
         GFBKnF4pcUEoLc4CdF6kGk0P/5hOjM+bARpOnWZ0MEA6WRzCR5811gSOcpvhZtDmchsj
         PDzx26gH/5em4GBRfMB08tjyLvCZLwnNLEFcoHj70yGb2q+opZ43jERhWLsOQZ2n1c6u
         8z0Ctl4xHH1MNsXALW5nGKTlzWuvKkvSKXk+tYw0x4Ulv9octYtf/PwsogELGs0xmzj2
         Eq06j9mDjh7oyhc8oJDUUK+8HPQY1hF7M/BU45r4JjTUwTtSdlgnvTneXRX4Gosp3Yvf
         j/Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=VD586ImevohgoVlCfNZkBOx0xQbrxRNg3qHeOa4t++s=;
        fh=YocVbK/bwrsOwsKTiMiw7J4iNakj0hU/o4hB91sSyrs=;
        b=jkRgqI9tUWA4bmlWNrQpTNDZsNPcweg5VhxqQmN87Anc2qh5YYy9lE5072mXLz0WM7
         a1/dnmUVBL9NwpDtWkTj7fpGRMZiGjmgPINV9vBRG70sB1q02r9aLqFfhKUGR7esr0L4
         ngtVTYglZ97aEXtdi8M/IMEw9os8AqcRJwuefCCCG7HAH/3J09q04P3NOnANU4m3E8/Q
         HVPHT2ri3QQuj/72046XqBMybd351vAwqy04kq/upV+JzbDAJcP700R20jyiLLP30UeJ
         0jHD3Iejn4ABBIxrqHG6mg2jpVI7fXW5hOdfQQHcB5Une+FY4QsBrLKU4R3f27IWZZzq
         LpXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EhGKrIQd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766493694; x=1767098494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=VD586ImevohgoVlCfNZkBOx0xQbrxRNg3qHeOa4t++s=;
        b=uPY029LZ4Mi+aMm9q7yphHGjVtJ4UD1FOlyejgWxJ2qrwmsNzQgIZ93yNCyRZxnSgN
         hhQhVjUZF59JKZNZ9aMk1zw/72dq5WqKDMa3RevNF0HuHbju79i8m2MLrCfiAiZrlt42
         ZO3kpL9wjw+dAvOpwSWe7UNYgMTZJCWRRTpKDT+E+iP8x7pHsxSP94q3oIuWh00vtdPc
         o9IRVxh+kJtavFu9xhJw6KuW1tOevvl09rBmkVVnjbpIbgSTCI2Vi1XEEGkPSLGhVgyD
         KBTvIKXP1bFRug+A/GO5sPh5PNZdYCKXwispm2fwjIl3nJxIXzI6KkkXuq0cxGis7h3c
         vSzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766493694; x=1767098494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VD586ImevohgoVlCfNZkBOx0xQbrxRNg3qHeOa4t++s=;
        b=awU+CGErX5ZGIMU3BlR/qBGijEJoeVT2KWAM8yMBF82b0sDlKL8vxZtmVS2eoTRlRD
         ZsQ4cSZ5Z95/LdIWBlbxWP/bIG4xyOqkLbypTQOcoVZ3pmhP/0s6f1FJ5rOGAF3vk22p
         Ap1usq/ZYNU4moOpktt3KPcNpHlXB0YE/FQlqJoNy9IYJCW2V8imnpLayXOkhTlT5hDt
         VuaXcZrmr2sH3SEGYHxJV8OOGuIElzUCEG1/clT9cGwKEZO3UidUs+AIGaqYnM8w/85U
         45h2ucS9LE01DUya2gcG9+PP/QXx6nhHHP5Bxqsafns3dN8ao8jPOoJENeDPR38Qz9f7
         Wr1Q==
X-Forwarded-Encrypted: i=2; AJvYcCVjbNx6ipmmGjHFUSwZV/HImfw0qVccTywPgi/tQ9Rrr+lROBaC5MrOVNc1FyYFNI2sv2dw1Q==@lfdr.de
X-Gm-Message-State: AOJu0YxZDexzmFG860t93fgE+yfDq8jFT3VlikM8KsEyCcmuQWDgAg9G
	v0Oh6CVMMyXA6bPTsq1b9TirUYx9+4jcgUjsRwhfD4KmNLZh+HitSihX
X-Google-Smtp-Source: AGHT+IGvcNRFf/9ZRQA3p+XAVmjz0O9VrvVQnqPAyaqJJ7Nz62YaM2FxeHVMDt06YfraOXsA8IcPCg==
X-Received: by 2002:a05:6214:da7:b0:880:854:908f with SMTP id 6a1803df08f44-88d833b6996mr257700306d6.38.1766493694093;
        Tue, 23 Dec 2025 04:41:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa2ogSnNoKfpk0tDJrVoEHRS1YLc933XPQiaQaNSOQx0A=="
Received: by 2002:a05:6214:3005:b0:882:3ab0:1d93 with SMTP id
 6a1803df08f44-8887c96673als224745996d6.0.-pod-prod-02-us; Tue, 23 Dec 2025
 04:41:33 -0800 (PST)
X-Received: by 2002:a05:6122:208f:b0:55f:e72a:7fae with SMTP id 71dfb90a1353d-5615be4af30mr4513595e0c.16.1766493693065;
        Tue, 23 Dec 2025 04:41:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766493693; cv=none;
        d=google.com; s=arc-20240605;
        b=O6WBnkufpdCT9NSQavoYjbIeUshz+NuEbR/O3nYn2VP7Y8MFTuD4oGMMcsnVBczYBN
         Hcw0jB64NdYl6oV4kdgzqZX9S7f+I0rhVEOUZaW/NbkXRru/yA1NuHlYC6TqZ+JZotGY
         oD5rN4uia80vAcCtDMiEIAkakgxdXq32ykjXQsaBE7uXY6QtvIHT2Pg0v0075aSKAZvl
         4OycjZLnxz1bJgC75z7GJjIvJiw8ZQkac0Tyye9qQDG/4xK4GNwh365jf+zeJ9/ewysI
         8b7sz1fNVjnt9YmFBA3n+tTqOsjxatCXJ24ahsH/cUrA/zUAL9WJM5s4gHmikFq8GKF7
         /9Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Hw4QlkubJ/PY6EpoflLQU5G/F+gaq6L58UqOARz+KlY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Gphfol2T61eAvTBLyLedH8H9RjZsxKe5cZOiT1vv235RB8gwrChyE4rjl4HVK1rKxv
         OjS+jmM1T18TwSb7ZQwG3zMZ3I3zrpzRp6S3efnXSvPSV3CS4aoRhMUDMRrRmLEOnRXH
         E4jFIyjqgyDY/vE+Yza5yHD/OuCoi7hSsPsYhbKGl4Wca9OfYKm1as5nCGuPfKfZL6iy
         IfgIsGqTFVP77HYoVaMXCLaB2qY2sXLI/+TzD80o6RS5lyZNYsNJnUt/cCcKnGPHXYcO
         eeB6/MXblXFptcU5i+AN8+ff/tHjbsrU9LcNuNc8XbSl4Ronz1O2nwkdpq6dIvNEh4Y3
         T9yw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EhGKrIQd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d0b292asi310726e0c.1.2025.12.23.04.41.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Dec 2025 04:41:33 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 1DF3F439DC
	for <kasan-dev@googlegroups.com>; Tue, 23 Dec 2025 12:41:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F12ACC116D0
	for <kasan-dev@googlegroups.com>; Tue, 23 Dec 2025 12:41:31 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E14C5C53BC7; Tue, 23 Dec 2025 12:41:31 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Tue, 23 Dec 2025 12:41:31 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: joonki.min@samsung.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-220889-199747-BM3hjBELPS@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EhGKrIQd;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=220889

--- Comment #5 from joonki.min@samsung.com ---

When "old_size" value is a multiple of 8(which is in the granule_mask range),
panic on warn occurred in kasan_unpoison().


[   79.334574][  T827] bpf_patch_insn_data: insn_aux_data size realloc at
abffffc08ef41000 to 330
[   79.334919][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c00000

[   79.335151][  T827] bpf_patch_insn_data: insn_aux_data size realloc at
55ffffc0a9c00000 to 331
[   79.336331][  T827] vrealloc_node_align_noprof: p=55ffffc0a9c00000
old_size=7170
[   79.343898][  T827] vrealloc_node_align_noprof: size=71c8 alloced_size=8000
[   79.350782][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c00000

[   79.357591][  T827] bpf_patch_insn_data: insn_aux_data size realloc at
55ffffc0a9c00000 to 332
[   79.366174][  T827] vrealloc_node_align_noprof: p=55ffffc0a9c00000
old_size=71c8
[   79.373588][  T827] vrealloc_node_align_noprof: size=7220 alloced_size=8000
[   79.380485][  T827] kasan_unpoison: after kasan_reset_tag
addr=ffffffc0a9c071c8(granule mask=f)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-BM3hjBELPS%40https.bugzilla.kernel.org/.
