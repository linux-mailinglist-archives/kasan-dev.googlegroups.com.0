Return-Path: <kasan-dev+bncBAABBKHZVDFAMGQE2XMX5AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id AC768CD84C8
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 07:54:34 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7b90740249dsf8197052b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 22:54:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766472873; cv=pass;
        d=google.com; s=arc-20240605;
        b=WJQjAsFpjd1JyVPN6sE28y5xMvPJpP4PWn5zHWtr66QVC0HTqdEh3CueF7RKjcMSgI
         Hw2AgDvqRGyR32x7mIuuPcS03LhowHA4+esT47vnvq7xb6H0RpMQMj58S5PjFKO5YCni
         GcJJbIX3K9KplMAhFqvhIoDAPIwb8p2ZbGcrkfK3yD+XViupDT3fCaaPkBXA4DSZOkmM
         crpnUjlhjxUizixvXfEz7e0fFqAgH8N5+dy/bS5XfrAdVXuS46Lhv8nEXssXpcuk+W7c
         /LqyeGwDhHcdDRQs1c8yoXH9rUcSfBBH2rSRYFXFQaASKh6uYmc469jW0kBYMNa0P1ol
         wc/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=nnyUFro6kNbGKqbAzYKdyPy4OlR9PR9/cXJZ9mgrHoo=;
        fh=EEI0b/x7WGKv0TBx+Svp+l0I9k1kA2hofOHaGvCQqjU=;
        b=dE43pLMyKPpJ23px/r64XyUSIrs1wPW1hXwTKydAGNXw+YxlUHIm3cBkf+1ItNL/CJ
         d++Fm1AlkLiegi7N8VHL6NDmi0aWDao80XEzn7yHUCEPCtmgQOXvW8rQOgPJ7nY9BHKc
         bzkUxncVrwcWfPVgCyjMd1XPMPoCmzQDRaGP5NQgXXiP21G9kf9dgcMXi5kD7nAojlfW
         GBLJKdjAunP2M9yH1U91Yj2dyvKtg0n/WCiA4BTtlgvNhOqBs8zEyMugotrzdtNdRvdW
         lfIzOIkhKDOURXaUksDkm0xgcFsL42o1PyTnH3IyucHJdKY+LNqaxiTWh+t7zw4kQdB6
         sbeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gKkJuFH5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766472873; x=1767077673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=nnyUFro6kNbGKqbAzYKdyPy4OlR9PR9/cXJZ9mgrHoo=;
        b=EypQ4+YtmVogmLgxyly+zZz0XduNT6F6EEIswsF5JPY4ATqAnh8hFKZMs0FWNoxoHN
         3YuNNjvQDpuAv/jWoAQjE/l2VFzaUQDGqJmpV9K6wLn41o88aBvTFa3ABpBTMhxrMKia
         n6UUJqqTLAKDEkffCJ9AwezTKMu9d87D5Y38q3dBaT2TXcgUimuxt8EI92AkbGjlUDn4
         kN0TYrt58pETiTRkM8JYsoHjRDyiEdXq+ZfffvmUHBcCH7/A4FQqCXsBeDkHbJ3ryLYf
         0XrZBRzHk+sESznttzG63OchB8xPMVJlolPzNSnv79KucUZD2KB5VSo6i7BO6gZKezYk
         Xb2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766472873; x=1767077673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nnyUFro6kNbGKqbAzYKdyPy4OlR9PR9/cXJZ9mgrHoo=;
        b=McV6/dHpklOPEwqtx0hB3xHxdDGzgblP7+9DDYKHlyszVLu9ETLBCKwqHDUja9Bj4q
         ubFEWtcUvGGlazUglLaoOvHfaqmKGM/5/Qslry2LRo5+SBuHb5edJRf/szDZcDuUkb4V
         nAfJ0TQ7AnVjktLZdTqMNX322wHEUJjE9WcqR2XAGKLP8Kj5PwEvE6BGGCk+UmVHLQEd
         QZgSPYeodvTFl4d7UtpXaiT213Et4BjoBgYqmOVSPDLY6EcFxOp4RzYLHUsOsvruitmG
         yYZJRxC9ZB6BFTBHgCkSYZuYBUv8uTdLu5qqNjsg0v8c66sXfE2vS1EqAq56eS3dmr11
         u6eQ==
X-Forwarded-Encrypted: i=2; AJvYcCVktc4W2NYgBzGm88eI3yh+UokmvnyKCX0n68435M+gIaSaQaov8wK87MUMprGl/YWbIf/yOA==@lfdr.de
X-Gm-Message-State: AOJu0Yy4LSa9TXeB8mzY4VewWsXMOjrg74/kSpz6J9ZVlvTwjteBe4kw
	96WTuRlUwklZJZYxcjxr5/9h2BuxHmTrkMv1Mv6W6ic0PKLEIZZxQa0W
X-Google-Smtp-Source: AGHT+IEOWBMli1rd/I4dkVx/CwAxa01GjrQUHn+pxXILVQUjak08XIt8xafZmaKR4u5M4LpJ+kHhdQ==
X-Received: by 2002:a05:6a00:3002:b0:7ab:8d8a:1006 with SMTP id d2e1a72fcca58-7ff644011fbmr9604424b3a.2.1766472872720;
        Mon, 22 Dec 2025 22:54:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbadTkm8LFCd6Ld0R/y+d0Jio5wDAzuaVu7fJWmnVkJGg=="
Received: by 2002:a05:6a00:4285:b0:7f1:9aaa:f35 with SMTP id
 d2e1a72fcca58-7f6455dd3b0ls12390075b3a.0.-pod-prod-01-us; Mon, 22 Dec 2025
 22:54:31 -0800 (PST)
X-Received: by 2002:a05:6a20:6a24:b0:361:4f82:e545 with SMTP id adf61e73a8af0-376aa300e2emr12908156637.53.1766472871554;
        Mon, 22 Dec 2025 22:54:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766472871; cv=none;
        d=google.com; s=arc-20240605;
        b=M2nkNgWmLKPQ7veuHf3x3NdasXbHcwbjPYxeUCWQdDwlERp7sAQCevpHbyxHUdPk3V
         9X9JumT190MfKfUGt9H3tK2rsBITmf9hsAF5/0bQirprBCwmAdcJNaOHOO5FOKnNeC4I
         AA7WmZOSErWLdw4RKYYvSSPJ+AlO5CF6KqSm2nHEBS0PmasZ2PjMWM4ihEcAMYk3AlYW
         31FKhhry9+ygDPpVviHQuRGb7s9YKKeohOJM9kMD+tXE7m4hjqu6NkXkNxjA3+Zs1Syy
         Q5NU7SJNsdj3Nv7cQixM7rf1jSrDaYFkIajeH5nGiSvxbmO/7enCGxCqznXwyqbz8yDT
         dStQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=UESpwXNH2Iaj6/tc6GAf/wa3H1K04Z4zSprpnXaa7tU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=DjslfdM+w/UJW9H2+jLzivAl0dSV0X8lEdD/ir+i5YKOq3kmKuePzS6BtBKO9h8/aW
         p4VH4q/KVMjs8J+Xebp9PtkdlMcwY5DcielJi7/FM9OdIHCGPURguLF6CDUjkSIREPqu
         L/QNs7ehqVt6CC93ce8pQlmzFf4MUWXfwXcGuo6hpL1qXmrXqpHCEKR4XysdLFbRgN4s
         91fcogANfeBSIrlOMjPHeaP9+MvJpnQWFWThaZcGJZBmZ4lNIADzpNGGWItWS1P7ANBP
         H7w/ZHaj6DwN89YUs66kFqhRuJEZTRWoxKTJDImvPHev/nlxbOXIYmd6SkfmoTcm80At
         QwWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gKkJuFH5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1e7952129csi482415a12.1.2025.12.22.22.54.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 22:54:31 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3D81F441E4
	for <kasan-dev@googlegroups.com>; Tue, 23 Dec 2025 06:54:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 21B41C19422
	for <kasan-dev@googlegroups.com>; Tue, 23 Dec 2025 06:54:31 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 18569C41612; Tue, 23 Dec 2025 06:54:31 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Tue, 23 Dec 2025 06:54:30 +0000
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
Message-ID: <bug-220889-199747-X2oLfGoS4n@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gKkJuFH5;       spf=pass
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

--- Comment #4 from joonki.min@samsung.com ---
After applying fixes, panic on warn occurred.

Did I missing something?


[   84.536021] [4:     netbpfload:  771] ------------[ cut here ]------------
[   84.536196] [4:     netbpfload:  771] WARNING: CPU: 4 PID: 771 at
mm/kasan/shadow.c:174 __kasan_unpoison_vmalloc+0x94/0xa0
....
[   84.773445] [4:     netbpfload:  771] CPU: 4 UID: 0 PID: 771 Comm:
netbpfload Tainted: G           OE       6.18.1-android17-0-g41be44edb8d5-4k #1
PREEMPT  70442b615e7d1d560808f482eb5d71810120225e
[   84.789323] [4:     netbpfload:  771] Tainted: [O]=OOT_MODULE,
[E]=UNSIGNED_MODULE
[   84.795311] [4:     netbpfload:  771] Hardware name: Samsung ERD9965 board
based on S5E9965 (DT)
[   84.802519] [4:     netbpfload:  771] pstate: 03402005 (nzcv daif +PAN -UAO
+TCO +DIT -SSBS BTYPE=--)
[   84.810152] [4:     netbpfload:  771] pc :
__kasan_unpoison_vmalloc+0x94/0xa0
[   84.815708] [4:     netbpfload:  771] lr :
__kasan_unpoison_vmalloc+0x24/0xa0
[   84.821264] [4:     netbpfload:  771] sp : ffffffc0a97e77a0
[   84.825256] [4:     netbpfload:  771] x29: ffffffc0a97e77a0 x28:
3bffff8837198670 x27: 0000000000008000
[   84.833069] [4:     netbpfload:  771] x26: 41ffff8837ef8e00 x25:
ffffffffffffffa8 x24: 00000000000071c8
[   84.840880] [4:     netbpfload:  771] x23: 0000000000000001 x22:
00000000ffffffff x21: 000000000000000e
[   84.848694] [4:     netbpfload:  771] x20: 0000000000000058 x19:
c3ffffc0a8f271c8 x18: ffffffc082f1c100
[   84.856504] [4:     netbpfload:  771] x17: 000000003688d116 x16:
000000003688d116 x15: ffffff8837efff80
[   84.864317] [4:     netbpfload:  771] x14: 0000000000000180 x13:
0000000000000000 x12: e6ffff8837eff700
[   84.872129] [4:     netbpfload:  771] x11: 0000000000000041 x10:
0000000000000000 x9 : fffffffebf800000
[   84.879941] [4:     netbpfload:  771] x8 : ffffffc0a8f271c8 x7 :
0000000000000000 x6 : ffffffc0805bef3c
[   84.887754] [4:     netbpfload:  771] x5 : 0000000000000000 x4 :
0000000000000000 x3 : ffffffc080234b6c
[   84.895566] [4:     netbpfload:  771] x2 : 000000000000000e x1 :
0000000000000058 x0 : 0000000000000001
[   84.903377] [4:     netbpfload:  771] Call trace:
[   84.906502] [4:     netbpfload:  771]  __kasan_unpoison_vmalloc+0x94/0xa0
(P)
[   84.912058] [4:     netbpfload:  771]  vrealloc_node_align_noprof+0xdc/0x2e4
[   84.917525] [4:     netbpfload:  771]  bpf_patch_insn_data+0xb0/0x378
[   84.922384] [4:     netbpfload:  771]  bpf_check+0x25a4/0x8ef0
[   84.926638] [4:     netbpfload:  771]  bpf_prog_load+0x8dc/0x990
[   84.931065] [4:     netbpfload:  771]  __sys_bpf+0x340/0x524
[   84.935145] [4:     netbpfload:  771]  __arm64_sys_bpf+0x48/0x64
[   84.939571] [4:     netbpfload:  771]  invoke_syscall+0x6c/0x13c
[   84.943997] [4:     netbpfload:  771]  el0_svc_common+0xf8/0x138
[   84.948426] [4:     netbpfload:  771]  do_el0_svc+0x30/0x40
[   84.952420] [4:     netbpfload:  771]  el0_svc+0x38/0x90
[   84.956151] [4:     netbpfload:  771]  el0t_64_sync_handler+0x68/0xdc
[   84.961011] [4:     netbpfload:  771]  el0t_64_sync+0x1b8/0x1bc
[   84.965355] [4:     netbpfload:  771] Kernel panic - not syncing: kernel:
panic_on_warn set ...

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-X2oLfGoS4n%40https.bugzilla.kernel.org/.
