Return-Path: <kasan-dev+bncBAABB7ORUXFAMGQEM2SOCIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FA76CD69E7
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 16:51:27 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-88a2e9e09e6sf137123856d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 07:51:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766418686; cv=pass;
        d=google.com; s=arc-20240605;
        b=jtZz83IdcG8+xL/e61jeOeEFDfJJcyjJtp4ueo4JqV3duFdQZpph+Y056lVvfq0ot9
         KHBeV0keZ4OLPdbl9IiOQzEG+wSrgkYC/C9o+MyEC1h/1FPQKfXJm7rFakg2ByJclRF0
         xh9UEMHIQF7ub/TaB/yhSU0UuFlQgZOi0GTrPnjy/9tfXei0A6T9kz0ME21p0LUft+Uc
         S9Xd/tgaSj/nrG+JrL7rm2DmrcBAQq5p84EI3ds3xGWCYXqpPYv8qmdEWsQUiOM2S2LQ
         LvmjxSnum1wQr9A/3I/yu3YZNnVgHuxidx+aLBwgP3cHN0oQnfk+THDJma0ASwlVV/I6
         pzpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=z+XSQZ6GAAbeTxo3YHwqyMck0bI/vPS3jIDEXEi8C5A=;
        fh=HF+759Qt/aDFzwSFuhyWrx5PCShg02pGNefrJScTKXI=;
        b=N6qVKPaf2diq5y+Ze+iJB35XtYWAHjNTDR9IfJ3Kr9lJOaluB34yxtCyhNdsy/FguP
         mQZZVo48IO16nYiXt5m/Dyu0eDcDb/oYw/WiCMVKTzYyq3m7DaxlJDK6+/IB+qT67tGV
         wraB7MrjCGpuCec55s/FP0GixDTm2n8jQMjmHONwdeVf5qF/LQtXh5q9YBynDidxToKH
         ZR94jNsAX6N3ggGMapZ0jm6ubVYGcwdpmYcqxLJNv3l93vOuHQ29IIYo6S0j+3yOjvnn
         lmEXjBDVYhbvt1kEPqy43GdQvhwzrmt2AjnRQRyCscreS91fu4VR0ij0hR8gaBm0QTSo
         MGpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IUQUPXYj;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766418686; x=1767023486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=z+XSQZ6GAAbeTxo3YHwqyMck0bI/vPS3jIDEXEi8C5A=;
        b=PjKjO/3ufc1v4ikEFWmlomg+ZnijW+f5rtDZfvhjIBx9qTRqYlf6yRKAhuVpnXxu8B
         ZkuplGGIuT5NPSnbIsrRSFCCJUADpRYVcU9A2sI99WkL7KqExF0HCcMCB+GrH13WIm6m
         c1GnpwtwpC4slHk1Pp1G7VR/QkFFHZbQwHVIpe0v5z7wrawDXfhEPF5GQjU+0ppMe3in
         5W5moeEQ0xbH9AW8MOtpRqPayaooSkjykafw93bai6Y7pCUEYx1FZw8Ay8KOHoW9hB7o
         B+pcZg4/TyIDXwBDeqP3lRIKPAEf0HctrMLZZ7LRajn3Mse6i3qxUArS2csiR/FFdDoT
         UNvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766418686; x=1767023486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z+XSQZ6GAAbeTxo3YHwqyMck0bI/vPS3jIDEXEi8C5A=;
        b=ax3d0BUBiLM8NwUxiH4eQNms6sGLwS071CDylgYNAdpd5KYygmkPXL+DmO4Tz1gQBl
         AIYTKoeDUS4K9BRm/cEmAD5ms5SdKK35r7z3otKt4UaDKZH43T778z2mNkZAbuJQIcBs
         68sBStBRIpbNyaWuBkLWgOrIQJ7YfqjGqkUZDR5IpRs6T/UhpT2FMD893YR+WmZgjdvq
         UU6xsTxrHEhGdwlu+XNE54RHwkC9JwWRjbvN+f6+4kIslxnjoXljEhKJsgSz4gu3ww/9
         FFZkmtP89uEwAiWs+ioxUNWtalg4XRimDm1DLMCRwI5+hh6Sk1QVZnHx8gHRxb9DWtoK
         IL+Q==
X-Forwarded-Encrypted: i=2; AJvYcCU47SSCH1/ZhR9Rg+tsBQKhceUOnMdohdy7UrueBqTHFhbIsHbU+VPhcWmaj80SW/7tcuphUA==@lfdr.de
X-Gm-Message-State: AOJu0YwTk7K9ib5l+ukSrojJOT9W+2Ub6IpmekDal9IDnZE5ZpCyGd68
	YTmfhcmW1ZhkMBWwvdy15AEU0AwPM36p2uSYWZzfzgKAc/FgLEqb2J+v
X-Google-Smtp-Source: AGHT+IHU2dJUjK5r+Y+cJlIQgdFdTrF7Dp6jFxRAqDc/iu1cSznyqKph4TbqSzfWTVBSjMZDOvWWJA==
X-Received: by 2002:a05:6214:328e:b0:889:7c5b:8134 with SMTP id 6a1803df08f44-88d82138446mr185067246d6.27.1766418685925;
        Mon, 22 Dec 2025 07:51:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaaUnEptPKMY4YDrrwf21ozBJtwR95AR8lCnPSNVZAl2w=="
Received: by 2002:a05:6214:4006:b0:888:57c0:3d18 with SMTP id
 6a1803df08f44-8887cd70dc4ls178656246d6.1.-pod-prod-04-us; Mon, 22 Dec 2025
 07:51:25 -0800 (PST)
X-Received: by 2002:a05:6122:a1b:b0:55b:14ec:6fb9 with SMTP id 71dfb90a1353d-5615be767d9mr3424059e0c.14.1766418684877;
        Mon, 22 Dec 2025 07:51:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766418684; cv=none;
        d=google.com; s=arc-20240605;
        b=T1BLwso3o4jeT0ic10pE/PL77yaRFe7h/JI1vmpQRY/FxxxW0KJLniKeWWNNznread
         V+8kY2gpNCE/QPOWTp9Vo3q3Ogbc45KnaKnwrGdPBHATr/cS4mk0/YmeR/obS7aZdgzS
         IeuwDUSfCmvc5kEV7Ifcl/oIgoVb/ItRNIFx0fvK7I1PHpnNidJj51jC2peXULAalaT7
         FYrG7c2CNAqs5xkEFNZdsnwKgSfROu2A3Rq0o0qkzeN/qZ/nFbrxEd0sNU4WvwAjlxci
         yioi+DrNLDH3DHzqz4OtRf719ulTYKEd9VKIInJJrWooXSI1VkVJr/BWAsigTjwrsdF5
         Vfcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=oDam6C1Tqc7XmYkGeHGQv5M1fCvQwI6RldxjkewiHiA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=AFNXKRxCPL65kMtHmqkgWX6gjl/DH2pCpko413NQEtgsru/nSNuFy2NBMDhkjx7+Qj
         QVluAQlbyos2QVONsaiLnTUuReuTPZTFZJgMdekDbVB3+TP27LTNtFhAjVubb9o4WqD0
         OYPpTVOKrmhfovQYrdZ5TV3SlSBVnzXoKDsvUoOii5dW0eyktcKLdJ/7GW+PzkQTXVhf
         MyaQC80dohUA7/M5FpgnTvTuD5r5mzXoQ6uyhudQt9qGu1ADP1JJpQzn64CCMop2pyg2
         eu9vRGhDJZKkGj1xcEXQrYQMkMq3eHbpOfZKfoHB+XuPF67evohsjKid6KNefAfHKLF4
         h3kg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IUQUPXYj;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d1ebb99si322950e0c.3.2025.12.22.07.51.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 07:51:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 40AB760157
	for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 15:51:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id EFC62C19422
	for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 15:51:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E2CACC53BC5; Mon, 22 Dec 2025 15:51:23 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Mon, 22 Dec 2025 15:51:23 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-220889-199747-pmutS7IKLZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IUQUPXYj;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
These patches likely fix the issue:

https://lore.kernel.org/linux-mm/cover.1765978969.git.m.wieczorretman@pm.me/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-pmutS7IKLZ%40https.bugzilla.kernel.org/.
