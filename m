Return-Path: <kasan-dev+bncBC24VNFHTMIBBHNPT2BAMGQE7FZA5NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 7333B332ACE
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 16:43:26 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id j2sf5293843qtv.10
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 07:43:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615304605; cv=pass;
        d=google.com; s=arc-20160816;
        b=A8QiWOBgK1NGQsedwpl1OyT+gltMF1xN+ud0Gik/mNu51bRzidqKcapIRxo5XyrjTL
         MLM2nM+eI4PtspI8Sa0D80ZRde2kae0/+JztFDBiZKMhOq6qc7o+XFR+2vhlDXRX4eWM
         XTJIZfU9yiT+NePV+jiCu1a4I67OjfF5xGDo0qJ86gySYbSqy+Vy3hHBF1QT6jzHQcO7
         Pe9AXyYheRpEHhIircDrPJZ8N3IfNr/Wahyaxve84DakPkAgWa+g6IVG6tzN4ruEsnpn
         lJFuRKQ5NGXDACuVobuN96M9pCrts/JkPGIhJKMm9uf7btAK6/66awpOGnthIgSK8G00
         Mc7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=tkuaXsfEBvfJv761q1e5QX3nm6G0fcjJKAsaMHa/7P0=;
        b=JtBatAmDceKVWRsq6WqzRStwd4HsQG1IGCLGc9+ys/1xoZWMfwI2Dgbdr50l+6lO0n
         jYdHW0zoOXD8Wh/29ztzBG/7CmvsKAZ32UTtnHac6qEfFS1y4cT/HhSUEAK8TieUc0Mt
         p0gKrSvg5JvXXUPKb5ZBwP6ScAMkyvWFrS0kVoxdgyR4RyEhYWCPXTFbfh4Vs5VLkykB
         6QqvioGXVEfLKTSLoRx0cVG8xFJFq9SiU2MJ8gg3bhI6h+Xa9Fp9FykIBm0NuuavbFF6
         gjoRkkShKujRtozJgk8tAocubaVaLXC1B5FY3zISWp4ZxFCdW/ILwBr8fHgR+vLi1aXs
         QWVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pH8YJvjk;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tkuaXsfEBvfJv761q1e5QX3nm6G0fcjJKAsaMHa/7P0=;
        b=jynpcpLR9VBKdUXEqbgywVdhYMtpoescX2S32jBfbSIttuJ7COzgZtH/7ZeoIag7Hb
         1Ors81nbmABlbaRMyAAkLzpy1qxJVCtxVjf+yzo3N1JsavCTPYlBYmeVHTTE1UEdRonV
         ARdzYaHHZfejRU+vzz8VXI5w+is6AJOmbhmCR6xAFdep1cldLlqPIM0n0ZyPoyZz1MWh
         IK4BiRR7+qvzcDeM4RafTt1p3mLcWxg3m/caT0Awwkt4Ja97J6kJEfkgT02CKrFm4qC6
         TKEVlZT2oIogiab6ZYYxF7Nni707aMFDMhgxKZ5zECj7RMlT51ABcGKV7ic2optrFcfF
         uXVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tkuaXsfEBvfJv761q1e5QX3nm6G0fcjJKAsaMHa/7P0=;
        b=kp3hevcPmFYvSL2rAq3qSNTasdJ/3NQpGkozuXDm9N8BvwetC3inXzJGZZGdh9ogoJ
         mD5MmH89hImxrHNI+SOIDwk2ht43FKPvUL/2GtGMIugMS7q1Z+AzZNp95KiJQkxcsrQX
         BsvyRiaHIf1FAujLCcDfnp0mZLpnVY0/8cgiY/e9QQeoxx4Rg5yY+w8IpaOww9cZDAVg
         WhEiDrRlJ5dBuoamwM+5tJG6M5q8RUPAuq/RHzyDsD274XvFDyX7cnrbNz8K+ehAEodc
         2py5WsDNl5BLTSpW4GYk2og2KKRNAaoOHu93TqnG44KeAJmokNz9H++1VKdYIzIvDOts
         1PCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hXeIAXQeTXOZAuJaev71+FU3zCb/jpGO7K+fXdzglJv31yTCF
	UARM+SXcOXG6bgKjO/OrE30=
X-Google-Smtp-Source: ABdhPJwRkEfbINBnTJB9aJ06caRpEglFf9TjLW++vbUvi9375y4gTzl5RVKDwjxo8qr+I7AR9wI/7A==
X-Received: by 2002:aed:38a6:: with SMTP id k35mr23264260qte.280.1615304605573;
        Tue, 09 Mar 2021 07:43:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6b03:: with SMTP id w3ls5632200qts.11.gmail; Tue, 09 Mar
 2021 07:43:24 -0800 (PST)
X-Received: by 2002:ac8:4406:: with SMTP id j6mr1250393qtn.180.1615304604882;
        Tue, 09 Mar 2021 07:43:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615304604; cv=none;
        d=google.com; s=arc-20160816;
        b=rn9BAnNRZ9DoAkffVBrqEUR9Vk35LqbA9z0xGD7wJZ8z23tJTknxK4oCZ+3PCMeSL6
         pogUUm0bBQjkPoV3O3elQ9kgVvkKsW15qCZNxJkv4uKkKfQEHgAKrCCd1ubfQC7iNQw4
         MXsr7zRPW7/12CSeIMirY/CZV0sPzMbh2chuX8M3N8eyxw4/4HfQgPTGACquAaZz1vyS
         3gggxgkIqTH2JZl5iiTwVwwEs7ECeS76vNwCC0nTOWvFkpXI/OSBfKRRhJX1Hu5gTMhr
         3S2IjSEIeKgNuuqRudqd12ICn7wgitPZg9apPX+oHuTcZMOmEIyjGce8kgGCYFla37Vq
         jM8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=dVHfrsPerYHZAvFBlZJL6Qe7Njc9W5gGQsS7qcAYKIE=;
        b=hppb1JGPSv8Bw++txrAG+/VCH7gjjthhpMIkHDFaASXu5X+g3sEp+rIzruneo2J2O7
         0gdH+eWLU/xM1vSuySrZFfQh3ISm+w5SXfZ6zE7Y62LSqeXDzcy48aVsFA2voXG885FS
         9PY7V9b10vbLSXdVC7LXjV50uvnq4mw0hSW3Om51yu3FHQZUVOKA6KzWODiN8NC4rIEp
         biu2RQB9uMlJRvtYK+nbIiy92DW3zXHI870nN927BnbIY/zh63md6A0nbTELxgz1lXm7
         7rtKSwSfNTgPOFVo4jmJROYsFkV0HYHZAXx/c7Y7jlPHKBZnuLjxtu6/Laxbj7ahoM07
         vcRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pH8YJvjk;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g4si759972qtg.3.2021.03.09.07.43.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 07:43:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9B977651B2
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 15:43:23 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 8793365349; Tue,  9 Mar 2021 15:43:23 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212193] New: KASAN: better invalid-free report header
Date: Tue, 09 Mar 2021 15:43:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-212193-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pH8YJvjk;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212193

            Bug ID: 212193
           Summary: KASAN: better invalid-free report header
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
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, KASAN describes all invalid-free/double-free bugs as "double-free or
invalid-free". This is redundant. KASAN should either use "invalid-free" for
all of such bugs, or use "double-free" when a double-free is a more likely
cause (the address that's being freed points to the start of an object) and use
"invalid-free" otherwise.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212193-199747%40https.bugzilla.kernel.org/.
