Return-Path: <kasan-dev+bncBAABBDGO4CUQMGQE6ACYQBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E43287D5C53
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 22:20:30 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-27d11401561sf4171119a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 13:20:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698178829; cv=pass;
        d=google.com; s=arc-20160816;
        b=GKOyTBhqYptN7dw4qXGy3a/YH6L7kih1h7d61sbF9S/kmDAwR/Yc53GbZXoJ77+w3f
         zErPE+o/hfZe4twHQwB64WkIsMJkDGT48LFTs14jA2UdPhpKnP/5B48EmtE2ZWNoO9vf
         ZjOJbvNarvTBL74aMkc7zt3WqWtoLBP2gjYVznKN2tWyCIsLN2BvNPPxubqVQpBZGReo
         mgN12oUWxNCb6Q7VZ7bbVTHAj041ZewwU/AIQ/61NWzhJ4K2Lyz0OmcwQEAI/IU0kU/X
         0k7HdOx9nkejTK8BI+e+JqZF+mwPaIfMY4C82v/IDHJp/METy75GC2ghebfT7qEnPqig
         j6/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=2y/+JsCjNoN4XpSW9qxeTxrElZIXyk8Tj+s2pAnOqME=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=a0Jrh5mO2lAdrkPVoV8ZZyHWD9pO9vHocNNVnf4Llk1wfjkb8kM3QXnf3HwTqs4uEF
         wasmxDSwRkFUoy+WSzuQvBf7IzaclZbnGVdcV1CYKot1rNLP/IvWuBGfWmVdRouU1QWe
         XqtgCiB/7HnyczOQYK4agouuNDNi/fDR+ToaN1yMjZVc+0x9PH1bEtLK783lmNc3PN4B
         S3345nLbdBZeHiLuC3ItyBSiIS+EP34c59qBqy94H5fN2Xp5WEV/10kdwtM7Ohv0jIPV
         QQ3aRi4rxRb2wvj0Gz++b3slCb9eU1NGIBWoHpTCdLyO7GiXJ1Gg95CP3DoH0tboelXp
         ZvCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MRf1u41N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698178829; x=1698783629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2y/+JsCjNoN4XpSW9qxeTxrElZIXyk8Tj+s2pAnOqME=;
        b=ms4RF9ndZw84BnCuAV9VmOhoZ4BHtsoHW8T9lPgNJlUbhWAmKKAr4y2H5T33qVXMD5
         NtJM+TKtt0OZA9+xAJHyCSPtDWloE6+he/h59B6AXuA3WYZZKIVCATqtl/5VT9GDF3gA
         5wEtE4I34/Nu8pkTa+WAVylSBDvRcdlrJeRRX1oY1bkLKNcglRDQgDVFhrwPbhn3F4nO
         +Wu7FYm/njxvemGz5Agzm/znrMZZaMTCJ2p29YustT3+l3M3QL/W5zAnqedN0hylQywE
         bSHVPjgFD/Dhxy+GeMeMaYVhI5esV2tjdNhJ0oJVUPPMxqBrOIQkd8nkX841lA2XDXQo
         vzZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698178829; x=1698783629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2y/+JsCjNoN4XpSW9qxeTxrElZIXyk8Tj+s2pAnOqME=;
        b=cyRU21AjtBQs9OvxPCQlXN+SbTpPJhlwOqVh2j/qowSwD9iBRRM6/wQxbhskkUFRyY
         OI772r2PJGUvukqPAd9zBMNuqUmww4btj7xY8QDj9rPltNsB+ViqHlkpzMC4azq0JXyu
         eje7bO5aZ6jMm9saFbQCRtb25jfCK6GamvXEHLiNrlBpOLrHHwtjZ2aa/BiwfR0XAg0E
         PoKb2rVDClxSX81joxqlbx9PSYhXMDJkVU+RadMXKYiKgNTgvtCklybx6qCQ8lJpai4V
         2LklTbMd7vlXPzOxprFtM8AAkJkSX3G+qtTw37NGKPq4IvgiDyViwuyqdkHwfjt8wml/
         sadw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyRFoGIn0oBjAGoRYfEqcZtmGzoZWDA7lqQtqivfxZ4OMZEWErc
	p3hJcxcR3z7WDen9tSC4CVg=
X-Google-Smtp-Source: AGHT+IHVIhVG8PCFLYmK1CMe4ZUwCdeXIP8mcYAeACGlmrBF1uyD7SayZzkWEAccGtJ+68fB9OmGxg==
X-Received: by 2002:a17:90a:1648:b0:27d:51c4:1681 with SMTP id x8-20020a17090a164800b0027d51c41681mr10643640pje.18.1698178828996;
        Tue, 24 Oct 2023 13:20:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b90:b0:277:4dc8:8ca2 with SMTP id
 pc16-20020a17090b3b9000b002774dc88ca2ls351331pjb.1.-pod-prod-09-us; Tue, 24
 Oct 2023 13:20:28 -0700 (PDT)
X-Received: by 2002:a17:90a:1918:b0:27d:2371:9f74 with SMTP id 24-20020a17090a191800b0027d23719f74mr11214326pjg.0.1698178828106;
        Tue, 24 Oct 2023 13:20:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698178828; cv=none;
        d=google.com; s=arc-20160816;
        b=tGh42/Ymf/cgLyvhCG4OKZwIxSsDpKAP/gzCtX2YN22OHxK14egcdhy1+7r+W47E65
         I85uGIpG+KVkytv2lEexdXk6kCSwORdawCGV5ZZWROQgQIeqT3zGHh65xERyUAwcYo/i
         TtmKr46eb2FK3z/Z26WSjDBC4ndaRgttVvPb+8bSwG6E/xkXy0hB2w6+ToMIi/lwBN4h
         2RNtmDUubz/tv4jv2w9LHS9wpc288dJwi/4LcXwHGen6bkqOkZezSRdruJ2SYToD+qSO
         8m+4QKn36SxaISPGBXNsQmPXNEUFIPvXV7Y8wXTQMkmiuSWQIDtqVPAu7Kp4LzxLh1xx
         yTQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=d+VhLGWQYe/TvqPPLRbxxsFn+NlhlHmaDIwe5np7/lc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=DpDDzp8Veh2ZF0lPe/02iow5sBfIxss2mB/SRvoEIYBk6y5FCpxHLw5vwGRbSjpk0m
         B6iUu3zTAqxKXOtb6SK5c0G4e/6LWT/B1w6/KvEEUCtiEqv+n9XSFKlNQ59AIq2VqRB1
         zIx1u8aNpCzsjmA+jHoLo6H2TLG8n7jiruxlu5i0PF0qQBI05uWy/14LfSQZMBLa0xRH
         9vlJGWMPAziLL5lfXLxNozXRDlsz9XUzvQQaJt4Xgo5hRNzRjqWAahDw13UzeJpzDYCj
         d8pe3/xGmWmUDa+aMH0Daq4L3/lTQDob85d4vYfZ7pmt11ovOnz5ewKoEUusBfa7dKgw
         TI0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MRf1u41N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ci9-20020a17090afc8900b0026d54cdea99si96917pjb.0.2023.10.24.13.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 13:20:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 619EA60F1B
	for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 20:20:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 0FD43C433C9
	for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 20:20:27 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id F1106C53BD0; Tue, 24 Oct 2023 20:20:26 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211517] KASAN (sw-tags): support GCC
Date: Tue, 24 Oct 2023 20:20:26 +0000
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
Message-ID: <bug-211517-199747-8J7NanADZM@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211517-199747@https.bugzilla.kernel.org/>
References: <bug-211517-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MRf1u41N;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211517

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
GCC support for SW_TAGS was added in [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5c595ac4c776c44b5c59de22ab43b3fe256d9fbb

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211517-199747-8J7NanADZM%40https.bugzilla.kernel.org/.
