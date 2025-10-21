Return-Path: <kasan-dev+bncBAABBV5E4DDQMGQEBHUEMXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B0AFBF92E9
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 01:08:09 +0200 (CEST)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-63e1eca302esf6251453d50.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Oct 2025 16:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761088087; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZMmUW2IqC0bvHWsEGBu08ugBOpW3Skg9vEbeaFgAkQIBvXC+I+zFUgfeBfZFDGxSDt
         qnYz4jRDgVfknsiXE1G50YNOwsxewlPLNDc2xoRhBCux9SupN/I9ozO0AEkXXw55clCz
         9gMIWPq0fr0oNkD6+66/1shjVrT0bk/9LRS5m8FW+P6++fO5yl3V3MztOM9Q7zFqWOIr
         9xwRzTRd34A3uU/rUwUrb75bxEOwLaPtRg+AKFixAyzvN6cUH7tLcalYisrGLGzpjW6s
         UqAPRroG12spQNYZvNsOoSmosXkmRnQw4xjr8FdqFpxmHVcl5CwkEf7sXSVkQCD3m2mr
         2B4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=q0ZZdUgxRPSUDbM4As8LiPP/Y+Aesqjf+2IJdQT+/2w=;
        fh=78uyYOCh1Pco+Jc+5VhwwRtDEZ0k2TIQgNzoQj6QP4o=;
        b=GJtTBaE/HbvPLKSp33EuJXRzaNfGTzhLsIFJ4dcl95hW2gv1oecdrUA2YD8V9egLs1
         OYqD1dMmCU+KafDw35nfJmvAvl9XzB6MKdDuORFIG/yD1KVouTjLWLCR3PSdzU3TDPcS
         nNMWchHYYmtZRxx7teG5Cpr4t6fGTZYxI+Z84A9xkd40lC7/g8qXy/E6R/BC8vanTO6L
         scufTitl9GMtyn1Seex+gxt7lLkkfYuUzIUvNId41uHQN9+2bpeGFzafQf1EHWPaVI6G
         6J3671abAAeZP93KgSKuL7p6HuplhRNQL6Pt/UBDe4JWtaI07fc97sYNOAdLByT+0bcn
         aFrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DSKnaPHF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761088087; x=1761692887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=q0ZZdUgxRPSUDbM4As8LiPP/Y+Aesqjf+2IJdQT+/2w=;
        b=QFptubSoJ6qFh0+3zPxKwxNfGlnPTXM88+MeU25IN4j8w7wu6MobPQQvMjEZJaYdtv
         vY/J5n80v8VnCxICSUQ01T5nNV9+3QSSpkadtckPkpUDBw5dfZ/gRCRpoeIu5dTJMu7T
         Qv0X5fghagRqW88JdKg5ux01nDNp3CC/wjW7bHfl5VbGxdgPBYY8AuZ7wxPT2zdl1G+6
         NkNreVr4eCXEn2BNEtQZMuFgqHnNOyM45mOQmd57aL2LO0+tCgnQDW+4Ovv56xk0jYVk
         hr2Kx9AunEJLXfFntdnwxF8skFgqlU+djDxJJApAQKBYT8ZIk7LgdqyrqL8c0TKo8MQ0
         9Z8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761088087; x=1761692887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q0ZZdUgxRPSUDbM4As8LiPP/Y+Aesqjf+2IJdQT+/2w=;
        b=uwyfQR7ylduIfW8UWCP4+FJBmlRdVVk/Zok10ZoRNAdmjDlV17AJ/k1zUbN22z9Lvt
         z4QsoKUU7D+faH5lv4kFZ+1FrYZt8psXtWPjvkL8xpfG2LaOMz4DnxDqyaQxn603En5x
         SnVL4lpu8XDOb1uoyns2cE63liXy4rh0amAORCIfggV/r/TyEsr99OjUYphXCWQmmOVk
         EyeEgap4gwTXELDxcQ38MPA2uEas+3EVyDOB70rChWseEBUCa4MI403Jx02Gvfh+BfdB
         BVEIVI9NG+cv00SJuelyp1ZqfKpg1orxQKL2CzaryxO3/RzJuH+wgwBKtZSFhwvxtP4H
         wACw==
X-Forwarded-Encrypted: i=2; AJvYcCXepIGYAX3Xzfge0zqnqKnvFMtM2k2IPLHlvtUG0PZPPJUUZytqfB0MK7SQepOHkY1veAsvbg==@lfdr.de
X-Gm-Message-State: AOJu0YxOHkEr+gfT4dWiaDuB3kmLSDu4T5mD7f8Rx1PnXbDiwZEUEvKC
	lsysKCqUQD+VzbJCBqznWLIPvmZV/AIiHM13ywNrmJX4i6WCjXu9nm5S
X-Google-Smtp-Source: AGHT+IHcsFxk6JWwtL/8OwvIS7NTpkNMelswWdUaa6qlXZfUM8rPsJEC+NQSG1FP7QQHrn65Agwibw==
X-Received: by 2002:a05:690e:150a:b0:63c:f478:a392 with SMTP id 956f58d0204a3-63e160e99a1mr14732949d50.6.1761088087415;
        Tue, 21 Oct 2025 16:08:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4YeDspqX2ztytr4ufDW9kDnqifLBEN5HdPLT44JDRXYQ=="
Received: by 2002:a53:b24d:0:b0:5f3:b6f7:98fb with SMTP id 956f58d0204a3-63e0d7ab9b8ls5555553d50.2.-pod-prod-09-us;
 Tue, 21 Oct 2025 16:08:06 -0700 (PDT)
X-Received: by 2002:a05:690e:4294:10b0:633:b356:236d with SMTP id 956f58d0204a3-63e1610cab9mr12944015d50.15.1761088086517;
        Tue, 21 Oct 2025 16:08:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761088086; cv=none;
        d=google.com; s=arc-20240605;
        b=JFFjylSqYKK2G5O5vLYSgUpH20e8z4A2rhHNJ8JZbZk5Q4qzUAn48DcJ+QwM22znTe
         rUkRRYt3LgMZbTDDIkaYP6l/yowdLjsNnyJrN5PegpEGZ3Rj1gt6APwRjeycCafE4jZg
         8YWXdXYnhPstRujD8iTib6yh/4ZSUmuhjjpAXz4SklmmdHZKsDuYyjK8p6T6mJ6Bhk+R
         ScZo/91RQ5sRf5wrR62mpLcxomlx8aSTVap9mAEqQy8QfYZ0g2iRvM/addO/IVDHqSL2
         i1ML7e2Ow5HO2RG5YusbbrtZgJIJPQ9tTfKgHXHwhBrgetPayUDAjZMkdeDe2Ew/YF9A
         9T0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Z0k5Ht/E4mBxMFGFhnJF/DhFHBvxM7DAs8+bf9rwYSE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=OpmdX1HP8xOReR9qgaZnLEO/+4/DSkeI+Q9suKuHdB7/1Y2EuZ++cv5JRKIq8fdMdh
         5ilR8myUXgk4sBHLdlpDe4TN4IjwFDF3Ayte5uR0fuW7q4xFpY9fctpZbvA4hSJ2yYk+
         ueMdGWUAgHxhLig0Ym7H213Xmt2ayukDl+hS0FV2NIq+ThkzDyl2ICOQAiscHq60J57R
         kYQgpwDuTX9T17iOJLzl+Cv+gQXU22RZNVHoF1H3nRIihlPGKqYp9cWizSFYCwEKHEBq
         wIDv3ZvnCn9SYAx33cWE1LzVh4BaRn4B1eT+8D70aClXhDVkQhzXqTLHHQ8r3ecRkiXz
         fM1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DSKnaPHF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7846a70cef4si7199427b3.5.2025.10.21.16.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Oct 2025 16:08:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id E853A44922
	for <kasan-dev@googlegroups.com>; Tue, 21 Oct 2025 23:08:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C6F5BC113D0
	for <kasan-dev@googlegroups.com>; Tue, 21 Oct 2025 23:08:05 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BC9D0C53BC7; Tue, 21 Oct 2025 23:08:05 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 217049] KASAN: unify kasan_arch_is_ready with kasan_enabled
Date: Tue, 21 Oct 2025 23:08:05 +0000
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
Message-ID: <bug-217049-199747-0549bmQ11K@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217049-199747@https.bugzilla.kernel.org/>
References: <bug-217049-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DSKnaPHF;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=217049

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #5 from Andrey Konovalov (andreyknvl@gmail.com) ---
Thank you!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-217049-199747-0549bmQ11K%40https.bugzilla.kernel.org/.
