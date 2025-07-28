Return-Path: <kasan-dev+bncBAABBHHNT7CAMGQEFFWF6LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EAE4B14441
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 00:15:58 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-235e1d66fa6sf51257625ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 15:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753740957; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZixtBre4kYMtWa/sqxoYLEcjaqsud7iuEtMHxoMpg/VLXQcpce4H1NqE0KUcvxximb
         HZqA480zv8K5ANPGTO8K/fNK6EwnT6YASvpDlwGJUKOAGiPVEbBZw6IG8rKxz5rYS9vY
         Tz0/BV7T51WV8YqQYYX3mD/ld3UWJWdWGQl5f+1aSKRaUJ38v3JFZ7E5DcIsuxoWUv5/
         Ax5fUXGH4HiN0k3966FQMJi1z3aigeYq8F5JxhSnSp9XrEbs46ISwJ5hlqbW4hSnWZVs
         ti8Zd9QM6xgpPZPk+vJGb9VahT46w37QNMxVpjA3BE6dk+nPG6HPly9LNfgXP1c9MQoj
         Bm8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Y1h2ax1hYEtmRVwua71HEKgea4M2ukOeBRpjBxRokfM=;
        fh=TuULGhmimuj7WjeQtFzdeRU/aYnC+7+3tG5b3tx+47o=;
        b=Ef9D4ysdKJ4zR4kt33gG3JdNEbLCNgqwRqkkxemQUPj7v0YSqi+BH84b6iVezpW6Jy
         wX4iAKSvi2ueb9eed0Khi8m0C8T/VZf06yIrLaaOAmA/8AOoi14prhxQyt7HlqFA0h1a
         AR8SUBEaqPRlKLsypeTw5XDi/0J7wMjmLC+9Hf0RqAn+F0KzcQdJepb3m5H1WbKQX2GT
         Z3rlQQMOtJf5J98huDS+lMEnhMiyMi33VqynIxWclbtsmDXnMeP3A1xfSHMjqFW/0r1u
         YKwTkpsaIJHF1PuzHs3Alq9ZE/XxHImyPbshb1tdgINofvqFfpbJjZyep2UwC+NtFkqp
         8OdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kv4cF8Ew;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753740957; x=1754345757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Y1h2ax1hYEtmRVwua71HEKgea4M2ukOeBRpjBxRokfM=;
        b=RRd0gohalUHRUuhs/vKHI4H80VXevsBtVfC6scR9oFFNzbQ4TCOv+IafHtdUEUM9HG
         rKPd07+T5Vewdxh2O7AYYl2dedUBRiaV9k4Tw3I/c5zbxEk+8p7O1cZsbj9KbtlnrziK
         L+taZPx9I1IHG6onyfy7/0cKPsM5SHewmtSWj4hIsEq3U0LlsV1qiGL0upXvxp61mhd1
         m5bmVqNQlkchIeFxrPIHHsqyF37CP4Meau02OG3HO1KWbJKsvI+JIxB9GcP8ecXrSxG+
         yFULa0Av19nu2YoV/rvaJH7h07RbbekudpFRGDh4geYKNaCys6Adcn64BOKpxVEsfJMl
         n0MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753740957; x=1754345757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y1h2ax1hYEtmRVwua71HEKgea4M2ukOeBRpjBxRokfM=;
        b=QxSZkXFPX31kk8yIPayp9VBDT+Ie1ZYIbRoC6EkLzPnGSiDzTp2/DgkBI570rNlMQt
         fdAuL06BtQZ2/042tLsuEkOkrD6OQOuwwY7DX6c5gfu0w98tGFyjMMtbRXlSx/EA2duB
         R5SzloBS7hCMHJg2Xbqtk/pU/h8hjMW7RTjhxEaAkia85uszt5bTLhPtv21rEsGkypQa
         WkR8xQjarhNWH32iNBZaGX/t22OQwX8MfGtd+BlBBvjdDtDKkR8C/v1adBmokdyPAdQ8
         PgbsP64zla0jCMnvpy399yRoF00FHDepK3pIZG7ZdX6m0hk3kgLE3KCDnC3U4PBmAz32
         ZhuQ==
X-Forwarded-Encrypted: i=2; AJvYcCUt0QG3dfomWBKfcAXrigJepFldUaZXEriOTXQZwqPyQPyPrg3Tafq+tPjmaFECFoHVTBcmVg==@lfdr.de
X-Gm-Message-State: AOJu0YxP193XCjyotBjjdxqdbaNckZ/SF1I9kDDBy+28mzkGiJp9LdLH
	TGc9+EgmFZpXcOh8PZh3/PCMULhS3Smn+G2ySSRnmhe1f3iEamRFq9iT
X-Google-Smtp-Source: AGHT+IEC6Re9C2+B2oqebOrF9Quj5Qae1CDgFBsPnfXz/CNoC+1/m0raTeWDZwDSzZRcK79k0+tWaQ==
X-Received: by 2002:a17:903:1ae5:b0:236:7333:f183 with SMTP id d9443c01a7336-23fb3084edbmr178529535ad.19.1753740956781;
        Mon, 28 Jul 2025 15:15:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZddYjSM5ByhSVmRpDxp1WxbfwUpmUX/HCDj+hDbqBhTFA==
Received: by 2002:a17:902:ce08:b0:240:9e9:b889 with SMTP id
 d9443c01a7336-24009e9bd17ls17506385ad.1.-pod-prod-01-us; Mon, 28 Jul 2025
 15:15:55 -0700 (PDT)
X-Received: by 2002:a17:903:3d05:b0:240:7fb:cb05 with SMTP id d9443c01a7336-24007fbccb7mr104559915ad.10.1753740955678;
        Mon, 28 Jul 2025 15:15:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753740955; cv=none;
        d=google.com; s=arc-20240605;
        b=Afs228TW7rh6JNTINaCqAl9eCgvd9gNazAo7ynbu0GX2Qfqc/Ee4WACEECKQ5/xDbP
         SnCnZAbyqMCWqA2EfSwWIY1cro4V/CBtbanyCUQkokA1MmUeDq7rQ7Rg4mR2/5K1JNbC
         kPkrAyuPKVrXoAfCaIRq6laQXwp81vjOhM+/HXy3DHHWvanPI2jjw6mYee454QiAZwIS
         1kqvgXf7L1M9ooiKjofm/Se+c8VygRXjzjo5GaeN8QNPE/Wht2oqEJIlqLSme+GUnfUL
         h4/QBf4b4z90pfWprT+n9cc/v35o4g/Th7j6GciVWFRAyD6tCNcN/t8IswY19lCiIV3Q
         a/7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=CsRuz+ZCS0ag+AeXSyfgNAl5E4NF8uztUg9FQXZ/RFM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ddhN188L8DcLUC23ajNCkKS/XEjPHnKe5YIwcD5UGSmzpUtBVj4DUITv5O6P0sNqO8
         Y4JP/sr2MTjVFbWVof81+076hEdg4nMKdIUYDdjNnaSTEKEVqtGrgB/5JgLTQUIRFFG7
         ymyvEVPsPFS1Pku7Y9f+ieGO81ECwDfO6hmsjBCnZN89y5cHb2ZGaZOpOyq3lYV0Ztkb
         m/T+GvFs0Ldn1EM78+fHaOvGRLCbAFcJtUq4AVNpHBLFH1WaJwnAKJZeDxtR+753pnl7
         Bfh3vMooePnQ0purEvpq8m1lmjzozEUU+2tAMaEWze4QV8JOLM/m5igE0dDWkm1jiFAP
         ViTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kv4cF8Ew;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23fbe4fc78dsi2601155ad.9.2025.07.28.15.15.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 15:15:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id BB060601FF
	for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 22:15:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6DBC9C4CEF7
	for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 22:15:54 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 618CEC41612; Mon, 28 Jul 2025 22:15:54 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220338] KASAN: restore printing info about vmalloc mappings
Date: Mon, 28 Jul 2025 22:15:54 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-220338-199747-9dzBggQd8y@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220338-199747@https.bugzilla.kernel.org/>
References: <bug-220338-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kv4cF8Ew;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=220338

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Commit:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6ade153349c6bb990d170cecc3e8bdd8628119ab

Thank you for fixing this, Marco!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220338-199747-9dzBggQd8y%40https.bugzilla.kernel.org/.
