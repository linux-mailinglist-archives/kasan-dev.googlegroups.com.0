Return-Path: <kasan-dev+bncBAABBTHH3GYAMGQELGBYIMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3412689F064
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 13:11:10 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5aa1b55ef83sf3423594eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 04:11:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712747469; cv=pass;
        d=google.com; s=arc-20160816;
        b=k0TrAmox7jdJfz1t+KNse+STqZLv4hLvUkYUtEMgH03mkyqmihhURSQ7ioEnPL3kjg
         S4JHX+eWgwaJWtSk4P0tUJFNw4WvdNn3e3B8FWpfFBgQjQHyvnnkbAB8g9jUR5sUIlVt
         lvQ7/o9MxYyolFYvqifMUMlY+Vdz/WN2ktRWxVFGKmW6dnqpQVmpsmceqTSCklMEJ19P
         4/UN7AFL4ZYUQdBvIyx3DHInkdPCA6ed66wluGHFMMTzlVLY7BuTlOdWplgHuQYDSJXv
         eydsOVL8epeLCTqIWqmU6g2Rsf+U1B9YWvx57oxFcpDMlDsSL5cdOCbppxLupoAIiQpk
         rfWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=g63GNKR/U/OlmcVDOh4vTIAVAxhnXcNdG8sY03w7l7U=;
        fh=yqb4GuRuReuPyd7LehLCKrqvH1KE0pwr1U0i60+nDMo=;
        b=tUZ603HtqkLINh7LkQ0ptSfodcMpMCHNSbv7O/d42jKYTBbvw9Rpi7/H6SjzauPOHa
         /+x5UMv3E/O+LOBUuzuxdBteJJKsmqqfI+JMNwbGpYiKI0/dkvyKmVxM3ajDCl+TnS+A
         B94HN5efaBAwanuwXR5sOY+XbFkjop3GX2+bE5CJ54wgG3KkH5btZshmTFCYYY2ho4W1
         Au+uWeFsDEOvJ1JnoevvpmYm/uCu0J2ZwG2Kv16BAfWuu4U2nJCgiwsN+RH67q+IzPbT
         PK+vkOglEQsGQoQhFaXBdTNf6aLUW+uM1ldxf9xC4JXbWiuc6yPAJz1aKFEjHQGfEHdr
         5pPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bYmtXiuR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712747469; x=1713352269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g63GNKR/U/OlmcVDOh4vTIAVAxhnXcNdG8sY03w7l7U=;
        b=izPG+Gw093PMxdno6NLv/4hejyGYKjy6v+aTFZpksUX5OOxzARi8ZVdYHRsPA1H45B
         kkPYSAn9jTIvbuCKKVKixcVT5dkX1tnlNzxyNcb4PrueGErC9OqWun+C7T9NJJ9uiMKS
         VBwa5ZUUvKyQIf55AU2M5s3DPAguCwehGj5H81CJ8JdlN37KJG+DCumlKSOsTzh3Ezpp
         f/RXqUtD7fuNjU9Y3jKHUt4icL+7JB0DsBJQP3mgL9fvv1ugJs4inhZdxHqi06pTb3nm
         JytesD9iBSw7B/accFNYV7XE+AhndXEFEMhy9i+H1UIq3/OUrx4nJ1ZNRplO+0m5zZHM
         wMyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712747469; x=1713352269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g63GNKR/U/OlmcVDOh4vTIAVAxhnXcNdG8sY03w7l7U=;
        b=K7C1GZ9oGdn/3NZxSKtfVVE/PGwPhj80YC0t+Mjf5tip8wXWNi5d7I2XGo6rzOKk/7
         dCYV16/NycMfNhd895EdpzXfgQxoAAsc1A3rFMJb325BE+Q7pzIRQ7c0cQ/aCm/oigRa
         AoOBlIpw/RrxNBSgJdpypkL8dp4m8j/BhJXaFDjb+Wzb+9EXPOp4hVCDwzi1nyO5PjYq
         za0EtAvOW01lXNj5UOGzXSN0AWq8J8zQNl9Oa6bJreVN0NyNIg6oIB21oaB+wcX0R+VR
         4KqVTJjbLlHq2093bkiEy+W0coYOd5mzu39U8+LwD6dluhQIz2OoYZvKnVI9XkwxQHxU
         ON6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4KRZ/G9KVJmVX1kZBki/c5hopDY8cII3S6yi7CpdvuSxcH1reHq878Awuff/E76mkr12zufP/guhgUFfDtx19hrzx+GeHvw==
X-Gm-Message-State: AOJu0YxPjCC8FAfnxZSzZYMLN3haT2/93aosZ59oLZOuDb0khsNXlThG
	BZ1fXWkauA4ASIxH1xYSdKvf3LIo0prWtSrQLT6JJRy+wOfL1IhU
X-Google-Smtp-Source: AGHT+IHVka135fgpe4bu+Cyd01b5xEgpn/KeBqGVW8NXqihzjLAsPwiSGP01RJrsPxMhHhf0U9H7Kw==
X-Received: by 2002:a05:6820:2707:b0:5aa:3564:129d with SMTP id db7-20020a056820270700b005aa3564129dmr2755130oob.8.1712747468823;
        Wed, 10 Apr 2024 04:11:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b0c6:0:b0:5a4:7c40:c40 with SMTP id l6-20020a4ab0c6000000b005a47c400c40ls2042352oon.2.-pod-prod-08-us;
 Wed, 10 Apr 2024 04:11:08 -0700 (PDT)
X-Received: by 2002:a05:6830:1b6b:b0:6ea:1854:c0c8 with SMTP id d11-20020a0568301b6b00b006ea1854c0c8mr2623705ote.7.1712747467908;
        Wed, 10 Apr 2024 04:11:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712747467; cv=none;
        d=google.com; s=arc-20160816;
        b=gH2KnWRgejlyKYDyPyZ820V0cHbJfuSZjUcD9HFIGBR7sw/edIuLi+DLyzMlZdKhYG
         RcgzcDZRSkczgRKdnkyU/vaDT/mRel/U3tNjofplOH342xTsfCYBIxb7vxUNJGJ5IET7
         OpEb/DnA8dl80px6EllNZIbW8ezt55yLtDKBF7Jo53cQ0YXKZcr/eBqugDvM/fRm0jVs
         LaieL9PIx58Vwp1ytN9pBRuzE9Fq7CiPvNIOHDJUTK0jLxkV5wiNZAk9CNyXB8PkrX7N
         qQrpEDc4Q6m/NckYFV3vkTDVoPq4UjN55Jhz4XOkWjlFblJSkWjoZGWRQ5Yi0UbgbRag
         pDCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=4IawNFg5+pzYCfqx9RR+Ku+lJbMfCc1axLw5zkNWniE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NNO16HDRJKtCzn0C3u+G0Lk+WroaECdwkvP/i4ERc56lMMN7jD6dY88y6kYQkbpd9f
         dTeWUhK9ZWXGzjhCPJQj6bRZ6teTL9REqrByCyOzB5tP2nzSTDQ/lVy7R4UwXSpELvba
         AL+1WZiVlGnnIA7cMchP5OaSUupM/EThtozidGluChpSjk9+cqQxYvygK6UePgPViPt6
         5cIjKdHBzFMWy/UjJ3NEKWdSzz0NMl6dqxh+e6IcdxyzcnpB4EUnCeNlnnuMOFPmX2yQ
         KPj4nh3/MgeH57YzsPy+GUikCWQ3YRpxZzNOuLkhsKIb5xw+1Gh36j/SzF5yERSbRrSf
         e1iQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bYmtXiuR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id w18-20020a9d70d2000000b006ea15cfc8e1si347142otj.5.2024.04.10.04.11.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 04:11:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 67226CE1A71
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 11:11:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A6963C43390
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 11:11:04 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 95E3FC53BD9; Wed, 10 Apr 2024 11:11:04 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218703] New: KASAN: make compatible with USE_X86_SEG_SUPPORT
Date: Wed, 10 Apr 2024 11:11:04 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218703-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bYmtXiuR;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218703

            Bug ID: 218703
           Summary: KASAN: make compatible with USE_X86_SEG_SUPPORT
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

USE_X86_SEG_SUPPORT [1] (enabled by default) is incompatible with KASAN [2] due
to a bug in the GCC instrumentation module [3].

While the bug is being fixed in GCC, USE_X86_SEG_SUPPORT is marked as "depends
on !KASAN". Once the bug is resolved, we need something like
CC_HAS_WORKING_NAMED_AS (defined to match GCC 13+ versions where the issue is
fixed?) and make USE_X86_SEG_SUPPORT depend on that config instead.

I'm not sure what's the state of things with Clang, but USE_X86_SEG_SUPPORT is
only supported with GCC right now.

KCSAN seems to suffer from the same issue [4].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1ca3683cc6d2c2ce4204df519c4e4730d037905a
[2]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e29aad08b1da7772b362537be32335c0394e65fe
[3] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111736
[4]
https://lore.kernel.org/all/CANpmjNOsZydmYVU-waN1BdA=2RH0fhjmZcjnaf4JiObA++1p2w@mail.gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218703-199747%40https.bugzilla.kernel.org/.
