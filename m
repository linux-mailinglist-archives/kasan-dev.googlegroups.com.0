Return-Path: <kasan-dev+bncBAABBQ5URK3QMGQEMLDXXUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 109599762CF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 09:37:43 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6c35b4e1709sf8725876d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 00:37:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726126661; cv=pass;
        d=google.com; s=arc-20240605;
        b=SMrJIgpIO4qqjzFHcG4qGE+DSkysek1+FTZB2t32MvtFPWVu5xu0R4xeKPP1U7EPXn
         5eKd2POhBzKeWmDlJ/TVQUcXHb6OqfeEAjLoIvyFIVCjU6TCwhN9bjdDa8K5bcliDcgy
         91Ww+aOj/SA/eZ6YtKNA3wzpsP8OBz9m3uCI4SO51y6VCHQ1sZfBlMnnyITeJFDziuQW
         2nhbuK0qGoZzRkuQh4zZaRbJrKmxhKCq3JNsI4/ZXriQuQGNwAHV6Z5Ow/jlA9cNBrNX
         0l2lQuZj/45Lss9ij19HbZesXtDPSM7M/ux0TkcE2VLPk2rQtbU8u1MVIjWST+DwPNtI
         nhsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=2FKrYNa+cT6XKCjYlSMU3EUpM9splv4mPbBJyYTWwhM=;
        fh=ErjvL871JVU47gyrYfMacccGyrhZ8UGPyiLqJqQFBMc=;
        b=gARdOqM2usMZGb9xTpTL3thFm7muu06xz0Ke0pingtyNTL+2gVqC4fQw8kyyT/pDrW
         9GtAkxiSlZhk4wpCNRAwTEP5Zp1QOcc9PVc2+/tr/elyqP4yNvtu2ppzo5SvX2ulDqbT
         bwRs1QqFM6ZPGuSOJ2IKsuinNwnWYeQWKCV63qdshBger5PPg6urv58kBBzUaYbtC3Dv
         gipQ42srZzXBpKBYf3LuepY9Kzn49+7qaedUR1qEoJiSoko/pdm3kWqPp0fm5IoQGLV6
         Bd8heQAUatwS0EMp77QVbiF9OdGsjduTSc4JCps0olMgYfqh3+piQnPHM5JQktCExR7o
         2x8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mf1O4HWK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726126661; x=1726731461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=2FKrYNa+cT6XKCjYlSMU3EUpM9splv4mPbBJyYTWwhM=;
        b=dc8Imem5bzOG5pt/jCq/wzsw0P+T20KiUKxhi0aGT8t0Uw7fN8yrt//aq1nzeGl94K
         w07tJ5/kt819d5lKh/OQf7UGjDuiseoMvdxl9ZZC3NB0D91FTSjmGasrMym1Tl1ApY4a
         XJn1hr91wUYf7efS/6nAaXdxUp4apw0NOOHam0BOLHnm0U4Y86g4gBeTBdNR8VKgbGl7
         +SV2WmU5Rx1VN2+9F7bMJEy78mM1Rw7l5qxEA7wKxh/l7hqO8YBRp8Itf2CR5PxJJO/w
         u+TtM/Cd00xo7WwSju0xeZlEnKgZFmqPeEnSOL8vKrVWdgPPjIOtud8E/DydBWk577N6
         fUhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726126661; x=1726731461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2FKrYNa+cT6XKCjYlSMU3EUpM9splv4mPbBJyYTWwhM=;
        b=tRjThriAt8sho1RgprO948yA7uvvN89JXEySv+Ns3QMndAZxDdobrgtyJwnzcJTRf7
         31b4DT4rtyZqYC44Qk1YxECWQ1xVQvgrRrPIQTEGb7yj8LptEyNHK1zrN3DV+GScXj3e
         ifov0ucdSNLwrmwMaOQ7PT3wxr2GCez34oliZSANyuSmWKM/IFeT2+Yzz3bfH19X6RQB
         8twLPNjB5vER0X1wdHSTKJEfu0PUuecV0T0os545wu4VbxpEmEgubUeTUcBAV1AzXFBo
         Qy3fpjyyw7P0gE2PtTepS4QlXUZUTMPG3EnTYcd4eClKiOnPdnHnHF9F98/tSMKAO0dm
         a2Yg==
X-Forwarded-Encrypted: i=2; AJvYcCVT8Avy4VVZvjSUrO0sRDjuxevgIrcT1ar6jYMPb1gMThd2PLnTe196CTSxLKfv8OeauvygEw==@lfdr.de
X-Gm-Message-State: AOJu0YxwaVJNmjpZgJOH5ZePNuuiHrSlIMCxsaLPM4fzBq70EM2enmSu
	21QOdB5Kn1UY9Endprj39ipVRsw34HcVRMY1CD2ooYvtvegzkb8I
X-Google-Smtp-Source: AGHT+IHki7PsDwhl0VBICZNmBCAEOIavpkcBYWSrJlxPF6qPhJXdVj3y3HlS0mOFI6A1jh6rIbZkbg==
X-Received: by 2002:a05:6214:469e:b0:6c5:2fc7:a623 with SMTP id 6a1803df08f44-6c573543ccemr30504206d6.11.1726126659807;
        Thu, 12 Sep 2024 00:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:d87:b0:6bd:9552:bc85 with SMTP id
 6a1803df08f44-6c5735087abls10832456d6.2.-pod-prod-08-us; Thu, 12 Sep 2024
 00:37:39 -0700 (PDT)
X-Received: by 2002:a05:620a:40ca:b0:7a9:af76:dae0 with SMTP id af79cd13be357-7a9e5f93488mr293244985a.60.1726126659182;
        Thu, 12 Sep 2024 00:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726126659; cv=none;
        d=google.com; s=arc-20240605;
        b=TThY1ruzqelCgcQZLRqftZwpxrsCQAQOCykJe1R7SkO/GScHav2jBcglt9hDNKSyoK
         nnS/WVvAguMS0y43gzxvRm7O5WTge3nAtIei5BWXmOOulpTKc8Lx9hKqYgjlpkQVUKKU
         8ZEIJIfT2l+Ehf1eg3Oz0aqOgA7vA5MV8oLtzB0Hl+e7QS9ZzOxxuy14yiH4xMLeL1iU
         RCSGrS1ztRn2da2ijEuoS4OzQ6hD2JHXfhtd3tQvumfbctR8DnJMEr6KIDwtOp8RBCkH
         YgjmDwguVfSQsG1dCHOpNVNGG1XFt4iwb7JnAD/NetOG/ZWL1x0HR8vUz+3CoMR5Vs4M
         xRDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=kPblaLTP66DFhKTFpaCc+LBGl9xfH3t1z1dr+lx7+Kg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=R+P/b5SHVwEKyRuMgJ5DH1C8pHEMfemeRd2LSY7yUzyLBbCwzNVU0UGkzkrQaineyK
         UBCmOK0HXzlF84uXQcSq+RECSp2xOMAk6mdLNmcw4ePVDv2+L6s8wJ2W7I/y0rdBgT7d
         6c9wOH7zy3gk8WECkKYn02+kQpSgNjObLDJ9Kpe8//yMrjKYlY7XBnS3jxYizYfiu8oD
         eKNWx2ny6m19b9hAkFxctgxE3ha4mH0cnG2N/Nvc1G/Zfn/IDfsY4fyEUX+BEz6Ww1Co
         xaAj5U9aE4GuOdHfvtprBnqiQw+HFsfsSL9xiwHR8Zd5cdsgfzimot4Fjxa2DmLZJe+w
         JqrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mf1O4HWK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a1d458si50181985a.5.2024.09.12.00.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 00:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 28BD2A44034
	for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 07:37:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 49BCDC4CED1
	for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 07:37:38 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 43E49C53BC3; Thu, 12 Sep 2024 07:37:38 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 12 Sep 2024 07:37:37 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-8iKBRXcxei@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mf1O4HWK;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #7 from Dmitry Vyukov (dvyukov@google.com) ---
Here is a simple patch based on KCOV that does it:
https://github.com/dvyukov/linux/commit/3ca715d1f7e1fbd592097149966d9034805e338a

It proved to trigger more bugs in local tests. Remaining work:
1. Figure out how to properly check that a task can sleep. Should this check be
moved to kernel/sched* code?
2. Abstract away/remove dependency on rdtsc.
3. Abstract away smap code (x86-specific).
4. Remove all hardcoded policy decisions and allow user-space to control them.
A large question is if randomization should be done for all tasks, or only for
tasks that have KCOV descriptor. I think the most flexible option would be to
add an ioctl that allows to enable delays globally or for the given KCOV
descriptor, and control all parameters (frequency/scale of delays). Per-KCOV
setting should take precedence over the global one. This allows to explore all
possible policies (either enable globally, or enable for each KCOV descriptor
separately). The ioctl should also allow to set the random seed, this will be
useful for snapshot based mode and will remove dependency on rdtsc.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-8iKBRXcxei%40https.bugzilla.kernel.org/.
