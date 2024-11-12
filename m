Return-Path: <kasan-dev+bncBAABBIF7ZS4QMGQEDK7PZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C9759C51F4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2024 10:28:02 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-720738f8040sf4810899b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2024 01:28:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731403680; cv=pass;
        d=google.com; s=arc-20240605;
        b=klvpFOQqaH4/lvY48gbB+AQbDKF+cUjERHs4xelanlsEsVoGrcjZu08GxiIZ9ErOsm
         eKiY8COYzafh/eHRmiEboxAQ/QDSbV2RLGH6CSM0mI7MeXdfbZbS7AywMsvU46Whh0ZB
         GtfV2pT2x3zlXxdPQDMPIVRVuLemdX1rneff1lCH4mmNqBSxI7Qr8qlouswTm7HuM841
         Ow1XOmAKGcCuV4ww6tinXWtbMQVd/l+GYB1k6CCweA4iKFcrrLaIaJUepr07dNeNBXnp
         1ieYrTuC1WAaL9L/f+GAwEpikFVLcZvndBRgPU9KZpqVe2QfVBzbQooq9p1XicsOFUNN
         xIXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=D4Q9+8RsE36gKQGSuyfo8aCxZOsr3m055Jw0ciH38vU=;
        fh=5YdbpzYkLm+ZSonDnDp/9Nwlfl5aefwCx3d1PUL0Thg=;
        b=VCaVnftYmwy93ulTiZvL8Z0aZBqZgXy19yPGJM6gkchyzlan8+DJFWgTP8B65GyRSf
         oxw9E8mOxp7ccq+VcGFj9DcW/1s4yNP+taKeipbDTBZ5N6q2+D0igELcyhNunCxe/tqe
         Y6p+f6GWe71eRGLzLBMUAYeDMlknbYdzfmAKYaaOBVU6OtPMPrCfQZqzI3jqD4xcSo6Q
         LZ+IUFpdg7k0gTN3LdwHOwb0UUHNcJYQa3U38rPvxBzdEdslO2SuPPIAOYZ6lgdtIud0
         YTuQ41NhPpC+70uOpoC9Sa/j3UAgeWKrH2fn91RtKAlHnT6JSVrsWjNu8BFhWBEgUOBt
         p1WQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NoD1wIud;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731403680; x=1732008480; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=D4Q9+8RsE36gKQGSuyfo8aCxZOsr3m055Jw0ciH38vU=;
        b=sQgLjMX+QlcUEUS4bteil7wUf4HgE2JvaxZPz0taW4SMhEgNTE/l22MtWFLeMmTzSW
         ABK8s/yNagDZUlyTqW5x7lVScalz6DcwluJEjGRRh0Z/u3tksYU2w6zfIaV9wLa9kjba
         XL6b3y4Vy41XDaemWS2VPuRGP99JEYxExKJ61+Cx5PFQsZ2dg8b07piNOAFNtGUs+qCQ
         BMivTNXGmJoFJs/C0zRn6mX3sMbR/yofn2IwykM+odr0/PypQ7N4UXv/+hIlq6l3lR2/
         5Mw39QRDLDNvOX4GSCXm57q1/2UW+ImW2m2QHgvBmKZ6CRE7HmKj5i1udtcWot7AX/qz
         DVSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731403680; x=1732008480;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D4Q9+8RsE36gKQGSuyfo8aCxZOsr3m055Jw0ciH38vU=;
        b=VJml73YBpdefZseazX90zIBMCfIsHq196GW1JJy4ecbFzGKtAUyZhRkMW2FQV5Viv0
         Z/xrDimBVAG9ZvOB/GjCHDNJ6pFwK/QqZUpSlY94xC9b22AjzNg/DTydmez1eUnFXDOd
         Et8Ku706Wd2Aypf7HqaK7mMCn2UI39sai9xDXSEVdgP61X3KOnV/SV1BMkPS5+L1YQaB
         ezwuZLqTzn1UyfRWOC35wdGHBCzfIOm7x16shmuGORXJeWWZsdayuQ6HZUQaHIYmUPA6
         rv6YdWE0T7UOqmGppcuialEGigVymXcH0CTjSOpJqtDroxMC8NDgqtzro+nR1ChJKIkY
         VcOA==
X-Forwarded-Encrypted: i=2; AJvYcCX37G2j+OpK5zrcVuNdfgbxodBry4MEd4tNRNUfWxsxT2MWGuDONBDxhgd6dXA2MED/Q6K7XA==@lfdr.de
X-Gm-Message-State: AOJu0YzypyC4HHQUzwuq8h1ekf1ZV+tuN/tuWpGQrRbDYfy0qbrgRT4d
	41y6r4LqzCInvRlOOmcZvX90jjQh/UsP4u/Z3Ph9wuzXxnjXD/Nf
X-Google-Smtp-Source: AGHT+IHWKa+gsHuHjbMA7qvYKqZRM6Gpflh2S84bklawOvzTLcgWYtPw3FmpqGcnrpgUdrw/fjKsbA==
X-Received: by 2002:a05:6a00:148b:b0:71e:7174:3ae with SMTP id d2e1a72fcca58-7244a53f77bmr2774084b3a.11.1731403680474;
        Tue, 12 Nov 2024 01:28:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2f14:b0:71e:7cb2:57fc with SMTP id
 d2e1a72fcca58-724035dabb9ls4144792b3a.1.-pod-prod-01-us; Tue, 12 Nov 2024
 01:27:59 -0800 (PST)
X-Received: by 2002:a05:6a20:8413:b0:1d9:d04:586d with SMTP id adf61e73a8af0-1dc5f9a2c85mr2699055637.38.1731403678932;
        Tue, 12 Nov 2024 01:27:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731403678; cv=none;
        d=google.com; s=arc-20240605;
        b=J1kjU5ep4+O6JotQIuZHd13bev86LtifMXGtSWuASu+15Jtzyl91dVOTrPGd2Gy10H
         uBUunY4B6t/1xS8V2jrEkAKuDHrHrvUvSUG2MdQaFYqFhoCMuP+4iqTF8b+e6WhQWMHo
         /cvjbFDGmKoUqeGZNAZMCEp26URG3eP6smmAHUyMSsv6Hlu6MgavkCZO3w9NigXELWAP
         nd4vxRHsV15sys9Hw8EIIC+2IjpbnIiLdz6Q7oAxL10bp+lYunIZy+flPGNJt93xkIQd
         TvhD3jVj1wyK94p+wi5wysgISSQ7a6Iij4tsZPc4OcP0tE13GURL5qpud1USoiS90cxR
         lKjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=NSpePn5e2B4SXoNZ1HDIWyfEJFTGIEJ5tia8H9CF9h4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=EqNqIABTxbOQXvu+4FAmHTC4OrBYTemZ1ovZuqkH5UQ99eQdTkgRYGvDz5bo8ZzOwJ
         2Ka4xDcZiwRIqwffkWeOrB3hdqxK5a47jF4TByOqnbAX4JbffTawAodCbWl6PdHYF5/p
         A+YeOQqGYXMpnPrunI/Wv6i4M2SAUGM/+P9f8cd595AscRzmNWbQVDrWA7IBK9PdM0Yt
         BN6bmG+ZRW/I+Q86iuoBwV+h1LcF56bmTXs0bR4aD8FzCkJxSbk8x7pwufTKnMbt/a/c
         KrJlqG+QG90aJuqjN45hNOa6HXlPi9+Jwz+mvtenOlfxCk2/N7M7GpMTbUFSyUukjj1F
         6C6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NoD1wIud;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72407a727f2si534566b3a.5.2024.11.12.01.27.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Nov 2024 01:27:58 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A77BCA41728
	for <kasan-dev@googlegroups.com>; Tue, 12 Nov 2024 09:26:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 97721C4CED6
	for <kasan-dev@googlegroups.com>; Tue, 12 Nov 2024 09:27:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 75AD5C53BC7; Tue, 12 Nov 2024 09:27:57 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 215019] KASAN: sanitize per-cpu allocations
Date: Tue, 12 Nov 2024 09:27:56 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-215019-199747-o9Ouk7HGPa@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215019-199747@https.bugzilla.kernel.org/>
References: <bug-215019-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NoD1wIud;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=215019

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Once we have proper per-CPU annotations, we can restore the test removed in
[1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=330d8df81f3673d6fb74550bbc9bb159d81b35f7

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-215019-199747-o9Ouk7HGPa%40https.bugzilla.kernel.org/.
