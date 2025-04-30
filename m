Return-Path: <kasan-dev+bncBAABBSNQY3AAMGQEC2VD7PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 788AFAA4155
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 05:26:03 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4767348e239sf129699831cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 20:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745983562; cv=pass;
        d=google.com; s=arc-20240605;
        b=dsWBDVZegXouDKzA11LtkzZGCmrkef1WRvedHF672Uvk0uPVbt/lsoYDeEcjCeyklk
         63DthemVtvfUu8YZyXFSyssPTg3oAHx8Zs5cbsIz5ksgywMkLKQz8XAGIri7Z3dsK4+e
         WlUnMXTJujzWYQN/gxVHryZH/Da++0mFx+BtNpXRCYEUI6d9XRBd1VLl3Sjy7fPr16Xd
         8h105t41mOzhjlpNQirlShjywDuFSmkOBV7V6gSwQZTmxCjjjOm2EiOYdxWYHJJEHgk7
         5mnyNcYa0Nmr+bb9TBL27oh0ju+JNEgyfgLDPTet7spfKlXgsNEDKwblh22kt24SdhjZ
         9z8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=clIDl28NiW7vnPwInhfBn1fXiWS0+yg43kDvWoTwlqg=;
        fh=9wTSYwPcDJb+Qrq51zs4Gn4uuVQX3uoMioQRjxaMXZQ=;
        b=DcY0FmTS4Cp8YtrLmx1pM4hhCJwR+4sCRGKHHkMh5pCh7MAJWA5TkzJ61f0P0dj547
         PqAPmOgLO64yBvufoZ5JGNv5plqeTLvIxQ1T/IFxX5kcDyobUe0wIVX5CiHMJhC8nPBW
         CWgcGGjroLt66RoTCwjGmmDvPHQuhipQdR30nI0rSSlSX/JO10vh4iSyLfJ+Rx3acirN
         SNM3uaS8gzfpszvWCKvAWlq5tlHCCi+bpU1dsG8jctUlRcG/qzXJOZL6iXlTIQqq61Tp
         F72nSJ3cbjsqBxqmlDYXsGgACD7MlgcpJI5qI6ug139D4OKlzR97W5sgRY15eGXYvH5/
         yarQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=t3e6ssQJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745983562; x=1746588362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=clIDl28NiW7vnPwInhfBn1fXiWS0+yg43kDvWoTwlqg=;
        b=dFB1wuZWfJi+ZbQZJGZTH7MXTpFzLZXCUXfd526BAmOFXmdgOrDKyto66avsk58Ood
         tCXOM8O5ce84DOnYCmIlP2bYNYdu8Z3W4OgHKCsKQAaYj5fOW7ddOr/fcbcISO6xinLE
         mZmG7o0LQtR4oBJVtGlkqr77sLjQIDcZX9wQ6L5gWn0D5XmNdL9DmlHWrI2fsVQjjISz
         cvKC8LIR87oDdPJZo0+le7HSdnWqUdfT0pnxoKOPQAaN8Unb841b4dCHGFWbjHV7eCzs
         HVUg42yDtzAx1kd6Yr2aj2A/8EesfFkGhukxsn2hlJ8z3R6vEXB1kZczUg9nTOFy/fFY
         KsAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745983562; x=1746588362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=clIDl28NiW7vnPwInhfBn1fXiWS0+yg43kDvWoTwlqg=;
        b=BK46AFSZYj7uzfCl/cJp44IFfUTiy2j7BloQmkIC8Beh126QPPxLamIt+enStfD7mB
         ss1EhwLsDjKmlFUGVvLtLpbss9MbpFoGpvmM9nt9uEUVcBW37Ms7tOKh5ECsh5MGYPj0
         bcy6DHmGWhGpgRzU4WXoJWdjK5ZtQzzd3Jb0SFxFdQmKFpbybWuJO2brF/UpHhOnS1jA
         q425RW1GRImntruZaGGD8Nx1sgSp3zvEDuGhDQvCHRZ5gjaHG5SJTOaMIiEF0eWX7Ix7
         aeW/6ElsX0TY7vn6SrRchSyS1GuPF7SjGGQ8s2RQd01vJUcSGtaAqN6HgDtwMRFzNO8M
         LpPQ==
X-Forwarded-Encrypted: i=2; AJvYcCUGIyLkUzXgmvwUA0q7SZ2m3prbjlMqyLPqayOh8ozzR47KShHIJfy1W43ih8wGgbpQRYNVdQ==@lfdr.de
X-Gm-Message-State: AOJu0YzjPMf41w1WdxTQ3SPoj5Ifv5R4ZD90MWy7utlUb4/Qn/Yfprn7
	FzcmKLYHRtJLMwyuFZ+UT2mqu1gIJK6gu6H1gH9fC9GvJivT4iC1
X-Google-Smtp-Source: AGHT+IF1i5asK3XKUpxSoJ5jtVV+xIMaYGA4FhB47/azeF/wIcpZ9Zi2gKhty/7COLNleFWMfN89Jg==
X-Received: by 2002:a05:622a:4a05:b0:477:4224:9607 with SMTP id d75a77b69052e-489c38ae319mr20812431cf.12.1745983561910;
        Tue, 29 Apr 2025 20:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGK3hQ+eyGXzecjhHvpHiU5nip34bb/UdwzVs8R5stbcA==
Received: by 2002:a0c:ef41:0:b0:6e8:f267:6759 with SMTP id 6a1803df08f44-6f4be044782ls27317296d6.0.-pod-prod-02-us;
 Tue, 29 Apr 2025 20:26:01 -0700 (PDT)
X-Received: by 2002:a05:6214:2349:b0:6e8:f433:20a8 with SMTP id 6a1803df08f44-6f4fce41098mr27749256d6.9.1745983561092;
        Tue, 29 Apr 2025 20:26:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745983561; cv=none;
        d=google.com; s=arc-20240605;
        b=QlaWMaOrFu7KrV58DcI1QrOLBRSuZ8hZYkXzr6N5KP7PuHFoSplXj74ZdWGuDM86uD
         6EYz0f0rDZ7LsgFogOFPJ6CnaL4pzP8MJHi4vnb3Erjl/zKPYoEVb9Qe1HEnoEIwjxF2
         Cz+g5I2xgUtjfnxgO22Ah3ijigiGXR+RPwVWX6YtVUVGgQX3NmtAfHHYxc/7A+7phMCJ
         SSKfxn24yJN61I1/eCoxJ2/HrX1cTVDXdbQjQvzG+ywUUDmIBuVG7bmwa01nbBV6wEfK
         3eI2gwOBoqvTZ+3rEsizBG9uUzj7wQP3u/ZFud2beRDFZg/LMqgmOBb77Xx8r69+oZrL
         /dkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=22CvOCb7tJEMEw5GrP8Z1tpPj6OmqrVfd0xPpSFytgM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ZR1Vf697uSU1eoJGCxrKh/WW2FakOIqpv8BHoP8obRYtfcaWn/+Dohq/hOpVMCoMjN
         veagOb6HQlsTBOhL7hiuE248mGLujay4FbXk0xfJr8CvT8QdHaYG8khc/BRHFl9y+jyb
         xlyC6yYXzIcfHsyGsfQg0qMwO7jvCrzyUIZdvkIfhxJ+2c/4uCfUsAuHslC75Tc5Uhl4
         46ox3YT+zh77PDYkEKwzGGhEib08uI+RKg4SSCUkAbFzo8XAYX8I5wnX9lLIPt/eOmYI
         IxVhXGX7V34X51Y6lnyjMtXLw/xY1MTejiTc51NsWi9ImXxMLCkWd+N4Y41sKgaa7O65
         Au4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=t3e6ssQJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4fe78fc6fsi284456d6.3.2025.04.29.20.26.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Apr 2025 20:26:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id CEA7B4AB6A
	for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 03:25:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E9B1DC4CEE9
	for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 03:25:59 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E175EC433E1; Wed, 30 Apr 2025 03:25:59 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Wed, 30 Apr 2025 03:25:59 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-199055-199747-sALyDny89f@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=t3e6ssQJ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

--- Comment #9 from Dmitry Vyukov (dvyukov@google.com) ---
KASAN does not track initialized-ness of data.
KMSAN does, but it reports bugs only on "uses" of uninit values (not reads,
results of some reads may be unusud later) + it does not catch out-of-bounds
writes + KMSAN it significantly less used than KASAN.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-sALyDny89f%40https.bugzilla.kernel.org/.
