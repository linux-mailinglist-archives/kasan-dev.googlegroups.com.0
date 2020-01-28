Return-Path: <kasan-dev+bncBC24VNFHTMIBB4MPYHYQKGQELFFDKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E1F7014BAA0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 15:40:50 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id o13sf10459092ilf.10
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 06:40:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580222449; cv=pass;
        d=google.com; s=arc-20160816;
        b=XyujNepb9JrMZR9yFnNE6m6h1clAlOmHUjTumVNoij6fMXu+Z+aqXcF+dqUmBb7kKo
         rE+TWBZv++bS81iJIKyjq1ku3U0IqIhNqNU47HJbrUPALc+g6wpp+TvoPtAvYwhsd0ZO
         DjcKVFBEbh6bYnhf2ninMiXDBJ8nliycdv8zTs99cxV4NPtvSu1Sd/1GX8abVqgJIIrL
         sMP28KTAkuaTWNhhR6nd858n7v4FwZc+xt26Ve7N0tYF62VuGDelEJYM8Q0+7Aoi0SNA
         cdZLfe6Eg6USyQjhD6LqWvcr/DAL+rRwY7DaLVDef3Xny86wSx8u/55uFdcOWw77sikQ
         pzdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=kH5iaQtKkNq5dJIdKkIge+I8fNy+vgX2caYQ+GDLLSw=;
        b=Gi2dkmSJ0L8Y1IYtSDNva24QUT0iYTZTzXupetuMqKSK1aPpL75W8qF28kPB/9ztMI
         BnCLDZAYFg668J9wtOsEefXYG4HtVVJ4PddObmykWtpOYVWUt5yGV+rU2lWCWZ5aePu6
         dzXFi/ZUPMKwrJZxwPQ9VaSzS/ZQ1bjHIxm9J0Q9G6QoC3jgb/fW37jFsbS15JtbTyw+
         t3RmTAcFPgaO2oW7IuYj3Yf8I/pJ/c/d7xpbqoz6svS9h1tG/3NJGkntxL9nXjY971vL
         naMH2FDwrydXreznMch4LisA32n5lMQazgbB7VDX/E1J6EJdaOmII3FLvz/pZss2MgX4
         2a2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kH5iaQtKkNq5dJIdKkIge+I8fNy+vgX2caYQ+GDLLSw=;
        b=ic6mIsUI3XAT/zvPP1dgW4dP/a31hk1YjKbFXLRLfSMnlhLpNwcpDjb+R+n91GKPm4
         Hoe2GFEvxgxMtfhNIGC4blF28xjPHybV981atmaGvoxEdn3hhneFoVgpMBtxWiXvJAOd
         9FObNyn0HshmOAoB0eeqQnFL32NE5nQ5lcduRbfJ9bf0xKh3hg0Bat2+KiX3Irti3zfr
         F9dveSmHYPX8NTthtT9c/hHncbWGv4CFAqVHQhjpuAJdV9WGd7JVbVZ2CFsRDs+DQ5zP
         ibqrZ4B7741Is90je9sgWc+otQYImfNncm9Z1oMyrhiEpa2RIsgM1pqsoJ8bAK/D1UbJ
         3LNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kH5iaQtKkNq5dJIdKkIge+I8fNy+vgX2caYQ+GDLLSw=;
        b=PNjJ7uw15YNDWIMxTib9k8eJc3p1OdMt23xVNo+Lu39Tty8MGM9hwNFnnCvmWk76YK
         wG74seTattZ+0NQ/vYSD27jRPt6P2vSlUW4choQrzS1P6UwIbTQJsZodK6NVWEhr3PAA
         7SiUcz7Rcg6WwBpzpsFdQmuB88CLg4vEWgv83bqPVINTwO4aWp5L7PqiViFifhvaFdHE
         nIG5xYQypLl8rnzKYtFRan/C2582XOR0HGDJHe6sIJ95xb2cbcjpTGY219BqjAkKXCSJ
         +5IUuXYg1ekQ8KXhtb1yQcYqebF6BxwqgfnijXRgs/c4YpxLyU2kdFHCQiyZqHV/fx67
         PV2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUcGxtMFFw5UkNeJCXajPpfAR7M4FVLtuHDjiPAx0aWo4dGWBEm
	69V2+4412Z9VeFPQJmfvS5w=
X-Google-Smtp-Source: APXvYqwicrkTtealJIQ40cBZujdRIVOVywNQlL9C6+N+eVeEb10XjBaBzSV0NT5MioQG35o8pYeeKw==
X-Received: by 2002:a92:9107:: with SMTP id t7mr20292185ild.51.1580222449706;
        Tue, 28 Jan 2020 06:40:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6216:: with SMTP id f22ls2520131iog.6.gmail; Tue, 28 Jan
 2020 06:40:49 -0800 (PST)
X-Received: by 2002:a6b:740c:: with SMTP id s12mr18180901iog.108.1580222449307;
        Tue, 28 Jan 2020 06:40:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580222449; cv=none;
        d=google.com; s=arc-20160816;
        b=L3HKLAZD1rdRWKf6/7hb4LaUpey+1cIDzvFKDbIG5NOE1t0dFqVc5RhEZDoKDQ8qHF
         5zKJTpnjlbZ2zuCPSC+/TKjoYEl+Q9SwlqAMXL1Wu3eIIt1hxV2RfFPbSaGMInp2fd/J
         Z+2zV0yTz978MV53S+Bp3QGF5emPXf1oUdD/g6u5QrU4RExBX+iGITkw28ygJcQFu4sa
         v3xyg0Hrm15N3osmYtgE69Nog1y9uFdu+DjOSNlrZAjJc/2bMKiR/Pwa1lOW6IQUAJpm
         kCA7NnBwf58Q2+L9Rad0vBTyWeGh/5SmnH7cjLxyDNM/GHyUU3rxUjWxiRGm8C53mZn7
         KIiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/qjKpc4fBJERCHcfDqHvRSsFkMjLTPfI6gG89bTyttA=;
        b=rBRo/84DtViWdmDvQ/oegzebyaB8EUOVZORwIrd5vdgSSvUGGbuGi60kIRqaVN6I/Q
         JNSOYPmxxoB68TLsm3+xcWGj3jCvG49f/SiG0cjP037JA5ZdJEAQURGknx1fe5/0Vy3Y
         nDzYvhhKCHJGoLgXP9vu/sC7XOLclmUI1UqDMbm5T5GTBGP1Ap5k6v46HqWeKVIwQkPv
         cs9/vrj7WqP53Zxvm2c13vm89yfBNJ1KGgG9Mj/HgfcFLC5O0pjn1Xlth3+yMV9qtHm8
         N7wNfS5GTcfa7/9z1+oKE71Fs439dgd0edbtvTV3rNAIYckOvUdWypDNUUfCyZn05yZ0
         7DTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u22si832354ioc.3.2020.01.28.06.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 06:40:49 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206337] KASAN: str* functions are not instrumented with
 CONFIG_AMD_MEM_ENCRYPT
Date: Tue, 28 Jan 2020 14:40:48 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206337-199747-GLtV9MCbdF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206337-199747@https.bugzilla.kernel.org/>
References: <bug-206337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206337

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
Overall this looks better. arch/x86/lib/cmdline.c is only used during boot and
with fixed data that is not controlled by any untrusted subjects (?).

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206337-199747-GLtV9MCbdF%40https.bugzilla.kernel.org/.
