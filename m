Return-Path: <kasan-dev+bncBC24VNFHTMIBBAOJVL6AKGQEN2C4LJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 493D52910A2
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Oct 2020 10:00:03 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id m1sf3117721iln.19
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Oct 2020 01:00:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602921602; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMyblLFAuGZz7IretPov39hEO9H3ST1kd11hsaMhatZRs7czAq4IUwuDWQawdzen3c
         pIYtninKrYjPQdGFDP2WgokHGHg3sP5FNmN0SIE+mS9YyztsCeXDVO+uvCR4PnZsd5ea
         /ETa0kjIIlibcwEISCXD6WCuPVyIe1wvaLWVP2ySKMJ4uvEimCltkNMMlY5gSTjeNtTz
         x6QoLnulPOxwlLETFoFa4g0nbBl/KMRgJI1yJhjpAnuyzo9eVkQ2YOi7OF6ljkxc3Kec
         Hjh5aWF3Ix2NJyemymBaN2wF0LP3Sy6FlaMq+W0xBSK3IDoC/hAivoX8qna/Ws0PH2nZ
         keAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=UsNTl8Dj8fStUqz7iWh/CiWlYWp419LxFyBhw82JZUk=;
        b=G4emrfbDgpOdQlfRGQAyxOe57yTqlKjAdBWIlJXRWgRPfjJp/5C8xwRUYwwLIiMNZv
         1dji7V7/pyjg7t8FY+BDdXgBrDeOOzCJOnjZOJYdV6HtJ8lr1cXbiHU5yITaDR46r9J/
         BDoUPRSmJManfYs7KtTfZHlZgQ9BUGTOoRQf2DlQijGQFa9t5f25WMQWz07kZMQZ5FvB
         XRd7o9/V2OAwoBpOyq9TUrmayzWvVcNtd1Fz+v7SRt8GhX2sI5bgH5ydcj0vRhH6crpX
         KyjXEMq6lj2Gdr6JyiPYiEQI4bnLiltz0qWLuPn//riLOiKgToIR6DfkNagYSIElyc2p
         joQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPrn=DY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UsNTl8Dj8fStUqz7iWh/CiWlYWp419LxFyBhw82JZUk=;
        b=gdSggGHTRvNnPN436rukIvXK75+P10Vv64lPqFf+hNdqfCPZGQSCwPPYM8Pd7sbSUg
         YrkIQq2qtZd2f51o9zpLtEqMGfKeb02E0OwBO5xF6PKLpgzm0+EixMIOpLvS3b/J+Ksg
         q0U28yB97Mu2Leq+UzBfoeuu1RZu31cifIRP+81hWpvFNEqModlXMoO/0FC7mwlhw9g9
         5a+PNRVs7IFOKZPjWwTau2I4d1HnLEjsIBlRfKz8sNn9FSc9fmOufoTd7Jdta6lc9cyi
         S0gxtmpijV0ucp75FmrG4ASebbjGVHuP8Y1TCnFrGsl7iBhEfkCcRsP4pIBZhrO+lp/2
         fmVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UsNTl8Dj8fStUqz7iWh/CiWlYWp419LxFyBhw82JZUk=;
        b=Rmvwpnm4LsD1yQo3eIgb1miXHdeOX1KWLAbls1EckQx+gfuZ0D5ma0l1PoQyb5BWQ8
         Lqv5tNkEdCgVtv8qktrhhJTTaq6xzh7xPQ8UXNoG3YqJRBWBi7NefKYL5rBFeKKQHTNk
         ZId5W7UDtMCs1qmQI6YAxL8GSZYNA1FPhzjxt+9nrE0qQudpZuvMKgmE78ZRgXq1g2vf
         umYX1P42BdhmtPMCOiRBlKpNjhTforbU9xTExgsZC6nc1YieNcVPSy+tviEWis0erQP5
         5ppYeVUVrtNYWMSxhRRUlJ/yaJ0Iizgzh4v8LsikglRLddtixHVGCqzrizpKuqsQLLro
         6ruQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kjtZwUsqOCD/ocixW5+u3/hLQmLoVKR28bINgu3+zOMdKVXQq
	b1a1cM+evufsOj0nzq2Up0k=
X-Google-Smtp-Source: ABdhPJy41xEtiX7kjEFBd2UrpcJ3W9np/HOryG4WCT7Pj1q2yPhSVogrDsImDMqyFXMVtMvIUD9utA==
X-Received: by 2002:a05:6e02:de8:: with SMTP id m8mr5487271ilj.292.1602921601887;
        Sat, 17 Oct 2020 01:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2054:: with SMTP id t20ls555850jaj.3.gmail; Sat, 17
 Oct 2020 01:00:01 -0700 (PDT)
X-Received: by 2002:a05:6638:92a:: with SMTP id 10mr5544125jak.125.1602921601245;
        Sat, 17 Oct 2020 01:00:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602921601; cv=none;
        d=google.com; s=arc-20160816;
        b=WijXbsPnJpTT+OKRW8I1cdCUeAzwiqO4X1CM1ZjwbzFFaqZSdNrq+fPg5M91jAvlX0
         7WKGH1X0gG10HKpUXlpgU+QOChV8Pwc/4yM1GegXcxDrbKt0ukgyZvJq8QKnFVOObjN0
         ccXLuAp+B/86B5Ls9hD55aMHzkt1UN7dnkjXRUmo3AtmFDjlZKfXwlROZG7a/MAZa5yv
         QPvlRe5IpnSdEUWC2zQL3fH3A7OheP01auO5GKth/G2XvOC0k17fhuR56A/cxG1O14Z9
         cIQRq2/tkeTAIDNfoWrs1M4qFeRKogekPoTT5cHWmIKwQAerVax+4g7bM58YlTS3wdEw
         sqGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=U36f6JxH4LpvwQ0gX0IYQFWkV/hBxZIGVA575wT6Knk=;
        b=XoCOWEnT845qdrr2v1iLowgkvvK43TsKjf8JtIvD4i5MUGAGUILkXAzrrjXMvn5r3w
         ikgeOty00C6c0PoUcMEHfqX8UBR+2M0sJ7uPuwmPnEBfrUWDv3SzSO8qGBs/UXFt11Jn
         GT4pNvd7eIM21BDnwZ6pmVOK3ZF+2oIyMIA9BLTGXgvs3fluHH7dNIy9h5ovELEA969D
         DeBKtjMoEjzAVMx1GMyirIwls1AAZ93Vq1OxHFEsWHszRm90iuhSjLLzvodOQScUp9DF
         qJwSyqZYYRtUOS3go+iNhpIDfczRwz5DUsov1UUcZjgM5rbY21EmfOhJqMWAHdMlDN+0
         3tlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPrn=DY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d24si270477ioh.1.2020.10.17.01.00.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 17 Oct 2020 01:00:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 199359] KASAN: double-free is not detected on kzfree
Date: Sat, 17 Oct 2020 08:00:00 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-199359-199747-3MmDg5fjfJ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199359-199747@https.bugzilla.kernel.org/>
References: <bug-199359-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPrn=DY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=199359

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Yes, fixed by 0d4ca4c9bab3 ("mm/kasan: add object validation in ksize()")

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-199359-199747-3MmDg5fjfJ%40https.bugzilla.kernel.org/.
