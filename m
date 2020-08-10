Return-Path: <kasan-dev+bncBC24VNFHTMIBBSVMYX4QKGQEAWC43AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id E9D1E24074D
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 16:14:36 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id p2sf3010728vkp.4
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 07:14:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597068875; cv=pass;
        d=google.com; s=arc-20160816;
        b=nyH5+zBMlgccfaYynoIpzL34VlkxfM123ABGzlV5e1fS3n2kl0j24YE+NpZfkP4br0
         l7hoxF2QFMDAFPnkQ4ij30/CCEbRC2G/5zp6OpssYnlplTjxIBaRkQIpynE/M4qvGL8T
         Fv3pLEC6DmdEH8Q4RL6uJ16OG7Vl9QhT9wYv6YtL1yAUwHAu1PFdAtDeGvFZrKtqVbps
         azhWata8pW3dTdAZa6Fe1UYSR8xWK4wY21JT+i8tYAl1zIkDJveaGQ00fr20dVCqNygf
         7UqfIeqDbmD9BJnaQJ6UA+ABF8HGOzMZTdvPuBT1QwFOJNpEjU4gW/I34csKotJLemOZ
         4+nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=UaK34dnOdH58x+mOyqN6Xmt63csnCn+9ukb2Ti1WXpM=;
        b=qNiJtoZU4NEukzP9BfiTmaOJrBPph+JIUdLDVXDHUyLa3h6IfEZk71CsAy+yCxwSLS
         sJMtx+aBTRyxqFjbKotCoIRLb5L1/I91bKURp9FkjqhSLIqdIaFZ9ieds5y+J0YBBqHQ
         OjGLUM1rKYY+yC8cob/+6daIEpzOHbPkDBuOT+qbXq8ah6veTmcdtwhdA72X6/qVC1zn
         0gRcIqtYnaSMJaKJ8vgKkpvbM8wJtxZrWclC58ljOK8XVSvLIoQxzBUGTNDvPotltzLL
         NIhTB0HNywDwm9sY/LkUSFIctPtyhayrLq1n1Ect0k8usqNc6nUolyPVKYhKbFjyZNaQ
         HtKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UaK34dnOdH58x+mOyqN6Xmt63csnCn+9ukb2Ti1WXpM=;
        b=sYoq2oqLw34ByehyM8QKmg5A+JqFleusWDTMtja8s2eaa7j6plyFhmoE1NqZPVf20e
         4RYsdoTvee86nihY9pk1gB9US3Zoc0I02ajB9ZBYINITi1hHjlHhimybSlVfirU4ZZXz
         +1EtIauChefDycAvDIFIoaus1ojrtzVg7YiEtO1rV7wJF3jHuchRFKIFR4VC64ksQy0P
         7DA8ap+NWCr2SF/qxLDkOsagGqF9UZHVZSKh7+9tymNAsJCjYN+/keYC5etVhG2aftmj
         VnBrw/6w7WbaYheXzlStDHDVUzQnopIOY5cRBmTZZtRNVSZABAOR0Mfa2EgQLE1lrR30
         MAzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UaK34dnOdH58x+mOyqN6Xmt63csnCn+9ukb2Ti1WXpM=;
        b=Pb0UfYIRWOYgnY2a3IY3Rf/LdID0Vo2dYOWr9Xk6WfHhGJi0AR+jj1+QHjQsq3ab5N
         xywcIOrmkDaUH5a8Wsy+/qTmLOkNQ0t8gxmlc/PqDQtHxh1gOdxTQoJaBFjXAkU0ACFP
         OkLB3cBBfk02WmxOs8W3jNYh3jn7lWGYVjRC4Fmber8rJQzrM4Wc3Mn/37WrjuGWJ7od
         nfnpHxP+IGCrg1sDbcYreb3AWDQ6To7MGFzLsmHGHgdDsD5PXjaqrKuxA61SYcwcpZHH
         YiysAOD34XPL2bZ8FEoYwkGWKOdGebn6utw27Bt3kad1Q9F3lsQnjMGjTg6HhA2jUjk9
         +iiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312CbzewXRIYu02SA64viMyHoci6IjB8HLT33b3w/EOxnsK8mRI
	01OOoW0gXhrfSvmDJmocc6A=
X-Google-Smtp-Source: ABdhPJwqTGoHANr1wFNHbuYnj3FAjyvdcMc3g68xNG2Be1U4SAc4GDGn7+1mCfsAcldxi6oQCtgtBQ==
X-Received: by 2002:a67:3242:: with SMTP id y63mr18312812vsy.72.1597068874751;
        Mon, 10 Aug 2020 07:14:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc0c:: with SMTP id o12ls1509300vsq.9.gmail; Mon, 10 Aug
 2020 07:14:34 -0700 (PDT)
X-Received: by 2002:a67:ffca:: with SMTP id w10mr19696573vsq.142.1597068874350;
        Mon, 10 Aug 2020 07:14:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597068874; cv=none;
        d=google.com; s=arc-20160816;
        b=GBpfsvIyQ/MXAZYxvdSAavSfh6QH8tjC9nd/sIM+y7TWYEsgI4W6fRyjleSJrnrS/I
         zs/fL9m0UDVyVwHoJxOkEcQQaNfGydrtSH4yEM4oTrrg45nXaqEA4M2o5dEyUTGIhBzz
         ZSu9v7fUj/vQ1OlINKvGdj4XYSlcXB4G8NylvCAcb3VtgJRMRU3Vj8RGCBo5TgFyR0yo
         8x+cyT72/XRYu2kfpMdacaQmZ2XoOwQ48YjPByVRuIKj147yQPc4O1ciE9wCMZmdVYhZ
         u7ZkuprtCuqn9JgfjriOoPa+38Usm0dL6tkDAcHt/FEt+ecP2GS/zA4+2L6h9Uvt8HHo
         RbHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=18ZRh7dOS1UViIpR8daEJusRQBb871iOH+S67TKCcuA=;
        b=rjuLCcq3KRezJojj9PK6Wsca8mRkz9bqSZprQMwundef4VNPr6VWCk8Mf4akM5BBoX
         nC9jnlL7ukiOpmQr6D21b3QsUOi3FTb/R7/3mylT3Dmwk6xq8+R8lYf7VBULRQmpv+DF
         kspVBeZ4MKEFOHbbCDwJGhfWitBIgHfai7w1hbGrVlGsUnVt/9WY1cRM6BsOfgsxsdAN
         JH/g1oD6L7292jSbB8FZqRdnQg9YPamnDk0fghbETVdJ/HuPOJqq/IhJeAwfSjhVhBVc
         0Wi6LnsgAoJQkKbUbDFYbxh6kYEK00wFrRjZ29iNEpzy8XN/ue8aGS+b9r9JMlK4Wbj/
         FF0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p19si5142vsn.2.2020.08.10.07.14.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Aug 2020 07:14:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Mon, 10 Aug 2020 14:14:32 +0000
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
Message-ID: <bug-203497-199747-FszS1t4Vut@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #24 from Andrey Konovalov (andreyknvl@gmail.com) ---
Basic stack instrumentation support has been merged.

No short granule support for now, filed:
https://bugzilla.kernel.org/show_bug.cgi?id=208865

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-FszS1t4Vut%40https.bugzilla.kernel.org/.
