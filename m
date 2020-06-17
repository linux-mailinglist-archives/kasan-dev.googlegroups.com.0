Return-Path: <kasan-dev+bncBC24VNFHTMIBBP42VD3QKGQERLSHZ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 72EEA1FCD77
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 14:32:00 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id s7sf1382596plp.13
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 05:32:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592397119; cv=pass;
        d=google.com; s=arc-20160816;
        b=XOgGhAr7/faDj+a42jnJQVB6nq0Y2x46xKdfOaic7JJHLPgxkrxud/UPVRi3KL86z7
         KEoQsRfkzdlcYC04hUSRXrtntl4Lyh1WyiTwRo9B3tvd4vsfCSqrV1wWvqQx/6B/23yO
         H+46B3IbRIQllPalE0jc4rLdmJvzevhccAVTVhUDOnDVg66dFJSAMzg53q36T8Hpg7w/
         xsaqCCpRhlyoMwaTgL0UVSd+MJvAkwUjVr2zVMj1qreQ2PSLg0GpZTqvVMkEdTee+hij
         cFd0s6zlrIqLVXUPkjcjMzkLITo+n2vbb63cASm7mK/98L5wqBbpOBTV5P3y72ZNomvs
         h7Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=sI83AC1I3E2VQUP6vhlozaAaOdeoil7vvLTIwji17fI=;
        b=Ras6+PGIXMjF+mhZ7saZKv//G03nJWK7u8im6I+Jfqk55H9Fe9MyPyY1KAuF50BTT2
         KZ6CuiHS6IAgL2qELvXRuebMxIgDxAQp5bzbhp83h/eK8WHtsQEOVGVVSPpZlFufgLpS
         gZLHwNjWR0VAxl4k+0oGe5qoWbgaDOMW7wJ5O7vvQDsbqSt63sCvBD+/XfcPl3Tml0rD
         RJJxoNkwSrRALdzK7nGkWwwOiGWQg8eG0DWaYWj4yCrqh+6CQECXsdF1DpyBqyNOeMBY
         RBmwRSv0JfzNX8QRZ6yrcPbgTIt0pRZTVkHcz0KzttCi0ipfagO+kxORvo0UMYGEuTVb
         s7eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sI83AC1I3E2VQUP6vhlozaAaOdeoil7vvLTIwji17fI=;
        b=nCpk2HdEWpndHsVFK8zr7uJzYNWo3xgIr7zcvWx6+AdhUECQv3e7C0/dT+nmQblgk/
         I356yjCnp2eLqLqS4ZGnvh46bbuhu9dXoix3bsDbh/FCSdy/e5qzATx0tFw2bFXMuPBd
         JEXjmJr3Us//KFgXUY/YTTtwugAqJp7g3C4iEhIjOdBeTwXEeQgOyyj5BcSho9s1WbwV
         2WyNzE5w6GXef7eEHsu4q2f58XzIOa3ZDMbg6oIKDryBYwxOw80WhfyGS83MCdBOuKPg
         PcfxOzL3zCkzvAphvIf7Sg0eT6MNj9rDS/NbpaMSGRpcAT237mFPzDuKUbz+vUi6unDr
         +q0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sI83AC1I3E2VQUP6vhlozaAaOdeoil7vvLTIwji17fI=;
        b=geEgsRk7Upsb0dYAjxJukA+oSxDtyHzqVUbZLRKZUagQpXDP05jHstWBlbWs+mM+He
         zAkPXhF6Dof2kVVSzQn4wgmlCtrj/iFiHZwrSwhV/O+atrEEqbS97ExjMD7iEGD1LnFM
         BqICMagTiLU6zJ2fJovTA/7k3fb+EOOHsrmFbvb49zWaMsgwwg9t+XRfKv0xcLDS/63t
         SdNT8+sLLt9XVz6D1kTbVtQhJOY2zs905A1Ny3B2t1/AKSW/DmzGnGidse1CibBJ2nYH
         UDWwvbxU3vjR+xvXSD8/tsAZMwwf3PAzpqThcNGmPDXwjKrK0PF02cgm0VOy07RohhXG
         VJXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Li0++IwgMPIKrFtqoNO9shkcCtinU/NbVNf5YWARkXvQ24734
	FM+gYXbai1Zy7YmmqLjVR48=
X-Google-Smtp-Source: ABdhPJyWfmcEIStT2NOREj6GR4q+xk8vqQhB3/Qev8agSTsi3OqaN27SipbhB9kFlRyglrZ6uLkrnA==
X-Received: by 2002:a63:f854:: with SMTP id v20mr6398404pgj.0.1592397119065;
        Wed, 17 Jun 2020 05:31:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a0c:: with SMTP id v12ls771677pfc.1.gmail; Wed, 17 Jun
 2020 05:31:58 -0700 (PDT)
X-Received: by 2002:a62:2b55:: with SMTP id r82mr6824469pfr.68.1592397118607;
        Wed, 17 Jun 2020 05:31:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592397118; cv=none;
        d=google.com; s=arc-20160816;
        b=DreakfdNfV7wnBcWTn+L1F4aBbozUMA4yPrfXDiKD+vIsTKveQDvdIDI/pnmAWFCJ/
         pz2JdV7bkiBzo8i9JOfSSIeixrLRXfkaLeE9RP5dzIaCrC3RT6Z/vG6L4h9Fxh/6SR6J
         FCUD3c/DuAE6K0h2tG3BsU2CNMCrI3kZwXovF9d/SHp291o1WhSjkcqkD8i5IHKs4Qj8
         qHL22U90prN7Y5zZX/a5uRL0qpm1rJM5d3kd3746LgdZrqBctz8z06g1glQ3faS7u5fF
         NRzTEfHA4q8yzkClApizY8qx54f1bnfYiAbTVvgYpJXUmUkQRZIRv2IpV6TroEOQuui2
         m4rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=cYHH9MX+nMXgjlqUXDH0QGXp3lwho04ovx9dWq07I5g=;
        b=0jRsex5HpWuXNFoV8E0rzdN8lnugLn3+vEcFqZZaDmX3A3lIP0otj7prElmljpDNBv
         PqAlUBXUJ6QbDcOXi9nTJOPbwJr7cinmki/lOG7WxK+SImNIDEUH4E7piXc8LBgLg4Dq
         RyuAnir8KzBPcv1kq8UMqY7sJXd2nIHRj+ZZJcnywZaKebtvzrhLPlXUPIqCdwNE/86w
         6xTIsBtno+RJGxwhIMoVYzMlVw37bqz120fJxQZ2H02VF+dtqIwZPFu0NGxo1xVi3zRf
         evonnDOmL4FMi5DQKy9PVhz6BUjpmLvFMTL14Buda2UJEWawhZF5+IHaahAgeo2IxzLe
         qGuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l9si224750pjw.2.2020.06.17.05.31.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jun 2020 05:31:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 17 Jun 2020 12:31:58 +0000
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
Message-ID: <bug-203497-199747-6Cr7uCW7SS@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #6 from Andrey Konovalov (andreyknvl@gmail.com) ---
newsp is a userspace pointer, it's incorrect to use it with kasan_reset_tag().
Why do you need to do anything with it anyway?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-6Cr7uCW7SS%40https.bugzilla.kernel.org/.
