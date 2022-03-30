Return-Path: <kasan-dev+bncBAABBLOBSCJAMGQEZYHB64I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AD784EBD7A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 11:19:42 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id bq6-20020a056512150600b0044840cccf4bsf6247372lfb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 02:19:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648631981; cv=pass;
        d=google.com; s=arc-20160816;
        b=lX4NAOOe0XmgtyVJxrD5fdkKcjXLC6D9541R+Uvk2QeNFXZgL1NrlEX7xUz9WSyGXj
         /RrsC65xksNQ5Gr0PzM0YWrNRRjCgv0fSwrmNVGUM0On3MCEtRfaOfYL0zjXT7ntQPx8
         Cmuxq4OYqeWQaKwSukoM1Mc4xc0LxuqUUFdkRT5kG71y2Yc6mfB9M/qYrJvuczNx+hLc
         K/TMQ0Qrl4NNCHsAdmJ2eTdF0taUC5kmSwE4iZ9Jty7sOmrBOInaELVvfAFhGsah5A2L
         5Wek8FMwc9T9HZAGNpdik4gHr3V4UTD4GmG4yXY96vYHg7CnibWzKZBMzfpCQERWj/AP
         Iu+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=idr2ZKCDweO++fZY1yAcJstUBp81e0qfJgf/OKa++VQ=;
        b=SXmZSeIc9VSqM3b8MCzTgFwxY3vVUpCaW3GTKgWIPKX5HqAdVzduUj58sbMG5i8hoL
         DdWQbG7LdZGKNJggcf2unwPEBq3wyFz0ZK2F61AF2+Df2a2qtP7+R1J984AJJcTo8Q0e
         EgPNfHvIHUDeV5L83ZRuO6vOKk+pDj30Ld5oZSpQXDkBS9WKGS7AXh2GSs0mvH2F9e8U
         iHwaO8aXuhfo4y10n/wm0vycfMb0dpRXR45bDmGJYcMAxhoT+tqj9ZPgGIZWDCrquRJW
         tQpZUHLYtubT642Zh+5eMYyirJfEBxuoRPKlIbRH2EswxW4Pm4d/jY+tqIyceDnq9iFm
         JFAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CGPRohGV;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=idr2ZKCDweO++fZY1yAcJstUBp81e0qfJgf/OKa++VQ=;
        b=HkXi8kMJbydA8l5aaqo02Pvb79YsJedioVq2056IhMr6M8mhH9BOCBBf2C/HokDEBL
         pHpg1YkAf/oBEmfeJXkmFQbrCBsOEjhykdaPzqTzNhrlqFm6fz9bOVXXbIH64fmRKVD0
         ueJJOykrLVU2UW3dXM841Xku6Ik3mFkeeyYvGshjbuXLuAkfefyNPXwwqiilipsOdA53
         CCfw6ObxPkrQSnWmzLrPeasY6sg7e7w2H7m0OOAnuBzjOvuXgxa16ob0Ubnn58EyCpBU
         S0IUWnU0H2fniWkCJLFsxIBU1wje9WYhLsdBWpOzGW4psAPYaXjG436ECQxRyCGlRXGq
         AZQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=idr2ZKCDweO++fZY1yAcJstUBp81e0qfJgf/OKa++VQ=;
        b=Ly9HkHWPkSXD7i3XxLcgozgk8WanBgc+VO1/NEqdxkGREZtv2YgWNYrsp0Qu8oVxMo
         kLFVyoKuP2DnHMHcmj5lSRGuHh7beiponQoJpEQl4xrskc/GmP23OrbgoyASVzA60RzE
         OcMRNVaG7C9RwwToLP2vR4U3gb9ajXt5jEt28KG1PdcOZT+QmDnXJOm+YY31C8bCYk7c
         /9d2W8KzrJk7fZS/fki/6clLLxkIm0e/68G/YMy+9gzJ4o7XybW4tlcQHuT8BUuklPE6
         B2LoI5PHhDFwmXT1YQf0nsbUmnjSq4cy/F9dbdtElw1s0SSDJH1ZLNNyIhN/q2PimpJc
         apOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532u2Ramxs/bBNFNf2f+XVVKd8hIuFEuONvSWYlvF30ULicDWrQe
	pRcvE0O1dnPhnc3pqFB13T4=
X-Google-Smtp-Source: ABdhPJySXUSjlCpUy722SaVEjsLOXdcq1mzRf4ZVMuMuP08jGya+07Y4+RyTLKRSTgEbykttlBp1UQ==
X-Received: by 2002:a2e:91c4:0:b0:249:a943:d764 with SMTP id u4-20020a2e91c4000000b00249a943d764mr6001600ljg.129.1648631981257;
        Wed, 30 Mar 2022 02:19:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d04:0:b0:249:324d:ebb2 with SMTP id y4-20020a2e7d04000000b00249324debb2ls327738ljc.1.gmail;
 Wed, 30 Mar 2022 02:19:40 -0700 (PDT)
X-Received: by 2002:a05:651c:179c:b0:247:e1b4:92aa with SMTP id bn28-20020a05651c179c00b00247e1b492aamr6160281ljb.55.1648631980420;
        Wed, 30 Mar 2022 02:19:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648631980; cv=none;
        d=google.com; s=arc-20160816;
        b=H2zzKCDhDKZR8SfFsfkBfiaK9dikPVqM2Tyb6Jw5uMXfGCof0QyIdVosbXR5pjdVJA
         IiSgGuXC4RExxs0VohHha5bC/3yLX7JL6BJiAdh+jJ2C8F61y493jfXl5Cs5G6OXKFnU
         R1JGWkWJZ1bqxnWe+P4xcz4H7eK1V+lFl0P3/ouBwkxUfg4kB0dfCelbfZRwbyKzt3jW
         8Lkv6rXWANuXqTnVnaD5FgkKAn3tOpLyNPj23JxtcM5uKR4xpeYZcHtHEkhFLGDh5xVa
         G6Apf688PofQSPG7Aafw5BwbdJVs0hEBZukqBYiFH53ejaVjS7wJtkIVZyKsHbxx7mt4
         A0uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Mn6CnuQGPxrG47QH0TVaJY1h6KTBAr43xz/y4/Z6V20=;
        b=makRc/GXUy38I1Qie8Sl4b0+HJ6XHoBw+fQrgW1L0GN88EoOvd24VFT5qR3WOul8c+
         vuIraSWsegBMQIuIOtPi8aOgj8lB3vJCAb4PFs7fyx1XeuZVfLzOsSxdzx8/Eo4S4i8i
         DhM2d42BzZ91MaW5EtDyL6mp7ygl9Rj3ve560iKKRaQrFwqFGBD8WNLGL5robAOiNyVJ
         KRqF+jGzl0+rL+9cUpRVTjKeD9N/mC+6zArDvJDx5ztjMnBwC17/WEPT0XeLs0aqSwzO
         fsIhZaYro3vXR82kJjjmuARYudOR08hfNIpMLQWb+ROQ1fk5tE9/K/K2mD+0+7oa3Qum
         kUzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CGPRohGV;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id p1-20020ac24ec1000000b0044a984833cesi495131lfr.7.2022.03.30.02.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Mar 2022 02:19:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id CF57CB81AD4
	for <kasan-dev@googlegroups.com>; Wed, 30 Mar 2022 09:19:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8F373C340F2
	for <kasan-dev@googlegroups.com>; Wed, 30 Mar 2022 09:19:38 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7DCC6C05FD0; Wed, 30 Mar 2022 09:19:38 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211877] Make "unregister_netdevice: waiting for dev to become
 free" diagnostic useful
Date: Wed, 30 Mar 2022 09:19:38 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-211877-199747-vg3klKDxqa@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211877-199747@https.bugzilla.kernel.org/>
References: <bug-211877-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CGPRohGV;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=211877

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
Yes, +Eric's patches for debug refcounts in the net subsystem.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211877-199747-vg3klKDxqa%40https.bugzilla.kernel.org/.
