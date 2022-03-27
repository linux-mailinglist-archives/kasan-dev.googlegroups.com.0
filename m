Return-Path: <kasan-dev+bncBAABBEXGQGJAMGQEMXLM3FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A2164E880B
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:22:11 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id r63-20020a4a3742000000b00320d9025595sf7592510oor.5
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:22:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390930; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7c0NQ4kFb/TnGI3KsALhxuqoHZzb6tSsC4T1GJT7XKQoP0g42IOjTnnDCZZcWPCYH
         ImI49han5nxFLqlPtBR19xaCQZ9xmfrqPsWL03LZVm8HNRvzNdEC2GO2nlmZnOftzwEB
         AP5XM6bDeLjZ+k8eIGKeQenuCwRQ3Ox14g4TnzQcB/j6LSse7XNDHPgR4v9Akk1k2fg8
         86ju55rr5YnEg8xTezRxJAJiK/2t9snveHXtIcvb/ChEX7+3Wqc/x5BUR0pFUsnMFfXV
         Fg60g3fFNcDWd8Uz9HQiTZnpOjXVCsCdweW7mIO3xTwoAZc0ikIBWur6pGutZgGIWVtL
         dVMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=MgfpQMuVuqyKR7W4kqbQbnlv1sLwpyzyPPRTD5Cpwe4=;
        b=p4qyMftoqjPhpBUp9p9wAcLX1jILqtJgGa0tEWt2oJh79BX1CEMD1kyMzVHCMGVEgn
         33GHkphncGEMpOxkD884Ih/hGKDuiJCmPh4FYPHxH0G+bJhwz7ECtn0sEpqp7/xOzj+Q
         k+QZNpthxIyJEANUf2Uuw3z+PLa7gUQF3lvooqB5X8zz74KznwVu2g35YrqMiiBSJ8pk
         2PeLfAWW1SZhdbDFAqBxSFuPCBYLOQ+0PobNEjT5TIRTq7HCqc6u3MluBLgcPXWeb0r/
         dr8xjhErNV+NadVmz5VO+22NaTWmDPyVWK8EJn73ipQtd+ucT9YYIKdTfWLhsLwYGXS3
         qKyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NdvkYmDA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MgfpQMuVuqyKR7W4kqbQbnlv1sLwpyzyPPRTD5Cpwe4=;
        b=mILgaCHpIQmkW/rGIHRCidKaeulDDvkebLx09w+C6D5CpoiwOu40TZNH26TS14ytHF
         dotckGvprEJ7nz/H5/LsAohanzLqGkVUGnea0cCeFp6DKZqL/1hp0pDfVpKdPM2/5vDh
         eh1lKU40TwwySrSrhj8PJy3dbFxib6yle9EUXA6SHs1Q7yF9X3cHWq8bBISdmUSSS2mr
         48yjRX/D8L/QUSoRDYSE/d6AnofZyx0CRWQAHgkqJEOtWPgskOYcP7LuCAcBP5a11fm5
         XEVzwcMy5jXTAzYsssGljVEpAFsuXWwRwv6s1AOZZ+tGKVk3jjG0dAkZ5B7lUeZNYpz6
         t1Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MgfpQMuVuqyKR7W4kqbQbnlv1sLwpyzyPPRTD5Cpwe4=;
        b=W7kJrEoyTekD+gcxB+eDczAyywZIaZlNP1cO5UdEL8drGnTl6/VLY92YyNXtH30LPh
         wa7BnQiXYrgH3uIxlI5aEbY0WvrMzvB83QoPOgye45Ai9j92BDyzKrU+DyMPWvDKc642
         JyD0/nJazHq4oP84Oc4qplpOhp0MhRajfMWRlJPT2rucVqxS7RVFFg/Yoqbm1JapbWdI
         S0uXSxnqmPrkm5Wu/N+YRhRDW/WJvDnL3mNB1RuOvqbT07RGhcm7OrIEbtvBc3B/OOue
         0iV+L/vdgflibFwZ4Me0V8PoF8QXmjBWyHJaufz2YPJBPGgT7ttOnDlSQGz6cC4cpb0p
         C2kA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uSbb24TQIy0p0wOnG2fLXE8UgdJo9jSE0sRoZkwasG5SYXZs6
	lQn0MwaVRdkaN2zor5OZb5c=
X-Google-Smtp-Source: ABdhPJyo7dONthFoxBckRgjzNqI+i3pAkC/QaWbDLiQIl+HUgO6/YvQZA/26K9NIbf5S7qp9xSaUEw==
X-Received: by 2002:a05:6870:c8a5:b0:de:8f05:f53f with SMTP id er37-20020a056870c8a500b000de8f05f53fmr7709612oab.76.1648390930095;
        Sun, 27 Mar 2022 07:22:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1998:b0:2da:32ff:a70f with SMTP id
 bj24-20020a056808199800b002da32ffa70fls4190277oib.9.gmail; Sun, 27 Mar 2022
 07:22:09 -0700 (PDT)
X-Received: by 2002:a54:4390:0:b0:2ec:e47e:95bf with SMTP id u16-20020a544390000000b002ece47e95bfmr14420689oiv.131.1648390929803;
        Sun, 27 Mar 2022 07:22:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390929; cv=none;
        d=google.com; s=arc-20160816;
        b=Ya14E/tGkk6H6t3lw4KOGp8EBKGyPwjhYA85JqiK4nyD67ssMLviqGGmlVLjT4khPW
         XOD6pMiZOWCE4dQ/VbbAP0YEIZsRqZN0Ae6IbZnKd44YMfZelLZZCun+evW+Z8UFyCli
         etyU7AIzsrJP6whwJqhv/L1DCNuIst3+mypbROWMflyMiEsd6YgFjAttiO1ISCs+1Cut
         JVw2MVJAWe2mcjF7yR9+6K/JUSs5rBMku0vK4B0B2KhOFWGfXh5U1CdwTiepje9D91b/
         pnoAk9FMBp4QT+VpTwRT3J1NGzUnU4n6A3FmVQ/2qyfyQNJPucckseNwmT8DPqJBIBQF
         9hng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=hLUQya21+PBz4AgzIn8Q2EfxqfGjV+NiH+uoxVpFZm8=;
        b=sEW5axwxMlO6mBZoiORIsNTiyqYAAdlLQEYg/3XloI+2cKKeTcJPsJLsedMiVeKs8H
         LYymLeWZkBRHIexLHAxbDa+dSwsQcrpQ9IatExPzqnxpsfr6jKxhJyW63YXX6ls9MWXr
         b9uLrAynZOc/+LIMTVODFsIygszmp+2eskECmW+eJX8eaiA99hVtQMGv8mOncIhrZ2Nd
         ZrWBvZRCn/skKCC3VmCKlOi7ZW3WOvGDiM5iuaWT96AbOM0/kjD795c0w8l/Jyi047p8
         vkkl9kHS0+Ch4s4rRJEPI6UZZothQmM/v64clYT9/So/Funq/Hfuegccw6Zzz+9bodlE
         bzlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NdvkYmDA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y10-20020a056870418a00b000d9d5c45df3si697463oac.1.2022.03.27.07.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:22:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 88AD46101C
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:22:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id ED243C340ED
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:22:08 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D7AB4C05FD4; Sun, 27 Mar 2022 14:22:08 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215751] New: KASAN (sw-tags): instrument dynamic allocas
Date: Sun, 27 Mar 2022 14:22:08 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-215751-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NdvkYmDA;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=215751

            Bug ID: 215751
           Summary: KASAN (sw-tags): instrument dynamic allocas
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Software tag-based KASAN does not instrument dynamic allocas, unlike the
Generic mode.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215751-199747%40https.bugzilla.kernel.org/.
