Return-Path: <kasan-dev+bncBAABBU6ARGOAMGQEJOWH2DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F2956397AD
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 19:52:05 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1427cec35e0sf3950158fac.2
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 10:52:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669488724; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ve/+0KeJOQ2zCaw2aHGW9Crx0hQti8N9reTWne6ShYvcMKDYXgt6PnEePlkiuY66sP
         5kTB2RtWUmghi2g/cX+CYgF6dSbOBNoEnV3D173lfZ2j4TwxFJKZ1rOoesCb621GKVFq
         IJM//SGs7dz4AaExOQcfAb7haVOnVjH/0atVl6j1dXhEzLfR/7sNv6ic/yyFR3W//eVq
         olLNubualALVzufzbHFPdzf0D1bRs+CPirLdyhyXDOccbLoIJS69XB0Jb+9gu8n5UXAa
         IW9xC/58EQ69zlngujXanO5DUI+ngu2CWLVbQjjsEjsp5fmv158qr8LFis6w3gexRGqN
         2dLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=ic8IjRZZfRBLH3DxqeCmYmw4xfjqgpCs14t4AGfuW1E=;
        b=qcbh15n1ha9bk30e3Hcf4ZAM3qn2pc7r9XGwDMUsaZKe5lAN13Ki5MHVM/mEulekTm
         rJG+OJQG/Zh74v+5idEvMWfPRn1H74C5AAZ2joc46LsCWyKba3sAeTHqnzbPzZSv3wT6
         CSOJ2roVh5MDfeZvCpl20I6ZXQeuMhXJ0XMCsErbByk5ciCHoWg6UXNxH3FoEqiqIU3H
         khX/bf9C4Vnx5794HC2pSRlK5Chb38vUtgeaPouAbshwqlGbnTpYb//VP2PkLHYQLJJG
         pabdn+vFwtcZwgqy3v+9vQKz1UmF7Gkg/HOQq5K3uc81dH87MXUmJ02pW7dfMUD8USuC
         /zJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eQd6SDNN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ic8IjRZZfRBLH3DxqeCmYmw4xfjqgpCs14t4AGfuW1E=;
        b=kF+jC6+a/DvrUs2Pp241mPbKZkXhuVsv/JrcTMk6YFoGLRNxrNGYccy67TaPUr8Uvr
         RnBnK+c28hdEW33mjFpseqsmFk1FNmS06Y8xp70jrTyv5RHn/+eKjuhCiSuKErzVSJx5
         Io3aaOBkw3IDA6vB5wf8HhV+CFnJk3tTKvCuMi2GT8S/Kf7UyBcssumVxANK9aRgnMwV
         rH745oiJL1wXxfWBuemwF/T/t3g5n+bqlEYxKiBAjNLFNie5GRALLpiOxEHx3PbSAiQn
         ByPhbqBkbKhI0fSxdxcpIB5xQBDc96y6Kss7H23wMtVKdHCxGaSVBkw0/7+Y+k4FHQYv
         GQfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ic8IjRZZfRBLH3DxqeCmYmw4xfjqgpCs14t4AGfuW1E=;
        b=tj/3vrNZaYdRSV346bmhpEZkT4seQ1uq31mB6oC9aaRhCk7rc8LulJg3WbfEEZLOmr
         FKG9Ts3L03WGbw2sI5HqoHxFSMWbdM+S3SY2f9RbbDblDPGNieF6mGe1fReXm5KIBpAl
         BWBarKdjI9KrFVTkqDVtkCsDICK9vFWkYQN+co0LvHHjU5uKbOtOxECS8yR0AGfiumCL
         J4BTy03ejV8NTwXymnK0F506CweHGAmDP1GBYkpcNGRvccJ0suXoA/r0QPAU44l4qIGK
         x2+86Q2Exei9wdNz4/eAXyzqkmVfRvYPCNttbUKu+XzdCOLh//1Or4RBEufbat9rx8Cm
         3Mnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plPmK/eyFFmhETXhArHMUjQoCgTldC/rZ0j5qNNmOuXe+CA8Ttu
	gCr121HX7pjI+Hdp1pCLHFM=
X-Google-Smtp-Source: AA0mqf72csJZVpXY0Y9wqYact6EnB4n3Pwd23rIv3dm2D9XxBjivF9Pb5XSksx8hvsKrXuV/+FLeXA==
X-Received: by 2002:a05:6830:8a:b0:66c:33c4:c985 with SMTP id a10-20020a056830008a00b0066c33c4c985mr14759233oto.298.1669488723885;
        Sat, 26 Nov 2022 10:52:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:378b:0:b0:66d:a9f3:4e75 with SMTP id x11-20020a9d378b000000b0066da9f34e75ls1368235otb.9.-pod-prod-gmail;
 Sat, 26 Nov 2022 10:52:03 -0800 (PST)
X-Received: by 2002:a9d:7d13:0:b0:66d:5dd1:f425 with SMTP id v19-20020a9d7d13000000b0066d5dd1f425mr22234805otn.210.1669488723595;
        Sat, 26 Nov 2022 10:52:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669488723; cv=none;
        d=google.com; s=arc-20160816;
        b=ABtgC1UFT4H0mCqnYKrCZtAKXAfqk5XuRWKfRUDJoIXtkKG1x9ZQ+ZraibqPHrwYLV
         RjLNyRRxRNl8UCcrzI32F+yywqkNAo0u3WbFzO4ai9QIovB7QuhOjOUkBpIU6eACzC0a
         4gEqyAI3RMkLPXxQh3GBwzeQp78mcQvmLa6QuwfNTWI93SfEmjO+P0SCchx1t1C0tLuT
         yFQkvAI8mNVdG5VUCJMw57a9o7itpDM0E1N5NS79Vlt3MvdpfGrUE4GwJad7JrM3F0aw
         +uh0q5FtykcRMId0sdHOqODqfGNuVzJnIsPSLewnui5oEwHCPzqQp9SRfDJTQwo8OL6x
         bH8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=RaXIuyfU19UK4hW/DfutFtw4RoAK8a+BHjSfSNVrGAc=;
        b=q3d6zrls/DJ3Ql8xFsq/X3R2QQBCvwqZHL340xSRZe/8LCpxQsQuZAkNnrByst7VjG
         1jBtAenz6jSSVCfFXEgNF+4S1Jt+GXtehKwUi3bTWnDs1DfJCo3oSl+M4Y+NQlJmF/ZF
         rr8R4+4fGuP+tUd9djOYxWNEYhpvEGLYiqBfZjj367Us/6bECj9QqxnOdsJjUoK+kv9I
         OrbLdE9xDQJ6LDUk7fOkJa4/og/E3e5wbGdcXgtAvxnUPw3ls9D3oyDsARJCZOryNeIS
         4LF6IkvHltrQvtW/1tLWuUWmKIc13Q6jL6p8+S8A9IvRFT/MomxVxUkbHONAa7hCTnpq
         nOxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eQd6SDNN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c17-20020a4ae251000000b00476ba3a3008si343476oot.1.2022.11.26.10.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Nov 2022 10:52:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 598CA60C35
	for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 18:52:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B6437C433D6
	for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 18:52:02 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A7901C433E4; Sat, 26 Nov 2022 18:52:02 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216743] New: KASAN: fix sparse warnings in tests
Date: Sat, 26 Nov 2022 18:52:02 +0000
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
Message-ID: <bug-216743-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eQd6SDNN;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216743

            Bug ID: 216743
           Summary: KASAN: fix sparse warnings in tests
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

Sparse reports [1]:

>> mm/kasan/kasan_test.c:36:6: sparse: sparse: symbol 'kasan_ptr_result' was
>> not declared. Should it be static?
>> mm/kasan/kasan_test.c:37:5: sparse: sparse: symbol 'kasan_int_result' was
>> not declared. Should it be static?

We should either mark these as static or remove and make tests that use these
self-contained.

[1] https://lore.kernel.org/lkml/202210130342.YgXO5JMz-lkp@intel.com/T/#u

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216743-199747%40https.bugzilla.kernel.org/.
