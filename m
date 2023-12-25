Return-Path: <kasan-dev+bncBAABBTXCU6WAMGQEJXK2LRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07F7481E26D
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 22:17:04 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-5454e8c85d9sf161418a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 13:17:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703539023; cv=pass;
        d=google.com; s=arc-20160816;
        b=jcOJTdjZHJ19PwICJMC3Njh8PvbDliGkPNqc/9XNwpOaFkP7R3ZPrpD7PZhEx4aJkA
         mZxYORx66yUUsnvRLZ2Ezwnsn3OEQ4I/MPJJhMVOgrOPhZ1GU5jtYVGkUJ4DZK//R77o
         KAIF584p+eX/cMzr7oUmSH9QMGR0f7TVJ0TqgADDljSKcmbI2AnDeHxBCFXkqzwS2yME
         t5l5FMk3DrczBqVzloE/4yilQfB2WMOQSOi50jnafBg1AjLFEQgkLUHyvbEhN65VKxaF
         VXl6GOiFaW0QEscdm6dqpO7Z4e+YAywi9s/hXjSiC6M1rOKz6MVTSYEgHm/Adh+2InE/
         MwJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zgWW2LHfDMWxuRtCMecAuKK1MAaSFBlOgjX9Zo3CAQw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Rs2Jv4bO3ORaoDhWx1KduZDFa2CTaWw3vvhFpaDVAjae0sm57oLhGufNoGBEaZqrh+
         bCmgF4SVuADBgUSEyEQNk/4fwT46A3cmLiqpU8UdUQceVuzqFZN/5vgrvuNsJ9eKU5Ik
         9HCfMNU3ip/phL/khtsHbOIn3GRj1K5YsfXd0Dfu2zhto55CeJH96iAJ85dc+bnIaobS
         tlIF+xmgXLMYCMFAFztKUnMXYC8QPoNcvD8CPOSbiGDpfggyUDcBDrJOZvpfoz9Smso3
         KOAi0rs6bqJBLKnAH5asxzzWyK4393t/mzysls7gAdG+3QrsP+dsAM057D1UvatMrqHJ
         i6Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="gyeogK0/";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703539023; x=1704143823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zgWW2LHfDMWxuRtCMecAuKK1MAaSFBlOgjX9Zo3CAQw=;
        b=VYpQcBO2difm7YLkQU6zMXTx6oJZUBeak5DXOEKJuxldIfLDSirOQxytMYgCmH9z/1
         KglHpapLOlOwaE/QcbMH1YHXbHsg2Mpza3GCwDAgfcmXhKYx3chO70jCuCNxwpf+AxAX
         maorQ8niAa+Ua1uB78n9TzgMPzo8jztoza9xLnf/t/lJAFWdCpbG3OJWjrCc7WiV7gTq
         xDy9IA8V4r+Sk3om/9qV+ujwxzA3spgcfkj8LNYGY075zFq02dMuDIT4CdAAkMTMZV0B
         yIlmDkZdPbpRmduv11V6GXA60HvPn4n91LPf6/GH1heMWgEwkb6hdEu/Q121kHq8yd1v
         tR7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703539023; x=1704143823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zgWW2LHfDMWxuRtCMecAuKK1MAaSFBlOgjX9Zo3CAQw=;
        b=Aud81KQ5uksgC04qy7LDrwiwUPZaRP1JqFN/dLZRrGfTd0h2gguTDj7EJj+Y01OcR+
         FCQ2cugvEKnCVrI2t5EwkB/ZaoF8hQDqCGkRF9BfJ7LRYH5sR+yL1j7jEzaG98jbLi2Z
         Cs04tZ6wVwSV5Aul3rMjSONgU9aUWx2u497L2UvjMaxhU7JEIbz2u7BjljDe2avJAbtv
         26fq53eFW/1ryl9M5qp5WeNDCJCOnXwQskJZ84XD+kkGvzEMzluIxVMooprbwE9NxXW9
         4CzyBLapoGxAWlp30iYn5Cu+hdAovBOv2SAWI+j7gS7Q48Tkpa4ZSe32tJZUKnoDiYAL
         OvfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzbBFryPRlF43pXdEVO1NN2Krp7771FkMTa35EVXfPzT4a7gCZF
	josOBlaCgfymley3HYPqzZ8=
X-Google-Smtp-Source: AGHT+IGI5sp4J3lV0Wgum4YwGiYXE8G9j6uwZMGIEJKsQvFXtc0K5J3lXobZHF+Q5cWZ/u5TT2UkjQ==
X-Received: by 2002:a50:930a:0:b0:554:1b1c:72c4 with SMTP id m10-20020a50930a000000b005541b1c72c4mr305520eda.1.1703539022218;
        Mon, 25 Dec 2023 13:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2709:b0:554:22ec:9c29 with SMTP id
 y9-20020a056402270900b0055422ec9c29ls1398105edd.2.-pod-prod-06-eu; Mon, 25
 Dec 2023 13:17:00 -0800 (PST)
X-Received: by 2002:a50:d717:0:b0:553:7cea:3d91 with SMTP id t23-20020a50d717000000b005537cea3d91mr4549100edi.28.1703539020632;
        Mon, 25 Dec 2023 13:17:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703539020; cv=none;
        d=google.com; s=arc-20160816;
        b=QPE6rvhftnor/seig9wDsSosZuMY9ybhYc9XxwqqLhKPS0HMFybJQI0X1aBWnpq5UK
         KxJ3RtFs1wyS0CIGcpUfCrRyXO5kalosiqElzjnP/2UjPnYiFqG6wEuDzrJ/h3FYAmCc
         N8+mmwfeyMG0czjWC2M6nKlGJEnPXtmREYu62pUx2yMxyWzvdvXrdJpEW6su1iuEkgLt
         zCtc8e5awgzvax4rKEKiaHrFvhrFD85IwyFSz6GXBDrOCygIhyJ7l/7MHx316Pz8IGtA
         xLxkR/y+t/O9zoujDzwtitUXpwOPZvDtHdy2LA7U3Rt2OV6qv0gu/Ro8m3yhodWcFyC3
         BDVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=fA81GM/2ddAIwpEAQqLH5puqtjiEp5/8unVZbHycRuM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=snZX5Sh8yFFZ3XbIuhcrxAzCVbF1xVa9j31PeExtX9NaOzbotvcDEPRdo4uiIHKRfA
         d5kNw1z4HA2VTwWtXF6est2jI9prAoAO/sm2hJ+QCe2gOo1/jXE2Xq9Tw0HqT/AzpF3m
         JDUV0zIVQ6KMsBFiJ1b4vfVpVoWirZvssudF4zLbMvTlhJ4RhdccbHNtH6hu1n+JJCbN
         cNJdNufKYsYqdyUKtzf+w2ODrqMIw0kdjh1B8t/kN4D3PRW9yFKwzYLheV7oD22KrsOj
         p5SHPVzZVlP7bQDdg2xO+0SBrd097nKdkR0OsRTQbfLc/YklMXmOZq8J5xhhRGf2P7Pp
         LsSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="gyeogK0/";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id f19-20020a0564021e9300b005533f8f54a2si234523edf.4.2023.12.25.13.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 13:17:00 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 51223B80B0B
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 21:17:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D7B7CC433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 21:16:58 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C2C2DC53BCD; Mon, 25 Dec 2023 21:16:58 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218319] New: KASAN: fix UML build warning
Date: Mon, 25 Dec 2023 21:16:58 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218319-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="gyeogK0/";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218319

            Bug ID: 218319
           Summary: KASAN: fix UML build warning
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Kernel test robot reported [1]:

> arch/um/os-Linux/mem.c:28:6: warning: no previous prototype for
> 'kasan_map_memory' [-Wmissing-prototypes]
> 28 | void kasan_map_memory(void *start, size_t len)

[1] https://lore.kernel.org/lkml/202310151211.jASHBduj-lkp@intel.com/T/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218319-199747%40https.bugzilla.kernel.org/.
