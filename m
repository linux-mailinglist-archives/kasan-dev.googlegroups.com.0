Return-Path: <kasan-dev+bncBAABBH7RU2WAMGQEWAYJPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E58C81E1AF
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 18:15:13 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-427af266d32sf1036211cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 09:15:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703524512; cv=pass;
        d=google.com; s=arc-20160816;
        b=teGUYD+mgbNm4XnO/Fpl2rfWifFGC8Sh6x1nlJKroJZB7bMDyMz7m5hIziZjObjouO
         xLdA71x6eiJLsxbPU7jLyM4vKamEaKsJ379LmQ5JsfBIb6C2e8iJy2djlk3ZM50qmn00
         Lj8HuoLChNiyOd4n0D+eVEsSFlzj4W2tmzDk3rdlkL2P2UQqiCZOhhfR3seH8plXGvQI
         0RtXLmwEUKgYmz3izt8g2DYjbxX60Z21xitQV7eSTvz46oVaP3vH5eS35ID27gy4o34Q
         EViGZAXN9grJtoJThBAbZT+ZA0HUMf8bmjCCpq3Zbp8EsuOOvR1YcgcGwLW5d/LSEEbj
         ZDpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=/a/ZHW5Fa0CBoBBOJZ2ld3uq29gPq385qEW+kvfGCzE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=KfHf1rrpq/RjX8wKqk3r1WBdl9bc2VsppT4wUmTsR0VVe5g8phqEf0wNc1OKaaTpN6
         e4galzuaHzxPbq723f8xtgysibFR4tqVh1I9COkuyUWFCamH0IkvRes8/SxkVRh1bQ7f
         2+creKmiVPUxF7xXZuXMkDH7Smh1UDH/ACplYFKV2Ivm7ksRDGBKdzL4XEPXMMDD1gEc
         ktj045ZpLLVdX9iVzMrEzcujwno375vBiVGeUWBjiR2BLutjU+onzMm3K4Y+EnfmHXKx
         Ia5XZpB2sK3tHfnCTsUVyRIO8JM0AhZPanDdgA2pxTm1TURz0HasSNct4f54kYW+wIO7
         nt/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P+PAzHcX;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703524512; x=1704129312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/a/ZHW5Fa0CBoBBOJZ2ld3uq29gPq385qEW+kvfGCzE=;
        b=nV6sJzzE0mNpMW/qrFqIbU4Hb9r+w9mPcX0pgpi4/drwP19W6XsW3mg8E4OGy+KwB/
         fVrN5JcbLeApgDZcl6UORdtZRED++ilih1iWAcCra/wtJvBRXqpQQgrghU4porGk8XqR
         dfWkpEM+s0wSb4aCiBI9hfB7T/wEEv73FGHgv3X5r116exo0nHMVPsvjDHsnLfjdqmjZ
         V68VLsa+T5CaBCKKtQhgUTkFrC99GtUVhJgHwGAISAPJ0B0RvmOx3NKA3OcJGYW4FtIs
         i52QCRqKWUsUk4BHHknWIsomXbs+wFDTDaJl3N1n11dFGoOswn1doTmm57vtOQ7Njzz9
         hPHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703524512; x=1704129312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/a/ZHW5Fa0CBoBBOJZ2ld3uq29gPq385qEW+kvfGCzE=;
        b=fB2tFeajnvhmwNfRzWVu4NLES0aGsCTbTAJpZwn1DtnswZ4td8o/cZ4ehuCnx+9SjD
         owxyCkzmreX3RUXyCuqegU/9EMA0LVim7Dpw45UM6XiEy9AVRVui5REOK+8Hekmy3cL7
         vwvmM2n1k+yPDHZnqx48Jt5JIOFcwoQ9jq28ocx85S+skU7xnFfiU8SQi/KgimQVbf5H
         I2kQhFcGk22zgkkP8rByDC5lhJjKj0/xjCcMRLkYwyG00rOj4s5EYkdqg3MufH8gmlA7
         yh0vCvh6/WxUGE8KtXfOT34S6R1tokqjvhFb/M8Xy9Z5nMpLMFbZp3OU+0voWNmIKspl
         FQQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw+vwGwnDihT0KGsqvDXyaOqGyVY9aPDJ1etBF98sb3wM8GxS+i
	xChavWWcoz3bAl+Kb0XUhPI=
X-Google-Smtp-Source: AGHT+IFzLuiETTOJTarN0k0Pie0m4j1x3fmd86eaIO2mH2L7ZUVzQW/Us92GE479Ly4u/Orp/hvovg==
X-Received: by 2002:ac8:5710:0:b0:425:99b5:6113 with SMTP id 16-20020ac85710000000b0042599b56113mr451882qtw.17.1703524511810;
        Mon, 25 Dec 2023 09:15:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:ac3:b0:67a:1a58:78fc with SMTP id
 g3-20020a0562140ac300b0067a1a5878fcls1034887qvi.1.-pod-prod-07-us; Mon, 25
 Dec 2023 09:15:11 -0800 (PST)
X-Received: by 2002:ad4:470f:0:b0:67f:d6aa:f9e1 with SMTP id qb15-20020ad4470f000000b0067fd6aaf9e1mr4866720qvb.101.1703524511165;
        Mon, 25 Dec 2023 09:15:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703524511; cv=none;
        d=google.com; s=arc-20160816;
        b=TGi8ZQp+93DOWYWRL6pioj3+E8uTCCzzkyU9SOeEaTlpVHL4zKNqJSy+7lBXQea4g8
         nG2mDyEfNt8IV+rl/ddvIDrgDmYx/XMAxwmRqJ2wq9BavUVc6UXitob0zPM8fRN6zrlM
         obe3qOjTW9XZmoP2toDAYUXu618JVFyuAs3EeMDYjzijg7u1WLuXEIWCaxwNXWPrtGHS
         wplEkd6tdynQAiRnBBgZ2nj5SR6Q1p6FkMsR6eieYqm7eoNbTpxZglVXUxyibUa+VvJQ
         b/71Up1/qbuNFxJQiEBrEjziF4MkCt4h3ibg5dFG+Y7yU8+wGfAVktKqSUlmWcyyaPG9
         5Sgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=up5J1odrwQKnALb9zp5a4Y1M79AYnUYdeheMFB5aTUw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=RYl/Dh33tVCXNRoe+MFu5y3T/bjPstYs39J59ymOSniXAh17J7wqG+BCelmVggcxb5
         1pw59suP443o/YvYNcA8qrxVpGrrhEDEmHHJ13rJ3yruMHcLQaIDM7GHswVctSIS14ka
         88JesxzWXdvbV8CHPory1IEJm/5GhLyjm+I9zwOQkGmfmF6qfuwVAP6uLtF4SL9NJbc8
         CJ26U/bgJo24urN8GGJgk7iOrKei9oWk45ev6zelVKajY263q/GZ7RHl17XbXVu+YTqu
         y9XZ2RHry/VswpngXkm9otIIikEqz+zb4m8jl4bzUQfDcBaiQkBdyHhtMMIRK6MktiAD
         y4/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P+PAzHcX;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ra8-20020a05620a8c8800b0077576de1665si677063qkn.3.2023.12.25.09.15.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 09:15:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A013460C00
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:15:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4B4FDC433C7
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:15:10 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 370A3C53BCD; Mon, 25 Dec 2023 17:15:10 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218314] New: stackdepot, KASAN(tags): allow bounding memory
 usage via command line
Date: Mon, 25 Dec 2023 17:15:09 +0000
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
Message-ID: <bug-218314-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P+PAzHcX;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218314

            Bug ID: 218314
           Summary: stackdepot, KASAN(tags): allow bounding memory usage
                    via command line
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

We should allow limiting the total amount of memory used to store stack traces
for tag-based KASAN mode via command-line parameters. This includes memory for
the stack depot hash table, the stack depot storage pages, and the stack ring
used by the tag-based KASAN modes.

For the stack ring, we already have kasan.stack_ring_size with current the
default value of 32768.

For the stack depot, currently, when KASAN is enabled, the hash table takes up
8 MB and the storage pages are allocated dynamically with total size up to 32
MB. (However, with the "stackdepot: allow evicting stack traces" series (will
likely be merged into 6.8), as the tag-based modes evict unneeded stack traces
from the stack depot, the actual memory usage for the storage pages is
significantly lower.)

We need to add a command-line parameter for the stack depot, which limits the
total size of the hash table and the storage pages. We can limit both via a
single parameter: e.g. add a parameter for the maximum number of storage pages
and figure out how large the hash table needs to be accordingly.

It also makes sense to update the default value for kasan.stack_ring_size to
work well together with the default values for the other added parameter. E.g.
keep just enough stack traces in the stack ring to exhaust half of the stack
depot storage on average.

As a part of this change, we should also mark stack_bucket_number_order as
__ro_after_init or drop it completely (suggested by Marco in
https://lore.kernel.org/lkml/CA+fCnZeBzs+PQP8SQGorSsOe2e_NzDnqP_KksjfLwkUu+aVTZQ@mail.gmail.com/)

We should also replace the WARNING on reaching the stack depot capacity limit
with a normal console message.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218314-199747%40https.bugzilla.kernel.org/.
