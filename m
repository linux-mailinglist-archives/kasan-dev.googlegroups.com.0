Return-Path: <kasan-dev+bncBAABB26B7K5QMGQE7WTRYBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A44CEA060ED
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2025 16:59:40 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6d884999693sf278308856d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2025 07:59:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736351979; cv=pass;
        d=google.com; s=arc-20240605;
        b=MN5JjSGViijkFdbuvmUrsUee/hWW1zBAbsvB2Htyxj4BPRkGzpITuydMIkqTRlQx5a
         tYAM3gbSDCwbtOgLHLpiowzvw5ym/trVh/3os4mT09nuElUUKY0BCaDZN0XNOIhdezPK
         iPY/A+u9s3JDcbfA9qp8audixWrT6aMWv/k+blLwwHU+EbDpAnnHlGE+kJdfdfbW8vVn
         lFC+JcREbUFzL8h457nCDlz/IqMPJr0z9G9W8wJXOZ/wG1gRlZWsde4l4J1O8MUdsjRB
         7+r2G09WbpVpCV+TSamfYR3sC3Ilv9WooxCbkgzeD1yl8SVJDCJSe+dDa9T61sFOkt7K
         xtFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=dT3RaCyotPPORxYL1K8W4z/YIuyvGSQSFDK948OTu3I=;
        fh=jzZiWINuZ1rU/QwP/Qhuu8qHejwBTII9wqspjsmoNhY=;
        b=PbjJIC5IDi2+2FJLtUfEmd8wG1soei38IUcj4GegZh7/snP9RuguUWupj5B64RxG/b
         7HMs5/rBoq8HxhlqEGOV9kq3mgr5GDJGC+u4Mug+FR6pf2C/8/DCLcWc/U3nQhS009Mc
         +BTe8etIjbWJim9slQaO1jiu/i5qM9C2x4u0UuR89/gcWQwafASN0ECM6T9nmpIrVNHW
         ZWfIBew2Bcls6qsw8N5uPoXwSKPC3d3XhxxyxQdDYX87KJw8mWZmt5bJDC+AcNBFGZ5s
         cyt+WQh1QIBic3+U66MHi00i8y5QY81DmA1M2/haWnmU7YN9GGJ9aIjsOpsoAMde2MbF
         S25g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dew8Qx8Z;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736351979; x=1736956779; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=dT3RaCyotPPORxYL1K8W4z/YIuyvGSQSFDK948OTu3I=;
        b=ShmuLEjBOrLLYQPpYXr3EZbOr8+f7aV5NmlcagWpZTYOXzZSAroYPA8fWuNU6RvF4D
         wSm+vVlCotefvwKD02/+SyEKeJJctQhIHVAwPzqyznZN0RCXaePusNXNiS8VjNhJeNvj
         w/DdP0TbDrPxrKbRevdq8XhaCeeoeWQ92GpMvFpa+g4yeX0OBwS0GWNiCeLYl/Orgda4
         dVvM/8BaDsWfqp/69sd7extEFB6yFkkWgkWFofkha6aa7136YfioYIyM7Ui/a0+n3vC2
         LopG7hcoUIC+G8Mpy7tEaVOfbTkx12sDt+75fm9kyIxMB7U3dIZSG50agGMVESHp9rEA
         x2Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736351979; x=1736956779;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dT3RaCyotPPORxYL1K8W4z/YIuyvGSQSFDK948OTu3I=;
        b=dcJuzP63FMmBnyj/52pZP3EEXoZmxJPKrJVxdoFPcFPmZZyAjMsJBh2Ey44pg056hh
         m5AJuaxm4IRVviUzbhrUl6J0ZssZGcsEFclCDHypYui/KXK7EEvV2n/CcWYFYCRkztYN
         FRkoGCkoTq1WSAHwrfZivronadnafcnWWAuB/awmYMQ6ucjJHZIdMRd+k6CLVdr+GTjr
         INhCdB3tRe4lozlN9CrLBXMLBq5pHOV1MOgs78RAbqVaOonAre8rfEb6j0JB5pCDr/4G
         sk33OQjNCLles+FuutY3UEZTMrn685TbKOb52rKph9yUPLfZw05fd7e0/T9YtpKW1Q8f
         PKLg==
X-Forwarded-Encrypted: i=2; AJvYcCWM6FgG5T/HU2t8tuHndJwvekzfKRYM6kdTGITd2l7zwySmyzTRYgliY5G9Mw8E0bsEesVuRw==@lfdr.de
X-Gm-Message-State: AOJu0YyZu1rwfdP708GSL2kzxezFbUDY343aOBGVN/ardVmRO9XqBHiK
	8q2j/seC5Jup0kD2nzsbOqpfIGGHisBC4zaYXXMZIFTTHzJlkAjt
X-Google-Smtp-Source: AGHT+IFQFnOaGm/GigYFVhLtycO1g3WN1bA2Vp8fSQnaqNG7DfPFDeWGEs1WHLfyzIR205IlYvJ+cg==
X-Received: by 2002:a05:6214:242f:b0:6d8:a5da:3aba with SMTP id 6a1803df08f44-6df9b221686mr60432006d6.20.1736351979399;
        Wed, 08 Jan 2025 07:59:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:480c:0:b0:6d9:832:c74c with SMTP id 6a1803df08f44-6dd15481939ls82888976d6.1.-pod-prod-03-us;
 Wed, 08 Jan 2025 07:59:39 -0800 (PST)
X-Received: by 2002:a05:6214:4282:b0:6d8:7ccf:b692 with SMTP id 6a1803df08f44-6df9b1dfc20mr52546066d6.11.1736351978755;
        Wed, 08 Jan 2025 07:59:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736351978; cv=none;
        d=google.com; s=arc-20240605;
        b=WSvd4+MvTINerSuXQX7/m2cIC1Vo3uLF1FWfUH3E/azkv7vOaXlg93RRHrd1s0ThVb
         eKPMIewiWRCctweRGL96PoEOPvM5MRt8s7CfyuMM/7Yr8Fu3EzCl8fleoezQeVR+2ngh
         ArzpsM8dz9ds5T6CB9TwmiyfvBV7M+BGm+2eNqnXYSGuBfttkTdZzUOieX/BPNmfx++K
         n2RTvb/HVkVk/zvC/Jw9H0jSg0R+ALi6A4B7C3XcBH3WCYNWC890XbS3AIsggqgX+UeX
         sAeobkloBhSXeODeaYfzB3vB8xlpujlL2SjFvQ+rzPfoaoijFRyJAVKLlJ6F736CoSml
         H87A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=JWqiA8LmeDm2+v+ParQaoFJ42C6YdHMxVsbcWTjM9TY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=QKX15TawLXhBkEI4ueX1hILxjl72mLlyL5QOVOy1Vi0YBW0tnZTrT6DXcrooDQOiHT
         Oyf70Bna5f/MXfh5kl2+mxoHBky/KDx4J1PmbXMkwPKt4r/hq1pl9qbw7BX3tG9Tf3vp
         Vx/h94NV8hUIQFLlumBgsWE2khoQN8TY0W8f+Oxe+H9Ha7jtvlLKr/TQY/wWO/bxu+89
         /1nsE61CY0lhkuKXFaxtdbwgdv97x7XOUEKQ5RnG840+SQ3LJx3nYA51zPs1qZQM77t5
         LwbzL/+aYzwkznNIuOvMDRyy5qQgKiZ2qr9pdbo2v7aS+pSjlq/6grDK8sWfLEyQLHJp
         EX0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dew8Qx8Z;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6dd181a2cf9si16310746d6.4.2025.01.08.07.59.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jan 2025 07:59:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 43BEC5C5405
	for <kasan-dev@googlegroups.com>; Wed,  8 Jan 2025 15:58:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 095C0C4CEDF
	for <kasan-dev@googlegroups.com>; Wed,  8 Jan 2025 15:59:38 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E9BBAC4160E; Wed,  8 Jan 2025 15:59:37 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 212479] KASAN: tests failing with KFENCE enabled
Date: Wed, 08 Jan 2025 15:59:37 +0000
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
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-212479-199747-I5IwPY8Lw7@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212479-199747@https.bugzilla.kernel.org/>
References: <bug-212479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Dew8Qx8Z;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212479

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KASAN (tags): tests failing |KASAN: tests failing with
                   |with KFENCE enabled         |KFENCE enabled

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-212479-199747-I5IwPY8Lw7%40https.bugzilla.kernel.org/.
