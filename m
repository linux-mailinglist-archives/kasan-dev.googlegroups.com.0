Return-Path: <kasan-dev+bncBAABBDORU2WAMGQEQBFXYDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id BBDD781E183
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 17:06:39 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-336599bf7b8sf1882849f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 08:06:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703520399; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4tsfLmtxYUuO1DTh2EBzTthwYKSAFgkcBdwyq3gMW8HE9JakI0DoUH5TfI+8nXwx7
         7WDkBuTxRBom9SL5m57mCj6WzD0eKRCChN+d3k7vZ82Bt5l6ke6iB5w28yLEVDaKDEPV
         nfzFD3qaG/sq+QUAMuyteeUEGDYnFp6fGYksETDYsINrLXoSoRQQqzb7QEoKZMJS4HF8
         zNRwrEBvjEcgSO9ccyvGXOJzNA3yMphKJ/8iYzX0trG9Di2fxROpV4Yp5opI7z5uM1Fh
         psQYDBeKIrlcf/X4wKxC+3FrGGBN+O9SjamtC4mz8iHI+t9TPyPCxe8T+woxMxJGVgdy
         u9GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=6xOAKatbZLmT3OtfL3t5l9q+aLofmDi4vJXez3oBzdg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=d/g5ThIVyIviotgxrpf+BEeKmbhTzVs+XdHycJYYbm0FlVcqSpGOp0Zv8cZ0F5SwQV
         Rh7+puKcfTcSeUd04tzqCyK9se9Z9pD4gIh2e08KDT0nHlEwi8dxPru4Rs3JjpOO/IId
         MIPtPnTcV5z0SCPxExlq6SI18OLJxYImB5FQqelc/Tl20C9Cl0bQa3Xr0EjIJ9SBAP76
         W5s/grg6gKGqe9msWJyUdr1FGHvvZnnvJn+b1vZ1+tvQlXjEIys9PC2HsOCSGP+aGBCS
         CpcfYj2JLsV6nPZWHSbff8UV1p2qKMhM3zGEsxEM47IF0m/RfBze9u7uoK32IJ9YNXeW
         hfDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P46HsOsP;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703520399; x=1704125199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6xOAKatbZLmT3OtfL3t5l9q+aLofmDi4vJXez3oBzdg=;
        b=P9DzNZAC7Bw08lgX/3g/CGDv8uQRfR9MUzmfl7UV9pxZ67urj5j/VikfMoJEWOnh9+
         bmvWoBFpD5fK9E5b4rMlDNBWzBPGd7CONWEnRWywaS3fZyDhelkrRsxrFDyqCnuJx7Zo
         neoIXsldeRX8452Jbkmd5odT/WE0QWy4VsV6aG0xAH2ONNybYjvvqj0QZ9QWCud/D5mM
         XRAFPLTsCap4wdPeWGI2nJRnGTysWFpg3OIoFJryvHseswvHyQWyRqapaPDcUPYzapEu
         xcejN6UQpYOMiBWqlhZQ36R7hsccMLsdFcTJ8dSHDRZSGDm8ZwcAdQGdbIVYnIMGjsPv
         OsRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703520399; x=1704125199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6xOAKatbZLmT3OtfL3t5l9q+aLofmDi4vJXez3oBzdg=;
        b=elFIxXKMkhQoMH9yxnzlQGVm5ykFrWdGKfwObq6DjdadFCpRwK3vw8zV3MmXhKIjy2
         d+YC9FvpySQTRuDE9PkphCUYJ2M1MdGMm00auJKJVcBm+BKrsqPsEUZ20X6fR0IpHxEJ
         rQappM45YNT6uYvKqDP3IKQMrwdJ4hX9JD5apGpaXzvVgoQ9I+NyS0T0cr+yWLi1xVJ8
         cLk0NY1yWU+yqejSmN8SxQYo64xQ6SvJMAWSrG1Wvo9tl88pXtxnv+oyOgHh077znAMq
         C+naT6/+PvdsrQSql3PXQ2k+kPUBK268Kj5oc6JOB58FQkgBnhpVoRwl501bYHO09uZQ
         LOhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzWV4y8+PoghilTNizJ6KMcAlJ+P8NAtBHgE05aL7oDMjqwoHUR
	E6aHILUS4ygkzOESCN/u1AM=
X-Google-Smtp-Source: AGHT+IEa3aGR546/XIoqm9RLKWwxNBYs1o0oT0Ovyt9gJvXNhrsZVAdLW1DAIutZe5KJTfoJf7Nldw==
X-Received: by 2002:a05:600c:2296:b0:40c:2ba2:8add with SMTP id 22-20020a05600c229600b0040c2ba28addmr2948617wmf.117.1703520398067;
        Mon, 25 Dec 2023 08:06:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:548b:b0:40d:3523:8076 with SMTP id
 iv11-20020a05600c548b00b0040d35238076ls93865wmb.0.-pod-prod-00-eu; Mon, 25
 Dec 2023 08:06:36 -0800 (PST)
X-Received: by 2002:a05:600c:1f0d:b0:40d:53b6:3d1d with SMTP id bd13-20020a05600c1f0d00b0040d53b63d1dmr1010879wmb.158.1703520396617;
        Mon, 25 Dec 2023 08:06:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703520396; cv=none;
        d=google.com; s=arc-20160816;
        b=WqxTYm7I3pDi0piivVDUxuqNK1jLi7cHdnmz1Gef9GCiMYpjcn9oRHBFg5tLgbqU31
         TiXKNEqYAwGobDOCcXdGem0f7AgaoSGn9NGRSmdUXo5xdTXGUhcEf03CdUzh27dSPFJ1
         ZUb69wblUl/SajAEfmmfvKCrGIvyzWAOF/OiWIz3UHLKpoS39EbLKiZ5jHJ9bIH5Ba55
         gHOKPby/DTMpWFXXA6fDs2I1IS0FmifowOni9o3LpB8RAXldI5KxAQay5SxwfpBhOs0B
         kadTWHUcKKaG99xiFRL8kwYly5yA/mMe8BZf8xVPB5n1Eu9CQnPUN+/hGpD3UsSh+X6a
         v1aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=BIqgta7PVTJIFPI+Y0B5kQshCCsfUV1dWAubNeJP9k4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=0lc+OEPMJSqDVWEC2I3Aa9+qRManpS9vGRfBI+c9jHZ36cZznIlDlVSf1IqePy+MHO
         IngDhAgbMUUDZ63RN/rKanQKQ8XKUleQxZ0EretleYy/0JEQELlk+K99KYSvzNc7Oyhr
         SG0L9CGKxEalEpOB2f7j0ahzAarPVY18ErRnXN511N/EDt8fGZJNtPD5QzWAZ/WW248Q
         grpaW1md7y+JmEZh0vm+HGMPxB1pHSupW6/s/5BdSGx1Y8lVsl3KvkA4N+vcIC+9xrOP
         fTwV/0gu9a6sip3V0E6a4VAEAJ/2FFuFeDlihuriKmby0z+ge6GIqc5JVw6gEWAj38cL
         mqvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P46HsOsP;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id j34-20020a05600c1c2200b0040c69352d1asi180949wms.0.2023.12.25.08.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 08:06:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id E58D5CE0E34
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:06:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 2E398C433C7
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:06:32 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 171A4C53BC6; Mon, 25 Dec 2023 16:06:32 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Mon, 25 Dec 2023 16:06:31 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-218313-199747-APvwaPvCcY@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P46HsOsP;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|stackdepot: reduce the      |stackdepot: reduce memory
                   |memory usage for storing    |usage for storing stack
                   |stack traces                |traces

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-APvwaPvCcY%40https.bugzilla.kernel.org/.
