Return-Path: <kasan-dev+bncBAABBSPY6GIAMGQEMFZFTRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E1C564C63E0
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Feb 2022 08:39:54 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id u62-20020acaab41000000b002d48ee5b710sf4854550oie.20
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 23:39:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646033993; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2dGOC3Ee13DFzr2f9KHiMAxu6VjtJlGyBIOH5pzCBSOQJD1PG1E2S3Q8gvVgDxrzW
         XvjahdFzn2wo57HP1654zHjilnxFnxcaUdLGeny/m9uvzZ/eLnpwYazlpkhUvUzHiZlH
         YmefUUSWdbVBzgT8paB5LvHqAISW8t+nssup1kEXOTsuQ3PlJISd+4/MSewR+c86viam
         0sdulAwekg0JAmDMY0HQ/Jp48iUoOXhwiXE+IWye3sPyFXw+emTefah8OgZjbYh+ulQt
         PDrpUcmBYHA2NUuZ1HFwko3u6a6FEAOWF2PobbVMU3PI088pV93l9MgEtz39yKc/LuSX
         Y70A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=st+MF6O2aGydDQbdMgAHQh8b2eZamaOZg83uez8ToFQ=;
        b=0WcXUIeyComtr+q5+RglfbMLJC0Hn7KC97f+JsXBPPrhf4Z28n2vG+5aGjkjqkVKvh
         1mkjrVT9V2xNG/DPz+LmOYvUNeBRttzGtTomd/OhVVutxVfv9W8JO3L+WVpEnyQWznw/
         5JkmAwVmSpfJDClpOIcB7aqLOTKHZAjyDYvCtbfjcfuUWdBHOWYJDMweZlxUXoHnTIiy
         rg3j4Xz3ynC3gWb4gxFlWILNVxuN5RJHT5oidK2WQwrivU1iH1uQvIiIik1h/zruxF7H
         k0hGJEguzcT6DvYhhWkWtJ30QgPLDyA7vijaxgK22LeW+OhVlYKPmQoHu+cyrUwAQeGh
         2KfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pxEqnRPy;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=st+MF6O2aGydDQbdMgAHQh8b2eZamaOZg83uez8ToFQ=;
        b=qrTemK0cyCxo1q5jUJ59/16NXGd2P9hJqlhbDRR+WiSxtcOO+PFeU/fvybhgCZmDWI
         sPKa5ajK1hcU25rfOfq0Bstp3H+2PV1RT7bNZyTSMxRJ4LEbrDxTlRUoncewFvChKpWP
         ZePdNut99jR7YPkB2wntqpXMDtx9SK38ZgM2snZT8FOYQq37nxVwf0D2SdFA5Qbe/mOX
         NB61Md/dKh9HxPk3aMb6Qrz41P4WQA6rhIx/xJaPNM6gDQbnG62RZd3cykNmBStBEbuD
         OlHpku6uvh7m7o84iZC06fk0/imdnYaF4xIvY4vNOEFlVn/9hm8Cp3KjpXesxsDibQ7A
         IzqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=st+MF6O2aGydDQbdMgAHQh8b2eZamaOZg83uez8ToFQ=;
        b=nHUvbW+ahJzB44kDe+x76JXzzKxvRrOymqTDJ/hVj5WaYKhQjIXyE6C1JkRu12e4sd
         oc7CpX6mqtxk/4Gsd6QgpKcukwJ1QY7kCZqQi1OzVCFtNW3w5FW1P28SvEmw84+l45Cx
         lwQeJZy6WrH8QeDLIiCL3vs4g2ZAnIol2FOTtCONLh2eoXBmOQ3F1xUZUxg9UQiIBH5c
         Kf7OXY6fbd48xBY2bkbCMG3VafC+uROdkB9ma++Y2nHw/m6S76MyqNu0UXHuR+qQgNY8
         FfZraujfJYfYSap3uukCV86ui0C+v9PvMHVyWGWAvcPyuKPMkiLUqLcN2jDJDXYl4QK+
         PRLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AazdHhffudHXiW4MLI+KE4l7g7X6NWu5faCH4BpJjjH+5RgKG
	/9zGa/93joIC9tsXx8mFngg=
X-Google-Smtp-Source: ABdhPJxZZMLhtJjHmk/1QA/Rf7Esp5Dn0Pi2Xdvi4+ZRQhwj1ibxoMojO9VdB+NyBD8MLtINjX+zQg==
X-Received: by 2002:a05:6830:25c3:b0:5af:538c:3635 with SMTP id d3-20020a05683025c300b005af538c3635mr8221959otu.198.1646033993523;
        Sun, 27 Feb 2022 23:39:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2123:b0:2d7:b26:4be4 with SMTP id
 r35-20020a056808212300b002d70b264be4ls3640786oiw.1.gmail; Sun, 27 Feb 2022
 23:39:53 -0800 (PST)
X-Received: by 2002:a54:438f:0:b0:2d4:4348:d58b with SMTP id u15-20020a54438f000000b002d44348d58bmr7578830oiv.102.1646033993248;
        Sun, 27 Feb 2022 23:39:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646033993; cv=none;
        d=google.com; s=arc-20160816;
        b=MbXruhA3PNiCtW91/qF5nbU1v1fu+nKHiRdgjSb6MuaSp4B20gsmJsHYrzLNpJJw0P
         mKMySYdtsNxn2gDGA5lhV97bL7W5dgPgPZJtI1gjw7siMH+EcU+ns3jVpTJ28waUwZFa
         NrLuz2aNfQPz0Y9Z1jS4wSwq4d6sj0maom7xQHAnUdQaWhxmbBxW8dskAmJ/xlFLlrHC
         n8j/ZxmOmf6C5Ddh6EvCv9MvN3mY7pNKe992W+MD1/DwJcXsaDCRWtGIBi1o1G3PBhrD
         jBEQIOnBsvaGUfp5Ihx2h9QEt3x+IS0ur6F3Se5r6sIhzZ9uER15s2LmwZKsqPSdzmBs
         /qbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=YAtSiC+v9LoelhQmr7VYPJ96fXf8P1EU4t8pgW47LDw=;
        b=YGlWPhXvkfvc4JGlz8xzjkwEE/8Qc2y4XJJumZ9D26iRB0/h9B9yF4d6IzBgwevfo7
         fNCQlub7fQ6xyQSP98ShnHRkyaKlJPXxXzXsnnfakmxEXTg2+Meh1gNJ1xGTEtNmG3fs
         WMm26iG+j6ioUUQRzI+5l4yQHf9XQU4pWBPA6QiDQbGQ8vnCeq+ogDW3PzdfxKMAUmjD
         TV1tNu7MbEqPmVnzffka4w2YIeBx1rPdCCtPCJx+PnQdBqTy9p50FTDuEzYVpn+dipcS
         87Df3kkzkCI+xxi3GTGUpqQYQxMgaNdCAeIsgko9LB5gy9ZxqBXtV6mxSuZvHV5o6JIO
         VNLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pxEqnRPy;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id hp6-20020a0568709a8600b000d70382ac1dsi318014oab.0.2022.02.27.23.39.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Feb 2022 23:39:53 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 04A2961045
	for <kasan-dev@googlegroups.com>; Mon, 28 Feb 2022 07:39:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 68C25C36AE2
	for <kasan-dev@googlegroups.com>; Mon, 28 Feb 2022 07:39:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 506B0C05FD0; Mon, 28 Feb 2022 07:39:52 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Mon, 28 Feb 2022 07:39:52 +0000
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
Message-ID: <bug-198437-199747-woa3xCESW9@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pxEqnRPy;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|REOPENED                    |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-woa3xCESW9%40https.bugzilla.kernel.org/.
