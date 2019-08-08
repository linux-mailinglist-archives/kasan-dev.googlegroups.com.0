Return-Path: <kasan-dev+bncBC24VNFHTMIBBVFUWLVAKGQEXUJQKGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 56D8086CC3
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 23:55:33 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id c7sf14081374ybc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 14:55:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565301332; cv=pass;
        d=google.com; s=arc-20160816;
        b=0fZ1wt+CmkHLUvaeWHpfnvZGhAHv0x+MYu21gZuzd+7GPpzpZClu0qEOxVwYCPJykC
         0ryqeMYohNdNIc6pLStormPhkmWKvIARxtl4K+wPdAtdEVhqLTzCSudki+2tx9yVydU6
         mqavnECKXLpbS2r+UTsv159Bf42nU5P+YzaaJ7Mz40nN/nGK929zxEqmxt4CZaKZScnx
         rLkQCF3LYVwN1IEuRbab85KZxLtvVIIEF1lEli8meLe1Vm/CtPYjUvWXToheVkDh3j8y
         VW6IH7fxDyZiVozaUh68zQUJtHgBkK8LuPVI2TawlFfiHLAW7bJ2ei8+WiK96VjUxnqL
         sKWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Tftuzw88sCvg7hV9ZUVBofhNT8/TYWG2W9TVmfRYvtU=;
        b=YtPDXiI850K6YcpbMJEgHXvYh4kdR0gB0/aJy9/wyjyShSDk0Jmt2OGEWP/TT2/gPK
         tGwSFQWRy/PVcKQML6WsfKtVTj07ZQ2mrhWwP17mCv3mKrMAM47a4GbBSn1u74Xq/zpR
         r77SNuRqTdhdr5pKaDUgpBVBXRPmk2KCaZB0ydDiVy6kshH0wCbk4fWSy4VPpTFfT1ih
         xpr4ha4RCKFf+cNxufWRWYDMITZ3u5Y9FJbS+DiNjJEOUb3p14UTFgouo+4gcS7fFWBY
         GKS68PIcUAmVS4IuH6Q2k0U5hTL8+hv0zEcIKrExFnoRlZ2baAodyYqBfZbUpvjnD7I/
         9Btw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tftuzw88sCvg7hV9ZUVBofhNT8/TYWG2W9TVmfRYvtU=;
        b=hU1XBMFbxiG+1P0Oz5VXlJ7tT4sNXVwpyD7ySOWqWedH0rlevw5Pt6sGAMd3UR6vOz
         yTmlST6qeaP3SkwQ71wpaxrA5OWsStJDywZ8YJ+S2k/IFT7eI4iS4lWUMJITYJTkTkJD
         MVtoo8vw/OHM5uh3sIyos8Q9zTvIGq0mEZTyhovNKEUNfYRdf/5qw4NqRXmz6Pdw4NHY
         eFAqtsCnObAhrqu7lSRL1KAvx0dztssFw9aRRdeWujYv3Qvf9RkU4QKN0saf7jWHnbqP
         tXepEmsEKHlSkawVMpaflB0wMMndCAqDZNTJlBQQhCdVepSFd52a4vCgbMUDwSqnxFd6
         2DcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Tftuzw88sCvg7hV9ZUVBofhNT8/TYWG2W9TVmfRYvtU=;
        b=IRe4n+/LK3LAQfaMNhg3Jqrt90ZeBs/pHqV1I+nZzNH2JeL0cyFkUSMGSMNSEc3+hB
         pB5ujnfZVmQLGxIkUrFDmjOoskHeZMv929oj08HhHathBlY3z6mh0xYyaergVn/LNmbk
         9krYz8BdTaHiGSSq1f55XdwGwkI8XbawRdibu7J07NBOlWhX1v8nflZA3cHiMQijeG1c
         psNL8G0qCbm7EZjRrHGhhDuDM6DatUcABZ1NeQyFOPo0811B7Ayxn4LBEYdCn+T8QIc+
         nh6ZMatw5LYkNJUFOitG5E7WeS4E3OtOS0+nDM74z1YXxR56SpgBJ9CbnQYzmpPEZ7+y
         FyHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVnZUzumzdO03laJbqlDvmhgX/E5ug2IGvE+jCy7704+DoL0Hgu
	nFEg5bsZiF96lcZLSOX5v1o=
X-Google-Smtp-Source: APXvYqx4jNn7Ff6PLbShtbbQ+g/2e4eGCOSPAe4uWrQNuOlq7jqlkTnA/CVBXfM9CUV3/3XE1VabeQ==
X-Received: by 2002:a81:13d4:: with SMTP id 203mr11710811ywt.181.1565301332286;
        Thu, 08 Aug 2019 14:55:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d387:: with SMTP id e129ls4399331ybf.2.gmail; Thu, 08
 Aug 2019 14:55:32 -0700 (PDT)
X-Received: by 2002:a25:7357:: with SMTP id o84mr11793460ybc.54.1565301332076;
        Thu, 08 Aug 2019 14:55:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565301332; cv=none;
        d=google.com; s=arc-20160816;
        b=bJduPPQcMBNmiF16PYXkoJiWqYfLztJWeM3iCotUzZqRYNXh95KJnbeuxiBHhxXhji
         C0rrEvpt25uwFWoklGOLWVatWQV9F7E1fQaTlwCQ0GXryV4fznFvSvAUaVJjs5IGHAUC
         i0ygSFhMQgj0CeXw62Wk8R7OUinCkpdJDQi7EcqxpflAQgf2AgJFxisrli0JQCJ8wMKT
         x4QdsG15UwIdemYR6Ekm5eQ93BeGWaAbaLA6Kw8OGcSaVbqCbKI9dL4+uONFKUlEEAKs
         +WvEt7ZOrncdMd1WR23+fZOoT/1Bi3GJIGyu6EyL5dJ8WYlnYDebWYZpRLJO1DC37INr
         6BxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=KoCqbyb8IYqL9GXEqDBbf0v3MacM8hlc/S+gh8oWQLo=;
        b=ufZJZsDet7Dar6hfpe+OLCguetOiGsSzXKDnH2nKK2lQSkpWA1OkbmVbPFMW5NLGnx
         VXRDs9Y6XFYKpHJRKwrdlXBtn4jijf6oBh8esRcIkl7eikMLH8QkV8Q8AJF8fLaz6A6L
         Si/RiklRFftw9psO+aUU628fHXsMM3AWUJv4EOvCu/I5Edk1oiXGmvf5x8or5yOpo8PD
         66bw3CCjn2z2lDs0GZTMTozRyo4JZ4NqYtRVI6Davn/m0aawn3XbExOwMVbcSplSpIRo
         Zr6CcXL7vdLIXOkXihYxkFtGapAPCh0bkiCtO6pT2e1JIAbk8I0dNI3WrctJe5lUurKK
         udKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id r6si541321ybb.1.2019.08.08.14.55.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 14:55:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id EFA7428BD3
	for <kasan-dev@googlegroups.com>; Thu,  8 Aug 2019 21:55:30 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id E28FC28BD5; Thu,  8 Aug 2019 21:55:30 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Thu, 08 Aug 2019 21:55:28 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.isobsolete attachments.created
Message-ID: <bug-204479-199747-IwNPLjdGAz@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
 Attachment #284177|0                           |1
        is obsolete|                            |

--- Comment #5 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284271
  --> https://bugzilla.kernel.org/attachment.cgi?id=284271&action=edit
kernel .config (5.3-rc3, PowerMac G4 DP)

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-IwNPLjdGAz%40https.bugzilla.kernel.org/.
