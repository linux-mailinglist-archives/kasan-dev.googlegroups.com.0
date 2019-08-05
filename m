Return-Path: <kasan-dev+bncBC24VNFHTMIBB2PMUDVAKGQEJWQYYSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 44DD181E54
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2019 16:00:10 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id j4sf46167305otc.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2019 07:00:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565013609; cv=pass;
        d=google.com; s=arc-20160816;
        b=CPEE0gTe8dRoygbxjW05YRRGSKrJM0GlvVIwYCZea3gYVf+dXSX15a86TN3rR6GYfZ
         eWaHx9TAa6y3eM1pG+KZBzxjQZc1nP/qn5TlD+r7iIgr0fhkMp38RfNIq6NQmsjk6PKU
         XsrCNavKO73QI3yD1H74Gj1n5kCh4grCCmGSqkYfz1rdKTuCFyN6BB+ltBSA9myPC1ko
         KTCvmFz4u6XVF1VUWr1nDIDHtRfhW/tVS6/2bvGTVNGsAoDCrnHwPaTEAy6WUb/BWdOe
         yVoYpmInJSRBpQ0whZxdy3TXAQ0FPKw7o2Wuj9u/yqMB7VqfLd0dHZSgoXHnq1fuUYYN
         KLlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=OHvHV8FCw0dNtA1e4cNk1EQe325Zu1ECJOgMNhwCn7c=;
        b=ZVA9m9MysLYGcuWq/dfK7QNYIIBnaj+cFnTdPz9w2ooh4ihtNgad58SHle/5wyZIo4
         H+cmkDhE5wO5N+Age/cMgVthRVEiqgjyMyIYR92laMyncX2K2Pm4iqCWl42fdSKjvW/Z
         3fFigBs6AjCxhKKrVbwa13sG5rlt+zPoNQYHvAxirM/ltrZ8LMXMakrJB+NBjvVzu/KJ
         1wLxmjzZiTn3CSPK1OaVajq2bwYFTTH6c7BdCnfX844uNvYfMqoffZed/V8ld5vsdfTb
         KA297UN4+auJtk2p7RN8BHNTJ86qHSb1xdnh6XI9rSt3sknd3eCIL3KTisdlRw+uzfSg
         tGNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OHvHV8FCw0dNtA1e4cNk1EQe325Zu1ECJOgMNhwCn7c=;
        b=kAP2rtLKSg45C1kG7wFzQO4LOtYAB7qckweZ6h2Eq/eYOGQhJd9oHBiq5z3ktTl5gf
         535hz64APRWREwq3UVK9JcdzDqgD643NUt4xqX1VEvCMNCU8yy5c5ViX4syQFLtnfePj
         W4JytMLRUOL1EGM7dmIcbnih2iYd6Y7aL6U/FsVQrwatOmmwOkU/Idj4e/9GMwffJfzZ
         St82K15BB5cfFVdOtyVy6QxqjK75QiyYTDXE7Mzw/ht4naqkNkCDp+hEJBBSmv8FDl7S
         JgmzOO1oLZ6KUNdq70HRrY+3F1Y6sQIkOZJ56Ew2cagl48OblEh1+SGstktvRzHCJUvT
         bAVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OHvHV8FCw0dNtA1e4cNk1EQe325Zu1ECJOgMNhwCn7c=;
        b=qHmgnfW9eBXdHYOTk6sJLc/1Z/nLSL0FwC8clXD8gJZc7kJWDjovlyUW6FP10g3m57
         j6LfPUIMF9jxqIfp+4//CssbSE36GxkFnNiXKpRWkL5tPaDrzDKQuwhRRbWDZoN3FAru
         sxxuk6Sk8ToAeUlhZYDil6B+lFvPh8kkeBYyrEGt4wJOsU2Gc/ppG89MFDg/mMBoyaYz
         wXR1j5Qle2paGHQqJm/3jkM2QPm2y7djTCF+52LXVITl86S9gTHEhxgzHvYNC9iPOBMh
         6BL3O7H92p97Y7bf5kYYXLQljaEuR+5aeli10n2/A73B3I/N98i+6/pTBvb8b5esMB4z
         XdBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXUlJvfAzqafxar0Sc8E6zb8/na4IM0wrFjwbi8eh432QenF2PR
	QFBcppHhEaRehmj6xHeOkoM=
X-Google-Smtp-Source: APXvYqy223AujQM3Utfzmge2VvGD6lDkpj5JuBVhQAkOTxQkdd0aJiLzb+irZEvoDv9MkK6lZNEQQg==
X-Received: by 2002:aca:90c:: with SMTP id 12mr10913360oij.91.1565013609070;
        Mon, 05 Aug 2019 07:00:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1e97:: with SMTP id n23ls386420otr.5.gmail; Mon, 05
 Aug 2019 07:00:08 -0700 (PDT)
X-Received: by 2002:a9d:7c91:: with SMTP id q17mr5494161otn.277.1565013608856;
        Mon, 05 Aug 2019 07:00:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565013608; cv=none;
        d=google.com; s=arc-20160816;
        b=bSh1nhHn3ecvRAK2r01bFr+toV0b/isOGkEC+zsagSGRITdEf2Oql+TprBpnREtYJH
         Wa9FKqpPwPJTOZw7sWhzAXj7wOCcNB6wQqljdTR65i5oufkVapJSoQg4D7BvNR9xawNg
         Bim0xFU6h4Z5L8xHUzH3cu+wVqXA68uDQMD3VwnX3g9q7fWHb2j2GmAiLO+/oFgnimhS
         8kWhiwHC0Sk5izhSQAVPZUNT9q+35Zt0ErsT9m26yFVyqrjvsibqg5uY/8sDVI6zcv04
         ADUSZTMrGA3v0M6gpT3leXS6Scc/bNjxee9rft/C2kiMZWiSWF3A5yoC+Ti4j7q/DPn/
         sRIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=CoC3kEbx/wMCWHUDodtI9Kxs9DIxvz3tlf22zo6UZ6U=;
        b=uB/Qx+PsBw1yjUoOX7P52R8/GOhHONpzC6KzzkPCoj10+sXS18/1+KNiRrkxkGYq7I
         Lpswh1vOA7Skl2tmUA1MPafYWaeWTUk2uXcACl0bgbe9SGm1Y4Kts6Y6PMXeKqsqAt59
         2An3g1gbXfEdFtUsy/Hid0EXY9W5DwSIuLwGwRMRtIjV2KW67CaXXaBIFN9HuLiytkPy
         Raj97sy3Y5cvhklEe6Up9BXShK4I+VAgU5LXextDNFsGAdprrwvS2IjOoveSVrakexmh
         q6D/6WGXKTG61NneAsoggT1qLOQRcsTLtcWGyDdr8IfyCkcxQ23+/GLQH0iWcKbletDw
         4GFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id i20si4684324otf.0.2019.08.05.07.00.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Aug 2019 07:00:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id C055B2890C
	for <kasan-dev@googlegroups.com>; Mon,  5 Aug 2019 14:00:07 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id B293E28931; Mon,  5 Aug 2019 14:00:07 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Mon, 05 Aug 2019 14:00:06 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-Q3jTO8kghR@https.bugzilla.kernel.org/>
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

--- Comment #3 from Erhard F. (erhard_f@mailbox.org) ---
Yes, at least one usb driver is also affected.

Also radeon.ko sometimes loads ok, sometimes it stalls:
# modprobe -v radeon
insmod /lib/modules/5.3.0-rc2+/kernel/drivers/i2c/algos/i2c-algo-bit.ko

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-Q3jTO8kghR%40https.bugzilla.kernel.org/.
