Return-Path: <kasan-dev+bncBC24VNFHTMIBBRXFW3VAKGQEMBXVZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id B6E1E881A8
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 19:52:08 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id k9sf57861820pls.13
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 10:52:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565373127; cv=pass;
        d=google.com; s=arc-20160816;
        b=QTJCSzQVG8h0N/NNNnhEfFNZUee7Zngmuj1IPGNFFQu76ayQeUaHPU5WGBsNFU8DcY
         fzckdTF9bgAAC5kntEIG5QMmVbprdT7l79yCIQiBCjCtVNzvbL04hNJ+2r3qlTLfgVCo
         jEo25RcrXqvQmD2gC1iZNrU31IrXRi4JTBDCFW4FEw8VUgTYCytuifW8XYq1+46NnOXe
         UylBah/Jl9J2X70KrfZ+hoqs0wnZyCr+HGe1J2LHlBswrQh6bZ1K5SjytfjX9AEWI/9F
         WQo2Oc7rwoPVgfsMdg1CoDlU/v2BtZhQGDzou+rTk3oB32ZY6D3uARuHXnzCt49fsPWP
         He8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=F6pPYc3Y/XzUcUEP4yGrUHAF9vZJnHqHCXZtWrXkC/0=;
        b=fu6rBWa9M0UrFNFkmkcfbvv0LzHU/+1uu0pUJaPwehOjVUkw9fvg9RaKceybhJCMDa
         N5G0CfgzXbi9zAt8KU69Cme1ZrqTVIQNwdMtqaLcu3v12g8OR1jhXoSEEfWbm4NchaBF
         XpuMc34GJA5byu3vF8ejtxp5l1FxzG8icFOMVmbpk55qZ1yRGiIsiJLmF4yr5S78Fdq8
         czC9KCIJd3g33NsyTI1zPFYPbzFQ+Z5g1AArL7A+0iDTI732c0nYTsOSDjWIZaJFplBB
         UUnYdKNbQBDq5U/xf10iV7iyAALX0/t9qBqBqzyAaCfxcsQVVBgppNH8fLY/C5Yy2lki
         gT3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F6pPYc3Y/XzUcUEP4yGrUHAF9vZJnHqHCXZtWrXkC/0=;
        b=BRnt2ZqDf3+VqGB3irPzUQSafITh4/gScVkWrxMJnjfnZjYb1ZYwnJ/pKPEnkmSi6V
         5424lGNgh2xmICT7QodOIQ3NUKwTNdJweDv3fUDB1pr57pz3zbkVQggT7sCmLGf9ZL2e
         uC2BpZ2MT3/Zddb+h/IHXD3tnvRoIdcyDD+Bd/w+cHjnSMyhE3wZSFaorXmSHOe+9R7z
         ww7Z+RiqBtmXNcwIGBiMAwGK9vJGvkMVp8yZIHylQ0QW4aNGuJoF18lfpFLzWBkZ3R+z
         VG/TuJkOL06aXzAY2cabv7XkGrGLFGhkg4Qod5l2A19qUHih3MnerqmRwDpIMWRaFcr6
         vNRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F6pPYc3Y/XzUcUEP4yGrUHAF9vZJnHqHCXZtWrXkC/0=;
        b=DySrwNtMQ77k82IyQ8UOf0yRiU3oX8o2vGx24r4epFpXWcQiVQM99rCg2PfeJNzaVf
         nD9FYbdJd9X2p9WjwnV3GrhdIzXsVlM1Mub/FLg0JSLLI80xsw2g9v0gCZt10e2DUhd6
         Tww+dd5rA1hujIdy/WMqA1zvBsIghUUfb05vNyzrtJK/Ho8K7UY5O9McJC9clt0FvWL3
         EJWmkZpWB1iWlYGKmWMbHSDBqnzw0W2q1Y5jKBfiWJthIRdFsnWKFPV695Yktpe/7c6x
         t7P2wlqbTwahYTSruHs/GLB/g7LwRCTa7vIYgN8Zy14aUd8GcjqPgx01w8P6DBjamt1s
         BCCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcJ9eXGf8ZJUuKQaYK9svYIEaUSbZFWuoh+Hpwou2Jj9uoQeb5
	FGns8n9YyLsO4k5msU1XsNE=
X-Google-Smtp-Source: APXvYqy6rGI5C1/Ue7l4cyycB2eFqcF339+XqBlvbnuWl/MuavLcPJTw5cdLy/KFRQ9IyGCqgj4fzg==
X-Received: by 2002:a17:90a:d983:: with SMTP id d3mr10503558pjv.88.1565373126914;
        Fri, 09 Aug 2019 10:52:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:614e:: with SMTP id o14ls21517829pgv.7.gmail; Fri, 09
 Aug 2019 10:52:06 -0700 (PDT)
X-Received: by 2002:aa7:8108:: with SMTP id b8mr3047595pfi.197.1565373126601;
        Fri, 09 Aug 2019 10:52:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565373126; cv=none;
        d=google.com; s=arc-20160816;
        b=uht9RdqMcPknPi8bmBCuuD1+2eiuzN2Tocv2pan/pZPt/Pdyd7A6QvOxOBL9XHzIZq
         dbVmH/JAMtNfA5ecIp9he5VLZXsdiZS+a7ir2zmHKpDzQ/vM94avWgZg4b2ZitM6RS4h
         t4tcSjawGeRocWb8F7cbTq9DNmN92RWonI6bIZt1h/1+xirj5Yl+sSwrBVIHbOoI1A8R
         KGgGp5A49nG2K+7ubkmhIHXzh4D8uTzhhP+whkl6Aer5qgQ3d2BlF3RwhWP+wiR1bmAd
         SXBa8T8CSwuZfK/T0/lz/zjRept2lTuXv0i11LozH0F9WBCoJ3S6UwpXSEXe1NvAScog
         yXLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=i/bvtt6cBvkjJZEjibIV6Q8T5KFXM0R6jnGH+5PDgUM=;
        b=vbsUbFQOcdlcF+BB36aZh98g8RvJH0N+u+0O9joPZmZdAmgbdT3Uuhq+5jxjvMBxy3
         k11MJqQ/JTIQfKlk5WQrc3+ugnkD6aM1Py1Hn9bt3XJ1wCvVzGEXvGvjxJMDJ47N6Qeq
         wWnjSmG094tbQ3vs/DenMq1DCev4u1GLK8bccwS1xNeomK79vZycP9tqk2rJvQ90aSmt
         a+jkK9CmihGGUK9XXhzas6RabePWoBw4VeCi7QGDWB0LygHrToW0ynDb+ktip0lB2PQU
         lCJszJllkoXW1cwN9jAnsUmdK6gOP5Zb/LNv3bCdX78s3YfShXWlHSw2dGYCn8CbXNM4
         EM1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id u199si320922pgb.1.2019.08.09.10.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 10:52:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 652BC205E9
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 17:52:06 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 59E3F208C2; Fri,  9 Aug 2019 17:52:06 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 17:52:05 +0000
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
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-204479-199747-gbjJWAMe60@https.bugzilla.kernel.org/>
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

--- Comment #14 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284303
  --> https://bugzilla.kernel.org/attachment.cgi?id=284303&action=edit
dmesg (kernel 5.3-rc3 + patch + 2nd patch, without CONFIG_SMP, v2, PowerMac G4
DP)

However the radeon module und btrfs (if built as module) still freeze the
machine until the 2min reboot timer kicks in. Also some EHCI driver modules
oopses, but not always.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-gbjJWAMe60%40https.bugzilla.kernel.org/.
