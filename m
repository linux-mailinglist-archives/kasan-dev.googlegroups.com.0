Return-Path: <kasan-dev+bncBC24VNFHTMIBBU7EW3VAKGQENC3RB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E1AF88195
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 19:50:12 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id o123sf1869281ybo.7
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 10:50:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565373011; cv=pass;
        d=google.com; s=arc-20160816;
        b=lSbFCNesrDYhfvSbNvPyZRGk2g+bKc9BU/cONTRpOGC907ftoxJot5GrBumr/voh8u
         NshjtgeYIEnaH/G6qglQAKIssZ4jqHBJ3CHB2EiipONuxzYizsRAmOqipAaU1wHZiaha
         AfqhEIe07PLxVaVSqSvGG7AnuELQQLJq1GQXzmd3/nwVSOv/1mU1fTRN81l5voxk0VZ7
         ep1aF7FP/jCvwYsLDbRDxtvr7F66iWwUZsSdLqpvXY4Zq0CMphrnnoIwvSuGYium+A5i
         vC/tCjQKHpphhp9IoSjCC3sJfjyWlwZ0leCROTmhDfpvRqP9UMwVaL5TNN2E9JwD9BlT
         M3Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=enz0JXcc/b1wN1g4m+Tm0gaslIpa6IEpFKNK6aU5BUI=;
        b=hH66oqYK+rhS2cMjN6jlBH2a143wCO54Te1OoHfZ8IF/5uKsGWol+Kkz3qgpjQ58S5
         r4BjBk662glXvoy27YkEA+Zp1QzLpCs7XgeUbKJh17negDQ0sRVkder+VrBLwyUPVc4X
         Mz0xl437ljHFzcxDVFcWEkCygyZZi3g5jNY1aOi8N8C37XexkRlmsnT1tAxErPC7CKLE
         tRQXA0j3b55O67sIAF5UqGdoSiPzli+uIPfEfsCKgc7RNB04Ydi/sI3spO1mIyb+f2PB
         HaHwNppsTK8CqT3/CTKk6S8zzueq3oXL1uvCGKvn+NcLgmZqRjDoGQAt3JSK9mdqFkwD
         pU+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=enz0JXcc/b1wN1g4m+Tm0gaslIpa6IEpFKNK6aU5BUI=;
        b=k1Kim9cVn5bN34c5eLFepacLTUNWzxmBnIbOPteocQl6A2d6lC6ROfcWIly6Tj0+Zt
         7X/J+h7R+9VvCKYaI8Mqg/QPvxvz9n7u08XIYWfdhMWIl9QCjPjCWe7LByoNLHoNKWg+
         c+YZrt4uWIXCBkdq0hNgbtReRSFKm0ur3gcVnih40v9i9CzGMBpSy+lXZ3Tk9lLZjC3E
         aZy9D44M79FpOjMdHJNFHMndU9EFj1KIdDlBKAcBxpcJnrXtZFzYi57AREdAOVDA5BMH
         tomCvksKyJ1+81lNZV/J2k2YUz06pEqJaF3JiIiDnPSLUHlRM7HTP3do5X4uyh35SopD
         6a1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=enz0JXcc/b1wN1g4m+Tm0gaslIpa6IEpFKNK6aU5BUI=;
        b=pWmzoZFmfpI78wjNZl1c/dYe+3VRzGKIFXPlRkADOPQxHt/oWcc1SVmWJZ44/TOp9m
         +qw8cZndZgUJZOFM4I/DAgI/1FKIBT3TfpJtV799b9sSqH7rugldPJ1iDfiRldkNc7cv
         2Oh3zt+f4nlNA/Q3FmIGZraLAC0TLTEWRfAwwQSbajlv9xWucVyEhDOAQgC2u0AI9n5u
         OXZD9tWoPXbN655DqAhMTc0ybE+T7i1s3t0PVrJqq8J3NEtSJ0TNMduJRCuuqblVvbgo
         vwGwmj7FfIaRx78ZlMa/RMcK4QxnP/sPvYcx0CKntAshQ85wyIG6knpcXaTGi/7Ww8he
         wf4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXdW1m82TZ+YQ5EPOV6bo45jcnpdBWSLXfaGotjtmkHpJNJHsPY
	24KY4vLmbaIsfgQax7l/IEk=
X-Google-Smtp-Source: APXvYqzmranbFUhJMYT+aTkeH+TLCQIUbTaVKHX4LFMOAPUYKvmYKvlEraCw/WldhPLk/Xv4ueu4/g==
X-Received: by 2002:a25:504c:: with SMTP id e73mr14037580ybb.357.1565373011272;
        Fri, 09 Aug 2019 10:50:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:40a:: with SMTP id 10ls7337833ybe.15.gmail; Fri, 09 Aug
 2019 10:50:10 -0700 (PDT)
X-Received: by 2002:a25:86cf:: with SMTP id y15mr15712828ybm.15.1565373010980;
        Fri, 09 Aug 2019 10:50:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565373010; cv=none;
        d=google.com; s=arc-20160816;
        b=cWtrTjoFd3BcRGBQrVO5QY92VSAVVuTi08r2hpkbAjit4LneaWB8g5cmUTOu4ilLz2
         ikNEHwHjkl33chr1qq4hgSZ+GP6RJ8x0Ux2L6IWPjMsqazBlFHTPkkTuc7B5uMM2uqOa
         O7x5/8L25Kpkg+VtZwx532GZ+JX+ec4sexpDxRjFKFE9E2pBGinQmhzr8Uz9IH6Uy30c
         sEGl7EHsF0GjSBAESMfCAOejsE6lITWVnMi5BSS2EVMFklbRi/lLQuETQsBx/09P36iB
         hda8kGgJO0Z3+d2MwlH3VZ5Iy92M2nToo3aaDyTIaW3ObN3w7F0+AryO3OvfsXcoeooQ
         RfoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=GP+kIU3FTQslYlU3szDHHbDWgmIOGUTEUecj37Wn5DE=;
        b=Ftzr96obOVSFE/4A43NXEobJnXJ65Tgru0f+lzEFBaPK3lAuYBBpoeCE1VHGaSFNWa
         xp6edr3URv/wX5L23qam2U1J4Gnl6XV+BEI/ZHpy5TUEN+hOVG9lo3FdsGVbOMxTuS5U
         E6j8fob+fiwG/ge/g7AqYdY05WLhBXjbL4evas4TbZYw3XxQlu9j1GI/QRDZLYWZIBjC
         Lz1Wh+QEzxcWySRbALDTLZJnAzafhEHZyDNCv2aHG64aSZEqDRTZFGM9dLYsWituCbp0
         4Q+93syRzoZgwQiSzFUtoY9jLQegz2NcnYDI6Zh09zy/RvuXdcoUX7v32lGxjDBELZj1
         mJbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id r1si5562285ywg.4.2019.08.09.10.50.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 10:50:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id E26CB205A8
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 17:50:09 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id D4AE4208C2; Fri,  9 Aug 2019 17:50:09 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 17:50:08 +0000
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
Message-ID: <bug-204479-199747-BcG8tlNP79@https.bugzilla.kernel.org/>
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

--- Comment #13 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284301
  --> https://bugzilla.kernel.org/attachment.cgi?id=284301&action=edit
dmesg (kernel 5.3-rc3 + patch + 2nd patch, without CONFIG_SMP, PowerMac G4 DP)

Definitely an improvement with the latest patch. b43legacy and nfs load now
reliably without Oops.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-BcG8tlNP79%40https.bugzilla.kernel.org/.
