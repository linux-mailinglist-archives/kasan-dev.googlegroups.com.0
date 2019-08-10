Return-Path: <kasan-dev+bncBC24VNFHTMIBBSVPXPVAKGQEJLHY62Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 73AD788BC6
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2019 16:42:20 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id c9sf5169309pgm.18
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2019 07:42:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565448139; cv=pass;
        d=google.com; s=arc-20160816;
        b=iieJapZwpbuwJM+BQb3CMW5cVYFGOBNFHZj4bn01FZcp0PH2J0yUc8jTojz8I6gsWC
         5Kl5qCnTK9QSXFPW63phVhRJR9PGMialwnSEHHkTPs47NbH9FiitENsX7m2L/OfR/SVM
         G99a5vaOeaWWM93fxMOLnYgVmQFMhzM+T5QZqcJdSA79AKHSCqOouBVtJbc/2pGT3z7T
         olkiJ3WUkoKnCFPHeJ9xBoOG6tl2a9kaNUxg6xopLeus6EMF4BriLEP+AmjoweApbLRy
         qyom0TcMyieZHl8hcS+ho0mCoTEtQ6Wg6cRzbsrEcficWRoIbzA0H2zXcSgb/Ykh2rB9
         Kb4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=CK4IwGboe3AXZCCf6QKRjNg+b9bI2dp6JnC0IWvcCFw=;
        b=g8OngXqtJHO50dG+fgg8zVhkYK3UlpEW29w+8l3uQnuV0GI0X0NdXF146jPsz85T47
         qCDJewUqEbaYSmUQxu4bTt/pamgsuaQTppZCwFJZScsHLrDBEnSTDa7zNQEL3o26CEve
         KtZ7gKvO7HfhuYrT1ppmu4WatkRwApRxrOJ/vQlJ5JErpPdTpSzXECLoD0XJ3p/qJ8hE
         gaI6d/hhV5p/lnpD0JCEYeaeMWROMHFwTLr2N2SYRLEb1HP7Ai0+KoBBiDBkJSTeipfT
         x24HT9YHVhmFHZKRF7C8Z4XmTwoDu9SgkF1JwQ3zR5aebwEbsgqD1hiKRQlOeOENTPO1
         iBug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CK4IwGboe3AXZCCf6QKRjNg+b9bI2dp6JnC0IWvcCFw=;
        b=B5I+fMBxQCv4VgZ6SrnbCA/K/11++rnoNs3tWt7Wb581ABGON28uTh8jNsizw7kqic
         I4fWwAeSct0dt6sFlI8iTNmnTl6xWXBTj45XEI/FxuBZ19BHwBoK9qP2IQo16dg/iqem
         mIvKDfTdw2XeLAc5a/JfqwgXAj9leShWOx6otP+CwS2IwfSAt3YFiXzXUn9V3IFm8r39
         8+oeSQSZFIW6GkbRhNHlhCB1Z8zTrcVEccka4RYXwVWgQEpo7pI9Bky8lnkyWRUbkHnv
         Xs26dBfhMysQ4CbJoJqE9tu3nZ+KtJvfcYrhxRQojO0zOXJ5BWmq0fRee9G0SO8385+w
         HvRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CK4IwGboe3AXZCCf6QKRjNg+b9bI2dp6JnC0IWvcCFw=;
        b=hqNUuvm6Q4cYwtHdXUBNUUH9R72+ksv1DZOHgEQYwSSclmZPsPWC1uJPNQEBZA8ASw
         WbXn4jastmILT4XrnRZ1sdJI5FQwuchWwsOutPVSmFcLf4DDoIwZMlLIey96fI6NpuV+
         vUzftohEPyhBpA97pf5WHHYK0TThnvTsJgnQlggoTVImqRk6qrHnUibPNEQJN7lTwBsf
         tO07z0rrJE7IR26BO6Xy2/CKfGgOfEvZkufjUajDh6MKeyLErJ7IqJ+cSEA2NpxBV65t
         Z6cCy5CdRI2EcUQZeua+wE8FodX24pF4pgzBHX8HLhALWQfryEvXaAcRs69xJP/TVX0K
         O/Hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXLGTHR+fK4ZGb6GktSk764JLKo1pZZ3kLM8YTrQHosSwUVfAt3
	7ZiXQhQ9IUH4mTqxsPve5p8=
X-Google-Smtp-Source: APXvYqwksUiRgUqCCcd9nBqDCmkrvaKCw0kH+3SOOgLWMtkOh1h7VoVkOP/G5Ype4siwBQ1geteOtQ==
X-Received: by 2002:a17:902:bf07:: with SMTP id bi7mr24938896plb.167.1565448138902;
        Sat, 10 Aug 2019 07:42:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:800d:: with SMTP id j13ls23392860pfi.12.gmail; Sat, 10
 Aug 2019 07:42:18 -0700 (PDT)
X-Received: by 2002:aa7:8b51:: with SMTP id i17mr27628995pfd.33.1565448138446;
        Sat, 10 Aug 2019 07:42:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565448138; cv=none;
        d=google.com; s=arc-20160816;
        b=Ycsq4vnxlpFwn9Q2x0ZJwuRzqDfBCp4kja6vtc7JadLOL6bu9JSEcWKCvym2HnWHLE
         mrBhIzZpEbTl5w7qBX0CilbyTadvETTy0mOY9SLm786VpfKqDinEFu2c9VuTAOE9JOd8
         ywl94uzm/mqWwzG9pNLxoBaC7c5Lz4Hni9tI0zkyYnu24iyR2iUza2JD5kzg16tnD2CX
         st5DvF1BA5HxRTjklriJy1DUPth18/OuyX8KS4AyxyPo57bPGoI/orjPbtx6QVJz4BCr
         gYvd0X03rkmBtPrEQ0qDXmlGZgMbqmTOaqF5973qI/tm0C8IikKss/Ffwb+hHkRQNxed
         7EAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=9lje9R4j6p3oA9v+ZT7mKkumlJ7X3R9v4WqHsms4uoo=;
        b=sCOhaRDTGttCuKg0ytoYf5oTQvdwcAQ2nTH3eBwKKWhBgHW+kQYemhRs9yuC3SP8GU
         LehquCYRqJRuBgLOE4xqHzYNf4fxxgPpZAEjXlJC2sZlADbM9qMvb0DkQK7rlSvkMbaO
         ls7pZOpAyqIjyUYl2sUaeodM2XUZKJOv8Q9tS2ejQiLR9SbjuaLwmqXz63zDcaOWe3io
         O2d5Mjx7fL4Z+XTZtqP/MJ51MXyK55qAVmjre1UofPoxbkik/jwe+LPh3bVRzpnd3PFC
         JiuNd2EReaqsTx81cpOGg+9toGQ6D7txUVrrfB4lnu2jfzSvbwzPjNDGKP9nIvEsxJ8j
         mG7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id cm10si4385212plb.0.2019.08.10.07.42.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 10 Aug 2019 07:42:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 297FB26E47
	for <kasan-dev@googlegroups.com>; Sat, 10 Aug 2019 14:42:18 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 06FC326E54; Sat, 10 Aug 2019 14:42:18 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Sat, 10 Aug 2019 14:42:17 +0000
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
Message-ID: <bug-204479-199747-6sProvYS72@https.bugzilla.kernel.org/>
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

--- Comment #16 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284309
  --> https://bugzilla.kernel.org/attachment.cgi?id=284309&action=edit
dmesg (kernel 5.3-rc3 + debug patch + shadow patch + parallel patch, PowerMac
G4 DP)

Also tested your powerpc-kasan-fix-parallele-loading-of-modules.diff now which
seems to work fine! dmesg from the G4 DP with CONFIG_SMP back on is almost
identical to non-smp kernel dmesg.

raid6 pq reliably oopses. Probably the 1st issue revealed by ppc32 KASAN. ;)

Loading the radeon module at boot still freezes the G4. modprobing it later on
works, without any special dmesg output, switching display over from Offb to
radeonfb.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-6sProvYS72%40https.bugzilla.kernel.org/.
