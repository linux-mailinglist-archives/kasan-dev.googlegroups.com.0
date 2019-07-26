Return-Path: <kasan-dev+bncBDPNRNUM4INBB6O35TUQKGQEX3GM63I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E9F4F76F3B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 18:44:42 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id h26sf29373968otr.21
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 09:44:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564159481; cv=pass;
        d=google.com; s=arc-20160816;
        b=j2FrYD63ZWxTRHNXdpIUxK2V1SINxMv+I6KlnRvEZUfQ16G64r60GhPXtI5LUnPzmx
         yN98saDjVfT+fRwt47Ijfl/TN0VEZN2JxQALLGMZQ3Hdxi+8wZmvj7rJgTt1gYXIgdiL
         cMKHGQSDGZZMteqs3vi6SYJ2fkXmhcJjg6WuTaQglw7CMPBmsOZSyDY5O4xbEYLnuXjo
         zFi87rjlvQ+Nzmb17D70fbrOhlmUJlgA8BCrvFb5usCDkGCIezVbKdWh2SH52CWiNnDx
         iZfrs+sSHLhVlc65jtS1Xr1A5aBex7nLHJH9ECErNH7QXF9kH5jtEzxLZUVe1z6Lx9nv
         MpZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=DY8vexXk88oP4Q9kOa+0CsxqaeTm8e4YaeR0D7LmYE4=;
        b=PUvkWTzm0Kaxbmn1i7VfyxbCvwzGXbVyqJYUCmy3Y/Asj1kqUBpapMzsR6m9PniEJ/
         GOKgoIl9yrvnQ49FW88ujvpOl4gDWbOsghDO1ggRP5iMA+0wqM1F7wg+ftq0fB89oXoF
         6BmiSc0x2ujDk3LzRRstsIxMv3v3olz+uRxZhtjsrcbMQOBwAVlhRzy77ayIM570Z7Ll
         nk/qkXNpAQW66tVTp7JZTQQc6hrhp9QZLnV/xjCjQ0mnaMmE6OOZ9AfaFct8qqyU0itP
         BpRtMHZawxlTcgyeKWXsBOikzJdkdIrwwHVTQaNAcOh2e5IbK3wk6y9VVXl03/Kq7JRn
         6HLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Em+hYHBl;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DY8vexXk88oP4Q9kOa+0CsxqaeTm8e4YaeR0D7LmYE4=;
        b=Q52upsUhZLdENmwsFhxEXWc3LVyBds7Y1kZz48joVDE6wZSRdoponMLUo09Q4yGMaY
         Oh6dfRb5T2rwIZN7ycGaC0MTBRaGr0mQiFG8rxs+DDR2EkMdRpuS27QtNLSPD4t4YbQ0
         BPAxChCDwxKu4Sin40woaC/qA1gBqTD9Wk2FkilbK2+jgfoyB4iTwZ9sqD3XpmTnbJuP
         ME33/EaK850UHOVO3ImZr7ftXb9SCG7V0sdEtDPyXd5HiL6qNWf10nPfxWhNUnU+/eSj
         DNk7TJABSA9iJapdXrxyKAW7ZIfePCtgcGmmjjwIBE/dq0LnbLpI8bc6s4OZJzGlwZwF
         jEVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DY8vexXk88oP4Q9kOa+0CsxqaeTm8e4YaeR0D7LmYE4=;
        b=Prtx3OjmU/tRw1Bi+dtdPv7/iV7GcuQOEE0XdjyFMnejd67Cwd5u2xhVrLL8LxftcL
         9XOZrk+GboqqW0eWIyS1Z1CYUnEmsOkHWff6gYddyI3xPh8N/lqWgSqB5jj3rZzppdbd
         8w4CuchzLISyKjzfdY/eFgPRHtV9ijXOop0fSfbJyA06qpGeV7zXq6AJPdlXojYAYDo7
         M5KIWEsbWK1pE9VBuD0OjlOAkjYdtAFtaUhgkUzMBQR74ujFf8exfV+yU5QAyWpANHAz
         M9/UzxQL5nHtkZFW7pKimd0VverYsthOy40EhsT/T3DWfBvxDGFaAnK4F3FPXSUofYRw
         lvWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DY8vexXk88oP4Q9kOa+0CsxqaeTm8e4YaeR0D7LmYE4=;
        b=DhG4DemGuqNugQeceUxph8qvMIrYHnVCO1QdCp8Y/0cEDKyHgaTcyCxTi7rfAyfeqi
         Lu92IERaE9TaKfS6vrrbGWROFSuGJG9PKZwXPqgkrSQm8b6sQr9EexsRkpexzlSfuPMk
         sQINni5jve5ArtnDB5rbWgpI0aLejpwiPv7eLJ1mamycFOa9PzOjB8KjH+w96a1k8nOE
         s5J5XxOU9TvWV+momxcd5Ule1OowurLFDQOvdq1z4BbMEll3NTwJbhIRB7rM5EnJTUU/
         /leOjao5yg1DnkaOTe21hKJHNjCHm0zoT2bMg1BMHHoy9LyYg/eAJVe8bV1do13uFz7Q
         58Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU+7CqnUV71lkdV7CQ5jiwDGLNMVpMk/5NAunjMYjW5Gd+lA9pf
	fWkNuIJF7L/MhknWieNEp+k=
X-Google-Smtp-Source: APXvYqwhv7jwduvbUZaKKwGv+oNTYm/P885RqRv2O/FRmjWVK8Fg8SMQ3tKHIg7tUUvvMKjKHBAJfQ==
X-Received: by 2002:aca:ea0b:: with SMTP id i11mr11210972oih.102.1564159481618;
        Fri, 26 Jul 2019 09:44:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b642:: with SMTP id g63ls7478234oif.8.gmail; Fri, 26 Jul
 2019 09:44:41 -0700 (PDT)
X-Received: by 2002:aca:3787:: with SMTP id e129mr48925087oia.145.1564159481235;
        Fri, 26 Jul 2019 09:44:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564159481; cv=none;
        d=google.com; s=arc-20160816;
        b=cqqjhTFhaazV+jZMvwn/VoiI9hinGpCPE0R0xaO9zWHIalinTnJqTn8yzS4octnAmS
         DYazE4uwt0CDYLxKsU7iAB+WN1zT3nvv7S+YwGOXK20tn/4U8oJ7NOCUjxLzDt2EbmHt
         7SwAT/AETyluk1s+hnIiyZwFYFQQii6z7RMmGJIkKZMTjmFfyVlrxC1EUwC9sMwZV4E6
         MyjJsV1sF1sLqWmBFmUhMtSvg4/ql0C/oIiEK7y/wdvvfyMmn5uJo6PBZ0TKxxvbmudA
         KMOpc9z8VsZ1HOOj8uH1WxxJUBqm3MPRe8+J/Lh3W5/7CTyo7i5pSuUeIjJZIcYq/2mg
         IGHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=qaOWGs23G49TWwws7WjjdoCv06+sXW9upizbWmsREGM=;
        b=hEvLLXMBNd44S3kLTBbGYs4zvjO4PILv3RE5g4vijCE7Or5oTpLFZ8WJepj4gQHozP
         QqKXBSJt8w39mzwtS2IknxPyECtILNALSaHEfqDzM5U6U1W8KpSW12TunYyl00HlLDwz
         /8bm8mjwaGAp6DQCC4+bzimSs9ea2F86sW4p8J8oUJv8B0BTFAqz8RpXp9X0P0q4ySkQ
         U/KmKhbAnV8Jjwc7fDN8/uTBV1NNYFK2YynsOiAKZ31TwUBZc+DKCpFBX1Qvb+MV2UYL
         ngauDa+Z/hbt0OGvGtrCFnM/YdMV10J2f5o5HHLmJ6s4uEmilVDAo1+j6a2YtyZbZHr2
         RREA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Em+hYHBl;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id d123si2065528oig.5.2019.07.26.09.44.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Jul 2019 09:44:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id n11so53196787qtl.5
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2019 09:44:41 -0700 (PDT)
X-Received: by 2002:aed:3667:: with SMTP id e94mr62010491qtb.382.1564159480752;
 Fri, 26 Jul 2019 09:44:40 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:aed:3544:0:0:0:0:0 with HTTP; Fri, 26 Jul 2019 09:44:40
 -0700 (PDT)
Reply-To: dhl.benin2019@outlook.com
From: "DR, MOHAMMED BUHARI, PRESIDENT OF NIGERIA" <westernunion.benin982@gmail.com>
Date: Fri, 26 Jul 2019 17:44:40 +0100
Message-ID: <CAP=nHB+gnib-BS+VYtThgXT-KDL4gopLEZ5qpiCtSXaa_3LFQQ@mail.gmail.com>
Subject: Attn Dear Atm Card beneficiary. GOOD NEWS,Shipment number:
 4Z69536197319960 Content Packages: ATM Visa Card, amount of $18.5Million
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: westernunion.benin982@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Em+hYHBl;       spf=pass
 (google.com: domain of westernunion.benin982@gmail.com designates
 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Attn Dear Atm Card beneficiary.

GOOD NEWS,
This is to inform you that i have paid the delivery fees for your ATM
Master Card
I paid it because our bank director stated that before, they
So contact Dr. William Roberts, Director DHL Courier
Company Benin to receive your delivery ATM Visa Card amount of $18.5m US Dollars
It is shipment was registered to your addres.
Contact the office now to know when they will delivery arrive to your country

Email id: dhl.benin2019@outlook.com
Tel/mobile, +229 99652699
Contact the office now to know when they will delivery arrive to your
country today
Shipment Details
-----------------------------------------------------
Shipment number: 4Z69536197319960
Content Packages: ATM Visa Card amount of $18.5Million
Scheduled Delivery
Remember I have paid the insurance and Security Keeping fees for you
But the only money you are required to send to this company is $125.00
been your accurate ATM Visa Card clearance Fee before they will effect
the delivery to you.
Send the required delivery fee $125.00 only to the DHL Office on this
information
Payment is to be made via Western Union or Money Gram transfer for
security purposes.

Receive's Name---------------------Alan Ude
Country-------------------------------------Benin
City-----------------------------------Cotonou
Quest-------------------------------Honest
Answer----------------------------------Trust
Amount---------------------------$125.00 only
Let me know once you send the fee today okay.

Blessing upon, blessing upon, blessing upon blessing upon,God has
chosen you for testimony time,
I wait for your urgent reply

Sincerely
DR, MOHAMMED BUHARI, PRESIDENT OF NIGERIA

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP%3DnHB%2Bgnib-BS%2BVYtThgXT-KDL4gopLEZ5qpiCtSXaa_3LFQQ%40mail.gmail.com.
