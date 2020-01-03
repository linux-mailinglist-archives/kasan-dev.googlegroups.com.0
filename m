Return-Path: <kasan-dev+bncBDPNRNUM4INBBRWDX3YAKGQEXBP3KJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7021712FD88
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jan 2020 21:19:20 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id i196sf1373818pfe.6
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jan 2020 12:19:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578082758; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMOZU43QmEqd1h808ecghpXx5KcwQHeXuIBrLio09SduZyCsyKIvlfaw8sD2eDQ3RP
         Egqj0fU5htcGrnFxqzDoZmmfu8amlxv/a6BF1N+9ByLNhablOqPN5uN30uNVqOVry4nx
         cl/3vUYZcRaJ50vvdbeySFp6klb0xdhCNirKArSxD5nS3Uwc+osuveb+md20wFD3umpI
         cuBjer+A0Tg1fZ/IUXYfNFgZ91Z7dG/5hQTrUOnd3/RkMLjGgRcbuULL+7hOl1NyZoOb
         ZULV7wTd/BTEWv3ZRNGDUYAfsSX68cLoQoCgnRUFOIf9pQ6qmOSB8xu75KfkmPbsBljI
         AJww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Y6zv24Jlhu2obiREfjlFuK6BggJVruzdo77fX/hRPuo=;
        b=A7ui1ScPcpaWa+zGA6vX3punIyxbCeS5bBy/YYPq1+2m+KBjNklg0OMflNLtVamEhn
         x688xztUBWw8+QzaUm5m4+H9V3To1AKUhwVMAr6IL7k5xlj6mykczy9c+Ns98UE1XXws
         EEyF1Oz1Hn0GJcqmL1Zrx9VsugZYw21EMiqRvpBcc23tU9H+ZNOY+4AurvTdVW4AzBMr
         Vv8W462QztwxZrRePdNBgza3e61FnKzLWuT1vRSraJcAWVGC2ZhtEk819A6oxfHTyzjW
         B04wDckVZDE0IXA3ht9KuhErJk0oameqtLUSOpUdavvIj0R2a0tmCBpUz0HqcjKqu4sD
         zYFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=FtXJ+sdX;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y6zv24Jlhu2obiREfjlFuK6BggJVruzdo77fX/hRPuo=;
        b=euCSkz00uQFLMiQe1YJAUAZ2Wqh6eqgv8jnH6TXKQkheOYkjGkGS9o6kiipR0J/GaK
         oDEejlHRm54zhOSjbSwgY5QvSefjQCJhlaLP34Q9h/poIEpyWGd1wSbLfjBB7iCcPRiV
         up3TqRc1AQct2xj3YChhJl1TXnL/E5Lsd8pcaTPYfoC0jLnPSJV5suKes7vcRNv+B/nS
         nJoSDyaQ+SPSoWIqSIo8+zBNwwWuFgLHOOTOfDiMnPY9Dvr2HI58gTR3FQ3ZONwAPv3h
         a29ESsJDPCfBbpKR/p/T7zcRYPHMp7zfOuyFLRahsfT9hsp+7RHDwQuIiQHSobLotxQN
         VvWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y6zv24Jlhu2obiREfjlFuK6BggJVruzdo77fX/hRPuo=;
        b=GlT9haQsAqacPRZTg5Ik1xLlKN9Ekk+4ieKAxtMqy5IKKsM3p9iTJaTIXd9lajDlyg
         i7T7JIN4fmSLaFNII4mcGKhIrTz+WazUjNBKhkZk5Dx6QolR43WGtL0zBKK7Ikb+eoaE
         iGvdYouEeeDOzgd6t/Xb9wMwMz6F2CMBKDgvEcoU1i0XB06FPd5cHPNz5Ko3YFVD9xum
         qnqFgY4iHCYTr82rP1mphZ6OE15UAy/4BWitjEWaBotlp/sqHhR2yANeEsjnxwjap6sZ
         XjtnEZJXziwygzOHT5eKLDzkZiEhNn0YmQX5gS7YPqur6J7ZtCs7nzG86MvHUlPlwPc9
         roBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y6zv24Jlhu2obiREfjlFuK6BggJVruzdo77fX/hRPuo=;
        b=N+G8odh7kCiyV/LzGMCQHUvSyYaK5qZ1p3qjvtjPNSA48WJ6NlV0EE0+GU9XxwUDxs
         AhSRrVKThaH0jJd6K+nUmNLcakIqRtFCdOEFi0PkfhGd5dZF/UG6BT8xBKHAa2FkpK1E
         r4jkQzjQabgr23UUedEEfWU0NwKSD2+GqSTxhH9bH4om7k25//IpBzXGOvNd8257w5RS
         b/3H1nDeGhauhheCQ89ODRcKF8NBKAYeQW35GVB1Dv4qv4cIiQ2SNnP2Mf/R39+zSxG8
         T+VFNgDtvvv5pCJ+wLdmT2FbF3tvy9l0WdMQlD6PE3gjnAV55k9mfBd2OcGe82HoQeuk
         E+jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXxgYfrPYfmYmtsCJyldRd9fM4HKAlAg5B6RVsXpsJmbWVkP65L
	qlDtFpAKPTxlkIWKfW1QYKY=
X-Google-Smtp-Source: APXvYqzPXqTOwB9yKCXnIc9ySNvSg6YUsFT1bwOGek4OSQVBT5JY90xlE/mbPPSLhZSL8jTSh9D6mw==
X-Received: by 2002:a62:e40e:: with SMTP id r14mr95963556pfh.115.1578082758816;
        Fri, 03 Jan 2020 12:19:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7c94:: with SMTP id x142ls13623445pfc.3.gmail; Fri, 03
 Jan 2020 12:19:18 -0800 (PST)
X-Received: by 2002:aa7:8193:: with SMTP id g19mr97559108pfi.172.1578082758445;
        Fri, 03 Jan 2020 12:19:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578082758; cv=none;
        d=google.com; s=arc-20160816;
        b=RahadjyEsauqexYFgXMsHYpgjENz/tQDPDZQWDkVwQyZ8gSjdoxUqt8IRn8Iyb2mLu
         hF0eG8FoWFkmtqyKPWV/QbrBH9rqkSpQ+jBxQ6kgnha9OovMPYcZKBV05xo6QdiSe0gX
         EzQDb6K32svbHTr0qUK6+s7bkOe5Y8qbBsh/knZTOzmGqlFiycHD5hEiBg+rQZF7fxwi
         1hvJVQtNsLbgwomzM2cQaPnhD3DkI9waxaTSMkIaqQ+Y/M9fJzLLfHEGXShsGqLv1Mva
         GqNiLPB0H3PiUcix/kYxZeo8iG1nShCDwSCQ6hGmCO53UrafiuqNfATtH3c3pVQYgtDU
         gejw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=40ACnQIUnpge54Cj+EODMXbGQ2AM0yGbootCDBdgIh0=;
        b=Po3VcU3ZGhG7Gu7H9uaOOXXb3mLIBHWYiZls4/JLM6BveG7W5ReR68jGdVjZ3KWR3s
         iMjbSVFeOVpcLkR4IoXWf84jgaxtMWsQRvKyb4TW7lKmldmlx6iHKSRaisbvUKFZz7eJ
         BOfqks7m4al36LFJAozUraJh3bMdUjIqR6RHlUrS8OsGNAUTVU27MfwaW6oqeT0nidbR
         wuGn7R6VE4iWFHs2BNRS2Z8EjfoSic6hkYlvof7Rlb7/I6tc6elCdf8muM1kHvAtxgBe
         FRVbUR1XCmy7ZUWm+/HWR7R6RF9nknnnstC95cfdzJVHVozjAQkBPKYEMXdzE3CkvhKu
         OCqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=FtXJ+sdX;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id 65si2069127pfx.5.2020.01.03.12.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Jan 2020 12:19:18 -0800 (PST)
Received-SPF: pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id e5so37705221qtm.6
        for <kasan-dev@googlegroups.com>; Fri, 03 Jan 2020 12:19:18 -0800 (PST)
X-Received: by 2002:ac8:2ffa:: with SMTP id m55mr65791769qta.189.1578082757591;
 Fri, 03 Jan 2020 12:19:17 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:ac8:4410:0:0:0:0:0 with HTTP; Fri, 3 Jan 2020 12:19:17 -0800 (PST)
From: "Rev.Dr Emmanuel Okoye CEO Ecobank-benin" <westernunion.benin982@gmail.com>
Date: Fri, 3 Jan 2020 21:19:17 +0100
Message-ID: <CAP=nHBK6rc2CQAng9XKwH9+ruQTyJZxK3WdSB3LXNERjOM3xXQ@mail.gmail.com>
Subject: I promise you must be happy today, God has uplifted you and your
 family ok
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: westernunion.benin982@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=FtXJ+sdX;       spf=pass
 (google.com: domain of westernunion.benin982@gmail.com designates
 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
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

Dear Friend

i hope all is well with you,if so, glory be to God almighty. I'm very
happy to inform you, about my success in getting payment funds under
the cooperation of a new partner from United States of
America.Presently I am in uk for investment projects with my own share
of the total sum. I didn't forget your past efforts. IMF finally
approved your compensation payment funds this morning by prepaid (ATM)
Debit card of US$12,500.000.00Million Dollars, Since you not received
this payment yet, I was not certified
but it is not your fault and not my fault, I hold nothing against
you.than bank official whom has been detaining the transfer in the
bank, trying to claim your funds by themselves.

Therefore, in appreciation of your effort I have raised an
International prepaid (ATM) Debit card of US$12,500.000.00 in your
favor as compensation to you.

Now, i want you to contact my Diplomatic Agent, His name is Mike Benz
on His  e-mail Address (mikebenz550@aol.com

ask Him to send the Prepaid (ATM) Debit card to you. Bear in mind that
the money is in Prepaid (ATM) Debit card, not cash, so you need to
send to him,
your full name
address  where the prepaid (ATM) Debit card will be delivered to you,
including your cell phone number. Finally, I left explicit
instructions with him, on how to send the (ATM CARD) to you.

The Prepaid (ATM) Debit card, will be send to you through my
Diplomatic Agent Mr. Mike Benz immediately you contact him. So contact
my Diplomatic Agent Mr. Mike Benz immediately you receive this letter.
Below is his contact information:

NAME : MIKE BENZ
EMAIL ADDRESS: mikebenz550@aol.com
Text Him, (256) 284-4886

Request for Delivery of the Prepaid (ATM) Debit card  to you today.
Note, please I have paid for the whole service fees for you, so the
only money you will send to my Diplomatic Agent Mr. Mike Benz is
$50.00 for your prepaid (ATM) Debit card DELIVERY FEE to your address
ok.
Let me know once you receive this Card at your address.
Best regards,
Rev.Dr, George Adadar

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP%3DnHBK6rc2CQAng9XKwH9%2BruQTyJZxK3WdSB3LXNERjOM3xXQ%40mail.gmail.com.
