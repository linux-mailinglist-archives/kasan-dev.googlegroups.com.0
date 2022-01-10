Return-Path: <kasan-dev+bncBDPNRNUM4INBBW7A6CHAMGQE3DZZHCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FD1B48994F
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jan 2022 14:10:52 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id v12-20020ac2558c000000b0042c81cc06afsf2045009lfg.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jan 2022 05:10:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641820251; cv=pass;
        d=google.com; s=arc-20160816;
        b=T8osAx4334YJHDiMgu8QT01IxzSmEa1ed/0RtTo3z52id8QV/bECEELHW3E7qxTOVI
         W+94gCTpbQhpB4O3BG8Je0T1gjFgDILDmDhHs0AYZyfrCAp+t+j+TYOOkjZVtHOUrhYF
         YnKYsald2XwDpNweWSPDsLh6vi5W/xWFThD+FPZSbJhHZMjezXrStUxW4dOzzv4hDgVl
         f+cP7lNzW8vytZaUNb2LqR4ABi8gPS3XY4199MgEhOo8/wDde5ZNrX1f5sZIeSO+LFI2
         EDno68h9SfnwHCBVF5ifQ3CfbyBAtfj95JcKESrlpGFSWCkRHD8NSOB2nQ54ZhTemF4S
         EkrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=awu8TI2/lcILXcNyUiKIHF8VKTmDh8ZVM1aAYUihF3g=;
        b=s4EZmTrjq7yz8r/96E/C+50QppngCMWzAURm10VHWNjoh8MKr2sjpPc9pggbVk9yaH
         huOc8hO7oQ6PvFFMdFI95PujGHSOXtXVq6qXYyCy2Q8FnPQgoHplF4G8pNd6fFw0AyNb
         jsM7LSiGTzWwRmjuM7bS/aNEDcZTaxVoD6y/fF+35I+QVqe/CyPAfim28LgLOOuju+8g
         ffGKYabn7vgCSZbjHzj6R0HlrKvwVGu17oA/y+f/6IivHFukC4vBNYbieW5yPhyFo5XS
         F+TsljyZUA5ky3N68EobxQ1HHjn11Bla4r0mC9vkaAfV5k9FqaEKiIooCC2GzcT42SaY
         Mi1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=MxUO5WRT;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=awu8TI2/lcILXcNyUiKIHF8VKTmDh8ZVM1aAYUihF3g=;
        b=cWSL4qTAKQDz5+G08z+8G0clEH/76O4kqNMZj3d5Nl84QyaPopAcbBi0OSmk8QYcn5
         6NhMhHUzRCTEzQVdj9ULKbb0ndAPciTtwZh8hIKQy9B7dk2Wgcr5XW+ngrz4cRO9SybW
         nn7rNVW3IV68h8+MkJpS00h0wGv39+gMdbXWxJRBoPDSDkyT/evAqpHVrNobsFJ5MFqt
         EP3doCCTnS+uG6za0jCem7LA09JXmqeTxlrYYxyl3K7I59gq2FUrTG5XYKNvOGWm8imw
         rpJldWd8wAsjc1eMCbBXi8oOxPELdcOuCjtTrsAsbecUzjhrgSxslLSyvA1/eegXYv0x
         NvZw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=awu8TI2/lcILXcNyUiKIHF8VKTmDh8ZVM1aAYUihF3g=;
        b=khjPaKUcyH2Lyhjh5UuPGSknITY6+xY71gvb9cYEBPWWT3yuDp9I2VYPSkLLCieU1P
         eeqHIkVQqjAux2KyfSwfRalPK6+XwCkwy+YU6cL9VkwudM7Aq5UT0O4pAPJZ6QnQ5lLp
         H+e5vXIuvrkqPo+wGiaxCloMKXuCMIQSaYWhIw2P+d4qr+ci5TNw5crs+wVSrtPLdykr
         K88fNz+cEirNNHzpbIQvqG7nTN3rDND3+lpdDvqJv6Ylioyr08KhYvolm2qjKrHyl1Pk
         2tb+ZomMEsGTN7aq2cUPvetqKWimP2m+/GzROJRqsV2rKX+kibFN1iCr/b26BKVe1BCl
         wgFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=awu8TI2/lcILXcNyUiKIHF8VKTmDh8ZVM1aAYUihF3g=;
        b=WDMkq+tGegyaw7+nqmeVG13waPxEYRcfIng6KJ5tm8MqXSgzyumfx/mxgEFNYPdpYH
         lPmEZXtXUVd64lJS4inbzu5f7a5RO+Wiy8yJSI0JEfzF6HyvseuVMFbpEDVG11B+0bxu
         vS5XCy9y583+PM3iI9EgwUR/3QlwWsezFRH0jnhNGoOJxuyWqq1uFeVv4JqzKzG8vtTv
         J5v7ZQwNh6ytAQ//0vi/PxSYigCJQxSI6W9X3LEKX4P6rN3p25aAVp2O7nsXNDWEmekL
         6Vdv9GoEhbiB7+PheU9KnEWz8ZLfWvQMbmbMANSfEjseK7xm2qj4q5r9ixUYwzL9tYv+
         f1aA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533B951vodO+DAS+uDZudg0FxfUqFrH+JfQOdOeVjtJKlVG6+4lY
	3aAEOMu4LeHNYrP0GZDI4Lc=
X-Google-Smtp-Source: ABdhPJyW00CAr78tEND4hzs1c55BnRNKrdRGQjGtjAJwxZLb1Oc/QYFoNKKtuBhMLSkn6kkKwei4GA==
X-Received: by 2002:a05:6512:10d2:: with SMTP id k18mr872670lfg.167.1641820251556;
        Mon, 10 Jan 2022 05:10:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158e:: with SMTP id bp14ls52624lfb.2.gmail; Mon, 10
 Jan 2022 05:10:50 -0800 (PST)
X-Received: by 2002:ac2:4651:: with SMTP id s17mr2068957lfo.347.1641820250475;
        Mon, 10 Jan 2022 05:10:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641820250; cv=none;
        d=google.com; s=arc-20160816;
        b=sMs8caqY9+nqhdGkpQFP5dJhXPi0YJV19ZMV65s6FfTrwfteXqeTJqlHTZwOtNilBS
         R4v/l4B6r0+AwPffaNk+wVZAwoWjLJvtzch0Jazv9R0ooh/4wZZcbp7WBe6dyuksQXsH
         /P0SbQgH6lwDDJYzAqZ3Ma8oRs0Sa70XYsaLd1xTiuQ+/xbF3F6r8FCbNdbzRc6EqEyC
         Qr9qU71V6cMu0xpNlPQYlgTChcQZYZU3PHafm+t0ccRjGAcx4Ms7V35p1GGtMZzexedp
         N3LoYittQUIV3vee6/QolcE3UHQ4U5rDGudpFYqghjuW06RB7oqFNvhJJVnigpswdmfl
         4SIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=STst/NZz7XpLuhkw/fjT1YooCLQUEgoChj9j28RAYfs=;
        b=kXNwyZVxU/iugnp+6axboFGxrbUVordg1edX1AtBUPcmCmy5zkBo031JBDmm1n91G4
         T9auTy1Ju5XXimZ4GCnkQBqbQAHVz224jv2W2i5O6fMOorHB833UizfIOFGXKJujgmSk
         3pa4zXSH45J1YMT5Z1habOCSw7iXEYwX4fm2ZF87Vy8/cLAuXuG+LHa3vm5OAv5G9DkB
         dgsqQukXe67FKAPNSmzplmaplSX0+aGyVtd1G17nyPWZ02gpgfBcHP38RMhAu6psBk9c
         wtxYFFPLgsDv4dlwNHYs2nNkuPrmwZubgKlJrN79FXP4Y4knpBfa3XtlImUIjg2uGOoh
         RNUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=MxUO5WRT;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id j15si252709lfg.9.2022.01.10.05.10.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jan 2022 05:10:50 -0800 (PST)
Received-SPF: pass (google.com: domain of westernunion.benin982@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id l25so15811911wrb.13
        for <kasan-dev@googlegroups.com>; Mon, 10 Jan 2022 05:10:50 -0800 (PST)
X-Received: by 2002:a05:6512:b1d:: with SMTP id w29mr63965537lfu.219.1641820239421;
 Mon, 10 Jan 2022 05:10:39 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a05:6504:15d1:0:0:0:0 with HTTP; Mon, 10 Jan 2022 05:10:38
 -0800 (PST)
Reply-To: gtbank107@yahoo.com
From: Barr Robert Richter <westernunion.benin982@gmail.com>
Date: Mon, 10 Jan 2022 14:10:38 +0100
Message-ID: <CAP=nHBLx9+oZZEXh4NOqjqVYOsF7h6SEbjGzy47zap3iwt--uQ@mail.gmail.com>
Subject: Contact GT Bank-Benin to receive your transfer amount of $18.5m US Dollars.
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: westernunion.benin982@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=MxUO5WRT;       spf=pass
 (google.com: domain of westernunion.benin982@gmail.com designates
 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
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

Attn,Dear
I need you to know that the fear of the LORD is
the beginning of wisdom, and knowledge of the Holy One is
understanding. As power of God Most High. And This is the confidence
we have in approaching God, that if we ask anything according to his
will, he hears us. I will make you know that Slow and steady wins the race.
It is your turn to receive your overdue compensation funds total
amount $18.5Milion  USD.
I actualized that you will receive your transfer today without any more delay
No More fee OK, Believe me , I am your Attorney standing here on your favor.
I just concluded conversation with the Gt Bank Director, Mrs Mary Gate
And She told me that your transfer is ready today

So the Bank Asked you to contact them immediately by re-confirming
your Bank details asap.
Because this is the Only thing holding this transfer
If you did not trust me and Mrs Mary Gate,Who Else will you Trust?
For we are the ones trying to protect your funds here
and make sure that your funds is secure.
So Promisingly, I am here to assure you, that Grate Miracle is coming on
your way, and this funds total amount of $18.500,000 is your
compensation, entitlement inheritance overdue funds on your name.
Which you cannot let anything delay you from receiving your funds now,

Finally i advised you to try your possible best and contact Gt Bank Benin
once you get this message to receive your transfer $18.5 USD today.
I know that a journey of thousand miles begins with a single step.
Always put your best foot forward
Try as hard as you can, God give you best.
take my advice and follow the due process of your payment, the
transfer will be released to
you smoothly without any hitches or hindrance.

Contact DR.MRS MARY GATE, Director Gt bank-Benin to receive your
transfer amount of $18.5m US Dollars
It was deposited and registered to your name this morning.
Contact the Bank now to know when they will transfer to your
country today

Email id: gtbank107@yahoo.com
Tel/mobile, +229 99069872
Contact person, Mrs Mary Gate,Director Gt bank-Benin.
Among the blind the one-eyed man is king

As you sow, so you shall reap, i want you to receive your funds
Best things in life are free
Send to her your Bank Details as i listed here.

Your account name-------------
Your Bank Name----------------
Account Number----------
your Bank address----------
Country-----------
Your private phone number---------
Routing Numbers-------------
Swift Code-----------

Note, Your funds is %100 Percent ready for
transfer.
Everything you do remember that Good things come to those who wait.
I have done this work for you with my personally effort, Honesty is
the best policy.
now your transfer is currently deposited with paying bank this morning.
It is by the grace of God that I received Christ, having known the truth.
I had no choice than to do what is lawful and justice in the
sight of God for eternal life and in the sight of man for witness of
God & His Mercies and glory upon my life.

send this needed bank details to the bank today, so that you receive
your transfer today as
it is available for your confirmation today.
Please do your best as a serious person and send the fee urgent, Note
that this transfer of $18.500.000 M USD is a Gift from God to Bless
you.

If you did not contact the bank urgent, finally the Bank will release
your transfer of $18.500.000M USD to  Mr. David Bollen as your
representative.
So not allow another to claim your Money.
Thanks For your Understanding.

Barr Robert Richter, UN Attorney At Law Court-Benin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP%3DnHBLx9%2BoZZEXh4NOqjqVYOsF7h6SEbjGzy47zap3iwt--uQ%40mail.gmail.com.
