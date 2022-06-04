Return-Path: <kasan-dev+bncBD2OFSWRS4HRBRPT5WKAMGQETNWB57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A0B6E53D77B
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Jun 2022 17:27:02 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id g11-20020a05651222cb00b0047872568226sf5523718lfu.3
        for <lists+kasan-dev@lfdr.de>; Sat, 04 Jun 2022 08:27:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654356422; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bj6sCCAE5D/ivcDoYTQsiF8TjRKFVza3sYQUlFOunuAxaJ0JLizlikIoZ3DneQhGJj
         Gh24DcYkvhb8ApYAwFTmRXa5ySSp4Zny9WkoXCcZ+3M9o4sBzuU/75t/kmGKX1clKQf6
         tZbpontKDkJAUy5pwDJH3E+uwQODcnmWvJuMwNHQWlnLJOTGD1JAi/I3vsij/+DNiXsO
         HcG/PihyL0PJBpX3qgZfze7B4nOqpSQwIEwpNTXmRKF4HoHRVtsZYMDRkA6zMH9kf8y5
         P4B5FdzfoOuqMmJwWItJcsalAJnoCzNyNHieiHxWzkI6Vlo/MV07C+p4ZHZnW+i1IkU4
         GZsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=oLt1Awb21AOD4GnPKS7ZenG1bLmgGftnyydfXCjsgMU=;
        b=Le+ng/2LkIWps1obHqEKS3X+HQw5cXgzhVp+VQiNmZhB/PbmIkE7A5FgPlp7QJXuW+
         dBsglIOW4jbAprrcgfWYzyjFbnMAFB+IN8z4PxqlrJg+9oMy1HryjjM56nSYwHGHQKMb
         /0+3bjkORjfNItA5CrqQq8dsEC0PJPEaYZP0HldeL0Se8CDFJUK6BZXaUax9FeziNOIV
         uaMixBZYX7ZDVI3pFyusFSVwdbEnVP7P8WZFYm4xLuusI6EoauQpkUcp0/7leT4bPSLG
         SHw7M6iQGTxudz0lGIBXR/70uWFYq4FvNND7tQ1s/NPQnO+l9E6smg2h8P1oCCJAnqfS
         degw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="fAE/4nL1";
       spf=pass (google.com: domain of banghgf122@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=banghgf122@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oLt1Awb21AOD4GnPKS7ZenG1bLmgGftnyydfXCjsgMU=;
        b=No3eqpj24DdidRV0Ji38VI0V2zjjpnhLR+sUx5fYhvrK+3cUkIx1y70nuHJ89RrRDZ
         M/4ASVUrALeIbLu/oA+lTtLp93ROkQJDu7DUT1Q5NN9n++GKNRnWchBNZoOP0RS53hQa
         FKxjkELq+zWhPm1yxzAWflbygC+VIhJxc/eEyPb/FxOeuzPVkqqlsCtIA6bWnC8ivVPg
         8ihlQgv3tiS0CCgzjC0FOmP4PFfOyS9kRClSBOSvCmshCxjSXRXwn76ZR36U8XsrIiSP
         HRNhtb/lAZPrm1y0Ow87BG/h3SRlyMYVCeyvJ5vKC0m5GwzeINuR/1fVyy0SvPQT0VjR
         +9dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oLt1Awb21AOD4GnPKS7ZenG1bLmgGftnyydfXCjsgMU=;
        b=ZoDWNwwyGWjLy4mPkITsiw0YmjepBQ+QT+xEM6NrPlo/Lggs6P+llO5ZPGCnmUFINw
         pnCtmtbK/VqP9zwLCZFB1nMti1dXmUYAGU81AX24e0lnQ0wLABS+vfHBjwPIToR9LDkJ
         iYcSBdrAPKrjQc7TuMywrP/MC/5UxBzOxp7SPMBEZJoay7Vly7SDKCTb4E8vJNKCFplQ
         F+XhMmbOKy0IPwGowlJIUFd1kCi0qifS6oh3zRJlYBDEaV1ptR3heReiCJMMUBuAxSw2
         Qk73zl4leOkULlV3dRDwqcX2s9YZ4cL7456vht/wvii65Nuy84J7XV5WXqCu8irJ7ELB
         fLTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oLt1Awb21AOD4GnPKS7ZenG1bLmgGftnyydfXCjsgMU=;
        b=yrGA74wT6SH2noP7K+fcT3hpG5kmMk17EUBi+t+Z9V3WEFbuptaObrnJa6S7NBYXW8
         7tCLWqp0lk4eKSYqfhKKNtTnk/moz0WszpDbzQ69sHBAfKxmIGcAWjC097fa8iOn2BPi
         3S0pp0LItcBG7khSo+uLfcRep22tprnKnu2h7v1iFQTo7L/cBstmpCfiEzmWQVqw4NwX
         2wCcYp2FBBYFmo2lO5O3hv0nR/29E97qj10Nt8T12LYoAtUODyKkpY9xA6K69+Uqv2l2
         nApvOUsglsNE3hHgGzkFwmhaaxvakaXzu0duC5cQpyWpiQ7Tgq7VLqTD30YD/+5TzaqI
         ZkGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ol1z4cfxczBgFTu6P80d9kzhJcIiCkLU2ZubZ0gFYKFGHXbvs
	AAEi+8yjY9crqaVmd8vQers=
X-Google-Smtp-Source: ABdhPJzkseteSgHZhwfIQqoXj9Cr1YKY6krMkCoQsp2UbW35Fl72OXCEqLF6gesDY5RbesVTQNQdXw==
X-Received: by 2002:a05:6512:1047:b0:479:2308:ac0b with SMTP id c7-20020a056512104700b004792308ac0bmr2650588lfb.167.1654356421705;
        Sat, 04 Jun 2022 08:27:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als2206086lfa.2.gmail; Sat, 04 Jun 2022
 08:27:00 -0700 (PDT)
X-Received: by 2002:ac2:4bcc:0:b0:479:16a9:897 with SMTP id o12-20020ac24bcc000000b0047916a90897mr6340231lfq.71.1654356420458;
        Sat, 04 Jun 2022 08:27:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654356420; cv=none;
        d=google.com; s=arc-20160816;
        b=P7nr4huCPM7ULylvV8KZdOHzxIwiFHeBP0DaZLCTLG+E56G+hVOu2X/O8NXRalowI9
         WOTEjXeuqVs365XLBnNsk1Lgzew7QYITQlokyziwspDnD+XO2m6t2FQ1hBNe13o0+sd6
         gC69hQ3Xwi7OvsJ6rXP7bCL9jkW40pKgxzQj+gZyhe3orFOf3Uu+Y3EgsDrzShZ2F6aL
         dGMe+PEh/eC533jOEjDM2TRNyUIPEzXESM34LCFnESlUt9y2+DSZHmzP4H5gd+AkGoql
         oI8hk4XY1CSXk4NyL3CU/djbJr6sSsAwew46aO4tKLd9QJpfM+kAMayBooAMRzJoQCUo
         qN6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=6EerBljktP+gnWzHtPxVlfrDboUl7I/he8meIBCxse0=;
        b=xkKdeCU+zHpNAN5xiF4M0owzwiNqRB9NURWM/JzDCxjGcKN+Rqr2rr9pQWYzW395fo
         4wishtju+SEI6E9XkO1KZy4UnVb9Kid4ryhS8xgFWvlXqlbVFYjj7TnY/ZUZ0byPy2GC
         dKflBo9crPPAqvy1d89dBfTTy3AyM8ozHcavErmkmqMW0wQ6uKIZqvGLA3DbGiqsTGDC
         ZT9PQZrRPEU6q878PJhhoU/vbzf7IV/PrNlxFvX651SW+dPIc1sY6nHjVJ3I9U1kUNqp
         0Q6h81qRdbkuNeRxuPqVlfR6crLyzWlLdsRwgSMmnz+heOUQaLWEnta/P3BbmmMnjysb
         TCew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="fAE/4nL1";
       spf=pass (google.com: domain of banghgf122@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=banghgf122@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id z17-20020a0565120c1100b004793154b447si41014lfu.13.2022.06.04.08.27.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 04 Jun 2022 08:27:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of banghgf122@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id b8so13531481edf.11
        for <kasan-dev@googlegroups.com>; Sat, 04 Jun 2022 08:27:00 -0700 (PDT)
X-Received: by 2002:a05:6402:49:b0:42f:b4d4:3848 with SMTP id
 f9-20020a056402004900b0042fb4d43848mr5571991edu.290.1654356420087; Sat, 04
 Jun 2022 08:27:00 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:a05:6f02:6495:b0:1c:fa85:8bde with HTTP; Sat, 4 Jun 2022
 08:26:59 -0700 (PDT)
Reply-To: drahmedcompoare71@gmail.com
From: "Dr. Ahmed Compoare" <banghgf122@gmail.com>
Date: Sat, 4 Jun 2022 08:26:59 -0700
Message-ID: <CAHfPWB2FWkwvmyEddrJqA=DYgdmQJGv0OL6iyudjSD-TOYE+Kg@mail.gmail.com>
Subject: BUSINESS PROPOSAL I NEED YOUR REPLY
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: banghgf122@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="fAE/4nL1";       spf=pass
 (google.com: domain of banghgf122@gmail.com designates 2a00:1450:4864:20::530
 as permitted sender) smtp.mailfrom=banghgf122@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

FROM THE DESK OF DR. AHMED COMPOARE
AUDITS & ACCOUNTS DEPT
BANK OF AFRICAN (B.O.A)
Ouagaduoguo Burkina Faso.
MY PRIVATE E-MAIL; boa.bank_remittance.bf@protonmail.com
MY NUMBER. +226 64554871



BUSINESS PROPOSAL I NEED YOUR REPLY!


Greetings Sir. My Names are Dr. Ahmed Compoare the manager Audit &
Accounts dept. in the BANK OF AFRICAN Burkina Faso (B.O.A). I am
writing this message to request for your assistance to transfer the
sum of ($10.5million) into your accounts. The Saying amount was
discovered in abandon account that was used by some African
Politicians to move Billions of Dollars out of African and most of
this Politicians stole this Billions of Dollars from the Government
Fund and transfer it overseas out of their greedy ways and this $10.5
Dollars has been in this account for over ten years because they dont
have the access to Claim the fund from my bank, So i and two others in
my Department managed to Deposite this fund into an Account that
belong to a Foreign Customer MR. ANDREAS SCHRANNER from Munich who
died along with his entire family in the plane crash since 2003 and
since then, Now all we is someone to stand with us to Claim this fund
from my bank.


Now Our Bank made all further investigation about he fund and
discovered that Deceased died with his entire family and according to
the laws and constitution guiding this banking institution stated that
after the expiration of (7) Seven years, if no body or person comes
for the claim as the next of kin, the fund will be channel into
national treasury as unclaimed fund. base on this matter i wish to
contact you to handle this transaction with me to enable us get the
fund from my bank, all the Deposit certificate of the fund is with me
so all i need is some to stand as the next of kin so that our bank
will accord you the recognition and have the fund transfer to your
account. Please My Good friend you dont have to worry on how to stand
as the next of kin because i will give you all the informations you
will need to accomplish this Deal without any risk or problems.


The total sum will be shared as follows: 60% for me, 40% for you and
expenses incidental occur during the transfer will be incur by both
us. I will give you all the Details informations you will need for the
Claim, Please dont see this as risk because all my bank meed is
someone who can stand as relative or Business Partner of the Late
deceased and the fund will be release to him according to our bank
Legal procedures.


The transfer is risk free on both sides hence you are going to follow
my instruction till the fund transfer to your account. More details
information with the text of application form will be forwarded to you
to breakdown explaining comprehensively what require of you.


Your Full Name... ...
Your Sex... ...
Your Age...
Your Country...
Your Passport ....
Your Marital Status...
Your Occupation...
Your Personal Mobile Number...
Your Personal Fax Number...


Thanks
Your's sincerely,
Dr. Ahmed Compoare
Audits & Accounts Manager

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHfPWB2FWkwvmyEddrJqA%3DDYgdmQJGv0OL6iyudjSD-TOYE%2BKg%40mail.gmail.com.
