Return-Path: <kasan-dev+bncBCBPFK4KXMKBBKFF76LQMGQEMMYC4FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C6B1759A53A
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Aug 2022 20:12:57 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id p8-20020a2e8048000000b0025e51a00a43sf1295304ljg.9
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Aug 2022 11:12:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660932777; cv=pass;
        d=google.com; s=arc-20160816;
        b=KaE4UTUZzKCTyvAAQU6eE4Gi/98LfR/RzGmozw/mjBgIkPLqYZ2vC80Wz/h8fdchUn
         t0Mr1A2SYDOhr7BhDRN2jpyY67gv2UjYosywcbkcmBqNws7G7wJs04eW/qsN1Ino0v1W
         lnsmpsB543u1Aj/4NSBBP2xAa0zinIkKqpaDBje8ys7JPKPPyBYaQPOysWhQCu1L4W1D
         cFb3cagsyfyfyTOvYQKEKaVlocRbR7nFVO1fHfC0drnSDX55wIBKUrHkDToYtbyqiWih
         abKMsIbvw4ucPDmEq1rjhtsB+DwwhHV2sZC7PJmCH1Wy1CzybGSfOs+ZMI18VmEThusE
         QieA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=blN+TNmWJweI4YtWgG66FsDzmVUB9KvkcB7y/Hl7YDw=;
        b=FlXv5WWZtNIm3VHAD/hRZxuuj456fCCt3IHkXdgUUVn7SSFkHVt7y1bgdq8T6NAAiB
         4S+lqyWnpX6ftfgeQXvQgUYgPotVAHAqXYYm+AHU1Sc8to91IeTOuAdcu7VHcbD+Q1Vn
         VpmTKWuJQVx27fV6q6N5J3H/NbhOz7Vd8rG+DQqC5/PvorxxvBmqP8sSLg9gXWnmcc19
         e7lMirJ7amw3USFi420S26ROhxxaIryZ0Ew+B4qWi0g7Oy00nTrXN8sUAnPXl5xNO3C6
         azOOEB7R2Kyb19tlRyuZrk7Tn6nA4FpIkNR5VRlMNYYUv+z7/CvNDr98KeAFu9CZ0lIU
         XMug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iop74KZc;
       spf=pass (google.com: domain of anyanmileelijah@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=anyanmileelijah@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc;
        bh=blN+TNmWJweI4YtWgG66FsDzmVUB9KvkcB7y/Hl7YDw=;
        b=GrfCMJiIb9pK1+MrxiFsWW03a7DywuD9Jv8Vc5PKMP6tn1GmywP45dvIAPHIzvFel0
         EBsTa+osI2QYwi5vgbuFLeda110hkZ2tD0w7hOGWPxLNgLrRgh0OpBZo+AzOYlo6KKKO
         dsi3+Vt/TGUKOPgAjRpIhj/Rh7Gl4ggFCGSaaKQy53wDh9VASogfDge7mA5VNbrY8LU0
         Y/ERYBzq3K6IsGlII59VLMNi80YVI6WNlvgWYPPSRd0W0QVeG5rEWb5CSPa7IYEd9Xe1
         mForOh6tKlOUnOPjnOhgZuoPWQEYTpTU1IYRgiiP4ctxXz6PXvt/gq3bt/3HGt+cT4bu
         QS+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc;
        bh=blN+TNmWJweI4YtWgG66FsDzmVUB9KvkcB7y/Hl7YDw=;
        b=b/7nqmebZAcENodgHrjZZ6LYrw27woUlr3xA+Q0cu4q26fRm5k8Z4xxEqWE+yiGxQ9
         ly3sI5mmcd0KxKrgKmip5OtLObhnEa+jYO/LVsvoPHR1Lo5jgp/IljxZCElLFeeHQqk+
         zeB0X8NgH89ds5cQuGmOpUF0GOeiJNG/rE4YVvVlYnKWGPGwzBrybmCFWRvyfCzBJjYd
         2SQ9Lj/VWliQmQoCy2IqOaj4sa41cK41Lye5P34L+ka6HUKxRpRUjwNuJDa6K8wdcGbb
         dK71UcRmIBulwBolzZX6yrfqW0m6GI9Pz0Pqp43uQYUCYbmVbRjBOyPjD+IacqgpTVPp
         kR9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-gm-message-state
         :sender:from:to:cc;
        bh=blN+TNmWJweI4YtWgG66FsDzmVUB9KvkcB7y/Hl7YDw=;
        b=WXZ9KY0SrxXRg0qin1op0ntCYhogZaznaI4AQBRPm3yGebW8qL6wFNfeJV5oOcs2fK
         6eh9C7A94EFch5IPCM3R7Q8TRpd07Pxlj3bKV8PSgOMO+J4+8LCS9AtRb4CjXv3pdVyM
         TvOPcNDCyehedsKHjuhcPv96nUbuTpWuaH9Su63PW1sW0PnMOm+ulxP87Mgag/fNZ+UM
         K+Fh+kgCaZGvHn+w9Yz6EMQAX4LhO/oHv1vY7lvC3eOyhatiAGD7Lx45ehLLuMjeERPG
         vHultu89jLS7ddL4yS+kcGhWLG1CD5Ij42pwkJyeD4NN1MhrDnd1IFzFmEkvjRqZyANJ
         SEdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0PQLL5p+BOptOTdIvRxj5W4xG2ox5siaLVwxRpVADoGXZJ3r0p
	H56LCGVW+9RZm/M6/RAzHLU=
X-Google-Smtp-Source: AA6agR5sW1kHoxH1SkYiWB/3nBQDWhlG6CTN2wgn1FPvUHyD7Ta6PpsptBnfWKU89sEgp5Y5/Y3tnQ==
X-Received: by 2002:a05:6512:1115:b0:492:ccab:f9f4 with SMTP id l21-20020a056512111500b00492ccabf9f4mr1193381lfg.458.1660932776778;
        Fri, 19 Aug 2022 11:12:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc81:0:b0:25f:dcd4:53b4 with SMTP id h1-20020a2ebc81000000b0025fdcd453b4ls715065ljf.3.-pod-prod-gmail;
 Fri, 19 Aug 2022 11:12:55 -0700 (PDT)
X-Received: by 2002:a2e:9a9a:0:b0:261:bbaa:df12 with SMTP id p26-20020a2e9a9a000000b00261bbaadf12mr1528246lji.134.1660932775579;
        Fri, 19 Aug 2022 11:12:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660932775; cv=none;
        d=google.com; s=arc-20160816;
        b=Jgc9JE9TIJPibMlPHDZHgQ61TJwR75DL54go+ZcVAQ5nIfek1TTMBTJyMqvTVtuHuz
         BHn3CZTaMIJdipCe+SfC+fEf97ptQTYpVB6qNJw3PZhk0zm3JOvdgBVS9DToS5+Poi2z
         A22hloUQy/6eL9KGlmGfK1KLbq1dZCQFawMb5/KpC/jlpSAKlJ+NpPq/59Is7qPmcCgD
         GRzzOMX0GnAm8pWDkROUlifXp8CnZfa18pBTYz7WhyIi/8CX+sJal08l31AVpg2iGTL6
         N4YcQUvdEKDoeXyLpozE7t2KJeay7NaF2Pc2kfgRiE+U2+CYQLENeN9Xt66lcGPnZ8gL
         bwHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=zwjVZwGnm2rg15FlsdzE5yN9sbaUulvkvf2Xp5lcvmE=;
        b=xepbW2lmAvLdttkaPx9ULxMVpfsy5/DCzEue+/J3ZZ6dPu3GxdI1lHseqQANZTRm1j
         CYZ/9JyDtUQotBwsDUMORw9aFx/sU8tg3U63e88RIAGvZ5c5muFW7E0XtwwLWTYTzdG1
         sQ22nBmu1QDY9qfwYuyVnvRFResle9taLDzCqLK0uOnQy5ymFsyUQ765A23suzLQVw2F
         PyV/zdhMpNV4SYH7niJiU6yQqxpeijfeW1n9cCf+to+Y/8uGaGboJUAUhCEKVZt7qPPs
         zepodTRAbCpdPlgzp6Cmsh6IsfH1La55BoPSDaKl1BBKfO14ZetdF+lr4QhNGSkDZdj6
         U2hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iop74KZc;
       spf=pass (google.com: domain of anyanmileelijah@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=anyanmileelijah@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id m18-20020a056512359200b0048b39ae06fbsi198555lfr.11.2022.08.19.11.12.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Aug 2022 11:12:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of anyanmileelijah@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id m3-20020a05600c3b0300b003a5e0557150so4144677wms.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Aug 2022 11:12:55 -0700 (PDT)
X-Received: by 2002:a7b:ca48:0:b0:3a6:2932:c16b with SMTP id
 m8-20020a7bca48000000b003a62932c16bmr4746430wml.140.1660932774835; Fri, 19
 Aug 2022 11:12:54 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:a5d:6a4c:0:0:0:0:0 with HTTP; Fri, 19 Aug 2022 11:12:54
 -0700 (PDT)
Reply-To: imf017851@gmail.com
From: International Monetary Fund <anyanmileelijah@gmail.com>
Date: Fri, 19 Aug 2022 11:12:54 -0700
Message-ID: <CANZGQiS8Er22A7+E+fQrbbxYMHvf3pbM14aTUtZJWMkcYPv3ag@mail.gmail.com>
Subject: Contact DHL for your released Funds
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anyanmileelijah@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=iop74KZc;       spf=pass
 (google.com: domain of anyanmileelijah@gmail.com designates
 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=anyanmileelijah@gmail.com;
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

IMF International Monetary Fund
Fiscal Affairs Department
1900 Pennsylvania Ave NW, Washington, DC 20431

Attention: Beneficiary,


This is to inform you that the IMF has instructed the Courier
Companies in this Country to release and dispatch all the Monetary
Instruments in their Custody to their owners before the end of the
the first quarter of the year 2022 unconditionally.

During our investigation, we found out that most of the seized funds
were not for illegal transactions, including your fund that was
stocked with the DHL for some months. We have passed instructions to
DHL to dispatch your Fund to you since your fund was not for illegal missions.

We have paid for delivery and insurance charges and also supplied to
DHL the legal documents needed to deliver your Fund to you.
We understand that the content of your package is an ATM CARD worth
$3,500,000.00 USD, DHL does not ship money in CASH or in CHEQUES but ATM
Cards are shippable. For your information, the VAT & Shipping charges, as
well as Insurance fees, have been paid by this firm.

Note that the payment that is made on the Insurance, Premium &
Clearance Certificates, are to certify that your Fund is not a Drug
Affiliated Fund (DAF) neither is it funds to sponsor Terrorism in your
State. This will help you avoid any form of query from the Monetary
Authority of your State.

However, you will have to pay a sum of $195.00 USD to the DHL Delivery
Department being full payment for the Security Keeping Fee of the DHL
company as stated in their privacy terms & condition page. Send your
Postal address, telephone, and your name in full. It is mandatory to
reconfirm your Postal address and telephone.
Kindly complete the below form and send it to the DHL DELIVERY POST
with the below information.

It is mandatory to reconfirm your

FULL NAMES:
TELEPHONE:
POSTAL ADDRESS:
SEX:
CITY:
STATE:
COUNTRY:

DHL DELIVERY POST
Email: dhle76384@gmail.com
Contact Person: Mr. George Ted.

Have a great day!

Yours Faithfully,
Mr. Jerry Harrison,
Regional Director
International Monetary Fund (IMF)
Contact DHL for your release Fund ATM CARD.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANZGQiS8Er22A7%2BE%2BfQrbbxYMHvf3pbM14aTUtZJWMkcYPv3ag%40mail.gmail.com.
