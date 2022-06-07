Return-Path: <kasan-dev+bncBCX3ZGPQYINRBPGU7OKAMGQEAZJBH6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 676F553F5D4
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jun 2022 08:03:42 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id ob5-20020a17090b390500b001e2f03294a7sf13317297pjb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jun 2022 23:03:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654581820; cv=pass;
        d=google.com; s=arc-20160816;
        b=zGfyB4O9MIHLxVu3jDYw6errEzmAJuNovQ8rzgfDyqQlh9NBtVj7WVXr1OtcyBTiZs
         bb+KFIPM8W6YQl94rGsF0z5BCQLTbjECGdTkHB/CBBH0wF/TpgyMSOk494nwYqvBZsKl
         e9X5Hy7LYoemr2kWluBeKsYkFLyCtP402SrSiA2blXBZLbtSrzsCBdjkNBiZAf7RBdRa
         tf9i4QQVpT67c9x5GTQiqwDE0RgwBiG8/ELc3DHsUJfyBUv1VYRJguYYJgZYmA5ffBAt
         HoO5tqemhXGLrYL4zSG369xCC9+tw0Ad5DuRhncoe7l1zVYiGp0T3Eu3WHd5ybydl1XB
         dENw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :to:from:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=XshcakbrbjlWYwXN2xGlJ5ecUsNuVkLB2S30Z19GqjA=;
        b=VJebtD3gmyQPJQ3AxmDGxpZhemcsJlwyQthNhMbiEDxwQ8dxHlvco36+IXC31NR66a
         J3h8Ivjh2BdU9xBapJYZ8hiMGL1Mdg2qAwMO1c6qKC5fVNyvwS3EQzy/elKE0FFUGGGv
         N2/rr//h2CDQzNRdLMbytV3uVZXx+DHSDy3abKEOu5/5TPW7DpEhpJ8tnIjuZIHQMIXu
         x1c7cjp53d4aAw/Ee0fzn+dXJwvpL+5Vip8Lrrb1mb/vJcz3GqP3Uedmvj+wtmpd47tf
         SwnVNJ/GxeAg4Tt/VBgwyEw64XNlijmQZ27jYBCSkDW53uO3S+YrgpY7liYUKiPZoHXt
         dmDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P6mXJM59;
       spf=pass (google.com: domain of rodrigohezekiah728@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=rodrigohezekiah728@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:from:to:subject
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XshcakbrbjlWYwXN2xGlJ5ecUsNuVkLB2S30Z19GqjA=;
        b=HocEu2m97MKDYJRCh6gd/egjceaF2vgcw78dHfOIAUYV44OFOD6nb6/xd4cK5j0ThE
         82cGRzqFFb9Kt9ZCfTD0Uu/Ak9BjGpJfSxo7Sckp0B/znSlf5vv+jvDwkv3uP9IgNnty
         qb4TfE8BnWtx/1vjvsQS0veSIhHxjfT9Hown5ldAFqyYNzaR3EeZvq/ElKYsutVpx8IB
         F3w2Nv7tLg4tGlIABB7jORanSPUbKKOBbjGOhn8OQYXSNtrcdQ5BtytwvPNnbJPWY2og
         0SUmxO6+1PH3FhG65OX2JXf1SVfa5l4lW0DkXmUGS/2abqIq0alSYv/opvj2mZIUvuQn
         fxfw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=message-id:date:mime-version:from:to:subject
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XshcakbrbjlWYwXN2xGlJ5ecUsNuVkLB2S30Z19GqjA=;
        b=UtsWC4oFKVbFKiDGLVpyDyNOiDfciuv8ikFLHVf1Fcf8x0+yQ7uwv4/Ee2JqW5/Rmv
         UEAxaxXlV9YH3PK2gswe/fBwOKuEXxIKStNNHBZvNnvlOurTpK029kZzzOoBVxvqcmLo
         y5LJaeuHswM+n4LcEofdLxLp2i748O23IxLIy/3a0CIFk/2/9Q6tMUfOlxhXTchQ3cNC
         gDoMkxC1zjonTKv5b3BOOb+rm5wrg7z8CLesaRArTbCc2wyRI6YdAzE1PCR70hGMllQ0
         +rj/8qcLTCYFsRH9MHgWcCIAcofCw4kN8uWdmFYtDg4fvDit0umi+RfND51eqdCt/tbV
         SHXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:from:to
         :subject:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XshcakbrbjlWYwXN2xGlJ5ecUsNuVkLB2S30Z19GqjA=;
        b=rjqVRsKJVem75VIv4sco09iorAOfnP8CCAeuPrLm7cGYgJjm3tWCvlbr4OW4urTt2F
         O9XdlZUww1B1N5aK/bfdjeXg/52wWjSjT1AtyhMaPn0QEgrbWmVbBmNTFZwn2SPzUDCU
         +nmu5JkF6C6/E17P2FaKUyJmuO2pE3Z6HdlXK6fg1CyVAK3ZvQj9IL5xa9LXKBqxcB7b
         6nd/IftWwpYO651MGjwYzlnyQk+ocWkdrY6S934JNKe5vnLtlVFinQmveLQ6ypVz3gY6
         m+fu9CRMPSIXHLLgjNqCj3s9MCD/nzQBc8Lri+6l3Z52faqq9ULFgPFmjEeHmgZs4Kp6
         o5ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ncr9n4vSM7ns3ndnUzBWontq2PIXl1KGZf6ZrWsIsyi0FFqtg
	CMkMRZ9s+lCPwV5RzQFro9w=
X-Google-Smtp-Source: ABdhPJzzIf3e83B78OQyMGaXn0KVUtZn6YBsgafGLvDVMlboWwu2bN2j2A2giY05lH2ImtLus/QL4A==
X-Received: by 2002:a17:902:a413:b0:156:15b:524a with SMTP id p19-20020a170902a41300b00156015b524amr27586837plq.106.1654581820567;
        Mon, 06 Jun 2022 23:03:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:22d0:b0:51b:ee43:d2aa with SMTP id
 f16-20020a056a0022d000b0051bee43d2aals4504328pfj.6.gmail; Mon, 06 Jun 2022
 23:03:40 -0700 (PDT)
X-Received: by 2002:a63:3d0b:0:b0:37f:ef34:1431 with SMTP id k11-20020a633d0b000000b0037fef341431mr23968080pga.547.1654581819979;
        Mon, 06 Jun 2022 23:03:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654581819; cv=none;
        d=google.com; s=arc-20160816;
        b=nFZhYPmsQPJHsNT8XkMgM+ySXtyilTOS/4i220z8JCBdsNrLRjs85O+JRRLpCsMhMp
         ZsOgI/r5yv74tAHDb2VG8PAVzxudoh1E0bLn+1fJF5SJYxzTAML9NQ+xnoKxMEc8IDcr
         eVF4xFg2CNOhg1qirycWXOrLT3RvU0g0U97Ytrqp3QYZX3LXh2AgJUIDV41zQ0V2I1dz
         4ALpZtjH+8GbluIEUxD/jmbDf8h//OX3g4dUIWSrBsae3Ja0aSYD8F5UlWZJI4ulUciL
         4gQfhPVztO4Bvg2snhNicncO4Poiwk0XwPVUP/POuwXmQF27Oq+3xw57CWbJ+MUqBYOa
         ku6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:subject:to:from:mime-version:date
         :message-id:dkim-signature;
        bh=2Bv9SpDZbs58RkgSmmv+783lhQJ+GWUHa4QNh+IkRBs=;
        b=oJFTdiUc5GAiDsjxfXTni4av0YVZ1hUoC22WPXd+6RFvvI4uEiCx4yCTvmFS/ZNTv4
         JRNAEiZpOSGKzjXkTL0PCR7nMTccnjnRGaPMWdXK9S0XbrXV+0wZgIFcHP2268XSeAM1
         80RE2k4chAfsKBv3Awdj5gvfToAQrxwNRpK3ffhd7O6fMWC0Pn8ytDpeP/3egDIv2M94
         0knmkFUE9F+K4pCqi/3ICa9qBn8DKoo6QOTbmNM776uLaygi2GXqATaCDWCQp3qFGj26
         E3ut2UOz1CbEuyOdPhAEBcioGoYQ51jFDMSiTZwEjebzxHay6Du8tpYwnM2JbMlCiyY4
         MjWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P6mXJM59;
       spf=pass (google.com: domain of rodrigohezekiah728@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=rodrigohezekiah728@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id mg18-20020a17090b371200b001dc5c02d737si881937pjb.2.2022.06.06.23.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Jun 2022 23:03:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of rodrigohezekiah728@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id d7so7924011iof.10
        for <kasan-dev@googlegroups.com>; Mon, 06 Jun 2022 23:03:39 -0700 (PDT)
X-Received: by 2002:a02:aa92:0:b0:331:c856:fe69 with SMTP id u18-20020a02aa92000000b00331c856fe69mr2146976jai.187.1654581819655;
        Mon, 06 Jun 2022 23:03:39 -0700 (PDT)
Received: from sdgs ([20.98.161.10])
        by smtp.gmail.com with ESMTPSA id bo22-20020a056638439600b003315c30100bsm6067219jab.7.2022.06.06.23.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1 cipher=ECDHE-ECDSA-AES128-SHA bits=128/128);
        Mon, 06 Jun 2022 23:03:39 -0700 (PDT)
Message-ID: <629eea3b.1c69fb81.4a7db.e1e4@mx.google.com>
Date: Mon, 06 Jun 2022 23:03:39 -0700 (PDT)
MIME-Version: 1.0
From: "Hello-Bill Pay Amaz" <rodrigohezekiah728@gmail.com>
To: kasan-dev@googlegroups.com
Subject: =?utf-8?B?SW5mbzogdVBkYXTDqy1BbWF6ZShpbnZvaWNlKS9SZWNlaXZl?=
 =?utf-8?B?ZCAmRGlzcGF0Y2hlZHw4OTc1Ni1SZWZlcsKiRGF0ZSg2JzIyKQ==?=
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rodrigohezekiah728@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=P6mXJM59;       spf=pass
 (google.com: domain of rodrigohezekiah728@gmail.com designates
 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=rodrigohezekiah728@gmail.com;
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

<HR>
=20
<P><STRONG>Shipping(s)&nbsp;#:&nbsp;23567854</STRONG></P>
<P>Date: Tuesday, Jun&nbsp;07 2022</P>
<P>Existing User,</P>
<P>Your&nbsp;purchase for $469.23 has been successfully charged. Your Order=
 details are stated below.</P>
<HR>

<P><STRONG>Dispatched(s) Summary</STRONG></P>
<HR>

<P>0rder#&nbsp;56ER48TY188IO5<BR>Billing Date- 07/06/2022<BR>Item:&nbsp;Ech=
o Show 5 (2nd Gen) + Echo Dot (3rd Gen) =E2=80=93 Charcoal<BR>Tenure: 3 Mon=
ths<BR>Payment Method: Pay Later Service<BR>Price: $469.23<BR><BR><STRONG>T=
otal: $469.23</STRONG><BR>Product Key:&nbsp;<STRONG>******78JK458F</STRONG>=
</P>
<HR>

<P>You must download the app &amp; Login to start using services</P>
<P>1. Download the Application</P>
<P>2. Login using your registered email &amp; password</P>
<P>3. Do not reply to this mail, it is auto-generated, so it's not monitore=
d</P>
<P>For more assistance or to cancel this order reach us on</P>
<P>+61 8 7200 4838</P>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/629eea3b.1c69fb81.4a7db.e1e4%40mx.google.com?utm_mediu=
m=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/=
629eea3b.1c69fb81.4a7db.e1e4%40mx.google.com</a>.<br />
