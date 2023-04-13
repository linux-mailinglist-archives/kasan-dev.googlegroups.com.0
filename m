Return-Path: <kasan-dev+bncBDOOJX6A7UBBBOPQ36QQMGQE5VFTTYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D01B6E0D90
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 14:40:26 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d21-20020adfa415000000b002f68de99106sf9418wra.19
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 05:40:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681389625; cv=pass;
        d=google.com; s=arc-20160816;
        b=izaA3jXXqij9bYWvFpFPNPvrDgIUwFkUvGqzUUET8L/nQNIWiC10e4vW7UOTHzpqVU
         p37IBmZTlKC3yKZ/rGA4V0bSmhqqmxWijxIMgMTDbQwUWglH1/ZUUdm+U1hoGG/62V3D
         u/Um3aycknNyBy1hXI7UheYPYq//gEDpVYYy307XjHf32je/yNmCpkSSfjyLsQo2zqbA
         jrbyyYIwiYNrDRWVGqHtxvB48dw3GjrD8nlsbQfZtOvqBhkbjMDLTuwQzKh/XDH3M7bH
         36iZzCciQ4HI5CJMYHF7ubSxDPubRe912NFCHS0aVATISBt730+deTLBVgvLX+WRs0iy
         pd4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=wFOVdrlPWxjvzTSLYFonaP8yXoGCQtZzsJ21eURxKxM=;
        b=R60Yt6h3PDgD6wIBlzkUCFolG82O59oiP2Sf+tfeX+mSZ2RAoKs5ZN6xmhLE9VUCuJ
         X5pRFFi/AHnbNSOXcoyKvcUaB71e27XXGs98bqWytgB2MoB2N/OgtDTtUX4e/Aqp7kPA
         MBIn6nFVbriXOPo83Jl6CW3X4WgmrhWwMHn43n/FR8HDhOXviXjCkbgml4Sgly2VcY6K
         BZKVb+uSF4EQzbPOoFXEE5nimFGWLiB5f/waZZqjow4ti9qc5d+Ahg6Bxi6/ZRGLsEuf
         GQgNDnCl2Hdlb3bAFbdOqTL2vat5nQn0sfcnK2VXReRzbACr8fvu478VgWf77NH/cu/c
         XqFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Q8Wbusdg;
       spf=pass (google.com: domain of ousmane.ouanga70@gmail.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=ousmane.ouanga70@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681389625; x=1683981625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wFOVdrlPWxjvzTSLYFonaP8yXoGCQtZzsJ21eURxKxM=;
        b=VEJHYqIPX34VmdCnlcVN2spMMzWQfQq/IJm2WiHaZDJAwedn9/K25oqcrX5YPCXV88
         CXaV1IRbq8MLlc7TUmEhb/mE4QG4zpfX1R6lEBEmPi7dRQKQR9xck+iFKadqfRmPENBA
         xKJtmmzyN4wKfBpnwS/JGgXkqndWNmR952RYXHGMniWqniuZA/Gdf4dsnLlnEKyaSW1C
         Nk9PTUCC4jB6nRzG9oCFflv47bA0zsjHCiCx5An3Akw+a4NlO+TitlgCYWqTcscPY4We
         XfL7sbWqCb3rj4FAlE4atm4RhMWMVg9e/B8MLXz9U7gbdZzCKlxp+m/3GIGzoGD4PTrW
         aQOw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1681389625; x=1683981625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=wFOVdrlPWxjvzTSLYFonaP8yXoGCQtZzsJ21eURxKxM=;
        b=jNnhdzqK6ExlRD9yOSEBFlZWA4Oe8wm5f+b34lMrCpUDjYE8p0bZNrYpSld+wfIpjm
         Ievi9li7lbC5fpAdk/XR2sxFzPdoeCzAsy2eV8YNDNc3UE15OdtxYOV7HtzMHtI7zcWH
         Lwjnh54AlWXCyBZXAoQDFtWzcIzMOMMobXckJunNz6UywXfyrhxxQwazHugX3EbSDqJZ
         k7YCAw00R9tM2Q/TsoKpKoqUCwNs7et6Gswp1hR4KI7Mn/4LWP8gIA+2dLlIRRdlfWQR
         h6nJ8TlKTB8huoC5EJXAQMbsa0Ec158vlyGOVBeueQZw3mCbiooDPjdA2JkihNYv6e33
         L2dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681389625; x=1683981625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wFOVdrlPWxjvzTSLYFonaP8yXoGCQtZzsJ21eURxKxM=;
        b=PXBa/1gWoLJaYv19Zvje6NH85yhor0tCm3SiJEbS121pfNMyd+h9Im1GTvt6nOTsYi
         rVihQHp3w55J3KQXKQQGnxFXkr8PCU8gvsoephfUHyEtLoybyE9mBEAbjGWnRVOKD0X3
         5YsbkYha72qBSMHT8c0DVuxANhpadVe7SguXgi2qYpT9DeG9bwqMWAlIKsRmO0DfT9cY
         eaUKDNf7mwwQhmSqj8YSzu3PPKDDn1uGKbpphVxu/EmCI1IkmihJY4G3kCNsch5w5Ka+
         me/fqNuu4sKYZ9g/OR2BALtd0dZRaUsbiGp7ws4Rh2EYnmrYCZTAdxTLg4C3fHd7J0O0
         VjWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ebFWVKwq33raRxGcZrOe5xmZh3wErXaA/QVDQe4QLJsNiwe7O4
	mDEHNIeK6MMyF2iVTIcjtHk=
X-Google-Smtp-Source: AKy350YBKpvDZwvujcrmKmutYl+egibeGqdQOS07wEfMTaa2dEaIahu2PjDWVb/qcRkI9Ll7SjBTqg==
X-Received: by 2002:a05:600c:20c:b0:3ed:2f78:e331 with SMTP id 12-20020a05600c020c00b003ed2f78e331mr560176wmi.6.1681389625245;
        Thu, 13 Apr 2023 05:40:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:470e:b0:3f0:87a0:98f8 with SMTP id
 v14-20020a05600c470e00b003f087a098f8ls5978306wmo.2.-pod-control-gmail; Thu,
 13 Apr 2023 05:40:23 -0700 (PDT)
X-Received: by 2002:a05:600c:2141:b0:3f0:9a3f:c8b5 with SMTP id v1-20020a05600c214100b003f09a3fc8b5mr1767095wml.27.1681389623658;
        Thu, 13 Apr 2023 05:40:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681389623; cv=none;
        d=google.com; s=arc-20160816;
        b=tnz3mi/XePd/zfSPXdskedJxC17mP4h7tTkwCIn6r3m3WxUJa6PT1MYQpSQwwthPZh
         90gjjuSKxg52Ud4t/IxPycw6K3eHuFbbCoR01jT+XLvkjOU6NSFf9yqpWTeDP/tD8Z40
         YPgHH/FzxQOdoGvpm2N35v3C5Ae4MAzkg2t8StwF9JtmPfXU7S8kU1OtlPj4pqT2y9+j
         rqS3xd6+0o01hJ4KytzDNBJAW1iEhsgAkiocrdNryyXBonX5IKY5RktsKzEUi6zqprKQ
         FjRN5/E6jpnwaQN0H4Gek/XOjz/Q6lmQj9vli0eUc6twF3BKMsHBkSb+1tj82nNTBwJP
         ce2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=5RfXJvDmjvocWuhXvJ6jLpYq4JXsjR+fgzQcvxm1L7I=;
        b=l2+6dMrVw0ef2ZZR4df+PZDW2B0oeKW2FQLIE6UnMIHCUCyesWgHFsaAaRz+NIVW76
         CBYT/Bfu5XqG1r1ejatCeq7hRxxe5oQc9WZJmT4pearU+qxb0FRzgSRxjzCm1pSx8O3K
         Zr/ZhZCKz+0I1miM98VcBaiwzA66qPXDm5mSWkl5r8X/cnLbHM0VnU5+M/e7fx/lULLp
         NizCCjnXl3R8TL3yIgiQLyq89raRdGHsSGZkz7FAtsyOTbbIUHwzerFyXgLOoyL0Kf3D
         PMpnng5Gt83ZZjOwg9t6siHb/GXmmtNem/fTEoRf+z/hbVMH+6U+bE+39DJiXiMp7wMx
         YElQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Q8Wbusdg;
       spf=pass (google.com: domain of ousmane.ouanga70@gmail.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=ousmane.ouanga70@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62e.google.com (mail-ej1-x62e.google.com. [2a00:1450:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id n36-20020a05600c502400b003f0608ca743si99527wmr.2.2023.04.13.05.40.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 05:40:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of ousmane.ouanga70@gmail.com designates 2a00:1450:4864:20::62e as permitted sender) client-ip=2a00:1450:4864:20::62e;
Received: by mail-ej1-x62e.google.com with SMTP id dm2so37175450ejc.8
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 05:40:23 -0700 (PDT)
X-Received: by 2002:a17:906:48d1:b0:94a:9f54:5396 with SMTP id
 d17-20020a17090648d100b0094a9f545396mr1146125ejt.11.1681389623257; Thu, 13
 Apr 2023 05:40:23 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:a98:af85:0:b0:1c4:e95f:7b0c with HTTP; Thu, 13 Apr 2023
 05:40:22 -0700 (PDT)
Reply-To: mrs.elizabethedward77@gmail.com
From: "Mrs. Elizabeth Edward" <ousmane.ouanga70@gmail.com>
Date: Thu, 13 Apr 2023 04:40:22 -0800
Message-ID: <CABR31BEymN=2OdfgHfTM9WJEnO6DRbE8gJcX+pRhVxYZFd_yaQ@mail.gmail.com>
Subject: HELLO
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ousmane.ouanga70@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=Q8Wbusdg;       spf=pass
 (google.com: domain of ousmane.ouanga70@gmail.com designates
 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=ousmane.ouanga70@gmail.com;
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

Greetings
Please forgive me for approaching you through this media. I am Mrs.
Elizabeth Edward, 63 years, from the USA, I am childless and I am
suffering from a pro-long critical cancer, my doctors confirmed I may
not live a few months from now as my ill health has defiled all forms
of medical treatment.

Since my days are numbered, I have decided willingly to fulfill my
long-time promise to donate you the sum ($7.000.000.00) million
dollars I inherited from my late husband Mr. Edward Herbart foreign
bank account for charities work of God and there is no risk involved;
it is 100% hitch free & safe because it is my inheritance from late
husband.

If you will be interesting to assist in getting this deposit fund
transfer into your account for charity for the mutual benefit of
orphans and the less privileged project to fulfill my promise before I
die, please let me Know immediately and you will take 50% percent of
the total money for your effort and assistance while 50% of the money
will go to charity project. I will appreciate your utmost
confidentiality as I wait for your reply.
God Bless you,
Mrs. Elizabeth Edward.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABR31BEymN%3D2OdfgHfTM9WJEnO6DRbE8gJcX%2BpRhVxYZFd_yaQ%40mail.gmail.com.
