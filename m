Return-Path: <kasan-dev+bncBDC6JPM7YQIRBHWX6KFQMGQERXN77TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C87AE4406E7
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Oct 2021 04:19:10 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id b133-20020a1c808b000000b0032cdd691994sf1682854wmd.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Oct 2021 19:19:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635560350; cv=pass;
        d=google.com; s=arc-20160816;
        b=JAKVl2XHLRRYYjFTwVDs7GDknfEh0g8MqJIFQnEUwIh/UpIr6qREKtC/F/ud6CwxaO
         ZEoLdTvfNFSGdvTuyrXhG43bG6hObW7oGDw5yV0J5ImXQo+wdyRHK6Vya5AI9W2EKLgR
         BAnA/n/n8OMJ422IyJ7frKCHWSPed2pGLPYviFHMqxxLrxdK0aig7FCM5Qdc8108Nnum
         nBRWmSR5Rkrsyho93Vl1COg5SyKZg+2v1jpFhydEm2J3tOuocHS58sNVn0gZD2ZOUJa6
         9DO74tu1WcL9LWFvzLj+JEQLkhl4yECsfLVKKoixc4xHDtX2IZgg4qlim8Z11ZDIalXo
         QNEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=PUe47S7pjjeEw48aC5oWacWw+OLBJ1yoZnPM3DMEpBI=;
        b=mtcCdQTfjE90aQIH9sQGz8Lbf9OEwxRQumopF01Z3k6IgWOBSaGYFMLo6InGJi0ORz
         VgeZ95KyVpveEi9e8XP8uod8UoRAFr+HyALrbWkJrK7s5tstasCTvv5+28MrcWiH8z/B
         RoIZLl3MfkQuDluyyL7qeu7/55EZ3efx8ejVDNkjGJ1OaJgvpUDwQiN4j4jfSGcigXgi
         QfxJJ3tshiKJ2LkqSG0c7UdKZr33tk8yldGS1f1bb5emTESH/CNhYDSIgI/UYsm8tZw1
         dHWsVxzQy+EAZmAT44kr/btoS0WIp8H93En24xe/MtLkQzSaZ3Fw6mE4k+1wDCuaekjQ
         b2Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=evPD3m7J;
       spf=pass (google.com: domain of demirkol.chambers0001@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=demirkol.chambers0001@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUe47S7pjjeEw48aC5oWacWw+OLBJ1yoZnPM3DMEpBI=;
        b=d+wnnLCM6YxNh9qailNjA/p7eJWmBigubfEnodXArMVL+SIRmbwdngy6weOvdsVejQ
         Txd8ltyO/KwrYd19cMQ6m2jfxeCp6TpOavw1WYUKm+OIRZxB1M+NT31VpD2UJDn7VMzJ
         G8PiUt8MAG0ezpL4KSYslPQMhvVfFfKlJcMVGsPl6/3ngjmbj7CIAiTy19dSJVnOG2ld
         q+viDeCXrFaYV2+o0c7fmmoEFClfgcuGjwTRT/f9SGkOL2Wa22fDhMegKel/lyN4m1EF
         +vZc8p95/ibNv6fxdpIXvI0EzxkWO/vsHlXwb9LCJM5e9fudCIpst1vXGmpH60w4Zszs
         FKoA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUe47S7pjjeEw48aC5oWacWw+OLBJ1yoZnPM3DMEpBI=;
        b=l1NZwn5eBINrcQ1g7qaDHJ1PuOYgw7hw5xKl90VdyZc/m1ZtVn51UVdbStWco91dPf
         79DZxddEZXV69E4RiWusrWx3Cg0ZuUKXlpZ0yuQrR7/0V6OPx2sOuqVlYUQmpdHI7RAK
         EstMxsbqrHUSpFt4QRFg1JiSGZUCoI93wFb0aMT71xUrW+FHDgiesj+yUs9hp19sXxgM
         6Fejoq4HBrwwiUOmd2Q7oIW3zfwcn20qxZFBPRGCSbQRy5GPE2NlBF2avqq302wi8bi5
         Hdu1pNLczY+mm/Y25vU9uR3nrvLnlxcpts0CWUJNOc23KMz1YclV4AmZAlKuulrp9m9e
         bnxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUe47S7pjjeEw48aC5oWacWw+OLBJ1yoZnPM3DMEpBI=;
        b=ntReOMnP3ejt/2IXyxmeI4Z+3O3LB3dFrQ3EoVmPFeDbzGAyTc3fRsEMJk+8DC62DU
         eqUK3Dv6EtVm/rmZOpPAwjOjYvfi9KPA6XMMpdRNQC8Yrw2aYvJLiGs11Syw3uhD5b+h
         yyM4BS5qKOrOZJGgUdYeDLXAbOGAp1+Y1Xo2ASLc1fOI0F+4/Oiegm457pMcm2zlOiCc
         HFnotY3tI6eAWBzKPIkHX/CaanvfxkkIUVmsemwGywK1sr5dNYDUlmvp4I+ZxLC9q5Ng
         bdxR3b8xi5lU6QcAqgMhAcosgZeWp5XVgdHRWk4ifCC2/WJvRlK8IjgI/iA5dTRdcC8o
         /6cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312iUH2eca7sb7pB1R+i1gVhgwS6t6OEXGXSxk0AIB6Y9X6e6ce
	IfkgftH0zIkPe5fXLyBUnf4=
X-Google-Smtp-Source: ABdhPJwOyzVapwIAZ/mImk9gT5mGk9Ion+PCPwIUigpgym6+VGrO11WMwdHW8q2MNAjpO6aU10x3KQ==
X-Received: by 2002:adf:f744:: with SMTP id z4mr18914071wrp.17.1635560350541;
        Fri, 29 Oct 2021 19:19:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5111:: with SMTP id o17ls1022477wms.3.gmail; Fri,
 29 Oct 2021 19:19:09 -0700 (PDT)
X-Received: by 2002:a7b:cf18:: with SMTP id l24mr15143338wmg.39.1635560349649;
        Fri, 29 Oct 2021 19:19:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635560349; cv=none;
        d=google.com; s=arc-20160816;
        b=hsSLtDjxJGBQFFbBuCHn3LtDvYdc9Nw/5gOFyB2MNcC8gSjnXrM7cMSfHRL/3ymduq
         t9A2NArQ7Cy1q1SHNxIH/I+nHHOxlzRRRrOrrbPWTOzq+pYkh70h6LFZ3Ymp0LetboBw
         6G2LNM7sbqwP1hwWzoy4asjgusBRxi3sYubRsdjSr5J7O5SXJrht+ZC+twSpdQmXImSz
         CSJMrhq1lhdELpKkDo4FjpOrKuV3IiFJ3ukqu0zYvDAgayOPNZ3Zg/fO9/1tEu2bfoSL
         24oZzDvGK1Dy4F5xpgu3Xx1UzxDuHNPkPFFhn090Rfm02GWxLXdfxBar7YLyFz9YOpTl
         3Y6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=FbjPR/D2UA++NETcsSOGiYmuH4yEEM1ejZTcmzMHQMm21XdNAVl4X6yKmxEdtGsGnX
         dtT3jurKTaXCFJOTPP8yX9JhHpawG8qawfB0z7k9JQ55jAhkWf/x3IJUNo+9aUmGgDm9
         CPa8kOm+kMw/Nvk4lHQ3xcEn6rZ5WI/INMGcwodKA/EMcCvmVqUGd3Qjr+d9qn/GARkm
         qagAe8JKib0noR5YnkRBkCV5nVo4rD7S+hjS1WDsxa56F8Mqf3bRvFstS2S7HA1Zdo3J
         RK6gRisBeKvzzLcwDFkiUy2d9EMSbQF1KbW7NnlJJtqfj6kuFhrlGSxmlNsxpPJ/Iu+F
         usmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=evPD3m7J;
       spf=pass (google.com: domain of demirkol.chambers0001@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=demirkol.chambers0001@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id l9si699565wmh.3.2021.10.29.19.19.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Oct 2021 19:19:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of demirkol.chambers0001@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id d23so18389992ljj.10
        for <kasan-dev@googlegroups.com>; Fri, 29 Oct 2021 19:19:09 -0700 (PDT)
X-Received: by 2002:a2e:944e:: with SMTP id o14mr15392214ljh.464.1635560349187;
 Fri, 29 Oct 2021 19:19:09 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:a05:6512:398d:0:0:0:0 with HTTP; Fri, 29 Oct 2021 19:19:08
 -0700 (PDT)
Reply-To: demirkol.m.sadik@gmail.com
From: "Demirkol M. Sadik. " <demirkol.chambers0001@gmail.com>
Date: Sat, 30 Oct 2021 03:19:08 +0100
Message-ID: <CAHxH=9B8n9nsVbeg8TJwLOZdKv2629brAZaZ5i1R-q9dctTPrQ@mail.gmail.com>
Subject: Hello. Please I was wondering if you got a chance to review my
 previous email. Thank you.
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: demirkol.chambers0001@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=evPD3m7J;       spf=pass
 (google.com: domain of demirkol.chambers0001@gmail.com designates
 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=demirkol.chambers0001@gmail.com;
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



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHxH%3D9B8n9nsVbeg8TJwLOZdKv2629brAZaZ5i1R-q9dctTPrQ%40mail.gmail.com.
