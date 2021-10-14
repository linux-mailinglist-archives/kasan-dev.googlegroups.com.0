Return-Path: <kasan-dev+bncBCCMFI6L4MMBBPVAUCFQMGQEH4HU4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F3BB542D7D5
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 13:10:54 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id s18-20020adfbc12000000b00160b2d4d5ebsf4309990wrg.7
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 04:10:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634209854; cv=pass;
        d=google.com; s=arc-20160816;
        b=uvD9+G3za9mePIahn3Eg0IPZW7vbN0ThtnS1G0ElskVZ/42EJ9ZxeTrTfwOW0dOeVI
         IHVmunrFmWJliy3DzMwgg9QgxLxBKDCyxk+4tzwpOKVWbNGoD4SJcqm55Y9ud+IJB/C4
         kozb3yliGxCjh4wpcJ9A25hzt9IAaAkIvTt/MRW6huRD2H6NgZfyGWzZVsuq8QoQQJBl
         9Z4eNrGfB1naP0GlZXRBogRnXaeCHPcdrJK4dBAKTu7fdkdOaUCCyOyliY+p/eMD3P/p
         sJX+WytJZlkxQ4vLpjyXEkulCgu9oc+6Oh0WZuzYjDamcYXFNJMmZpNyqtmKth6YWsWO
         R8xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :sender:mime-version:dkim-signature;
        bh=pszPHNuuZfsLpLCAPFY4JNgpDIKZkWn6OCzzFxzcgVk=;
        b=YWksRkCkTyeaZXOAgCp257Z/LlYaEbksQ+Wuz2QSQTNK5TZy/3aoMEaajhC82sQRwd
         BlunvwCtus/OH1qzLpfZZ9+Kl8RB77/qvLYjdfC3sCzVgSRS7vCuxv1wK27ZKtRkCb0Y
         HQe9KuCrhQOl2BWhLHATUXq7DYOguWFM6yanjFCPdWbFSyGhKHDl8TVwCYFiB21Llno6
         deXUcmqRsuZeHOwWxqwY+Y40RmIooomhwgBnuXbFX8LY1zk/xNOD2t2ltAEriFNyk92q
         fqR3dD3Sjg6YaVrGUy0qeQfEcoG5qL0Agfss4OWojHXOQH6E+8v7Ra8zxyA9f8vLBuWT
         8fiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IIvZ9En2;
       spf=pass (google.com: domain of florencelornalaboso@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=florencelornalaboso@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:sender:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pszPHNuuZfsLpLCAPFY4JNgpDIKZkWn6OCzzFxzcgVk=;
        b=liYMI7oErhOvPxCHzSIg4e7ZuKzm6yaBOopn3bNHl/TZB3IvlEJH6PaoWzebfn9454
         /LPOtr11lYk9BpLcJh9lp5I6E8FOIAF1SW2ecwIWam7997CN1PbkmUl6H1bk9agRdGNk
         2M0k410pQgUGT7GYDn1uNANyCVI2WFUSGOXteoSeR0XwWPhV2QBC13fmK3P4Y0CBade2
         B8b6Gen2lQ450yXZowwIlJfxUdtoLK2SlzI7cyhe2ULjaJ9kwRRiPOG2RONGGDl/YqYG
         0oNAGqZhgi0NNe7nGOE3M5lMdY3OkwXIw7I4ItyRGVEaN+IR3hER5TccMp+9+MMfGswq
         0uCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:sender:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pszPHNuuZfsLpLCAPFY4JNgpDIKZkWn6OCzzFxzcgVk=;
        b=N2xDoDrnFWkmPqcBuLdGHF/kvXEsNoKzSSdjAnE1tKeFHqmaRYTp88K/AQ0QP/io7L
         xEqRUqyCDXyNfNGRwlhLjquq8UBzex1VQFo6WUr+TnP3vWyY6QBfdzFrxMRmRVaNNg+V
         2UQOEE+HEf1alduBBlg/NT7UAjr59I4nzl0QS8KQKhZDRwzqqKN3LlnHQKQ3jj7lMjhF
         e1VPeSjTR36fZRr0u6Pcal6CNUi35hUaS/54+Zbpi7Jy/3D0kMpF97K6+bIlMmgnqip2
         OemYsDp9VFob68x9gi9fjZ51v24ZL+6iqPhqxMopa5zkgPUyyw+mK+mbfPUdh1+NNL90
         DctQ==
X-Gm-Message-State: AOAM53314D5hyJzOXpgVrDY5otmDxGdlMQ2bLCNBcCINqzgkP9z8kKUt
	Xm75CEEBMUuZDSDBymSmlAw=
X-Google-Smtp-Source: ABdhPJxsYmI9J6Y7asDhVUJYXs5kovx6CH8k1zrqTNYx2sxr9knvKfCMVTQ5Cxv+XZCbWoXGG3j3Fw==
X-Received: by 2002:a1c:2282:: with SMTP id i124mr4896201wmi.164.1634209854732;
        Thu, 14 Oct 2021 04:10:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1caa:: with SMTP id k42ls4606779wms.3.canary-gmail;
 Thu, 14 Oct 2021 04:10:53 -0700 (PDT)
X-Received: by 2002:a1c:2b04:: with SMTP id r4mr13514087wmr.48.1634209853752;
        Thu, 14 Oct 2021 04:10:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634209853; cv=none;
        d=google.com; s=arc-20160816;
        b=Qe8GKMr4QFqntdOeC2nuoxODVqIIi5KWxHHwN2fMwRT312071NzBCDpzz6Iao9atvI
         jWeDNzrxKDNi4XRWIupV8OVariKlWVZHyPgaNRJLXAjDpk0P1jPEIJIxgSW7Kq4t3X2k
         4SdT1eC4A5ovPUECUha9DU4w2e9zG5xL9FsETGdx7WpGRAyRK6tkBJ5pDMpxj9kmY286
         fqeGzNNOQqFXyw/u1TDH34VET6o0bHgRrxLJf+addT6E/AG8uVdD1pwBH/ndyaDwwpLy
         PuRATo9ZX43Aif0OAQL3QYXiUAOpPLTj7XFEnK367evuMlYbL6j/qexQ2L0iiKrDdT6J
         0tUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:sender:mime-version:dkim-signature;
        bh=DjPUUn1axG7nGncHfesfsKT8SZCMIwt1jz58EwcASzE=;
        b=RG8ERW29RhUY0vBlZ6U8bl+OBDpr2qFgDNpoA/iqCRB7qIJWHRoIpO0eSAZFCa2IxA
         mvlT4/WkN4uv0BNbZmIv7IVXA1zOltPHQx7qKeM0tg3SJERDyS8e6mPG3BxA2/Z7/sva
         s6vGM9Sq7fg3vB2qZHTQEttVmg0i6rA4iKKliDJo95ycm6CHg7rzj/xC60Rq2YXNWOPq
         UhiIPW2xFu5+H7mPxKMah5N59g6eo69CKkkibI2IuLZsiYLEDXz0JYVJNdF0ZIbOGmev
         LqVt8WKPzvn3XKIBYFXu4Zpap6c/+k8UkCws08N8RRKMXEivWzmgw3w21x1a+UOZ8cKC
         DV1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IIvZ9En2;
       spf=pass (google.com: domain of florencelornalaboso@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=florencelornalaboso@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id a10si165147wmb.0.2021.10.14.04.10.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Oct 2021 04:10:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of florencelornalaboso@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id p16so25454262lfa.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Oct 2021 04:10:53 -0700 (PDT)
X-Received: by 2002:a05:6512:e96:: with SMTP id bi22mr4452412lfb.156.1634209853207;
 Thu, 14 Oct 2021 04:10:53 -0700 (PDT)
MIME-Version: 1.0
Sender: florencelornalaboso@gmail.com
Received: by 2002:ab3:6209:0:0:0:0:0 with HTTP; Thu, 14 Oct 2021 04:10:52
 -0700 (PDT)
From: Natacha Wesa <natachawesa@gmail.com>
Date: Thu, 14 Oct 2021 17:40:52 +0630
Message-ID: <CALZBHgGYAjxdXoU-uEGY+AgvJhPWC28vXOaBaRb_iV6vkEtCtw@mail.gmail.com>
Subject: Hello friend,
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: natachawesa@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=IIvZ9En2;       spf=pass
 (google.com: domain of florencelornalaboso@gmail.com designates
 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=florencelornalaboso@gmail.com;
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

Hello friend,

My name is Natacha Wesa, and I am 29 years old, and I  used to live in
New York, USA. I am so sorry for using this medium and this
circumstance to contact you, but I have something very relevant and
tangible to disclose to you. I know that we have never met but God
cannot mislead me on this since He directed me to you, and I want you
know that whatsoever you will read here is 100% true.

My late husband was a boat and yacht dealer and he made a huge amount
of money during the past years. Early 2020 he flew to Italy for a
business deal and on reaching Italy was when the Corona Virus pandemic
was rising, after his business deal and he was about flying back to
USA he was examined and tested positive for Corona Virus. He was put
in an Isolation camp where he died after 2 months.

Now he has a sum of $ 3,750,000.00 deposited in a private and reliable
bank, and due to my situation here in New York, USA then, My husband's
brothers and sisters are doing everything possible to find the
location of this fund which they know that I am the only person who
knows the location of the fund, they have tapped my phone and fax
number for any external communication that will lead to the money, and
if they eventually find the location of the money they will kill me
and my only son, because they are wicked and now I cannot discuss this
on direct phone call except WhatsApp which is more secured for now.

I will send to you the contact of the bank where this money is
deposited so that you will contact them on my behalf, and before then
I will send to the bank a LETTER OF NOMINATION / AUTHORIZATION on your
behalf as my foreign partner. You will contact the bank and they will
transfer this fund to you and you will send to me some reasonable
amount of money to prepare my traveling documents with my son and fly
to your country while we discuss on the modalities of how and where to
invest the money in, and I promise to give you 15% of this money if
you do this for me and my son. I know this might sound like unreal but
I want you to never doubt my proposal and I know that God has plans
for us . I know this might sound like a difficult task but there is
nothing impossible for God to do. I want you to also know that this
transaction is 100% risk free.

Please I await your response as you as you receive this message to
enable me send across to you my bank contact details for you to
contact them immediately before my late husband's family kill me.
Please also keep this transacting confidential and secret from anyone
around you. contact me with my email (natachawesa@gmail.com).

God bless and keep you safe.

God bless you
Natacha

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALZBHgGYAjxdXoU-uEGY%2BAgvJhPWC28vXOaBaRb_iV6vkEtCtw%40mail.gmail.com.
