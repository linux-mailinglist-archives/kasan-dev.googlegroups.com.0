Return-Path: <kasan-dev+bncBDM3P4G7YIARBXPS5GCQMGQEH2RUB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id DB7B539C020
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 21:05:02 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id ot14-20020a17090b3b4eb029016677cc42f4sf8227131pjb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jun 2021 12:05:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622833501; cv=pass;
        d=google.com; s=arc-20160816;
        b=rzwwnHeiz0eZnWP47smQ9HZIyDL7vSHdWhiV8v4qeSIaW2x9E2OlAyn34jkzlbDk8r
         kAM5GEEt+Ra1fr23Jt540AC1S7/43hB1ZJ4CHrkfWTH6nIQKFgik+GmyiwFJEm4pv0gy
         5qcJvjZ9Ht9n1SO3E/gkT5nR8Bl9r4pSg6ChusVX4GxLwQ6bM8WlBlzNd1NPYltMuO5v
         ph4ScXxBm+sycKJ5eS7It9gynOSfBkr3bf2ZAf9Ry6ERc4N7u6+eelTUeU/Sx6Gpc9jY
         6e4uW46Wau31bQ4RRS2ZF5eOMB12mw4yz7RdSNdYLtLy6Tr9TSPm/lpAKS/Et7GYBHpo
         OSWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=KB4Eqdc0i0ISiqkCSxXNYoyBvOoyswSZ07eOaDTV8Dk=;
        b=GGmASMCgWNMi/OTpsp9WMSUMsbWoKbzeLyQxV205KwRV9HqkhEyPNy+IDUwdPlrjEU
         yhfdyrvvfCjy8z9/2I8bNxeqGaI6rrfbUOw0LDdOJ0PHCmvOxwlPOdRKlN9MYlW7B1xS
         77s0yOx5siUHLq/xPU76ojbPod+0a0wxb2JaCc1rnnRodJP/tUB4IXD+9q0orxFk6QLR
         4a4dXcaSDmsDRP2CTkRs41v8eitch4qhFKa+NZTG662yKbRqkBHmUpZsOyRI1Wkajdrj
         Ec0ZnjBWE7HP2tlXwN3TNyX77n5ffAPBFwKFqwhpC5OT9H3ycp1vqkjuMf0wB1Sh7rnC
         Va7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=GYXMeWLy;
       spf=pass (google.com: domain of samclaughlin2323@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KB4Eqdc0i0ISiqkCSxXNYoyBvOoyswSZ07eOaDTV8Dk=;
        b=sa+rAzjYFUZJifBL0HLtNmW/wUhb5JFUqwY6XZbkcPxgpYyhQcjG3JH2pB6VzhQNpw
         ZT8NMy/aGvH2+i4fWWfOAUF1OgImnPBRKaPWrujTuFi2qD+DlIMBKYId5x0CNdJaJCj7
         vB0RHm810qG47kR6JEv8ngRGO1HLdxeL3x3aJuqobQ7cFQxFji2xtBZCHs6A3NFL85op
         BywGEbTsMd/TXtdYpmG9L7QDdrFydtEsMympFNm28vlovt2MwtFMww3cG3c8OQL5SbO4
         o8UK7SJXdhhNvMIPMHGTVOpApJC5KtZCYjgYoN3/ZOTQKDSgGuJutVE8ffr8x93zi6Pd
         4d8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KB4Eqdc0i0ISiqkCSxXNYoyBvOoyswSZ07eOaDTV8Dk=;
        b=mhcSsebwsx9I/yU7GtqLEN+JybjZ62YRCpR9hEdnCFgcSZ51I9B5oCYRaZscmr/2GS
         Mga6TUGo4o0cx8M5aqmj46GXXCzXvWDf/NpmL0BZzXxPQg71RTWnARm1uryItK0cq5w5
         QdOgPXXZ4ZHuN+1tRHh2hl+du59DMNKknmekdGtCNMrPwy1B9/bZ0nsr0KTZXIfDnSVU
         6wNqC43kMu7q3t15hGwsjkKGQKfXtrYHWJH18AWlr63roLYFR3SFIZq2ORM9SdMLTal8
         4g6EKs2JrMXkdakiXZPv+R0fkcBJpeDiANcH7YWodV7X8tphi5eNpzjeFLll0FHZ+bPt
         IYFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KB4Eqdc0i0ISiqkCSxXNYoyBvOoyswSZ07eOaDTV8Dk=;
        b=l8OBbaVNVEl0HLarEFKVFF/8rU+f/COFKkRapOmiLiRZjRRxaOyTtq3kXcvpONF4wq
         R0JZUYLvZTKNeLG3XaVFTbSG4o3t2JnvX9jA0/eEzPsmdK0FO2vEWAShhuctrJ1oOow4
         IzWVcy6t3y9OR9BPHTkmvglvcALqPao8x2C01w6a+3fM1ZhQD1f0oRGv2Ah3Xq5a5FNz
         VsbdfREIFRG1GNCeJQniRcaHta5JbX3SYDcEszfuvKbFKH9i6jxxE7jgTB6QJhYykMgE
         oLcnVd96altAdmhdK/gvH64/wg7+UfBX+nwqmqnvEW4yTjMzsuwQugsb/NfKwOTKmxIU
         aulw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pPk1YhfNBU+OHpiNO33ccnTVsq1SzcIplsxfOZsWOXaUVOJF/
	vkKiEmS0Vktd1p4X5YfQ6Co=
X-Google-Smtp-Source: ABdhPJxtHmwsh6dyDgn0UHf9RygW54svsU0vnpcDiegeBAjE6by05LxFcR2FrzfXIan15eVi+nb78Q==
X-Received: by 2002:a63:5c4e:: with SMTP id n14mr6458849pgm.192.1622833501520;
        Fri, 04 Jun 2021 12:05:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:fb0e:: with SMTP id x14ls3680178pfm.10.gmail; Fri, 04
 Jun 2021 12:05:01 -0700 (PDT)
X-Received: by 2002:a63:1a4f:: with SMTP id a15mr6397664pgm.136.1622833501009;
        Fri, 04 Jun 2021 12:05:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622833501; cv=none;
        d=google.com; s=arc-20160816;
        b=Wa5J4Z52CMYRhLqyNY0/Mq4fcUJ2rCjXdMAQovFGO3OiER4gdq49rKQEL0BBCWXkqx
         zn7B9tU7BnlsMj9SmVdJL0OLikas/fqmeyn9+mWjc9LZZ+8kr2+BTNaiOB0On/ELqFZq
         WfSjbBtGW0Dn74WIvqGpk1SyRtnVFoChlrB+Mhc/Up4Zaum6Jl/2qZTcVBvJDns6CUHq
         egasnT+4b+l33dDqvG88GaB41gwEmE3NYzw12jhtLFrMRTT9UmX9313NY3VxicdGjgEF
         7mjQyKUafZ71adlhAvzWIq52wWW0nEwtw/yyPoXSXZts4pJ+7CDqVkrnyqazQe9lU1T8
         ereQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=2nETW4+U25qGb76Y6En5wf8+6pJcKpxgItpFX6FPlKU=;
        b=Hr43cPwdjmE0BGU/P5PThZVde4HiEdKj1D9MCRstuZqPNQBdTlmgjP+Tr4n8xrilxH
         1RpdR+uuF34Kry1rFgD5irJi5FTvvniMo3LXZECAXVdsxb+MFVkmUhI+xu+ITvYrNyfK
         6zxxrfODCCp2xVvzU44yUvWLgKAEL/gcqdFYNHKEpvm8EehZBFl3E03fwkVd7TVqwPaQ
         1MgBv7145KzzUFIsYveRLxqsUd4ttzcpeewdF3KBDdLMnsLFkD0dnXluMbGX+h4YqrD7
         5O5TPZj8gXVKZNiWyghDcMDo2CIpcE7toYXEK8FKxnCTL18KBaYPSWDEYQ4siHeKk8tS
         bE2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=GYXMeWLy;
       spf=pass (google.com: domain of samclaughlin2323@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id k78si277449pfd.5.2021.06.04.12.05.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jun 2021 12:05:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of samclaughlin2323@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id s107so15138754ybi.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Jun 2021 12:05:00 -0700 (PDT)
X-Received: by 2002:a25:ccd2:: with SMTP id l201mr7394858ybf.35.1622833500111;
 Fri, 04 Jun 2021 12:05:00 -0700 (PDT)
MIME-Version: 1.0
From: Santiagoht Mclaughlin <samclaughlin2323@gmail.com>
Date: Fri, 4 Jun 2021 12:04:48 -0700
Message-ID: <CAHJyeeauQsonCqq9uOG4FMVdsf5Zr3efUcm684Dg3UxbpEvzBg@mail.gmail.com>
Subject: 
To: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="0000000000004dc50305c3f55e56"
X-Original-Sender: samclaughlin2323@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=GYXMeWLy;       spf=pass
 (google.com: domain of samclaughlin2323@gmail.com designates
 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=samclaughlin2323@gmail.com;
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

--0000000000004dc50305c3f55e56
Content-Type: text/plain; charset="UTF-8"

treygtrewytreytgwerhbryebtherbthreterb the rtniseb treeeetretrejktforrjetre-

re\terjtbretbrhtrbithtrehbteh tebaeh tr euyterht erwt wertand ert
erbtverthet er eyoutret]]]
grejthtorebtIrebteistrteugforthuerbtuhbethtjh;ittehtierhtuhe
]rehnhjerjtbert retrbetrehr9ehkrn,n

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHJyeeauQsonCqq9uOG4FMVdsf5Zr3efUcm684Dg3UxbpEvzBg%40mail.gmail.com.

--0000000000004dc50305c3f55e56
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">treygtrewytreytgwerhbryebtherbthreterb the rtniseb treeeet=
retrejktforrjetre-<div><br></div><div>re\terjtbretbrhtrbithtrehbteh tebaeh =
tr euyterht erwt wertand ert erbtverthet er eyoutret]]]</div><div>grejthtor=
ebtIrebteistrteugforthuerbtuhbethtjh;ittehtierhtuhe</div><div>]rehnhjerjtbe=
rt retrbetrehr9ehkrn,n=C2=A0</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHJyeeauQsonCqq9uOG4FMVdsf5Zr3efUcm684Dg3UxbpEvzBg%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAHJyeeauQsonCqq9uOG4FMVdsf5Zr3efUcm684Dg3UxbpEvzBg=
%40mail.gmail.com</a>.<br />

--0000000000004dc50305c3f55e56--
