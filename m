Return-Path: <kasan-dev+bncBAABBOVHSOVQMGQEYZTHDUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BD5717FA830
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 18:36:59 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1f9f561ba4csf4207109fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 09:36:59 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1701106618; cv=pass;
        d=google.com; s=arc-20160816;
        b=VW769KI409WAQvTkvfEcwP+f0Yt6CLCiW6AmBTIuSMvCxbWH7vYO1vGxh6Yu+WmBhA
         eJQ+4/hR1i6Vh5xLDMuKfcS+qLBcJHE4PygeQYQwP1L0VqaeJ4Mnl2XLoz513vZEef+U
         iJFIG+ahlcI6RnPMz2ijc1Sm4HE2v1NqCW5cfKCG9iJcAxpKH7Y/1xD17kqunyrIXBK4
         /NzE/itSqb+9sSE08XMW3c3fWIwJKaqUavU/CipDfqSWgzusO8Swi1r3uRJO57BVfhRf
         XFfC4od0qUkQwhSVShhiQiZgzqCKzloj8Bnx64PWk8uRN1QcG37UvefppPY0PGTS1vHn
         30tA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=kwz1JpHEWUi9a5Loq9/MbX/7n4ASiGhS97cLZ93fr48=;
        fh=jbVJpa6y1kFfVaEzIZIbFuVdgktfCZfUyP5Q8nXqkFQ=;
        b=mzP+9YCQedvKTSfMKXg6SRDdvMhGDZ3sl7yXQ2AuWKuucjc+IaleaVB4iYYqXFxrGJ
         bf5WgnGOt3ZlMOPKvYCdy/Xy+qegHjf7n1WhDFg5YnVyuoC0WklylbpgSPgxY1oSHciW
         YoUpQUE/AlIbJ19LtdBOxrokMhF3gXI86TZUXj2fbq9BkajFO8sthWcdVU9FqsM937+7
         XztB1Rwt5ZfptF+E9eA2AM6XqPGRJf/uCTpgEkAnRDuGePezKk9AmIliti1jKTSkRBP3
         F+NMiTd14uzoNrCBzVzhtS84ait/xvXHJPXcAfkWQmCBad4DeEMlNCUBRVu0qRXW35Mm
         tHfw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=DdzbBpVo;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::828 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701106618; x=1701711418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :subject:user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kwz1JpHEWUi9a5Loq9/MbX/7n4ASiGhS97cLZ93fr48=;
        b=H7CljQiN86E1lP/+aih0E7e6LLXai8yA/pTVOHrUv4MoF5da1+EEPS2TKy7pdZe0kp
         zim0NAcOicQGljO4Ve6q8KYrolgmk1eBvMX8Br9nK1jY3Ap8YOCy8NYA85p3v9uNf9i5
         JFLyQcOhx+Mg4fWHQUq+Xku7uxQxanFV3nbjwYF0jVm0/+K+XxeZ1/xk9lFoEsQaIItV
         Vbz7EPAFUZPeS40vPX71RmXEVLeyjEkQOK8HBuInYWH0inrS46DaSzNB/M4+toRmtc3y
         TVE70vl37KkN6mjrm1jzpru1xkmpwx+8Kl/O0b/tFOZa9dJsr4LON2M5oOTpDhSP/86Y
         bPcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701106618; x=1701711418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kwz1JpHEWUi9a5Loq9/MbX/7n4ASiGhS97cLZ93fr48=;
        b=SK+aTkxkI6ClgHH/Q+BdO2c1wVz91vV/WQ6TW3ID7jVkZ/z8KTUh4lhvG7NaNT1utG
         eJ7UkS2J/kvM6cf+g4g9EKqsJZ9KCzomOd3zB9UkPBy0gWuRfNkytVXKSWizmQdS8QKb
         j/ugVEwaR+C+tOiYcQTiw4i54qxAFFciPD/pKmTMhfDxGIFwJxTEYHCvQAhUvD2EW+Gx
         mWRFD5FD9MXVCSXk8XIz9mTk/XvZ+mcUIRW75RXZuvpgmBU1YFs22AbCWNl76xYc7sjJ
         6YLSnMahpjtJsj+YamkXiXZKIWp/AUi5OGYXHBu0cl/JR2gx17MuWlJjDtX9SvOGHfow
         Ih/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxm72qvw8NH/SEMCFVdLiwsTwGKXuaxWYGo1kmUej7HuYoGbwoy
	nmihy/Uj58KgeNXH0n/bX7A=
X-Google-Smtp-Source: AGHT+IHShEbnJWuZFUnvUQ6rCLEIpI9dNV8R236pAzq1llcAnxKr5+QCTABMDhVwJwfd4E+gc0wy/Q==
X-Received: by 2002:a05:6870:1e8f:b0:1fa:1fa9:f2db with SMTP id pb15-20020a0568701e8f00b001fa1fa9f2dbmr14398413oab.21.1701106618359;
        Mon, 27 Nov 2023 09:36:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ab15:b0:1fa:2603:b5fd with SMTP id
 gu21-20020a056870ab1500b001fa2603b5fdls487599oab.2.-pod-prod-01-us; Mon, 27
 Nov 2023 09:36:58 -0800 (PST)
X-Received: by 2002:a05:6870:9f87:b0:1f5:994:9853 with SMTP id xm7-20020a0568709f8700b001f509949853mr17990672oab.22.1701106617855;
        Mon, 27 Nov 2023 09:36:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701106617; cv=pass;
        d=google.com; s=arc-20160816;
        b=ptq9jNeRezpCTUOe4ijHDftIHnH6a7c6DKGaGTwsoCChY+35GfIUB42IEJmEAaw4IG
         5RvM4OkYmpBgM+uclC38MLpIyrID88U5fybLJ9s+u5w1RcEqmaNBens+QNL+GL061M4/
         pX6jTZHTKgrfT91QyJ2PHbmiGvVNLOfltH8ZSSP5HkCqXqo8+fUfjU5hT+3Xf2ynidBf
         WyIDyNUebQ/8qUgUdBtTd5E64iCKy0GTiHwjK7pwU8+1ZQNwW5vnnXdGkzMBwNA0Hyoq
         UY5//ZSfqYtUQZPqZhCx6bF+Qp2cVo/HPhIz14f+67kNAPJskG1q4jQ6NWc7hzqlCXdL
         TMMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=hKhQnC4FfGM11h1OfvjDehUSpO6gPJ4z7NsVFLHDQG8=;
        fh=jbVJpa6y1kFfVaEzIZIbFuVdgktfCZfUyP5Q8nXqkFQ=;
        b=HN4+F4CF85PG/aKU3CD+uicj+cEAsUlAYymziQ3JTQfMHKrtECZWN3PEuGH5itKCDg
         +oPtpb8+HXg5SxvjvWKaAuErdwvJ+mOSqIibgiRkd3wGEpi45Z0Vs3vH/AVEkXjo8941
         3EJWAty9z1TaxtMjdv4ROQYxgZRTfZEUyJWoATpNLRI/+F/yUIE5dxkX8bTk5M6SrPUA
         83Bc/YIFe5Nv7m8Rtdtu0QlN47J1VB9aYlI2mviQlKiOL6OCeuyHJumH5PcHKkexJMbA
         OjunHAc55IpkuaiPXdev+I4ANgVbHEDONOCwpwal22WRgavcsechKV207iJ+CVAk27wx
         o20Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=DdzbBpVo;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::828 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05olkn20828.outbound.protection.outlook.com. [2a01:111:f400:7e1b::828])
        by gmr-mx.google.com with ESMTPS id jd4-20020a0568702a4400b001fa3b060d68si1054002oab.2.2023.11.27.09.36.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Nov 2023 09:36:57 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::828 as permitted sender) client-ip=2a01:111:f400:7e1b::828;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ekNi5v4fKa5poQXatde8b2z2eUDAQEhlWhtnpac+KUcAtVM8VvfiAOIIQ2daSa7dJ1RuipYClVBwOwN9ymV/+bMegjTdIfpkCNRVT4p7xjXJlpWBaMIpgibhQnPKAG4r6+4ebZP+RM4CFRrLo46IpDfcvGg3Hu8C2vujRbgpAkalnQ0RuPLwfwp0UZJ8s1LxWJfd1hOtDPaTrOW2DMXQ3Li5bO8SwZQY0vjhcmOzbStCvgDFqUAr8gn2uoNW2O07I0Dn7x9r2gPv/3aiyLbiv8iHoOhDSm2GCfxhp4JGhe0oVVty/2cUoUpcCzug0baxMdklpDCdbqE0WWOxKSbdQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hKhQnC4FfGM11h1OfvjDehUSpO6gPJ4z7NsVFLHDQG8=;
 b=VB31Fzr5y3ztLWXSTdBKxGR5s/Ry+PsWCFdJm8mo3JLm44JTNMEB1ywC8/p5Ao/cXmtuTiDdBBcmBQZ0x1+JBWHWGADDcqYQfJMxg2KDv9CdmSapbsqHGVHCrDHgSWl/CYAA+DNCjPMZqei8neJFujc1JMye4I64fNEZmG++8qP1oEywdCOVHiRp0Z2nc+Cchl4lO/xRaUrttASzLNN+JHL6BTcZxdwebWVNi8R4HcmUnuPW4cIs/LiMxg1aZ0+qAunwZBVHfPwtyFB7gkFKibzjBzL9kWeH7ezthHerAeen3CFhuHLrodg6PT6KWd3xpWLrqNP2EQTj1DVJZ2XGRA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by PAXP193MB1389.EURP193.PROD.OUTLOOK.COM (2603:10a6:102:13d::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.27; Mon, 27 Nov
 2023 17:36:55 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.022; Mon, 27 Nov 2023
 17:36:55 +0000
Message-ID: <VI1P193MB0752B1A233DACC44EEC7FB8199BDA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Tue, 28 Nov 2023 01:36:54 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: Record and report more information
To: Dmitry Vyukov <dvyukov@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-kernel-mentees@lists.linuxfoundation.org
References: <VI1P193MB07529BC28E5B333A8526BEBD99BEA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+aVjKTxTamnybC9gS7uvSodYjvHst9obo=GjJ_km-_pdw@mail.gmail.com>
 <VI1P193MB0752C5B781EC2A351EDF62CC99BDA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+YDnXD3SeordJ8X6tQO+7nr5VuWVrJ-DUi3BXac0zdVxw@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CACT4Y+YDnXD3SeordJ8X6tQO+7nr5VuWVrJ-DUi3BXac0zdVxw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [ChjgQRLRLD84fLTyN4mpH6+bc1bxKGRB]
X-ClientProxiedBy: LO4P265CA0011.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2ad::19) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <b764f1d2-1546-4e36-8061-5b6c3987ae50@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|PAXP193MB1389:EE_
X-MS-Office365-Filtering-Correlation-Id: 3c7d07af-8826-4b03-fb5f-08dbef6f72fe
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: EmXJgjGakWI9rfg30GvarQspeDZ9TATdhXW+1u4Q5B38E8hPUdSHmmQLI/vlKYBMT9aszxmegAgujlp4+qFOVieEDkGl3LbcDQZECGDQnGeWyuz4uFp431GMMAA5zJp+qcdmYLWAF+N60PRZ8blkQiFH/5cNF8P7153148cIJAXUP6CcACY25sC1zXczTYnz1vkWu94CF69av77dXFV6MJcIcReAY6xzv9h6r1MiaFviqMtpYPOrRxmxX6P8K94/CxXSh418UutdhHQqGRqzeZ7R9kVq2UjwyR079w1foFx8tM0BMwC6b+EX8uihHNNAkiV4l5R+8sajmqsn3v6Fz/AtRt4e9kGXOZ+sOJ1b3Yx2y2iClcsiMdNM62lfO5Y70FDGZVXwUDEQDd0ju6LbAjCQQM2leP+GSUBm21oTBXIuPhzc+kfvyNwFJag5gJDg22/DB18w9/8qxyYMafb52aED/ry0/Niu6im2cMp7698G+7nsTRn5rr26pJLbm7VSZq97k192b2EdsAQvuR900bcuJWhKcnYLFBAC1CIIzWjMOUPQRYRd8FFuL345joEF
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?OHk2VzRaMklLTGpJeFV5aEx6cmc1Z1ErOUVWdkp4VWl6UFZJWVhWVDhyU1Bq?=
 =?utf-8?B?Z2ZiRUozdGlVZ1luOEFUaUdJc1JJbzlDMW5vQkQrb24yMEFnVVY1ZkRiRnA4?=
 =?utf-8?B?Z2xxK2pST1l1TW9ndzZ2OHV5bGJ6dExjTUZ2TFdwN1dkWTR6TmJOTjJSbTZh?=
 =?utf-8?B?bDhDK1ZOdEdZQ3Q3MWxFclJhWDFtT2V4bzRuQmZpc3JwVm13cHl2RHIvUTVT?=
 =?utf-8?B?SUVnR1BPV2JYb1RURkhwS0N6TXdud0o1YVNHUzJpaTZndEFhSVcwQiszNFJ6?=
 =?utf-8?B?U3FpNE5ya2RacWhjQ0srdFAza2Qvei9ENTgzaXdyM0RXeHkwb1kyUjgrcTBj?=
 =?utf-8?B?NnE3S1RqK0dGWHp3Qkg4bWVmNEpJcFFrbllOb3E3UklyZTg4dDZtdmRFVncx?=
 =?utf-8?B?Tm1kUDQrcHZqQ3F0WTFQaklEM2JUdG5KQ2owYVRDYVUyNkovWG9SNGJpNVpD?=
 =?utf-8?B?Z0xzaHBZZDhraTRrYTJ3NmRUM0l1UUJ3Z0tUaTJ5emo1NG9OUXdzMmJzZVlL?=
 =?utf-8?B?dFZMbS9MeEhiT2dSUmt3WC9jbXljSUowRnZlQ1Zsdkc2R2l1SHdWWHNPS3Rt?=
 =?utf-8?B?c0c4ZHdSczR6eEtmS2pjUHc1dVUzVmFLRkwybmlxa0ZBOVI2S3BmOUYxeFIx?=
 =?utf-8?B?WHV3d3ZRVENlcG8wME43L0ExN1VPdnhMRVZQQll5akc0c09KOGt2ckZibmpn?=
 =?utf-8?B?L2ZXUytMdU8wWGlDYXlnSkJxdnZtMFBnQjhZc1VIR2hHZkJFR3dkdFVGbjRw?=
 =?utf-8?B?Yk10RlpsVWF6MnRNdFBOaU5pdjVHVlZpc1hBaEIxY1MwcHVGaldJUm03Q0JK?=
 =?utf-8?B?MGtGcjkzM3ZLQ1NNaHlycTBtK3VoSmxSQ01zY2p5TXlkWDJLdEtOMS9XMEl6?=
 =?utf-8?B?bXBhQkFVL1h0cVFDUUZoU1hqTS9TaVBRRXJCR1VtLy9NYnJJYnFNdVFZVFcz?=
 =?utf-8?B?U0cySDNtc2h3RXQyNjBRUi93ZGdINXQ0Q2hmVzk0dFBjKzcyZm56eDN0YU4x?=
 =?utf-8?B?bjZjSnNBbnlCb1Ric3hvV3ZIR3Joand1RzBTNm14TktMZWxNNll2L3JZTGJE?=
 =?utf-8?B?c3RqajArdW91MVRLVmM1VnNrT1A1WjZCN21qNVJMc2tERWJJOG9OeFArUWRw?=
 =?utf-8?B?UCtpek5NdXpBU2pjYmgxVEhyVGkyeXdzZXdXL0hBbDUvSHRGaXBEK3EzT2tX?=
 =?utf-8?B?ZW5yUHNEWHJJcjh2U0FtQ3ZpNXU2WG5yTGowK0xFVytpRDVibkxNMklnWmph?=
 =?utf-8?B?TEhxYnQ1aTZYSEVzaE5sVjMzTDYyWjY1Yy9Yd3g5c090Z2pXMXhpL0ZIazZ5?=
 =?utf-8?B?N3k2Zkw4cUZPRmhLRGVnZk1VSE90SVZUUlQ1WVdsQ2JWeTk3RHNWbHlWNEFl?=
 =?utf-8?B?Rk5aeHhkWnZQUlM4cVVZOWlHRTNOaG5aSnhubDNNL1JqRCswcXlYMi94V0Zu?=
 =?utf-8?B?SGoyNVN0SGI2TFhhUGROZ2czMEtJMzJoNTlFL2R2Q29IZVdsZGVod25wdWVj?=
 =?utf-8?B?S1lCOW82M25Nb0MwQVlEOGhnbjR1ZFJsaVJYRjBzNlBzbUpyNjUxZis3WlRG?=
 =?utf-8?B?NVpiK2xFTVltdVNtaGdxckg3Y1VXSW5GN2h3QmtKN1l6K0ZqSmUwVXMvZVI0?=
 =?utf-8?Q?BRjb1K9GT6p3jnzR0451gpvTWyT76G4BlwtYzz9tsjT4=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3c7d07af-8826-4b03-fb5f-08dbef6f72fe
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Nov 2023 17:36:55.6211
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAXP193MB1389
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=DdzbBpVo;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7e1b::828 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

On 2023/11/27 17:38, Dmitry Vyukov wrote:
> On Mon, 27 Nov 2023 at 10:35, Juntong Deng <juntong.deng@outlook.com> wrote:
>>
>> On 2023/11/27 12:34, Dmitry Vyukov wrote:
>>> On Sun, 26 Nov 2023 at 23:25, Juntong Deng <juntong.deng@outlook.com> wrote:
>>>>
>>>> Record and report more information to help us find the cause of the
>>>> bug and to help us correlate the error with other system events.
>>>>
>>>> This patch adds recording and showing CPU number and timestamp at
>>>> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO). The
>>>> timestamps in the report use the same format and source as printk.
>>>>
>>>> Error occurrence timestamp is already implicit in the printk log,
>>>> and CPU number is already shown by dump_stack_lvl, so there is no
>>>> need to add it.
>>>>
>>>> In order to record CPU number and timestamp at allocation and free,
>>>> corresponding members need to be added to the relevant data structures,
>>>> which will lead to increased memory consumption.
>>>>
>>>> In Generic KASAN, members are added to struct kasan_track. Since in
>>>> most cases, alloc meta is stored in the redzone and free meta is
>>>> stored in the object or the redzone, memory consumption will not
>>>> increase much.
>>>>
>>>> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
>>>> struct kasan_stack_ring_entry. Memory consumption increases as the
>>>> size of struct kasan_stack_ring_entry increases (this part of the
>>>> memory is allocated by memblock), but since this is configurable,
>>>> it is up to the user to choose.
>>>>
>>>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
>>>> ---
>>>> V1 -> V2: Use bit field to reduce memory consumption. Add more detailed
>>>> config help. Cancel printing of redundant error occurrence timestamp.
>>>>
>>>>    lib/Kconfig.kasan      | 21 +++++++++++++++++++++
>>>>    mm/kasan/common.c      | 10 ++++++++++
>>>>    mm/kasan/kasan.h       | 10 ++++++++++
>>>>    mm/kasan/report.c      |  6 ++++++
>>>>    mm/kasan/report_tags.c | 16 ++++++++++++++++
>>>>    mm/kasan/tags.c        | 17 +++++++++++++++++
>>>>    6 files changed, 80 insertions(+)
>>>>
>>>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>>>> index 935eda08b1e1..8653f5c38be7 100644
>>>> --- a/lib/Kconfig.kasan
>>>> +++ b/lib/Kconfig.kasan
>>>> @@ -207,4 +207,25 @@ config KASAN_MODULE_TEST
>>>>             A part of the KASAN test suite that is not integrated with KUnit.
>>>>             Incompatible with Hardware Tag-Based KASAN.
>>>>
>>>> +config KASAN_EXTRA_INFO
>>>> +       bool "Record and report more information"
>>>> +       depends on KASAN
>>>> +       help
>>>> +         Record and report more information to help us find the cause of the
>>>> +         bug and to help us correlate the error with other system events.
>>>> +
>>>> +         Currently, the CPU number and timestamp are additionally
>>>> +         recorded for each heap block at allocation and free time, and
>>>> +         8 bytes will be added to each metadata structure that records
>>>> +         allocation or free information.
>>>> +
>>>> +         In Generic KASAN, each kmalloc-8 and kmalloc-16 object will add
>>>> +         16 bytes of additional memory consumption, and each kmalloc-32
>>>> +         object will add 8 bytes of additional memory consumption, not
>>>> +         affecting other larger objects.
>>>> +
>>>> +         In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
>>>> +         boot parameter, it will add 8 * stack_ring_size bytes of additional
>>>> +         memory consumption.
>>>> +
>>>>    endif # KASAN
>>>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>>>> index b5d8bd26fced..2f0884c762b7 100644
>>>> --- a/mm/kasan/common.c
>>>> +++ b/mm/kasan/common.c
>>>> @@ -20,6 +20,7 @@
>>>>    #include <linux/module.h>
>>>>    #include <linux/printk.h>
>>>>    #include <linux/sched.h>
>>>> +#include <linux/sched/clock.h>
>>>>    #include <linux/sched/task_stack.h>
>>>>    #include <linux/slab.h>
>>>>    #include <linux/stackdepot.h>
>>>> @@ -49,6 +50,15 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
>>>>
>>>>    void kasan_set_track(struct kasan_track *track, gfp_t flags)
>>>>    {
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       u32 cpu = raw_smp_processor_id();
>>>> +       u64 ts_nsec = local_clock();
>>>> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
>>>> +
>>>> +       track->cpu = cpu;
>>>> +       track->ts_sec = ts_nsec;
>>>> +       track->ts_usec = rem_usec;
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>           track->pid = current->pid;
>>>>           track->stack = kasan_save_stack(flags,
>>>>                           STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
>>>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>>>> index b29d46b83d1f..2a37baa4ce2f 100644
>>>> --- a/mm/kasan/kasan.h
>>>> +++ b/mm/kasan/kasan.h
>>>> @@ -187,6 +187,11 @@ static inline bool kasan_requires_meta(void)
>>>>    struct kasan_track {
>>>>           u32 pid;
>>>>           depot_stack_handle_t stack;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       u64 cpu:20;
>>>> +       u64 ts_sec:22;
>>>> +       u64 ts_usec:22;
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>    };
>>>>
>>>>    enum kasan_report_type {
>>>> @@ -278,6 +283,11 @@ struct kasan_stack_ring_entry {
>>>>           u32 pid;
>>>>           depot_stack_handle_t stack;
>>>>           bool is_free;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       u64 cpu:20;
>>>> +       u64 ts_sec:22;
>>>> +       u64 ts_usec:22;
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>    };
>>>>
>>>>    struct kasan_stack_ring {
>>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>>> index e77facb62900..8cd8f6e5cf24 100644
>>>> --- a/mm/kasan/report.c
>>>> +++ b/mm/kasan/report.c
>>>> @@ -262,7 +262,13 @@ static void print_error_description(struct kasan_report_info *info)
>>>>
>>>>    static void print_track(struct kasan_track *track, const char *prefix)
>>>>    {
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       pr_err("%s by task %u on cpu %d at %u.%06us:\n",
>>>> +                       prefix, track->pid, track->cpu,
>>>> +                       track->ts_sec, track->ts_usec);
>>>> +#else
>>>>           pr_err("%s by task %u:\n", prefix, track->pid);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>           if (track->stack)
>>>>                   stack_depot_print(track->stack);
>>>>           else
>>>> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
>>>> index 55154743f915..bf895b1d2dc2 100644
>>>> --- a/mm/kasan/report_tags.c
>>>> +++ b/mm/kasan/report_tags.c
>>>> @@ -27,6 +27,16 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>>>>           return "invalid-access";
>>>>    }
>>>>
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +static void kasan_complete_extra_report_info(struct kasan_track *track,
>>>> +                                        struct kasan_stack_ring_entry *entry)
>>>> +{
>>>> +       track->cpu = entry->cpu;
>>>> +       track->ts_sec = entry->ts_sec;
>>>> +       track->ts_usec = entry->ts_usec;
>>>> +}
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>> +
>>>>    void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>>>    {
>>>>           unsigned long flags;
>>>> @@ -73,6 +83,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>>>
>>>>                           info->free_track.pid = entry->pid;
>>>>                           info->free_track.stack = entry->stack;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +                       kasan_complete_extra_report_info(&info->free_track, entry);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>                           free_found = true;
>>>>
>>>>                           /*
>>>> @@ -88,6 +101,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>>>
>>>>                           info->alloc_track.pid = entry->pid;
>>>>                           info->alloc_track.stack = entry->stack;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>                           alloc_found = true;
>>>>
>>>>                           /*
>>>> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
>>>> index 739ae997463d..c172e115b9bb 100644
>>>> --- a/mm/kasan/tags.c
>>>> +++ b/mm/kasan/tags.c
>>>> @@ -13,6 +13,7 @@
>>>>    #include <linux/memblock.h>
>>>>    #include <linux/memory.h>
>>>>    #include <linux/mm.h>
>>>> +#include <linux/sched/clock.h>
>>>>    #include <linux/stackdepot.h>
>>>>    #include <linux/static_key.h>
>>>>    #include <linux/string.h>
>>>> @@ -93,6 +94,19 @@ void __init kasan_init_tags(void)
>>>>           }
>>>>    }
>>>>
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
>>>> +{
>>>> +       u32 cpu = raw_smp_processor_id();
>>>> +       u64 ts_nsec = local_clock();
>>>> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
>>>> +
>>>> +       entry->cpu = cpu;
>>>> +       entry->ts_sec = ts_nsec;
>>>> +       entry->ts_usec = rem_usec;
>>>
>>> I would timestamp as a single field in all structs and convert it to
>>> sec/usec only when we print it. It would make all initialization and
>>> copying shorter. E.g. this function can be just:
>>>
>>>          entry->cpu = raw_smp_processor_id();
>>>          entry->timestamp = local_clock() / 1024;
>>>
>>> Dividing by 1024 is much faster and gives roughly the same precision.
>>> This can be unscaled during reporting:
>>>
>>>          u64 sec = entry->timestamp * 1024;
>>>          unsigned long usec = do_div(sec, NSEC_PER_SEC) / 1000;
>>>
>>> But otherwise the patch looks good to me.
>>>
>>> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>>>
>>
>>
>> I think it would be better to use left shift and right shift because
>> dropping the last 3 bits would not affect the microsecond part and
>> would not affect the precision at all.
>>
>> In addition, 44 bits are enough to store the maximum value of the
>> displayable time 99999.999999 (5-bit seconds + 6-bit microseconds).
>>
>> 010110101111001100010000011110100011111111111111 (99999.999999) >> 3
>> = 10110101111001100010000011110100011111111111 (44 bits)
>>
>> I will send the V3 patch.
> 
> Agree.
> Modern compilers are smart enough to turn division/multiplication by
> pow-2 const into necessary shift, so we may not obfuscate the code.
> 


In my actual tests, right/left shifting by 3 bits gives a different
result than dividing/multiplying by 1024.

Right/left shifting by 3 bits did not cause loss of precision,
but dividing/multiplying by 1024 did.

I think the compiler did not convert that part of the code very well.

I think using bit shift would be a better option.


> 
>>>> +}
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>> +
>>>>    static void save_stack_info(struct kmem_cache *cache, void *object,
>>>>                           gfp_t gfp_flags, bool is_free)
>>>>    {
>>>> @@ -128,6 +142,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>>>>           entry->pid = current->pid;
>>>>           entry->stack = stack;
>>>>           entry->is_free = is_free;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       save_extra_info(entry);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>
>>>>           entry->ptr = object;
>>>>
>>>> --
>>>> 2.39.2
>>>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752B1A233DACC44EEC7FB8199BDA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
