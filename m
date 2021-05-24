Return-Path: <kasan-dev+bncBDD3TG4G74HRBRPCVWCQMGQEG5Y4EMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B59E38E34B
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 11:26:31 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id c14-20020aa781ce0000b02902e8f588ec26sf422216pfn.17
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 02:26:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1621848390; cv=pass;
        d=google.com; s=arc-20160816;
        b=uUSYuHGGXRtBgZBx4Bok1ftpvGTFGyePys+PPHZOy0nxfo0f1zErQTl8ScD1Z9S3yl
         vIeCXKTK/KhhMNQX+t1toJkX6PT7h94SYFtJYT1m9naA01+hPQVQhZsEX5IMYLENZ8I+
         o2a4jMHx0p35+Q4Ys281aWXRMo89X/PV2mT4SBeOZvWdB8sKkcxQ+yW2im1wOutXlDo0
         WROhwXVga71H3oFT89yiL2pNkRhNNcWL68T/1Eq/iROIwHuadAxXYv0xxYVbU3keNlWP
         1TjwUFmwd7s3S7QUMfOYokrqgNJE23qBw0dVysXxIQBMG0giLQDmbZvz2y72rj55uWwO
         YiPQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=zInHbpg7WrC7LoZtZpqvjODGohHEhc2Dcj0M7j0hIp4=;
        b=aAMAK4MoGotTK0fbsUhKNp3nMd8nvEjtCnpaIBNpPR2wTn3mRMVqVxHQ+CrqhLDYq3
         HJlYfOGUl2XBCXqoEJgEvhbDJ3kGy0ihxOi2nA37+8f8WrzAVDks08O4/LbcaNnKdslb
         eAI7Pd/NpxAPxf2fdkNybvnHt/c+1G7Z1KH6VgcciJz0eA9PuIPSqVOibajvY4d3IlPl
         sb/ZX5BjR5lbMH9AMkDt9fZZygeUM2jnwRJnAl8aqKm6gEVgsmEd1rmyQIts+n+91H+H
         AS6u7ZAwOn9h2BFyZKTEi0yU7kP0/p6WHnoN/f4CCLL8W07SK3v+6XkLBUxc/59i+opI
         aQ0w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=bQe6+eQa;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.94.56 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zInHbpg7WrC7LoZtZpqvjODGohHEhc2Dcj0M7j0hIp4=;
        b=Pv4GgHzvZILvXF7Z54lcYOlLM1naDT+/1J1ATYzI5h6CoQkgubO4Ehuhuuj1ZhXlpO
         S4rJATPLNVPc6fBYSsYCgWRv6pFcVyQZ+RMwgt7EPKnVcGth1+YHm+qlJUF4IEmwAN8q
         Hlcaew/3i9ScFi77zx0q/L0hbFqEcetfI5k9zM6iBBFTslw2odDPKerZOpSfa/SBIzcx
         5XmGU9mRc1skMXn/H2NI6kJtZW0WSdMyNQu94qgzFnBNtJUlqCfVp+M/uFcCNm9dgJ0A
         kr918gZhLjQ6ZBq0mAAVrKpycvghe6hdgFiMPMyxrjavjVOUMW+5NYspK8W098dEMvcl
         ieUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zInHbpg7WrC7LoZtZpqvjODGohHEhc2Dcj0M7j0hIp4=;
        b=qCXVuB8WvuP4tDJFMSWaNdOLRBSYyREy5ldc4M4+APFFvivNlrzFg9Yfoi4FZ3fSZF
         c8zCrDPx3l8kuVCPpKOdh8jkTAypKQpDV2l4GORox857EPTHS8uKLANnbKNmX8UTYwgG
         vJt+AGYSgRTxKfctUSxc42nUHyl3dOuCjATT0GP1QOrfS2P3bmhMJoaD1DrHLPFmngTm
         iuS0E5vOJ1Vm0JKrG6oGn8tbp/VqedOq593F1cy3qTHoQ+E0vGiCN2mqZFMOoveGL7HT
         I0/IGUCXpD4aNtkQHo/bCkmorlsn8gMOwibElQiyyOEZdcd+IG71Rn8SFmmMpsOY+9UA
         Rq9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530queFO0v7109/rlkbs7JWJIV80oIcfpSLMsmunR5t0rDXdozb4
	dAg6wrDAVI208iGzlZJUNUA=
X-Google-Smtp-Source: ABdhPJwhld6fRP/ZOomTZXelaQ8FWuTx5dkMnCWDRKNp9Hxd0ZdK2vOcxbrH8P6avQR0ef+g5tSaIg==
X-Received: by 2002:a17:90b:1187:: with SMTP id gk7mr24922151pjb.104.1621848389753;
        Mon, 24 May 2021 02:26:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2c96:: with SMTP id s144ls6278296pfs.0.gmail; Mon, 24
 May 2021 02:26:29 -0700 (PDT)
X-Received: by 2002:a63:e402:: with SMTP id a2mr12762613pgi.181.1621848389287;
        Mon, 24 May 2021 02:26:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621848389; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ty5M5Nr9GJi18iurbocfDszZJrXvQL3PaYCDpIDCUhFfPhqVfhMEHM1H2OV/3/q8tm
         qA/WpZ+ciOZHW5A4/J4pnXm4o5QEtK/UggaFAhycsG8AEKmBRU+CcTftpfci0o2Jsq8B
         UhL3IvRiA0+GK+wnXX2sK9i+z+yvMIQiedfAAYyO/1EbUeKInoJNq6pzKsGDG5hpw8wo
         aJF/DMJU988EBG9h6TRECwszACJ48h8b6Kej+vJb6Hu9xNQS5yIQmlQ9oMTC5O+8J4x+
         jg200hTNk38nYhbI6/TcmksGUBS3ViFPVgiwu2ztX3h0W7XAA0vluGNm+YhpEmgeDNqs
         +2qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6M0nJU/y2MKjtfSlFmSxDKO8kQQbJQf3ehgUixbHk4A=;
        b=tbe+wSPeS/qGQ90FIEJ6Z0Ft6wTsmt214SFkAy+Uiwc4OkX77t0Pzc8Ye94dFj3hYq
         PopcIcKLQejFiBRNrU3bjkUoryqjQjpZ5UsvRWAUFxKwcjYIxz/SKXaxl8KIcfcImLVL
         fp6mUNGlgSTJPLHqu7bQK0SU0jmQznT/T4p27SlnAkL2aUUFktn+ML6e/v7u01pgUxnF
         iSA/yEo7qJhFuN6tCHfSI4wZUNadCk22/KfM6aTAuHVEHfKidcaRNfbbRFRi39OoDI6z
         zBWhWJGeZxuJPB10fTfnJbrEjgk/8tjCQyHdXL14y50VzgQYo2UxMDk5UfS/lWCP8+hO
         kGGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=bQe6+eQa;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.94.56 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on2056.outbound.protection.outlook.com. [40.107.94.56])
        by gmr-mx.google.com with ESMTPS id c2si1697497pgb.5.2021.05.24.02.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 May 2021 02:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.94.56 as permitted sender) client-ip=40.107.94.56;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=BjhgAeO8wwJW4KWCQ5dJcdiiM3zkqcsTMc6JFrj2uBwgYxjAOYWK/vTB5spDkU/ZDWG+0mFLWpoTkzy60NlSTuFNJxUjqWD/qzxTfEoWMx06QHNc4Q/TtqzoC7bofzvqNLyn/BMUEAs1D5+5q+NQAAcMtfysEjXIBWCW3UsJCafOGBATyzvpoanfP06qg3GqJULx+44+OISsYNGgEkxckGrwN5gb5z4i5bfRcvviAb6VxpXOYbHP2TK2X13DQWc798JjeaZeMmlGiH89vi1F3GRx5PfsaOixfxtJ3exoon3B8SxOeKWzMDn3+rOOSOrstLU9sZoOkP2dQOf4kEREcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=6M0nJU/y2MKjtfSlFmSxDKO8kQQbJQf3ehgUixbHk4A=;
 b=ixj30kcvisQs6iMv8pQKHVnqGadRLMr94irbBwGYYkgbMlddrvUNBHrkW0AtMO0p1JzpYoGqL+xattSTGiARbZKKU24tYNiItDV6FgaJRxs/POgKl/GI07Fea0hq2B9/K/VbEuPe0NP5498V9xh9NXkwEsbGkt3w8NxL6E0T/3sJ0YgAYqWG7pWeKBpQw8Ex3YnAfm3066tThVCl7jlM/5bcWqRvg5o0vA+g2bm7R/vniBPoIH49pKXAlN97GB+5Pn1qD+sRaO4lmhLgAIEarr6KXJZUMqvkkQihwa5pdBEybs+tiuwUYSox2/du+MYzy6SPQx4/1CtQWBLhluaW8Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synaptics.com; dmarc=pass action=none
 header.from=synaptics.com; dkim=pass header.d=synaptics.com; arc=none
Received: from BN9PR03MB6058.namprd03.prod.outlook.com (2603:10b6:408:137::15)
 by BN9PR03MB6188.namprd03.prod.outlook.com (2603:10b6:408:101::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.23; Mon, 24 May
 2021 09:26:27 +0000
Received: from BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791]) by BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791%4]) with mapi id 15.20.4150.027; Mon, 24 May 2021
 09:26:26 +0000
Date: Mon, 24 May 2021 17:25:29 +0800
From: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: [PATCH 1/2] kfence: allow providing __kfence_pool in arch specific
 way
Message-ID: <20210524172529.3d23c3e7@xhacker.debian>
In-Reply-To: <20210524172433.015b3b6b@xhacker.debian>
References: <20210524172433.015b3b6b@xhacker.debian>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [192.147.44.204]
X-ClientProxiedBy: BY5PR17CA0069.namprd17.prod.outlook.com
 (2603:10b6:a03:167::46) To BN9PR03MB6058.namprd03.prod.outlook.com
 (2603:10b6:408:137::15)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from xhacker.debian (192.147.44.204) by BY5PR17CA0069.namprd17.prod.outlook.com (2603:10b6:a03:167::46) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.26 via Frontend Transport; Mon, 24 May 2021 09:26:23 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 212b5db6-68fb-4623-cbff-08d91e96014d
X-MS-TrafficTypeDiagnostic: BN9PR03MB6188:
X-Microsoft-Antispam-PRVS: <BN9PR03MB61886206BCE947C8E13A97AFED269@BN9PR03MB6188.namprd03.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:4941;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: MVcBFegMUBkO7fU0YjcOqwYno3UYFc/Jgq9KIewO2toWp82wXWMRVvR/uMP8Pj1iMYKU0RMkWhrYJTCytSnwhV2GLiBCH1FngUvinN+aKSmySXZqACsmpU9Wf3tRQ0vUGeg4u2oTLfMjBBvaqE7ktuRjGPDyOjRPuwoft2fBGgAS02o5jVhvzyhSThtkuH5xjkmqZ+6DM40YzrGosvSJjm0lbvLXLE4dtLigO7nSwRWAx40+o7lqgy5I9Cblf9DjfTVVlr44yVKpYPaqUKqasn5ns7FuuuY0JT1SqOanr2xflKTG3RvXMKU0KTV3p5H5ms3eFHGombtFZrJjbZG3FgIvU0iITX+5Leu0nC2V99Ik7kkGbDCSsAFjj+XXyO/VA4mEv6aQBan/SSmBWYugMGzt6NORGZOYXe07mlY3Rvq5sgpL4DpexV98kMTk2xCOutr6B1E83u1OkOOD5pKuacDXHH/OQmkDCjhFDIEYmpn3GBWWw0N2uCvLOMHnsW8/zRXuTVILHha85Be5vvVAyqVorZlSnX1Uqtz1FTCZ8OzYY5qal0tdhRnow2v82MZbBb5XimXVzI8lmguiitFRoLneW3LjpqvzQA35AXJ2svaOQGO0HVzi577sJXVkJjOX1Uck8KyDS1AA0jgaG0LtqiokWGvU5Ry/fkdZtguTU9k=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN9PR03MB6058.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(39850400004)(346002)(376002)(396003)(136003)(366004)(66946007)(1076003)(316002)(66556008)(66476007)(5660300002)(478600001)(2906002)(4326008)(110136005)(7416002)(16526019)(186003)(26005)(8676002)(52116002)(7696005)(956004)(55016002)(6506007)(86362001)(83380400001)(38350700002)(9686003)(38100700002)(8936002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?0qMlpUMKtnluZ2JfT5oP48G8nX2hVfICByh/N/wcuAkrhB8IuWJZgphE7ICA?=
 =?us-ascii?Q?VjBTyXkYeTbAH3V4ntXhCqmNRFXzhne7EZeI1OG7HZaLmGsvRc6DQj92pkao?=
 =?us-ascii?Q?V97ynW88BRkGat2lQbAShCJB9W9w8X7IWw2oQEyjo0IDTBnFhig0fFjcW5WH?=
 =?us-ascii?Q?SSKdmc37u8MmOoDwI4zE6pKUPxV3VFp3ybPymTvEsqX6ZF8niLJRD7d/Ak6U?=
 =?us-ascii?Q?O+Y8T0M2yA+Jif6ZTEnNvmhLU4K304LlhKJCCIVuszl/2eKzCtAkVnoUugom?=
 =?us-ascii?Q?O6fz4n26yXuCOBdUsCzldkwiMtUECyrUk5fRLauVBDnHbnJfvtELz7Jrjfcr?=
 =?us-ascii?Q?0cLDjMta2GXVCRVhW8iW6qsrZD6uIdGGpUQ3kln5oQGUDXebOgwCnQ7GtZZs?=
 =?us-ascii?Q?jPn5IJpQz/7dZ+CuBKgBj4piP4d0RmvaqLkCvTmYVTEy9xkIdmf7+8Jir8wF?=
 =?us-ascii?Q?DsgaNTWcTz+v85KJbzxH5SlxP1yfWbZCQcFsjK/F/gFDqELm2YGSx/Hlfzuj?=
 =?us-ascii?Q?mWYV52iAWVw7ozyZ5koixXzwiuBxH0JRSdhj4BCmqe2tyBxcA8maUwpxKB2K?=
 =?us-ascii?Q?f+WCXDXzFP2UXa+i+Uy3iX+kmpUcR8eOBx6bAD2KSh+4gval2Y54yDpMdXEJ?=
 =?us-ascii?Q?/7+KjzjIsOOvVYmPiLcIpZAH1YVre2ir1P9JsDDWR5ynHlrr4Icgy2yCQSw+?=
 =?us-ascii?Q?+aObZO1/WLNtyL4RsoMmPkG1yFT/x9cLyiqfGvdovAvNULNmJ//kPG+Rukn3?=
 =?us-ascii?Q?H31DUk3bwMgj/zkECvrBXTgIu/6G5u/BcF6jnWsw56QsIhc79D8MtXuFcB8C?=
 =?us-ascii?Q?RHOoDy8OrUHYp9oliQ2A527QS/MjfxLlIYuAlRGVwQs1dp7dzHwtT3G4IxYv?=
 =?us-ascii?Q?F7nWHfZjeo+OnoryC62qmHvUbroq83aTzX0iTmvmSyhqgj8xyeAd2RTHcH+W?=
 =?us-ascii?Q?BiU2VAExk5pwNzbdWN39YmG+1VAWZgubfcOXaSY0gUiHCG0S8Dvtjmo3mwbI?=
 =?us-ascii?Q?si5dpM7N9nrjcUMWOHhyXtt62lrkG4f/J72H9sAM+5Q+Qp1pHiggMACKZSR5?=
 =?us-ascii?Q?9xll5ufa+j0Fx8aGjY+3/bJRUEyAUe0Bj0gaUdq9w54hbUxX7Ikwko3WQFM6?=
 =?us-ascii?Q?E1FT05DO47y37FUNNrDgtveK8CHKb8rdExeIxVS9M8LxpUqjEU6mYaBUIGcD?=
 =?us-ascii?Q?FNZyS1FWcFB3WA3v0lf5E/LmgD7y3mH0cyGcjA77FW3rmTVuKPika4tfes8x?=
 =?us-ascii?Q?7/S9FZulgk55YiGuyPIHH1nmv0eQpIbfm+I6LY8BhAjbKBlS79+A8dHsO1mD?=
 =?us-ascii?Q?zqZ6+JbHQLdAOGOA4PhsODAo?=
X-OriginatorOrg: synaptics.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 212b5db6-68fb-4623-cbff-08d91e96014d
X-MS-Exchange-CrossTenant-AuthSource: BN9PR03MB6058.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 May 2021 09:26:26.7669
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335d1fbc-2124-4173-9863-17e7051a2a0e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CZRkAq73ytDBjrW+o+bNwG4TB+9naOak+z8LepMTL09TGP1P8l/gY0vREYptP6xErxvf22sfleFXhzBH+wATbQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN9PR03MB6188
X-Original-Sender: Jisheng.Zhang@synaptics.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com
 header.b=bQe6+eQa;       arc=pass (i=1 spf=pass spfdomain=synaptics.com
 dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates
 40.107.94.56 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
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

Some architectures may want to allocate the __kfence_pool differently
for example, allocate the __kfence_pool earlier before paging_init().
We also delay the memset() to kfence_init_pool().

Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
---
 mm/kfence/core.c | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index e18fbbd5d9b4..65f0210edb65 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -430,6 +430,8 @@ static bool __init kfence_init_pool(void)
 	if (!__kfence_pool)
 		return false;
 
+	memset(__kfence_pool, 0, KFENCE_POOL_SIZE);
+
 	if (!arch_kfence_init_pool())
 		goto err;
 
@@ -645,10 +647,10 @@ static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
 
 void __init kfence_alloc_pool(void)
 {
-	if (!kfence_sample_interval)
+	if (!kfence_sample_interval || __kfence_pool)
 		return;
 
-	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	__kfence_pool = memblock_alloc_raw(KFENCE_POOL_SIZE, PAGE_SIZE);
 
 	if (!__kfence_pool)
 		pr_err("failed to allocate pool\n");
-- 
2.31.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210524172529.3d23c3e7%40xhacker.debian.
