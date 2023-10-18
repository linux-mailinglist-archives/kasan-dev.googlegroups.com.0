Return-Path: <kasan-dev+bncBAABBF7VX6UQMGQEN4KOJIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BA88B7CE139
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 17:32:40 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-66d08175882sf62596466d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 08:32:40 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1697643159; cv=pass;
        d=google.com; s=arc-20160816;
        b=COdxmoW/4NEjyhvfXDMFXDst+daZlp2t/rdfm9qeDAV0mqvSL32v4aAyTHsu2SKP/u
         OrF3i3OhHBPr2gRRNTa9kumu2QIJBduhp1xSheNrkLD4BZ6jNw6dlxyql4cpzCjYyAP8
         jPzgmGUQ6V2J2tndORu8lMRJW9kt7H60m9qIhCE65eXHfJBpT8wLlqp6PmkmQyxtm2oH
         BrOINksEVPtdLTyKvbZtImOr2edScdTJgCGrMnxiCsKg6Wded1/czs2b1bSfGif22RQq
         l63SRSsmvOhcj80J6r2zJoGaIqawVGA9FQCobUO00b70rgc5Pd3JH7JZojXJUjOZglVO
         CMFQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=mewZ01MNKSCaOnBsJo2iTfaBkchs7rIPM/7vFtzBruE=;
        fh=0PnjhOJ24SnMLzYtKNrFO0j0HqDX3SBRyOrM3f29YRM=;
        b=S4+kVN4qUXTUj2upyZtWRMzU5mfnVUuymsMfT3vb3S2HGhCCqI18HjwG+7aDy54VLd
         fqWSJgCiYlLjLIhkgcRWbVtEqh6E8WxG27XODTtYbd9giXRz/YwghxaXUCn/PCnO/GxX
         5dTk857Fto54rNYvbotlffPPyHGZsp8BXxPxnO6Kkj8IRlH2Eu9H1KwTT5TyoKHii8+o
         8zHmf/Y5f3ReQGYTjrtsW9Bhog33sTVbI52e5zO9V+dSwZ+IMbP8X3Yb/WHyBfdMp8jd
         apbuKQ3e0kYZ9SRv5U/BCt6F+SxLz8OqIDR86M2BIhhMxReOQsUfvb1bR2yljRPkRymh
         IaTg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@amd.com header.s=selector1 header.b=Cl5teZ2e;
       arc=pass (i=1 spf=pass spfdomain=amd.com dmarc=pass fromdomain=amd.com);
       spf=pass (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e89::607 as permitted sender) smtp.mailfrom=Hamza.Mahfooz@amd.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697643159; x=1698247959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mewZ01MNKSCaOnBsJo2iTfaBkchs7rIPM/7vFtzBruE=;
        b=afA+q5413TLer5PtNhNRIoLTYMaZwHJ5eA6Sp3ztY+c0ThsqRxm+ZdIcfAbPX75G4d
         cvZedTdgdPXDx+DV8co3eFRjWYb9PSKMAFHrON12BHFqH4oHGgLSyjDtIiXaRTkSxjNm
         tFULk+D5DEA0horjr4PyQ7mE8HgWDVuODGGm/JBlbAwpu+CeNMfJymQ5H7aZrgUoihxq
         zLOXCLPCjs2wNiuwMc745rMclAX50kszfuh/GoEboZOHRmQhs9FVHtHSItY0GCLarir4
         +sAhET08STBjcOY96ZtNH8Bymcd7g4KYB7dnYUcUWGzAqGZby5oS0WHs73AJj5YXAfZQ
         wUaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697643159; x=1698247959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mewZ01MNKSCaOnBsJo2iTfaBkchs7rIPM/7vFtzBruE=;
        b=jY7gUDlREUI86obMAGnvbMVxk5Pys2PmSf4+T5wnInCf2rZlyJzGB1n9iAUoR3NCHO
         fNy47RPW5DuDRnIG4GCSkYJ5EeJEPTl/zeHLZ+IWOFyAWOhJlL5Zn0zQgSf5y7aN/kkn
         neXeMQ44TDz6Ef9sJEMkSAjrozIvcr56QHfu2OtEQem5TyRnVtmJMlUtVS1zGdLWzDjO
         9RC4QVYI43Whj1Ac+FkYGkwonJ9QLDttJid5E6myBXKVA7tF5yGn/fR2aaXiDtchNlLe
         X1r9ybnnTzR8wQtiRnipd1wZDvu5+qCYf8YJq9Ntaqm2ENBaue17q41bXIhqnFs/J8/J
         c0Nw==
X-Gm-Message-State: AOJu0YxxTIp6yhVDGjYIA6TxIw1qYCvM6emG+yzEnR6KNZDn+LnHonNo
	7cS0MUfT6VpNTjIsFzOpojQ=
X-Google-Smtp-Source: AGHT+IGeGYtpCs+vj8gZvbkUd6GWtECx9w/sxnE/wsE+ey0II4yfYdwbgxekuA6uMTWzPyQdMSPFig==
X-Received: by 2002:a05:6214:2487:b0:66d:4cb3:b385 with SMTP id gi7-20020a056214248700b0066d4cb3b385mr6533626qvb.22.1697643159585;
        Wed, 18 Oct 2023 08:32:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:43ca:b0:65d:b9b:f30e with SMTP id
 oi10-20020a05621443ca00b0065d0b9bf30els2763984qvb.0.-pod-prod-03-us; Wed, 18
 Oct 2023 08:32:39 -0700 (PDT)
X-Received: by 2002:a05:6122:90d:b0:493:7df9:bcc4 with SMTP id j13-20020a056122090d00b004937df9bcc4mr6039091vka.4.1697643158935;
        Wed, 18 Oct 2023 08:32:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697643158; cv=pass;
        d=google.com; s=arc-20160816;
        b=anXeIoC8PLooJORZqHNAHSoyEwNwpz1oVriUUfpe/SL/d6YJPaIav730Z9hqhlFAej
         PiZmFr/BhyjFzRnQA8diI5y4uYDvmAKX0W0cV6pAMCeW7g8QEqnTG7XxDfC52tEJlwq5
         1v2zu5JHYXuaswXxisBMKdf/haQ7GWulzOn+na0ft2YYQ1F1TaiC8080PLpSSUL7QG8s
         gT/HDw4SxkLbgtZhpL7XcuWVSZ6Ysi0FLAJMiYki/7pi9K38fqTY+QfOhyr69+AKa/4b
         yAlP05wrhr1G4nOL7s9epxVpEpZKvoCBi49R6Tj/JBLL5i3xkajcnBC/3beuhEzrLQb8
         Lguw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=t4EGmEG7/6VTSsdQ95kDL3H+dHVvpGu9d8qKc+oIY+I=;
        fh=0PnjhOJ24SnMLzYtKNrFO0j0HqDX3SBRyOrM3f29YRM=;
        b=csw7o/Mw46PQLy3X5yyoxmldXVZ35NDUTqQvIt5HhW3ajTJEG5VEBqz2kw8S7YfgUE
         TkbIyojH0shFaD9GusFBHXnO1vLjbG2wM3meipUmwrLjRO8B9hjVYJO8ShYjv4GpGOOs
         7OsrB5+4uHoA/W9ucYvCp84bU2wLLwETh3FyX5WAgCt+4kgUgbyBplfTgU3hz5j0Jfmg
         zTqvVxhGewGRS7HXQQJo9AqgM9uu8zeJsN4zk1u0V2XdhyCYUv2HtXuH/t1cBllM88cC
         TcplBRu9dcAlVeuQjt7VdlnSNkNoXi+yhYvlmjoBWXmC0ukZI54IIhekMX2itaQzBuiS
         ihtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amd.com header.s=selector1 header.b=Cl5teZ2e;
       arc=pass (i=1 spf=pass spfdomain=amd.com dmarc=pass fromdomain=amd.com);
       spf=pass (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e89::607 as permitted sender) smtp.mailfrom=Hamza.Mahfooz@amd.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on20607.outbound.protection.outlook.com. [2a01:111:f400:7e89::607])
        by gmr-mx.google.com with ESMTPS id n4-20020a1f7204000000b0049362af6c50si374899vkc.5.2023.10.18.08.32.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Oct 2023 08:32:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e89::607 as permitted sender) client-ip=2a01:111:f400:7e89::607;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=clNpQy5ZybGfdVjI2sKzIxRKmWpuzX2t0fMpvx+gtGr6SdUPC4mHrXl5pKMa8b8DqLnPfteTwDyz5c0OaQFge4/w+Gsm3R5UvaQxoyDzrGmJs/Vp/F5HCBwwnaUme88ndNW3u6vUA9LRRZc6LsddGgat8OubVIfSJyfaHFDJKMuabd6RkKuprPmBwoMqgb1mlBGxlM1qgl1AIc0Y17eCJJYIjAj/oGjmQXOcvp2IPW596LhXumYxTIGMCK+6n6ZRNhTzJ/6Cc90iilwhunel7douEx4Jh9lha9kABb8qq1h+2E/N/EM6QmyAhs/hrcvNFmdfZZykckfwC+ubAZWyVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=t4EGmEG7/6VTSsdQ95kDL3H+dHVvpGu9d8qKc+oIY+I=;
 b=AgXkfxaz5NN2az36eZOBWUJ3V1J6QcnydNd0R4y148BY+dpzaz/gzvL1G4ExrEUuRJci9+dlt42o331CYIcWJ6bFhCTSKvpJ343JmLh+yRPi3uZ3BEYmIoE9zZfswBfm79Y/p3RuYAJPEgfHfXUY9j8wK4IXdhWoSyCqHuUyt1bwLPC7Edh92FjiCIYZgxcOrMP0EFTa3wnhwg9wl8YzKksp9F72OrfEB/mChcmP0kmOpmYpML5IjbbOTf3BjwA73cHEwcJwIkbaU3wDKmxqbEtL+pAk/Y+pmo1kUEjZlY0baJ4ojqHpKNg1WFHRdAdkm3cW1OE8g31pk7fTRRQjjA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 165.204.84.17) smtp.rcpttodomain=vger.kernel.org smtp.mailfrom=amd.com;
 dmarc=pass (p=quarantine sp=quarantine pct=100) action=none
 header.from=amd.com; dkim=none (message not signed); arc=none
Received: from CH2PR18CA0024.namprd18.prod.outlook.com (2603:10b6:610:4f::34)
 by IA1PR12MB6018.namprd12.prod.outlook.com (2603:10b6:208:3d6::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6886.36; Wed, 18 Oct
 2023 15:32:33 +0000
Received: from DS3PEPF000099D6.namprd04.prod.outlook.com
 (2603:10b6:610:4f:cafe::f0) by CH2PR18CA0024.outlook.office365.com
 (2603:10b6:610:4f::34) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6907.21 via Frontend
 Transport; Wed, 18 Oct 2023 15:32:32 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 165.204.84.17)
 smtp.mailfrom=amd.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=amd.com;
Received-SPF: Pass (protection.outlook.com: domain of amd.com designates
 165.204.84.17 as permitted sender) receiver=protection.outlook.com;
 client-ip=165.204.84.17; helo=SATLEXMB04.amd.com; pr=C
Received: from SATLEXMB04.amd.com (165.204.84.17) by
 DS3PEPF000099D6.mail.protection.outlook.com (10.167.17.7) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6907.20 via Frontend Transport; Wed, 18 Oct 2023 15:32:32 +0000
Received: from hamza-pc.localhost (10.180.168.240) by SATLEXMB04.amd.com
 (10.181.40.145) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.27; Wed, 18 Oct
 2023 10:32:31 -0500
From: "'Hamza Mahfooz' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>
CC: Rodrigo Siqueira <rodrigo.siqueira@amd.com>, Harry Wentland
	<harry.wentland@amd.com>, Alex Deucher <alexander.deucher@amd.com>, "Hamza
 Mahfooz" <hamza.mahfooz@amd.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, "Nathan
 Chancellor" <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, <kasan-dev@googlegroups.com>,
	<llvm@lists.linux.dev>
Subject: [PATCH] lib: Kconfig: disable dynamic sanitizers for test builds
Date: Wed, 18 Oct 2023 11:31:47 -0400
Message-ID: <20231018153147.167393-1-hamza.mahfooz@amd.com>
X-Mailer: git-send-email 2.42.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.180.168.240]
X-ClientProxiedBy: SATLEXMB03.amd.com (10.181.40.144) To SATLEXMB04.amd.com
 (10.181.40.145)
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS3PEPF000099D6:EE_|IA1PR12MB6018:EE_
X-MS-Office365-Filtering-Correlation-Id: 7a9b12ee-24d8-449f-8024-08dbcfef7267
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: mctP/W0JJzx5e8Gr0LMtnjvwecDuaiSjxQc0JAwdrUEgI52ao7heP2qJs/AjRaI4uxNjKcIaX+a1XmQMzQlJtdnbVrrGycazbHE1wn96wX6pI0Q2cfZIw2CiXtq1rthkYADckm0zVE2TePGJpAHpiPKoAXoBhWfnyX+pOmXs9UOSC+d0fbquVKZigbwzmUVMYBKcXz0gNi/89TjBK9jAKvq2BsPenHLB64J2/lDXjmQenYpwl4yD8Wa35NiE7nSVE8HnDo76kO5loD6dRNuwNmdNKBk1Xt3OGN7QeqUIno1XnRwTpQpnwnFx3KHzYOq6EST32iFZ2sucXBby52HRrrYUKDqrCW4Jm58KWtbYfISxDwAE0aBoQhDBbzX52bem1tvFaQuz4X5LKDK+Ps2Tfk0achvSMrv/2l+prssuff5qgOjo/nSloRtApFj/5maql8HfesCs/5u2C7oGxlomGWQCheLWWzZDh3e6V46io/T8Nro5/6FQE3A8dDDmzR1noVwOKUaXFgA/8ivrDPKE2iylFq9+5TYhqnkMKmFZ1hFGtWkALLSIEe0PdlNcc3DhAHgoGJOn5hMh3G7bPD+v869QZ3S2Un8xw1QvLav2vTL6IEmOjndxKQO5qJbL3VPQ/K6EosnmjiYUbsXy+knDtKWAJQVOlPs+bdNLZY4gAavafsMD7gAqgQF3SGLKugGTdDCe7RtgFjowSarCHVFN5U1S3Q3+l5a7ySo0pGs446zEBOzjk1SSCxuz3oMBcX4nCzvUAczYtEA42WlHwUW96IedgvNk8m+W9qIZaNHOIKQ=
X-Forefront-Antispam-Report: CIP:165.204.84.17;CTRY:US;LANG:en;SCL:1;SRV:;IPV:CAL;SFV:NSPM;H:SATLEXMB04.amd.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230031)(4636009)(136003)(39860400002)(376002)(396003)(346002)(230922051799003)(186009)(1800799009)(82310400011)(64100799003)(451199024)(36840700001)(40470700004)(46966006)(478600001)(40460700003)(70206006)(70586007)(6916009)(54906003)(336012)(36756003)(40480700001)(16526019)(81166007)(426003)(1076003)(26005)(2616005)(86362001)(83380400001)(356005)(82740400003)(36860700001)(2906002)(7416002)(316002)(47076005)(41300700001)(6666004)(4326008)(5660300002)(8676002)(8936002)(44832011)(36900700001)(16060500005);DIR:OUT;SFP:1101;
X-OriginatorOrg: amd.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Oct 2023 15:32:32.5794
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 7a9b12ee-24d8-449f-8024-08dbcfef7267
X-MS-Exchange-CrossTenant-Id: 3dd8961f-e488-4e60-8e11-a82d994e183d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=3dd8961f-e488-4e60-8e11-a82d994e183d;Ip=[165.204.84.17];Helo=[SATLEXMB04.amd.com]
X-MS-Exchange-CrossTenant-AuthSource: DS3PEPF000099D6.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR12MB6018
X-Original-Sender: hamza.mahfooz@amd.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amd.com header.s=selector1 header.b=Cl5teZ2e;       arc=pass (i=1
 spf=pass spfdomain=amd.com dmarc=pass fromdomain=amd.com);       spf=pass
 (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e89::607
 as permitted sender) smtp.mailfrom=Hamza.Mahfooz@amd.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
X-Original-From: Hamza Mahfooz <hamza.mahfooz@amd.com>
Reply-To: Hamza Mahfooz <hamza.mahfooz@amd.com>
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

kasan, kcsan and kmsan all have the tendency to blow up the stack
and there isn't a lot of value in having them enabled for test builds,
since they are intended to be useful for runtime debugging. So, disable
them for test builds.

Signed-off-by: Hamza Mahfooz <hamza.mahfooz@amd.com>
---
 lib/Kconfig.kasan | 1 +
 lib/Kconfig.kcsan | 1 +
 lib/Kconfig.kmsan | 1 +
 3 files changed, 3 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..fbd85c4872c0 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -38,6 +38,7 @@ menuconfig KASAN
 		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
 		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
+	depends on !COMPILE_TEST
 	select STACKDEPOT_ALWAYS_INIT
 	help
 	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 609ddfc73de5..7bcefdbfb46f 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -14,6 +14,7 @@ menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
 	depends on DEBUG_KERNEL && !KASAN
+	depends on !COMPILE_TEST
 	select CONSTRUCTORS
 	select STACKTRACE
 	help
diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index ef2c8f256c57..eb05c885d3fd 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -13,6 +13,7 @@ config KMSAN
 	depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
 	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
 	depends on !PREEMPT_RT
+	depends on !COMPILE_TEST
 	select STACKDEPOT
 	select STACKDEPOT_ALWAYS_INIT
 	help
-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231018153147.167393-1-hamza.mahfooz%40amd.com.
