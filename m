Return-Path: <kasan-dev+bncBCJYVOM5MUILHEHZZIDBUBEVOJVUC@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 96A71CFD795
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 12:49:08 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-88888397482sf55327166d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 03:49:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767786547; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bi0TGcX04tR4RSf8tu8H9nVwt7zSdjjifiPJVSPYnV4cWFFpBfkWsKEDlc2FnBIYQk
         UNhjkDPpHwELoX1FrdEZS1UVMyfkJ/IDMlrg7y+EJunZBAi5Lka9BMMr443aMFBhAOJ7
         uYifjs0JSCc3WTB1qcyU/gyCn2IOzVkEVLqnj0Q85vj3b0e7HeQ7+A59GVydZl+nPiqO
         YCUK0Jz+GdQi0xOhY974/1Jnk9HW5KhdTJDX6cl2XrNDnLUiiUuVeWesqbbsc3vZs0Fj
         EIkZrVbTiDbZNYr+JdRdcjh/y2ycEF9PwUm0iplLZLlOXXF7bRXHzc6yvFzNbBWfwF9t
         YPDw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=YPKcn4sNi+eqxnlEnEAqmonJfQG5w6bDCFr2IAXYo/I=;
        fh=axlIzdN2SfEv6T67E9TUVt5mSoON0QghHtZVEUKyqjQ=;
        b=Z62uT8gAf3Nib1eG3WKDG7Sh2J1W+8pzB4BYEuH2bw/vuwA/c99t0yr4Yv0SfzLJRw
         NLTmk2Kp7XbwwSvo3e9UZcEV7kI9Xq34AD1Iwv2KzACrNX4WnAflBETjrupd85Wn/vE/
         KEm/N1BLuBp7+dREBkpC8S9ibRcs0aJWr/kF0sIkBnqaoMrFd43ocvXHiL9OxQGcf+8p
         Uhfkn5XoPOHZ0qsVCZV1mRTYwlZ5Qqn4wpGxMy1/6PQoagswHRun4G31i0BAJzPaF6iG
         6dMJG98j1DDaVw9G1PBUYIFAMWSXLqp8nQAN9Y5Xsw8q5B0sc5b3c8yxeIaadt+9xgvK
         DnHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.com header.s=selector2 header.b=bHEPmOIw;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of stefan.wiehler@nokia.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=stefan.wiehler@nokia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767786547; x=1768391347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YPKcn4sNi+eqxnlEnEAqmonJfQG5w6bDCFr2IAXYo/I=;
        b=HefNEaZmwXyw2XaZSrxKX9tlW6LWF6gdQHupHNWNTnuenRm3+ul0anfPhDDYZCv5X5
         tfsNJvj2JirdmWBEZPXhV38i/m8stjS8a7DznVFXOMOUqG5iGyYwoCLk2Gi9I+unCzAJ
         Zxcdn7Sj6mtalwtc++tjZFGnmD9VjuMupUpsruvTFx9/E3tZxtYsm/zflcBFiNeBGGmG
         6lisQIBypfhM7OIzntxaYzA1fpmnjQreEppwuCWsIIGkQjG5RMG+tQRsA2LmvYfyb9gb
         BCezg7tMdZX034dtjdQ8cjvM8+ubIlxbni5u0YfgD/TF5ckXkSjvWPCmNiiqj8sYvy74
         hdAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767786547; x=1768391347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YPKcn4sNi+eqxnlEnEAqmonJfQG5w6bDCFr2IAXYo/I=;
        b=dEe80IoLGqs82AuXrY/dS6b6YnkOLmRkb9EGeussEN/XHriEAUyeFj/EV+qNjFJSbJ
         9dRxPKpVm00ZMBElLnI26MgW2sG6SFPOzYPnOnWsQypR84zDPIPRXWAXqIkw7C9J1xIu
         a9GQkCJzw5/fzjtlF9kZCIzulj97mW4RS7bP7d4EkqxsSQ26Kdrumg+LaeQ2micge7x2
         OtRNQ1HPeP07vU5dbeb6YnRp7nSgebwPIX4iua4V5rZ8ljcx9LR3m47KSs6Es1wbsE0B
         Qpe+WgZngJqcO4WlQF1W1MlXdgmr5QKMY01V+GECJZHPEEy65+xw7+Iclci+IhFqU93B
         Zckw==
X-Forwarded-Encrypted: i=3; AJvYcCVczVQuk9l/Es8GjwFKs+877f5v0FifOY2v1amc4JiQcMAnWl1HnwZU5oNpW+2McQh8AgKPwQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywelndj01b0mYIQVIQ8laW8graRVZ3IZdAVX8sK7axsrjvNTVwP
	Fxqno0I6T4Lcra3E97HX3aWj2ZAjdm3nPcYobHn8qYMoNpB2/GwvVbPY
X-Google-Smtp-Source: AGHT+IF9Jyd1qy6sxoRihjC0zblelM8unnWPrMZGx+4gZWYEYDFZCe0LjE3lODcHaaJ8M1C1MKXrXQ==
X-Received: by 2002:a05:6214:d49:b0:888:710a:1750 with SMTP id 6a1803df08f44-890841ae7eemr26710346d6.31.1767786547260;
        Wed, 07 Jan 2026 03:49:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb4XyCZ+6pX4bQv8Gj9M4LqC7dapwbYloY+VFHZodGdHQ=="
Received: by 2002:a05:6214:f6a:b0:88f:cb33:4213 with SMTP id
 6a1803df08f44-890756e225dls38175116d6.2.-pod-prod-09-us; Wed, 07 Jan 2026
 03:49:06 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVTYTmVCQLxfeDFsdfRZNzk3WOSVLpuFHzIEr+oNkBjPrtZ7Xry53m8Fq/jsOIJGWBYwZObsA+WhoQ=@googlegroups.com
X-Received: by 2002:a05:6122:1d4d:b0:559:7acd:1d3a with SMTP id 71dfb90a1353d-56347d49792mr711175e0c.2.1767786546505;
        Wed, 07 Jan 2026 03:49:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767786546; cv=pass;
        d=google.com; s=arc-20240605;
        b=D0+fGK+KGaVifLzubLm0LKCe6Vs9WTiA9eUtIEiQUYmtuYlloSXpW/m1RU+lZFHFrU
         sT7ZZY6F+bQhY23PcIy6+Go4pxnIopw7gZcIqYJZWrYYp/2fd+cD8MkF6RLa8hzTybVZ
         7QMs624Mmyy9ZhLt35Yrq6ulK+BDW6yV2URkViQ+ImBOaVOFdiXUblYvUfhkprc3AC/B
         mHa4naGay/EhlwwUSoywnzjVScuih4pFV9hq+JaYWzc4nyaULnoyz6oHjQb1uM6fUylf
         j3n4bUg8pfNpY4Xb7/g7VC9dFXaqLK3GDhgew26Yl14Gb3DTOOUGdWTALS8b7/WbTMi4
         eu1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8LJI9lTv0lnYpcg6iCJdz7YA5sfdYuZ5D0UnYJdd0lw=;
        fh=52vaBeXhvd45nab57LGZzbzYA8csWwieC1G7501rxGI=;
        b=QkkM0Z7vgRRaO48tv4tiDS+FcUJrCHo2NSVVY7ezFZQZD5riz+kTMExWgtz5Q3pCCD
         sozYD2pPQU3JrrhmXwvb9yMFG8gNCYnT1Qq8JNd1nqu7jF3FSCwNtabq8eLxn9QQPBo7
         Vi/KVe4Kfju01JAi/jS0XNlCAuPyBzC7lHpqmIOCzdbfFiNFPNJ7ZnTzyvNm9aKSlNQw
         EvvSeknFlpHYTLvhCpfyJOoqCml9C3VuHt3BuFSFNVMrSCUT/wIvDYRFNch82yhbsVI7
         gMelgO7lnT7HBaQOMCgoUVIMeItOOdYRgIkKWHk1wYHCMKizKh7dpRtVW2fovm3ToH/Z
         QOxA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.com header.s=selector2 header.b=bHEPmOIw;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of stefan.wiehler@nokia.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=stefan.wiehler@nokia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nokia.com
Received: from GVXPR05CU001.outbound.protection.outlook.com (mail-swedencentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c202::7])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5633bb01ff1si90786e0c.4.2026.01.07.03.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 03:49:06 -0800 (PST)
Received-SPF: pass (google.com: domain of stefan.wiehler@nokia.com designates 2a01:111:f403:c202::7 as permitted sender) client-ip=2a01:111:f403:c202::7;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SQwacbrOelBn0BwM/wcvYD8q5yKinN/sxVejYynHIlDdd+RrljRlLbn3FHOM48ResSCf49uF1HZvDwgnsVzxVkcJ4Yibw1Cq8F9hk4ZXL+zIZTP4r8gzgHk5fxk9pC8uLp7jxCafdFRbLJ9uPIROHkzwKpc5imnT7SikM+1ZfmT9HLN2mQZ93U8WCKUh7JzdpMUxAVjHtW21uHmD8M3XMOQCX3pZfPMt0MgG8Vct6qif/73PePDLGB4OidQdvh2Z5dpZGWfAGsHG+3sLFbzdqRjxft6g51uWN42VPkfsdhm8En0qKX2bA6Z67dlDyibPNplSE0zX4n7fy8xc3ql18Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8LJI9lTv0lnYpcg6iCJdz7YA5sfdYuZ5D0UnYJdd0lw=;
 b=hzO3I69ZoHB9sSshKPY7U6u4SBiSu5balIIEG50DD6Gz7KWPKaxm/KXorQ+0NWrihqwMKnYpzE09Wkc4ld6iXCp4zZ2/wLxUcTtysF5CTYyrEopzqgZ8o1ZyFYjM05XtRBnDjlKH7+rOdfID6Gt0MrHAO7NAqcZ7BwD3qwTCy4nATVM1eHi01qJaNJRbGgUx4oxoqs9sNieTIRtDhG5fJoCu7H8obKhqVgqLFFreHVWu+yVaDfzC4t4V9bO/mEc1L+trYMGTMLgK9JEy2deVNraUFJHvh84xzqqwASb/9X0d4zJcxdOj/+xw1zyr8DriBgWNIO+wLzBur8d0wKAoLA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 131.228.6.101) smtp.rcpttodomain=gmail.com smtp.mailfrom=nokia.com;
 dmarc=pass (p=reject sp=reject pct=100) action=none header.from=nokia.com;
 dkim=none (message not signed); arc=none (0)
Received: from DU2PR04CA0060.eurprd04.prod.outlook.com (2603:10a6:10:234::35)
 by PAXPR07MB7856.eurprd07.prod.outlook.com (2603:10a6:102:131::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.2; Wed, 7 Jan
 2026 11:49:02 +0000
Received: from DU2PEPF0001E9C0.eurprd03.prod.outlook.com
 (2603:10a6:10:234:cafe::69) by DU2PR04CA0060.outlook.office365.com
 (2603:10a6:10:234::35) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9478.4 via Frontend Transport; Wed, 7
 Jan 2026 11:49:02 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 131.228.6.101)
 smtp.mailfrom=nokia.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=nokia.com;
Received-SPF: Pass (protection.outlook.com: domain of nokia.com designates
 131.228.6.101 as permitted sender) receiver=protection.outlook.com;
 client-ip=131.228.6.101; helo=fr712usmtp1.zeu.alcatel-lucent.com; pr=C
Received: from fr712usmtp1.zeu.alcatel-lucent.com (131.228.6.101) by
 DU2PEPF0001E9C0.mail.protection.outlook.com (10.167.8.69) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9478.4 via
 Frontend Transport; Wed, 7 Jan 2026 11:49:02 +0000
Received: from uleclfsdev02.linsee.dyn.nesc.nokia.net.net (uleclfsdev02.linsee.dyn.nesc.nokia.net [10.47.240.2])
	by fr712usmtp1.zeu.alcatel-lucent.com (Postfix) with ESMTP id 5BB271C0030;
	Wed,  7 Jan 2026 13:49:01 +0200 (EET)
From: "'Stefan Wiehler' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Stefan Wiehler <stefan.wiehler@nokia.com>
Subject: [PATCH] Kconfig.ubsan: Remove CONFIG_UBSAN_REPORT_FULL from documentation
Date: Wed,  7 Jan 2026 12:48:33 +0100
Message-ID: <20260107114833.2030995-1-stefan.wiehler@nokia.com>
X-Mailer: git-send-email 2.42.0
MIME-Version: 1.0
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DU2PEPF0001E9C0:EE_|PAXPR07MB7856:EE_
Content-Type: text/plain; charset="UTF-8"
X-MS-Office365-Filtering-Correlation-Id: c1735e89-9b4a-4f91-90d0-08de4de2c09f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|36860700013|82310400026|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?NEwMtiXI+xzuv0CVjj1q6V3vx7mqa6NWLNzD+uzpBsLtSVAhmfpH9vUxbOep?=
 =?us-ascii?Q?9guNPI3F4pKMI3joB2j//zNd5TjyUhcpdsuXYn3FkdUFMepzrZxjzZr5tzWe?=
 =?us-ascii?Q?fnNuJLRKj1RIXvS4MO2gPGVgmMqrhNWngtNqDjpgWMOLRfvcRwL2IW333ZWW?=
 =?us-ascii?Q?0fWEzUthJFUKLhLcqbRyX7WU9GYSAoOBQCzo/vR/k/YEmXWR0vFu1wTq7rV/?=
 =?us-ascii?Q?iBfL3m6a6i8qBNJ5+MRewbDh0QReYK+GN8et9w2te6wIBm2paqAn27M3JMfM?=
 =?us-ascii?Q?aVWxxBZHgLTiAkweP9fZy7jF+7viNcB+UIAi8wJfrbf1Yu/H5/A5lHAE1dj/?=
 =?us-ascii?Q?xFLZgOlqoqcfH6HFh0fdY/vLGy0rRsoAd6GytjJr+VEL1HLZ6kdLk0jRZ0i/?=
 =?us-ascii?Q?jUn/uQzlem4cb5FhlphVC6HWyxrZ0hliy2a8i7QXkcRB/tMJbvNysYQ4NoeG?=
 =?us-ascii?Q?ovYsqlvHeU3NBCOgjNsuwLu2WMa9/dC8QGmQ2R9kL9rbRrvkQqzW4rcKELQt?=
 =?us-ascii?Q?Tjk7bVmRLfNBnu4MsdRocds7W7T4nq3cNoyeIvpk/c8DZCCh376BV8NGEy3i?=
 =?us-ascii?Q?M1YDUiHohwi5lek6Q90EqkloFViULVWM3qMm5FXHnYrwbzzTTV8pIrSfJ9Vv?=
 =?us-ascii?Q?tj5ANF52XybWj0vdNio2niAJ+rKc5rn9v1147d7PrYPE/sFwT/HMY1SCjoOc?=
 =?us-ascii?Q?sMc9nXQMO1Z4JsUpVKMLo2Twrqf51VG/BZiv55VPPk7Umg2Xd0eiKwwihBvS?=
 =?us-ascii?Q?0+m5qI8ASZAkcYELlIW7XVa611ZlfrUoso8TzbinZhduFMU3/wyrXJ32a7Dj?=
 =?us-ascii?Q?Vwq4P01DWFNxYiVm0/joxfM0QGLzGEvb45ykLlyC9YcLxCDEbNGtEgO7G+MC?=
 =?us-ascii?Q?gA59uyXKfygc03pdzS2SmJd1jr3074olAL5/i8674zC1EJmWKnFQZu6qbWu7?=
 =?us-ascii?Q?gUD4s/U/zZ/QKp7nqq54BEG73ng75s9B8zbExGlHJsZ1k2NDMknEmNbqtZwj?=
 =?us-ascii?Q?9SwLxxtjGPJklySJrP9MA3DStFWMtJUsxRZyYotXZyKc5G6eJ9+uhaYQfQUh?=
 =?us-ascii?Q?JLj4N+Wm0DZTDrQKvOJT2Fs4v0W8h4j49uOA8M4NHswD9IQkdoJxWkH0I+SY?=
 =?us-ascii?Q?nWLffM0B/T+zQ0Sr6c69bdrmJYG84rYRiFboSPg7GPff93uHTewHFhpA/q6h?=
 =?us-ascii?Q?RCLvYgHLj3Q2gj0SE1UQy9m/apvqGBmFW5xkuE59fifz9v90zkcK5P0PtcQg?=
 =?us-ascii?Q?1fgQvm7xRAkawMhlouDUyieapQZVdhqfiwePIE8MJbTvfbOV98QlrFJk1G10?=
 =?us-ascii?Q?+k57BSZXy7K7KuEFgVjL+hKRa+F9Hf5xWtO/kQ2ylSBAA5e4yCqQIQwL4uss?=
 =?us-ascii?Q?VYBp//d2Xo/qdxDJ/84YgMaYRd6IMCSEb6A/REakmdlmrnhFDxZV7ogy2JuD?=
 =?us-ascii?Q?7Ab0grUxTJJnfsDJp6eUGi6Bigny12Eh8JZA43pWd+zKfuKRyJAPfqpLAMov?=
 =?us-ascii?Q?7D5XSAGNoX96buWuKL3O+4szyExN4RelWkRQUTjyb/kYo/IOZ7yuK1gsIlNE?=
 =?us-ascii?Q?pUgxquNRt9MMa8d2pj4=3D?=
X-Forefront-Antispam-Report: CIP:131.228.6.101;CTRY:FI;LANG:en;SCL:1;SRV:;IPV:CAL;SFV:NSPM;H:fr712usmtp1.zeu.alcatel-lucent.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(376014)(36860700013)(82310400026)(1800799024);DIR:OUT;SFP:1101;
X-OriginatorOrg: nokia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Jan 2026 11:49:02.1760
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: c1735e89-9b4a-4f91-90d0-08de4de2c09f
X-MS-Exchange-CrossTenant-Id: 5d471751-9675-428d-917b-70f44f9630b0
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=5d471751-9675-428d-917b-70f44f9630b0;Ip=[131.228.6.101];Helo=[fr712usmtp1.zeu.alcatel-lucent.com]
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: TreatMessagesAsInternal-DU2PEPF0001E9C0.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAXPR07MB7856
X-Original-Sender: stefan.wiehler@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.com header.s=selector2 header.b=bHEPmOIw;       arc=pass (i=1
 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);       spf=pass
 (google.com: domain of stefan.wiehler@nokia.com designates
 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=stefan.wiehler@nokia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nokia.com
X-Original-From: Stefan Wiehler <stefan.wiehler@nokia.com>
Reply-To: Stefan Wiehler <stefan.wiehler@nokia.com>
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

There is no indication in the history that such an option was merged to
mainline.

Fixes: c637693b20da ("ubsan: remove UBSAN_MISC in favor of individual options")
Signed-off-by: Stefan Wiehler <stefan.wiehler@nokia.com>
---
 lib/Kconfig.ubsan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 744121178815..1ecaae7064d2 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -104,7 +104,7 @@ config UBSAN_DIV_ZERO
 	  This option enables -fsanitize=integer-divide-by-zero which checks
 	  for integer division by zero. This is effectively redundant with the
 	  kernel's existing exception handling, though it can provide greater
-	  debugging information under CONFIG_UBSAN_REPORT_FULL.
+	  debugging information.
 
 config UBSAN_UNREACHABLE
 	bool "Perform checking for unreachable code"
-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260107114833.2030995-1-stefan.wiehler%40nokia.com.
