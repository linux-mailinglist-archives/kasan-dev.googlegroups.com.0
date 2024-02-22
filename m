Return-Path: <kasan-dev+bncBAABBDF63KXAMGQEGHXHBJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F40385EE72
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 02:10:38 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1dbbd6112d1sf224735ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 17:10:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708564236; cv=pass;
        d=google.com; s=arc-20160816;
        b=bqld6j6aCRvZfRpRBteNmIf/L65764caJcxmv9iEnM0cvEoAyQEwzfy3eX1oNu+fCA
         5uyyF3sTcO8E0SfBoizDJ4DLMRgYSgy0gTvLYHoGnzZCsMIRDEiCek49zsGgssSt/Apz
         0wFet+YmmL9qxXtoYWy5ZNcWdNLomgh3LIpGPR2HF0dGtjQEm+HJtYPAsgEGeZ40zMNy
         8ByLXcfhsC+isM2gT44Ub3mpK/2uQpAkeWK2ZrgYH6UoqyHxiVUMgQeZSM0jlFYpBakF
         EBERum2WeeZOnAXkRzXF6Ael64VefGuNzdKRynujrqIr3OjLUo9yc7cw56ov383dSAST
         xnMg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=wI5hZ1fq3pDWVDG8ZAPDhIKJ72lHIuLdX+lf2RJsmsY=;
        fh=t9sSExQ/QxiP8X0ICW+DrXQhPcOHqZInlped1Vbaphg=;
        b=hxNh1dawUw98F2gx5Hd/pDsFxedEMKwN4w4PIYUEeSMVXeAjSL+9cp/NvugFUUw+9F
         rfijNPhS1CDNWO8sBDtEafESZLa2NZWb5e8yKq5MkCLpgsMnuCLhM7R2rPsDTch703P0
         DMIOrBviNB57McsnCP1zHptHa6NrGSu3Z9gEqRlK04QyrvmyYzr1oRZJjILTB4IAatEX
         ZfBXUI2kjoOF2yUoCB6r0Qx/0b58dkh0TAtWjKOxi7ldHHZyMKFH0cBYoqGLshl2hWKN
         GeBZ4zKSVKcDObT7KwB1Sj//ZTUah5FkTt1TaRs7p+atPQSBJE0WKlorJ77xwTPFWfcV
         +K3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=o57G+e1k;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=278288f4cd=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708564236; x=1709169036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wI5hZ1fq3pDWVDG8ZAPDhIKJ72lHIuLdX+lf2RJsmsY=;
        b=hwmCNSlftrGgMo38V1jtvOnWkr3K0gUwfv9tW4vuOVgELSSOBUwDh1xuigB0Dkj4J5
         eTudwfHyCH8R6KpO9QRVKp4rtxHIqcla1BoMIiTp1XwLykFNty1JOiU+6RULXGkYrC4y
         ZDrb4dQitrXeieK4p0CWyyBD9h24pSAFVMjboA/IbQI7VYBeQ6aQiJCDEXMJWvsekX0G
         dk6vxxeKvJgtsZe+ATzzxmMx4+73SvfR+K+lL65+n330210BOJn78lP/UNh1Q8bjpm5g
         eDEp23s+nKIuxhaM8XO3rdxMEC9bOWEZMtoHQe5wnBN9C3vzCqnwQ0q+eDWlt07T4AJT
         Bx0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708564236; x=1709169036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=wI5hZ1fq3pDWVDG8ZAPDhIKJ72lHIuLdX+lf2RJsmsY=;
        b=bJGD4XHnvXTLKs/ho3zbe4uM7+3qID0oXRXyj39r8H/f1axMby4hF3JZiuZlpGUDeW
         rWUX6v+9lHYpBBT0AN2cHvibLku2FtnjX4rOytsBtSt9jHT2EiGXJMsOg4WSIHiiW/2O
         z/TI/gQzTpYiyhEPg1S8n7il+J8dLCUEuIaZMN+FfL9ObecPeDdcmVKn71uwG+ia9NsL
         FjSqDcj2e/kYpP8m4o7VOrd+5/d7bAp3J3yEY+bVnkyUXXWBGU281V8r0Njn5qAXyu+a
         TjMwB3W2odft0HC7KO8TEf5/ivRMwegorUGIKfTCn1aKjpvvjGc2TfPMajCszh1weRgm
         mbzg==
X-Forwarded-Encrypted: i=3; AJvYcCWd0MRq7wLMVO6enjsZjUr3hSTA8CLmpp0qf+exU1xA5Iqk/S3I0gZTVABTRQ1tcBIqeaCeiOXe3IjwL7E07EB38yM+qBjE6Q==
X-Gm-Message-State: AOJu0Yy5JZoDu9mTA9Qt13bgAEjfIlzMdqhEbC/Lvia//lDS6H2GuON5
	fGICRWlH8LyiUgaBMFjXy3CoMWD935bQhgUlRXTzI7sv8LChlWMT
X-Google-Smtp-Source: AGHT+IEi+MFyqOAzKhMNzLlJn8FHggTFwGyVSgd2SqK4uKWYotDAQ7L0aBP6izzMAJmqCWHGYnxe7g==
X-Received: by 2002:a17:903:3113:b0:1d9:8e37:56cc with SMTP id w19-20020a170903311300b001d98e3756ccmr398176plc.10.1708564236692;
        Wed, 21 Feb 2024 17:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d04b:0:b0:dcc:4b24:c0de with SMTP id h72-20020a25d04b000000b00dcc4b24c0dels1207141ybg.0.-pod-prod-00-us;
 Wed, 21 Feb 2024 17:10:36 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXU5C4nPlC4JONFMoZkpe3wPq29Fvu3TJM+DsLqr7tlN8ORlVdkJSU6qbigp52Nf7GP59gqWzEoVgWQFA/iQiBhuqH6YPMe8oTU/A==
X-Received: by 2002:a0d:e211:0:b0:608:95d3:43f with SMTP id l17-20020a0de211000000b0060895d3043fmr577905ywe.5.1708564235966;
        Wed, 21 Feb 2024 17:10:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708564235; cv=pass;
        d=google.com; s=arc-20160816;
        b=PlVRLurltSf3NpSDm3nY4HfJmvQINx7QH648xsrI2V8F6JAfcugl2vkgudmFghAmFG
         S/300OOTaA9nubHjKPW1zrQKOdDJUBGn0xXgz0v8CHipDGwigjwNEi+L5XETxd62pnSm
         iP6TheBLeUVGKc0V6/o7HF+JOyv7HxMAGF7qWlGmf0rXToVA9KiUizRYCfOFtDeOxT8W
         2ruJ5PdFh051cpjbB1mlU2oXdULXvw/TcKPA2vbXm34TzQYOilmwy9XIMprvN4+jaWTs
         4fUOPMmIPD1S5aVdPaojuqa4hlZvMIIDF40Qn+W7XIlh4dzh7PsFTC8TjcvFxw/IZaC6
         ibUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=RzWovPmZvUqzwJjkbYBCloIPTIZe+8rZG5rGgapZD/E=;
        fh=bhhnX54Mt+ob/1HolldHu1sE2ks5/Hdc7a7AF3o7R6g=;
        b=ayyHECY9NckzhYVUHXneTcRI92GRAG1kaeT9XXctlGRg0BxKIyFKpoX+OkBkh2OUqq
         X4fjMLbeK/igOIJLYwMrMDfNVjH4H6akPcnzp7jPCSM3hj0CkBN7q3adXtw07nRL6b2i
         efzH6I6ocAiz7p0YiQodJ5bbZ1kBdL+xL1VQJbgocPeF2AeFZ7fzGc275LAqLI+2FriD
         hcVkQ+YMGw/dAVrW4PHRpCNX13sr55l4lferwJKOUTdlCqQYrbeY5nhpdNx/ykb7ncSa
         3WFAJtCSxI+Z+mErquepmQREBsFxwURjqwU7EsvG9cNzZYbnIIl5BdXG32xpGUqGrt/S
         2dcw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=o57G+e1k;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=278288f4cd=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
Received: from mx0b-0064b401.pphosted.com (mx0b-0064b401.pphosted.com. [205.220.178.238])
        by gmr-mx.google.com with ESMTPS id z64-20020a814c43000000b0060861e9cba2si534663ywa.2.2024.02.21.17.10.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 17:10:35 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) client-ip=205.220.178.238;
Received: from pps.filterd (m0250812.ppops.net [127.0.0.1])
	by mx0a-0064b401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41LMfBkX030647;
	Thu, 22 Feb 2024 01:10:29 GMT
Received: from nam11-bn8-obe.outbound.protection.outlook.com (mail-bn8nam11lp2168.outbound.protection.outlook.com [104.47.58.168])
	by mx0a-0064b401.pphosted.com (PPS) with ESMTPS id 3wd218hfat-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 22 Feb 2024 01:10:29 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=SRAb/xTbfEmU4t2rRjptNxyFhdb5qD0RLbP/91S61DJCAv+XoisrEaK0TOiryNtQJRCfl4z+PzdSb5RgvNIMmfuMvoycs8s3YzUT/wbwy7ae5vAFVoa9XGe5TN1ZJ4EPZ8bqIvIVAgsNsdr1jekbh7D9YoXfuSwn3e4sFFyWBH5MGTOoSkWh7u2taFsMxpkhJUnNl9fjNmUVky8MYzS48dTJJuGXCpcg0/x3yKHUD7Zoom/VUHsk0wj8ydzHj309MMXcUwd+GrHtMlF44r6h3ol+JItwPhzF01jX5BWZWhI0qSzj3vm4sQoK/Am0vQZePnHRlJcLw2YByPKafKgHUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=RzWovPmZvUqzwJjkbYBCloIPTIZe+8rZG5rGgapZD/E=;
 b=ka80lFF06aPRqk1NwNLd4s7J66NUOMjA3Jrx3KlPAB6HZgGeVd3H3BlEAjoaizRk5hI7FntIvi0VOXn2CufN1Uz2deoMQ9zhvQtr4x386uiUvu4HNK2SpUCqiIGzq7b0zxZ5hr9YFkL1LlT9ZX5fR6SNHoqPXuokOeS1UgXZunkyqK7GWKL+dy+7qYHjSIY01KmdyStCecxICm3IzEy3FmJa5gNRcCq7HnEa4LCPrQDpyAzkS5r3eejoC6NVmTDRlUiqx/yDbcpkpbyFdMgPCwJzSTYNrVUXQEMIW0YxNZHUsVMxRVcE+sJtFgmhEbZSxA8sH7sHJcxDzsRUyLhKYA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from CO1PR11MB5185.namprd11.prod.outlook.com (2603:10b6:303:6e::11)
 by PH7PR11MB7595.namprd11.prod.outlook.com (2603:10b6:510:27a::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Thu, 22 Feb
 2024 01:10:24 +0000
Received: from CO1PR11MB5185.namprd11.prod.outlook.com
 ([fe80::6bca:5feb:7ff0:c686]) by CO1PR11MB5185.namprd11.prod.outlook.com
 ([fe80::6bca:5feb:7ff0:c686%6]) with mapi id 15.20.7316.018; Thu, 22 Feb 2024
 01:10:23 +0000
From: "'Song, Xiongwei' via kasan-dev" <kasan-dev@googlegroups.com>
To: Roman Gushchin <roman.gushchin@linux.dev>,
        Vlastimil Babka
	<vbabka@suse.cz>
CC: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
        David
 Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Andrew
 Morton <akpm@linux-foundation.org>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko
	<glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov
	<dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Zheng
 Yejian <zhengyejian1@huawei.com>,
        Chengming Zhou <chengming.zhou@linux.dev>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        Steven Rostedt <rostedt@goodmis.org>
Subject: RE: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Thread-Topic: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Thread-Index: AQHaZB4V5G9cauwLMUeerVHZZ0FHGbEVH8qAgABvR8A=
Date: Thu, 22 Feb 2024 01:10:23 +0000
Message-ID: <CO1PR11MB51854DA6F03753F12A540293EC562@CO1PR11MB5185.namprd11.prod.outlook.com>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
 <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
In-Reply-To: <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: CO1PR11MB5185:EE_|PH7PR11MB7595:EE_
x-ms-office365-filtering-correlation-id: 7fdcda3b-37df-453c-bb01-08dc33430c26
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: An7QVeMPPHLvsuCB5tWRRpsIMazYNtykSGe0JsCLMGihdG19/WbYSwS9QlU5wy9aJ2+TwITDyCPawMkAfY9woHhX/9npFjqOeUfkw8dHCE3WGo1nn6Zhuu9dhKElpdOp/qrodIqWYkmtp0+t2p8Fo/oywPnuvFxQCeXd5fqdOEaKAA0jproLBWU5FbLMU+WiI4vwxyrR45y8TE9YICSLF7PD4Mlm/ymgPzhob8pG/NAblWYmb+cEsm47kS3kpnAPltCnweNB6AfQ7rnzwr7MPs6YZBTD9KjyvoIqzw1UmHDuONh4zj+vDULAJlZOBxgH9gkZ8HLtprWgfPpwxm7XHy/PKhKFEZUQ/8ys2PZP57LnukPTcAQfbo6z4/rH5/3U66YVipny0Rq3CUrBj3U822DK1m0Ql6Ij81YhqzEUKxgbpz3F9c1XnDxJIaKZL2UeMinl9txwFJ/zAeEFv3h2/mcutJ+3mV48+JYqUgHeghg6WzN+rWSnDCu1AAYb6ud+WxklQsEscXzTaB/udO3JCvwziAjjbbeUpn8FQGv0E/2qU3CPJxPk+tWq+LoU3QGSzktZplwfbIBYSgYPvkGucn4vNO4NXYmn68t7ai7nhu0=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR11MB5185.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?Er60AqX8mo46Nrbmh793dQE+qaddbBEpXxIjBOmt0w7L9e36p0Yo+Q8Mqzsm?=
 =?us-ascii?Q?tPp3XLDzI0ZRjVPM032pATTYP5rbF0fEiMw1ZtYngyE1NvGCPPyZTWBqOIxs?=
 =?us-ascii?Q?ArrV3ZSMCh485kn4OJklTOUbR4hj4wJGzyXbBe5TxF55grKduvWIzcXGRo4Y?=
 =?us-ascii?Q?LY7GMQA0iSLWVvnzB0EIBuVj/jQmXhKOEkoz0AoWni0TS9K/hyJjIxpSmTTN?=
 =?us-ascii?Q?K8W5JPIJ/tuuQwrMd4j/ydCYEgHcYa5/Ew7JS8tqL1DsWVAQ7jlCeg8lpY/z?=
 =?us-ascii?Q?M1kytjz767h7s9H1lXCJE5ORona3l2bE5MIPnODx1p6aelV5evvVEPzyLyEk?=
 =?us-ascii?Q?SV/anC0MtHgQggXENeIsmNBQ6R+6vNKSQZVmZiItpwoV1dMJOSLAYFABk1tD?=
 =?us-ascii?Q?p2yKPfSRUQEwHl5keRWK3KZ23TMiHzydCNMtfMaDNC4FvGtr4m5VPEgnrlyp?=
 =?us-ascii?Q?qN9HDfe0c0MhfPZjfL4lpqKxvH4Ht5zdlWTZv63153jJwWQ61SaZ5Czk+/Hg?=
 =?us-ascii?Q?mIRyzmzC5k8lbLukKjHA72PK4mn6pVKH7/LHM07NpL6UxPHM5psv3eXL9DGY?=
 =?us-ascii?Q?/JnXdX7ClDHd7WmqfYtXmjgFlLPziUJVsriKtnrXYcaan1RxilemmUj47jq/?=
 =?us-ascii?Q?HfA36JGEBmfoiUYhkR8vGD5Bb+mOag0el1zxIdKn8duMsi8zGOZM8CWwRT+z?=
 =?us-ascii?Q?H31M+0ovfZAfSCdaczuwFa/uQIRInFqcT7cjonyUvbkKPR7TWDq1+0XsgZu2?=
 =?us-ascii?Q?sBIeBo0fnqldTpS+fUxZlrtO41e4dlbSA9oxQalFfZGS2vD7kg/rxOtWXJzK?=
 =?us-ascii?Q?SFZwoFvOrvDre7O63TMOebupept9gbRthd2CCJTSN/y0DKMeYKz0YUoGP2pU?=
 =?us-ascii?Q?lKeUuXb2fXiuCK+GLDa1W78qkKofWpYaBceEVzLqGRog2uw056RxW83Xvzvm?=
 =?us-ascii?Q?5Z/kaTRKqqPXe3OFG7MEiqoMVEZdKG6IRntzfbmWQ3SvyWTxM8aIWnz4GeR0?=
 =?us-ascii?Q?/6qDJuWMbLSr85UhxP9aFJY9XX9G68SePjT23NWfj5DZFzQbXerTyqJb/g2M?=
 =?us-ascii?Q?pu09fyt9+qwuKfCaExyrhPN/WAZ2j7kz7Ix4t+zZj9Di53LHRG/KkurGYXE0?=
 =?us-ascii?Q?K8kBXjvbWIO759WkmXspI2RsSQEU/DQWbW9MhGoqvByv8PAfkWpPHGU5vxCH?=
 =?us-ascii?Q?XJqn9t4lpN+4uptF3rxHOu5cpM2qgpxAlkwcskAWEC5DURzVvvbzaXxx0evS?=
 =?us-ascii?Q?59ZjgzCE5Jea43TaTf/Q9tvIOjAVStu9dDJEgLxbqHU2ditffxsM/wOPzYk1?=
 =?us-ascii?Q?IiBTA3xC3vtv3uyugNIhCs+tiAps68+tXppHt9L2TtFA1a7MirNjzOW97a7f?=
 =?us-ascii?Q?wGtSChbtJfhTyrr9AxSSid6pvNil3nY0pgBAl55U8gfuRsmr7CwhwJU4CGkZ?=
 =?us-ascii?Q?kI+5nY98P7vi5DZGM1YS0W0r5WdvNLLU923S9y3kqVWP0I+zWUreTNgS5H78?=
 =?us-ascii?Q?E3nbF6Lpyr04Z73Rau8XZzkFotUac9cMylAz0qGvxq16EGRVPG4k3z1hm4+L?=
 =?us-ascii?Q?ky5XLSAHajJQfjMxjtYC7LAvCyyp3V1S8u9zoCSrNPqjqYEU6bxovo+zdrNc?=
 =?us-ascii?Q?QA=3D=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: CO1PR11MB5185.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7fdcda3b-37df-453c-bb01-08dc33430c26
X-MS-Exchange-CrossTenant-originalarrivaltime: 22 Feb 2024 01:10:23.9306
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: ODxNRSoyYIHzGeKljsflMqmXhGKMkaqseLFaIs+gnr1Q116nV9mi20XtESL04tBA4HGXU+Gkpg57VB7CPrKqGK2cSgFsKlajI7LwWu/cnwc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB7595
X-Proofpoint-GUID: bTzno3AKQmfE3USkVLx3fNJnpuAmQhyb
X-Proofpoint-ORIG-GUID: bTzno3AKQmfE3USkVLx3fNJnpuAmQhyb
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-21_09,2024-02-21_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=525 mlxscore=0
 priorityscore=1501 suspectscore=0 impostorscore=0 clxscore=1015
 bulkscore=0 malwarescore=0 adultscore=0 spamscore=0 lowpriorityscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402220007
X-Original-Sender: xiongwei.song@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriver.com header.s=PPS06212021 header.b=o57G+e1k;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass
 dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);       spf=pass
 (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates
 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=278288f4cd=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
X-Original-From: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
Reply-To: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
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

Hi Vlastimil,

> On Tue, Feb 20, 2024 at 05:58:25PM +0100, Vlastimil Babka wrote:
> 0;95;0c> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
> > removed.  SLUB instead relies on the page allocator's NUMA policies.
> > Change the flag's value to 0 to free up the value it had, and mark it
> > for full removal once all users are gone.
> >
> > Reported-by: Steven Rostedt <rostedt@goodmis.org>
> > Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> 
> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
> 
> Do you plan to follow up with a patch series removing all usages?

If you are not available with it, I can do.

Regards,
Xiongwei

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CO1PR11MB51854DA6F03753F12A540293EC562%40CO1PR11MB5185.namprd11.prod.outlook.com.
