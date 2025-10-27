Return-Path: <kasan-dev+bncBC37BC7E2QERBTPO7TDQMGQERWJTWJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F9C0C0C90B
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 10:11:45 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4ecf72a45f5sf32929541cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 02:11:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761556301; cv=pass;
        d=google.com; s=arc-20240605;
        b=eWDWO2LXRGLy5+nA8qv7j/yqteZSnKgvZam8VgXpui70BzcErL9507Vm3KZXYo74rc
         c+gxhISI1fj/FlICKZ+tWCVDLPGR44r8ILmc/xPmPUzASzvDZmgpP+fDkuG9HrUHvuQM
         dExYu1SqZWTJ1GVkG2oIomr41K2cVG9onTLrkBs8lK56sbuiRMQdJg2Z2Ab4r/StcMs7
         347umiEnpobn1jFw7PhiO9PAMQoJ1joBr24uynQmCRPJJLSK8p4RMYLwj6nNwYfHAZ5Y
         TiAmhXUE4EmBCN6/RwfA668Z8SzcZWgp4FbLPILQ3zojnNjQpJ6fwlGl+H/Sr2otikyj
         CPTQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=fo6txvajvE6rGhOAKqQBMz6fQiKhHAch8GrvHRl0p+I=;
        fh=XgpS0V6NBafb8f7Z6LPDOQ0DpdLenAuZ6N3zcZ5rjEU=;
        b=daaAIacuDDZKv98eZF8iymlyZogcUIUB38AMmkZ1CNrgmpV1JmWkNe6+dZFYpZDIG7
         qHCuHbFlNevifcxS5dXTZ1SKnXmOXIG0hwYv5fKJ0iQuK6AMJkhQHJJgHx3y76zWPw8F
         j+vMkpnBXWH6zdV6u08dBI5hzfLujKsjdWkuVim8OYsIKR2ccNOjKYA/Jni9C49HTMb7
         e+WeviK1DkyjZf7Xd6kKQWjBn62lvK11J8/wVcrR8EIDE35N/7RZ41VbZApSoaXl4uQ3
         bF6GT1JnJk34THAoyKW0on4S8BexyWA8t4i/X07n1hC83M9XTnlxWo3o3xnQwnftRM2q
         jt4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=glyZgBo3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=WvfT7GSP;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761556301; x=1762161101; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fo6txvajvE6rGhOAKqQBMz6fQiKhHAch8GrvHRl0p+I=;
        b=Sn5x/WdQYjKlZYS0Xq84JqTuZkFtApmNxiiWc0d3bBBnobPFflPZ2QL9ftc36Hj+B4
         WSniJJRctlyqD+5nbirLQh+Y8jpakxCeIz5n5SoplYiWgbAT2P7Hfb9EpI5t/luiA7Mv
         85XCYwiffsmZOmWfH8Atwh/FD0HRZ4ECi+RZY9Y06/wax2ARkI8hAsS33MqiYBZZtj53
         V//ITED60iauIzM0Hj241LuP/TnJzAmPJNkNEtjRIklKu+V1ebcPhHDY/p+JwnNHWFd8
         wYUZ1AR7NDOA0flfP0HB3LTgxsruaUhBsL0VCl41bE/MduCh3Wd6BPZECy9EYyaypgB2
         UD2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761556301; x=1762161101;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fo6txvajvE6rGhOAKqQBMz6fQiKhHAch8GrvHRl0p+I=;
        b=UzRnJxqNe6fPxPRxfeNZAJLIHjwSAFkr9MlSKeqD8pj3beU7JrBjYfUJhMLHAWPkxu
         /+Jhj3K6D/5R5id6FlyahjJ79+Ss1mULafPaC6rRWJ5n25Omom66OV3gxSzV+yV7n2jz
         Wkx8l0Olw62NCrohci2gqREk1ZJyofWt6v5p70vJRUV8y67vagrJTQwdrgJxtKTbkWCX
         ttWtjCQRpUJec1wutUUG/G1c0q/CRou6H9llVwhNmQFuEFtdV3HvVkpe0PBk8Co4NvHs
         5dEj9AgWUYWbUsEzOnGTMmyK0UhOs7mg3YY+uZjc3Lqot8VMt2FW9rg2EBjuZWefliC0
         cang==
X-Forwarded-Encrypted: i=3; AJvYcCWSANrTh3/PyP1dbD9sBIai1OuSii0ZN/z/XXkDPlYd8ONjPGU94KW5ULu0jrbeWEoqvntEYw==@lfdr.de
X-Gm-Message-State: AOJu0YwJdvWFeJGHvwryqjHnrWXaI66ImVmmNm8DwROdkB9w6MB0zsen
	IWy2CmvU85IwTNGerV7CE+VMWlcTdH30QM52yzAicXNS38x97bZG9yuH
X-Google-Smtp-Source: AGHT+IGospBx3MU2YAQwu96tLvCpwH/vCNWLXu1IgeI7jmE2A6eY0mcNt+33eQno/T1xcqrMScJGxQ==
X-Received: by 2002:a05:622a:5a98:b0:4ec:f3ba:ceda with SMTP id d75a77b69052e-4ecf3bb1e3fmr38295311cf.65.1761556301418;
        Mon, 27 Oct 2025 02:11:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZrbhJ2MNDdDY42zcQfkpkVywUTRiqVeHJ6GqNE6H90cA=="
Received: by 2002:a05:622a:409:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4eced413a30ls22058281cf.0.-pod-prod-02-us; Mon, 27 Oct 2025
 02:11:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU316qSgTh/vRo9QuTunvcbce9h/EcHSeluYqUU6TT2iek3rtt0ZM7j/stHxW3MynOWJC5E7zQtN1c=@googlegroups.com
X-Received: by 2002:a05:620a:3192:b0:88e:1123:ec8 with SMTP id af79cd13be357-89dc289e6f9mr1263960785a.81.1761556300351;
        Mon, 27 Oct 2025 02:11:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761556300; cv=pass;
        d=google.com; s=arc-20240605;
        b=UlA00tYnmk2nz55vI7W6Ws7HBn+pys5acmwuuCluQodJ+EusnXxb1qzPqZUAtt80pk
         QH6CxL4Vu92TOgPCU2FyfP6NAmlHqjQOMFsw40y01jeQxDPxKEUwhfiyvbGBDlEQnJ9t
         g9V9dp7fw14R3hHJH9s1L+fggO8o2qwnhwdBrW/UJltzEb5muw50b65FAA6mAI+wPW7T
         k7PTgujahIwB5HM/G+/TUY54C0vbEclibJByW/fWh2NuZH/epg6hwNIxYyXcacMtfd4j
         /8pLiIn+Se7NQZCKnFyWNZww+/zlbjgdVh4lLVoVgRn7MgefM608mlxDCDC8yixcSU5k
         2M8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=+p2bZ5JOVzFlfB0y2/AJmzbKorj/+Al/dmO5ujwE9Dc=;
        fh=ndziwN/lmeFpSDyV5btdRc0hszqvDB1uukrSsGeZypc=;
        b=eQurj3GC7KEdhN7kWLA4U5CV9b1BqeT7tuMrBszzZQCfj+uVWfW/inJEMj/vIxjnhE
         MeAWVHnXof9xemZYIjQ6BX7sPAOzsBEaOsKQppuWA0FcavyV+3odP7+hk2aV/WBPGWNY
         a0GjFhgAYgtljJ6Hdpobo/klhRCqYDTIg6b1GNWcpeNFU20DWHWr4ZVQguSM7v1BteBj
         lhG9RAXsiF4csGqd2xstL6F3nshHQTCIamIJN03XGzGQZ4pEbxWmyWA0IAFnVHdOdmfU
         K7/ICwPj6brW9ssSTmEJxpfmNDvlEV3sPlRgw7xNTLtBOpiINN7x4dljvYxy6aQ5RyXy
         0f4w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=glyZgBo3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=WvfT7GSP;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4eba501c2e3si977931cf.2.2025.10.27.02.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Oct 2025 02:11:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59R8gZ84015156;
	Mon, 27 Oct 2025 09:11:37 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a0n4yjxmu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 09:11:36 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59R8Dbrn025790;
	Mon, 27 Oct 2025 09:11:36 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013061.outbound.protection.outlook.com [40.107.201.61])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4a0n06s99t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 09:11:36 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bzJ4n1YQAwNq9cpyx6SDWU1AfEOZlg8r/WsHbBvu2FyuYZV8y8mNlM0fDzgeGY5e/QzDbOYrnblCd2NR6ttW1T+NmMxUPLq6yOS7/vk9xp2RDnJ9pbMLdNK7wpIzL0XpPdRngM1+4iB3yfeytVY2wmjJur+WG7LCrtD0ECAiEErR6ZNIH7tDHvdNFEuFXsXcfzYhgdPONKlWTIFuUs6xi9mkbwVrARq7+27E9pAlm9VDSJo9ONMM0D1d9AG6fXH03Q//o4ESH/ck0QIbVYPaV58NDnPtGYmcjxpUGZUALvl0ywID7kVTW9iAZ9K6O948i81wnPpknpCDA3d+py8+WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+p2bZ5JOVzFlfB0y2/AJmzbKorj/+Al/dmO5ujwE9Dc=;
 b=EXFPJ7LchvVTwYkGbTQORCg94dGImwVWB4m/oH/iEyk9I0nhOFmJxrhaLpPwMSTrS9JiNxheS9oQt+gv7zqJgpfJiqeDZfo2NHowBQQM6O5LSlnNk3gku/ziHrxvggFfWoU62DLdRotGTlyzNevQCF3XE+xu9PyudRVoZP51G/b0sj6KKmuHik6+3Ui1LUIJVs96VgSaQC+Mx7w39/nKYhZ7AtBOKqXt9j+vQIwXkDsFzGMsjceayYdGdySj2Hu/txzo/745Dmy0lchML/b/wWaxClb92RIZAfGI92VinE+b/lxmm31k1cBGUoM4zXqwBpyXzBCgRpCsaxUf4UBeQg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SN4PR10MB5590.namprd10.prod.outlook.com (2603:10b6:806:205::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.19; Mon, 27 Oct
 2025 09:11:33 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9253.017; Mon, 27 Oct 2025
 09:11:33 +0000
Date: Mon, 27 Oct 2025 18:11:26 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC 09/19] slab: add optimized sheaf refill from partial
 list
Message-ID: <aP83Phkqnf7PGGmL@hyeyoo>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-9-6ffa2c9941c0@suse.cz>
 <aP8dWDNiHVpAe7ak@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aP8dWDNiHVpAe7ak@hyeyoo>
X-ClientProxiedBy: SEWP216CA0069.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2ba::15) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SN4PR10MB5590:EE_
X-MS-Office365-Filtering-Correlation-Id: 0a24a7dd-67e5-47e2-c7da-08de1538d2a6
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ohD2E/xXLw1bkWq4oDc/D32ccCFhyoSgovk2EfDNyc5rLgMcNX05Ur6aVvOr?=
 =?us-ascii?Q?x9vK2uQmgLM30ymOQ3KXmeFkg3VHrbskPDb9+zBcWe/3ATD/jF/GsOq+ustC?=
 =?us-ascii?Q?9t187XNRQ3Sf/SkNssA3gMcyO2nxVojB/Nk7vFPvGMP5rWjBNg9o2+NzPqEz?=
 =?us-ascii?Q?audKlDbg0komS2FInmYPANBJ+vYEUzvchQtIkcdgcVjZfn35TE+FmNWCv+WE?=
 =?us-ascii?Q?wHZnaLs2MXgvlwmXtqgl/7rdJ2kJFRySO13w8Jaic1DGfR0b5heMALwJoy9P?=
 =?us-ascii?Q?7yijLUe0jWBe8+XdgXYADkh59bU3DN38mcuYD12aCe9LIbW0KJOZnU53uxMV?=
 =?us-ascii?Q?DPZg2TqvN4S4MoJRlv24Y48LvVSVzWMPntrUSpKFPDBBbdogOqnrleWUsW//?=
 =?us-ascii?Q?1U5c+eX7tVDx3wf1xHlM73aogNTatSlcj87hTlQlfsaw5VNagMzYoO4dl54i?=
 =?us-ascii?Q?FDt1XTakBKD437kAJxgxzvc2wwOSMpz9lLqbGEDawRZhR9oogvodIgJ/xCYj?=
 =?us-ascii?Q?HY9nd/oajZnfPbvMAuso6lujjo3E8bqqnRaJbZzUVR/rGUJBxrVFPouANOGz?=
 =?us-ascii?Q?k301ISsnUjzfH4LDt35KwavXFswVZ0eFTXt9ldVWA0XryFqss2BvRyohA1YH?=
 =?us-ascii?Q?rD+hAVx5Db16xMSgWijOmmmhnjuzdHWavdkqvLRBAzNLz97NOWrmWzMeBYDg?=
 =?us-ascii?Q?n2a48pCDCbRqfIpIxo1WHszs5f396EUAoTt0b8LkfIAeZiqfn5zYVBurtr5j?=
 =?us-ascii?Q?X687aYvMaobZmyrtt1y8ZD2L1p0fYHOBwOIxs/sswIo4yGeUO4vcgOkOguIU?=
 =?us-ascii?Q?TinXOEGODjdZ6MD/XIEvATeoXdezg4dOLlWwh6bctBMj1eaNcOTYs7a8Y3JG?=
 =?us-ascii?Q?gxi8vwuXsD+Gz5p7wNLnkc/7YNnZUmfscl+XXUbiEvyxgZyhEfWfnD4IH513?=
 =?us-ascii?Q?VsonH1w6Rti7aHix7OxKOngghd7xPQg9qruW3glbbXzfbukv5iU66qxQZueb?=
 =?us-ascii?Q?EZMErDb7tZV5cVMmFO1xqwIjI/JBGS8bfJqfAQL3Vn5GxbUC8x0bimpRIqAS?=
 =?us-ascii?Q?1eSq/Z+cyKfP5R7ZvVRTMN4xr1w2Im9/XDOZIj6L2CRRF0MTAolIHTUVMgnd?=
 =?us-ascii?Q?xDFM4hACCUree/PeGW/+hfqA1wqUKWNygefQyepHDsJsBPjPAWw1ZbmriXFy?=
 =?us-ascii?Q?GNlDnnFVpRTP56BFApPOEmmDu2tPQsbmRPKIOTXS0J2ISEHV6kT6n1Bd1HBW?=
 =?us-ascii?Q?yUbqaXHdIzaCgDmstpulUp9ku1gbSTlPNxaT35sPHTNcYMIdIImxkbZg5Ycx?=
 =?us-ascii?Q?CNnoX7Wz76iug5X4g7EeOtRKWb39LicQkNQuwny5/8sIzBy2sjpP/LINpocS?=
 =?us-ascii?Q?BtlpL78jgi3oBIv3h044SoFVLoJ5c9GJBNbQx5iRfhjED8qi836yPP+KfGp+?=
 =?us-ascii?Q?OhY3nhKgnWAV83CMH63pysvIxm/PPn5V?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?bnPMPHGXkDnK9LgNFVZteyzmwpqPMhRvizycTs/DUwf09OOFNk95qaZrbFgo?=
 =?us-ascii?Q?vayQfiy8pyFC1PzpcVE99rNVQ0mnGsJwU09hNMboAsA16IWi664YRqiEDetu?=
 =?us-ascii?Q?SqyQGbEs8gkMPOHzKQchNrPzgUP+vgl9gFO3FFjHLySmDJBk2LVuH9ZH9Ull?=
 =?us-ascii?Q?XsFVsGoNip2sSMeDQ5/yFCKLlbcTfyZuTgVnyjsm/fLQMvvZLJLIVJndxAWL?=
 =?us-ascii?Q?uySMZxO6AnjNJ7GmysravAPgu2kb74QMst47t41rj+D0KxPhqxHuWp3Vy0iQ?=
 =?us-ascii?Q?bhnIPHV69q6OClb2jPMPKL4sVB42VHnG6MA7ul0Rzw47pE1A4OJJFBzrgxfY?=
 =?us-ascii?Q?um3GTijr/cbI3S0ub8ia6JBHGY/t9nuQiiSbtfHpk1497H4Rk7uCZYHgukx8?=
 =?us-ascii?Q?WGVDiUrRmVQlVxSykCKK4edryDbHQEJVZfo5O/c2gSGNFbrh5ZHs1Qtv3aZG?=
 =?us-ascii?Q?2hhIy1NvcxAzKzVwFBxKHSsEEg3Erqph1ifTQGDNFte/X7sqTnR7mS1JVc52?=
 =?us-ascii?Q?VaIRcWsom6t+pdkH7NPZy53jZh0C6hZuLcw4GyCgJoGQna16eLmc4NCxFMlk?=
 =?us-ascii?Q?uZDfp9n2FQ0uj+BoNn/XwWvmO6VqFiCrYmT6IVsCGPgYJPl1Myb8LUxvBm82?=
 =?us-ascii?Q?p7/eD25xhb6VkPrwSt8UkCjrjCbSa8qc5p63QIhtm8e47DULyq27MQxg01eh?=
 =?us-ascii?Q?3iLe4XIuD8YcRvxD8OKRGl81k/DynGIX0g6gCFu0uTGUAL5VamYrDrre6Ls9?=
 =?us-ascii?Q?WipJgMLKG9TySg+Ll9w+CEKoWgrhul9ucVkU0jb7kqvPE9wYRGPhsO+KVuGb?=
 =?us-ascii?Q?qa6rptKn5CC+fLhRCUWafp6kAqNj+QITBEIgMUD5tJOHC72PrCSfB42L7lJx?=
 =?us-ascii?Q?KKEKngq+ppBGYJ+o22Ddx03Rt+WBAv25JpO97hzm3p2QnBgD3M3UEwr7+LJo?=
 =?us-ascii?Q?6EU8SeN2E7rMbEb24Af1Gg5ezlwJniBQD65ITUfurNuYaOVKGNLoWoQjpxx7?=
 =?us-ascii?Q?IxnJZfO6EeNL3NBwx8jBXJQVtmoNsqkeKUUNMuD1orpZ9SI58fxXYwteYNhT?=
 =?us-ascii?Q?lk9vru5QyhJ7kBjlX59Xv2ymUi9sEfcS7opWFKM3eNNpa901tRLQXKdlQdDi?=
 =?us-ascii?Q?0a7bdwRCUCkovTEgKa8qmbEJ6abXJs1r3HMt7Yv9Ceae3w0GgQHyqgjtELsO?=
 =?us-ascii?Q?LfzSIVKBEgrkxzbhioVPD1Erlb4QGCoO3acdqm/3IrkPLx/ctmJzXhkCuKoz?=
 =?us-ascii?Q?JPxpIrgGDKX9wL3FD/apzwD+9aYhe6xOzH96meFTCCaYrkjJZJddpT+0WK1M?=
 =?us-ascii?Q?GMRSnG5SVdn5cVVCzUjNwWESnlAGq3JFuQnCgFdJ/Dwk+8n173WEu7UVfmt2?=
 =?us-ascii?Q?H9rr79sYza34jiSHgRdJw8Dh//skRrSJefth4uOfWl5587CI5Un+clSDCZrK?=
 =?us-ascii?Q?el3fnK6i46cK8q31i+e5NQJ3YuC+tUbLIAhKN9xUeuFK/NsDHQ3Vciwn6hEV?=
 =?us-ascii?Q?PiJDpZq3+cVqqJh7egTmP9F2ep8uoAFUDdswg0sVtFL8BubhZl/Bx+NBKKiA?=
 =?us-ascii?Q?OqgYE6k4QFlnq2on/IwzRoQQSZXq30bvOZ9cz5oQ?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: glIikd305AGz3D+sJS18HT4Q7fhMhj64B/hl6fCSJWLKj8uw/qnzeW1SESy5nQeurr1z24xzgvPN5B3u0pZRNAT/COymrNBO2ch0J1zACY5189dCn/GOvDJKl+5KFKQQnmO1JjDFwfe2Oyes40DDDt1j/4qV72paahaZ2WpXxpcE3BbJTTDWnRVEuZPmjOlrE3d5U8A1FnfQZA5DTil208iejPtItJWUMFPFiZ7n1lzuX89u9QrROssT2F5mYnQWB/cWrUqPKqg8ZA+9ZfIDRQFDUUyXn2d4rruoPB2GGjZ3pzvZ5tUrmSos89ULRDmIiFV7I3QW3l0Oa6JRVBTu7C84OlQdmQxKGwSE5e3ht+VJHHI2df1xWCOtIvhG36JsXomWumnvR1lzCvZpGXlH3HVC5R6f/GSXhrBpQ22H3MhPkRM9HexIxtEVexpAKhZk/yWY4SChjVlR7GdGEXsE/kdAC0yQFQ4EyZFvNnxZKhC49Foo76aHhKEFSEz/tRn8fRdpb3O8EyRxSG9GPwJ32+r9UrR4Do/P2t1k5BYvQ3Lyu7zC+rNNsYEZekJbGTQ/hl2XXzwPJlslPA+8mjswqzeTb/G8ZccxVa+SIQjNIrs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0a24a7dd-67e5-47e2-c7da-08de1538d2a6
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Oct 2025 09:11:33.1515
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ttTz9iGb44/LT76aDNEAjv9nVEW08Bu7K16OjHBP/mGL5u7kPBWlIrxhAJPlGaw9RuYZFMD7AkJW8hUpCr5wKQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN4PR10MB5590
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-27_04,2025-10-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0 mlxscore=0
 phishscore=0 malwarescore=0 spamscore=0 suspectscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510020000
 definitions=main-2510270084
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI1MDAxMyBTYWx0ZWRfX0nkH+/eR3NuS
 MLGlaetuyXEYH85hefohzAEJOnGtbo6PaJkxA+bfzYgdzaiVFHeJEsjtCG77C89Kmu2WbzCKBw2
 PHwY6F2qoOqUBSFf/S3nXhMQGPS2GVJIcoP78JRyImEZacGrP4ttjIge/G4fQ8OsABhGYxwQLp8
 DloK6ftRTqJwQ0MWN7sWk1td6q+zxrLjSFDjQ/p+eF2hzHLbui5Y5HYUI0LAld8xKI66HY4Kj/G
 RDB+HQA3hodCoyMsat6I99QZP0yj175WQC8HFK6sneLMHAf9ntrElHhjBVqmPfWz7ujb7fRN831
 IsQoct5mrouhF0SPakJe/LAFZkXszGsG+ckv7bBqxM6KF6SsEReRrqHpPVyDDLRUrrZh1ZPHajS
 RYWre1kZqfkRejrL/dYDW++3sPIGvQ==
X-Authority-Analysis: v=2.4 cv=Z9vh3XRA c=1 sm=1 tr=0 ts=68ff3748 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=AlIOxi0qyfaPRz1eFCsA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: WZQna4yTk3B00cLETsXQvNxUQG95lOmT
X-Proofpoint-GUID: WZQna4yTk3B00cLETsXQvNxUQG95lOmT
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=glyZgBo3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=WvfT7GSP;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

On Mon, Oct 27, 2025 at 04:20:56PM +0900, Harry Yoo wrote:
> On Thu, Oct 23, 2025 at 03:52:31PM +0200, Vlastimil Babka wrote:
> > +	if (unlikely(!list_empty(&pc.slabs))) {
> > +		struct kmem_cache_node *n = get_node(s, node);
> > +
> > +		spin_lock_irqsave(&n->list_lock, flags);
> 
> Do we surely know that trylock will succeed when
> we succeeded to acquire it in get_partial_node_bulk()?
> 
> I think the answer is yes, but just to double check :)

Oh wait, this is not per-cpu lock, so the answer is no!
We need to check gfpflags_allow_spinning() before spinning then.

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aP83Phkqnf7PGGmL%40hyeyoo.
