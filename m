Return-Path: <kasan-dev+bncBD5IVPGEYAJRB2PL5H2QKGQE6JU3ZWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A0AB1CF225
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 12:09:45 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id 90sf6633577wrg.23
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 03:09:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1589278185; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OmS47foJyBoVNhl6pudE0GZ2Z62NSfikSwY894ucUW+6R0MQXv2ZmtJmanHmmmfAX
         whozh3oL1GjlenTKTSEo33JdUFCWWKRVNdef/xRpuVurrzMnJsgGXFP3pnbuDdNZ4wxl
         Hq7Y359ber8dxlCAGEQSWHpa0xh1ez9lkp55nC3o/0PLm73xaSc0hYKQiTo3h53gLGKM
         937Kz780hKMpiFoCsdwM4TRDErxIt5wxs8HLbwV7b9UxVJv1dBmBzqJQv3mapCqDCBo9
         4bLTgR0Rpz7qZ2Nx1gQDeT/9UKUD5hSzPomgdKcCha9yXAAYpElNhRCmoh+dT/IJr+qQ
         eupw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=Pm+h5CxzXCr2WYw2yEhIQvWuPlVHqZVN8c7qD7akfO8=;
        b=DENyKwh5I34yhIHfQEVRz1PewJvhH+Y5dUvZfdoE7k3bgFerdC4oNEqtnuQWs2irEF
         7+u8x/pjJ+1l1/M/XYhhqUi7vm+vmiawJoike2iwkjZGMndIgaMvgczwualkteVLVOv3
         ptHa1SrqhfwYLJ9XY37729Myq0Hn/M0aqGzbOh/xtdqlqk75C0YxNVUfbAa0bQ12GIKp
         1PKDIwVNKb8PIqJ4azyLgGr8KZRqLmfPqb092F3ze4IRMw7DBgImxlUX1WIYh7C0XH6T
         lFWbL7BCCgd1K2buN5rPdA9JeIcJBcBw7FGnKUUyapAKjZz1BwKW8QchvpMr8KED8lao
         l22w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Mellanox.com header.s=selector1 header.b=GOYRuq3y;
       arc=pass (i=1 spf=pass spfdomain=mellanox.com dkim=pass dkdomain=mellanox.com dmarc=pass fromdomain=mellanox.com);
       spf=pass (google.com: domain of leonro@mellanox.com designates 40.107.20.57 as permitted sender) smtp.mailfrom=leonro@mellanox.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mellanox.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pm+h5CxzXCr2WYw2yEhIQvWuPlVHqZVN8c7qD7akfO8=;
        b=TT9M2zuiNR5VZ2Gq+h41ig68FrmMzaWqF962QJGf3+bQORcV6ipS0vi19SFtr37C+a
         fOMZRdXUG3fMWNsDP1DXE19qJhDqrvoJnrA3LExqOPhCgbgm+A8TRvWELrFdAoJ00/UE
         IyXNd+Xd/hIg1YWZvVBElWJsjAOxfKrUgtN7MJfbnRT0Xef1B1YA8BnQUAzFvoJ6B3oM
         pUbfxeEOGWmoxZ76wYwnrWNId6ns1KfMPTjlgHPySdqhju4GxSPP5/uXL/u3Y73ANu8Z
         6hdWUHWlkP5tpfW3T0E0sbRZM9z2GMrNowwtkvnbkrfSCSidcfr5b7EIhHdB4cPYagp7
         n0GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Pm+h5CxzXCr2WYw2yEhIQvWuPlVHqZVN8c7qD7akfO8=;
        b=ZUbe3Uuanw8FpebwzYwg/g65gftgEW9q669dowGe+OjAySDDVXskuyeRrYVWPdR36N
         oY0FejinWHeCsPr7MsGE8NHouaN+TYCPMhYw3jTqzneBkPkpdUSlajD0PBGasigL4UBc
         7dTD3NLXS3R2QGEOrtCT+lxjEWdJFTZ3SiQvTSCuqWVBLuYIfpFx24ldNG1nncGZ2nYQ
         Z+ECgwOfOnLI3qgWjbdmLL9DhNEwcsfqTinBJ3IHek9cqipXoK9/fD2Qd6FIAJ/iilsw
         ETh/Sm+ucgNGOVHxKaREpuNgsVaA8IV5psBojgIpuoLV7WrGc4Q+iOIaJF+sDWyJkYdW
         m2zQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYKr9puI8Dcfhu+9E9nk7K3y+/SHOAGblJzJ1HSrLBAR2SpDF6t
	iuDMguYwkVqUq3d22xuXXPE=
X-Google-Smtp-Source: APiQypJmc+wklYQ3ME6X3oFcz5Tkt8YAnNESfVKi+NbqbLmne/R5wiV+xad7NXs7lXPXO+h3pJ8G5w==
X-Received: by 2002:a1c:2b81:: with SMTP id r123mr36238193wmr.34.1589278185275;
        Tue, 12 May 2020 03:09:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:9:: with SMTP id h9ls7878745wrx.9.gmail; Tue, 12
 May 2020 03:09:44 -0700 (PDT)
X-Received: by 2002:a5d:6144:: with SMTP id y4mr13297910wrt.185.1589278184773;
        Tue, 12 May 2020 03:09:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589278184; cv=pass;
        d=google.com; s=arc-20160816;
        b=j/FL4YLHV7VhZPvU7qKGnMdJTUXvFvPCm5o2k3A4pnVh5DZ8SzASNGlMnBnzRBYWe4
         2xlELQCv3APh3SVctbujpVRkXsAMCckhKUFoiGBM+iOfQUBajWxxSrqfDFpYfxa259Zw
         7Msp7mdwQcv0JnJUHtmRfnXEE5gF0a1zqLIz79pRpl4Mp/AZig+6Rs9knMRXUoLZd3tb
         dOvXFOBwmXLZADiqBwWblFg27PM5RKm4IdGyqU5CDMVFdk+XpZBgCuidlpKAhGg/GBto
         21n7nMz91ElhsZTVioLwqoDSobTzrCROMNoLBu4bHHq9l6RBNIBT60NWJgUnhNaKwndi
         Z2SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rFkQkgUlW2AmGjwfOSn5kwX9+ZwjPY2rffOeSZOViCA=;
        b=uyt/npWsuzQB1Cq8WcckZyVZfkMIQ3h8bKLX65mVM0witOIgjQ5ZL7fopM4fISOW9o
         3+mri0APSFLki8OgTXn+rAW0iQl+54su8AoE2OHZ304lAHUSD3J5SK0Ky+sNbpC58OWZ
         rII5dqR+YhuWUxgCV1QHovgRSsJws4uzYljXJIxqxpCF5ebiOn9J3conKV3NKZKV4tD7
         /FceVgB50hjy3vALVZ6gkvqPrA8V392HRN+P+sYYbR14Ibs84y/pxLWqFF9u4ARsyWn2
         fetAtf2Tg7rItFxaXzcg243QjTSXGvw3Xgl6LMip2XXi1mS7WUT2ohPtVELNmQiIC7yS
         4zGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Mellanox.com header.s=selector1 header.b=GOYRuq3y;
       arc=pass (i=1 spf=pass spfdomain=mellanox.com dkim=pass dkdomain=mellanox.com dmarc=pass fromdomain=mellanox.com);
       spf=pass (google.com: domain of leonro@mellanox.com designates 40.107.20.57 as permitted sender) smtp.mailfrom=leonro@mellanox.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mellanox.com
Received: from EUR05-DB8-obe.outbound.protection.outlook.com (mail-db8eur05on2057.outbound.protection.outlook.com. [40.107.20.57])
        by gmr-mx.google.com with ESMTPS id u16si1195957wmd.2.2020.05.12.03.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 May 2020 03:09:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of leonro@mellanox.com designates 40.107.20.57 as permitted sender) client-ip=40.107.20.57;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=jJMLlC1cPeOr/QgIG/ZlPunvVZR2p3CygY7bGt7Q7uCDp+6wT6iLOCVxiR1uyFECaXDKEWHlKSjZoywbxlhLa3R5sxcJhajCH8Bz8/gyHt0A7U4E/IaAIqQcASoX44wArWeqomPfbrtETD9qwPIUZknV+PGHEM52WnCgnO+jPlPvQCk5F6X5e2Sz3TAisBN21GbEz7Q2ap/bbgtVWiYfnn2hQy93owa9lQeLe/WiW6AIO0nhFo9lI7TGETrxmCWUqmm+4ttOhzsYZvxKemZLVh75k9fga8I1h54bwf7ClFwQohl30PlRrxOxmmADFRkMBx2Is/vYgV61siGGlGiikg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=rFkQkgUlW2AmGjwfOSn5kwX9+ZwjPY2rffOeSZOViCA=;
 b=LKgREaf1CYXfZKkCjDvRqf85Iu2D3rbYHI095Ra2jKHLZk2DLjMJ0SHMRzWI8jILkP4dTgHXDm2FunIuvOLJ8F79jMJs3H8Hhv88VEsqu/OZ5jYRHcxh5jwbB8qzJj+RgdtSeYl7ahA8iyEEHIRRu0MoiyyzRmOvPoM9PJEQ2MKmq5rOVLpJk2jRSc00dJLlfLBPyBFPtJiEBrsY9bDhkONIWeWyAsoQxJ7iolRz6xqecM4wMTTzFF/J5/uc4BQKZXDppMsabxC/KsamffbaBQRmUx4yePL+75gRTEH9tbeBnxyP70BDVJkVZhR3SACti/8dhlJcB9Aox2tCLAasSg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mellanox.com; dmarc=pass action=none header.from=mellanox.com;
 dkim=pass header.d=mellanox.com; arc=none
Received: from AM6PR05MB6408.eurprd05.prod.outlook.com (2603:10a6:20b:b8::23)
 by AM6PR05MB5379.eurprd05.prod.outlook.com (2603:10a6:20b:57::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2979.27; Tue, 12 May
 2020 10:09:43 +0000
Received: from AM6PR05MB6408.eurprd05.prod.outlook.com
 ([fe80::1466:c39b:c016:3301]) by AM6PR05MB6408.eurprd05.prod.outlook.com
 ([fe80::1466:c39b:c016:3301%4]) with mapi id 15.20.2979.033; Tue, 12 May 2020
 10:09:43 +0000
Date: Tue, 12 May 2020 13:09:36 +0300
From: Leon Romanovsky <leonro@mellanox.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <adech.fo@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Ingo Molnar <mingo@kernel.org>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Michal Marek <mmarek@suse.cz>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH rdma-next 0/2] Fix kasan compilation warnings
Message-ID: <20200512100936.GJ4814@unreal>
References: <20200512063728.17785-1-leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200512063728.17785-1-leon@kernel.org>
X-ClientProxiedBy: AM3PR07CA0056.eurprd07.prod.outlook.com
 (2603:10a6:207:4::14) To AM6PR05MB6408.eurprd05.prod.outlook.com
 (2603:10a6:20b:b8::23)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from localhost (2a00:a040:183:2d::a43) by AM3PR07CA0056.eurprd07.prod.outlook.com (2603:10a6:207:4::14) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3000.12 via Frontend Transport; Tue, 12 May 2020 10:09:42 +0000
X-Originating-IP: [2a00:a040:183:2d::a43]
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-HT: Tenant
X-MS-Office365-Filtering-Correlation-Id: 647f244d-d82e-49d0-8e5c-08d7f65c971e
X-MS-TrafficTypeDiagnostic: AM6PR05MB5379:
X-Microsoft-Antispam-PRVS: <AM6PR05MB5379F2737C9E86093E334A7AB0BE0@AM6PR05MB5379.eurprd05.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:3631;
X-Forefront-PRVS: 0401647B7F
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: Vkq3mV0PYDIXOr7OAcYhoV+gPxU7OkLA4cv0PDIepDmpbPWhkbzuba2NSz0LhYP+9LY8IiVxItBxESp5wVvnFAQwKxh3m+W7dGs96w0ytWgIAVX7ArgjarCJbF7Q1rwYdP5KATaa+wZl7pMvU0PeX1UsgeYYAL9ScYVM2UBXHr/B7BuDnYnNIeiSr8yNlLRR0FYaNFtwKNNBjMbb25oahOYnfeUBgE45xGIqhefBSyvrFPfz0brQJhCn3Rw6Pi/IYafTK5n+qohlGCFyubOd7El5TzNBDvu0yYcSnQDSkd/eny94dSD41DH79jI7vVK4WN3E4OUBhLvzLruC9uLu6Af9OzAcb6w4tH6zSAXndzEDXW6fxSiYFi4HlPJgT/cYL92zmUS+AvizMJvFlQmASUwWH52ZqSLDTft3nIFB4YC44uWt5W8ihoPXmAn3QiiuAphG27GDzacRTZ7dnkhHRzV13vTuoV8biMAeZPEErc7xJYh2cvd8B/0b1RVlb1JpqO7qg4v3G6t60KoRdxCJ+A==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:AM6PR05MB6408.eurprd05.prod.outlook.com;PTR:;CAT:NONE;SFTY:;SFS:(4636009)(7916004)(376002)(396003)(136003)(39860400002)(366004)(346002)(33430700001)(4744005)(1076003)(4326008)(110136005)(5660300002)(316002)(33656002)(54906003)(6486002)(16526019)(6666004)(52116002)(33440700001)(186003)(478600001)(66946007)(8936002)(6496006)(9686003)(86362001)(2906002)(33716001)(66556008)(66476007)(8676002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: AydzaXdGbyxpKz3wnTvoZeDjW55nJLimufSBx1AUu5/2OuJMO0QnEr1bIRWZB1LtPjQzCGt0R6r78rFcFzXKDl5U6g7Vg1Y4MspbA/9bM3QDezwFa4lUlzgQI1oFKWwoVgTeCsqr4unG/YSVdLHH9m/ww5UnCeQXwrv4HiTM0GMhgVx5QdbrS/q3lXj1RICKU6RvJeCna4lRLUqi6bDOvscQOVbaZHXLwB3Mci4o5VxYR0doUw9SSKXKw9dD4dHwrYT6KtgvI78WuAZFwsm5IXG6GrCEVIuXVBAoItIfIaOC+SkUTBs8r2khlw64nPVw1EtVpoBwPsf6M9pQEZO3f7OV2ag+SFIofrp1eGxE6oiP6gFIciZl0j/2TfDLlyeJt39iTaSpWp2gX3YL9pWtPmIvySNQGgVg+oQa2X5ZONzYzvzzWZtcGEMTY2Zuj6TP6vvMyOyetq8Z3PpMnCMC/gpxDN840/9YAN2uEdYL5g3xrCfkIktNiNPS0uLBgUolDzW9XZOC6gGgV7buC6nkgg==
X-OriginatorOrg: Mellanox.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 647f244d-d82e-49d0-8e5c-08d7f65c971e
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 May 2020 10:09:43.0400
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: a652971c-7d2e-4d9b-a6a4-d149256f461b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: U23lSluncczgnM5D1/1pPsqGez/QA6C2XSO/P8LrcZ1vxyvKDuMJ2G+xHcDiOgqDC0gLOIBgZGf+WXwEgM5y2w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM6PR05MB5379
X-Original-Sender: leonro@mellanox.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Mellanox.com header.s=selector1 header.b=GOYRuq3y;       arc=pass
 (i=1 spf=pass spfdomain=mellanox.com dkim=pass dkdomain=mellanox.com
 dmarc=pass fromdomain=mellanox.com);       spf=pass (google.com: domain of
 leonro@mellanox.com designates 40.107.20.57 as permitted sender)
 smtp.mailfrom=leonro@mellanox.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mellanox.com
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

On Tue, May 12, 2020 at 09:37:26AM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@mellanox.com>
>
> Hi,
>
> The following two fixes are adding missing function prototypes
> declarations to internal kasan header in order to eliminate compilation
> warnings.
>
> Thanks

Sorry for forgetting to clean subject, the patches are not "rdma-next"
but MM related.

Thanks

>
> Leon Romanovsky (2):
>   kasan: fix compilation warnings due to missing function prototypes
>   kasan: add missing prototypes to fix compilation warnings
>
>  mm/kasan/common.c |  3 ---
>  mm/kasan/kasan.h  | 15 +++++++++++++++
>  2 files changed, 15 insertions(+), 3 deletions(-)
>
> --
> 2.26.2
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512100936.GJ4814%40unreal.
