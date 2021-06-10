Return-Path: <kasan-dev+bncBCP7BJMSVEBBBYP7QWDAMGQELCOGJFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C3D8D3A2279
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 04:58:42 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id a10-20020a65418a0000b029021b78388f57sf15410585pgq.15
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 19:58:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1623293921; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9xcNJakxWTMDPJsm5DfJmQkzahj86HkEDecVR/BJO6uFqV0tfAfK1D4D2g5fW/xR+
         UNvuHXpOn2TpfTFV1iUDrW1tmFvdvg/4KBGoooLTDENV8UIjiHJDLqNwhqNkh6MT+ABP
         G8K0/RsZD/h9EQO7EB8vj2+sSfjy97D9X/Op87heDvjCKtRI4vwZC/vcQCH+jkYogjI2
         kefi9NLjhuhwITpG56o+N3As64doDOzl21h0+VWQGr0jgb7r0QP+mv/05ZpjqKxMffld
         BPuIsyG+W/EDma7l7SdAPTrZ91BB3pPRTKHSO5Pq9pUfr441CQE0VFKHd5VorFJyfzO5
         lmIw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=psIwIOD8JpFFzkHA1GS7RBM/giieJlCrej9L+U3HemM=;
        b=M88kWE3FEBQiPxMJ9mpX0vqph433fAok+GL6hYsx5jFZr+idpvwTjSg0hSl12hsor0
         Ppf8325ubPT6QZkfK/x/xcoFR9virYTxsJhs2AMza9gNIGlNpgYiMfk7Yn6UkBcdEl2J
         aS+LZ8nyo5IWlF/W5gMu0fXHLtQIP+qbtd9KuSaxW7dm1fPSvjez+TDqpBhZPs068je3
         c6/avrakT5wqDNVcsLBYIZkEkQOLR4HFQPbaWgL2uW6Y1a3YRnBfmaWa+wm/drFf774q
         8klUcFQg4djVQybBPwWI33vRLlFAeWj445IAcAra1uD2B3FihczJZBW3I4bWt0KstNZn
         n60Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=PXbCiOJp;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of soberl@nvidia.com designates 40.107.102.69 as permitted sender) smtp.mailfrom=soberl@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=psIwIOD8JpFFzkHA1GS7RBM/giieJlCrej9L+U3HemM=;
        b=Ub55PE76F5sb9EE6FC9sOp/VH0O2SgBdRc+uJUB7sF/aNkHLOZodf4xEdV2Pu6Gqsi
         iQbqtrCMHL890w77fHLN7h4DShHk64RuA4c1+ooyTbRxy2tmNIDjXkP/LWKbHVK7/6nQ
         4d091zxbIZvOJ6CZnjh25Lt6ZIfcf1yHfWFvGe5k13+ZA/c3U6kncF5WnNXoMhb9xyGp
         NTk6V88N+IqktT8RjO//UUF3GY0LgcoU+kqFFfa0o4NydTKq40HKWlMdt6Hx8OuxpucF
         dYdgBr2WzgSUW7ERC8bvzZ9njeCubr0rvXnZH/Mjy5ah6wxHPWAUIUhKEhiikAMn4MDB
         nxiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=psIwIOD8JpFFzkHA1GS7RBM/giieJlCrej9L+U3HemM=;
        b=kGL++duTGZESKbvgSPOW81z69Dox7zEBmgWy81uOt7eamW64kyTpObcwVT4SDB/ifh
         HuL2oUkJmT04T6QBb3WDe49bZzZPnwCO0bM8icMIXlu44WStM9zx1E0t7WLgNciS+2XP
         vp0B3pQNsuNhtERjFQ/5B1wIOBeE+MjFjHVZcuuBM11EvmjAAH+6Ej0eCh+PyGOnaE0x
         t6AOK+HPVNZxOkmZeWjkapvm/Sa1kXJMlOBODkSVNKK1mwQnUTp8I9SzGf58j8m4F56w
         2589135Rad3EMdASOY5gJ34Qlei26+qgtBJaN8FID+7QxPCCOkpJVpWo3RIvKfoPMKq1
         8yBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XUkUgFm4cS0rbnzl0NFy9y2sHVZJAE/RpAB8C1XkbEqME0zVz
	7GysJkUt550vCuinhwv2Tok=
X-Google-Smtp-Source: ABdhPJzJZm1eSF88mAa65Ll1NoYQzD/hiNkY4htkN2zAWivoYPTu06Gf7Q/Ebn6Rs1LgJJpZY9Z5zw==
X-Received: by 2002:a62:1d0e:0:b029:2d8:30a3:687f with SMTP id d14-20020a621d0e0000b02902d830a3687fmr820957pfd.17.1623293921419;
        Wed, 09 Jun 2021 19:58:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d4b:: with SMTP id 11ls2163899pgn.5.gmail; Wed, 09 Jun
 2021 19:58:40 -0700 (PDT)
X-Received: by 2002:a63:544e:: with SMTP id e14mr2837363pgm.256.1623293920846;
        Wed, 09 Jun 2021 19:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623293920; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIMAS4mSnNP/UWcbXLc5aaZL0ykE279+roAj62KkGbJXewdq61VXfUEROkggANuuJE
         sJ/v0a9GdK0t/zu0Mu/zeyexY0e8eFtdn1GjoQLzKfem8j7jawCglUEUEpJGJNp9AdOA
         of0Z8y41i46Ne9Fpgsggut71ifR8i41Agk9sZV4joDhY+LOKWxjII6KmX5bDKtISSMAg
         VrJ3ZhCfan0Kz6+gzztgMJDnk+udHBEKj2jI3fZk3LVBxQZmIWQPs69sopVAZLv4F0CV
         oPT8IdiiRSaW0lB+nl4dWckIc3WH6/x3T8xOZLiwXWP8/sQlhgGCeUxWxvT3UDdBs7+m
         oicw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=jBkyVEv2yHzfDItHpOHH2GyUyj+faw0XFkjPKh4F7NY=;
        b=Im6/eUl1sqZQmR2gwvd+3SSmDu+SS+0Fxoj4/KCXLtVWsUJCuynRgj52/m4l9aLuqI
         B/tmU9u3toZ6HN7zz3i/URRbt4XB212fi38fF7TYQNNhaxcPxZLbtsdhrLoR9U7qrq/J
         9F3GddsAt+sXNG63hZ62YkrJQPllyFqdYcOy+ZUcdWkW0HkYUxHpTZ73moHzLH00O75l
         3uXwCH44fuIfV97mTjL2zFaNI9K06DXOZ0nkBel84PtN3I84SJAQzhjRcfy/AB5olHY4
         tj/baaB6LYzAYr4H30JlDH8suK3WGCgQBzoImA8IfyhrC2a7gM9jzC3yiKs8VYeizzeS
         YX7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=PXbCiOJp;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of soberl@nvidia.com designates 40.107.102.69 as permitted sender) smtp.mailfrom=soberl@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from NAM04-DM6-obe.outbound.protection.outlook.com (mail-dm6nam08on2069.outbound.protection.outlook.com. [40.107.102.69])
        by gmr-mx.google.com with ESMTPS id b3si1086557pjz.1.2021.06.09.19.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Jun 2021 19:58:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of soberl@nvidia.com designates 40.107.102.69 as permitted sender) client-ip=40.107.102.69;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=nWYRWWyoQuT8oQOCcMzrqvEgjR2ywq5eF/iypR39bJVp1EKVhbtIq8+3UBhXSW5YZWakAvjP2j37JFV8cyjqlQjVvj94ZRISouPIK+UpmGDeL1tTECsSW9qhTzR+1LhiDadJWazU4uTt6VzsSjOpg5GO0VZQbqb5s6W0Ty0rix4ml+imUu6tnNMfgdAZOzJOOHo8GVmf51DpAU62jVafVYr45KfnE5teTFgEaLgn+yQwjfJr+FyTCCjAF1Jww6LFBF9cIlgXqwIyvRnt5APyz0nWqvY/nUvz0Zhed1rT5Mx4CmPjtKeUltKv+77GvLrsdbsy8kJvTj15oiF/WDy04g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=jBkyVEv2yHzfDItHpOHH2GyUyj+faw0XFkjPKh4F7NY=;
 b=XPOaLP1p2o7/Q6d0czGtXMFJw8ZwCh9g7fzO9zp/zf1GpiKypkTbUhzJGqHz7a23IeIhqbPKh0R/zBxEZQM2FwkPs9EJMGlB25YKKFaJhGgnNCD32r9XUWnbIHxy1gebDnh+Z6dH0Js5IBbClWUAC+1agI+Dd8vRX/Ph5IDkulg9RNExMHm6WYrAQjbLgw1kdfAY6g0cNPx9fClPzS/suz/fd/JwE//T6p8G0XfP7MuhSJ948nhdau+XmTb13QyEXk+PFnlsyvTezvRv1jJ+nS7WAWcrsoz32XJw5FL29FPExYKFW/7zI6IYwquVVp+1DASF8TRrFdPzdLGcgm/5mg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DM8PR12MB5416.namprd12.prod.outlook.com (2603:10b6:8:28::18) by
 DM4PR12MB5150.namprd12.prod.outlook.com (2603:10b6:5:391::23) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4219.22; Thu, 10 Jun 2021 02:58:39 +0000
Received: from DM8PR12MB5416.namprd12.prod.outlook.com
 ([fe80::b1f4:1cc4:5634:3803]) by DM8PR12MB5416.namprd12.prod.outlook.com
 ([fe80::b1f4:1cc4:5634:3803%8]) with mapi id 15.20.4195.030; Thu, 10 Jun 2021
 02:58:39 +0000
From: Sober Liu <soberl@nvidia.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: RE: Question about KHWASAN for global variables
Thread-Topic: Question about KHWASAN for global variables
Thread-Index: AdddORCE41vfWG3DRxWVahYduXzsrgABFPqAABk+GsA=
Date: Thu, 10 Jun 2021 02:58:39 +0000
Message-ID: <DM8PR12MB541628C0DE759463929B4442AD359@DM8PR12MB5416.namprd12.prod.outlook.com>
References: <DM8PR12MB5416B119812D7B939F9AC9CBAD369@DM8PR12MB5416.namprd12.prod.outlook.com>
 <CA+fCnZesNpTSrdnig+fx5A2_ZpZQxpN6fJwuXi5kgTVnJLncmQ@mail.gmail.com>
In-Reply-To: <CA+fCnZesNpTSrdnig+fx5A2_ZpZQxpN6fJwuXi5kgTVnJLncmQ@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [203.18.50.4]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 3a7625e8-7a72-4172-da6f-08d92bbba618
x-ms-traffictypediagnostic: DM4PR12MB5150:
x-microsoft-antispam-prvs: <DM4PR12MB51504D7689D9E8658559658EAD359@DM4PR12MB5150.namprd12.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: LaMfhlc+81i+zVuUFkQ6CiwtWDo5JW4RAWA1q3xBBLwLu9+vo3pNQWOy7NQVdPQ9gTY1n8g8AfiJngo1ybc9Re1rAFmhtBw8mmxLcgam0MSlqcdWNH2Az+DZHOX9OmR4q6u0oxPbBY8lJZEgNDPCR4XwhBKR54RFpXdPgf3kRmyqtaIi8+3jqI6jx8POucrsziiBzBgfC6/g0hn0sKWO5NPSqFB3xfjlkBFVm5YzqCMt12R2M2CZlukMA2a8vFx1qtX5D5JiO79JmumeGIvZqdUi5/UamjHriRiBnKJIV0JyqwOfZVxiXdnJpEbrtKxy8xB1QDyAPKSf6kKGoMoPb4yz9o8wJveV5bqEPxBgNpUliCEGrXgMVwJe8yWQi2ET4ImdIrzVeZNVOWlsu7u5nXPgquPTZRnau3t7gPswPtnJ1sCHM8M5tsg+mmR2UjIa9Qona0IhxW7QTYJmyzSHovVNjfWw+cdNm7UJ7bBNue6iaGAeouV+EaEORBubogCSHVFSyQKFZlWVRkwH6fmg0iqvWwNAQ0D/7xgcGkFB8Zyfaqmj57ykuFsRMgrBKwUPe5ogFvpPEzqaPURq1ltiriKPNJrhmiZC/o6gCvKsYBw26XA6DsIHOFwObzcwjwnFQbgjUZ+6TidDCnEBRb1WBPuNtmXOH4fT33+3hrY/ruA/l+M0dO1xuC4NpUvd8GIF4N0fW+hYAVxe3kcJAbyngA==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR12MB5416.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(346002)(376002)(396003)(136003)(366004)(39860400002)(33656002)(53546011)(4326008)(83380400001)(5660300002)(7696005)(26005)(6506007)(52536014)(2906002)(55016002)(71200400001)(966005)(9686003)(8936002)(186003)(86362001)(45080400002)(66446008)(66556008)(122000001)(64756008)(76116006)(66476007)(316002)(66946007)(38100700002)(8676002)(6916009)(478600001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?gb2312?B?dHdhN213NTZmRnJxSXZwVVZ4bDIreEl3d0gyUUJGRjJKUU45SlNuTUJ4NExV?=
 =?gb2312?B?K3lMVUF0WnNUY3VmdnZUeG96ejJWREJZR2cyVlU5dEIvZ0N6aVVaajhUV2hU?=
 =?gb2312?B?Z3daOGxHOWdDMzVETDZmWlVmcERiVWwyRFpuelFnUTZoVGt4eEwwKy80MzJz?=
 =?gb2312?B?KzZ5SWxjZHB5dkEzMjZ2ZmFXRVkrWDVWTXRIeUdmaDBCVUgzYVJaSmNTeWxE?=
 =?gb2312?B?Y1kybGZBT0FiZEhBOEdwamhOdFhuNFBXTHUvL1ZhSllpQmRvSjJlSk1NakFq?=
 =?gb2312?B?b09CODlZY1l2Y0MwdHpCZXNESU45M1BuUWU4UjgwMEZYSlhiYjYwdld6ZVZx?=
 =?gb2312?B?WHorakRGVlBhWiswWlRhZlBwdXNUVVlDOEJVMHNtZzlHQzVORmtSVlFEMkpJ?=
 =?gb2312?B?SmlrWnIxOVEvamhpazhtZjBtMWZXMWswY01CVWxyVHUxbTJaSXMvcHRLZVEw?=
 =?gb2312?B?LzhmSU5ySnBIcDFac0tLNFlrQTdiQWxqZDY0WVdHRkxGbzk0TFhzYktpdm9I?=
 =?gb2312?B?OXZEMDltT1doeldyL0FTZVplN1lzMTY1ZHp1MjUwYWRnOFdvRTh1OWJZNE9K?=
 =?gb2312?B?akRzUmRBcWlNRnUrcDZrdmhiTlVvN3BOZGp3RHNiVCswMk5wSnduZDNpMzQr?=
 =?gb2312?B?VDdOVXpvTUFRamVwb2pxbHR6YUh4TWlCbnUvRHhDZm5ZZTlScWtkWW8yejI3?=
 =?gb2312?B?bUdtRDlUcGIxbjVFYWwxclFvRngzSU9QZklnYVgvcy9mV2JRSGtpVmVzQlBQ?=
 =?gb2312?B?bnJVWTlNTHVudmpKdW5zMElGR2ZWbmxya0xpMy95WkhJTFY0ZWhCTDVSNjkv?=
 =?gb2312?B?WVdOelZlc0s1MnhwZk05ZTBKNFBVd2svdnErYTc0cWVQRXQ0SHY5NHpJUkRC?=
 =?gb2312?B?SEpoU1J0VVhvMVpvMGdGT0hsQzNTSENZOU5QNkxRVWFWRzRVZllYenNXaVlB?=
 =?gb2312?B?Qmd1czdoUmIvSTdRU0tVUUxybGtwaHh4KzZaQzE2M0tob3VKaUd5cHY5SnJW?=
 =?gb2312?B?aFMwTGRNMTI1eVd2RE9td3FGTkZsY1k3aFA5MUFTU09hWnUyWHNaaDBJcWh6?=
 =?gb2312?B?V0p1TWlFZmFFQTF0UUN3YytseVRnd3BYK0hTa1hrR3pEL3Z3MWNVaEJEb29D?=
 =?gb2312?B?bm1CdWwrWTZ4MXZzNEduMGF5ZnMvQlpCN0hYT0lNZDE5RTEvbHB4K1dHYXdt?=
 =?gb2312?B?aWZFc29EbER2dmZwTVRlRi90L3QrOFdzSldiK1pOYTlTUzZ3MnJoUjJEaTRK?=
 =?gb2312?B?SmovNEE0eFY5b2h3U2hiUHN2MmRqdk9NMzZDaGMxdHNFTUw0VmJtZmxtdjZS?=
 =?gb2312?B?dXl6b1pZM29nT29oRFV2Wk1iSmJUdGlOL3VlVndwcXB4WDUvdkhDSWQxYjZM?=
 =?gb2312?B?amJxU3Rjd0lialNDWVdZRDN6WThMUmhGRWQrRXFLMnFHaXRiYWZyR1M2QXpn?=
 =?gb2312?B?ZTFKb2J1RU05eitkaDRFUVBRUUtRc1Q5QjlJd1FlMWZkM2paNlpYQlVjS0R5?=
 =?gb2312?B?TlpEQWJlZTBzTGFjc3p5amtLQkQ1bnB6cXJoNk5rMndCMnRPM29ERVBsQlhs?=
 =?gb2312?B?Z1VvRkh5RzBQM1pMeWVhMzZOTllITVJWNkd2QVhBSTJYVjJtM05KeXZyK2k3?=
 =?gb2312?B?eUZ3R1hrako4UEh0UkNyMytHZXM2OFY0OENJaURGREVkL0lXdXlYZWJzQWd4?=
 =?gb2312?B?b1NLQWZmZFBNU3FNRkliRFBWaWovK0xDMENMMGJFLzI4dVExVVdnK0lvdHg0?=
 =?gb2312?Q?mQH48bedDAuThKhC74=3D?=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR12MB5416.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3a7625e8-7a72-4172-da6f-08d92bbba618
X-MS-Exchange-CrossTenant-originalarrivaltime: 10 Jun 2021 02:58:39.4553
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: nozyy1Ahnk1j1BhJV8K8iLKCzVQTfx0uNAxIJTxXqAY9OUT1//WiSS0jIg4pkTAUOTjW9rQkAaqtkHWKHjiPjQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR12MB5150
X-Original-Sender: soberl@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=PXbCiOJp;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 soberl@nvidia.com designates 40.107.102.69 as permitted sender)
 smtp.mailfrom=soberl@nvidia.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
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

Hi Andrey,
Thanks for the info.

For HWASAN, I think GCC supports global variables since __hwasan_init will =
be called with all loaded symbols iterated.
Looks like LLVM and GCC implement differently here. I have another try: htt=
ps://godbolt.org/z/1fe87xxWc
- For GCC, everything handled in __hwasan_init.=20
- For LLVM, beside ctor, 2 symbols (.Lhwasan.dummy.global and .Lx.hwasan) a=
re generated for "x" by compiler. This also describe in LLVM hwasan doc.

Regards.

-----Original Message-----
From: Andrey Konovalov <andreyknvl@gmail.com>=20
Sent: 2021=E5=B9=B46=E6=9C=889=E6=97=A5 22:40
To: Sober Liu <soberl@nvidia.com>
Cc: kasan-dev@googlegroups.com
Subject: Re: Question about KHWASAN for global variables

External email: Use caution opening links or attachments


On Wed, Jun 9, 2021 at 5:23 PM Sober Liu <soberl@nvidia.com> wrote:
>
> Hi,
>
> Sorry to interrupt. And hope this email group is suitable for this questi=
on.
>
> I am confused by whether global variables are supported by KHWASAN or not=
 in GCC.
>
> From https://bugzilla.kernel.org/show_bug.cgi?id=3D203493 (for KASAN with=
 sw-tag), it tells LLVM doesn=E2=80=99t, and GCC does.
>
> While for gcc/asan.c, both its GCC submit log and comments mention that  =
=E2=80=9CHWASAN does not tag globals=E2=80=9D.
>
> I also tried to make a comparison here: https://nam11.safelinks.protectio=
n.outlook.com/?url=3Dhttps%3A%2F%2Fgodbolt.org%2Fz%2FPqvdaj3ao&amp;data=3D0=
4%7C01%7Csoberl%40nvidia.com%7Cdf250e5b2859499fd04308d92b548ef3%7C43083d157=
27340c1b7db39efd9ccc17a%7C0%7C0%7C637588465491910111%7CUnknown%7CTWFpbGZsb3=
d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C3000=
&amp;sdata=3DAui5S2%2BS%2BE4HPZLuDouyNg5iZdmyLXs%2FFnsbDCicj0I%3D&amp;reser=
ved=3D0. Looks like GCC doesn=E2=80=99t generates tagging infra for global =
registering.
>
> Could anyone help to confirm that?

Hi Sober,

SW_TAGS KASAN does not support globals.

I was under the impression that GCC has global tagging support for userspac=
e HWASAN, but I might have been wrong. Clang support global tagging now, AF=
AICS. But there's no support for global tagging on the kernel side.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM8PR12MB541628C0DE759463929B4442AD359%40DM8PR12MB5416.namprd12.p=
rod.outlook.com.
