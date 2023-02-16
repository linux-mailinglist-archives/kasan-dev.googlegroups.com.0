Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZFOW6PQMGQEEQQJ4ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07033698D9C
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 08:12:37 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id i13-20020a056512340d00b004b8825890a1sf604423lfr.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 23:12:37 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1676531556; cv=pass;
        d=google.com; s=arc-20160816;
        b=rynKAYsAwMALbfBtlIpMz4Sf0O2qvSOq9L1zyCivr6jEyE25pM46Yk4k12lptYvQJU
         7xRx7pIUt7mQMy6a0EquiFBbjVFy64LM0+jqDWiG3wyZGM7L4UPnLtr1R0Dg1U7Ot3gB
         GrqZIyFVGt1cvaDK/mSc5DmbB360AxM7sujLL5QLd8VhgIIDvdcY2eRekVFQbn2kb/Il
         6i/cRBEsttBCYE29vgAkdejl94bWC4c6wSSKfRVZOjfeEsOR1taELvL8YPySN5Q0sUcO
         zQEmNj5VjNx96/w0cHnZgB1Rq0vuRyXod08gyO5yA9BVT+R1g5+NARNUWjhXcXvcZhr5
         YNuw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=pcW5uKtWnvRLPIBh1S34uqr/y/J8YW1adscyjBGWXD0=;
        b=A1BxRzSWGx2JluxkE0MYkMP4WKj9yXRjuehXlaHg0qtmSb39yylruo6jcg00kPu7p4
         gvxGZIZeHBNbNUKhZSM2lHAGuLhf+5SgLEjfgp8ywAPM3Rs0wEhQmUFmbzaAYRIAvVmG
         UKLd1XyVxqjfy94UzH53St1XxgVop/4E3dJVCKFgUfSct+GdWXjCulYCybFpcFNbcTbY
         3i4fZmwr6rnunH0TlHCWsJlBH713VuU0zUgTdTzhf1NMzQG9yloedcNCrUaKfwEqIZIi
         3w6CXZnXFRW7N/hmPKp7+/bfoUjXC++feemCrq0opJpT4YlPa+xLSkekJrwbg8zEewGU
         8zDg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=fvYeEJBj;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pcW5uKtWnvRLPIBh1S34uqr/y/J8YW1adscyjBGWXD0=;
        b=PPGtdwlYH8VjDcDKukdJOTzc5cUfrGnMtc4VMQA3AL3RW7l1bT8c0UeO6CZrPporYN
         KOCgAl2XmPBDC1MXujKRjk5xFxVUGg53NkjWJTTlc7C0NrXeSlyLcHavDSBH6jlFI1uK
         HWIznKO0LBZYDsFuEmj95NAe1wn2solROEtXudq/26XJd0IBFVISyx0kcBmYbkONPfHF
         QiHVxAzI8rqNSd3hwpDMgxCECwiLg5KAOcUrofCPCm7xukfLm4Ia5906EHrOStC8xorF
         gpZzduFcQqKRst1HG1ZKXDbbBQmWxzj5LTwp80mNIgmg/MAlVCZ44qoVJmkvT5EGNp7s
         xReg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pcW5uKtWnvRLPIBh1S34uqr/y/J8YW1adscyjBGWXD0=;
        b=200pxfMMpvyg8CU5A/DLNc7GBaNAs5xhhXvbtX8O9cmWZ8gN9WjVh/99KSV/kG10zs
         MZKVy1ZnNHWM1hnUvrROgHCnKAiXggGcNQs4XMr31DEOUxrYnrMpBbrRSHcmUqfUeENP
         AYZVdP2J4WQXjcaSnrI6UmYk3NNgHRnN67KVm53/RNA/WZMqtALBwNyyOPhDkCECYtvx
         fisEYPQpz8In3A4Z3ZEBTYBZduRlOgHqGz5Um5hpQ1ma2J8JBvn+3A9VraS8vBE5qBOQ
         /MAQQx/63CSzETKnWhhCvXp4KVCaXbr/YTZKu+Ljz2RqVBvH3zQafeddorJ/plEJDHvZ
         H+WQ==
X-Gm-Message-State: AO0yUKX8yiLEn0ZDfPWqjk60pcisV3mkZXYon5fl/kL82jkK9EgJ2RUW
	jF5mRD6KSbfH8X1XyuPI2nM=
X-Google-Smtp-Source: AK7set/gBGptQHtzSkL+O3RgGv7Sfb3DiuHfhJZ4v0umGrln4TjokjA2guqqrcxIsyJuXQ9dkfHjTg==
X-Received: by 2002:ac2:562d:0:b0:4db:1326:79b2 with SMTP id b13-20020ac2562d000000b004db132679b2mr1352029lff.2.1676531556247;
        Wed, 15 Feb 2023 23:12:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:210e:b0:290:6183:37b4 with SMTP id
 a14-20020a05651c210e00b00290618337b4ls212864ljq.0.-pod-prod-gmail; Wed, 15
 Feb 2023 23:12:34 -0800 (PST)
X-Received: by 2002:a2e:9b13:0:b0:294:669b:8f94 with SMTP id u19-20020a2e9b13000000b00294669b8f94mr103472lji.51.1676531554763;
        Wed, 15 Feb 2023 23:12:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676531554; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGog/ULY78POk2TnB/9zD/AgVloVmGBpg0zmla8K3vE8/iPmrkPYS6/oprkpWbGo5e
         uuKWyF+xuy7m7UZb0gqUmf/lD2wg9VV79X3EUuuvxq2oKMjrjIWll5CVElU4uX99ZukU
         cZSD40xZOCV1kBENYAJY/tkl5WUnZZZENgOv6pthUPZ7CKtrNrCqd1SKfiePwwxls6i3
         oKcNQmttJxF7PnKY+qDFaSIA/SgapFSNUsapbR0Shh2uEwwNThHE1YXGinx2IUa821MG
         303AVXMj5fwn6YXyS5+cTL6NshR4BCLYiJmYia4EyXuEnfP9eDDrD2N0UBmrPdAhVHvB
         7P8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=ApiSxe1aWj8ukzHxiVdzvhdJNp1KSoTgId6gZai+zaY=;
        b=edH6db5vYb7mXZ5DkDDsq3Uuqye8PpSIivva+n26hzH6YU7eqN7wOcEJ0ThCnnRBSb
         6jDAf+oiJDzuNxCYHPY5u46Cjaj5Ox+cp/De1HeRC4Jn68o1oQvYJ4YCEUKf3UDMxcSu
         /A4Njo2bwHpXQN5KXgh7BFGzCKMhu8mP69A4TXL6f+9br/Xk6UI9e/jbOr7GmbtdD9HE
         dHEIMqp5s/0iTG6FrDM6Nj+ZH8SriuZAcZDxIH3bwvcLV2lgq1Rscq0/xHXeEr2SXXbF
         9yLzFsPC3sVzYfWfe+61X4COOwBjW98UiXSH/b5l16Y6o1vCAEE2JAHaAlDSgTN9EFxd
         HmUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=fvYeEJBj;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on2062b.outbound.protection.outlook.com. [2a01:111:f400:7e19::62b])
        by gmr-mx.google.com with ESMTPS id o16-20020a05651c051000b0028ffa3d673asi22718ljp.3.2023.02.15.23.12.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 23:12:34 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted sender) client-ip=2a01:111:f400:7e19::62b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VdnUT1tSY4r5ni1yDvZO/O1wTCGxU30fqc1tiTU/6tlKGejT+YKm7cFFWHNDgNVlk5Vm0Esc+oj7SMqWNVlQ/MDHKrwzMlgW1nu0aMKEzfBqTalVZbwlhnIDSATZla7XyeWYkj49KpmTOt7dtGggH3vHw/X0vSW5X7tLd9hQBxVIgYAe+07xqRyfxYRvkwwxhtHt5MaY5UVYCbVWBHNSxUB97bYBNuqY6mlR7GnizTeq/puegWHZD67n0dQgfbJhRdhl8GVIWtrntT1mD97+W3SMkMkk9QWBYeftYPzwBHhL256yGXUJt0aDX0nyg1MnfK1dITmfcbVmPGelvwPsUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ApiSxe1aWj8ukzHxiVdzvhdJNp1KSoTgId6gZai+zaY=;
 b=DmhItXGJrbd6x/ew8ddhrFNfpflh6V631co5xw36rlk4nT0Mk3o/qmwz9TpGhe1somN4bfI7wN97ojTY5NQKnkA714W/+9GZR60BtXG9DqeebPwzC1QYo60HV1tr2mioBS/9a3XLxPB1RGmrqXti0fYn+UF73b4v2JM9yIReJTil0lNWPcLvb/jW34XyI+YkeeuctmS7H3RrcCLwNkufIQvbvabdBKFpkPHAuh4b4ggJVjnbT1nGBkoAdcVOoaDOg7NKL0qlVdiClq/Op173q84eQaC8paoenEeTWG0GOGwqs7A2TnQ6rA62VF30hsKKjlncVxmNkhZRT1kmGPtXCg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MRZP264MB2022.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:d::5) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6111.13; Thu, 16 Feb 2023 07:12:31 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::2cfb:d4c:1932:b097]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::2cfb:d4c:1932:b097%4]) with mapi id 15.20.6111.013; Thu, 16 Feb 2023
 07:12:31 +0000
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Rohan McLure <rmclure@linux.ibm.com>, "linuxppc-dev@lists.ozlabs.org"
	<linuxppc-dev@lists.ozlabs.org>
CC: "mpe@ellerman.id.au" <mpe@ellerman.id.au>, Max Filippov
	<jcmvbkbc@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH 1/2] kcsan: xtensa: Add atomic builtin stubs for 32-bit
 systems
Thread-Topic: [PATCH 1/2] kcsan: xtensa: Add atomic builtin stubs for 32-bit
 systems
Thread-Index: AQHZQcUG0YdOHgVMFEKNKlnA7MJd167RKIeA
Date: Thu, 16 Feb 2023 07:12:31 +0000
Message-ID: <42e62369-8dd0-cbfc-855d-7ad18e518cee@csgroup.eu>
References: <20230216050938.2188488-1-rmclure@linux.ibm.com>
In-Reply-To: <20230216050938.2188488-1-rmclure@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MRZP264MB2022:EE_
x-ms-office365-filtering-correlation-id: 67a21f3d-ee6b-4c77-fcca-08db0fed2ba8
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: VOUXgMwNG39lmidvK0xCK8pJ4Nrj2CZ3QfuxPmQEGx3zNIWn6t6K4kAwMbDsRqAmgxZAhu/bayuVmJiIaZTHZg7PSauPoKOqNpG3A42vLYpNP9+DKmK+osZb+hBNMSBHGZhTJgn1tKt0hgnom2jOlF/rdPp0lINiayU1YBgM5use006/e5MqP3An2uvrNPHH3XUPjm45e0BI20tjAYwdQu211RhT6h8GCqnd3Ogh17ygZagqrRDfdgBitdYMZFAElXedcj3Kb20qNiCS+8A7TcEyhm4PhkdyqB0aKxJMZTkzr+lsqE0yfjimMRzSg0/Wob0LcAEE0wZ6PDKcTN4X9fq3l2kQKLYL5CqtP4fY5gf7lK3Re11OHxlw/LIBAjpBLJ6+3l4aNHJP5lxNYPuW5w49I1uk8rI4BNphuFl+QB7aa0Tl+iux+tJEml720Yke4egZ7R9v55vkC5bRSCs1/bRDgrPEZMHzPFZcCb5xtxk2IIwibap/vdJzpHJV3EbmR3qpaSDZSRJ44mHUkd6CkwzZbOSCYB3AsH9iA7qlTBzsqrcVrW0NaNJ+1gM41nI0Gh04M4nb2KZUz3ydYzvVS3KoPVTo+KUCaqLPmuGfnj6EHRIrx+WCvF3ACVAasrGhjhimXmh59IuIdLuFAgK6Rp8PZGJOfJum08ThxVzqsQJFDAosXnmwXDmFui22uOAGFboko7KiWxqPTKKpnGkfsVtHvdTFP5Weam6hpOJ0DXy+UFk6l2ZhFwxBMbPLbYL6
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230025)(4636009)(39860400002)(346002)(376002)(136003)(396003)(366004)(451199018)(122000001)(8936002)(110136005)(54906003)(86362001)(83380400001)(91956017)(66574015)(64756008)(31696002)(66446008)(76116006)(66946007)(66556008)(4326008)(66476007)(316002)(8676002)(6506007)(38070700005)(2616005)(186003)(6512007)(2906002)(26005)(36756003)(41300700001)(38100700002)(5660300002)(478600001)(31686004)(6486002)(966005)(44832011)(71200400001)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?OVY5V0ZBWmFEOXIybFE2TGc0NnB0RDV1azNIWEsrbUdIWVNmbnNBeFQ4eTBY?=
 =?utf-8?B?dnNuOGNIV0tFcWQwVTNLeGl1elJlMkdwSVhVVHFVblJReWg1VXcrcnBsNXVp?=
 =?utf-8?B?bW5QYmxXNmVZWHpVV2UyK1ErbkVoZXJvRmdFSHQrMCsrREpyM0xZOCtQOVJj?=
 =?utf-8?B?TVcvZnFqaTI4VzRVRVNlTGpUWTZkM2NoWnd1SDYrNFZHbG8zdmJzbnJlZTcz?=
 =?utf-8?B?MEp3Y0R1Z2luMVNtSUJBcGtjUWlYZUcxRCs5UkxORFRMTnhsVWZsVGMwczVX?=
 =?utf-8?B?ZlRsWXI2dUswZEU3L2hCOGdOT0RSVkM0d0t4TFduRHlSTjgwN1JVK0tSa1M4?=
 =?utf-8?B?UFNtVW9KcTFYS0JoUk9QZmF6Umxpc1dGQnd4NVN6Z09SMzlQc3lVMG1paVg1?=
 =?utf-8?B?dDdjVERQczZBSkxrUGtJQ3ZLUkY0bUVkMWExMEN6SE1lQWRRN1R6WFg5K0tw?=
 =?utf-8?B?L095VFArWndLYS9zV1NLbEc2b1pZaFlxSmlSNnB5bzJpdFBnR1lEbzNTQld1?=
 =?utf-8?B?NVY4Y1BjZFhZZjhNenFwZFpBcDRSTGNXdERORmFxSzYxWUM1SUN2WTlablYz?=
 =?utf-8?B?aVZiWEMweE5xd1JwRXJPbEh2SC83NFN4MW1hR2FDUEU1L0pSVkljOHYvOW1K?=
 =?utf-8?B?NWhoWXkyandoTjhvVTB5aE1CQWhNR0VUU3NaSVhVME5PU0hKbXpZTHRGeUVU?=
 =?utf-8?B?azl4RC9HdkZNYmczNG5Cb0tkdldYT3d1cDV2dktEZGkvbDN1MVo0aDhWeGFk?=
 =?utf-8?B?NjkwamVRNzFVaWxqaGo0cHUwdGxsYXhOVW42NkdlNk5lcXJsckdFUFpzbXdE?=
 =?utf-8?B?Ny9QSTgrTTVObEJQV1BpMEFyVUMxbWRpVnFOcDZBUHlFZlZ1QXBkbFZxWDhz?=
 =?utf-8?B?V1NzenZhNkh3dFBQUUM5bEhGRmNmK0lvaGY2aU1BbDlVT3ZwOXk1M3RnUitG?=
 =?utf-8?B?Z2MzZTRxazVzV0Q1QnRhSFBSRTBmVEpjQWNlRXY2Nzh3RmlWdStmOXY2OHA4?=
 =?utf-8?B?aTQzdld3alV0enduSDZYVlZydllQUGhvbFQrUkN0eU5Va0M1dHhEK1llSW14?=
 =?utf-8?B?SVRVcC9kQUYvRWNncXJ2VUc4VlZ1d29qK1YzZ2lEWGp0cU9COHhJNnE2TnR2?=
 =?utf-8?B?QVJzMmpGdkdQK0hsRHpjTHBSUm1OY3NXQzdDSVp0ZEFvaHgyeUJHdlFkSTJi?=
 =?utf-8?B?UmJMUzBJZk5HWnAxNHZiTm8wUFQ1RFpsSkNGRnFuUDE5YmQ5L0xyM1VLb1Jh?=
 =?utf-8?B?VUpqRnQvM3M2dFVNT0JmYk1zUXZ1dWNPYVBYaS8zako1TVdtbHIydmdkczBh?=
 =?utf-8?B?ZWNKSGZwYVFQU3k0VkpSQmtmczBLL0xwekI0YWF0ZmNaWUlJZ0ZMclBUeTZM?=
 =?utf-8?B?MklrQXE3R3c5ZytPdWh3OStzVHhRSmpHc1JMOHFHRFNzUXpzT1lXcXFFaDdp?=
 =?utf-8?B?azVvSDZYMjFWZDR0ajNOUndwRko5ejN4RldZU29zRW00aXQ4SUN6dkNBcXpz?=
 =?utf-8?B?TmRycmdlaGs0cHBucG13WnVOYmk2Z29rZzlscm54UW9rNlJFbkJmRFNSZmNZ?=
 =?utf-8?B?dnlXaDUvYW9pUUtUdmgxT3o4UHlLcXRpSzZVbWdBODlsdGZRem1adVUzZThD?=
 =?utf-8?B?SG9SN3hMSzNiUXBzQSthb2J5eFpxSEI5aUhnRitLN3haRUQ4NlBkSEJEbWFn?=
 =?utf-8?B?aCtYYVFnZk9qbmwvQjRTeG1PMmMyRnM0R0owMk9mSW02WmhNQkRiakxaNEVK?=
 =?utf-8?B?NHJScFBPMDNncFZaSkFMMmZvOGtzd0VRU2hoQUR1TEwvUERCWDdFN1RiK3du?=
 =?utf-8?B?d2RrTHAzMlhvWUg0bkNmc1NYaWpXbk54R1ZpMVlEbW5vZFB1Lzd0VlFOS2hy?=
 =?utf-8?B?OWNlME5KeThtSzJZc2ZyR0o1UERqWHFhWkprRWpGSU5wSVdrWmdyUGFDcFpI?=
 =?utf-8?B?N3djeTdXczd1ekMvcE1EcGFpNmdpZ0NISFZILzBpTUJ4SUVYUEQ5MGw2UmIv?=
 =?utf-8?B?a09jc25CNlJxMDVJQTV1WUZDSkZuZjN6U2R5dUNNKzZIL2FDTUtpMU1IUzl3?=
 =?utf-8?B?dU5sYmd2RGt4N2N5c0VXL0U3bEVORzN3NWg1cmtPNzBVZmZ0RHludkROeXpU?=
 =?utf-8?B?eUI2OHVIYVdWVFQwamlob09aSjNSV01EQTQwa2FNd2NlUXBYR1UwVCtxSDVN?=
 =?utf-8?B?QVE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <68A5DB3C578889458F7CE706915B6B1A@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 67a21f3d-ee6b-4c77-fcca-08db0fed2ba8
X-MS-Exchange-CrossTenant-originalarrivaltime: 16 Feb 2023 07:12:31.7061
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: bKWw3qmup4UEkMI88NICxW56bFTgK3N1YBu6I6MpMeMtk9Tv3r2Wzj24YK1sYbRN1N63qugftix1R7RlGNU5LLY8Eh2yO+bn0a47+TJJXYk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MRZP264MB2022
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=fvYeEJBj;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted
 sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 16/02/2023 =C3=A0 06:09, Rohan McLure a =C3=A9crit=C2=A0:
> KCSAN instruments calls to atomic builtins, and will in turn call these
> builtins itself. As such, architectures supporting KCSAN must have
> compiler support for these atomic primitives.
>=20
> Since 32-bit systems are unlikely to have 64-bit compiler builtins,
> provide a stub for each missing builtin, and use BUG() to assert
> unreachability.
>=20
> In commit 725aea873261 ("xtensa: enable KCSAN"), xtensa implements these
> locally. Move these definitions to be accessible to all 32-bit
> architectures that do not provide the necessary builtins, with opt in
> for PowerPC and xtensa.
>=20
> Signed-off-by: Rohan McLure <rmclure@linux.ibm.com>
> Reviewed-by: Max Filippov <jcmvbkbc@gmail.com>

This series should also be addressed to KCSAN Maintainers, shouldn't it ?

KCSAN
M:	Marco Elver <elver@google.com>
R:	Dmitry Vyukov <dvyukov@google.com>
L:	kasan-dev@googlegroups.com
S:	Maintained
F:	Documentation/dev-tools/kcsan.rst
F:	include/linux/kcsan*.h
F:	kernel/kcsan/
F:	lib/Kconfig.kcsan
F:	scripts/Makefile.kcsan


> ---
> Previously issued as a part of a patch series adding KCSAN support to
> 64-bit.
> Link: https://lore.kernel.org/linuxppc-dev/167646486000.1421441.100700595=
69986228558.b4-ty@ellerman.id.au/T/#t
> v1: Remove __has_builtin check, as gcc is not obligated to inline
> builtins detected using this check, but instead is permitted to supply
> them in libatomic:
> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D108734
> Instead, opt-in PPC32 and xtensa.
> ---
>   arch/xtensa/lib/Makefile                              | 1 -
>   kernel/kcsan/Makefile                                 | 2 ++
>   arch/xtensa/lib/kcsan-stubs.c =3D> kernel/kcsan/stubs.c | 0
>   3 files changed, 2 insertions(+), 1 deletion(-)
>   rename arch/xtensa/lib/kcsan-stubs.c =3D> kernel/kcsan/stubs.c (100%)
>=20
> diff --git a/arch/xtensa/lib/Makefile b/arch/xtensa/lib/Makefile
> index 7ecef0519a27..d69356dc97df 100644
> --- a/arch/xtensa/lib/Makefile
> +++ b/arch/xtensa/lib/Makefile
> @@ -8,5 +8,4 @@ lib-y	+=3D memcopy.o memset.o checksum.o \
>   	   divsi3.o udivsi3.o modsi3.o umodsi3.o mulsi3.o umulsidi3.o \
>   	   usercopy.o strncpy_user.o strnlen_user.o
>   lib-$(CONFIG_PCI) +=3D pci-auto.o
> -lib-$(CONFIG_KCSAN) +=3D kcsan-stubs.o
>   KCSAN_SANITIZE_kcsan-stubs.o :=3D n
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index 8cf70f068d92..86dd713d8855 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -12,6 +12,8 @@ CFLAGS_core.o :=3D $(call cc-option,-fno-conserve-stack=
) \
>   	-fno-stack-protector -DDISABLE_BRANCH_PROFILING
>  =20
>   obj-y :=3D core.o debugfs.o report.o
> +obj-$(CONFIG_PPC32) +=3D stubs.o
> +obj-$(CONFIG_XTENSA) +=3D stubs.o

Not sure it is acceptable to do it that way.

There should likely be something like a CONFIG_ARCH_WANTS_KCSAN_STUBS in=20
KCSAN's Kconfig then PPC32 and XTENSA should select it.

>  =20
>   KCSAN_INSTRUMENT_BARRIERS_selftest.o :=3D y
>   obj-$(CONFIG_KCSAN_SELFTEST) +=3D selftest.o
> diff --git a/arch/xtensa/lib/kcsan-stubs.c b/kernel/kcsan/stubs.c
> similarity index 100%
> rename from arch/xtensa/lib/kcsan-stubs.c
> rename to kernel/kcsan/stubs.c

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/42e62369-8dd0-cbfc-855d-7ad18e518cee%40csgroup.eu.
