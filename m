Return-Path: <kasan-dev+bncBAABBM7NWGFAMGQELUO6YMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BBF48415EAE
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 14:44:35 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id a28-20020a056512021c00b003f5883dcd4bsf5989024lfo.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 05:44:35 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GkipLg03bewiSmImYqiuv51r0ZZAhOxjniyzuPzv/Q0=;
        b=dzCdf29zHEvn9ksjAqeKwrhKnSURwHnKZk2ICpTBl6NuvLg1tX7A+DW0aRA+DzDH6D
         CKvB7GIiiPQKd/FK/9kYrhMoGBS/KfTW8PS1gXNubd5HlZ49hZDITF/iT15WI8dIh1Jc
         367LFhS7hCpxt6kh9ZUDysau6yrhC3AaQnI/9FJHQlhg30Tfkb8oPwyGmzMOE762YRL6
         4KHe1xw8xhULDVPgxFzA31aKCztlbYsQ28HTaRnptieKP78mNUwZ1yItT203BttzevSO
         HifaOxybTTTjFfimB0j4hK5phB1pNASISZoM/lhwQZsNrUnuf0Cu3/M693TSbLCrVPvs
         9Xow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GkipLg03bewiSmImYqiuv51r0ZZAhOxjniyzuPzv/Q0=;
        b=BEx3+r+9UlVluOGwlpYwOfjj2RJ0k5xjqjE02kwmda9VMdaqD4UAOHHI4VuEiVppXD
         rlHobRBLJ2LzfEDI43jZRCklRmX1FyrLdSsX0QpmGTYWFASampKnFhTXgrKfEKAc6jV1
         srRd7p1M+FDLZGm1YtDGR0CZKHS+xmSzazDRNVoeGy7+Wja/0M4PCBXYXCfRXrEA6W5P
         1GCmYe4WMbplo09FHMEUSNFNuKIY1gVM33yXx+0N4wZQXoKX/3QHbxdItzwB2IoAzb7d
         hEHUFHvoG9Wyu7pothEq3i5y/iFtPAFkgCOu6F9YqGLmaYaimhiJtP+rATNtJ9QTJSjI
         WhLQ==
X-Gm-Message-State: AOAM532RZV0b49CjyJIXqifYKvzslE96pa9MsrqtqS7O7jzn20CqVI1y
	2oa3ih+uW2rY4hff2F8tFW4=
X-Google-Smtp-Source: ABdhPJzsMlOVIzmnK0VblSuhb74g5ELymX7SNd2rKUysOPy2dkkUOseJpmXp60rDTCkkh+P5M3Xesw==
X-Received: by 2002:a05:6512:3d94:: with SMTP id k20mr4200150lfv.359.1632401075337;
        Thu, 23 Sep 2021 05:44:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:881:: with SMTP id d1ls1147845ljq.11.gmail; Thu, 23
 Sep 2021 05:44:34 -0700 (PDT)
X-Received: by 2002:a2e:898f:: with SMTP id c15mr4811315lji.452.1632401074463;
        Thu, 23 Sep 2021 05:44:34 -0700 (PDT)
Received: from smtprelay-out1.synopsys.com (smtprelay-out1.synopsys.com. [149.117.73.133])
        by gmr-mx.google.com with ESMTPS id t14si234246lff.6.2021.09.23.05.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 05:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of shahab.vahedi@synopsys.com designates 149.117.73.133 as permitted sender) client-ip=149.117.73.133;
Received: from mailhost.synopsys.com (badc-mailhost4.synopsys.com [10.192.0.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
	(Client CN "mailhost.synopsys.com", Issuer "SNPSica2" (verified OK))
	by smtprelay-out1.synopsys.com (Postfix) with ESMTPS id 885924151D;
	Thu, 23 Sep 2021 12:44:30 +0000 (UTC)
Received: from o365relay-in.synopsys.com (us03-o365relay3.synopsys.com [10.4.161.139])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
	(Client CN "o365relay-in.synopsys.com", Issuer "Entrust Certification Authority - L1K" (verified OK))
	by mailhost.synopsys.com (Postfix) with ESMTPS id DAA1AA005C;
	Thu, 23 Sep 2021 12:44:26 +0000 (UTC)
Received: from NAM02-SN1-obe.outbound.protection.outlook.com (mail-sn1anam02lp2047.outbound.protection.outlook.com [104.47.57.47])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client CN "mail.protection.outlook.com", Issuer "DigiCert Cloud Services CA-1" (verified OK))
	by o365relay-in.synopsys.com (Postfix) with ESMTPS id 5410280151;
	Thu, 23 Sep 2021 12:44:22 +0000 (UTC)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Ql0OQazr/pNI1ie5lP8Ht8iY8eOUSaANgcsKDZeanbY5JGm2DYN7ViWFq0GSn7YuEdL/lqgPOUwfp6yIwIN7w682q4qOhfVMJJ030VSQuyLahcjVTcTLbj1waahXj9HMRlxKs4Vgg7OqUkLGVtxBHm8v4qbfy5zOmVpGOEgRFzdV+WPfmxr/w2EuS62IYorK7D6PicnCLwUU80cPNmSxzQBIwvJv9I4RLgCW7/OIo59UBGn6ngK54KflPmdMqyk3NB/if51/2tt090fXxKBAVjzRQMpUc9bdssSpKr5TVg7jvM9I1dvnobtwPMo1Rf+9jG2KB1ZQOFtNAl2+M4q1/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version;
 bh=p8yypIUjB8D1QtzMPOfUh/V1qIMQJPRo2PqJWZ5SYsY=;
 b=lB/dfGY6qGnlPCzk6jrqPkumxuD6Zle3JmpqYxFguRB+KFcNp6CEFP4jl5p0h3ScILyRfGJGJ6iKV9p6EUIXLi3OjLbHITHcmB3i9qnwN5UvUJ+iHOJpN9M6l6uzRQOqvLaLkjNjU0E+Phxy2TgG8aeY9o8aw+1/5wA0gAX08oYdQXqbqMe4QzUPO3Eju5H0KcnbEjLg54k/UTSE87WlvYxpA0bDlhO5ZZxMYqTaMkGZjoBOqwIIH33tyS1+bGTyH3MjjzIeRu+PbYAUtyPAxkMPpz55xCAno4NSztx5WB43EDkbi0NVyhaRoI8RaQ+rK40gjT3/SxJpzhaG68Z+6Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synopsys.com; dmarc=pass action=none header.from=synopsys.com;
 dkim=pass header.d=synopsys.com; arc=none
Received: from CY4PR12MB1160.namprd12.prod.outlook.com (2603:10b6:903:38::12)
 by CY4PR1201MB0200.namprd12.prod.outlook.com (2603:10b6:910:1d::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4544.15; Thu, 23 Sep
 2021 12:44:19 +0000
Received: from CY4PR12MB1160.namprd12.prod.outlook.com
 ([fe80::2d3a:44fe:fd31:11e2]) by CY4PR12MB1160.namprd12.prod.outlook.com
 ([fe80::2d3a:44fe:fd31:11e2%7]) with mapi id 15.20.4523.018; Thu, 23 Sep 2021
 12:44:19 +0000
X-SNPS-Relay: synopsys.com
From: "'Shahab Vahedi' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>, Linus Torvalds
	<torvalds@linux-foundation.org>
CC: Andrew Morton <akpm@linux-foundation.org>, "devicetree@vger.kernel.org"
	<devicetree@vger.kernel.org>, "iommu@lists.linux-foundation.org"
	<iommu@lists.linux-foundation.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "kvm@vger.kernel.org" <kvm@vger.kernel.org>,
	"linux-alpha@vger.kernel.org" <linux-alpha@vger.kernel.org>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-efi@vger.kernel.org"
	<linux-efi@vger.kernel.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
	"linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
	"linux-sh@vger.kernel.org" <linux-sh@vger.kernel.org>,
	"linux-snps-arc@lists.infradead.org" <linux-snps-arc@lists.infradead.org>,
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>,
	"linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>,
	"xen-devel@lists.xenproject.org" <xen-devel@lists.xenproject.org>, Mike
 Rapoport <rppt@linux.ibm.com>
Subject: Re: [PATCH 3/3] memblock: cleanup memblock_free interface
Thread-Topic: [PATCH 3/3] memblock: cleanup memblock_free interface
Thread-Index: AQHXsE7r2Z9Q1x5PbkCRzXvVc2eiLKuxkQqA
Date: Thu, 23 Sep 2021 12:44:18 +0000
Message-ID: <70364d6d-7569-3cd8-acce-559878ce4596@synopsys.com>
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
In-Reply-To: <20210923074335.12583-4-rppt@kernel.org>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: c1e5f238-9c40-4f49-2da5-08d97e8fdc67
x-ms-traffictypediagnostic: CY4PR1201MB0200:
x-microsoft-antispam-prvs: <CY4PR1201MB02008C7112226A9E691D827CA6A39@CY4PR1201MB0200.namprd12.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:2958;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: OamkW3UO1/WqFADz4A194HFP4oBQk8gtqnKNjVuDksrLnfE6l+GVJQhwsaegPUSH7gx9t8lMJ1FdmgYJCgJ4OZ3EhKf8RZTD3Ts0zaaHTLojOQ5TBH4ZPl6xEabh2XoGqBvwUOEEFr9uSp9MQZp9dSBW+UcQqhYiFNaSTPWozfT9nTMipLej1e9xdNsDzJwkWvc4Nqfx9vJUpUl1b2y3wVZ1oitLTB5EUrRSlKgJTGqIekv1SR1YFUhPDs3nw9WEL9bXMu/EvTL8nA8XhyS8T5AggLricxDpUq9wYUHjECvPt7tEppOAD3ENQzfE8EgYlSeEkDpjU97d+AXoZrfhgqvMnmxfIN2HYaS9mEsbHWU/v+kC/37zYn4F+xyL7BZ7yyVP3OXhFEbyRjeA1fu5yW3MacAsdznAi8uIZTlBVJnpBYFOXwFAXJRBkzH6xa4sV/7hMat8LxK4cZD3yPIhI0AN4eK6rNxYmtVdMz7h6nIy+EuGpBn1s07XirzbDNP3itQCWqt0TOrchOPjGN3ZLRqsKltq5PAMjMXOxRZdN2dqnUFCweBuWWfCwgrV5044fj0vvvSEUUfHpFWJLJRnyg4c3Eh2g6Ee+cAC9QDPHcsmAgajEJma1cFC1eRoIfuvfIe6apmOy46ssLpPZuMbub2YhBZ5/KLzyz/ik0j7m6nXwWbxN1QdS/7wnLeRcvfuaqggkqHcyct/8HQb0MRs9FG7LhwusDW07wtmQYsIsLg=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CY4PR12MB1160.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(366004)(38100700002)(71200400001)(86362001)(2906002)(83380400001)(54906003)(31686004)(110136005)(38070700005)(91956017)(66946007)(508600001)(66446008)(64756008)(66556008)(66476007)(76116006)(7416002)(5660300002)(8676002)(186003)(8936002)(31696002)(122000001)(6512007)(4744005)(36756003)(53546011)(6506007)(6486002)(2616005)(4326008)(316002)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?Z3E1Q1p2dDJNR052VkZ1TG1nK2ZKSGJNWWxCdkIxdlgvemFlRHNZdG55SnAz?=
 =?utf-8?B?NFZnVDlEWVZHN3c5dTc1U2pCY2lTdkhTeXB3QU0xV1pocFhjTHZlUFkzSkhl?=
 =?utf-8?B?UDlnbWhORjBYYXFRUUFnNDM5ZFdHbFlZSVFEa3lIUUxnREc5d2ducFNGY0pt?=
 =?utf-8?B?V2NTVGdxdVFMNlRLemlvQ1M2VUJHMVVYL0ZkaXZ2dEVBQnc3Y0EvQVQzQmo5?=
 =?utf-8?B?dzZDbWtxejJRZnFkN210bmIwczlpMGprc0JqY3Rza01pV2JLU29CWkw0SFRJ?=
 =?utf-8?B?bnNoQVBFbzZIRnBndm5VR2tHWWo5ejdEWURZTktZbGthMkdKbU1rcFNTcWxQ?=
 =?utf-8?B?K0tyNG9pRTNuZEY5NXIxUEF6U1k3Nlg5RVlTT0hTTzlQUWYzNVdiRVlpY1ND?=
 =?utf-8?B?eHRxRmg1aHEvVE9mcTVmZU1kalNoR1NBZmwzSUZmSEFwa2xPL1ZuUWd6ZHll?=
 =?utf-8?B?TS9vNDMzNVY4SUxOVTA3S0hQVjRsODRLWC9abmp1MGg4R1c5YmhlM25sK1Jq?=
 =?utf-8?B?WE1BOEM2bWE3RDN6YWs1TUdCOUdZZm5LaW4wYUVuWVR1SFg3RVRoeXZOSTFY?=
 =?utf-8?B?MjNROHlxdHlWejJzN05uZlBQUGZPVXRSOHl5ZnRlTUFkVndJTHNyTS9CZWtn?=
 =?utf-8?B?ckYycndlMSt4bTk5TlEvZE1HOWFXZlRDRmJtOHY3MTdPZ3NhblhLVFZMYWx1?=
 =?utf-8?B?RFd1NXNBcjZCcjVYZWFyWDZGQzBTSmhzV09qZmZEUkdyOENUdFpteXNqQmFF?=
 =?utf-8?B?ejVtUldNT0swSzllQkNnc251RHhQZVJlN3JpdWlWVksyb3ZHMGZRcE0vOVJJ?=
 =?utf-8?B?U0xCQ0hnN294VDBXT1lOZXdKZEM4ZjZoOHdmVStLVnVSUElvNVZFRm1LWDBP?=
 =?utf-8?B?SVBaUjhXUHhHcEdId2hjRXorVkxiNTNISzFjTzkzb0dMMHBIRUtxZmF1aHRk?=
 =?utf-8?B?NEI0a3lZN0prRlNQTGtGTmNWT3VJSjYvVWltOWswWVAreU9BUkxaOHFhOFdq?=
 =?utf-8?B?TkZBZGdXVE9Icnlyd0YraDFNZHR5TDdrVGZmbVVJRXZDRXFtclFFc21TNEk0?=
 =?utf-8?B?WVdjOUJoRHdPdEpMY1pKMDFiK1RuMFZsbFRJMGRLVklCNTQ2bS9CanI4VENx?=
 =?utf-8?B?RkloOG1BZmU2ZnlRTmJCZjJXdDlYaFJnSzhkTFFTbFJSWFBFOGQrcS80NXVU?=
 =?utf-8?B?YjNqOHVwWVM0TkY1NktBVEVmMnVVV1ZYNWp4Z0xySVJFTC9BSm9qNkNzdmZM?=
 =?utf-8?B?MXFFOEIxWDdieU5BQ1pGZlFWWTFaZjhFbi9XUSs1Y0JHemtQUXhrNElVTzU2?=
 =?utf-8?B?K1JtOG1aQUN4UUVyR1ArNmpvbWdscWFPdlJWTi9mKytoSTN5ZUkvc2dvMDEw?=
 =?utf-8?B?c0lmWWFvcWxLRkNiUFU1VTF1QnRoMDJrVkpNK0FtN2FFUVhqKzV3ZHVVTzh4?=
 =?utf-8?B?RkxWQS9YcnZwcklycTcrZy8rWDhxSEdJalZaMllBQ0FHZEhHL1YzTTJsWUpT?=
 =?utf-8?B?MmNvbnFxYmk4ZllDcnJ5U2UycExRUHRmVEJLTEI4UHFOeDJUWjN3UjdkcU9T?=
 =?utf-8?B?RjBtOTJ0M3VPeTdNVVpSbHQxeXVsVDU3LzBMM2RnNkNCd1BuZlZEalZLbTNG?=
 =?utf-8?B?cHQwc3luVmpwc2ZJWVZEY3IzVENiRTdrRHp5NzM3b2xvRnA5LzlCcWpuTE43?=
 =?utf-8?B?ZkFzTUNlWkxVdlFGQ1NtdDBvZS95aGRTUkNaSlBIQ1NNY2FabGNSWFp5dVpr?=
 =?utf-8?Q?zxZX1W1RS474i7oyqAN1Twr11o31hFkPD6o09yZ?=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-ID: <BEE0BCB4DA8E9D4FA42EB8E75B22E457@namprd12.prod.outlook.com>
MIME-Version: 1.0
X-OriginatorOrg: synopsys.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: CY4PR12MB1160.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c1e5f238-9c40-4f49-2da5-08d97e8fdc67
X-MS-Exchange-CrossTenant-originalarrivaltime: 23 Sep 2021 12:44:19.0739
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: c33c9f88-1eb7-4099-9700-16013fd9e8aa
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: YXVpj8MQIzNFMgREFPcSyNOhb48DBCQjuuwYd+4/FTIRz+7n+fNOo/94DmdqxSrRhwhnoAWwsgrHeewqRJ+nSA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY4PR1201MB0200
X-Original-Sender: shahab.vahedi@synopsys.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@synopsys.com header.s=mail header.b=Gvq9P4b8;       dkim=fail
 header.i=@synopsys.com header.s=selector1 header.b=XjlMBsSZ;       arc=fail
 (signature failed);       spf=pass (google.com: domain of shahab.vahedi@synopsys.com
 designates 149.117.73.133 as permitted sender) smtp.mailfrom=Shahab.Vahedi@synopsys.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=synopsys.com
X-Original-From: Shahab Vahedi <Shahab.Vahedi@synopsys.com>
Reply-To: Shahab Vahedi <Shahab.Vahedi@synopsys.com>
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

On 9/23/21 9:43 AM, Mike Rapoport wrote:
> From: Mike Rapoport <rppt@linux.ibm.com>
> 
> For ages memblock_free() interface dealt with physical addresses even
> despite the existence of memblock_alloc_xx() functions that return a
> virtual pointer.
> 
> Introduce memblock_phys_free() for freeing physical ranges and repurpose
> memblock_free() to free virtual pointers to make the following pairing
> abundantly clear:
> 
> 	int memblock_phys_free(phys_addr_t base, phys_addr_t size);
> 	phys_addr_t memblock_phys_alloc(phys_addr_t base, phys_addr_t size);
> 
> 	void *memblock_alloc(phys_addr_t size, phys_addr_t align);
> 	void memblock_free(void *ptr, size_t size);
> 
> Replace intermediate memblock_free_ptr() with memblock_free() and drop
> unnecessary aliases memblock_free_early() and memblock_free_early_nid().
> 
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>

arch/arc part: Reviewed-by: Shahab Vahedi <shahab@synopsys.com>


Thanks,
Shahab

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/70364d6d-7569-3cd8-acce-559878ce4596%40synopsys.com.
